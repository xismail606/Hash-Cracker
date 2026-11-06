"""Multiprocess candidate hashing, comparison, progress, and cancellation.

The engine compares one operator-selected target hash against a stream of
candidate batches using a bounded ``ProcessPoolExecutor``. Workers perform
the CPU-bound digest calculation; the parent process streams batches from
dictionary or brute-force sources, tracks progress, and stops scheduling new
chunks on a match, cancellation, or the candidate budget.

Supported worker counts are 1 through 8 with a default of 4. The effective
worker count reported in results is the configured count after it is clamped
to the supported range; the pool never creates more processes than that.
"""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor, TimeoutError
from dataclasses import dataclass
from typing import Any

from .bruteforce import DEFAULT_BUDGET, HARD_MAX_BUDGET
from .hashing import hash_candidate, verify_candidate

MIN_WORKERS = 1
MAX_WORKERS = 8
DEFAULT_WORKERS = 4

# Terminal run statuses.
STATUS_MATCH = "match"
STATUS_NO_MATCH = "no_match"
STATUS_CANCELLED = "cancelled"
STATUS_BUDGET_EXHAUSTED = "budget_exhausted"
STATUS_INTERRUPTED = "interrupted"
STATUS_INVALID_INPUT = "invalid_input"
STATUS_STORAGE_ERROR = "storage_error"
STATUS_PAUSED = "paused"

# How many batches may be outstanding at once; keeps memory bounded while
# keeping every worker fed.
_OUTSTANDING_FACTOR = 2


class EngineInputError(ValueError):
    """Raised when audit options are invalid before any candidate work."""


@dataclass
class RunResult:
    """Terminal outcome of one audit run.

    A paused run is not terminal: ``status`` is ``paused`` and ``resume``
    carries the state needed to continue (attempts already counted and the
    number of source candidates to skip on resume).
    """

    status: str
    attempts: int
    elapsed_ms: int
    workers: int
    matched_plaintext: str | None = None
    message: str = ""
    resume: dict | None = None


def skip_source(batch_source: Iterator[list[str]], skip_count: int) -> Iterator[list[str]]:
    """Yield ``batch_source`` minus its first ``skip_count`` candidates.

    Used to resume a run: the skipped candidates were already submitted by the
    paused pass. Fast for dictionary streams (read-and-discard) and for
    deterministic brute-force generators (regenerate-and-discard).
    """
    remaining = skip_count
    if remaining <= 0:
        yield from batch_source
        return
    for batch in batch_source:
        if remaining >= len(batch):
            remaining -= len(batch)
            continue
        yield batch[remaining:]
        yield from batch_source
        return


def clamp_workers(workers: int) -> int:
    """Validate a requested worker count against the supported 1–8 range."""
    if not isinstance(workers, int):
        raise EngineInputError("Worker count must be an integer.")
    if workers < MIN_WORKERS or workers > MAX_WORKERS:
        raise EngineInputError(
            f"Worker count must be between {MIN_WORKERS} and {MAX_WORKERS} (got {workers})."
        )
    return workers


def _hash_batch(
    batch: list[str], algorithm: str, target: str, salt: str | None = None
) -> tuple[int, str] | None:
    """Hash every candidate in a batch; return (index, plaintext) on a match.

    This runs inside worker processes and must stay a module-level function
    so it can be pickled with the spawn start method on Windows.
    """
    for index, candidate in enumerate(batch):
        if verify_candidate(candidate, algorithm, target, salt):
            return index, candidate
    return None


def _await_ordered_batch(
    future: Future,
    cancel_event: Any,
    pause_event: Any = None,
) -> tuple[Any, bool, bool]:
    paused = False
    while True:
        if cancel_event is not None and cancel_event.is_set():
            return None, True, paused
        if pause_event is not None and pause_event.is_set():
            paused = True
        try:
            return future.result(timeout=0.1), False, paused
        except TimeoutError:
            continue


def run_audit(
    target_hash: str,
    algorithm: str,
    batch_source: Iterator[list[str]],
    *,
    workers: int = DEFAULT_WORKERS,
    budget: int | None = None,
    total_space: int | None = None,
    salt: str | None = None,
    cancel_event: Any = None,
    progress_callback: Callable[[int, int, float | None], None] | None = None,
    pause_event: Any = None,
    resume_state: dict | None = None,
) -> RunResult:
    """Compare candidates from ``batch_source`` against ``target_hash``.

    ``budget`` caps the candidates submitted per run. Pass ``None`` for a
    plain dictionary stream; the default is the brute-force budget when
    ``total_space`` is given. ``total_space`` is the size of the full
    configured search space; a brute-force run that stops at the budget with
    space remaining ends in ``budget_exhausted`` instead of ``no_match``.

    ``progress_callback(attempts, elapsed_ms, fraction)`` fires as batches
    complete (``fraction`` is ``None`` when the total space is unknown).
    ``cancel_event`` is a ``threading.Event``-like object checked between
    batch submissions and completions.
    """
    if not salt:
        salt = None  # normalize empty-string salts from form inputs to None
    workers = clamp_workers(workers)
    attempts_base = 0
    skip_count = 0
    if resume_state:
        attempts_base = int(resume_state.get("attempts_base", 0))
        skip_count = int(resume_state.get("skip_source", 0))
    if budget is None:
        budget = DEFAULT_BUDGET if total_space is not None else None
    elif budget < 1 or budget > HARD_MAX_BUDGET:
        raise EngineInputError(
            f"The candidate budget must be between 1 and {HARD_MAX_BUDGET:,}."
        )
    else:
        budget = min(budget, HARD_MAX_BUDGET)
    # For brute force the budget is a real stop when the configured space is
    # larger than it; a fully covered space simply ends as no_match.
    budget_is_limit = budget is not None and (
        total_space is None or total_space > budget
    )
    budget_remaining = (
        max(0, budget - attempts_base) if budget is not None else None
    )

    started = time.monotonic()
    attempts = attempts_base
    submitted = 0
    matched: str | None = None
    cancelled = False
    budget_stopped = False
    max_outstanding = max(workers * _OUTSTANDING_FACTOR, 4)

    context = multiprocessing.get_context("spawn")
    executor = ProcessPoolExecutor(max_workers=workers, mp_context=context)
    pending: dict[Future, tuple[int, int]] = {}  # future -> (batch_size, batch_offset)

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    def finish(new_status: str, message: str = "") -> RunResult:
        executor.shutdown(wait=False, cancel_futures=True)
        return RunResult(
            status=new_status,
            attempts=attempts,
            elapsed_ms=elapsed_ms(),
            workers=workers,
            matched_plaintext=matched,
            message=message,
        )

    paused = False
    interrupted = False
    try:
        batch_iter = skip_source(iter(batch_source), skip_count)
        exhausted = False
        while True:
            # Submit new batches while there is capacity and no stop signal.
            while not exhausted and len(pending) < max_outstanding:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                if pause_event is not None and pause_event.is_set():
                    paused = True
                    exhausted = True
                    break
                if budget_remaining is not None and submitted >= budget_remaining:
                    budget_stopped = True
                    exhausted = True
                    break
                try:
                    batch = next(batch_iter)
                except StopIteration:
                    exhausted = True
                    break
                if budget_remaining is not None:
                    batch = batch[: budget_remaining - submitted]
                if not batch:
                    continue
                offset = attempts_base + submitted
                submitted += len(batch)
                future = executor.submit(_hash_batch, batch, algorithm, target_hash, salt)
                pending[future] = (len(batch), offset)

            if cancelled or matched is not None or not pending:
                break

            future = min(pending, key=lambda item: pending[item][1])
            batch_size, offset = pending.pop(future)
            hit, cancelled, pause_requested = _await_ordered_batch(
                future, cancel_event, pause_event
            )
            if pause_requested:
                paused = True
                exhausted = True
            if cancelled:
                break
            if hit is not None:
                match_index, matched = hit
                attempts = offset + match_index + 1
                break
            attempts = max(attempts, offset + batch_size)
            if progress_callback is not None:
                fraction = min(attempts / total_space, 1.0) if total_space else None
                progress_callback(attempts, elapsed_ms(), fraction)
    except KeyboardInterrupt:
        # Operator pressed Ctrl+C; report as interrupted rather than a
        # deliberate cancellation through cancel_event.
        interrupted = True
    except Exception:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if matched is not None:
            status = STATUS_MATCH
        elif interrupted:
            status = STATUS_INTERRUPTED
        elif cancelled:
            status = STATUS_CANCELLED
        elif paused:
            status = STATUS_PAUSED
        elif budget_is_limit and budget_stopped:
            status = STATUS_BUDGET_EXHAUSTED
        else:
            status = STATUS_NO_MATCH
    result = finish(status)
    if result.status == STATUS_PAUSED:
        result.resume = {
            "attempts_base": result.attempts,
            "skip_source": skip_count + submitted,
        }
    return result


@dataclass
class HashlistResult:
    """Terminal outcome of one multi-target (hashlist) audit run."""

    status: str
    attempts: int
    elapsed_ms: int
    workers: int
    targets: list[dict]
    message: str = ""


def _hash_batch_multi(
    batch: list[str], targets_by_algorithm: dict[str, dict[str, list[int]]]
) -> tuple[int, dict[int, tuple[int, str]]] | None:
    """Hash each candidate once per target algorithm; report all matches.

    ``targets_by_algorithm`` maps algorithm -> digest -> list of target ids.
    Returns (candidates_examined, {target_id: (index, plaintext)}) for every
    target matched in the batch, or None. Runs inside worker processes and
    must stay a module-level function for spawn pickling on Windows.
    """
    target_count = sum(
        len(target_ids)
        for digest_map in targets_by_algorithm.values()
        for target_ids in digest_map.values()
    )
    matched: dict[int, tuple[int, str]] = {}
    for index, candidate in enumerate(batch):
        for algorithm, digest_map in targets_by_algorithm.items():
            digest = hash_candidate(candidate, algorithm)
            for target_id in digest_map.get(digest, ()):
                matched.setdefault(target_id, (index, candidate))
        if len(matched) == target_count:
            return index + 1, matched
    return (len(batch), matched) if matched else None


def run_hashlist_audit(
    targets: list[dict],
    batch_source: Iterator[list[str]],
    *,
    workers: int = DEFAULT_WORKERS,
    budget: int | None = None,
    total_space: int | None = None,
    cancel_event: Any = None,
    progress_callback: Callable[[int, int, float | None], None] | None = None,
) -> HashlistResult:
    """Compare one candidate stream against many targets in a single pass.

    ``targets`` is a list of ``{"id", "algorithm", "hash"}`` entries with
    explicit, already-validated algorithms (see candidates.parse_hashlist).
    The stream runs until every target has matched, the source is exhausted,
    the budget is reached, or cancellation fires. Every candidate is hashed
    once per distinct target algorithm and probed against all of that
    algorithm's targets.

    Returns a :class:`HashlistResult` whose ``targets`` list carries each
    target's status, matched plaintext, and the attempt number of its match.
    """
    workers = clamp_workers(workers)
    if budget is not None and (budget < 1 or budget > HARD_MAX_BUDGET):
        raise EngineInputError(
            f"The candidate budget must be between 1 and {HARD_MAX_BUDGET:,}."
        )

    targets_by_algorithm: dict[str, dict[str, list[int]]] = {}
    for target in targets:
        targets_by_algorithm.setdefault(target["algorithm"], {}).setdefault(
            target["hash"], []
        ).append(target["id"])
    unmatched_count = len(targets)
    budget_is_limit = budget is not None and (
        total_space is None or total_space > budget
    )

    started = time.monotonic()
    attempts = 0
    submitted = 0
    cancelled = False
    interrupted = False
    budget_stopped = False
    matched_plaintext: dict[int, str] = {}
    matched_attempt: dict[int, int] = {}

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    def finish(new_status: str, message: str = "") -> HashlistResult:
        executor.shutdown(wait=False, cancel_futures=True)
        target_results = []
        for target in targets:
            tid = target["id"]
            matched = tid in matched_plaintext
            target_results.append(
                {
                    "id": tid,
                    "algorithm": target["algorithm"],
                    "hash": target["hash"],
                    "status": STATUS_MATCH if matched else STATUS_NO_MATCH,
                    "matched_plaintext": matched_plaintext.get(tid),
                    "match_at_attempt": matched_attempt.get(tid),
                }
            )
        return HashlistResult(
            status=new_status,
            attempts=attempts,
            elapsed_ms=elapsed_ms(),
            workers=workers,
            targets=target_results,
            message=message,
        )

    max_outstanding = max(workers * _OUTSTANDING_FACTOR, 4)
    context = multiprocessing.get_context("spawn")
    executor = ProcessPoolExecutor(max_workers=workers, mp_context=context)
    pending: dict[Future, tuple[int, int]] = {}  # future -> (batch_size, offset)

    interrupted = False
    try:
        batch_iter = iter(batch_source)
        exhausted = False
        while True:
            while not exhausted and len(pending) < max_outstanding:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                if budget is not None and submitted >= budget:
                    budget_stopped = True
                    exhausted = True
                    break
                try:
                    batch = next(batch_iter)
                except StopIteration:
                    exhausted = True
                    break
                if budget is not None:
                    batch = batch[: budget - submitted]
                if not batch:
                    continue
                offset = submitted
                submitted += len(batch)
                future = executor.submit(
                    _hash_batch_multi, batch, targets_by_algorithm
                )
                pending[future] = (len(batch), offset)

            if cancelled or not pending:
                break

            future = min(pending, key=lambda item: pending[item][1])
            batch_size, offset = pending.pop(future)
            hit, cancelled, _ = _await_ordered_batch(future, cancel_event)
            if cancelled:
                break
            if hit is not None:
                candidates_examined, batch_matches = hit
                attempts = max(attempts, offset + candidates_examined)
                for target_id, (match_index, plaintext) in batch_matches.items():
                    matched_plaintext.setdefault(target_id, plaintext)
                    matched_attempt.setdefault(
                        target_id, offset + match_index + 1
                    )
                if len(matched_plaintext) == unmatched_count:
                    attempts = max(matched_attempt.values())
                    break
            else:
                attempts = max(attempts, offset + batch_size)
            if progress_callback is not None:
                fraction = min(attempts / total_space, 1.0) if total_space else None
                progress_callback(attempts, elapsed_ms(), fraction)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if interrupted:
            status = STATUS_INTERRUPTED
        elif cancelled:
            status = STATUS_CANCELLED
        elif matched_plaintext:
            status = STATUS_MATCH
        elif budget_is_limit and budget_stopped:
            status = STATUS_BUDGET_EXHAUSTED
        else:
            status = STATUS_NO_MATCH
    return finish(status)
