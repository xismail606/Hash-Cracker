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
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass
from typing import Any

from .bruteforce import DEFAULT_BUDGET, HARD_MAX_BUDGET
from .hashing import hash_candidate

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

# How many batches may be outstanding at once; keeps memory bounded while
# keeping every worker fed.
_OUTSTANDING_FACTOR = 2


class EngineInputError(ValueError):
    """Raised when audit options are invalid before any candidate work."""


@dataclass
class RunResult:
    """Terminal outcome of one audit run."""

    status: str
    attempts: int
    elapsed_ms: int
    workers: int
    matched_plaintext: str | None = None
    message: str = ""


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
        if hash_candidate(candidate, algorithm, salt) == target:
            return index, candidate
    return None


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
    budget_is_limit = budget is not None and total_space is not None and total_space > budget

    started = time.monotonic()
    attempts = 0
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

    interrupted = False
    try:
        batch_iter = iter(batch_source)
        exhausted = False
        while True:
            # Submit new batches while there is capacity and no stop signal.
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
                offset = submitted
                submitted += len(batch)
                future = executor.submit(_hash_batch, batch, algorithm, target_hash, salt)
                pending[future] = (len(batch), offset)

            if cancelled or matched is not None or not pending:
                break

            done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
            stop = False
            for future in sorted(done, key=lambda f: pending[f][1]):
                batch_size, offset = pending.pop(future)
                hit = future.result()
                if hit is not None:
                    match_index, match_value = hit
                    matched = match_value
                    attempts = offset + match_index + 1
                    stop = True
                    break
                # Batches may complete out of order; attempts must stay
                # monotonic in submission order.
                attempts = max(attempts, offset + batch_size)
                if progress_callback is not None:
                    fraction = min(attempts / total_space, 1.0) if total_space else None
                    progress_callback(attempts, elapsed_ms(), fraction)
            if stop:
                break
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
        elif budget_is_limit and budget_stopped:
            status = STATUS_BUDGET_EXHAUSTED
        else:
            status = STATUS_NO_MATCH
    return finish(status)
