"""Run dashboard audits and persist their local results."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .engine import (
    DEFAULT_WORKERS,
    STATUS_MATCH,
    STATUS_PAUSED,
    run_audit,
    run_hashlist_audit,
)
from .history import (
    HistoryError,
    connect,
    record_batch,
    record_run,
    utc_now,
)

_LOGGER = logging.getLogger(__name__)

_STATE_RUNNING = "running"
_STATE_VALIDATING = "validating"


@dataclass
class CandidateSource:
    batch_source: Iterator[list[str]]
    budget: int | None
    total_space: int | None
    temp_path: Path | None


@dataclass
class AuditJobRequest:
    params: dict
    mode: str
    source: CandidateSource
    temp_hashlist: Path | None
    salt: str | None
    targets: list[dict] | None
    plaintext_withheld: bool


@dataclass
class DashboardJob:
    """Mutable state exposed to the dashboard while one audit runs."""

    job_id: str
    state: str = _STATE_VALIDATING
    target_hash: str = ""
    algorithm: str = ""
    mode: str = ""
    workers: int = DEFAULT_WORKERS
    budget: int | None = None
    salt: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    pause_event: threading.Event = field(default_factory=threading.Event)
    resume_state: dict | None = None
    run_params: dict = field(default_factory=dict)
    thread: threading.Thread | None = None
    temp_path: Path | None = None
    temp_hashlist: Path | None = None
    started_at: str = ""
    targets: list[dict] | None = None
    result: dict | None = None
    error: str | None = None
    attempts: int = 0
    elapsed_ms: int = 0
    plaintext_withheld: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


class AuditJobRunner:
    def __init__(
        self,
        job: DashboardJob,
        request: AuditJobRequest,
        db_path: str,
    ) -> None:
        self.job = job
        self.request = request
        self.db_path = db_path

    def run(self) -> None:
        self.job.state = _STATE_RUNNING
        try:
            self._run_job(utc_now())
        except Exception:
            _LOGGER.exception("Dashboard audit failed unexpectedly")
            self.job.error = "The audit failed unexpectedly; no result was recorded."
            self.job.state = "interrupted"
        finally:
            self._cleanup_uploads()

    def _run_job(self, started_at: str) -> None:
        if self.request.targets is None:
            self._run_single_target(started_at)
            return
        self._run_hashlist(started_at)

    def _run_hashlist(self, started_at: str) -> None:
        outcome = self._execute_hashlist()
        self.job.result = hashlist_job_result(self.job, outcome)
        self.job.attempts = outcome.attempts
        self.job.elapsed_ms = outcome.elapsed_ms
        self._record_hashlist(outcome, started_at)

    def _record_hashlist(self, outcome, started_at: str) -> None:
        try:
            batch_id = self._persist_hashlist(outcome, started_at)
            self.job.result["batch_id"] = batch_id[:8]
            self.job.state = outcome.status
        except HistoryError:
            self.job.error = (
                "The hashlist run finished but could not be recorded in local history."
            )
            self.job.state = outcome.status

    def _persist_hashlist(self, outcome, started_at: str) -> str:
        conn = connect(self.db_path)
        batch_id = uuid.uuid4().hex
        try:
            self._record_hashlist_batch(conn, batch_id, outcome, started_at)
            self._record_hashlist_targets(conn, outcome, batch_id, started_at)
        finally:
            conn.close()
        return batch_id

    def _record_hashlist_batch(self, conn, batch_id: str, outcome, started_at: str) -> None:
        record_batch(
            conn,
            batch_id=batch_id,
            mode=self.job.mode,
            status=outcome.status,
            attempts=outcome.attempts,
            elapsed_ms=outcome.elapsed_ms,
            worker_count=outcome.workers,
            started_at=started_at,
            target_count=len(outcome.targets),
        )

    def _record_hashlist_targets(self, conn, outcome, batch_id: str, started_at: str) -> None:
        for target in outcome.targets:
            record_run(
                conn,
                **self._hashlist_history_fields(target, outcome, batch_id, started_at),
            )

    def _hashlist_history_fields(
        self, target: dict, outcome, batch_id: str, started_at: str
    ) -> dict:
        match_attempt = target["match_at_attempt"]
        if match_attempt is None:
            match_attempt = outcome.attempts
        return {
            "target_hash": target["hash"],
            "algorithm": target["algorithm"],
            "mode": self.job.mode,
            "status": target["status"],
            "attempts": match_attempt,
            "elapsed_ms": outcome.elapsed_ms,
            "worker_count": outcome.workers,
            "started_at": started_at,
            "matched_plaintext": None if self.job.plaintext_withheld else target["matched_plaintext"],
            "batch_id": batch_id,
            "plaintext_withheld": self.job.plaintext_withheld,
        }

    def _execute_hashlist(self):
        source = self.request.source
        return run_hashlist_audit(
            self.request.targets,
            source.batch_source,
            workers=self.job.workers,
            budget=source.budget,
            total_space=source.total_space,
            cancel_event=self.job.cancel_event,
            progress_callback=self._progress,
        )

    def _run_single_target(self, started_at: str) -> None:
        outcome = self._execute_single_target()
        if outcome.status == STATUS_PAUSED:
            self.job.resume_state = outcome.resume
            self.job.state = STATUS_PAUSED
            return
        self.job.result = single_target_job_result(self.job, outcome)
        self.job.attempts = outcome.attempts
        self.job.elapsed_ms = outcome.elapsed_ms
        self._record_single_target(outcome, started_at)

    def _execute_single_target(self):
        source = self.request.source
        return run_audit(
            self.job.target_hash,
            self.job.algorithm,
            source.batch_source,
            workers=self.job.workers,
            budget=source.budget,
            total_space=source.total_space,
            salt=self.job.salt,
            cancel_event=self.job.cancel_event,
            pause_event=self.job.pause_event,
            resume_state=self.job.resume_state,
            progress_callback=self._progress,
        )

    def _record_single_target(self, outcome, started_at: str) -> None:
        try:
            self._persist_single_target(outcome, started_at)
            self.job.state = outcome.status
        except HistoryError:
            self._set_single_target_storage_error(outcome.status)

    def _persist_single_target(self, outcome, started_at: str) -> None:
        conn = connect(self.db_path)
        try:
            record_run(conn, **single_target_history_fields(self.job, outcome, started_at))
        finally:
            conn.close()

    def _set_single_target_storage_error(self, status: str) -> None:
        if status == STATUS_MATCH:
            self.job.result = None
            self.job.error = (
                "A match was found but it could not be recorded in "
                "local history (storage error); nothing is displayed."
            )
            self.job.state = "storage_error"
            return
        self.job.error = "The run finished but could not be recorded in local history."
        self.job.state = status

    def _progress(self, attempts: int, elapsed_ms: int, fraction: float | None) -> None:
        with self.job.lock:
            self.job.attempts = attempts
            self.job.elapsed_ms = elapsed_ms

    def _cleanup_uploads(self) -> None:
        if self.job.state == STATUS_PAUSED:
            return
        for path in (self.job.temp_path, self.job.temp_hashlist):
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass


def hashlist_job_result(job: DashboardJob, outcome) -> dict:
    return {
        "status": outcome.status,
        "attempts": outcome.attempts,
        "elapsed_ms": outcome.elapsed_ms,
        "workers": outcome.workers,
        "matched_plaintext": None,
        "target_hash": None,
        "targets": hashlist_target_results(job, outcome),
        "plaintext_withheld": job.plaintext_withheld,
    }


def hashlist_target_results(job: DashboardJob, outcome) -> list[dict]:
    return [
        {
            **target,
            "matched_plaintext": (
                None if job.plaintext_withheld else target["matched_plaintext"]
            ),
            "plaintext_withheld": job.plaintext_withheld,
        }
        for target in outcome.targets
    ]


def single_target_job_result(job: DashboardJob, outcome) -> dict:
    return {
        "status": outcome.status,
        "attempts": outcome.attempts,
        "elapsed_ms": outcome.elapsed_ms,
        "workers": outcome.workers,
        "matched_plaintext": (
            None if job.plaintext_withheld else outcome.matched_plaintext
        ),
        "target_hash": job.target_hash,
        "plaintext_withheld": job.plaintext_withheld,
    }


def single_target_history_fields(job: DashboardJob, outcome, started_at: str) -> dict:
    return {
        "target_hash": job.target_hash,
        "algorithm": job.algorithm,
        "mode": job.mode,
        "status": outcome.status,
        "attempts": outcome.attempts,
        "elapsed_ms": outcome.elapsed_ms,
        "worker_count": outcome.workers,
        "started_at": started_at,
        "matched_plaintext": (
            outcome.matched_plaintext
            if outcome.status == STATUS_MATCH and not job.plaintext_withheld
            else None
        ),
        "salt": job.salt or None,
        "plaintext_withheld": job.plaintext_withheld,
    }


def new_job_id() -> str:
    return uuid.uuid4().hex
