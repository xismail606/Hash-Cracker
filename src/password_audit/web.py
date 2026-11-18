"""Local Flask web dashboard: JSON API and static frontend serving.

The server binds to ``127.0.0.1`` only; there is no host override. State
changing routes require a same-origin request plus an anti-CSRF token issued
by ``GET /api/session`` (double-submit cookie + header). One dashboard audit
job may run at a time; the CLI can run separately.

Wordlist uploads are limited to 256 MiB and are stored as temporary files
that are deleted after completion, cancellation, validation failure, or
application shutdown. The browser never sees temporary file paths or raw
exception traces.
"""

from __future__ import annotations

import atexit
import contextlib
import csv as _csv
import io as _io
import json
import logging
import os
import secrets
import shutil
import tempfile
import threading
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from .algorithms import (
    ALGORITHM_LABELS,
    ALGORITHM_LENGTHS,
    ALGORITHM_NAMES,
    HashInputError,
    assess_hash,
    is_adaptive,
    is_salted,
    select_algorithm,
)
from .bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    iter_bruteforce_batches,
    list_charset_presets,
    resolve_charset,
    validate_bruteforce_options,
)
from .candidates import iter_wordlist_batches, parse_hashlist
from .engine import (
    DEFAULT_WORKERS,
    MAX_WORKERS,
    STATUS_PAUSED,
)
from .history import (
    DEFAULT_DB_PATH,
    EXPORT_COLUMNS,
    HistoryError,
    clear_runs,
    combine_report_rows,
    connect,
    decrypt_stored,
    export_batches,
    export_rows,
    init_encryption,
    is_encrypted_value,
    list_runs,
    utc_now,
)
from .job_execution import (
    STATE_RUNNING,
    STATE_VALIDATING,
    AuditJobRequest,
    AuditJobRunner,
    CandidateSource,
    DashboardJob,
    new_job_id,
)
from .rules import iter_rule_expanded, list_rules_presets, resolve_rules_preset

MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MiB
UPLOAD_CHUNK = 1024 * 1024
DEFAULT_PORT = 8765

# Abandoned paused-job records older than this are removed at startup.
PAUSED_JOB_RETENTION_DAYS = 7

_LOGGER = logging.getLogger(__name__)

# Terminal job states used by the API.
_STATE_QUEUED = "queued"


class AuditPreparationError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def create_app(
    static_folder: str | Path | None = None,
    db_path: str | Path | None = None,
) -> Flask:
    """Create the local dashboard Flask application.

    ``db_path`` overrides the SQLite history location (used by tests and the
    CLI ``--database`` flag); ``None`` uses the default user-local path.
    """
    if not db_path:
        db_path = DEFAULT_DB_PATH
    db_path = str(db_path)
    if static_folder is None:
        static_folder = Path(__file__).parent / "static"
    app = Flask(
        __name__,
        static_folder=str(static_folder) if Path(static_folder).exists() else None,
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (1024 * 1024)

    @app.errorhandler(413)
    def upload_too_large(_error):
        return jsonify({"error": "The upload request exceeds the 256 MiB limit."}), 413

    # One active dashboard job at a time.
    app.config["_job_lock"] = threading.Lock()
    app.config["_job"] = None
    app.config["_decrypt_key"] = None
    # Temporary upload directory cleaned up on shutdown.
    upload_dir = Path(tempfile.mkdtemp(prefix="password_audit_uploads_"))
    app.config["_upload_dir"] = upload_dir

    def _cleanup_uploads() -> None:
        shutil.rmtree(upload_dir, ignore_errors=True)

    atexit.register(_cleanup_uploads)
    app.config["_cleanup_uploads"] = _cleanup_uploads

    # Paused jobs survive server restarts: their state (and any uploaded
    # wordlist/hashlist) is kept next to the history database.
    paused_dir = Path(db_path).expanduser().parent / "paused_jobs"

    def _secure_paused_path(path: Path, *, directory: bool = False) -> None:
        """Restrict paused-job artifacts to the current user (POSIX modes).

        The kept uploads can contain a real wordlist, so other local accounts
        must not be able to read them.
        """
        if os.name != "posix":
            return
        with contextlib.suppress(OSError):
            path.chmod(0o700 if directory else 0o600)

    def _persist_paused_job(job: DashboardJob) -> None:
        """Move a paused job's uploads out of the temp dir and record its
        state so the job can be resumed after a server restart."""
        paused_dir.mkdir(parents=True, exist_ok=True)
        _secure_paused_path(paused_dir, directory=True)
        record = {
            "job_id": job.job_id,
            "target_hash": job.target_hash,
            "algorithm": job.algorithm,
            "mode": job.mode,
            "workers": job.workers,
            "budget": job.budget,
            "salt": job.salt,
            "run_params": job.run_params,
            "resume_state": job.resume_state,
            "targets": job.targets,
            "plaintext_withheld": job.plaintext_withheld,
            "started_at": job.started_at,
            "attempts": job.attempts,
            "elapsed_ms": job.elapsed_ms,
        }
        for attr in ("temp_path", "temp_hashlist"):
            path = getattr(job, attr)
            if path is not None and path.is_file():
                if path.parent != paused_dir:
                    moved = paused_dir / path.name
                    shutil.move(str(path), moved)
                    setattr(job, attr, moved)
                    path = moved
                _secure_paused_path(path)
                record[attr] = path.name
        record_path = paused_dir / f"{job.job_id}.json"
        record_path.write_text(json.dumps(record), encoding="utf-8")
        _secure_paused_path(record_path)

    def _clear_persisted_job(job_id: str) -> None:
        with contextlib.suppress(OSError):
            (paused_dir / f"{job_id}.json").unlink(missing_ok=True)

    def _discard_paused_job(job: DashboardJob) -> None:
        """Delete a paused job's persisted state and its kept uploads."""
        _clear_persisted_job(job.job_id)
        for attr in ("temp_path", "temp_hashlist"):
            path = getattr(job, attr, None)
            if path is not None:
                with contextlib.suppress(OSError):
                    Path(path).unlink(missing_ok=True)

    def _cleanup_stale_paused_jobs() -> None:
        """Remove abandoned paused-job records past the retention window.

        The newest record is always kept because it is the one the dashboard
        restores; older leftovers (crashes, repeated pauses) are deleted
        together with their kept uploads so sensitive wordlists do not
        accumulate on disk.
        """
        if not paused_dir.is_dir():
            return
        try:
            records = sorted(
                paused_dir.glob("*.json"), key=lambda path: path.stat().st_mtime
            )
        except OSError:
            return
        cutoff = time.time() - PAUSED_JOB_RETENTION_DAYS * 86400
        for record_file in records[:-1]:
            try:
                if record_file.stat().st_mtime >= cutoff:
                    continue
                record = json.loads(record_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                record = {}
            for attr in ("temp_path", "temp_hashlist"):
                name = record.get(attr) if isinstance(record, dict) else None
                if name:
                    with contextlib.suppress(OSError):
                        (paused_dir / name).unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                record_file.unlink(missing_ok=True)

    def _load_paused_jobs() -> None:
        """Restore the newest persisted paused job, dropping stale leftovers."""
        if not paused_dir.is_dir():
            return
        _cleanup_stale_paused_jobs()
        try:
            record_files = sorted(
                paused_dir.glob("*.json"), key=lambda path: path.stat().st_mtime
            )
        except OSError:
            return
        for record_file in record_files:
            try:
                record = json.loads(record_file.read_text(encoding="utf-8"))
                job = DashboardJob(
                    job_id=record["job_id"],
                    state=STATUS_PAUSED,
                    target_hash=record.get("target_hash", ""),
                    algorithm=record.get("algorithm", ""),
                    mode=record.get("mode", ""),
                    workers=record.get("workers", DEFAULT_WORKERS),
                    budget=record.get("budget"),
                    salt=record.get("salt"),
                    resume_state=record.get("resume_state"),
                    run_params=record.get("run_params", {}),
                    temp_path=(
                        paused_dir / record["temp_path"]
                        if record.get("temp_path")
                        else None
                    ),
                    temp_hashlist=(
                        paused_dir / record["temp_hashlist"]
                        if record.get("temp_hashlist")
                        else None
                    ),
                    started_at=record.get("started_at", ""),
                    targets=record.get("targets"),
                    attempts=record.get("attempts", 0),
                    elapsed_ms=record.get("elapsed_ms", 0),
                    plaintext_withheld=record.get("plaintext_withheld", False),
                )
            except (OSError, ValueError, KeyError, TypeError):
                _LOGGER.warning("Skipping unreadable paused-job record %s", record_file)
                continue
            # Single-job dashboard: the newest persisted paused job wins.
            app.config["_job"] = job

    # --- static frontend -------------------------------------------------

    @app.get("/")
    def index():
        index_file = Path(static_folder) / "index.html"
        if not index_file.is_file():
            return jsonify(
                {
                    "error": "The dashboard frontend has not been built yet. "
                    "Run `npm install && npm run build` in the frontend/ directory, "
                    "then restart the server."
                }
            ), 503
        response = send_from_directory(str(static_folder), "index.html")
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    @app.get("/<path:asset>")
    def assets(asset: str):
        # Astro builds each page as <page>/index.html (directory format), so a
        # clean URL like /changelog resolves to that page's index file.
        target = Path(static_folder) / asset
        if target.is_dir():
            target = target / "index.html"
            asset = f"{asset}/index.html"
        if target.is_file():
            response = send_from_directory(str(static_folder), asset)
            response.headers["Cache-Control"] = "no-cache"
            return response
        return jsonify({"error": "Not found."}), 404

    # --- session / CSRF --------------------------------------------------

    def _csrf_protected():
        """Return an error response when the CSRF or same-origin check fails."""
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin:
            host = request.host
            if f"//{host}" not in origin:
                return jsonify({"error": "Cross-origin requests are not allowed."}), 403
        header_token = request.headers.get("X-CSRF-Token", "")
        cookie_token = request.cookies.get("pa_csrf", "")
        if not header_token or not cookie_token or header_token != cookie_token:
            return jsonify({"error": "Missing or invalid CSRF token."}), 403
        return None

    @app.get("/api/session")
    def session_token():
        token = secrets.token_urlsafe(32)
        response = jsonify({"csrf_token": token})
        response.set_cookie(
            "pa_csrf", token, httponly=False, samesite="Strict", path="/"
        )
        return response

    # --- supported formats (single source of truth for the UI) -----------

    @app.get("/api/formats")
    def formats():
        """Expose the supported-format registries for the dashboard.

        The Python registries are authoritative; the frontend renders from
        this response instead of duplicating the tables.
        """
        salted_by_length: dict[int, list[str]] = {}
        for name in ALGORITHM_LENGTHS:
            if is_salted(name):
                salted_by_length.setdefault(ALGORITHM_LENGTHS[name], []).append(name)
        algorithms = [
            {
                "name": name,
                "label": ALGORITHM_LABELS[name],
                "kind": (
                    "adaptive"
                    if is_adaptive(name)
                    else "salted"
                    if is_salted(name)
                    else "fast"
                ),
            }
            for name in ALGORITHM_NAMES
        ]
        return jsonify(
            {
                "algorithms": algorithms,
                "labels": dict(ALGORITHM_LABELS),
                "salted_by_length": salted_by_length,
                "charset_presets": list_charset_presets(),
                "rules_presets": list_rules_presets(),
                "max_workers": MAX_WORKERS,
                "default_workers": DEFAULT_WORKERS,
                "hard_max_candidates": HARD_MAX_BUDGET,
                "default_budget": DEFAULT_BUDGET,
            }
        )

    # --- identify --------------------------------------------------------

    @app.post("/api/identify")
    def identify():
        payload = request.get_json(silent=True) or {}
        value = payload.get("hash")
        if not isinstance(value, str):
            return jsonify({"error": "Request must include a JSON 'hash' string."}), 400
        try:
            assessment = assess_hash(value)
        except HashInputError as exc:
            return jsonify({"error": str(exc), "valid": False}), 400
        return jsonify(
            {
                "valid": True,
                "submitted": assessment.submitted.strip(),
                "normalized": assessment.normalized,
                "compatible_algorithms": list(assessment.compatible_algorithms),
                "ambiguous": assessment.ambiguous,
            }
        )

    # --- audits ----------------------------------------------------------

    def _validate_audit_params(algorithm: str, workers_raw, target: str):
        if algorithm not in ALGORITHM_NAMES:
            return None, (
                f"Unsupported algorithm {algorithm!r}. Supported: {', '.join(ALGORITHM_NAMES)}."
            )
        try:
            assessment, _ = select_algorithm(target, algorithm)
        except HashInputError as exc:
            return None, str(exc)
        try:
            workers = int(workers_raw)
        except (TypeError, ValueError):
            return None, "Worker count must be an integer."
        if workers < 1 or workers > MAX_WORKERS:
            return None, f"Worker count must be between 1 and {MAX_WORKERS}."
        return {"target": assessment.normalized, "workers": workers}, None

    def _start_job(
        job_request: AuditJobRequest,
    ) -> tuple[DashboardJob | None, dict | None]:
        job = _create_dashboard_job(job_request)
        error, discarded_paused = _reserve_job(job)
        if error is not None:
            return None, error
        if discarded_paused is not None:
            _discard_paused_job(discarded_paused)
        runner = AuditJobRunner(job, job_request, db_path, on_pause=_persist_paused_job)
        job.thread = threading.Thread(target=runner.run, daemon=True)
        job.thread.start()
        return job, None

    def _create_dashboard_job(job_request: AuditJobRequest) -> DashboardJob:
        return DashboardJob(
            job_id=new_job_id(),
            started_at=utc_now(),
            run_params=_dashboard_run_params(job_request),
            **_dashboard_job_fields(job_request),
        )

    def _dashboard_job_fields(job_request: AuditJobRequest) -> dict:
        params = job_request.params
        source = job_request.source
        return {
            "target_hash": params["target"],
            "algorithm": params["algorithm"],
            "mode": job_request.mode,
            "workers": params["workers"],
            "budget": source.budget,
            "salt": job_request.salt,
            "targets": job_request.targets,
            "plaintext_withheld": job_request.plaintext_withheld,
            "temp_path": source.temp_path,
            "temp_hashlist": job_request.temp_hashlist,
        }

    def _dashboard_run_params(job_request: AuditJobRequest) -> dict:
        source = job_request.source
        return {
            **job_request.params,
            "mode": job_request.mode,
            "salt": job_request.salt,
            "wordlist_size": (
                os.path.getsize(source.temp_path)
                if source.temp_path is not None and job_request.mode == "dictionary"
                else None
            ),
        }

    def _reserve_job(job: DashboardJob) -> tuple[dict | None, DashboardJob | None]:
        """Reserve the single job slot; return (error, discarded paused job)."""
        with app.config["_job_lock"]:
            active = app.config["_job"]
            paused_job = None
            if (
                active is not None
                and active.state == STATUS_PAUSED
                and active.thread is None
            ):
                # A paused job restored after a restart; starting a new audit
                # abandons it (its persisted state is removed).
                paused_job = active
                active = None
            if active is not None and active.state in (
                STATE_VALIDATING,
                _STATE_QUEUED,
                STATE_RUNNING,
            ):
                return {
                    "error": "Another dashboard audit is already running. "
                    "Cancel it or wait for it to finish."
                }, None
            app.config["_job"] = job
        return None, paused_job

    def _remove_temp_file(path: Path | None) -> None:
        if path is not None:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)

    def _save_upload(file_storage) -> tuple[Path | None, dict | None]:
        """Stream an upload to a temporary file; enforce the 256 MiB limit."""
        fd, raw_name = tempfile.mkstemp(dir=str(app.config["_upload_dir"]), suffix=".txt")
        temp_path = Path(raw_name)
        try:
            size = 0
            with os.fdopen(fd, "wb") as handle:
                while True:
                    chunk = file_storage.stream.read(UPLOAD_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise ValueError("oversize")
                    handle.write(chunk)
        except ValueError:
            _remove_temp_file(temp_path)
            return None, {
                "error": "The wordlist upload exceeds the 256 MiB limit."
            }
        except OSError:
            _remove_temp_file(temp_path)
            return None, {"error": "The wordlist upload could not be stored temporarily."}
        return temp_path, None

    def _resolve_variants(mode: str, rules_name: str):
        if rules_name == "none":
            return None
        if mode != "dictionary":
            raise AuditPreparationError("Rules apply to dictionary mode only.")
        try:
            return resolve_rules_preset(rules_name)
        except ValueError as exc:
            raise AuditPreparationError(str(exc)) from exc

    def _prepare_dictionary_source(variants_for) -> CandidateSource:
        upload = request.files.get("wordlist")
        if upload is None or not upload.filename:
            raise AuditPreparationError("Dictionary mode requires a wordlist upload.")
        temp_path, error = _save_upload(upload)
        if error is not None:
            status = 413 if "256 MiB" in error["error"] else 400
            raise AuditPreparationError(error["error"], status)
        assert temp_path is not None
        batch_source = iter_wordlist_batches(temp_path)
        budget = None
        if variants_for is not None:
            # Rule-expanded streams are bounded like brute-force runs; the
            # operator selects the budget (default 1,000,000).
            try:
                budget = int(
                    request.form.get("max_candidates", str(DEFAULT_BUDGET))
                )
            except ValueError as exc:
                raise AuditPreparationError(
                    "The candidate budget must be an integer."
                ) from exc
            batch_source = iter_rule_expanded(batch_source, variants_for, budget)
        return CandidateSource(batch_source, budget, None, temp_path)

    def _prepare_bruteforce_source() -> CandidateSource:
        try:
            alphabet = resolve_charset(request.form.get("charset", ""))
            min_length = int(request.form.get("min_length", ""))
            max_length = int(request.form.get("max_length", ""))
            budget = int(request.form.get("max_candidates", str(DEFAULT_BUDGET)))
            alphabet, total_space = validate_bruteforce_options(
                min_length, max_length, budget, alphabet
            )
        except (HashInputError, ValueError) as exc:
            raise AuditPreparationError(
                "Invalid brute-force settings: charset, length range, "
                f"and a candidate budget up to {HARD_MAX_BUDGET:,} are required."
            ) from exc
        batch_source = iter_bruteforce_batches(
            alphabet, min_length, max_length, budget
        )
        return CandidateSource(batch_source, budget, total_space, None)

    def _prepare_candidate_source(mode: str, rules_name: str) -> CandidateSource:
        variants_for = _resolve_variants(mode, rules_name)
        if mode == "dictionary":
            return _prepare_dictionary_source(variants_for)
        if mode == "brute-force":
            return _prepare_bruteforce_source()
        raise AuditPreparationError("Mode must be 'dictionary' or 'brute-force'.")

    def _prepare_resume_source(job: DashboardJob, params: dict) -> CandidateSource:
        if params["mode"] == "dictionary":
            return _prepare_dictionary_resume(job, params)
        return _prepare_bruteforce_resume(params)

    def _prepare_dictionary_resume(job: DashboardJob, params: dict) -> CandidateSource:
        wordlist = job.temp_path
        if wordlist is None or not wordlist.is_file():
            raise AuditPreparationError(
                "The uploaded wordlist is gone; re-start the audit."
            )
        size = os.path.getsize(str(wordlist))
        if params.get("wordlist_size") not in (None, size):
            raise AuditPreparationError(
                "The wordlist changed since the pause; resume is refused."
            )
        batch_source = iter_wordlist_batches(wordlist)
        budget = None
        variants_for = resolve_rules_preset(params.get("rules_name", "none"))
        if variants_for is not None:
            try:
                budget = int(params["max_candidates"])
            except (KeyError, ValueError) as exc:
                raise AuditPreparationError(
                    "Stored rule-expansion budget is invalid."
                ) from exc
            batch_source = iter_rule_expanded(batch_source, variants_for, budget)
        return CandidateSource(batch_source, budget, None, wordlist)

    def _prepare_bruteforce_resume(params: dict) -> CandidateSource:
        try:
            alphabet = resolve_charset(params["charset"])
            min_length = int(params["min_length"])
            max_length = int(params["max_length"])
            budget = int(params["max_candidates"])
            alphabet, total_space = validate_bruteforce_options(
                min_length, max_length, budget, alphabet
            )
        except (HashInputError, ValueError) as exc:
            raise AuditPreparationError(
                "Stored brute-force params are invalid."
            ) from exc
        batches = iter_bruteforce_batches(alphabet, min_length, max_length, budget)
        return CandidateSource(batches, budget, total_space, None)

    def _start_resumed_job(job: DashboardJob) -> None:
        source = _prepare_resume_source(job, job.run_params)
        request_data = AuditJobRequest(
            params=job.run_params,
            mode=job.run_params["mode"],
            source=source,
            temp_hashlist=job.temp_hashlist,
            salt=job.salt,
            targets=job.targets,
            plaintext_withheld=job.plaintext_withheld,
        )
        job.pause_event.clear()
        job.resume_state = job.resume_state or {}
        runner = AuditJobRunner(
            job, request_data, db_path, on_pause=_persist_paused_job
        )
        job.thread = threading.Thread(target=runner.run, daemon=True)
        job.thread.start()
        # The job is running again; its restart-recovery record is obsolete.
        _clear_persisted_job(job.job_id)

    def _read_hashlist_upload() -> tuple[list[dict] | None, Path | None]:
        hashlist_file = request.files.get("hashlist")
        if hashlist_file is None or not hashlist_file.filename:
            return None, None
        temp_hashlist, error = _save_upload(hashlist_file)
        if error is not None:
            raise AuditPreparationError(error["error"])
        assert temp_hashlist is not None
        try:
            return parse_hashlist(temp_hashlist), temp_hashlist
        except HashInputError as exc:
            _remove_temp_file(temp_hashlist)
            raise AuditPreparationError(f"Invalid hashlist: {exc}") from exc

    def _prepare_target_params(
        targets: list[dict] | None,
    ) -> tuple[dict, str | None]:
        if targets is not None:
            return _prepare_hashlist_params()
        return _prepare_single_target_params()

    def _prepare_hashlist_params() -> tuple[dict, str | None]:
        salt = (request.form.get("salt") or "").strip()
        if salt:
            raise AuditPreparationError(
                "--salt is not supported with hashlists (no per-target salt)."
            )
        try:
            workers = int(request.form.get("workers") or DEFAULT_WORKERS)
        except (TypeError, ValueError) as exc:
            raise AuditPreparationError("Worker count must be an integer.") from exc
        if workers < 1 or workers > MAX_WORKERS:
            raise AuditPreparationError(
                f"Worker count must be between 1 and {MAX_WORKERS}."
            )
        return {"target": "", "algorithm": "hashlist", "workers": workers}, None

    def _prepare_single_target_params() -> tuple[dict, str | None]:
        algorithm = request.form.get("algorithm", "")
        target = request.form.get("hash", "")
        salt = (request.form.get("salt") or "").strip()
        if not algorithm:
            raise AuditPreparationError("An algorithm is required.")
        params, error = _validate_audit_params(
            algorithm, request.form.get("workers"), target
        )
        if error is not None:
            raise AuditPreparationError(error)
        params["algorithm"] = algorithm
        _validate_salt(algorithm, salt)
        return params, salt or None

    def _validate_salt(algorithm: str, salt: str) -> None:
        if is_salted(algorithm) and not salt:
            raise AuditPreparationError(f"Salted format {algorithm} requires a salt value.")
        if salt and not is_salted(algorithm):
            raise AuditPreparationError(f"Algorithm {algorithm} does not take a salt.")

    def _candidate_options(rules_name: str) -> dict:
        return {
            "charset": request.form.get("charset", ""),
            "min_length": request.form.get("min_length", ""),
            "max_length": request.form.get("max_length", ""),
            "max_candidates": request.form.get(
                "max_candidates", str(DEFAULT_BUDGET)
            ),
            "rules_name": rules_name,
        }

    def _complete_audit_request(
        mode: str,
        targets: list[dict] | None,
        temp_hashlist: Path | None,
        plaintext_withheld: bool,
    ) -> AuditJobRequest:
        params, salt = _prepare_target_params(targets)
        rules_name = (request.form.get("rules") or "none").strip()
        params.update(_candidate_options(rules_name))
        source = _prepare_candidate_source(mode, rules_name)
        return AuditJobRequest(
            params=params,
            mode=mode,
            source=source,
            temp_hashlist=temp_hashlist,
            salt=salt,
            targets=targets,
            plaintext_withheld=plaintext_withheld,
        )

    def _build_audit_request() -> AuditJobRequest:
        if request.form.get("acknowledge_retention") != "true":
            raise AuditPreparationError(
                "You must acknowledge the local plaintext/hash retention warning "
                "before starting an audit."
            )
        targets, temp_hashlist = _read_hashlist_upload()
        try:
            return _complete_audit_request(
                request.form.get("mode", ""),
                targets,
                temp_hashlist,
                request.form.get("store_plaintext", "true") == "false",
            )
        except AuditPreparationError:
            _remove_temp_file(temp_hashlist)
            raise

    @app.post("/api/audits")
    def start_audit():
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        try:
            job_request = _build_audit_request()
        except AuditPreparationError as exc:
            return jsonify({"error": str(exc)}), exc.status_code
        job, error = _start_job(job_request)
        if job is None or error is not None:
            _remove_temp_file(job_request.source.temp_path)
            _remove_temp_file(job_request.temp_hashlist)
            return jsonify(error), 409
        return jsonify({"job_id": job.job_id, "state": job.state}), 202

    @app.get("/api/audits/<job_id>")
    def audit_status(job_id: str):
        job = app.config["_job"]
        if job is None or job.job_id != job_id:
            return jsonify({"error": "Unknown job ID."}), 404
        payload = {
            "job_id": job.job_id,
            "state": job.state,
            "mode": job.mode,
            "algorithm": job.algorithm,
            "workers": job.workers,
            "attempts": job.attempts,
            "elapsed_ms": job.elapsed_ms,
            "budget": job.budget,
        }
        if job.result is not None:
            payload["result"] = job.result
        if job.error is not None:
            payload["error"] = job.error
        return jsonify(payload)

    @app.post("/api/audits/<job_id>/cancel")
    def cancel_audit(job_id: str):
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        job = app.config["_job"]
        if job is None or job.job_id != job_id:
            return jsonify({"error": "Unknown job ID."}), 404
        if job.state == STATUS_PAUSED and job.thread is None:
            # A paused (possibly restart-restored) job: finalize as cancelled
            # and discard its persisted recovery state and kept uploads.
            job.state = "cancelled"
            job.result = {
                "status": "cancelled",
                "attempts": job.attempts,
                "elapsed_ms": job.elapsed_ms,
            }
            _discard_paused_job(job)
            return jsonify({"job_id": job.job_id, "state": job.state})
        job.cancel_event.set()
        return jsonify({"job_id": job.job_id, "state": job.state, "cancelling": True})

    @app.post("/api/audits/<job_id>/pause")
    def pause_audit(job_id: str):
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        job = app.config["_job"]
        if job is None or job.job_id != job_id:
            return jsonify({"error": "Unknown job ID."}), 404
        if job.state != STATE_RUNNING:
            return jsonify({"error": "Only a running job can be paused."}), 400
        job.pause_event.set()
        return jsonify({"job_id": job.job_id, "state": job.state, "pausing": True}), 202

    @app.post("/api/audits/<job_id>/resume")
    def resume_audit(job_id: str):
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        job = app.config["_job"]
        if job is None or job.job_id != job_id:
            return jsonify({"error": "Unknown job ID."}), 404
        if job.state != STATUS_PAUSED:
            return jsonify({"error": "Only a paused job can be resumed."}), 400
        try:
            _start_resumed_job(job)
        except AuditPreparationError as exc:
            return jsonify({"error": str(exc)}), exc.status_code
        return jsonify({"job_id": job.job_id, "state": STATE_RUNNING, "resumed": True})

    # --- history ---------------------------------------------------------

    @app.get("/api/history")
    def history():
        try:
            conn = connect(db_path)
            records = list_runs(conn, limit=100)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 500
        decrypt_key = app.config.get("_decrypt_key")
        payload_records = []
        encrypted_count = 0
        for record in records:
            data = record.as_dict()
            if is_encrypted_value(data.get("matched_plaintext")):
                encrypted_count += 1
                if decrypt_key is not None:
                    try:
                        data["matched_plaintext"] = decrypt_stored(
                            decrypt_key, data["matched_plaintext"]
                        )
                    except HistoryError:
                        data["matched_plaintext"] = "<decryption failed>"
                else:
                    data["matched_plaintext"] = "<encrypted>"
            payload_records.append(data)
        return jsonify(
            {
                "records": payload_records,
                "encrypted_count": encrypted_count,
                "sensitive_note": "Successful matches include the recovered "
                "plaintext/hash pair stored locally.",
            }
        )

    @app.post("/api/history/unlock")
    def history_unlock():
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        payload = request.get_json(silent=True) or {}
        passphrase = payload.get("passphrase", "")
        if not passphrase:
            return jsonify({"error": "A passphrase is required."}), 400
        try:
            conn = connect(db_path)
            key = init_encryption(conn, passphrase)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 403
        app.config["_decrypt_key"] = key
        return jsonify({"unlocked": True})

    @app.get("/api/export")
    def export_report():
        """Download the full local history as CSV or JSON."""
        fmt = (request.args.get("format") or "csv").lower()
        try:
            conn = connect(db_path)
            rows = export_rows(conn)
            batches = export_batches(conn)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 500
        if fmt == "json":
            payload = {"runs": rows, "batches": batches}
            return Response(
                json.dumps(payload, indent=2),
                mimetype="application/json",
                headers={
                    "Content-Disposition": "attachment; filename=audit-history.json"
                },
            )
        buf = _io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(combine_report_rows(rows, batches))
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit-history.csv"},
        )

    @app.post("/api/history/clear")
    def history_clear():
        """Permanently delete every local audit record (destructive, CSRF-protected)."""
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        try:
            conn = connect(db_path)
            deleted = clear_runs(conn)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({"deleted": deleted})

    # Restart recovery: restore any paused job persisted before a shutdown.
    _load_paused_jobs()

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=DEFAULT_PORT, threaded=True)
