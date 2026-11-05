"""Local Flask web dashboard: JSON API and static frontend serving.

The server binds to ``127.0.0.1`` only; there is no host override. State
changing routes require a same-origin request plus an anti-CSRF token issued
by ``GET /api/session`` (double-submit cookie + header). One dashboard audit
job may run at a time; the CLI can run separately.

Wordlist uploads are limited to 100 MiB and are stored as temporary files
that are deleted after completion, cancellation, validation failure, or
application shutdown. The browser never sees temporary file paths or raw
exception traces.
"""

from __future__ import annotations

import atexit
import os
import secrets
import shutil
import tempfile
import threading
import uuid
import json
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .algorithms import (
    ALGORITHM_NAMES,
    HashInputError,
    assess_hash,
    is_salted,
    select_algorithm,
)
from .bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    iter_bruteforce_batches,
    resolve_charset,
    validate_bruteforce_options,
)
from .candidates import iter_wordlist_batches, parse_hashlist
from .engine import (
    DEFAULT_WORKERS,
    MAX_WORKERS,
    STATUS_MATCH,
    STATUS_PAUSED,
    run_audit,
    run_hashlist_audit,
)
from .rules import iter_rule_expanded, resolve_rules_preset
import csv as _csv
import io as _io

from flask import Response

from .history import (
    DEFAULT_DB_PATH,
    EXPORT_COLUMNS,
    decrypt_stored,
    export_batches,
    export_rows,
    init_encryption,
    is_encrypted_value,
    record_batch,
    HistoryError,
    clear_runs,
    connect,
    list_runs,
    record_run,
    utc_now,
)

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB
UPLOAD_CHUNK = 1024 * 1024
DEFAULT_PORT = 8765

# Terminal job states used by the API.
_STATE_QUEUED = "queued"
_STATE_RUNNING = "running"
_STATE_VALIDATING = "validating"


class DashboardJob:
    """State for one dashboard audit job."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.state = _STATE_VALIDATING
        self.target_hash = ""
        self.algorithm = ""
        self.mode = ""
        self.workers = DEFAULT_WORKERS
        self.budget = None
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.resume_state: dict | None = None
        self.run_params: dict = {}
        self.thread: threading.Thread | None = None
        self.temp_path: Path | None = None
        self.started_at = ""
        self.targets: list[dict] | None = None
        self.result: dict | None = None
        self.error: str | None = None
        self.attempts = 0
        self.elapsed_ms = 0
        self.lock = threading.Lock()


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
        target = Path(static_folder) / asset
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

    def _start_job(params: dict, mode: str, batch_source, budget, total_space, temp_path, salt=None, targets=None, plaintext_withheld=False) -> tuple[DashboardJob | None, dict | None]:
        job = DashboardJob(job_id=uuid.uuid4().hex)
        job.target_hash = params["target"]
        job.algorithm = params["algorithm"]
        job.mode = mode
        job.workers = params["workers"]
        job.budget = budget
        job.salt = salt
        job.targets = targets
        job.plaintext_withheld = plaintext_withheld
        job.temp_path = temp_path
        job.temp_hashlist = None
        job.started_at = utc_now()
        job.run_params = {
            **params,
            "mode": mode,
            "salt": salt,
            "wordlist_size": (
                os.path.getsize(str(temp_path)) if temp_path and mode == "dictionary" else None
            ),
        }

        def run_job():
            job.state = _STATE_RUNNING
            started = utc_now()
            try:
                if job.targets is not None:
                    hl = run_hashlist_audit(
                        job.targets,
                        batch_source,
                        workers=job.workers,
                        budget=budget,
                        total_space=total_space,
                        cancel_event=job.cancel_event,
                        progress_callback=_progress,
                    )
                    job.result = {
                        "status": hl.status,
                        "attempts": hl.attempts,
                        "elapsed_ms": hl.elapsed_ms,
                        "workers": hl.workers,
                        "matched_plaintext": None,
                        "target_hash": None,
                        "targets": hl.targets,
                    }
                    job.attempts = hl.attempts
                    job.elapsed_ms = hl.elapsed_ms
                    # Record per-target rows plus a batch summary.
                    try:
                        conn = connect(db_path)
                        batch_id = uuid.uuid4().hex
                        record_batch(
                            conn,
                            batch_id=batch_id,
                            mode=job.mode,
                            status=hl.status,
                            attempts=hl.attempts,
                            elapsed_ms=hl.elapsed_ms,
                            worker_count=hl.workers,
                            started_at=started,
                            target_count=len(hl.targets),
                        )
                        for t in hl.targets:
                            record_run(
                                conn,
                                target_hash=t["hash"],
                                algorithm=t["algorithm"],
                                mode=job.mode,
                                status=t["status"],
                                attempts=(
                                    t["match_at_attempt"]
                                    if t["match_at_attempt"] is not None
                                    else hl.attempts
                                ),
                                elapsed_ms=hl.elapsed_ms,
                                worker_count=hl.workers,
                                started_at=started,
                                matched_plaintext=t["matched_plaintext"],
                                batch_id=batch_id,
                            )
                        conn.close()
                        job.result["batch_id"] = batch_id[:8]
                        job.state = hl.status
                    except HistoryError:
                        job.error = "The hashlist run finished but could not be recorded in local history."
                        job.state = hl.status
                else:
                    result = run_audit(
                        job.target_hash,
                        job.algorithm,
                        batch_source,
                        workers=job.workers,
                        budget=budget,
                        total_space=total_space,
                        salt=job.salt,
                        cancel_event=job.cancel_event,
                        pause_event=job.pause_event,
                        resume_state=job.resume_state,
                        progress_callback=_progress,
                    )
                    status = result.status
                    if status == STATUS_PAUSED:
                        # Non-terminal: keep temp files and wait for resume.
                        job.resume_state = result.resume
                        job.state = STATUS_PAUSED
                        return
                    stored_plaintext = None if job.plaintext_withheld else result.matched_plaintext
                    job.result = {
                        "status": status,
                        "attempts": result.attempts,
                        "elapsed_ms": result.elapsed_ms,
                        "workers": result.workers,
                        "matched_plaintext": stored_plaintext,
                        "target_hash": job.target_hash,
                        "plaintext_withheld": job.plaintext_withheld,
                    }
                    job.attempts = result.attempts
                    job.elapsed_ms = result.elapsed_ms
                    # Record the run in local history.
                    try:
                        conn = connect(db_path)
                        record_run(
                            conn,
                            target_hash=job.target_hash,
                            algorithm=job.algorithm,
                            mode=job.mode,
                            status=status,
                            attempts=result.attempts,
                            elapsed_ms=result.elapsed_ms,
                            worker_count=result.workers,
                            started_at=started,
                            matched_plaintext=(
                                (None if job.plaintext_withheld else result.matched_plaintext)
                                if status == STATUS_MATCH
                                else None
                            ),
                            salt=job.salt or None,
                            plaintext_withheld=job.plaintext_withheld,
                        )
                        conn.close()
                        job.state = status
                    except HistoryError:
                        if status == STATUS_MATCH:
                            job.result = None
                            job.error = (
                                "A match was found but it could not be recorded in "
                                "local history (storage error); nothing is displayed."
                            )
                            job.state = "storage_error"
                        else:
                            job.error = "The run finished but could not be recorded in local history."
                            job.state = status
            except Exception:
                job.error = "The audit failed unexpectedly; no result was recorded."
                job.state = "interrupted"
            finally:
                if job.state != STATUS_PAUSED:
                    _remove_temp_file(job.temp_path)
                    _remove_temp_file(getattr(job, "temp_hashlist", None))

        def _progress(attempts: int, elapsed_ms: int, fraction):
            with job.lock:
                job.attempts = attempts
                job.elapsed_ms = elapsed_ms

        with app.config["_job_lock"]:
            active = app.config["_job"]
            if active is not None and active.state in (
                _STATE_VALIDATING,
                _STATE_QUEUED,
                _STATE_RUNNING,
            ):
                return None, {
                    "error": "Another dashboard audit is already running. "
                    "Cancel it or wait for it to finish."
                }
            app.config["_job"] = job
        thread = threading.Thread(target=run_job, daemon=True)
        job.thread = thread
        thread.start()
        return job, None

    def _remove_temp_file(path: Path | None) -> None:
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _save_upload(file_storage) -> tuple[Path | None, dict | None]:
        """Stream an upload to a temporary file; enforce the 100 MiB limit."""
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
                "error": "The wordlist upload exceeds the 100 MiB limit."
            }
        except OSError:
            _remove_temp_file(temp_path)
            return None, {"error": "The wordlist upload could not be stored temporarily."}
        return temp_path, None

    @app.post("/api/audits")
    def start_audit():
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        store_plaintext = request.form.get("store_plaintext", "true") != "false"
        if not request.form.get("acknowledge_retention") == "true":
            return jsonify(
                {
                    "error": "You must acknowledge the local plaintext/hash "
                    "retention warning before starting an audit."
                }
            ), 400

        mode = request.form.get("mode", "")

        # Optional hashlist upload: one target per line, replaces the single
        # hash/algorithm fields.
        hashlist_file = request.files.get("hashlist")
        targets = None
        temp_hashlist = None
        if hashlist_file is not None and hashlist_file.filename:
            temp_hashlist, error = _save_upload(hashlist_file)
            if error is not None:
                return jsonify(error), 400
            try:
                targets = parse_hashlist(temp_hashlist)
            except HashInputError as exc:
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": f"Invalid hashlist: {exc}"}), 400

        algorithm = request.form.get("algorithm", "")
        target = request.form.get("hash", "")
        salt = (request.form.get("salt") or "").strip()
        temp_path = None
        budget = None
        total_space = None
        batch_source = None

        if targets is None:
            if not algorithm:
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": "An algorithm is required."}), 400
            params, error = _validate_audit_params(algorithm, request.form.get("workers"), target)
            if error is not None:
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": error}), 400
            params["algorithm"] = algorithm
            if is_salted(algorithm) and not salt:
                _remove_temp_file(temp_hashlist)
                return jsonify(
                    {"error": f"Salted format {algorithm} requires a salt value."}
                ), 400
            if salt and not is_salted(algorithm):
                _remove_temp_file(temp_hashlist)
                return jsonify(
                    {"error": f"Algorithm {algorithm} does not take a salt."}
                ), 400
        else:
            params = {"target": "", "algorithm": "hashlist", "workers": 4}
            if salt:
                _remove_temp_file(temp_hashlist)
                return jsonify(
                    {"error": "--salt is not supported with hashlists (no per-target salt)."}
                ), 400

        # Optional mutation rules for dictionary mode.
        rules_name = (request.form.get("rules") or "none").strip()
        variants_for = None
        if rules_name != "none":
            if mode != "dictionary":
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": "Rules apply to dictionary mode only."}), 400
            try:
                variants_for = resolve_rules_preset(rules_name)
            except ValueError as exc:
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": str(exc)}), 400

        params.update(
            {
                "charset": request.form.get("charset", ""),
                "min_length": request.form.get("min_length", ""),
                "max_length": request.form.get("max_length", ""),
                "max_candidates": request.form.get(
                    "max_candidates", str(DEFAULT_BUDGET)
                ),
                "rules_name": rules_name,
            }
        )

        if mode == "dictionary":
            upload = request.files.get("wordlist")
            if upload is None or not upload.filename:
                _remove_temp_file(temp_hashlist)
                return jsonify({"error": "Dictionary mode requires a wordlist upload."}), 400
            temp_path, error = _save_upload(upload)
            if error is not None:
                _remove_temp_file(temp_hashlist)
                status = 413 if "100 MiB" in error["error"] else 400
                return jsonify(error), status
            batch_source = iter_wordlist_batches(temp_path)
            if variants_for is not None:
                batch_source = iter_rule_expanded(batch_source, variants_for, budget or DEFAULT_BUDGET)
                budget = budget or DEFAULT_BUDGET
                total_space = None
        elif mode == "brute-force":
            charset_raw = request.form.get("charset", "")
            try:
                alphabet = resolve_charset(charset_raw)
                min_length = int(request.form.get("min_length", ""))
                max_length = int(request.form.get("max_length", ""))
                budget = int(request.form.get("max_candidates", str(DEFAULT_BUDGET)))
                alphabet, total_space = validate_bruteforce_options(
                    min_length, max_length, budget, alphabet
                )
            except (HashInputError, ValueError):
                _remove_temp_file(temp_hashlist)
                return jsonify(
                    {
                        "error": "Invalid brute-force settings: charset, length range, "
                        f"and a candidate budget up to {HARD_MAX_BUDGET:,} are required."
                    }
                ), 400
            batch_source = iter_bruteforce_batches(alphabet, min_length, max_length, budget)
        else:
            _remove_temp_file(temp_hashlist)
            return jsonify(
                {"error": "Mode must be 'dictionary' or 'brute-force'."}
            ), 400

        job, error = _start_job(
            params, mode, batch_source, budget, total_space, temp_path, salt, targets,
            plaintext_withheld=not store_plaintext,
        )
        if error is not None:
            _remove_temp_file(temp_path)
            _remove_temp_file(temp_hashlist)
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
        if job.state != _STATE_RUNNING:
            return jsonify({"error": "Only a running job can be paused."}), 400
        if job.targets is not None:
            return jsonify({"error": "Pause is not supported for hashlist jobs."}), 400
        if job.run_params.get("rules_name", "none") != "none":
            return jsonify(
                {"error": "Pause is not supported for rule-expanded runs."}
            ), 400
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
        params = job.run_params
        mode = params["mode"]
        if mode == "dictionary":
            wordlist = job.temp_path
            if wordlist is None or not wordlist.is_file():
                return jsonify(
                    {"error": "The uploaded wordlist is gone; re-start the audit."}
                ), 400
            size = os.path.getsize(str(wordlist))
            if params.get("wordlist_size") not in (None, size):
                return jsonify(
                    {"error": "The wordlist changed since the pause; resume is refused."}
                ), 400
            batch_source = iter_wordlist_batches(wordlist)
        else:
            try:
                alphabet = resolve_charset(params["charset"])
                min_length = int(params["min_length"])
                max_length = int(params["max_length"])
                budget = int(params["max_candidates"])
                alphabet, total_space = validate_bruteforce_options(
                    min_length, max_length, budget, alphabet
                )
            except (HashInputError, ValueError):
                return jsonify({"error": "Stored brute-force params are invalid."}), 400
            batch_source = iter_bruteforce_batches(alphabet, min_length, max_length, budget)

        job.pause_event.clear()
        job.resume_state = job.resume_state or {}
        thread = threading.Thread(target=_run_resumed, daemon=True)
        job.thread = thread
        thread.start()
        return jsonify({"job_id": job.job_id, "state": _STATE_RUNNING, "resumed": True})

    def _run_resumed():
        """Re-run the audit loop for a paused single-target job."""
        job = app.config["_job"]
        if job is None or job.resume_state is None:
            return
        params = job.run_params
        mode = params["mode"]
        if mode == "dictionary":
            batch_source = iter_wordlist_batches(job.temp_path)
            budget = None
            total_space = None
        else:
            alphabet = resolve_charset(params["charset"])
            min_length = int(params["min_length"])
            max_length = int(params["max_length"])
            budget = int(params["max_candidates"])
            alphabet, total_space = validate_bruteforce_options(
                min_length, max_length, budget, alphabet
            )
            batch_source = iter_bruteforce_batches(alphabet, min_length, max_length, budget)
        job.state = _STATE_RUNNING
        started = utc_now()
        progress_at = [0.0]

        def resumed_progress(attempts: int, elapsed_ms: int, fraction):
            with job.lock:
                job.attempts = attempts
                job.elapsed_ms = elapsed_ms

        try:
            result = run_audit(
                job.target_hash,
                job.algorithm,
                batch_source,
                workers=job.workers,
                budget=budget,
                total_space=total_space,
                salt=job.salt,
                cancel_event=job.cancel_event,
                resume_state=job.resume_state,
                progress_callback=resumed_progress,
            )
            if result.status == STATUS_PAUSED:
                job.resume_state = result.resume
                job.state = STATUS_PAUSED
                return
            status = result.status
            job.result = {
                "status": status,
                "attempts": result.attempts,
                "elapsed_ms": result.elapsed_ms,
                "workers": result.workers,
                "matched_plaintext": result.matched_plaintext,
                "target_hash": job.target_hash,
            }
            job.attempts = result.attempts
            job.elapsed_ms = result.elapsed_ms
            try:
                conn = connect(db_path)
                record_run(
                    conn,
                    target_hash=job.target_hash,
                    algorithm=job.algorithm,
                    mode=mode,
                    status=status,
                    attempts=result.attempts,
                    elapsed_ms=result.elapsed_ms,
                    worker_count=result.workers,
                    started_at=started,
                    matched_plaintext=(
                        result.matched_plaintext if status == STATUS_MATCH else None
                    ),
                    salt=job.salt,
                )
                conn.close()
                job.state = status
            except HistoryError:
                job.error = "The resumed run finished but could not be recorded in local history."
                job.state = status
        except Exception:
            job.error = "The resumed audit failed unexpectedly; no result was recorded."
            job.state = "interrupted"
        finally:
            if job.state != STATUS_PAUSED:
                _remove_temp_file(job.temp_path)
                _remove_temp_file(getattr(job, "temp_hashlist", None))

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
        writer.writerows(rows)
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

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=DEFAULT_PORT, threaded=True)
