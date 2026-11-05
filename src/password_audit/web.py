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
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .algorithms import ALGORITHM_NAMES, ALGORITHM_LENGTHS, HashInputError, assess_hash
from .bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    iter_bruteforce_batches,
    resolve_charset,
    validate_bruteforce_options,
)
from .candidates import iter_wordlist_batches
from .engine import DEFAULT_WORKERS, MAX_WORKERS, STATUS_MATCH, run_audit
from .history import HistoryError, clear_runs, connect, list_runs, record_run, utc_now

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
        self.thread: threading.Thread | None = None
        self.temp_path: Path | None = None
        self.started_at = ""
        self.result: dict | None = None
        self.error: str | None = None
        self.attempts = 0
        self.elapsed_ms = 0
        self.lock = threading.Lock()


def create_app(static_folder: str | Path | None = None) -> Flask:
    """Create the local dashboard Flask application."""
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
        return send_from_directory(str(static_folder), "index.html")

    @app.get("/<path:asset>")
    def assets(asset: str):
        target = Path(static_folder) / asset
        if target.is_file():
            return send_from_directory(str(static_folder), asset)
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
            assessment = assess_hash(target)
        except HashInputError as exc:
            return None, str(exc)
        if len(assessment.normalized) != ALGORITHM_LENGTHS[algorithm]:
            return None, (
                f"The hash does not match the {algorithm} format (expected "
                f"{ALGORITHM_LENGTHS[algorithm]} hexadecimal characters)."
            )
        try:
            workers = int(workers_raw)
        except (TypeError, ValueError):
            return None, "Worker count must be an integer."
        if workers < 1 or workers > MAX_WORKERS:
            return None, f"Worker count must be between 1 and {MAX_WORKERS}."
        return {"target": assessment.normalized, "workers": workers}, None

    def _start_job(params: dict, mode: str, batch_source, budget, total_space, temp_path) -> tuple[DashboardJob | None, dict | None]:
        job = DashboardJob(job_id=uuid.uuid4().hex)
        job.target_hash = params["target"]
        job.algorithm = params["algorithm"]
        job.mode = mode
        job.workers = params["workers"]
        job.budget = budget
        job.temp_path = temp_path
        job.started_at = utc_now()

        def run_job():
            job.state = _STATE_RUNNING
            started = utc_now()
            try:
                result = run_audit(
                    job.target_hash,
                    job.algorithm,
                    batch_source,
                    workers=job.workers,
                    budget=budget,
                    total_space=total_space,
                    cancel_event=job.cancel_event,
                    progress_callback=_progress,
                )
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
                # Record the run in local history.
                try:
                    conn = connect()
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
                            result.matched_plaintext if status == STATUS_MATCH else None
                        ),
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
                _remove_temp_file(job.temp_path)

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
        if not request.form.get("acknowledge_retention") == "true":
            return jsonify(
                {
                    "error": "You must acknowledge the local plaintext/hash "
                    "retention warning before starting an audit."
                }
            ), 400

        mode = request.form.get("mode", "")
        algorithm = request.form.get("algorithm", "")
        target = request.form.get("hash", "")
        params, error = _validate_audit_params(algorithm, request.form.get("workers"), target)
        if error is not None:
            return jsonify({"error": error}), 400
        params["algorithm"] = algorithm

        temp_path = None
        budget = None
        total_space = None
        batch_source = None

        if mode == "dictionary":
            upload = request.files.get("wordlist")
            if upload is None or not upload.filename:
                return jsonify({"error": "Dictionary mode requires a wordlist upload."}), 400
            temp_path, error = _save_upload(upload)
            if error is not None:
                return jsonify(error), 413 if "100 MiB" in error else 400
            batch_source = iter_wordlist_batches(temp_path)
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
                return jsonify(
                    {
                        "error": "Invalid brute-force settings: charset, length range, "
                        f"and a candidate budget up to {HARD_MAX_BUDGET:,} are required."
                    }
                ), 400
            batch_source = iter_bruteforce_batches(alphabet, min_length, max_length, budget)
        else:
            return jsonify(
                {"error": "Mode must be 'dictionary' or 'brute-force'."}
            ), 400

        job, error = _start_job(params, mode, batch_source, budget, total_space, temp_path)
        if error is not None:
            _remove_temp_file(temp_path)
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

    # --- history ---------------------------------------------------------

    @app.get("/api/history")
    def history():
        try:
            conn = connect()
            records = list_runs(conn, limit=100)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(
            {
                "records": [record.as_dict() for record in records],
                "sensitive_note": "Successful matches include the recovered "
                "plaintext/hash pair stored locally.",
            }
        )

    @app.post("/api/history/clear")
    def history_clear():
        """Permanently delete every local audit record (destructive, CSRF-protected)."""
        csrf_error = _csrf_protected()
        if csrf_error is not None:
            return csrf_error
        try:
            conn = connect()
            deleted = clear_runs(conn)
            conn.close()
        except HistoryError as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify({"deleted": deleted})

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=DEFAULT_PORT, threaded=True)
