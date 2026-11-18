"""Flask dashboard API tests: session/CSRF, identify, audits, uploads, history.

Runs against a temporary history database so the operator's real audit
history is never touched. Job threads run the real engine in-process; tiny
workloads finish within the polling timeout.
"""

import io
import os
import time

import pytest

from hash_cracker.web import create_app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    # Shrink the upload limit so the oversize-rejection test stays cheap.
    monkeypatch.setattr("hash_cracker.web.MAX_UPLOAD_BYTES", 4096)
    return create_app(static_folder=tmp_path / "no-frontend", db_path=tmp_path / "test-history.db")


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf(client):
    response = client.get("/api/session")
    token = response.get_json()["csrf_token"]
    return token


def auth(client, csrf):
    """Return CSRF headers bound to the client's session cookie."""
    return {"X-CSRF-Token": csrf}


def post_audit(client, csrf, **fields):
    return client.post("/api/audits", data={**fields, "acknowledge_retention": "true"},
                       content_type="multipart/form-data", headers=auth(client, csrf))


def wait_for_job(client, job_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        payload = client.get(f"/api/audits/{job_id}").get_json()
        if payload.get("result") or payload.get("error"):
            return payload
        time.sleep(0.1)
    raise AssertionError("job did not finish in time")


class TestSessionAndCSRF:
    def test_session_issues_token_and_cookie(self, client):
        response = client.get("/api/session")
        payload = response.get_json()
        assert payload["csrf_token"]
        assert "pa_csrf" in response.headers.get("Set-Cookie")

    def test_state_change_without_csrf_rejected(self, client):
        assert client.post("/api/history/clear").status_code == 403

    def test_state_change_with_wrong_token_rejected(self, client):
        client.get("/api/session")
        response = client.post("/api/history/clear", headers={"X-CSRF-Token": "wrong"})
        assert response.status_code == 403


class TestIdentify:
    def test_sha256_recognized(self, client):
        payload = client.post(
            "/api/identify",
            json={"hash": "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"},
        ).get_json()
        assert payload["valid"] is True
        assert payload["compatible_algorithms"] == ["sha256", "sha512_256"]

    def test_32hex_ambiguous(self, client):
        payload = client.post(
            "/api/identify", json={"hash": "8743b52063cd84097a65d1633f5c74f5"}
        ).get_json()
        assert payload["compatible_algorithms"] == ["md5", "ntlm", "md4", "lm"]
        assert payload["ambiguous"] is True

    def test_invalid_hash_rejected(self, client):
        response = client.post("/api/identify", json={"hash": "not-a-hash"})
        assert response.status_code == 400
        assert response.get_json()["valid"] is False


class TestFormatsEndpoint:
    def test_formats_lists_all_registries(self, client):
        payload = client.get("/api/formats").get_json()
        names = [entry["name"] for entry in payload["algorithms"]]
        assert "md5" in names and "lm" in names and "bcrypt" in names
        assert payload["labels"]["md5"] == "MD5"
        assert payload["salted_by_length"]["32"] == ["md5_pass_salt", "md5_salt_pass"]
        preset_names = [preset["name"] for preset in payload["rules_presets"]]
        assert preset_names[0] == "none" and "all" in preset_names
        charset_names = [preset["name"] for preset in payload["charset_presets"]]
        assert charset_names == ["lower", "upper", "digits", "symbols"]
        assert payload["max_workers"] == 8
        assert payload["hard_max_candidates"] == 10_000_000

    def test_every_algorithm_has_a_label(self, client):
        payload = client.get("/api/formats").get_json()
        for entry in payload["algorithms"]:
            assert entry["name"] in payload["labels"]
            assert entry["kind"] in ("fast", "salted", "adaptive")


class TestAuditLifecycle:
    def test_dictionary_audit_match_flow(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            workers="2",
            wordlist=(io.BytesIO(b"alpha\nbravo\nhashcat\n"), "words.txt"),
        )
        assert response.status_code == 202
        job_id = response.get_json()["job_id"]
        payload = wait_for_job(client, job_id)
        assert payload["result"]["status"] == "match"
        assert payload["result"]["matched_plaintext"] == "hashcat"

    def test_acknowledgement_required(self, client):
        response = client.post(
            "/api/audits",
            data={"mode": "brute-force", "hash": "8743b52063cd84097a65d1633f5c74f5",
                  "algorithm": "md5", "charset": "lower", "min_length": "1",
                  "max_length": "2", "workers": "2", "acknowledge_retention": "false"},
            content_type="multipart/form-data",
            headers=auth(client, client.get("/api/session").get_json()["csrf_token"]),
        )
        assert response.status_code == 400

    def test_unknown_job_404(self, client):
        assert client.get("/api/audits/deadbeef").status_code == 404

    def test_bruteforce_audit_no_match(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="brute-force",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            charset="digits",
            min_length="1",
            max_length="2",
            max_candidates="200",
            workers="2",
        )
        job_id = response.get_json()["job_id"]
        payload = wait_for_job(client, job_id)
        assert payload["result"]["status"] == "no_match"  # space fully covered (110)
        assert payload["result"]["attempts"] == 110

    def test_hashlist_audit_honors_worker_count(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            workers="2",
            wordlist=(io.BytesIO(b"hashcat\n"), "words.txt"),
            hashlist=(io.BytesIO(b"md5:8743b52063cd84097a65d1633f5c74f5\n"), "targets.txt"),
        )
        assert response.status_code == 202
        job_id = response.get_json()["job_id"]
        payload = wait_for_job(client, job_id)
        assert payload["workers"] == 2
        assert payload["result"]["status"] == "match"

    def test_hashlist_audit_rejects_invalid_worker_count(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            workers="0",
            wordlist=(io.BytesIO(b"hashcat\n"), "words.txt"),
            hashlist=(io.BytesIO(b"md5:8743b52063cd84097a65d1633f5c74f5\n"), "targets.txt"),
        )
        assert response.status_code == 400
        assert "between 1 and" in response.get_json()["error"]


class TestUploadLimits:
    def test_request_size_limit_returns_a_readable_json_error(self, app, client, csrf):
        app.config["MAX_CONTENT_LENGTH"] = 512
        response = post_audit(
            client,
            csrf,
            mode="dictionary",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            workers="2",
            wordlist=(io.BytesIO(b"a" * 1024), "large.txt"),
        )

        assert response.status_code == 413
        assert response.get_json() == {
            "error": "The upload request exceeds the 256 MiB limit."
        }

    def test_oversize_upload_rejected_before_processing(self, client, csrf, monkeypatch):
        # MAX_UPLOAD_BYTES is patched to 4096 in the fixture; upload 5 KiB.
        big = io.BytesIO(b"a" * (5 * 1024))
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            workers="2",
            wordlist=(big, "big.txt"),
        )
        assert response.status_code == 413
        assert "256 MiB" in response.get_json()["error"]

    def test_missing_wordlist_rejected(self, client, csrf):
        response = post_audit(
            client, csrf, mode="dictionary", hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5", workers="2",
        )
        assert response.status_code == 400


class TestHistoryAndClear:
    def test_history_after_match_and_clear(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            workers="2",
            wordlist=(io.BytesIO(b"hashcat\n"), "w.txt"),
        )
        wait_for_job(client, response.get_json()["job_id"])
        records = client.get("/api/history").get_json()["records"]
        assert any(r["status"] == "match" for r in records)

        response = client.post("/api/history/clear", headers=auth(client, csrf))
        assert response.get_json()["deleted"] >= 1
        assert client.get("/api/history").get_json()["records"] == []

    def test_clear_removes_hashlist_summaries_and_uploaded_file(self, app, client, csrf):
        response = post_audit(
            client,
            csrf,
            mode="dictionary",
            hashlist=(io.BytesIO(b"md5:8743b52063cd84097a65d1633f5c74f5\n"), "targets.txt"),
            wordlist=(io.BytesIO(b"hashcat\n"), "words.txt"),
        )
        assert response.status_code == 202
        uploaded_hashlist = app.config["_job"].temp_hashlist
        assert uploaded_hashlist is not None
        wait_for_job(client, response.get_json()["job_id"])
        cleanup_deadline = time.time() + 2
        while uploaded_hashlist.exists() and time.time() < cleanup_deadline:
            time.sleep(0.01)
        assert not uploaded_hashlist.exists()

        before = client.get("/api/export?format=json").get_json()
        assert len(before["runs"]) == 1
        assert len(before["batches"]) == 1

        response = client.post("/api/history/clear", headers=auth(client, csrf))
        assert response.get_json()["deleted"] == 2

        after = client.get("/api/export?format=json").get_json()
        assert after["runs"] == []
        assert after["batches"] == []

    def test_history_includes_plaintext_for_matches(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            workers="2",
            wordlist=(io.BytesIO(b"hashcat\n"), "w.txt"),
        )
        wait_for_job(client, response.get_json()["job_id"])
        records = client.get("/api/history").get_json()["records"]
        assert any(r["matched_plaintext"] == "hashcat" for r in records)


class TestStaticFallback:
    def test_missing_frontend_explains(self, client):
        response = client.get("/")
        assert response.status_code == 503
        assert "npm run build" in response.get_json()["error"]


class TestExport:
    def test_csv_export_download(self, client):
        response = client.get("/api/export?format=csv")
        assert response.status_code == 200
        assert "text/csv" in response.content_type
        assert "attachment" in response.headers["Content-Disposition"]
        body = response.get_data(as_text=True)
        assert body.startswith("run_id,")

    def test_json_export_includes_batches(self, client):
        response = client.get("/api/export?format=json")
        assert response.status_code == 200
        payload = response.get_json()
        assert "runs" in payload and "batches" in payload

    def test_csv_export_includes_batch_rows_after_hashlist_audit(self, client, csrf):
        import csv as csv_mod

        started = post_audit(
            client, csrf,
            mode="dictionary",
            workers="2",
            wordlist=(io.BytesIO(b"hashcat\n"), "words.txt"),
            hashlist=(
                io.BytesIO(b"md5:8743b52063cd84097a65d1633f5c74f5\n"),
                "targets.txt",
            ),
        )
        wait_for_job(client, started.get_json()["job_id"])
        response = client.get("/api/export?format=csv")
        rows = list(csv_mod.DictReader(io.StringIO(response.get_data(as_text=True))))
        batch_rows = [r for r in rows if r["target_count"]]
        assert len(batch_rows) == 1
        assert batch_rows[0]["target_count"] == "1"
        assert batch_rows[0]["batch_id"]
        run_rows = [r for r in rows if r["run_id"] and not r["target_count"]]
        assert len(run_rows) >= 1
        assert all(r["batch_id"] for r in run_rows)


class TestPauseResume:
    def test_pause_resume_flow(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="brute-force",
            hash="f" * 64,
            algorithm="sha256",
            charset="lower",
            min_length="1",
            max_length="7",
            max_candidates="10000000",
            workers="4",
        )
        job_id = response.get_json()["job_id"]

        # Pause promptly, then wait for the paused state.
        pause_response = client.post(f"/api/audits/{job_id}/pause", headers=auth(client, csrf))
        assert pause_response.status_code == 202
        deadline = time.time() + 10
        state = None
        while time.time() < deadline:
            state = client.get(f"/api/audits/{job_id}").get_json()["state"]
            if state == "paused":
                break
            time.sleep(0.1)
        assert state == "paused"

        # Resume and wait for a terminal result.
        resume_response = client.post(f"/api/audits/{job_id}/resume", headers=auth(client, csrf))
        assert resume_response.status_code == 200
        payload = wait_for_job(client, job_id, timeout=90)
        assert payload["result"]["status"] in ("no_match", "budget_exhausted")
        assert payload["result"]["attempts"] >= 1000

    def test_pause_rejected_for_unknown_job(self, client, csrf):
        assert client.post("/api/audits/deadbeef/pause", headers=auth(client, csrf)).status_code == 404

    def test_resume_rejected_when_not_paused(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="brute-force",
            hash="f" * 64,
            algorithm="sha256",
            charset="digits",
            min_length="1",
            max_length="2",
            max_candidates="200",
            workers="2",
        )
        job_id = response.get_json()["job_id"]
        wait_for_job(client, job_id)
        assert client.post(f"/api/audits/{job_id}/resume", headers=auth(client, csrf)).status_code == 400

    def test_pause_resume_hashlist_flow(self, client, csrf):
        from hashlib import md5

        target = md5(b"no-such-candidate-in-bruteforce").hexdigest()
        response = post_audit(
            client, csrf,
            mode="brute-force",
            charset="lower",
            min_length="1",
            max_length="7",
            max_candidates="10000000",
            workers="4",
            hashlist=(io.BytesIO(f"md5:{target}\n".encode()), "targets.txt"),
        )
        job_id = response.get_json()["job_id"]

        pause_response = client.post(f"/api/audits/{job_id}/pause", headers=auth(client, csrf))
        assert pause_response.status_code == 202
        deadline = time.time() + 10
        state = None
        while time.time() < deadline:
            state = client.get(f"/api/audits/{job_id}").get_json()["state"]
            if state == "paused":
                break
            time.sleep(0.1)
        assert state == "paused"

        resume_response = client.post(f"/api/audits/{job_id}/resume", headers=auth(client, csrf))
        assert resume_response.status_code == 200
        payload = wait_for_job(client, job_id, timeout=90)
        assert payload["result"]["status"] in ("no_match", "budget_exhausted")
        assert payload["result"]["attempts"] >= 1000

    def test_pause_resume_rules_flow(self, client, csrf):
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="f" * 32,
            algorithm="md5",
            workers="4",
            rules="append_digits_0_99",
            max_candidates="10000000",
            wordlist=(io.BytesIO(b"word-1\nword-2\n" + b"word-x\n" * 50), "words.txt"),
        )
        job_id = response.get_json()["job_id"]

        pause_response = client.post(f"/api/audits/{job_id}/pause", headers=auth(client, csrf))
        assert pause_response.status_code == 202
        deadline = time.time() + 10
        state = None
        while time.time() < deadline:
            state = client.get(f"/api/audits/{job_id}").get_json()["state"]
            if state == "paused":
                break
            time.sleep(0.1)
        assert state == "paused"

        resume_response = client.post(f"/api/audits/{job_id}/resume", headers=auth(client, csrf))
        assert resume_response.status_code == 200
        payload = wait_for_job(client, job_id, timeout=90)
        assert payload["result"]["status"] == "no_match"
        # 52 words * 101 variants (original + 100 digit suffixes) = 5252.
        assert payload["result"]["attempts"] == 5252


class TestPausedJobSurvivesRestart:
    """A paused dashboard job persists next to the history database and is
    restored by a fresh create_app (server restart) until resumed, cancelled,
    or replaced."""

    def _pause_job(self, client, csrf):
        # 350 words * 101 variants = 35350 candidates. The pause event is set
        # immediately after start, before the first batch is scheduled, so
        # the paused pass deterministically examines nothing.
        response = post_audit(
            client, csrf,
            mode="dictionary",
            hash="f" * 32,
            algorithm="md5",
            workers="4",
            rules="append_digits_0_99",
            max_candidates="10000000",
            wordlist=(io.BytesIO(b"wordx\n" * 350), "words.txt"),
        )
        assert response.status_code == 202
        job_id = response.get_json()["job_id"]
        pause_response = client.post(
            f"/api/audits/{job_id}/pause", headers=auth(client, csrf)
        )
        assert pause_response.status_code == 202
        deadline = time.time() + 10
        state = None
        while time.time() < deadline:
            state = client.get(f"/api/audits/{job_id}").get_json()["state"]
            if state == "paused":
                break
            time.sleep(0.1)
        assert state == "paused"
        return job_id

    def test_paused_job_restored_after_restart_and_resumes(self, tmp_path, client, csrf):
        from hash_cracker.web import create_app

        job_id = self._pause_job(client, csrf)

        # Simulate a server restart: a fresh app over the same database path
        # also reads the same paused_jobs directory.
        restarted_app = create_app(
            static_folder=tmp_path / "no-frontend",
            db_path=tmp_path / "test-history.db",
        )
        restarted_client = restarted_app.test_client()
        state = restarted_client.get(f"/api/audits/{job_id}").get_json()
        assert state["state"] == "paused"
        assert state["mode"] == "dictionary"

        # The uploaded wordlist was moved out of the temp directory.
        paused_files = {p.name for p in (tmp_path / "paused_jobs").iterdir()}
        assert f"{job_id}.json" in paused_files
        assert any(name.endswith(".txt") for name in paused_files)

        restarted_csrf = restarted_client.get("/api/session").get_json()["csrf_token"]
        resume = restarted_client.post(
            f"/api/audits/{job_id}/resume", headers={"X-CSRF-Token": restarted_csrf}
        )
        assert resume.status_code == 200
        payload = wait_for_job(restarted_client, job_id, timeout=90)
        assert payload["result"]["status"] == "no_match"
        # Resuming from a zero-examined pause covers the whole stream.
        assert payload["result"]["attempts"] == 35350
        # The restart-recovery record is gone after a successful resume.
        assert not (tmp_path / "paused_jobs" / f"{job_id}.json").exists()

    def test_cancel_after_restart_discards_persisted_job(self, tmp_path, client, csrf):
        from hash_cracker.web import create_app

        job_id = self._pause_job(client, csrf)
        restarted_app = create_app(
            static_folder=tmp_path / "no-frontend",
            db_path=tmp_path / "test-history.db",
        )
        restarted_client = restarted_app.test_client()
        restarted_csrf = restarted_client.get("/api/session").get_json()["csrf_token"]
        response = restarted_client.post(
            f"/api/audits/{job_id}/cancel", headers={"X-CSRF-Token": restarted_csrf}
        )
        assert response.status_code == 200
        assert response.get_json()["state"] == "cancelled"
        payload = restarted_client.get(f"/api/audits/{job_id}").get_json()
        assert payload["state"] == "cancelled"
        assert payload["result"]["status"] == "cancelled"
        # Persisted state and the kept upload are both removed.
        assert list((tmp_path / "paused_jobs").iterdir()) == []

    def test_new_audit_after_restart_abandons_persisted_job(self, tmp_path, client, csrf):
        from hash_cracker.web import create_app

        old_job_id = self._pause_job(client, csrf)
        restarted_app = create_app(
            static_folder=tmp_path / "no-frontend",
            db_path=tmp_path / "test-history.db",
        )
        restarted_client = restarted_app.test_client()
        restarted_csrf = restarted_client.get("/api/session").get_json()["csrf_token"]
        response = restarted_client.post(
            "/api/audits",
            data={
                "mode": "brute-force",
                "hash": "f" * 64,
                "algorithm": "sha256",
                "charset": "digits",
                "min_length": "1",
                "max_length": "2",
                "max_candidates": "200",
                "workers": "2",
                "acknowledge_retention": "true",
            },
            content_type="multipart/form-data",
            headers={"X-CSRF-Token": restarted_csrf},
        )
        assert response.status_code == 202
        # The restored paused job is replaced and its persisted state removed.
        assert restarted_client.get(f"/api/audits/{old_job_id}").status_code == 404
        assert list((tmp_path / "paused_jobs").iterdir()) == []

    def test_stale_paused_records_are_cleaned_up(self, tmp_path, client, csrf):
        import json as json_mod

        from hash_cracker.web import create_app

        job_id = self._pause_job(client, csrf)
        paused = tmp_path / "paused_jobs"
        newest = paused / f"{job_id}.json"
        ten_days_ago = time.time() - 10 * 86400
        os.utime(newest, (ten_days_ago, ten_days_ago))

        orphan = paused / "deadbeef.txt"
        orphan.write_bytes(b"secret\n")
        stale = paused / "deadbeef.json"
        stale.write_text(
            json_mod.dumps({"job_id": "deadbeef", "temp_path": "deadbeef.txt"}),
            encoding="utf-8",
        )
        eleven_days_ago = ten_days_ago - 86400
        os.utime(stale, (eleven_days_ago, eleven_days_ago))

        restarted_app = create_app(
            static_folder=tmp_path / "no-frontend",
            db_path=tmp_path / "test-history.db",
        )
        assert not stale.exists()
        assert not orphan.exists()
        # The newest record survives and is restored.
        assert newest.exists()
        assert restarted_app.test_client().get(f"/api/audits/{job_id}").status_code == 200

    @pytest.mark.skipif(os.name != "posix", reason="POSIX modes only")
    def test_paused_artifacts_are_owner_only(self, tmp_path, client, csrf):
        job_id = self._pause_job(client, csrf)
        paused = tmp_path / "paused_jobs"
        assert paused.stat().st_mode & 0o777 == 0o700
        assert (paused / f"{job_id}.json").stat().st_mode & 0o777 == 0o600
        uploads = list(paused.glob("*.txt"))
        assert uploads
        for upload in uploads:
            assert upload.stat().st_mode & 0o777 == 0o600


class TestPlaintextWithholding:
    def test_withheld_match_stores_no_plaintext(self, client, csrf):
        response = client.post(
            "/api/audits",
            data={"mode": "dictionary", "hash": "8743b52063cd84097a65d1633f5c74f5",
                  "algorithm": "md5", "workers": "2", "store_plaintext": "false",
                  "acknowledge_retention": "true",
                  "wordlist": (io.BytesIO(b"hashcat\n"), "w.txt")},
            content_type="multipart/form-data",
            headers=auth(client, csrf),
        )
        payload = wait_for_job(client, response.get_json()["job_id"])
        assert payload["result"]["status"] == "match"
        assert payload["result"]["matched_plaintext"] is None
        assert payload["result"]["plaintext_withheld"] is True
        records = client.get("/api/history").get_json()["records"]
        assert any(r["plaintext_withheld"] for r in records)

    def test_withheld_hashlist_matches_are_not_returned_or_stored(self, client, csrf):
        response = post_audit(
            client,
            csrf,
            mode="dictionary",
            store_plaintext="false",
            hashlist=(io.BytesIO(b"md5:8743b52063cd84097a65d1633f5c74f5\n"), "targets.txt"),
            wordlist=(io.BytesIO(b"hashcat\n"), "words.txt"),
        )
        payload = wait_for_job(client, response.get_json()["job_id"])
        target = payload["result"]["targets"][0]
        assert payload["result"]["plaintext_withheld"] is True
        assert target["status"] == "match"
        assert target["matched_plaintext"] is None
        assert target["plaintext_withheld"] is True

        records = client.get("/api/history").get_json()["records"]
        match = next(record for record in records if record["status"] == "match")
        assert match["matched_plaintext"] is None
        assert match["plaintext_withheld"] is True


class TestEncryption:
    def test_unlock_decrypts_history_display(self, tmp_path):
        from hash_cracker.history import connect, init_encryption, record_run

        app = create_app(static_folder=tmp_path / "no-frontend", db_path=tmp_path / "enc.db")
        client = app.test_client()
        csrf = client.get("/api/session").get_json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}

        conn = connect(tmp_path / "enc.db")
        key = init_encryption(conn, "passphrase-123")
        record_run(
            conn,
            target_hash="8743b52063cd84097a65d1633f5c74f5",
            algorithm="md5",
            mode="dictionary",
            status="match",
            attempts=1,
            elapsed_ms=1,
            worker_count=1,
            started_at="2026-01-01T00:00:00.000Z",
            matched_plaintext="hashcat",
            plaintext_key=key,
        )
        conn.close()

        records = client.get("/api/history").get_json()["records"]
        assert records[0]["matched_plaintext"] == "<encrypted>"

        wrong = client.post("/api/history/unlock", json={"passphrase": "wrong"}, headers=headers)
        assert wrong.status_code == 403

        right = client.post("/api/history/unlock", json={"passphrase": "passphrase-123"}, headers=headers)
        assert right.get_json()["unlocked"] is True
        records = client.get("/api/history").get_json()["records"]
        assert records[0]["matched_plaintext"] == "hashcat"
