"""Flask dashboard API tests: session/CSRF, identify, audits, uploads, history.

Runs against a temporary history database so the operator's real audit
history is never touched. Job threads run the real engine in-process; tiny
workloads finish within the polling timeout.
"""

import io
import time

import pytest

from password_audit.web import MAX_UPLOAD_BYTES, create_app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    # Shrink the upload limit so the oversize-rejection test stays cheap.
    monkeypatch.setattr("password_audit.web.MAX_UPLOAD_BYTES", 4096)
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
        assert payload["compatible_algorithms"] == ["sha256"]

    def test_32hex_ambiguous(self, client):
        payload = client.post(
            "/api/identify", json={"hash": "8743b52063cd84097a65d1633f5c74f5"}
        ).get_json()
        assert payload["compatible_algorithms"] == ["md5", "ntlm", "md4"]
        assert payload["ambiguous"] is True

    def test_invalid_hash_rejected(self, client):
        response = client.post("/api/identify", json={"hash": "not-a-hash"})
        assert response.status_code == 400
        assert response.get_json()["valid"] is False


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


class TestUploadLimits:
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
        assert "100 MiB" in response.get_json()["error"]

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
