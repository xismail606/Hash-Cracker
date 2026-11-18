//! Integration tests: the REST contract exercised through the router with
//! `tower::ServiceExt::oneshot` (specs/003-rust-backend/contracts/api.md).

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use hc_server::app::{self, AppState};
use hc_server::jobs::JobRegistry;
use hc_history::Store;
use tower::util::ServiceExt;

fn test_state() -> Arc<AppState> {
    let dir = tempfile::tempdir().expect("temp dir");
    // Leak the dir so state outlives the test (paths inside hold files).
    let dir = Box::leak(Box::new(dir));
    let db_path = dir.path().join("history.db");
    let store = Store::open(&db_path).expect("store");
    Arc::new(AppState {
        static_dir: dir.path().to_path_buf(),
        store,
        jobs: JobRegistry::new(db_path),
    })
}

fn app(state: Arc<AppState>) -> axum::Router {
    app::build_router(state)
}

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// Build a multipart body for POST /api/audits.
fn multipart_body(fields: &[(&str, &str)], wordlist: Option<&str>, hashlist: Option<&str>) -> (String, Vec<u8>) {
    let boundary = "testboundary123";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    if let Some(text) = wordlist {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"wordlist\"; filename=\"wl.txt\"\r\nContent-Type: text/plain\r\n\r\n{text}\r\n"
            )
            .as_bytes(),
        );
    }
    if let Some(text) = hashlist {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"hashlist\"; filename=\"hl.txt\"\r\nContent-Type: text/plain\r\n\r\n{text}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary.to_string(), body)
}

async fn post_with_csrf(
    router: &axum::Router,
    uri: &str,
    token: &str,
    body: Vec<u8>,
    content_type: &str,
) -> (StatusCode, serde_json::Value) {
    let request = Request::post(uri)
        .header(header::COOKIE, format!("pa_csrf={token}"))
        .header("x-csrf-token", token)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn session_token(router: &axum::Router) -> String {
    let response = router
        .clone()
        .oneshot(Request::get("/api/session").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("pa_csrf="));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains("HttpOnly"));
    cookie
        .trim_start_matches("pa_csrf=")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn formats_payload_matches_contract() {
    let router = app(test_state());
    let (status, value) = get_json(&router, "/api/formats").await;
    assert_eq!(status, StatusCode::OK);
    let algorithms = value["algorithms"].as_array().unwrap();
    assert_eq!(algorithms.len(), 23);
    assert_eq!(algorithms[0]["name"], "md5");
    assert_eq!(algorithms[2]["name"], "ntlm");
    assert_eq!(algorithms[2]["kind"], "fast");
    assert_eq!(algorithms[20]["name"], "bcrypt");
    assert_eq!(algorithms[20]["kind"], "adaptive");
    assert_eq!(algorithms[9]["name"], "md5_pass_salt");
    assert_eq!(algorithms[9]["kind"], "salted");
    assert_eq!(value["labels"]["md5"], "MD5");
    assert_eq!(value["labels"]["md5_pass_salt"], "md5($pass.$salt)");
    let salted = value["salted_by_length"].as_object().unwrap();
    assert!(salted.contains_key("32"));
    assert_eq!(salted["32"].as_array().unwrap().len(), 2);
    assert_eq!(value["charset_presets"][0]["name"], "lower");
    assert_eq!(value["charset_presets"][0]["label"], "lowercase a-z");
    assert_eq!(value["rules_presets"][0]["name"], "none");
    assert_eq!(value["rules_presets"].as_array().unwrap().len(), 8);
    assert_eq!(value["max_workers"], 8);
    assert_eq!(value["default_workers"], 4);
    assert_eq!(value["hard_max_candidates"], 10000000);
    assert_eq!(value["default_budget"], 1000000);
}

#[tokio::test]
async fn identify_shapes() {
    let router = app(test_state());
    let body = serde_json::json!({"hash": "8743B52063CD84097A65D1633F5C74F5"});
    let request = Request::post("/api/identify")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["ambiguous"], true);
    assert_eq!(
        value["compatible_algorithms"],
        serde_json::json!(["md5", "ntlm", "md4", "lm"])
    );
    assert_eq!(
        value["normalized"],
        "8743b52063cd84097a65d1633f5c74f5"
    );

    // Adaptive prefix.
    let body = serde_json::json!({"hash": "$2b$12$abcdefghijklmnop"});
    let request = Request::post("/api/identify")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["compatible_algorithms"], serde_json::json!(["bcrypt"]));
    assert_eq!(value["ambiguous"], false);

    // Non-hex error carries valid:false.
    let body = serde_json::json!({"hash": "zzzz"});
    let request = Request::post("/api/identify")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["valid"], false);
    assert!(value["error"]
        .as_str()
        .unwrap()
        .starts_with("The hash value contains characters that are not hexadecimal"));
}

#[tokio::test]
async fn csrf_is_enforced_on_state_changing_posts() {
    let router = app(test_state());
    let request = Request::post("/api/history/clear")
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["error"], "Missing or invalid CSRF token.");
}

#[tokio::test]
async fn full_audit_lifecycle_dictionary() {
    let state = test_state();
    let router = app(Arc::clone(&state));
    let token = session_token(&router).await;
    let md5 = "8743b52063cd84097a65d1633f5c74f5"; // hashcat
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "md5"),
            ("hash", md5),
            ("workers", "2"),
        ],
        Some("alpha\nbeta\nhashcat\ndelta\n"),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    let job_id = value["job_id"].as_str().unwrap().to_string();
    assert_eq!(value["state"], "validating");

    // Poll until terminal.
    let mut final_value = serde_json::Value::Null;
    for _ in 0..100 {
        let (status, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let state_str = value["state"].as_str().unwrap().to_string();
        if state_str != "validating" && state_str != "running" {
            final_value = value;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(final_value["state"], "match", "{final_value}");
    let result = &final_value["result"];
    assert_eq!(result["status"], "match");
    assert_eq!(result["matched_plaintext"], "hashcat");
    assert_eq!(result["target_hash"], md5);
    assert_eq!(result["plaintext_withheld"], false);
    assert_eq!(final_value["budget"], serde_json::Value::Null); // plain dictionary

    // Unknown job → 404.
    let (status, value) = get_json(&router, "/api/audits/deadbeef").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(value["error"], "Unknown job ID.");

    // History shows the run with attribution.
    let (status, value) = get_json(&router, "/api/history").await;
    assert_eq!(status, StatusCode::OK);
    let records = value["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["backend"], "rust");
    assert_eq!(records[0]["matched_plaintext"], "hashcat");
    assert_eq!(
        value["sensitive_note"],
        "Successful matches include the recovered plaintext/hash pair stored locally."
    );
}

#[tokio::test]
async fn submit_validation_messages() {
    let router = app(test_state());
    let token = session_token(&router).await;

    // Missing acknowledgement.
    let (boundary, body) = multipart_body(
        &[("mode", "dictionary"), ("algorithm", "md5"), ("hash", "8743b52063cd84097a65d1633f5c74f5")],
        Some("x\n"),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"],
        "You must acknowledge the local plaintext/hash retention warning before starting an audit."
    );

    // Bad mode.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "quantum"),
            ("algorithm", "md5"),
            ("hash", "8743b52063cd84097a65d1633f5c74f5"),
        ],
        None,
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "Mode must be 'dictionary' or 'brute-force'.");

    // Unknown algorithm.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "rot13"),
            ("hash", "8743b52063cd84097a65d1633f5c74f5"),
        ],
        Some("x\n"),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(value["error"]
        .as_str()
        .unwrap()
        .starts_with("Unsupported algorithm 'rot13'. Supported: "));

    // Missing wordlist.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "md5"),
            ("hash", "8743b52063cd84097a65d1633f5c74f5"),
        ],
        None,
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "Dictionary mode requires a wordlist upload.");

    // Salt on unsalted algorithm.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "md5"),
            ("hash", "8743b52063cd84097a65d1633f5c74f5"),
            ("salt", "pepper"),
        ],
        Some("x\n"),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"],
        "Algorithm md5 does not take a salt."
    );

    // Hashlist with salt.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("salt", "pepper"),
        ],
        Some("x\n"),
        Some("sha1:a9993e364706816aba3e25717850c26c9cd0d89d\n"),
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"],
        "--salt is not supported with hashlists (no per-target salt)."
    );

    // Ambiguous hashlist line.
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
        ],
        Some("hashcat\n"),
        Some("8743b52063cd84097a65d1633f5c74f5\n"),
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(value["error"].as_str().unwrap().starts_with("Invalid hashlist: Hashlist line 1:"));
}

#[tokio::test]
async fn audit_pause_resume_flow() {
    let state = test_state();
    let router = app(Arc::clone(&state));
    let token = session_token(&router).await;

    // A big wordlist so the run is still going when we pause.
    let words: String = (0..200_000)
        .map(|i| format!("w{i:06}\n"))
        .collect();
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "sha512"),
            ("hash", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ],
        Some(&words),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    let job_id = value["job_id"].as_str().unwrap().to_string();

    // Wait until running, then pause.
    let mut paused = false;
    for _ in 0..200 {
        let (_, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        let state_str = value["state"].as_str().unwrap().to_string();
        if state_str == "running" {
            let (status, value) = post_with_csrf(
                &router,
                &format!("/api/audits/{job_id}/pause"),
                &token,
                Vec::new(),
                "application/json",
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(value["pausing"], true);
            paused = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(paused, "job never reached running state");

    // Wait for paused state; the sidecar record exists.
    let mut sidecar: Option<PathBuf> = None;
    for _ in 0..200 {
        let (_, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        if value["state"] == "paused" {
            sidecar = std::fs::read_dir(&state.jobs.paused_dir)
                .ok()
                .and_then(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.path())
                        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
                });
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(sidecar.is_some(), "sidecar record missing");
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(sidecar.as_ref().unwrap()).unwrap())
            .unwrap();
    assert_eq!(record["job_id"], job_id);
    assert_eq!(record["mode"], "dictionary");
    assert!(record["resume_state"]["skip_source"].is_u64());

    // Resume.
    let (status, value) = post_with_csrf(
        &router,
        &format!("/api/audits/{job_id}/resume"),
        &token,
        Vec::new(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["resumed"], true);
    assert_eq!(value["state"], "running");
    assert!(!sidecar.as_ref().unwrap().exists(), "sidecar deleted on resume");

    // Run to terminal (no_match: empty-string target never matches).
    let mut terminal = serde_json::Value::Null;
    for _ in 0..400 {
        let (_, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        let state_str = value["state"].as_str().unwrap().to_string();
        if state_str != "validating" && state_str != "running" && state_str != "paused" {
            terminal = value;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(terminal["state"], "no_match", "{terminal}");

    // Pause on a non-running job → 400 with the pinned message.
    let (status, value) = post_with_csrf(
        &router,
        &format!("/api/audits/{job_id}/pause"),
        &token,
        Vec::new(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "Only a running job can be paused.");

    // Resume on a terminal job → 400.
    let (status, value) = post_with_csrf(
        &router,
        &format!("/api/audits/{job_id}/resume"),
        &token,
        Vec::new(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "Only a paused job can be resumed.");
}

#[tokio::test]
async fn single_slot_conflict_is_409() {
    let state = test_state();
    let router = app(Arc::clone(&state));
    let token = session_token(&router).await;

    // A long-running job (large wordlist, slow digest).
    let words: String = (0..50_000)
        .map(|i| format!("w{i:06}
"))
        .collect();
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "sha512"),
            ("hash", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ],
        Some(&words),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    let first_id = value["job_id"].as_str().unwrap().to_string();

    // Immediately submit another → 409.
    let (boundary2, body2) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "md5"),
            ("hash", "8743b52063cd84097a65d1633f5c74f5"),
        ],
        Some("x
"),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body2,
        &format!("multipart/form-data; boundary={boundary2}"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        value["error"],
        "Another dashboard audit is already running. Cancel it or wait for it to finish."
    );

    // Clean up: cancel the first job.
    let (status, value) = post_with_csrf(
        &router,
        &format!("/api/audits/{first_id}/cancel"),
        &token,
        Vec::new(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The slot frees up after cancellation completes.
    let mut freed = false;
    for _ in 0..400 {
        let (_, value) = get_json(&router, &format!("/api/audits/{first_id}")).await;
        let state_str = value["state"].as_str().unwrap().to_string();
        if state_str == "cancelled" {
            let (boundary3, body3) = multipart_body(
                &[
                    ("acknowledge_retention", "true"),
                    ("mode", "dictionary"),
                    ("algorithm", "md5"),
                    ("hash", "8743b52063cd84097a65d1633f5c74f5"),
                ],
                Some("x
"),
                None,
            );
            let (status, _) = post_with_csrf(
                &router,
                "/api/audits",
                &token,
                body3,
                &format!("multipart/form-data; boundary={boundary3}"),
            )
            .await;
            if status == StatusCode::ACCEPTED {
                freed = true;
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(freed, "slot did not free after cancel");
}

#[tokio::test]
async fn cancel_running_job() {
    let state = test_state();
    let router = app(Arc::clone(&state));
    let token = session_token(&router).await;

    let words: String = (0..50_000)
        .map(|i| format!("w{i:06}\n"))
        .collect();
    let (boundary, body) = multipart_body(
        &[
            ("acknowledge_retention", "true"),
            ("mode", "dictionary"),
            ("algorithm", "sha512"),
            ("hash", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ],
        Some(&words),
        None,
    );
    let (status, value) = post_with_csrf(
        &router,
        "/api/audits",
        &token,
        body,
        &format!("multipart/form-data; boundary={boundary}"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    let job_id = value["job_id"].as_str().unwrap().to_string();

    // Wait for running then cancel.
    let mut cancelled = false;
    for _ in 0..200 {
        let (_, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        if value["state"] == "running" {
            let (status, value) = post_with_csrf(
                &router,
                &format!("/api/audits/{job_id}/cancel"),
                &token,
                Vec::new(),
                "application/json",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(value["cancelling"], true);
            cancelled = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(cancelled);

    let mut terminal = serde_json::Value::Null;
    for _ in 0..400 {
        let (_, value) = get_json(&router, &format!("/api/audits/{job_id}")).await;
        let state_str = value["state"].as_str().unwrap().to_string();
        if state_str != "validating" && state_str != "running" {
            terminal = value;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(terminal["state"], "cancelled", "{terminal}");
    assert_eq!(terminal["result"]["status"], "cancelled");
}

#[tokio::test]
async fn history_clear_reports_deleted_count() {
    let router = app(test_state());
    let token = session_token(&router).await;

    // Record directly through the store.
    // (History writes are covered by the lifecycle test; here we only
    // exercise the clear endpoint shape.)
    let (status, value) = post_with_csrf(
        &router,
        "/api/history/clear",
        &token,
        Vec::new(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["deleted"], 0);
}

#[tokio::test]
async fn export_csv_has_pinned_header() {
    let router = app(test_state());
    let request = Request::get("/api/export?format=csv").body(Body::empty()).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(content_type, "text/csv");
    let disposition = response
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(disposition, "attachment; filename=audit-history.csv");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(
        body.lines().next().unwrap(),
        "run_id,started_at,completed_at,target_hash,algorithm,mode,status,attempts,elapsed_ms,worker_count,matched_plaintext,salt,batch_id,plaintext_withheld,backend,target_count"
    );
}

#[tokio::test]
async fn unlock_wrong_passphrase_is_403() {
    let state = test_state();
    let router = app(Arc::clone(&state));
    let token = session_token(&router).await;

    // Initialize encryption with one passphrase.
    hc_history::init(&state.store, "correct-horse").unwrap();

    let (status, value) = post_with_csrf(
        &router,
        "/api/history/unlock",
        &token,
        serde_json::json!({"passphrase": "wrong-horse"}).to_string().into_bytes(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value["error"], "Wrong passphrase.");

    // Empty passphrase → 400.
    let (status, value) = post_with_csrf(
        &router,
        "/api/history/unlock",
        &token,
        serde_json::json!({"passphrase": ""}).to_string().into_bytes(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"], "A passphrase is required.");

    // Correct passphrase → unlocked.
    let (status, value) = post_with_csrf(
        &router,
        "/api/history/unlock",
        &token,
        serde_json::json!({"passphrase": "correct-horse"}).to_string().into_bytes(),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["unlocked"], true);
}

#[tokio::test]
async fn static_serving_contract() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<html>built</html>").unwrap();
    let db_path = dir.path().join("history.db");
    let state = Arc::new(AppState {
        static_dir: dir.path().to_path_buf(),
        store: Store::open(&db_path).unwrap(),
        jobs: JobRegistry::new(db_path),
    });
    let router = app(state);

    // Built frontend serves with the pinned cache header.
    let response = router
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cache, "no-cache, no-store, must-revalidate");

    // Missing frontend → 503 with the build hint.
    let empty = tempfile::tempdir().unwrap();
    let db2 = empty.path().join("history.db");
    let state2 = Arc::new(AppState {
        static_dir: empty.path().to_path_buf(),
        store: Store::open(&db2).unwrap(),
        jobs: JobRegistry::new(db2),
    });
    let router2 = app(state2);
    let (status, value) = get_json(&router2, "/").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(value["error"]
        .as_str()
        .unwrap()
        .contains("The dashboard frontend has not been built yet"));

    // Missing asset → 404 {"error": "Not found."}.
    let (status, value) = get_json(&router, "/missing.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(value["error"], "Not found.");
}
