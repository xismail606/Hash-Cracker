//! Axum application: router, state, session/CSRF semantics — the parity twin
//! of the Flask app's security layer.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::jobs::JobRegistry;
use hc_history::Store;

/// Application state shared across handlers.
pub struct AppState {
    pub static_dir: PathBuf,
    pub store: Store,
    pub jobs: JobRegistry,
}

pub type SharedState = Arc<AppState>;

/// `GET /api/session` — issue a CSRF token and set the double-submit cookie.
pub async fn session() -> Response {
    let token = new_csrf_token();
    let cookie = format!("pa_csrf={token}; Path=/; SameSite=Strict");
    let mut response = axum::Json(serde_json::json!({ "csrf_token": token })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie value is ASCII"),
    );
    response
}

/// 32 random bytes, URL-safe base64 without padding (43 chars, mirroring
/// Python's `secrets.token_urlsafe(32)`).
fn new_csrf_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// CSRF guard for state-changing POSTs (everything except `/api/identify`):
/// same-host Origin/Referer when present, then header-vs-cookie equality.
/// `None` means the request passed; `Some(response)` is the 403 to return.
pub fn csrf_check(headers: &HeaderMap, host: &str) -> Option<Response> {
    // 1. Origin/Referer same-host check.
    for name in ["origin", "referer"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if !value.contains(&format!("//{host}")) {
                return Some(forbidden("Cross-origin requests are not allowed."));
            }
        }
    }
    // 2. Double-submit token: X-CSRF-Token header == pa_csrf cookie.
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_token = cookie_value(headers, "pa_csrf").unwrap_or_default();
    if header_token.is_empty() || header_token != cookie_token {
        return Some(forbidden("Missing or invalid CSRF token."));
    }
    None
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// Extract one cookie's value from the `Cookie` header.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{name}=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Build the full router (routes are wired in routes.rs/jobs.rs).
pub fn build_router(state: SharedState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(crate::routes::index))
        .route("/api/session", get(session))
        .route("/api/formats", get(crate::routes::formats))
        .route("/api/identify", post(crate::routes::identify))
        .route("/api/audits", post(crate::jobs::submit_audit))
        .route("/api/audits/{job_id}", get(crate::jobs::poll_audit))
        .route("/api/audits/{job_id}/cancel", post(crate::jobs::cancel_audit))
        .route("/api/audits/{job_id}/pause", post(crate::jobs::pause_audit))
        .route("/api/audits/{job_id}/resume", post(crate::jobs::resume_audit))
        .route("/api/history", get(crate::routes::history))
        .route("/api/history/unlock", post(crate::routes::history_unlock))
        .route("/api/export", get(crate::routes::export))
        .route("/api/history/clear", post(crate::routes::history_clear))
        .fallback(crate::routes::fallback)
        .layer(axum::extract::DefaultBodyLimit::max(257 * 1024 * 1024))
        .with_state(state)
}

/// Request host (Host header without port) for the Origin/Referer check.
pub fn request_host(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|host| {
            // Strip the port when present.
            host.rsplit_once(':')
                .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
                .map(|(name, _)| name.to_string())
                .unwrap_or_else(|| host.to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// Shared helper used by handlers needing state extraction + identity.
pub async fn state_of(State(state): State<SharedState>) -> SharedState {
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_43_urlsafe_chars() {
        let token = new_csrf_token();
        assert_eq!(token.len(), 43);
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn cookie_value_parses_pa_csrf() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; pa_csrf=abc123; more=y"),
        );
        assert_eq!(cookie_value(&headers, "pa_csrf").as_deref(), Some("abc123"));
        assert_eq!(cookie_value(&headers, "missing"), None);
    }

    #[tokio::test]
    async fn csrf_rejects_missing_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("pa_csrf=abc123"),
        );
        let err = csrf_check(&headers, "127.0.0.1").expect("rejection expected");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_accepts_matching_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("pa_csrf=tok"));
        headers.insert("x-csrf-token", HeaderValue::from_static("tok"));
        assert!(csrf_check(&headers, "127.0.0.1").is_none());
    }

    #[tokio::test]
    async fn csrf_rejects_cross_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("pa_csrf=tok"));
        headers.insert("x-csrf-token", HeaderValue::from_static("tok"));
        headers.insert(header::ORIGIN, HeaderValue::from_static("http://evil.example"));
        let err = csrf_check(&headers, "127.0.0.1").expect("rejection expected");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(err.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"], "Cross-origin requests are not allowed.");
    }

    #[test]
    fn request_host_strips_port() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8765"));
        assert_eq!(request_host(&headers), "127.0.0.1");
    }
}
