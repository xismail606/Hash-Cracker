//! API routes: session-independent endpoints — formats catalog, hash
//! identification, history, export, and clear (contract-pinned shapes).

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app::{request_host, csrf_check, SharedState};
use hc_core::bruteforce::{CHARSET_PRESET_LABELS, HARD_MAX_BUDGET};
use hc_core::formats;
use hc_core::identify::{assess_hash, HashInputError};
use hc_core::rules::RULE_PRESET_LABELS;
use hc_core::engine::DEFAULT_BUDGET;
use hc_history::ENCRYPT_PREFIX;

const SENSITIVE_NOTE: &str =
    "Successful matches include the recovered plaintext/hash pair stored locally.";
const DEFAULT_WORKERS: i64 = 4;
const MAX_WORKERS: i64 = 8;

pub async fn index(State(state): State<SharedState>) -> Response {
    crate::static_files::serve_index(&state.static_dir)
}

pub async fn fallback(
    State(state): State<SharedState>,
    uri: axum::extract::OriginalUri,
) -> Response {
    let path = uri.0.path().trim_start_matches('/').to_string();
    crate::static_files::serve_asset(&state.static_dir, &path)
}

/// `GET /api/formats` — the authoritative registry payload.
pub async fn formats() -> Response {
    let algorithms: Vec<serde_json::Value> = formats::FORMATS
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "label": f.label,
                "kind": f.kind.as_str(),
            })
        })
        .collect();
    let labels: serde_json::Map<String, serde_json::Value> = formats::FORMATS
        .iter()
        .map(|f| (f.name.to_string(), serde_json::Value::String(f.label.to_string())))
        .collect();
    let salted_by_length: serde_json::Map<String, serde_json::Value> = formats::salted_by_length()
        .into_iter()
        .map(|(len, ids)| {
            (
                len.to_string(),
                serde_json::Value::Array(
                    ids.into_iter()
                        .map(|id| serde_json::Value::String(id.to_string()))
                        .collect(),
                ),
            )
        })
        .collect();
    let charset_presets: Vec<serde_json::Value> = CHARSET_PRESET_LABELS
        .iter()
        .map(|(name, label)| {
            serde_json::json!({"name": name, "label": label})
        })
        .collect();
    let rules_presets: Vec<serde_json::Value> = RULE_PRESET_LABELS
        .iter()
        .map(|(name, label)| {
            serde_json::json!({"name": name, "label": label})
        })
        .collect();
    axum::Json(serde_json::json!({
        "algorithms": algorithms,
        "labels": labels,
        "salted_by_length": salted_by_length,
        "charset_presets": charset_presets,
        "rules_presets": rules_presets,
        "max_workers": MAX_WORKERS,
        "default_workers": DEFAULT_WORKERS,
        "hard_max_candidates": HARD_MAX_BUDGET,
        "default_budget": DEFAULT_BUDGET,
    }))
    .into_response()
}

/// `POST /api/identify` — CSRF-exempt; validation errors carry `"valid": false`.
pub async fn identify(
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let _ = request_host(&headers); // no CSRF check for identify (pinned)
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return bad_request("Request must include a JSON 'hash' string.", Some(false));
        }
    };
    let Some(hash) = payload.get("hash").and_then(|v| v.as_str()) else {
        return bad_request("Request must include a JSON 'hash' string.", Some(false));
    };
    match assess_hash(hash) {
        Ok(assessment) => axum::Json(serde_json::json!({
            "valid": true,
            "submitted": assessment.submitted.trim(),
            "normalized": assessment.normalized,
            "compatible_algorithms": assessment.compatible_algorithms,
            "ambiguous": assessment.ambiguous,
        }))
        .into_response(),
        Err(HashInputError(message)) => bad_request(&message, Some(false)),
    }
}

fn bad_request(message: &str, valid: Option<bool>) -> Response {
    let mut payload = serde_json::Map::new();
    payload.insert("error".to_string(), serde_json::Value::String(message.to_string()));
    if let Some(valid) = valid {
        payload.insert("valid".to_string(), serde_json::Value::Bool(valid));
    }
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::Value::Object(payload)),
    )
        .into_response()
}

fn history_error(message: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// `GET /api/history` — newest 100 records with encryption placeholders and
/// the Phase 11 `backend` attribution.
pub async fn history(State(state): State<SharedState>) -> Response {
    let records = match state.store.list_runs(100) {
        Ok(records) => records,
        Err(err) => return history_error(err.0),
    };
    let cached_key = crate::crypto::cached_key();
    let mut encrypted_count = 0usize;
    let rows: Vec<serde_json::Value> = records
        .iter()
        .map(|record| {
            let plaintext = match &record.matched_plaintext {
                Some(value) if value.starts_with(ENCRYPT_PREFIX) => {
                    encrypted_count += 1;
                    match cached_key {
                        Some(key) => match hc_history::decrypt_stored(&key, value) {
                            Some(Ok(plain)) => serde_json::Value::String(plain),
                            _ => serde_json::Value::String("<decryption failed>".to_string()),
                        },
                        None => serde_json::Value::String("<encrypted>".to_string()),
                    }
                }
                other => other
                    .clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            };
            serde_json::json!({
                "run_id": record.run_id,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "target_hash": record.target_hash,
                "algorithm": record.algorithm,
                "mode": record.mode,
                "status": record.status,
                "attempts": record.attempts,
                "elapsed_ms": record.elapsed_ms,
                "worker_count": record.worker_count,
                "matched_plaintext": plaintext,
                "salt": record.salt,
                "batch_id": record.batch_id,
                "plaintext_withheld": record.plaintext_withheld,
                "backend": record.backend,
            })
        })
        .collect();
    axum::Json(serde_json::json!({
        "records": rows,
        "encrypted_count": encrypted_count,
        "sensitive_note": SENSITIVE_NOTE,
    }))
    .into_response()
}

/// `POST /api/history/unlock` — wired to the shared encryption module; the
/// key lives in memory only (a restart clears it).
pub async fn history_unlock(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": "A passphrase is required." })),
            )
                .into_response();
        }
    };
    let Some(passphrase) = payload.get("passphrase").and_then(|v| v.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "A passphrase is required." })),
        )
            .into_response();
    };
    if passphrase.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "A passphrase is required." })),
        )
            .into_response();
    }
    match crate::crypto::unlock_store(&state.store, passphrase) {
        Ok(()) => axum::Json(serde_json::json!({ "unlocked": true })).into_response(),
        Err(message) => (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": message })),
        )
            .into_response(),
    }
}

/// `GET /api/export?format=csv|json` — attachment download, never decrypted.
pub async fn export(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let format = params
        .get("format")
        .map(|f| f.to_lowercase())
        .unwrap_or_else(|| "csv".to_string());
    match format.as_str() {
        "csv" => match state.store.export_csv() {
            Ok(csv) => attachment(csv, "text/csv", "audit-history.csv"),
            Err(err) => history_error(err.0),
        },
        "json" => match state.store.export_json() {
            Ok(json) => attachment(json, "application/json", "audit-history.json"),
            Err(err) => history_error(err.0),
        },
        _ => match state.store.export_csv() {
            Ok(csv) => attachment(csv, "text/csv", "audit-history.csv"),
            Err(err) => history_error(err.0),
        },
    }
}

fn attachment(body: String, content_type: &'static str, filename: &str) -> Response {
    let mut response = ([(header::CONTENT_TYPE, content_type)], body).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename={filename}")
            .parse()
            .expect("filename is ASCII"),
    );
    response
}

/// `POST /api/history/clear` — delete all rows; report the combined count.
pub async fn history_clear(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    match state.store.clear_runs() {
        Ok(deleted) => axum::Json(serde_json::json!({ "deleted": deleted })).into_response(),
        Err(err) => history_error(err.0),
    }
}

