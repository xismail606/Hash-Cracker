//! Static dashboard serving with the Flask app's conventions: index at `/`,
//! clean-URL directory resolution, no-cache headers, 503 build hint.

use std::path::{Path, PathBuf};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// Resolve `static/` relative to the working directory by default (the serve
/// scripts run from the repo root); `--static-dir` overrides.
pub fn default_static_dir() -> PathBuf {
    PathBuf::from("src/hash_cracker/static")
}

fn no_cache(headers: &mut HeaderMap, directives: &str) {
    headers.insert(header::CACHE_CONTROL, directives.parse().unwrap());
}

/// `GET /` — serve `index.html` with no-cache/no-store/must-revalidate, or
/// the pinned 503 build hint when the frontend has not been built.
pub fn serve_index(static_dir: &Path) -> Response {
    let index = static_dir.join("index.html");
    match std::fs::read(&index) {
        Ok(bytes) => {
            let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], bytes).into_response();
            no_cache(response.headers_mut(), "no-cache, no-store, must-revalidate");
            response
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "The dashboard frontend has not been built yet. Run `npm install && npm run build` in the frontend/ directory, then restart the server."
            })),
        )
            .into_response(),
    }
}

/// `GET /<path>` — resolve under `static/`; directory paths append
/// `index.html` (Astro clean-URL convention); missing → 404 JSON.
pub fn serve_asset(static_dir: &Path, asset: &str) -> Response {
    // Prevent path traversal: resolve and require the prefix to hold.
    let candidate = static_dir.join(asset);
    let Ok(canonical) = candidate.canonicalize() else {
        return not_found();
    };
    if !canonical.starts_with(static_dir.canonicalize().unwrap_or_else(|_| static_dir.to_path_buf()))
    {
        return not_found();
    }
    let file_path = if canonical.is_dir() {
        canonical.join("index.html")
    } else {
        canonical
    };
    match std::fs::read(&file_path) {
        Ok(bytes) => {
            let mut response = (
                [(header::CONTENT_TYPE, content_type(&file_path))],
                bytes,
            )
                .into_response();
            no_cache(response.headers_mut(), "no-cache");
            response
        }
        Err(_) => not_found(),
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"error": "Not found."})),
    )
        .into_response()
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_static() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("changelog")).unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>ok</html>").unwrap();
        std::fs::write(dir.path().join("changelog").join("index.html"), "<html>log</html>").unwrap();
        std::fs::write(dir.path().join("app.js"), "console.log(1)").unwrap();
        dir
    }

    #[test]
    fn index_serves_with_no_store() {
        let dir = temp_static();
        let response = serve_index(dir.path());
        assert_eq!(response.status(), StatusCode::OK);
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "no-cache, no-store, must-revalidate");
    }

    #[test]
    fn index_missing_returns_503_build_hint() {
        let dir = tempfile::tempdir().unwrap();
        let response = serve_index(dir.path());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn clean_urls_resolve_directory_index() {
        let dir = temp_static();
        let response = serve_asset(dir.path(), "changelog");
        assert_eq!(response.status(), StatusCode::OK);
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "no-cache");
    }

    #[test]
    fn missing_asset_is_404_json() {
        let dir = temp_static();
        let response = serve_asset(dir.path(), "nope.js");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn traversal_is_rejected() {
        let dir = temp_static();
        let response = serve_asset(dir.path(), "../outside.txt");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
