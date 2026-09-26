//! 内嵌管理面板 (Dioxus WASM 产物, CI 构建时刷新)。
//!
//! .gz 预压缩产物直接下发 (content-encoding: gzip); 外挂 data/admin-ui/ 目录可热替换。

use axum::body::Body;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use include_dir::{include_dir, Dir};

static EMBEDDED_UI: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/embedded/admin-ui");

fn mime_of(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn embedded_response(path: &str) -> Option<Response> {
    let gz = EMBEDDED_UI.get_file(&format!("{path}.gz"));
    if let Some(f) = gz.or_else(|| EMBEDDED_UI.get_file(path)) {
        let is_gz = gz.is_some();
        let mime = mime_of(path);
        let mut b = Response::builder().status(200).header("content-type", mime);
        if is_gz {
            b = b.header("content-encoding", "gzip");
        }
        // index.html 永不缓存 (wasm/js 带 hash 可长缓存); 其余短缓存 + 协商
        let is_html = mime.starts_with("text/html");
        b = b.header("cache-control", if is_html { "no-cache, must-revalidate" } else { "public, max-age=604800, immutable" });
        return Some(b.body(Body::from(f.contents().to_vec())).unwrap());
    }
    None
}

/// API 路径永不返回 HTML (客户端把 200 HTML 当假响应)。
fn is_api_path(p: &str) -> bool {
    const API_PREFIXES: &[&str] = &["/v1/", "/api/", "/chat/completions", "/completions", "/embeddings", "/models", "/messages"];
    API_PREFIXES.iter().any(|pre| p == *pre || p.starts_with(pre))
}

/// SPA 静态托管: 外挂 admin-ui/ 优先 (热替换), 否则内嵌产物, 未命中回 index.html。
pub async fn admin_ui_fallback(uri: Uri) -> Response {
    let p = uri.path();
    if is_api_path(p) {
        return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({
            "error": {"message": format!("unknown api path: {p}"), "type": "invalid_request_error"}
        })))
        .into_response();
    }
    let path = p.trim_start_matches('/');
    let safe = path.replace("..", "");
    let asset = if safe.is_empty() { "index.html" } else { &safe };

    // 1) 外挂热替换目录
    let ext = crate::storage::data_dir().join("admin-ui").join(asset);
    if ext.is_file() {
        let mime = mime_of(asset);
        let gz = std::path::PathBuf::from(format!("{}.gz", ext.display()));
        if gz.is_file() {
            if let Ok(g) = tokio::fs::read(&gz).await {
                return Response::builder().status(200).header("content-type", mime)
                    .header("content-encoding", "gzip").body(Body::from(g)).unwrap();
            }
        }
        if let Ok(bytes) = tokio::fs::read(&ext).await {
            return Response::builder().status(200).header("content-type", mime)
                .body(Body::from(bytes)).unwrap();
        }
    }
    // 2) 内嵌产物
    if let Some(r) = embedded_response(asset) {
        return r;
    }
    // 3) SPA 路由兜底
    if let Some(r) = embedded_response("index.html") {
        return r;
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}
