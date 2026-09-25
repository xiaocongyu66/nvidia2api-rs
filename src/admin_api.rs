//! Admin API——路径与原版 Django urls.py 一一对应 (28 端点)。

use crate::balancer;
use crate::config::Config;
use crate::key_pool;
use crate::models::UserApiKey;
use crate::nvidia::Upstream;
use crate::proxy_pool;
use crate::storage::{db, now_iso};
use crate::user_keys;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::openai_api::AppState;

fn ok_json(v: Value) -> Response {
    axum::Json(v).into_response()
}

fn err_json(message: &str, status: u16) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header("content-type", "application/json")
        .body(Body::from(json!({"detail": message}).to_string()))
        .unwrap()
}

fn admin_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .or_else(|| auth.strip_prefix("Token "))
        .unwrap_or("")
        .trim();
    !token.is_empty() && token == state.config.admin_token
}

fn guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if admin_authorized(state, headers) {
        None
    } else {
        Some(err_json("unauthorized", 401))
    }
}

// ---------------------------------------------------------------------------
// auth / dashboard / settings
// ---------------------------------------------------------------------------

pub async fn login(State(state): State<Arc<AppState>>, body: axum::extract::Json<Value>) -> Response {
    let username = body.0.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.0.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if username == state.config.admin_username && password == state.config.admin_password {
        ok_json(json!({"token": state.config.admin_token, "username": username}))
    } else {
        err_json("invalid credentials", 401)
    }
}

pub async fn dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let conn = db();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    let keys_total = count("SELECT COUNT(*) FROM nvidia_api_key");
    let keys_available = count("SELECT COUNT(*) FROM nvidia_api_key WHERE status = 'available'");
    let keys_invalid = count("SELECT COUNT(*) FROM nvidia_api_key WHERE status = 'invalid'");
    let keys_rate_limited = count("SELECT COUNT(*) FROM nvidia_api_key WHERE status = 'rate_limited'");
    let proxies_total = count("SELECT COUNT(*) FROM proxy");
    let proxies_enabled = count("SELECT COUNT(*) FROM proxy WHERE enabled = 1");
    let proxies_healthy = count("SELECT COUNT(*) FROM proxy WHERE status = 'healthy'");
    let models_enabled = count("SELECT COUNT(*) FROM model WHERE enabled = 1");
    let models_total = count("SELECT COUNT(*) FROM model");
    let api_keys_total = count("SELECT COUNT(*) FROM user_api_key");
    let req_24h = count("SELECT COUNT(*) FROM request_log WHERE created_at >= datetime('now','-1 day')");
    let req_ok_24h = count("SELECT COUNT(*) FROM request_log WHERE created_at >= datetime('now','-1 day') AND status='success'");
    let avg_latency: f64 = conn
        .query_row(
            "SELECT COALESCE(AVG(duration_ms),0) FROM request_log WHERE created_at >= datetime('now','-1 day') AND status='success'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0.0);
    ok_json(json!({
        "keys": {"total": keys_total, "available": keys_available, "invalid": keys_invalid, "rate_limited": keys_rate_limited},
        "proxies": {"total": proxies_total, "enabled": proxies_enabled, "healthy": proxies_healthy},
        "models": {"total": models_total, "enabled": models_enabled},
        "api_keys": {"total": api_keys_total},
        "requests_24h": {"total": req_24h, "success": req_ok_24h, "success_rate": if req_24h>0 {(req_ok_24h as f64)/(req_24h as f64)*100.0} else {0.0}, "avg_latency_ms": avg_latency},
    }))
}

pub async fn dashboard_usage(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let conn = db();
    let mut stmt = conn
        .prepare(
            "SELECT date(created_at), COUNT(*), SUM(CASE WHEN status='success' THEN 1 ELSE 0 END), \
             COALESCE(AVG(duration_ms),0) FROM request_log \
             WHERE created_at >= datetime('now','-14 days') GROUP BY date(created_at) ORDER BY date(created_at)",
        )
        .unwrap();
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            let total: i64 = r.get(1)?;
            let ok: Option<i64> = r.get(2)?;
            Ok(json!({
                "date": r.get::<_, String>(0)?,
                "total": total,
                "success": ok.unwrap_or(0),
                "avg_latency_ms": r.get::<_, f64>(3)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let _ = &state;
    ok_json(json!({"days": rows}))
}

pub async fn settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let _ = &state;
    let conn = db();
    let mut stmt = conn.prepare("SELECT key, value FROM system_setting").unwrap();
    let rows: Value = {
        let map: serde_json::Map<String, Value> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect::<Vec<(String, String)>>()
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        Value::Object(map)
    };
    ok_json(json!({"settings": rows}))
}

pub async fn settings_update(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let Some(map) = body.0.as_object() else {
        return err_json("invalid body", 400);
    };
    for (k, v) in map {
        let val = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        proxy_pool::set_setting(k, &val);
    }
    ok_json(json!({"ok": true}))
}

/// Admin 内置 playground (原版 /api/admin/chat)。
pub async fn admin_chat(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let cfg = state.config.clone();
    let routes = balancer::build_routes(Some(3), cfg.max_routes_per_request);
    if routes.is_empty() {
        return err_json("no available key", 503);
    }
    let upstream = Upstream::from_config(&cfg);
    let payload = json!({
        "model": body.0.get("model").and_then(|m| m.as_str()).unwrap_or("meta/llama-3.3-70b-instruct"),
        "messages": body.0.get("messages").cloned().unwrap_or(json!([{"role":"user","content":"hi"}])),
        "stream": false,
    });
    match crate::race::race_chat(routes, payload, &upstream).await {
        Ok(w) => ok_json(w.data),
        Err(f) => err_json(&f.errors.join("; "), 502),
    }
}

// ---------------------------------------------------------------------------
// NVIDIA keys
// ---------------------------------------------------------------------------

fn key_json(k: &crate::models::NvidiaKey) -> Value {
    serde_json::to_value(k).unwrap_or(json!({}))
}

pub async fn nvidia_keys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let keys: Vec<Value> = key_pool::list_all().iter().map(key_json).collect();
    ok_json(json!({"items": keys, "total": keys.len()}))
}

pub async fn nvidia_keys_import(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let text = body.0.get("text").and_then(|v| v.as_str()).unwrap_or("");
    if text.trim().is_empty() {
        return err_json("empty import text", 400);
    }
    let rpm = proxy_pool::setting_i64("default_nvidia_rpm", state.config.default_nvidia_rpm, &state.config);
    let res = key_pool::bulk_import(text, rpm);
    ok_json(json!({
        "success": res.success, "duplicate": res.duplicate, "invalid": res.invalid, "errors": res.errors,
    }))
}

pub async fn nvidia_key_detail(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    match key_pool::get_by_id(id) {
        Some(k) => ok_json(key_json(&k)),
        None => err_json("not found", 404),
    }
}

pub async fn nvidia_key_update(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    if let Some(status) = v.get("status").and_then(|s| s.as_str()) {
        if !key_pool::set_status(id, status) {
            return err_json("not found", 404);
        }
    }
    if let Some(rpm) = v.get("rpm_limit").and_then(|s| s.as_i64()) {
        if !key_pool::set_rpm(id, rpm) {
            return err_json("not found", 404);
        }
    }
    if v.get("name").is_some() {
        let name = v.get("name").and_then(|s| s.as_str()).unwrap_or("");
        let _ = db().execute(
            "UPDATE nvidia_api_key SET name = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![name, now_iso(), id],
        );
    }
    match key_pool::get_by_id(id) {
        Some(k) => ok_json(key_json(&k)),
        None => err_json("not found", 404),
    }
}

pub async fn nvidia_key_delete(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    if key_pool::delete(id) {
        ok_json(json!({"ok": true}))
    } else {
        err_json("not found", 404)
    }
}

pub async fn nvidia_key_test(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let Some(k) = key_pool::get_by_id(id) else {
        return err_json("not found", 404);
    };
    let cfg = state.config.clone();
    let api_key = k.api_key.clone();
    let result = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(async {
            let upstream = Upstream::from_config(&cfg);
            let (status, _) = upstream.list_models(&api_key).await;
            Ok::<u16, String>(status)
        })
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    match result {
        Ok(200) => {
            key_pool::report_success(id);
            ok_json(json!({"ok": true, "http_status": 200}))
        }
        Ok(status) => {
            key_pool::report_failure(id, "test_failed", status);
            ok_json(json!({"ok": false, "http_status": status}))
        }
        Err(e) => {
            key_pool::report_failure(id, "network_error", 0);
            ok_json(json!({"ok": false, "error": e}))
        }
    }
}

// ---------------------------------------------------------------------------
// proxies / groups
// ---------------------------------------------------------------------------

fn proxy_json(p: &crate::models::Proxy) -> Value {
    let mut v = serde_json::to_value(p).unwrap_or(json!({}));
    v["url_masked"] = json!(format!("{}://{}:{}:{}", p.protocol, p.host, p.port,
        if p.username.is_empty() { "no-auth" } else { "***" }));
    v
}

pub async fn proxies(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let items: Vec<Value> = proxy_pool::list_all().iter().map(proxy_json).collect();
    ok_json(json!({"items": items, "total": items.len()}))
}

pub async fn proxies_import(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let text = body.0.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let protocol = body.0.get("protocol").and_then(|v| v.as_str()).unwrap_or("socks5");
    if text.trim().is_empty() {
        return err_json("empty import text", 400);
    }
    let (ok, dup) = proxy_pool::bulk_import(text, protocol);
    ok_json(json!({"success": ok, "duplicate": dup}))
}

pub async fn proxy_detail(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    match proxy_pool::get_by_id(id) {
        Some(p) => ok_json(proxy_json(&p)),
        None => err_json("not found", 404),
    }
}

pub async fn proxy_update(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    if let Some(enabled) = v.get("enabled").and_then(|b| b.as_bool()) {
        if let Err(e) = proxy_pool::set_enabled(id, enabled) {
            return err_json(&e, 400);
        }
    }
    if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
        let _ = db().execute(
            "UPDATE proxy SET name = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![name, now_iso(), id],
        );
    }
    if let Some(gid) = v.get("group_id") {
        let gid = gid.as_i64();
        let _ = db().execute(
            "UPDATE proxy SET group_id = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![gid, now_iso(), id],
        );
    }
    match proxy_pool::get_by_id(id) {
        Some(p) => ok_json(proxy_json(&p)),
        None => err_json("not found", 404),
    }
}

pub async fn proxy_delete(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    if proxy_pool::delete(id) {
        ok_json(json!({"ok": true}))
    } else {
        err_json("not found", 404)
    }
}

pub async fn proxy_fetch_ip(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let Some(p) = proxy_pool::get_by_id(id) else {
        return err_json("not found", 404);
    };
    let timeout = std::time::Duration::from_secs(proxy_pool::setting_i64("proxy_timeout", 10, &state.config) as u64);
    match proxy_pool::check_proxy(&p, timeout).await {
        Ok((latency, ip, country, region, city, isp)) => {
            let conn = db();
            let _ = conn.execute(
                "UPDATE proxy SET status='healthy', latency_ms=?1, public_ip=?2, country=?3, region=?4, city=?5, isp=?6, \
                 consecutive_failures=0, success_count=success_count+1, last_check_at=?7, cooldown_until=NULL, updated_at=?7 WHERE id=?8",
                rusqlite::params![latency, ip, country, region, city, isp, now_iso(), id],
            );
            ok_json(json!({"ok": true, "latency_ms": latency, "public_ip": ip, "country": country, "region": region, "city": city, "isp": isp}))
        }
        Err(e) => {
            proxy_pool::report_result(id, false, 0.0).await;
            ok_json(json!({"ok": false, "error": e}))
        }
    }
}

pub async fn proxy_check_all(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let timeout = std::time::Duration::from_secs(proxy_pool::setting_i64("proxy_timeout", 10, &state.config) as u64);
    let proxies = proxy_pool::list_all();
    let mut tasks = tokio::task::JoinSet::new();
    for p in proxies {
        tasks.spawn(async move {
            let id = p.id;
            let res = proxy_pool::check_proxy(&p, timeout).await;
            (id, res)
        });
    }
    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok((id, Ok((latency, ip, country, region, city, isp)))) = res {
            let conn = db();
            let _ = conn.execute(
                "UPDATE proxy SET status='healthy', latency_ms=?1, public_ip=?2, country=?3, region=?4, city=?5, isp=?6, \
                 consecutive_failures=0, success_count=success_count+1, last_check_at=?7, cooldown_until=NULL, updated_at=?7 WHERE id=?8",
                rusqlite::params![latency, ip, country, region, city, isp, now_iso(), id],
            );
            results.push(json!({"id": id, "ok": true, "latency_ms": latency, "public_ip": ip}));
        } else if let Ok((id, Err(e))) = res {
            proxy_pool::report_result(id, false, 0.0).await;
            results.push(json!({"id": id, "ok": false, "error": e}));
        }
    }
    ok_json(json!({"checked": results.len(), "results": results}))
}

// --- proxy groups ---

pub async fn proxy_groups(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let conn = db();
    let mut stmt = conn
        .prepare("SELECT id, name, description, country, enabled FROM proxy_group ORDER BY id")
        .unwrap();
    let items: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "description": r.get::<_, String>(2)?,
                "country": r.get::<_, String>(3)?,
                "enabled": r.get::<_, i64>(4)? != 0,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok_json(json!({"items": items, "total": items.len()}))
}

pub async fn proxy_group_create(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let name = body.0.get("name").and_then(|n| n.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() {
        return err_json("name required", 400);
    }
    let desc = body.0.get("description").and_then(|d| d.as_str()).unwrap_or("");
    let country = body.0.get("country").and_then(|c| c.as_str()).unwrap_or("");
    let res = db().execute(
        "INSERT OR IGNORE INTO proxy_group (name, description, country) VALUES (?1, ?2, ?3)",
        rusqlite::params![name, desc, country],
    );
    match res {
        Ok(n) if n > 0 => ok_json(json!({"ok": true})),
        _ => err_json("duplicate name", 409),
    }
}

pub async fn proxy_group_update(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    if let Some(enabled) = v.get("enabled").and_then(|b| b.as_bool()) {
        let _ = db().execute(
            "UPDATE proxy_group SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![enabled as i64, now_iso(), id],
        );
    }
    if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
        let _ = db().execute(
            "UPDATE proxy_group SET name = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![name, now_iso(), id],
        );
    }
    ok_json(json!({"ok": true}))
}

pub async fn proxy_group_delete(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let n = db().execute("DELETE FROM proxy_group WHERE id = ?1", [id]).unwrap_or(0);
    if n > 0 {
        ok_json(json!({"ok": true}))
    } else {
        err_json("not found", 404)
    }
}

// ---------------------------------------------------------------------------
// models / api-keys / logs
// ---------------------------------------------------------------------------

pub async fn models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let conn = db();
    let mut stmt = conn
        .prepare("SELECT id, model_name, display_name, provider, status, enabled FROM model ORDER BY model_name")
        .unwrap();
    let items: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "model_name": r.get::<_, String>(1)?,
                "display_name": r.get::<_, String>(2)?,
                "provider": r.get::<_, String>(3)?,
                "status": r.get::<_, String>(4)?,
                "enabled": r.get::<_, i64>(5)? != 0,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok_json(json!({"items": items, "total": items.len()}))
}

/// 从 NVIDIA 同步模型列表 (upsert)。
pub async fn models_sync(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let key = key_pool::available_keys().first().cloned();
    let Some(k) = key else {
        return err_json("no_available_nvidia_key", 503);
    };
    let cfg = state.config.clone();
    let api_key = k.api_key.clone();
    let (status, ids) = Upstream::from_config(&cfg).list_models(&api_key).await;
    if status != 200 {
        return err_json(&format!("upstream_error:{status}"), 502);
    }
    let conn = db();
    let mut created = 0i64;
    let mut existing = 0i64;
    for name in &ids {
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO model (model_name) VALUES (?1)",
                rusqlite::params![name],
            )
            .unwrap_or(0);
        if n > 0 {
            created += 1;
        } else {
            existing += 1;
        }
    }
    ok_json(json!({"created": created, "existing": existing, "total": ids.len()}))
}

pub async fn model_update(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    if let Some(enabled) = v.get("enabled").and_then(|b| b.as_bool()) {
        let _ = db().execute(
            "UPDATE model SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![enabled as i64, now_iso(), id],
        );
    }
    if let Some(display) = v.get("display_name").and_then(|d| d.as_str()) {
        let _ = db().execute(
            "UPDATE model SET display_name = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![display, now_iso(), id],
        );
    }
    let n = db().query_row(
        "SELECT COUNT(*) FROM model WHERE id = ?1",
        [id],
        |r| r.get::<_, i64>(0),
    );
    match n {
        Ok(c) if c > 0 => ok_json(json!({"ok": true})),
        _ => err_json("not found", 404),
    }
}

pub async fn model_delete(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let n = db().execute("DELETE FROM model WHERE id = ?1", [id]).unwrap_or(0);
    if n > 0 {
        ok_json(json!({"ok": true}))
    } else {
        err_json("not found", 404)
    }
}

fn uk_json(k: &UserApiKey) -> Value {
    serde_json::to_value(k).unwrap_or(json!({}))
}

pub async fn api_keys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let items: Vec<Value> = user_keys::list_all().iter().map(uk_json).collect();
    ok_json(json!({"items": items, "total": items.len()}))
}

pub async fn api_keys_create(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let name = body.0.get("name").and_then(|n| n.as_str()).unwrap_or("default").to_string();
    let rate_limit = body.0.get("rate_limit").and_then(|r| r.as_i64()).unwrap_or(0);
    let (k, raw) = user_keys::create(&name, rate_limit);
    let mut v = uk_json(&k);
    v["raw_key"] = json!(raw); // 仅此一次展示
    ok_json(v)
}

pub async fn api_key_update(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    if let Some(enabled) = v.get("enabled").and_then(|b| b.as_bool()) {
        if !user_keys::set_enabled(id, enabled) {
            return err_json("not found", 404);
        }
    }
    if let Some(rl) = v.get("rate_limit").and_then(|r| r.as_i64()) {
        let _ = db().execute(
            "UPDATE user_api_key SET rate_limit = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![rl, now_iso(), id],
        );
    }
    match user_keys::get_by_id(id) {
        Some(k) => ok_json(uk_json(&k)),
        None => err_json("not found", 404),
    }
}

pub async fn api_key_delete(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    if user_keys::delete(id) {
        ok_json(json!({"ok": true}))
    } else {
        err_json("not found", 404)
    }
}

pub async fn logs(State(state): State<Arc<AppState>>, headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let limit: i64 = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(50).min(500);
    let status_filter: String = q
        .get("status")
        .cloned()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    let conn = db();
    let sql = if status_filter.is_empty() {
        format!("SELECT id, request_id, model, created_at, duration_ms, first_token_ms, status, http_status, error_type, \
             winner_route_type, winner_key_name, winner_proxy_name, is_stream, routes_count, prompt_tokens, completion_tokens, total_tokens \
             FROM request_log ORDER BY id DESC LIMIT {limit}")
    } else {
        format!("SELECT id, request_id, model, created_at, duration_ms, first_token_ms, status, http_status, error_type, \
             winner_route_type, winner_key_name, winner_proxy_name, is_stream, routes_count, prompt_tokens, completion_tokens, total_tokens \
             FROM request_log WHERE status = '{status_filter}' ORDER BY id DESC LIMIT {limit}")
    };
    let mut stmt = conn.prepare(&sql).unwrap();
    let items: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "request_id": r.get::<_, String>(1)?,
                "model": r.get::<_, String>(2)?,
                "created_at": r.get::<_, String>(3)?,
                "duration_ms": r.get::<_, f64>(4)?,
                "first_token_ms": r.get::<_, Option<f64>>(5)?,
                "status": r.get::<_, String>(6)?,
                "http_status": r.get::<_, i64>(7)?,
                "error_type": r.get::<_, String>(8)?,
                "winner_route_type": r.get::<_, String>(9)?,
                "winner_key_name": r.get::<_, String>(10)?,
                "winner_proxy_name": r.get::<_, String>(11)?,
                "is_stream": r.get::<_, i64>(12)? != 0,
                "routes_count": r.get::<_, i64>(13)?,
                "prompt_tokens": r.get::<_, i64>(14)?,
                "completion_tokens": r.get::<_, i64>(15)?,
                "total_tokens": r.get::<_, i64>(16)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    ok_json(json!({"items": items, "total": items.len()}))
}

// ---------------------------------------------------------------------------
// register (注册机)
// ---------------------------------------------------------------------------

pub async fn register_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    ok_json(crate::register::snapshot())
}

pub async fn register_start(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let count = body.0.get("count").and_then(|c| c.as_u64()).unwrap_or(1).min(50) as u32;
    match crate::register::start(count) {
        Ok(()) => ok_json(json!({"ok": true, "count": count})),
        Err(e) => err_json(&e, 400),
    }
}

pub async fn register_stop(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    crate::register::stop();
    ok_json(json!({"ok": true}))
}

pub async fn register_config(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let c = crate::register::load_config();
    ok_json(json!({
        "email_provider": c.email_provider, "cf_api_url": c.cf_api_url, "cf_admin_auth": c.cf_admin_auth,
        "cf_domain": c.cf_domain, "duck_api_url": c.duck_api_url, "duck_domain": c.duck_domain,
        "duck_api_key": c.duck_api_key, "captcha_mode": c.captcha_mode, "yescaptcha_key": c.yescaptcha_key,
        "captcharun_token": c.captcharun_token, "headless": c.headless, "org_name": c.org_name,
        "key_name": c.key_name, "key_expiry": c.key_expiry,
    }))
}

pub async fn register_config_save(State(state): State<Arc<AppState>>, headers: HeaderMap, body: axum::extract::Json<Value>) -> Response {
    if let Some(r) = guard(&state, &headers) {
        return r;
    }
    let v = body.0;
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let cfg = crate::register::RegConfig {
        email_provider: s("email_provider"),
        cf_api_url: s("cf_api_url"),
        cf_admin_auth: s("cf_admin_auth"),
        cf_domain: s("cf_domain"),
        duck_api_url: s("duck_api_url"),
        duck_domain: s("duck_domain"),
        duck_api_key: s("duck_api_key"),
        captcha_mode: s("captcha_mode"),
        yescaptcha_key: s("yescaptcha_key"),
        captcharun_token: s("captcharun_token"),
        headless: v["headless"].as_bool().unwrap_or(true),
        org_name: {
            let o = s("org_name");
            if o.is_empty() { "nvidia2api-org".into() } else { o }
        },
        key_name: {
            let k = s("key_name");
            if k.is_empty() { "AI_PLAYGROUNDS_KEY".into() } else { k }
        },
        key_expiry: {
            let e = s("key_expiry");
            if e.is_empty() { "2028-01-01".into() } else { e }
        },
        key_rpm: v["key_rpm"].as_i64().unwrap_or(40),
    };
    crate::register::save_config(&cfg);
    ok_json(json!({"ok": true}))
}
