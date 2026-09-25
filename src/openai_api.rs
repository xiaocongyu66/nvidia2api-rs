//! OpenAI 兼容端点: GET /v1/models, POST /v1/chat/completions (流式/非流式)。
//!
//! 流式转发: Winner 首行 + leftover 直通 + 后续 chunk 透传 (read_timeout 单 chunk 上限),
//! 上游未发 [DONE] 则补发 (对齐原版 iter_sse)。

use crate::balancer;
use crate::config::Config;
use crate::nvidia::Upstream;
use crate::race;
use crate::storage::{db, now_iso};
use crate::user_keys;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub config: Config,
    pub semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

fn openai_error(message: &str, code: &str, status: u16, typ: &str) -> Response {
    let body = json!({
        "error": {"message": message, "type": typ, "code": code}
    });
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}

/// GET /v1/models — 仅 enabled 模型。
pub async fn list_models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let _ = &state;
    let Some(raw) = extract_bearer(&headers) else {
        return openai_error("Invalid API key", "invalid_api_key", 401, "authentication_error");
    };
    let Some(uk) = user_keys::authenticate(&raw) else {
        return openai_error("Invalid API key", "invalid_api_key", 401, "authentication_error");
    };
    if !uk.enabled {
        return openai_error("API key disabled", "key_disabled", 403, "authentication_error");
    }
    let conn = db();
    let mut stmt = conn
        .prepare("SELECT model_name, provider, created_at FROM model WHERE enabled = 1 ORDER BY model_name")
        .unwrap();
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let data: Vec<Value> = rows
        .iter()
        .map(|(name, provider, created)| {
            let ts = chrono::DateTime::parse_from_rfc3339(created)
                .map(|d| d.timestamp())
                .unwrap_or(0);
            json!({"id": name, "object": "model", "created": ts, "owned_by": provider})
        })
        .collect();
    axum::Json(json!({"object": "list", "data": data})).into_response()
}

/// POST /v1/chat/completions。
pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::extract::Json<Value>,
) -> Response {
    let Some(raw) = extract_bearer(&headers) else {
        return openai_error("Invalid API key", "invalid_api_key", 401, "authentication_error");
    };
    let Some(uk) = user_keys::authenticate(&raw) else {
        return openai_error("Invalid API key", "invalid_api_key", 401, "authentication_error");
    };
    if let Err(reason) = user_keys::check_and_count(&uk) {
        return match reason {
            "rate_limited" => openai_error("Rate limit exceeded", "rate_limit_exceeded", 429, "api_error"),
            _ => openai_error("API key disabled", "key_disabled", 403, "authentication_error"),
        };
    }
    let cfg = &state.config;
    let payload = body.0;
    let model = payload.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let is_stream = payload.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let request_id = uuid::Uuid::new_v4().to_string();
    let t0 = Instant::now();

    // 模型白名单 (启用中的模型才放行)
    let allowed: bool = db()
        .query_row(
            "SELECT COUNT(*) FROM model WHERE model_name = ?1 AND enabled = 1",
            [&model],
            |r| r.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);
    if !allowed {
        user_keys::report_result(uk.id, false);
        log_request(&request_id, uk.id, &model, is_stream, 0, 0.0, None, "error", 400, "model_not_allowed", &[]);
        return openai_error(&format!("model {model} not available"), "model_not_found", 404, "invalid_request_error");
    }

    // 并发闸门
    let permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            user_keys::report_result(uk.id, false);
            log_request(&request_id, uk.id, &model, is_stream, 0, 0.0, None, "error", 503, "server_busy", &[]);
            return openai_error("Server busy, too many concurrent requests", "server_busy", 503, "api_error");
        }
    };

    let routes = balancer::build_routes(None, cfg.max_routes_per_request);
    let routes_count = routes.len() as i64;
    if routes.is_empty() {
        drop(permit);
        user_keys::report_result(uk.id, false);
        log_request(&request_id, uk.id, &model, is_stream, 0, 0.0, None, "error", 503, "no_route_available", &[]);
        return openai_error("No available NVIDIA key or proxy route", "no_route_available", 503, "api_error");
    }

    let upstream = Upstream::from_config(cfg);
    let result = if is_stream {
        match race::race_stream(routes, payload.clone(), &upstream).await {
            Ok(w) => {
                let ttft = w.report.iter().find(|r| r.status == "winner").map(|r| r.latency_ms);
                let (report, first_line, leftover) = (w.report.clone(), w.first_line.clone(), w.leftover.clone());
                drop(permit);
                return stream_response(
                    state.clone(), w.response, first_line, leftover, ttft,
                    LogCtx { request_id, uk_id: uk.id, model, routes_count, report, t0 },
                );
            }
            Err(failed) => {
                drop(permit);
                user_keys::report_result(uk.id, false);
                log_request(&request_id, uk.id, &model, true, routes_count, t0.elapsed().as_secs_f64() * 1000.0, None, "error", 502, "all_routes_failed", &failed.report);
                let msg = if failed.errors.is_empty() { "all routes failed".to_string() } else { failed.errors.join("; ") };
                return openai_error(&msg, "all_routes_failed", 502, "api_error");
            }
        }
    } else {
        match race::race_chat(routes, payload.clone(), &upstream).await {
            Ok(w) => w,
            Err(failed) => {
                drop(permit);
                user_keys::report_result(uk.id, false);
                log_request(&request_id, uk.id, &model, false, routes_count, t0.elapsed().as_secs_f64() * 1000.0, None, "error", 502, "all_routes_failed", &failed.report);
                let msg = if failed.errors.is_empty() { "all routes failed".to_string() } else { failed.errors.join("; ") };
                return openai_error(&msg, "all_routes_failed", 502, "api_error");
            }
        }
    };

    // 非流式 Winner
    let ttft = result.report.iter().find(|r| r.status == "winner").map(|r| r.latency_ms);
    let usage = &result.data["usage"];
    let (pt, ct, tt) = (
        usage["prompt_tokens"].as_i64().unwrap_or(0),
        usage["completion_tokens"].as_i64().unwrap_or(0),
        usage["total_tokens"].as_i64().unwrap_or(0),
    );
    drop(permit);
    user_keys::report_result(uk.id, true);
    log_request_full(&request_id, uk.id, &model, false, routes_count, t0.elapsed().as_secs_f64() * 1000.0, ttft, "success", 200, "", &result.report, pt, ct, tt);
    axum::Json(result.data).into_response()
}

struct LogCtx {
    request_id: String,
    uk_id: i64,
    model: String,
    routes_count: i64,
    report: Vec<race::ReportItem>,
    t0: Instant,
}

/// SSE 响应: 首行 + leftover + 透传 + [DONE] 补发。
fn stream_response(
    _state: Arc<AppState>,
    response: reqwest::Response,
    first_line: String,
    leftover: Vec<u8>,
    ttft: Option<f64>,
    ctx: LogCtx,
) -> Response {
    let read_timeout = std::time::Duration::from_secs(
        crate::config::Config::from_env().upstream_read_timeout_secs,
    );
    let body_stream = async_stream::stream! {
        // 1) Winner 首行
        yield Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(format!("{}\n\n", first_line)));
        // 2) 已缓冲 leftover 直通
        if !leftover.is_empty() {
            yield Ok(bytes::Bytes::from(leftover));
        }
        // 3) 透传剩余流
        let mut resp = response;
        let mut saw_done = first_line.trim().ends_with("[DONE]");
        loop {
            match tokio::time::timeout(read_timeout, resp.chunk()).await {
                Err(_) => break, // 读超时, 结束并补 [DONE]
                Ok(Err(_)) => break,
                Ok(Ok(None)) => break,
                Ok(Ok(Some(chunk))) => {
                    if let Ok(s) = std::str::from_utf8(&chunk) {
                        if s.contains("[DONE]") {
                            saw_done = true;
                        }
                    }
                    yield Ok(chunk);
                }
            }
        }
        if !saw_done {
            yield Ok(bytes::Bytes::from("data: [DONE]\n\n"));
        }
        // 结算日志
        let duration = ctx.t0.elapsed().as_secs_f64() * 1000.0;
        user_keys::report_result(ctx.uk_id, true);
        log_request(&ctx.request_id, ctx.uk_id, &ctx.model, true, ctx.routes_count, duration, ttft, "success", 200, "", &ctx.report);
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream; charset=utf-8")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(Body::from_stream(body_stream))
        .unwrap()
}

fn log_request(
    request_id: &str,
    uk_id: i64,
    model: &str,
    is_stream: bool,
    routes_count: i64,
    duration_ms: f64,
    ttft: Option<f64>,
    status: &str,
    http_status: u16,
    error_type: &str,
    report: &[race::ReportItem],
) {
    log_request_full(request_id, uk_id, model, is_stream, routes_count, duration_ms, ttft, status, http_status, error_type, report, 0, 0, 0);
}

fn log_request_full(
    request_id: &str,
    uk_id: i64,
    model: &str,
    is_stream: bool,
    routes_count: i64,
    duration_ms: f64,
    ttft: Option<f64>,
    status: &str,
    http_status: u16,
    error_type: &str,
    report: &[race::ReportItem],
    pt: i64,
    ct: i64,
    tt: i64,
) {
    let winner = report.iter().find(|r| r.status == "winner");
    let conn = db();
    let _ = conn.execute(
        "INSERT INTO request_log (request_id, user_api_key_id, model, created_at, duration_ms, first_token_ms, \
         status, http_status, error_type, winner_route_type, winner_key_name, winner_proxy_name, \
         proxy_public_ip, is_stream, routes_count, prompt_tokens, completion_tokens, total_tokens) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        rusqlite::params![
            request_id,
            uk_id,
            model,
            now_iso(),
            duration_ms,
            ttft,
            status,
            http_status as i64,
            error_type,
            winner.map(|w| w.kind.clone()).unwrap_or_default(),
            winner.map(|w| w.key_name.clone()).unwrap_or_default(),
            winner.map(|w| w.proxy_name.clone()).unwrap_or_default(),
            "",
            is_stream as i64,
            routes_count,
            pt,
            ct,
            tt,
        ],
    );
}
