//! 竞速引擎——多账号调度的核心执行层。
//!
//! 语义对齐原版 race_engine.py:
//! - 非流式: 全线路并跑, 第一个**有效**响应(200+choices非空+无error)即 Winner, 其余立即 abort(连接释放)
//! - 流式: 全线路开流, 首个有效 SSE data 行定 Winner; Winner 的 Response 连同已缓冲字节移交转发层, 其余 abort
//! - 永不把裸 HTTP 200 当成功
//! - 每条线路独立上报 key/proxy 成败; 被取消的线路不上报

use crate::key_pool;
use crate::models::{NvidiaKey, Proxy};
use crate::nvidia::Upstream;
use crate::proxy_pool;
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Route {
    pub key: NvidiaKey,
    pub proxy: Option<Proxy>,
}

impl Route {
    pub fn name(&self) -> String {
        match &self.proxy {
            None => format!("direct:{}", self.key.name),
            Some(p) => format!("{}+{}", p.name, self.key.name),
        }
    }
    pub fn kind(&self) -> &'static str {
        if self.proxy.is_some() { "proxy" } else { "direct" }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReportItem {
    pub name: String,
    pub kind: String,
    pub key_name: String,
    pub proxy_name: String,
    pub status: String, // winner / failed / cancelled
    pub latency_ms: f64,
    pub error: String,
    pub http_status: u16,
}

fn report_item(route: &Route, status: &str, latency_ms: f64, error: &str, http_status: u16) -> ReportItem {
    ReportItem {
        name: route.name(),
        kind: route.kind().to_string(),
        key_name: route.key.name.clone(),
        proxy_name: route.proxy.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
        status: status.to_string(),
        latency_ms: (latency_ms * 10.0).round() / 10.0,
        error: error.to_string(),
        http_status,
    }
}

pub struct ChatRaceResult {
    pub winner_idx: usize,
    pub data: Value,
    pub report: Vec<ReportItem>,
}

pub struct StreamRaceResult {
    pub winner_idx: usize,
    /// Winner 的响应体 (流式, 尚未消费的部分)
    pub response: reqwest::Response,
    /// 首个有效 SSE 行 (含 "data: " 前缀)
    pub first_line: String,
    /// 首行之后、流结束前已缓冲的字节
    pub leftover: Vec<u8>,
    pub report: Vec<ReportItem>,
}

#[derive(Debug)]
pub struct AllRoutesFailed {
    pub report: Vec<ReportItem>,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// 有效性校验 (原版 is_valid_response / is_valid_stream_chunk)
// ---------------------------------------------------------------------------

pub fn is_valid_response(status: u16, data: &Value) -> bool {
    if status != 200 {
        return false;
    }
    if !data.is_object() {
        return false;
    }
    if data.get("error").map(|e| !e.is_null()).unwrap_or(false) {
        return false;
    }
    let choices = match data.get("choices").and_then(|c| c.as_array()) {
        Some(c) if !c.is_empty() => c,
        _ => return false,
    };
    let first = &choices[0];
    first.get("message").is_some() || first.get("delta").is_some() || first.get("text").is_some()
}

/// SSE 行校验: Some=有效 (含 [DONE] 终止行, 对齐原版)。
pub fn is_valid_stream_line(line: &str) -> Option<()> {
    let payload = line.strip_prefix("data:")?.trim();
    if payload == "[DONE]" {
        return Some(());
    }
    let data: Value = serde_json::from_str(payload).ok()?;
    if data.get("error").map(|e| !e.is_null()).unwrap_or(false) {
        return None;
    }
    data.get("choices")
        .and_then(|c| c.as_array())
        .filter(|c| !c.is_empty())
        .map(|_| ())
}

pub fn classify_status(code: u16) -> String {
    match code {
        401 => "invalid_key".into(),
        403 => "forbidden".into(),
        404 => "model_not_found".into(),
        429 => "rate_limited".into(),
        200 => "invalid_response".into(),
        c if c >= 500 => "upstream_server_error".into(),
        c => format!("http_{c}"),
    }
}

fn classify_network_err(e: &str) -> String {
    let l = e.to_lowercase();
    if l.contains("timed out") || l.contains("timeout") || l.contains("deadline") || l.contains("elapsed") {
        "timeout".into()
    } else if l.contains("connect") || l.contains("dns") || l.contains("resolve") || l.contains("proxy") {
        "connect_error".into()
    } else {
        "network_error".into()
    }
}

// ---------------------------------------------------------------------------
// 每线路客户端构建 (代理支持)
// ---------------------------------------------------------------------------

fn client_for(upstream: &Upstream, proxy: Option<&Proxy>, streaming: bool) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder().connect_timeout(upstream.connect_timeout);
    if !streaming {
        b = b.timeout(upstream.read_timeout);
    }
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p.url()).map_err(|e| e.to_string())?);
    }
    b.build().map_err(|e| e.to_string())
}

fn clone_upstream(u: &Upstream) -> Upstream {
    Upstream {
        base_url: u.base_url.clone(),
        connect_timeout: u.connect_timeout,
        read_timeout: u.read_timeout,
    }
}

// ---------------------------------------------------------------------------
// 非流式竞速
// ---------------------------------------------------------------------------

struct TaskOutcome {
    idx: usize,
    ok: bool,
    data: Value,
    http_status: u16,
    error_type: String,
    latency_ms: f64,
}

async fn do_request(idx: usize, route: Route, body: Value, upstream: Upstream, t0: Instant) -> TaskOutcome {
    let elapsed = || t0.elapsed().as_secs_f64() * 1000.0;
    let client = match client_for(&upstream, route.proxy.as_ref(), false) {
        Ok(c) => c,
        Err(e) => {
            key_pool::report_failure(route.key.id, "network_error", 0);
            return TaskOutcome { idx, ok: false, data: Value::Null, http_status: 0, error_type: classify_network_err(&e), latency_ms: elapsed() };
        }
    };
    let url = format!("{}/chat/completions", upstream.base_url);
    let resp = client.post(&url).bearer_auth(&route.key.api_key).json(&body).send().await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            let typ = classify_network_err(&e.to_string());
            key_pool::report_failure(route.key.id, &typ, 0);
            if let Some(p) = &route.proxy {
                proxy_pool::report_result(p.id, false, 0.0).await;
            }
            return TaskOutcome { idx, ok: false, data: Value::Null, http_status: 0, error_type: typ, latency_ms: elapsed() };
        }
    };
    let status = resp.status().as_u16();
    let data: Value = resp.json().await.unwrap_or(Value::Null);
    if !is_valid_response(status, &data) {
        let typ = if data.is_null() { "invalid_json".to_string() } else { classify_status(status) };
        key_pool::report_failure(route.key.id, &typ, status);
        return TaskOutcome { idx, ok: false, data: Value::Null, http_status: status, error_type: typ, latency_ms: elapsed() };
    }
    key_pool::report_success(route.key.id);
    if let Some(p) = &route.proxy {
        proxy_pool::report_result(p.id, true, 0.0).await;
    }
    TaskOutcome { idx, ok: true, data, http_status: status, error_type: String::new(), latency_ms: elapsed() }
}

/// 非流式竞速。Ok=Winner; Err=全部失败的线路报告。
pub async fn race_chat(routes: Vec<Route>, body: Value, upstream: &Upstream) -> Result<ChatRaceResult, AllRoutesFailed> {
    if routes.is_empty() {
        return Err(AllRoutesFailed { report: vec![], errors: vec!["no_route_available".into()] });
    }
    let t0 = Instant::now();
    let (tx, mut rx) = mpsc::channel::<TaskOutcome>(routes.len());
    let mut handles = Vec::with_capacity(routes.len());
    for (idx, route) in routes.iter().enumerate() {
        let tx = tx.clone();
        let body = body.clone();
        let upstream = clone_upstream(upstream);
        let route = route.clone();
        handles.push(tokio::spawn(async move {
            let out = do_request(idx, route, body, upstream, t0).await;
            let _ = tx.send(out).await;
        }));
    }
    drop(tx);

    let mut report: Vec<ReportItem> = Vec::new();
    let mut remaining = handles.len();
    let mut errors: Vec<String> = Vec::new();
    while let Some(out) = rx.recv().await {
        let route = &routes[out.idx];
        if out.ok {
            report.push(report_item(route, "winner", out.latency_ms, "", out.http_status));
            for (i, h) in handles.iter().enumerate() {
                h.abort();
                if !h.is_finished() && i != out.idx {
                    report.push(report_item(&routes[i], "cancelled", t0.elapsed().as_secs_f64() * 1000.0, "winner decided", 0));
                }
            }
            return Ok(ChatRaceResult { winner_idx: out.idx, data: out.data, report });
        }
        errors.push(format!("{}:{}", route.name(), out.error_type));
        report.push(report_item(route, "failed", out.latency_ms, &out.error_type, out.http_status));
        remaining -= 1;
        if remaining == 0 {
            break;
        }
    }
    for h in &handles {
        h.abort();
    }
    Err(AllRoutesFailed { report, errors })
}

// ---------------------------------------------------------------------------
// 流式竞速
// ---------------------------------------------------------------------------

struct StreamOutcome {
    idx: usize,
    ok: bool,
    response: Option<reqwest::Response>,
    first_line: String,
    leftover: Vec<u8>,
    http_status: u16,
    error_type: String,
}

async fn do_stream(idx: usize, route: Route, body: Value, upstream: Upstream) -> StreamOutcome {
    let fail = |error_type: String, http_status: u16| StreamOutcome {
        idx, ok: false, response: None, first_line: String::new(), leftover: vec![], http_status, error_type,
    };
    let client = match client_for(&upstream, route.proxy.as_ref(), true) {
        Ok(c) => c,
        Err(e) => {
            key_pool::report_failure(route.key.id, "network_error", 0);
            return fail(classify_network_err(&e), 0);
        }
    };
    let url = format!("{}/chat/completions", upstream.base_url);
    let mut resp = match client.post(&url).bearer_auth(&route.key.api_key).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            let typ = classify_network_err(&e.to_string());
            key_pool::report_failure(route.key.id, &typ, 0);
            if let Some(p) = &route.proxy {
                proxy_pool::report_result(p.id, false, 0.0).await;
            }
            return fail(typ, 0);
        }
    };
    let status = resp.status().as_u16();
    if status != 200 {
        let typ = classify_status(status);
        key_pool::report_failure(route.key.id, &typ, status);
        return fail(typ, status);
    }
    // 逐 chunk 缓冲并按行扫描, 找首个有效 data 行; Response 保持完整待移交
    let mut buf: Vec<u8> = Vec::new();
    let first_byte_deadline = Duration::from_secs(upstream.read_timeout.as_secs().max(30));
    let started = Instant::now();
    loop {
        if started.elapsed() > first_byte_deadline {
            key_pool::report_failure(route.key.id, "empty_stream", 200);
            return fail("empty_stream".into(), 200);
        }
        match tokio::time::timeout(upstream.read_timeout, resp.chunk()).await {
            Err(_) => {
                key_pool::report_failure(route.key.id, "timeout", 0);
                return fail("timeout".into(), 0);
            }
            Ok(Err(e)) => {
                let typ = classify_network_err(&e.to_string());
                key_pool::report_failure(route.key.id, &typ, 0);
                return fail(typ, 0);
            }
            Ok(Ok(None)) => {
                key_pool::report_failure(route.key.id, "empty_stream", 200);
                return fail("empty_stream".into(), 200);
            }
            Ok(Ok(Some(bytes))) => buf.extend_from_slice(&bytes),
        }
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line_bytes).trim_end().to_string();
            if line.trim().is_empty() {
                continue;
            }
            if is_valid_stream_line(&line).is_some() {
                key_pool::report_success(route.key.id);
                if let Some(p) = &route.proxy {
                    proxy_pool::report_result(p.id, true, 0.0).await;
                }
                return StreamOutcome { idx, ok: true, response: Some(resp), first_line: line, leftover: buf, http_status: 200, error_type: String::new() };
            }
            if line.starts_with("data:") {
                key_pool::report_failure(route.key.id, "invalid_response", 200);
                return fail("invalid_response".into(), 200);
            }
            // 注释/心跳行 → 跳过
        }
    }
}

/// 流式竞速。Ok=Winner(response+first_line+leftover); Err=全部失败报告。
pub async fn race_stream(routes: Vec<Route>, body: Value, upstream: &Upstream) -> Result<StreamRaceResult, AllRoutesFailed> {
    if routes.is_empty() {
        return Err(AllRoutesFailed { report: vec![], errors: vec!["no_route_available".into()] });
    }
    let t0 = Instant::now();
    let (tx, mut rx) = mpsc::channel::<StreamOutcome>(routes.len());
    let mut handles = Vec::with_capacity(routes.len());
    for (idx, route) in routes.iter().enumerate() {
        let tx = tx.clone();
        let body = body.clone();
        let upstream = clone_upstream(upstream);
        let route = route.clone();
        handles.push(tokio::spawn(async move {
            let out = do_stream(idx, route, body, upstream).await;
            let _ = tx.send(out).await;
        }));
    }
    drop(tx);

    let mut report: Vec<ReportItem> = Vec::new();
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    while let Some(out) = rx.recv().await {
        let route = &routes[out.idx];
        if out.ok {
            report.push(report_item(route, "winner", t0.elapsed().as_secs_f64() * 1000.0, "", 200));
            for (i, h) in handles.iter().enumerate() {
                h.abort();
                if !h.is_finished() && i != out.idx {
                    report.push(report_item(&routes[i], "cancelled", t0.elapsed().as_secs_f64() * 1000.0, "winner decided", 0));
                }
            }
            return Ok(StreamRaceResult {
                winner_idx: out.idx,
                response: out.response.unwrap(),
                first_line: out.first_line,
                leftover: out.leftover,
                report,
            });
        }
        failed += 1;
        errors.push(format!("{}:{}", route.name(), out.error_type));
        report.push(report_item(route, "failed", 0.0, &out.error_type, out.http_status));
        if failed >= routes.len() {
            break;
        }
    }
    for h in &handles {
        h.abort();
    }
    Err(AllRoutesFailed { report, errors })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_response_rejects_bare_200() {
        // 原版注释: "never treats bare HTTP 200 as success"
        assert!(!is_valid_response(200, &json!({})));
        assert!(!is_valid_response(200, &json!({"choices": []})));
        assert!(!is_valid_response(200, &json!({"error": {"message": "x"}, "choices": [{"message": {}}]})));
        assert!(is_valid_response(200, &json!({"choices": [{"message": {"role": "assistant", "content": "hi"}}]})));
        assert!(is_valid_response(200, &json!({"choices": [{"delta": {"content": "hi"}}]})));
        assert!(!is_valid_response(429, &json!({"choices": [{"message": {}}]})));
    }

    #[test]
    fn stream_line_validation() {
        assert!(is_valid_stream_line("data: [DONE]").is_some());
        assert!(is_valid_stream_line(r#"data: {"choices":[{"delta":{"content":"a"}}]}"#).is_some());
        assert!(is_valid_stream_line(r#"data: {"error": {"message": "boom"}}"#).is_none());
        assert!(is_valid_stream_line(r#"data: {"nope": 1}"#).is_none());
        assert!(is_valid_stream_line("data: not-json").is_none());
        assert!(is_valid_stream_line(": keepalive").is_none());
    }
}
