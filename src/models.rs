//! 数据模型——与原版 apps/core/models.py 字段一一对应。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaKey {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing)]
    pub api_key: String,
    pub masked_key: String,
    pub status: String, // available / rate_limited / error / invalid / disabled
    pub rpm_limit: i64,
    pub minute_window_start: Option<String>,
    pub minute_request_count: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub cooldown_until: Option<String>,
    pub last_used_at: Option<String>,
    pub last_error: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub id: i64,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: i64,
    #[serde(skip_serializing)]
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub group_id: Option<i64>,
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub enabled: bool,
    pub status: String, // unknown / healthy / unhealthy / cooling
    pub latency_ms: Option<f64>,
    pub public_ip: String,
    pub last_check_at: Option<String>,
    pub success_count: i64,
    pub failure_count: i64,
    pub consecutive_failures: i64,
    pub cooldown_until: Option<String>,
    pub created_at: String,
}

impl Proxy {
    /// 代理 URL (reqwest 格式): socks5://user:pass@host:port
    pub fn url(&self) -> String {
        let auth = if self.username.is_empty() {
            String::new()
        } else {
            format!("{}:{}@", self.username, self.password)
        };
        format!("{}://{}{}:{}", self.protocol, auth, self.host, self.port)
    }

    pub fn display_name(&self) -> String {
        format!("{} ({}:{}:{})", self.name, self.protocol, self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub country: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModel {
    pub id: i64,
    pub model_name: String,
    pub display_name: String,
    pub provider: String,
    pub status: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserApiKey {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub enabled: bool,
    pub rate_limit: i64, // 0 = unlimited
    pub total_requests: i64,
    pub success_requests: i64,
    pub failed_requests: i64,
    pub minute_window_start: Option<String>,
    pub minute_request_count: i64,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: i64,
    pub request_id: String,
    pub model: String,
    pub created_at: String,
    pub duration_ms: f64,
    pub first_token_ms: Option<f64>,
    pub status: String,
    pub http_status: i64,
    pub error_type: String,
    pub winner_route_type: String,
    pub winner_key_name: String,
    pub winner_proxy_name: String,
    pub proxy_public_ip: String,
    pub is_stream: bool,
    pub routes_count: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

pub fn mask_key(key: &str) -> String {
    if key.len() <= 10 {
        return format!("{}****", &key[..key.len().min(4)]);
    }
    format!("{}********{}", &key[..10], &key[key.len() - 4..])
}
