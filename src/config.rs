//! 环境配置——与原版 settings.py 默认值一致。

use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub nvidia_base_url: String,
    pub default_nvidia_rpm: i64,
    pub max_routes_per_request: usize,
    pub upstream_connect_timeout_secs: u64,
    pub upstream_read_timeout_secs: u64,
    pub max_concurrent_requests: usize,
    pub admin_username: String,
    pub admin_password: String,
    pub admin_token: String,
    /// GC: 请求日志保留天数 (0=永久)
    pub gc_log_retention_days: u64,
    /// GC: 周期间隔秒数
    pub gc_interval_secs: u64,
    /// GC: 数据库超过该字节数时触发 VACUUM
    pub gc_vacuum_threshold: u64,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env_or("PORT", "8000").parse().unwrap_or(8000),
            nvidia_base_url: env_or("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            default_nvidia_rpm: env_or("DEFAULT_NVIDIA_RPM", "40").parse().unwrap_or(40),
            max_routes_per_request: env_or("MAX_ROUTES_PER_REQUEST", "50").parse().unwrap_or(50),
            upstream_connect_timeout_secs: env_or("UPSTREAM_CONNECT_TIMEOUT", "10").parse().unwrap_or(10),
            upstream_read_timeout_secs: env_or("UPSTREAM_READ_TIMEOUT", "120").parse().unwrap_or(120),
            max_concurrent_requests: env_or("MAX_CONCURRENT_REQUESTS", "100").parse().unwrap_or(100),
            admin_username: env_or("ADMIN_USERNAME", "admin"),
            admin_password: env_or("ADMIN_PASSWORD", "admin123"),
            admin_token: env_or("ADMIN_TOKEN", "dev-admin-token"),
            gc_log_retention_days: env_or("GC_LOG_RETENTION_DAYS", "7").parse().unwrap_or(7),
            gc_interval_secs: env_or("GC_INTERVAL_SECS", "300").parse().unwrap_or(300),
            gc_vacuum_threshold: env_or("GC_VACUUM_THRESHOLD_MB", "64").parse::<u64>().unwrap_or(64) * 1024 * 1024,
        }
    }
}
