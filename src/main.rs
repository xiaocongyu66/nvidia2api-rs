//! nvidia2api-rs: NVIDIA API 多账号调度网关 (单二进制)。
//!
//! 竞速引擎 + Key 池 + 代理池 + OpenAI 兼容 + 内嵌面板 + GC 回收。

mod admin_api;
mod balancer;
mod config;
mod embedded_ui;
mod gc;
mod key_pool;
mod models;
mod nvidia;
mod openai_api;
mod proxy_pool;
mod race;
mod storage;
mod user_keys;

use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cfg = config::Config::from_env();
    if let Err(e) = storage::init() {
        eprintln!("[fatal] storage init: {e}");
        std::process::exit(1);
    }
    let state = Arc::new(openai_api::AppState {
        semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrent_requests)),
        config: cfg.clone(),
    });

    // GC 后台任务
    gc::spawn_loop(cfg.clone());

    let admin = Router::new()
        .route("/login", post(admin_api::login))
        .route("/dashboard", get(admin_api::dashboard))
        .route("/dashboard/usage", get(admin_api::dashboard_usage))
        .route("/settings", get(admin_api::settings).post(admin_api::settings_update))
        .route("/chat", post(admin_api::admin_chat))
        .route("/nvidia-keys", get(admin_api::nvidia_keys))
        .route("/nvidia-keys/import", post(admin_api::nvidia_keys_import))
        .route("/nvidia-keys/{id}", get(admin_api::nvidia_key_detail).put(admin_api::nvidia_key_update).delete(admin_api::nvidia_key_delete))
        .route("/nvidia-keys/{id}/test", post(admin_api::nvidia_key_test))
        .route("/proxies", get(admin_api::proxies))
        .route("/proxies/import", post(admin_api::proxies_import))
        .route("/proxies/{id}", get(admin_api::proxy_detail).put(admin_api::proxy_update).delete(admin_api::proxy_delete))
        .route("/proxies/{id}/fetch-ip", post(admin_api::proxy_fetch_ip))
        .route("/proxies/check-all", post(admin_api::proxy_check_all))
        .route("/proxy-groups", get(admin_api::proxy_groups).post(admin_api::proxy_group_create))
        .route("/proxy-groups/{id}", put(admin_api::proxy_group_update).delete(admin_api::proxy_group_delete))
        .route("/models", get(admin_api::models))
        .route("/models/sync", post(admin_api::models_sync))
        .route("/models/{id}", put(admin_api::model_update).delete(admin_api::model_delete))
        .route("/api-keys", get(admin_api::api_keys).post(admin_api::api_keys_create))
        .route("/api-keys/{id}", put(admin_api::api_key_update).delete(admin_api::api_key_delete))
        .route("/logs", get(admin_api::logs));

    let app = Router::new()
        .route("/v1/models", get(openai_api::list_models))
        .route("/v1/chat/completions", post(openai_api::chat_completions))
        .nest("/api/admin", admin)
        .fallback(get(embedded_ui::admin_ui_fallback))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("[nvidia2api-rs] listening on {addr} (data: {})", storage::db_path().display());
    axum::serve(listener, app).await.expect("serve");
}
