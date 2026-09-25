//! SQLite 存储：单连接 Mutex + WAL。数据目录优先级: NVIDIA2API_DATA_DIR > ~/.local/share/nvidia2api-rs。

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use rusqlite::Connection;

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NVIDIA2API_DATA_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/nvidia2api-rs");
    }
    PathBuf::from("./data")
}

pub fn db_path() -> PathBuf {
    data_dir().join("db.sqlite3")
}

pub fn init() -> Result<(), String> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let conn = Connection::open(db_path()).map_err(|e| format!("open db: {e}"))?;
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "synchronous", "NORMAL").ok();
    conn.pragma_update(None, "busy_timeout", 5000).ok();
    migrate(&conn)?;
    let _ = DB.set(Mutex::new(conn));
    Ok(())
}

pub fn db() -> MutexGuard<'static, Connection> {
    DB.get()
        .expect("db not initialized")
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn migrate(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS nvidia_api_key (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'available',
            rpm_limit INTEGER NOT NULL DEFAULT 40,
            minute_window_start TEXT,
            minute_request_count INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            cooldown_until TEXT,
            last_used_at TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_key_status_lru ON nvidia_api_key(status, last_used_at);

        CREATE TABLE IF NOT EXISTS proxy_group (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS proxy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'socks5',
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            group_id INTEGER REFERENCES proxy_group(id) ON DELETE SET NULL,
            country TEXT NOT NULL DEFAULT '',
            region TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            isp TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'unknown',
            latency_ms REAL,
            public_ip TEXT NOT NULL DEFAULT '',
            last_check_at TEXT,
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            cooldown_until TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(protocol, host, port, username)
        );
        CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled, status);

        CREATE TABLE IF NOT EXISTS model (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT 'nvidia',
            status TEXT NOT NULL DEFAULT 'active',
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS user_api_key (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            rate_limit INTEGER NOT NULL DEFAULT 0,
            total_requests INTEGER NOT NULL DEFAULT 0,
            success_requests INTEGER NOT NULL DEFAULT 0,
            failed_requests INTEGER NOT NULL DEFAULT 0,
            minute_window_start TEXT,
            minute_request_count INTEGER NOT NULL DEFAULT 0,
            last_used_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            user_api_key_id INTEGER,
            model TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            duration_ms REAL NOT NULL DEFAULT 0,
            first_token_ms REAL,
            status TEXT NOT NULL DEFAULT 'pending',
            http_status INTEGER NOT NULL DEFAULT 0,
            error_type TEXT NOT NULL DEFAULT '',
            winner_route_type TEXT NOT NULL DEFAULT '',
            winner_key_name TEXT NOT NULL DEFAULT '',
            winner_proxy_name TEXT NOT NULL DEFAULT '',
            proxy_public_ip TEXT NOT NULL DEFAULT '',
            is_stream INTEGER NOT NULL DEFAULT 0,
            routes_count INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_log_created ON request_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_log_model ON request_log(model);

        CREATE TABLE IF NOT EXISTS system_setting (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )
    .map_err(|e| format!("migrate: {e}"))
}

pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
