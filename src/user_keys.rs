//! 用户 API Key: sk-nvidia2api-* 生成/认证/限流 (原版 api_key_service.py 语义)。

use crate::storage::{db, now_iso};
use crate::models::UserApiKey;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

pub const KEY_PREFIX: &str = "sk-nvidia2api-";

pub fn hash_key(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

pub fn generate_raw() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 24] = rng.gen();
    format!("{KEY_PREFIX}{}", hex::encode(bytes))
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<UserApiKey> {
    Ok(UserApiKey {
        id: r.get("id")?,
        name: r.get("name")?,
        key_hash: r.get("key_hash")?,
        key_prefix: r.get("key_prefix")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        rate_limit: r.get("rate_limit")?,
        total_requests: r.get("total_requests")?,
        success_requests: r.get("success_requests")?,
        failed_requests: r.get("failed_requests")?,
        minute_window_start: r.get("minute_window_start")?,
        minute_request_count: r.get("minute_request_count")?,
        last_used_at: r.get("last_used_at")?,
        created_at: r.get("created_at")?,
    })
}

const UK_COLS: &str = "id, name, key_hash, key_prefix, enabled, rate_limit, total_requests, \
    success_requests, failed_requests, minute_window_start, minute_request_count, last_used_at, created_at";

pub fn list_all() -> Vec<UserApiKey> {
    let conn = db();
    let mut stmt = conn.prepare(&format!("SELECT {UK_COLS} FROM user_api_key ORDER BY id")).unwrap();
    stmt.query_map([], row_to_key).unwrap().filter_map(|r| r.ok()).collect()
}

/// 创建: 返回 (记录, 完整 raw key — 仅此一次展示)。
pub fn create(name: &str, rate_limit: i64) -> (UserApiKey, String) {
    let raw = generate_raw();
    let hash = hash_key(&raw);
    let prefix: String = raw.chars().take(20).collect();
    let conn = db();
    conn.execute(
        "INSERT INTO user_api_key (name, key_hash, key_prefix, rate_limit) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, hash, prefix, rate_limit],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    let k = get_by_id(id).expect("just inserted");
    (k, raw)
}

pub fn get_by_id(id: i64) -> Option<UserApiKey> {
    let conn = db();
    let mut stmt = conn.prepare(&format!("SELECT {UK_COLS} FROM user_api_key WHERE id = ?1")).ok()?;
    stmt.query_row([id], row_to_key).ok()
}

/// Bearer 认证 → UserApiKey。
pub fn authenticate(raw: &str) -> Option<UserApiKey> {
    let hash = hash_key(raw);
    let conn = db();
    let mut stmt = conn
        .prepare(&format!("SELECT {UK_COLS} FROM user_api_key WHERE key_hash = ?1"))
        .ok()?;
    stmt.query_row([&hash], row_to_key).ok()
}

#[allow(dead_code)]
fn unused_ts(_d: Option<DateTime<Utc>>) {}

/// 限流检查 + 计数。Ok(())=放行; Err("rate_limited")=429; Err("disabled")=403。
pub fn check_and_count(key: &UserApiKey) -> Result<(), &'static str> {
    if !key.enabled {
        return Err("disabled");
    }
    let now = Utc::now();
    let now_s = now_iso();
    let window_cutoff = (now - Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let conn = db();
    // 窗口过期 → 重置
    let reset = conn
        .execute(
            "UPDATE user_api_key SET minute_window_start = ?1, minute_request_count = 1, \
             total_requests = total_requests + 1, last_used_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND (minute_window_start IS NULL OR minute_window_start <= ?3)",
            rusqlite::params![now_s, key.id, window_cutoff],
        )
        .unwrap_or(0);
    if reset > 0 {
        return Ok(());
    }
    // 窗口活跃 → 限流判定 (0 = unlimited)
    if key.rate_limit > 0 {
        let cnt: i64 = conn
            .query_row(
                "SELECT minute_request_count FROM user_api_key WHERE id = ?1 AND minute_window_start > ?2",
                rusqlite::params![key.id, window_cutoff],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if cnt >= key.rate_limit {
            return Err("rate_limited");
        }
    }
    let _ = conn.execute(
        "UPDATE user_api_key SET minute_request_count = minute_request_count + 1, \
         total_requests = total_requests + 1, last_used_at = ?1, updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now_s, key.id],
    );
    Ok(())
}

pub fn report_result(key_id: i64, ok: bool) {
    let field = if ok { "success_requests" } else { "failed_requests" };
    let _ = db().execute(
        &format!("UPDATE user_api_key SET {field} = {field} + 1, updated_at = ?1 WHERE id = ?2"),
        rusqlite::params![now_iso(), key_id],
    );
}

pub fn delete(id: i64) -> bool {
    db().execute("DELETE FROM user_api_key WHERE id = ?1", [id]).unwrap_or(0) > 0
}

pub fn set_enabled(id: i64, enabled: bool) -> bool {
    db().execute(
        "UPDATE user_api_key SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![enabled as i64, now_iso(), id],
    )
    .unwrap_or(0)
        > 0
}
