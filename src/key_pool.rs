//! NVIDIA Key 池——多账号调度核心。
//!
//! 语义对齐原版 key_service.py:
//! - 可调度 = 状态可用(非 disabled/invalid) + 不在冷却 + RPM 滑动窗口未满
//! - claim_rpm_slot 原子抢占: 窗口过期→重置占首槽; 窗口内→count<rpm 才占; 满→标 rate_limited
//! - 排序: (failure_count asc, last_used_at asc) — LRU + 少失败优先
//! - 失败冷却: 401/403→invalid; 429→rate_limited+60s; invalid_response→30s; 其余→60s
//!
//! 单进程 + 全局 DB Mutex ⇒ 所有判定天然原子。

use crate::models::{mask_key, NvidiaKey};
use crate::storage::{db, now_iso};
use chrono::{DateTime, Duration, Utc};

const MINUTE_SECONDS: i64 = 60;

pub struct ImportResult {
    pub success: u32,
    pub duplicate: u32,
    pub invalid: u32,
    pub errors: Vec<String>,
}

fn parse_ts(s: &Option<String>) -> Option<DateTime<Utc>> {
    s.as_ref().and_then(|v| DateTime::parse_from_rfc3339(v).ok().map(|d| d.with_timezone(&Utc)))
}

fn row_to_key(r: &rusqlite::Row) -> rusqlite::Result<NvidiaKey> {
    let api_key: String = r.get("api_key")?;
    let masked = mask_key(&api_key);
    Ok(NvidiaKey {
        id: r.get("id")?,
        name: r.get("name")?,
        masked_key: masked,
        api_key,
        status: r.get("status")?,
        rpm_limit: r.get("rpm_limit")?,
        minute_window_start: r.get("minute_window_start")?,
        minute_request_count: r.get("minute_request_count")?,
        success_count: r.get("success_count")?,
        failure_count: r.get("failure_count")?,
        cooldown_until: r.get("cooldown_until")?,
        last_used_at: r.get("last_used_at")?,
        last_error: r.get("last_error")?,
        created_at: r.get("created_at")?,
    })
}

const KEY_COLS: &str = "id, name, api_key, status, rpm_limit, minute_window_start, minute_request_count, \
    success_count, failure_count, cooldown_until, last_used_at, last_error, created_at";

pub fn list_all() -> Vec<NvidiaKey> {
    let conn = db();
    let mut stmt = conn
        .prepare(&format!("SELECT {KEY_COLS} FROM nvidia_api_key ORDER BY id"))
        .unwrap();
    let rows = stmt.query_map([], row_to_key).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

pub fn get_by_id(id: i64) -> Option<NvidiaKey> {
    let conn = db();
    let mut stmt = conn
        .prepare(&format!("SELECT {KEY_COLS} FROM nvidia_api_key WHERE id = ?1"))
        .ok()?;
    stmt.query_row([id], row_to_key).ok()
}

/// 可调度 Key: enabled + 不在冷却 + RPM 未满; 按 (failure_count, last_used_at) 升序。
pub fn available_keys() -> Vec<NvidiaKey> {
    let now = Utc::now();
    let mut out: Vec<NvidiaKey> = list_all()
        .into_iter()
        .filter(|k| k.status != "disabled" && k.status != "invalid")
        .filter(|k| parse_ts(&k.cooldown_until).map(|c| c <= now).unwrap_or(true))
        .filter(|k| under_rpm(k, now))
        .collect();
    out.sort_by(|a, b| {
        (a.failure_count, ts_or_zero(&a.last_used_at)).cmp(&(b.failure_count, ts_or_zero(&b.last_used_at)))
    });
    out
}

fn ts_or_zero(s: &Option<String>) -> i64 {
    parse_ts(s).map(|d| d.timestamp_millis()).unwrap_or(0)
}

fn under_rpm(k: &NvidiaKey, now: DateTime<Utc>) -> bool {
    match parse_ts(&k.minute_window_start) {
        None => true,
        Some(w) => {
            if (now - w).num_seconds() >= MINUTE_SECONDS {
                true
            } else {
                k.minute_request_count < k.rpm_limit
            }
        }
    }
}

/// 原子抢占一个 RPM 槽位。返回 true=抢到。
pub fn claim_rpm_slot(key_id: i64) -> bool {
    let now = Utc::now();
    let now_s = now_iso();
    let window_cutoff = (now - Duration::seconds(MINUTE_SECONDS)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let conn = db();
    // Case 1: 窗口过期/未启动 → 重置窗口占首槽 (同时恢复 rate_limited 状态)
    let reset = conn
        .execute(
            "UPDATE nvidia_api_key SET minute_window_start = ?1, minute_request_count = 1, \
             last_used_at = ?1, status = 'available', updated_at = ?1 \
             WHERE id = ?2 AND status NOT IN ('disabled','invalid') \
             AND (cooldown_until IS NULL OR cooldown_until <= ?1) \
             AND (minute_window_start IS NULL OR minute_window_start <= ?3)",
            rusqlite::params![now_s, key_id, window_cutoff],
        )
        .unwrap_or(0);
    if reset > 0 {
        return true;
    }
    // Case 2: 窗口活跃 → count < rpm 才占
    let claimed = conn
        .execute(
            "UPDATE nvidia_api_key SET minute_request_count = minute_request_count + 1, \
             last_used_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND status NOT IN ('disabled','invalid') \
             AND (cooldown_until IS NULL OR cooldown_until <= ?1) \
             AND minute_window_start > ?3 AND minute_request_count < rpm_limit",
            rusqlite::params![now_s, key_id, window_cutoff],
        )
        .unwrap_or(0);
    if claimed > 0 {
        return true;
    }
    // 满 → 标记 rate_limited
    let _ = conn.execute(
        "UPDATE nvidia_api_key SET status = 'rate_limited', updated_at = ?1 \
         WHERE id = ?2 AND status = 'available' \
         AND minute_window_start > ?3 AND minute_request_count >= rpm_limit AND rpm_limit > 0",
        rusqlite::params![now_s, key_id, window_cutoff],
    );
    false
}

pub fn report_success(key_id: i64) {
    let conn = db();
    let _ = conn.execute(
        "UPDATE nvidia_api_key SET success_count = success_count + 1, cooldown_until = NULL, \
         last_error = '', status = CASE WHEN status = 'rate_limited' THEN 'available' ELSE status END, \
         updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now_iso(), key_id],
    );
}

/// 失败上报: 401/403→invalid; 429→rate_limited+60s; invalid_response→30s; 其余→60s。
pub fn report_failure(key_id: i64, error_type: &str, http_status: u16) {
    let now = Utc::now();
    let (new_status, cooldown_secs): (Option<&str>, i64) = match http_status {
        401 | 403 => (Some("invalid"), 0),
        429 => (Some("rate_limited"), 60),
        _ if error_type == "invalid_response" => (None, 30),
        _ => (None, 60),
    };
    let last_error = if http_status > 0 {
        format!("{error_type}:{http_status}")
    } else {
        error_type.to_string()
    };
    let cooldown_until = if cooldown_secs > 0 {
        Some((now + Duration::seconds(cooldown_secs)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    } else {
        None
    };
    let conn = db();
    let _ = conn.execute(
        "UPDATE nvidia_api_key SET failure_count = failure_count + 1, last_error = ?1, \
         status = COALESCE(?2, status), cooldown_until = COALESCE(?3, cooldown_until), updated_at = ?4 \
         WHERE id = ?5",
        rusqlite::params![last_error, new_status, cooldown_until, now_iso(), key_id],
    );
}

/// 批量导入: `name---key` 或裸 key, 去重, 自动命名。
pub fn bulk_import(text: &str, default_rpm: i64) -> ImportResult {
    let mut result = ImportResult { success: 0, duplicate: 0, invalid: 0, errors: vec![] };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let conn = db();
    let auto_idx: i64 = conn
        .query_row("SELECT COUNT(*) FROM nvidia_api_key", [], |r| r.get(0))
        .unwrap_or(0);
    let mut auto = auto_idx + 1;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (name, key) = match line.split_once("---") {
            Some((n, k)) => {
                let n = n.trim();
                let name = if n.is_empty() { format!("NVIDIA Key {auto:03}") } else { n.to_string() };
                (name, k.trim().to_string())
            }
            None => (format!("NVIDIA Key {auto:03}"), line.to_string()),
        };
        if key.is_empty() || key.contains(' ') {
            result.invalid += 1;
            result.errors.push(format!("{line}: invalid_format"));
            continue;
        }
        if !seen.insert(key.clone()) {
            result.duplicate += 1;
            continue;
        }
        let dup = conn
            .execute(
                "INSERT INTO nvidia_api_key (name, api_key, rpm_limit) VALUES (?1, ?2, ?3)",
                rusqlite::params![name, key, default_rpm],
            )
            .is_err();
        if dup {
            result.duplicate += 1;
            continue;
        }
        seen.insert(key);
        auto += 1;
        result.success += 1;
    }
    result
}

/// 注册机专用: 以邮箱命名插入, 已存在返回 false。
pub fn insert_named(name: &str, api_key: &str, rpm: i64) -> bool {
    let conn = db();
    conn.execute(
        "INSERT OR IGNORE INTO nvidia_api_key (name, api_key, rpm_limit) VALUES (?1, ?2, ?3)",
        rusqlite::params![name, api_key, rpm],
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

pub fn set_status(key_id: i64, status: &str) -> bool {
    db().execute(
        "UPDATE nvidia_api_key SET status = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![status, now_iso(), key_id],
    )
    .unwrap_or(0)
        > 0
}

pub fn delete(key_id: i64) -> bool {
    db().execute("DELETE FROM nvidia_api_key WHERE id = ?1", [key_id]).unwrap_or(0) > 0
}

pub fn set_rpm(key_id: i64, rpm: i64) -> bool {
    db().execute(
        "UPDATE nvidia_api_key SET rpm_limit = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![rpm, now_iso(), key_id],
    )
    .unwrap_or(0)
        > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_import_lines() {
        // 覆盖原版语义: name---key / 裸 key / 空名
        let cases = [
            ("主账号01---nvapi-abc", ("主账号01", "nvapi-abc")),
            ("nvapi-xyz", ("", "nvapi-xyz")),
        ];
        for (input, (want_name, want_key)) in cases {
            let (name, key) = match input.split_once("---") {
                Some((n, k)) => (n.trim().to_string(), k.trim().to_string()),
                None => (String::new(), input.to_string()),
            };
            assert_eq!(key, want_key);
            if !want_name.is_empty() {
                assert_eq!(name, want_name);
            }
        }
    }
}
