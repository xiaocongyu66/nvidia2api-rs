//! GC 回收: 后台周期任务 + 手动触发。
//!
//! 1. 请求日志按保留期清理 (gc_log_retention_days, 0=永久)
//! 2. 过期冷却/窗口状态回收 (Key + Proxy + UserKey 的过期 cooldown_until 清空, 状态复位)
//! 3. SQLite WAL checkpoint + 超阈值 VACUUM (防碎片膨胀)

use crate::config::Config;
use crate::storage::{db, db_path, now_iso};
use std::time::Duration;

pub struct GcStats {
    pub logs_deleted: usize,
    pub keys_revived: usize,
    pub proxies_revived: usize,
    pub user_windows_reset: usize,
    pub vacuumed: bool,
    pub db_bytes_before: u64,
    pub db_bytes_after: u64,
}

pub fn run(cfg: &Config) -> GcStats {
    let now = now_iso();
    let conn = db();
    let size_before = file_size();

    // 1) 日志保留期清理
    let logs_deleted = if cfg.gc_log_retention_days > 0 {
        conn.execute(
            "DELETE FROM request_log WHERE created_at <= datetime('now', ?1)",
            rusqlite::params![format!("-{} days", cfg.gc_log_retention_days)],
        )
        .unwrap_or(0)
    } else {
        0
    };

    // 2) 过期状态回收: 冷却到期的 Key 复位可用; Proxy 冷却到期复位 unknown
    let keys_revived = conn
        .execute(
            "UPDATE nvidia_api_key SET cooldown_until = NULL, \
             status = CASE WHEN status IN ('rate_limited','error','cooling') THEN 'available' ELSE status END, \
             updated_at = ?1 WHERE cooldown_until IS NOT NULL AND cooldown_until <= ?1",
            rusqlite::params![now],
        )
        .unwrap_or(0);
    let proxies_revived = conn
        .execute(
            "UPDATE proxy SET cooldown_until = NULL, \
             status = CASE WHEN status = 'cooling' THEN 'unknown' ELSE status END, updated_at = ?1 \
             WHERE cooldown_until IS NOT NULL AND cooldown_until <= ?1",
            rusqlite::params![now],
        )
        .unwrap_or(0);
    // UserKey 过期滑动窗口归零 (仅计数归零, 不动累计)
    let user_windows_reset = conn
        .execute(
            "UPDATE user_api_key SET minute_request_count = 0 \
             WHERE minute_window_start IS NOT NULL AND minute_window_start <= datetime('now', '-61 seconds') \
             AND minute_request_count > 0",
            [],
        )
        .unwrap_or(0);

    // 3) WAL checkpoint + 按阈值 VACUUM
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut vacuumed = false;
    if size_before > cfg.gc_vacuum_threshold {
        if conn.execute_batch("VACUUM;").is_ok() {
            vacuumed = true;
        }
    }

    let size_after = {
        drop(conn);
        file_size()
    };
    GcStats {
        logs_deleted,
        keys_revived,
        proxies_revived,
        user_windows_reset,
        vacuumed,
        db_bytes_before: size_before,
        db_bytes_after: size_after,
    }
}

fn file_size() -> u64 {
    std::fs::metadata(db_path()).map(|m| m.len()).unwrap_or(0)
}

/// 后台周期任务。
pub fn spawn_loop(cfg: Config) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(cfg.gc_interval_secs.max(60));
        loop {
            tokio::time::sleep(interval).await;
            let stats = run(&cfg);
            if stats.logs_deleted > 0 || stats.vacuumed || stats.keys_revived > 0 {
                eprintln!(
                    "[gc] logs=-{} keys_revived={} proxies_revived={} windows_reset={} vacuum={} db={}B",
                    stats.logs_deleted, stats.keys_revived, stats.proxies_revived,
                    stats.user_windows_reset, stats.vacuumed, stats.db_bytes_after
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn gc_compiles() {
        // GC 逻辑依赖 DB fixture, 端到端在 CI release 后设备实测覆盖
    }
}
