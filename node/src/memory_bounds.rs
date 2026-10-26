//! Configurable in-memory bounds and a periodic memory report.
//!
//! Every bound has a default sized for an 8 GB host and an env override:
//!
//! | env var | bounds | default |
//! |---|---|---|
//! | `CITRATE_DAG_RESIDENT_BODIES` | blocks whose transactions stay in the DAG store's memory | 256 |
//! | `CITRATE_ROCKSDB_MEMTABLE_MB` | RocksDB memtables, all column families | 128 MiB |
//! | `CITRATE_ROCKSDB_BLOCK_CACHE_MB` | RocksDB block cache, shared | 64 MiB |
//!
//! The RocksDB budget is applied where the database is opened
//! (`citrate_storage::db::RocksMemoryBudget`). The report logs the live sizes
//! of these structures and the process RSS once a minute (`memory:` lines), so
//! a soak can show which one, if any, is still growing.

use citrate_consensus::dag_store::DEFAULT_RESIDENT_BODY_CAP;
use citrate_consensus::DagStore;
use citrate_storage::StorageManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Env var: how many recent blocks keep their full body in the DAG store.
pub const DAG_RESIDENT_BODIES_ENV: &str = "CITRATE_DAG_RESIDENT_BODIES";

/// Env var: seconds between memory reports (0 disables). Default 60.
pub const MEMORY_REPORT_SECS_ENV: &str = "CITRATE_MEMORY_REPORT_SECS";

/// Parse the DAG resident-body cap. Unset or unparsable keeps the default.
/// 0 is allowed (every body is read back from disk).
pub fn parse_dag_resident_bodies(raw: Option<&str>) -> usize {
    raw.and_then(|r| r.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_RESIDENT_BODY_CAP)
}

/// The configured DAG resident-body cap.
pub fn dag_resident_bodies() -> usize {
    parse_dag_resident_bodies(std::env::var(DAG_RESIDENT_BODIES_ENV).ok().as_deref())
}

fn parse_report_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|r| r.trim().parse::<u64>().ok()).unwrap_or(60)
}

/// Resident set size of this process in KiB, from `/proc/self/status`.
/// `None` where procfs is unavailable.
pub fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// One report line's worth of measurements.
pub async fn report_line(storage: &StorageManager, dag: &DagStore) -> String {
    let stats = dag.get_stats().await;
    let rocks = storage.db.memory_usage();
    let mib = |b: u64| b / (1024 * 1024);
    format!(
        "memory: rss={} MiB dag_blocks={} dag_resident_bodies={} rocksdb_memtables={} MiB \
         rocksdb_block_cache={} MiB rocksdb_table_readers={} MiB",
        rss_kib().map(|k| k / 1024).unwrap_or(0),
        stats.total_blocks,
        dag.resident_body_count(),
        mib(rocks.memtables),
        mib(rocks.block_cache),
        mib(rocks.table_readers),
    )
}

/// Spawn the periodic memory report (no-op when the interval is 0).
pub fn spawn_report(storage: Arc<StorageManager>, dag: Arc<DagStore>) {
    let secs = parse_report_secs(std::env::var(MEMORY_REPORT_SECS_ENV).ok().as_deref());
    if secs == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(secs));
        loop {
            tick.tick().await;
            info!("{}", report_line(&storage, &dag).await);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_resident_bodies_parses_with_default() {
        assert_eq!(parse_dag_resident_bodies(None), DEFAULT_RESIDENT_BODY_CAP);
        assert_eq!(parse_dag_resident_bodies(Some("x")), DEFAULT_RESIDENT_BODY_CAP);
        assert_eq!(parse_dag_resident_bodies(Some(" 64 ")), 64);
        assert_eq!(parse_dag_resident_bodies(Some("0")), 0);
    }

    #[test]
    fn report_interval_parses_with_default() {
        assert_eq!(parse_report_secs(None), 60);
        assert_eq!(parse_report_secs(Some("bad")), 60);
        assert_eq!(parse_report_secs(Some("0")), 0);
        assert_eq!(parse_report_secs(Some("5")), 5);
    }

    #[test]
    fn rss_is_readable_on_linux() {
        if cfg!(target_os = "linux") {
            assert!(rss_kib().unwrap_or(0) > 0);
        }
    }

    #[tokio::test]
    async fn report_line_names_every_structure() {
        let dir = tempfile::TempDir::new().expect("tmp");
        let storage = StorageManager::new(
            dir.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage");
        let dag = DagStore::with_permissive_vrf_for_testing();
        let line = report_line(&storage, &dag).await;
        for key in [
            "rss=",
            "dag_blocks=0",
            "dag_resident_bodies=0",
            "rocksdb_memtables=",
            "rocksdb_block_cache=",
            "rocksdb_table_readers=",
        ] {
            assert!(line.contains(key), "{key} missing from {line}");
        }
    }
}
