//! Bridge monitoring metrics.
//!
//! Prometheus-compatible counters and gauges for bridge health.

use std::sync::atomic::{AtomicU64, Ordering};

/// Bridge health metrics.
#[derive(Debug)]
pub struct BridgeMetrics {
    /// Total deposits processed.
    pub deposits_processed: AtomicU64,

    /// Total deposits failed.
    pub deposits_failed: AtomicU64,

    /// Total withdrawals processed.
    pub withdrawals_processed: AtomicU64,

    /// Total withdrawals failed.
    pub withdrawals_failed: AtomicU64,

    /// Total SALT credited via bridge.
    pub total_salt_credited: AtomicU64,

    /// Total SALT burned via withdrawals.
    pub total_salt_burned: AtomicU64,

    /// Current relay lag (blocks behind Ethereum head).
    pub relay_lag_blocks: AtomicU64,

    /// Active oracles count.
    pub active_oracles: AtomicU64,

    /// Total oracle attestations received.
    pub attestations_received: AtomicU64,

    /// Events pending processing.
    pub events_pending: AtomicU64,

    /// Last processed Ethereum block.
    pub last_eth_block: AtomicU64,

    /// Last heartbeat timestamp.
    pub last_heartbeat: AtomicU64,
}

impl Default for BridgeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeMetrics {
    /// Create new metrics with all counters at zero.
    pub fn new() -> Self {
        Self {
            deposits_processed: AtomicU64::new(0),
            deposits_failed: AtomicU64::new(0),
            withdrawals_processed: AtomicU64::new(0),
            withdrawals_failed: AtomicU64::new(0),
            total_salt_credited: AtomicU64::new(0),
            total_salt_burned: AtomicU64::new(0),
            relay_lag_blocks: AtomicU64::new(0),
            active_oracles: AtomicU64::new(0),
            attestations_received: AtomicU64::new(0),
            events_pending: AtomicU64::new(0),
            last_eth_block: AtomicU64::new(0),
            last_heartbeat: AtomicU64::new(0),
        }
    }

    /// Record a successful deposit.
    pub fn record_deposit(&self, salt_amount: u64) {
        self.deposits_processed.fetch_add(1, Ordering::Relaxed);
        self.total_salt_credited
            .fetch_add(salt_amount, Ordering::Relaxed);
    }

    /// Record a failed deposit.
    pub fn record_deposit_failure(&self) {
        self.deposits_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful withdrawal.
    pub fn record_withdrawal(&self, salt_amount: u64) {
        self.withdrawals_processed.fetch_add(1, Ordering::Relaxed);
        self.total_salt_burned
            .fetch_add(salt_amount, Ordering::Relaxed);
    }

    /// Record a failed withdrawal.
    pub fn record_withdrawal_failure(&self) {
        self.withdrawals_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Update relay lag.
    pub fn set_relay_lag(&self, blocks: u64) {
        self.relay_lag_blocks.store(blocks, Ordering::Relaxed);
    }

    /// Update active oracle count.
    pub fn set_active_oracles(&self, count: u64) {
        self.active_oracles.store(count, Ordering::Relaxed);
    }

    /// Record an attestation received.
    pub fn record_attestation(&self) {
        self.attestations_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Update pending events count.
    pub fn set_events_pending(&self, count: u64) {
        self.events_pending.store(count, Ordering::Relaxed);
    }

    /// Update last processed block.
    pub fn set_last_eth_block(&self, block: u64) {
        self.last_eth_block.store(block, Ordering::Relaxed);
    }

    /// Update heartbeat.
    pub fn heartbeat(&self) {
        let now = chrono::Utc::now().timestamp() as u64;
        self.last_heartbeat.store(now, Ordering::Relaxed);
    }

    /// Check if relay is healthy (heartbeat within last 60 seconds).
    pub fn is_healthy(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        let last = self.last_heartbeat.load(Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        now - last < 60
    }

    /// Generate a Prometheus-compatible metrics snapshot.
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        output.push_str("# HELP citrate_bridge_deposits_total Total deposits processed\n");
        output.push_str("# TYPE citrate_bridge_deposits_total counter\n");
        output.push_str(&format!(
            "citrate_bridge_deposits_total {}\n",
            self.deposits_processed.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP citrate_bridge_deposits_failed_total Total deposits failed\n");
        output.push_str("# TYPE citrate_bridge_deposits_failed_total counter\n");
        output.push_str(&format!(
            "citrate_bridge_deposits_failed_total {}\n",
            self.deposits_failed.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP citrate_bridge_withdrawals_total Total withdrawals processed\n",
        );
        output.push_str("# TYPE citrate_bridge_withdrawals_total counter\n");
        output.push_str(&format!(
            "citrate_bridge_withdrawals_total {}\n",
            self.withdrawals_processed.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP citrate_bridge_salt_credited_total Total SALT credited via bridge\n",
        );
        output.push_str("# TYPE citrate_bridge_salt_credited_total counter\n");
        output.push_str(&format!(
            "citrate_bridge_salt_credited_total {}\n",
            self.total_salt_credited.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP citrate_bridge_relay_lag_blocks Current relay lag in blocks\n");
        output.push_str("# TYPE citrate_bridge_relay_lag_blocks gauge\n");
        output.push_str(&format!(
            "citrate_bridge_relay_lag_blocks {}\n",
            self.relay_lag_blocks.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP citrate_bridge_active_oracles Number of active oracles\n");
        output.push_str("# TYPE citrate_bridge_active_oracles gauge\n");
        output.push_str(&format!(
            "citrate_bridge_active_oracles {}\n",
            self.active_oracles.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP citrate_bridge_events_pending Events awaiting processing\n");
        output.push_str("# TYPE citrate_bridge_events_pending gauge\n");
        output.push_str(&format!(
            "citrate_bridge_events_pending {}\n",
            self.events_pending.load(Ordering::Relaxed)
        ));

        output.push_str(
            "# HELP citrate_bridge_last_eth_block Last processed Ethereum block\n",
        );
        output.push_str("# TYPE citrate_bridge_last_eth_block gauge\n");
        output.push_str(&format!(
            "citrate_bridge_last_eth_block {}\n",
            self.last_eth_block.load(Ordering::Relaxed)
        ));

        output
    }

    /// Generate a JSON health status.
    pub fn health_json(&self) -> String {
        format!(
            r#"{{"healthy":{},"deposits_processed":{},"withdrawals_processed":{},"salt_credited":{},"relay_lag":{},"active_oracles":{},"events_pending":{},"last_eth_block":{}}}"#,
            self.is_healthy(),
            self.deposits_processed.load(Ordering::Relaxed),
            self.withdrawals_processed.load(Ordering::Relaxed),
            self.total_salt_credited.load(Ordering::Relaxed),
            self.relay_lag_blocks.load(Ordering::Relaxed),
            self.active_oracles.load(Ordering::Relaxed),
            self.events_pending.load(Ordering::Relaxed),
            self.last_eth_block.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_deposit_recording() {
        let metrics = BridgeMetrics::new();
        metrics.record_deposit(10_000);
        metrics.record_deposit(5_000);
        metrics.record_deposit_failure();

        assert_eq!(metrics.deposits_processed.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.deposits_failed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_salt_credited.load(Ordering::Relaxed), 15_000);
    }

    #[test]
    fn test_metrics_withdrawal_recording() {
        let metrics = BridgeMetrics::new();
        metrics.record_withdrawal(8_000);
        metrics.record_withdrawal_failure();

        assert_eq!(metrics.withdrawals_processed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.withdrawals_failed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_salt_burned.load(Ordering::Relaxed), 8_000);
    }

    #[test]
    fn test_metrics_prometheus_output() {
        let metrics = BridgeMetrics::new();
        metrics.record_deposit(10_000);
        metrics.set_relay_lag(5);
        metrics.set_active_oracles(3);

        let output = metrics.to_prometheus();
        assert!(output.contains("citrate_bridge_deposits_total 1"));
        assert!(output.contains("citrate_bridge_relay_lag_blocks 5"));
        assert!(output.contains("citrate_bridge_active_oracles 3"));
    }

    #[test]
    fn test_metrics_health_json() {
        let metrics = BridgeMetrics::new();
        metrics.heartbeat();
        metrics.record_deposit(100);

        let json = metrics.health_json();
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains("\"deposits_processed\":1"));
    }

    #[test]
    fn test_metrics_health_no_heartbeat() {
        let metrics = BridgeMetrics::new();
        // No heartbeat → not healthy
        assert!(!metrics.is_healthy());
    }
}
