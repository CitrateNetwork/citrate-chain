// citrate/core/api/src/metrics.rs

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};

/// Unwrap a metric registration.
// Every metric name, help string and label set passed here is a compile-time
// constant and names are unique process-wide, so registration in the default
// registry cannot fail at runtime.
// INVARIANT: constant, unique metric definitions (test: panic_s1_every_metric_registers_once)
#[allow(clippy::panic)]
pub(crate) fn must<T>(registration: prometheus::Result<T>, what: &str) -> T {
    registration.unwrap_or_else(|e| panic!("{what}: {e}"))
}

pub static RPC_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    crate::metrics::must(
        register_int_counter_vec!(
            "citrate_rpc_requests_total",
            "Total JSON-RPC requests by method",
            &["method"]
        ),
        "register citrate_rpc_requests_total",
    )
});

#[inline]
pub fn rpc_request(method: &str) {
    RPC_REQUESTS.with_label_values(&[method]).inc();
}

/// PIL-49c: depth of the kernel's accept backlog for the RPC listener.
///
/// On Linux, when an incoming TCP connection completes its 3-way handshake
/// but the application hasn't called `accept()` yet, the kernel parks it in
/// a per-listen-socket queue. That queue's current length is what
/// `ss -tlnH` reports as `RecvQ` for a LISTEN row. When the RPC worker pool
/// stalls — see PIL-49 for one cause — this queue piles up, and from
/// outside `rpc.citrate.ai` looks dead even though the node is still
/// producing blocks. Surfacing the depth as a gauge lets ops alert
/// *before* the public endpoint goes silent.
///
/// Summed across all listen-fds bound to the configured RPC port.
pub static RPC_ACCEPT_QUEUE_DEPTH: Lazy<IntGauge> = Lazy::new(|| {
    crate::metrics::must(
        register_int_gauge!(
            "citrate_rpc_accept_queue_depth",
            "Sum of kernel accept-backlog sizes across all RPC listen sockets (Linux). \
         Healthy under load is 0; sustained > 1 means worker threads are stalled."
        ),
        "register citrate_rpc_accept_queue_depth",
    )
});

/// PIL-49c: spawn a background task on the shared rpc_runtime that samples
/// `/proc/net/tcp` every `interval_secs` seconds and updates
/// [`RPC_ACCEPT_QUEUE_DEPTH`]. Safe on non-Linux: the sampler returns 0 and
/// the gauge stays at zero (the metric still exists for scrape parity).
///
/// `port` is the RPC listener's host-byte-order port. The sampler matches
/// any LISTEN row whose local-address port equals it, summing the RxQ
/// field (kernel accept-backlog).
pub fn spawn_accept_queue_sampler(port: u16, interval_secs: u64) {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    // Drive the loop on the shared rpc_runtime so we don't fight the
    // jsonrpc-http-server's internal tokio runtime for threads.
    let spawned = std::thread::Builder::new()
        .name("rpc-accept-q-sampler".into())
        .spawn(move || loop {
            let depth = sample_accept_queue_depth(port);
            RPC_ACCEPT_QUEUE_DEPTH.set(depth as i64);
            std::thread::sleep(interval);
        });
    // Observability only: a node that cannot spawn the sampler keeps serving RPC.
    if let Err(e) = spawned {
        tracing::error!("could not spawn rpc-accept-q-sampler thread: {e}");
    }
}

/// Read `/proc/net/tcp` once and sum the RxQ across all LISTEN sockets
/// whose local-address port matches `port`. Linux-only file; on other
/// platforms this returns 0.
///
/// `/proc/net/tcp` line layout (whitespace-separated, after the header):
///   `  N: local_address rem_address st tx_queue:rx_queue tr ...`
///   * `local_address` = `<hex ip>:<hex port>` (port is BE-hex of u16)
///   * `st` = TCP state — `0A` for LISTEN
///   * `tx_queue:rx_queue` — for LISTEN, rx_queue is the kernel
///     accept-backlog depth (i.e. completed handshakes the userspace
///     hasn't `accept()`-ed yet). Both fields are hex.
fn sample_accept_queue_depth(port: u16) -> u64 {
    let contents = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let target_hex_port = format!("{:04X}", port);
    let mut sum: u64 = 0;
    for (i, line) in contents.lines().enumerate() {
        if i == 0 {
            // header row
            continue;
        }
        let mut cols = line.split_whitespace();
        let _sl = match cols.next() {
            Some(s) => s,
            None => continue,
        };
        let local = match cols.next() {
            Some(s) => s,
            None => continue,
        };
        let _rem = cols.next();
        let st = match cols.next() {
            Some(s) => s,
            None => continue,
        };
        if st != "0A" {
            continue;
        }
        // local_address: hexip:hexport
        let port_hex = match local.rsplit_once(':') {
            Some((_, p)) => p,
            None => continue,
        };
        if port_hex != target_hex_port {
            continue;
        }
        // tx_queue:rx_queue token
        let txrx = match cols.next() {
            Some(s) => s,
            None => continue,
        };
        let rx_hex = txrx.rsplit_once(':').map(|(_, r)| r).unwrap_or(txrx);
        if let Ok(rx) = u64::from_str_radix(rx_hex, 16) {
            sum = sum.saturating_add(rx);
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::sample_accept_queue_depth;

    #[test]
    fn sample_returns_zero_on_unused_port() {
        // 65535 should never have a listener on test hosts. Sampling
        // should return 0 cleanly, not panic.
        let depth = sample_accept_queue_depth(65535);
        assert_eq!(depth, 0);
    }
}

#[cfg(test)]
mod panic_s1_tests {
    use once_cell::sync::Lazy;

    /// PANIC-S1: pins `must()`'s INVARIANT. Every metric in this crate registers in
    /// one process; a duplicate name or invalid definition panics here, in a test,
    /// instead of in a node's RPC handler. (This caught a real duplicate:
    /// `citrate_rpc_requests_total` was registered twice with different labels.)
    #[test]
    fn panic_s1_every_metric_registers_once() {
        Lazy::force(&crate::metrics::RPC_REQUESTS);
        Lazy::force(&crate::metrics::RPC_ACCEPT_QUEUE_DEPTH);
        Lazy::force(&crate::metrics_server::RPC_REQUEST_DURATION);
        Lazy::force(&crate::metrics_server::RPC_REQUEST_COUNT);
        Lazy::force(&crate::metrics_server::MEMPOOL_SIZE);
        Lazy::force(&crate::metrics_server::MEMPOOL_BYTES);
        Lazy::force(&crate::metrics_server::STORAGE_READ_DURATION);
        Lazy::force(&crate::metrics_server::STORAGE_WRITE_DURATION);
        Lazy::force(&crate::metrics_server::CACHE_HIT_RATE);
        Lazy::force(&crate::metrics_server::CACHE_SIZE);
        Lazy::force(&crate::metrics_server::DAG_HEIGHT);
        Lazy::force(&crate::metrics_server::DAG_TIPS_COUNT);
        Lazy::force(&crate::metrics_server::DAG_BLUE_SCORE);
        Lazy::force(&crate::metrics_server::EXECUTION_TIME);
        Lazy::force(&crate::metrics_server::PARALLEL_EXECUTION_GROUPS);
        Lazy::force(&crate::metrics_server::PEER_COUNT);
        Lazy::force(&crate::metrics_server::NETWORK_BYTES_RECEIVED);
        Lazy::force(&crate::metrics_server::NETWORK_BYTES_SENT);
    }
}
