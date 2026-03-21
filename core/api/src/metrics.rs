// citrate/core/api/src/metrics.rs

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};

pub static RPC_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "citrate_rpc_requests_total",
        "Total JSON-RPC requests by method",
        &["method"]
    )
    .unwrap_or_else(|e| panic!("register citrate_rpc_requests_total: {e}"))
});

#[inline]
pub fn rpc_request(method: &str) {
    RPC_REQUESTS.with_label_values(&[method]).inc();
}
