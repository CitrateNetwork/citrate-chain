// citrate/core/execution/src/metrics.rs

// Metrics for tracking execution and precompile calls
use once_cell::sync::Lazy;
use prometheus::{register_counter_vec, register_histogram, CounterVec, Histogram};

pub static VM_EXECUTIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "citrate_vm_executions_total",
        "Number of VM execution calls",
        &["status"]
    )
    .unwrap_or_else(|e| panic!("register citrate_vm_executions_total: {e}"))
});

pub static VM_GAS_USED: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("citrate_vm_gas_used", "Gas used by VM execution")
        .unwrap_or_else(|e| panic!("register citrate_vm_gas_used: {e}"))
});

pub static PRECOMPILE_CALLS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "citrate_precompile_calls_total",
        "Total precompile calls",
        &["precompile", "method", "status"]
    )
    .unwrap_or_else(|e| panic!("register citrate_precompile_calls_total: {e}"))
});
