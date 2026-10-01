// citrate/core/execution/src/metrics.rs

// Metrics for tracking execution and precompile calls
use once_cell::sync::Lazy;
use prometheus::{register_counter_vec, register_histogram, CounterVec, Histogram};

/// Unwrap a metric registration.
// Metric names and label sets here are compile-time constants and unique
// process-wide, so registration cannot fail at runtime.
// INVARIANT: constant, unique metric definitions (test: panic_s1_every_execution_metric_registers)
#[allow(clippy::panic)]
fn must<T>(registration: prometheus::Result<T>, what: &str) -> T {
    registration.unwrap_or_else(|e| panic!("{what}: {e}"))
}

pub static VM_EXECUTIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    must(
        register_counter_vec!(
        "citrate_vm_executions_total",
        "Number of VM execution calls",
        &["status"]
    ),
    "register citrate_vm_executions_total",
)
});

pub static VM_GAS_USED: Lazy<Histogram> = Lazy::new(|| {
    must(
        register_histogram!("citrate_vm_gas_used", "Gas used by VM execution"),
        "register citrate_vm_gas_used",
    )
});

pub static PRECOMPILE_CALLS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    must(
        register_counter_vec!(
        "citrate_precompile_calls_total",
        "Total precompile calls",
        &["precompile", "method", "status"]
    ),
    "register citrate_precompile_calls_total",
)
});

#[cfg(test)]
mod panic_s1_tests {
    use once_cell::sync::Lazy;

    /// PANIC-S1: pins `must()`'s INVARIANT: every execution metric registers.
    #[test]
    fn panic_s1_every_execution_metric_registers() {
        Lazy::force(&super::VM_EXECUTIONS_TOTAL);
        Lazy::force(&super::VM_GAS_USED);
        Lazy::force(&super::PRECOMPILE_CALLS_TOTAL);
    }
}
