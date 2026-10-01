//! Prometheus metrics for the learning layer.

use once_cell::sync::Lazy;

/// Unwrap a metric registration.
// Metric names, help strings and buckets here are compile-time constants and
// unique process-wide, so registration cannot fail at runtime.
// INVARIANT: constant, unique metric definitions (test: panic_s1_every_learning_metric_registers)
#[allow(clippy::panic)]
fn must<T>(registration: prometheus::Result<T>, what: &str) -> T {
    registration.unwrap_or_else(|e| panic!("{what}: {e}"))
}
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};

/// Total number of learning rounds completed.
pub static LEARNING_ROUNDS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    must(
        register_counter!(
            "citrate_learning_rounds_total",
            "Total number of learning rounds completed"
        ),
        "failed to register citrate_learning_rounds_total counter",
    )
});

/// Total number of aggregation operations.
pub static LEARNING_AGGREGATIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    must(
        register_counter!(
            "citrate_learning_aggregations_total",
            "Total number of embedding aggregation operations"
        ),
        "failed to register citrate_learning_aggregations_total counter",
    )
});

/// Total number of phase transitions.
pub static LEARNING_PHASE_TRANSITIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    must(
        register_counter!(
            "citrate_learning_phase_transitions_total",
            "Total number of OODA phase transitions"
        ),
        "failed to register citrate_learning_phase_transitions_total counter",
    )
});

/// Total number of adapters created.
pub static LEARNING_ADAPTER_CREATIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    must(
        register_counter!(
            "citrate_learning_adapter_creations_total",
            "Total number of learning adapters created"
        ),
        "failed to register citrate_learning_adapter_creations_total counter",
    )
});

/// Current embedding dimensionality.
pub static LEARNING_EMBEDDING_DIMENSIONS: Lazy<Gauge> = Lazy::new(|| {
    must(
        register_gauge!(
            "citrate_learning_embedding_dimensions",
            "Current embedding vector dimensionality"
        ),
        "failed to register citrate_learning_embedding_dimensions gauge",
    )
});

/// Number of active learning participants.
pub static LEARNING_ACTIVE_PARTICIPANTS: Lazy<Gauge> = Lazy::new(|| {
    must(
        register_gauge!(
            "citrate_learning_active_participants",
            "Number of active learning participants"
        ),
        "failed to register citrate_learning_active_participants gauge",
    )
});

/// Learning round duration in seconds.
pub static LEARNING_ROUND_DURATION: Lazy<Histogram> = Lazy::new(|| {
    must(
        register_histogram!(
            "citrate_learning_round_duration_seconds",
            "Duration of a learning round in seconds",
            vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
        ),
        "failed to register citrate_learning_round_duration_seconds histogram",
    )
});

/// Number of byzantine detections.
pub static LEARNING_BYZANTINE_DETECTIONS: Lazy<Counter> = Lazy::new(|| {
    must(
        register_counter!(
            "citrate_learning_byzantine_detections_total",
            "Total number of byzantine behavior detections"
        ),
        "failed to register citrate_learning_byzantine_detections_total counter",
    )
});

#[cfg(test)]
mod panic_s1_tests {
    use once_cell::sync::Lazy;

    /// PANIC-S1: pins `must()`'s INVARIANT: every learning metric registers.
    #[test]
    fn panic_s1_every_learning_metric_registers() {
        Lazy::force(&super::LEARNING_ROUNDS_TOTAL);
        Lazy::force(&super::LEARNING_AGGREGATIONS_TOTAL);
        Lazy::force(&super::LEARNING_PHASE_TRANSITIONS_TOTAL);
        Lazy::force(&super::LEARNING_ADAPTER_CREATIONS_TOTAL);
        Lazy::force(&super::LEARNING_EMBEDDING_DIMENSIONS);
        Lazy::force(&super::LEARNING_ACTIVE_PARTICIPANTS);
        Lazy::force(&super::LEARNING_ROUND_DURATION);
        Lazy::force(&super::LEARNING_BYZANTINE_DETECTIONS);
    }
}
