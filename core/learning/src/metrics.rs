//! Prometheus metrics for the learning layer.

use once_cell::sync::Lazy;
use prometheus::{
    register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram,
};

/// Total number of learning rounds completed.
pub static LEARNING_ROUNDS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "citrate_learning_rounds_total",
        "Total number of learning rounds completed"
    )
    .expect("failed to register citrate_learning_rounds_total counter")
});

/// Total number of aggregation operations.
pub static LEARNING_AGGREGATIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "citrate_learning_aggregations_total",
        "Total number of embedding aggregation operations"
    )
    .expect("failed to register citrate_learning_aggregations_total counter")
});

/// Total number of phase transitions.
pub static LEARNING_PHASE_TRANSITIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "citrate_learning_phase_transitions_total",
        "Total number of OODA phase transitions"
    )
    .expect("failed to register citrate_learning_phase_transitions_total counter")
});

/// Total number of adapters created.
pub static LEARNING_ADAPTER_CREATIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "citrate_learning_adapter_creations_total",
        "Total number of learning adapters created"
    )
    .expect("failed to register citrate_learning_adapter_creations_total counter")
});

/// Current embedding dimensionality.
pub static LEARNING_EMBEDDING_DIMENSIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "citrate_learning_embedding_dimensions",
        "Current embedding vector dimensionality"
    )
    .expect("failed to register citrate_learning_embedding_dimensions gauge")
});

/// Number of active learning participants.
pub static LEARNING_ACTIVE_PARTICIPANTS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "citrate_learning_active_participants",
        "Number of active learning participants"
    )
    .expect("failed to register citrate_learning_active_participants gauge")
});

/// Learning round duration in seconds.
pub static LEARNING_ROUND_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "citrate_learning_round_duration_seconds",
        "Duration of a learning round in seconds",
        vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .expect("failed to register citrate_learning_round_duration_seconds histogram")
});

/// Number of byzantine detections.
pub static LEARNING_BYZANTINE_DETECTIONS: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "citrate_learning_byzantine_detections_total",
        "Total number of byzantine behavior detections"
    )
    .expect("failed to register citrate_learning_byzantine_detections_total counter")
});
