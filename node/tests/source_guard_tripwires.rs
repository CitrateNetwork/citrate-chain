//! Source tripwires for two node-loop guards that live inline in large
//! functions with no unit seam (the sync tick in `main.rs`, the federated
//! learning checkpoint in `producer.rs`). Each check strips whitespace from
//! the source and requires the guarded expression, and each has a negative
//! control showing the predicate rejects the unguarded shape.

fn compact(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

const MAIN_RS: &str = include_str!("../src/main.rs");
const PRODUCER_RS: &str = include_str!("../src/producer.rs");

/// The sync tick computes its target from peer-advertised heads and must
/// clamp it to a bounded distance above the applied tip.
fn sync_target_is_clamped(src: &str) -> bool {
    let s = compact(src);
    s.contains("constMAX_SYNC_LOOKAHEAD:u64=10_000_000;")
        && s.contains(".max(seen).min(applied_height.saturating_add(MAX_SYNC_LOOKAHEAD));")
        && s.contains("sync_for_loop.set_target(target)")
}

#[test]
fn sync_tick_clamps_the_target_above_the_applied_tip() {
    assert!(
        sync_target_is_clamped(MAIN_RS),
        "the sync tick must clamp its target to applied_height + MAX_SYNC_LOOKAHEAD \
         before set_target"
    );
}

#[test]
fn sync_target_tripwire_negative_control() {
    let unguarded = "const MAX_SYNC_LOOKAHEAD: u64 = 10_000_000;\n\
                     let target = best_h.max(seen);\n\
                     sync_for_loop.set_target(target).await;";
    assert!(!sync_target_is_clamped(unguarded));
}

/// Peer contributions to the learning aggregate get a uniform trust weight;
/// the peer's self-reported `accuracy` must not become its weight.
fn learning_weight_is_uniform(src: &str) -> bool {
    let s = compact(src);
    s.contains("letblue_score=1.0f32;")
        && s.contains("peer_embeddings.push(PeerEmbedding{embedding:emb.embedding.clone(),confidence,blue_score,});")
        && !s.contains("blue_score:emb.profile.accuracy")
        && !s.contains("letblue_score=emb.profile.accuracy")
}

#[test]
fn learning_aggregate_does_not_weight_by_self_reported_accuracy() {
    assert!(
        learning_weight_is_uniform(PRODUCER_RS),
        "peer embeddings must carry a uniform weight, not the peer's own accuracy claim"
    );
}

#[test]
fn learning_weight_tripwire_negative_control() {
    let unguarded = "let blue_score = emb.profile.accuracy;\n\
                     peer_embeddings.push(PeerEmbedding { embedding: emb.embedding.clone(), \
                     confidence, blue_score, });";
    assert!(!learning_weight_is_uniform(unguarded));
}
