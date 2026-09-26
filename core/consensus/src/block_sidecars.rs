// citrate/core/consensus/src/block_sidecars.rs
//
// The block fields that sit outside the header hash's legacy preimage:
// `ghostdag_params`, `embedded_models`, `required_pins`, `learning_embedding`,
// `learning_confidence`, `gradient_commitment` and `learning_root`.
//
// Before the activation height none of them is covered by `Block::compute_hash`,
// so two copies of a block that differ only in these fields share one hash.
// This module makes the stored copy the one the hash describes:
//
//   * From the activation height, the block hash commits to these fields
//     ([`commit_into`], called by `Block::compute_hash_for`). A block whose
//     fields are all at their canonical empty value (the only shape an honest
//     producer emits outside checkpoint blocks) hashes exactly as before; any
//     other value appends a domain-separated commitment to the preimage, so
//     they cannot change without changing the hash.
//   * Below the activation height the legacy hash stays byte-identical, and
//     admission stores the block with these fields reset to their canonical
//     empty value ([`strip`]). Nothing reads them from a received block, so
//     dropping them loses nothing, and every copy of a block is stored the
//     same way. Genesis (height 0) is built locally and is never stripped.
//
// `equivocation_vote` and `signature` are signatures over the block hash, so
// they cannot be inside it. `signature` is verified at ingress; the vote is a
// sidecar verified by whoever uses it as evidence.

use crate::types::{Block, EmbeddedModel, GhostDagParams, Hash, ModelType, RequiredModel};
use sha3::{Digest, Sha3_256};

/// Domain tag appended to the block-hash preimage ahead of the commitment.
pub const SIDECAR_COMMIT_DOMAIN: &[u8] = b"citrate:block-sidecars:v1";

/// Whether every sidecar field is at its canonical empty value.
pub fn is_canonical_empty(block: &Block) -> bool {
    let Block {
        ghostdag_params,
        embedded_models,
        required_pins,
        learning_embedding,
        learning_confidence,
        gradient_commitment,
        learning_root,
        // Committed by the legacy preimage, or signatures over the hash.
        header: _,
        state_root: _,
        tx_root: _,
        receipt_root: _,
        artifact_root: _,
        transactions: _,
        signature: _,
        equivocation_vote: _,
    } = block;
    params_are_default(ghostdag_params)
        && embedded_models.is_empty()
        && required_pins.is_empty()
        && learning_embedding.is_none()
        && learning_confidence.is_none()
        && gradient_commitment.is_none()
        && *learning_root == Hash::default()
}

/// The canonical empty GhostDAG params: the values every honest producer
/// emits today. Pinned here so a later change to `GhostDagParams::default()`
/// cannot change which blocks hash as "no sidecars" (and so re-hash blocks
/// already on chain).
pub const CANONICAL_EMPTY_PARAMS: GhostDagParams = GhostDagParams {
    k: 18,
    max_parents: 10,
    max_blue_score_diff: 1000,
    pruning_window: 100_000,
    finality_depth: 100,
};

fn params_are_default(p: &GhostDagParams) -> bool {
    let d = CANONICAL_EMPTY_PARAMS;
    let GhostDagParams {
        k,
        max_parents,
        max_blue_score_diff,
        pruning_window,
        finality_depth,
    } = p;
    *k == d.k
        && *max_parents == d.max_parents
        && *max_blue_score_diff == d.max_blue_score_diff
        && *pruning_window == d.pruning_window
        && *finality_depth == d.finality_depth
}

/// Reset every sidecar field to its canonical empty value.
pub fn strip(block: &mut Block) {
    block.ghostdag_params = CANONICAL_EMPTY_PARAMS;
    block.embedded_models = Vec::new();
    block.required_pins = Vec::new();
    block.learning_embedding = None;
    block.learning_confidence = None;
    block.gradient_commitment = None;
    block.learning_root = Hash::default();
}

/// Append the sidecar commitment to a block-hash preimage, unless every field
/// is canonical-empty (then the preimage is left exactly as the legacy one).
pub fn commit_into(hasher: &mut Sha3_256, block: &Block) {
    if is_canonical_empty(block) {
        return;
    }
    hasher.update(SIDECAR_COMMIT_DOMAIN);
    hasher.update(commitment(block).as_bytes());
}

fn put_bytes(h: &mut Sha3_256, b: &[u8]) {
    h.update((b.len() as u64).to_le_bytes());
    h.update(b);
}

fn put_opt_f32s(h: &mut Sha3_256, v: &Option<Vec<f32>>) {
    match v {
        Some(xs) => {
            h.update([1u8]);
            h.update((xs.len() as u64).to_le_bytes());
            for x in xs {
                h.update(x.to_bits().to_le_bytes());
            }
        }
        None => h.update([0u8]),
    }
}

fn put_opt_str(h: &mut Sha3_256, v: &Option<String>) {
    match v {
        Some(s) => {
            h.update([1u8]);
            put_bytes(h, s.as_bytes());
        }
        None => h.update([0u8]),
    }
}

fn model_type_tag(t: ModelType) -> u8 {
    match t {
        ModelType::Embeddings => 0,
        ModelType::TinyLLM => 1,
        ModelType::GeneralLLM => 2,
        ModelType::CodeLLM => 3,
        ModelType::VisionLLM => 4,
        ModelType::Diffusion => 5,
    }
}

fn put_embedded(h: &mut Sha3_256, m: &EmbeddedModel) {
    let EmbeddedModel {
        model_id,
        model_type,
        weights_sha256,
        metadata,
    } = m;
    let crate::types::ModelMetadata {
        name,
        version,
        context_length,
        embedding_dim,
        license,
        framework,
    } = metadata;
    put_bytes(h, model_id.0.as_bytes());
    h.update([model_type_tag(*model_type)]);
    h.update(weights_sha256.as_bytes());
    put_bytes(h, name.as_bytes());
    put_bytes(h, version.as_bytes());
    h.update(context_length.to_le_bytes());
    match embedding_dim {
        Some(d) => {
            h.update([1u8]);
            h.update(d.to_le_bytes());
        }
        None => h.update([0u8]),
    }
    put_bytes(h, license.as_bytes());
    put_opt_str(h, framework);
}

fn put_required(h: &mut Sha3_256, m: &RequiredModel) {
    let RequiredModel {
        model_id,
        ipfs_cid,
        sha256_hash,
        size_bytes,
        must_pin,
        slash_penalty,
        grace_period_hours,
    } = m;
    put_bytes(h, model_id.0.as_bytes());
    put_bytes(h, ipfs_cid.as_bytes());
    h.update(sha256_hash.as_bytes());
    h.update(size_bytes.to_le_bytes());
    h.update([u8::from(*must_pin)]);
    h.update(slash_penalty.to_le_bytes());
    h.update(grace_period_hours.to_le_bytes());
}

/// A commitment to every sidecar field, with an explicit, length-prefixed,
/// field-by-field encoding (a new field has to be added here on purpose; the
/// exhaustive destructuring stops the build until it is).
pub fn commitment(block: &Block) -> Hash {
    let GhostDagParams {
        k,
        max_parents,
        max_blue_score_diff,
        pruning_window,
        finality_depth,
    } = &block.ghostdag_params;
    let mut h = Sha3_256::new();
    h.update(SIDECAR_COMMIT_DOMAIN);
    h.update(k.to_le_bytes());
    h.update((*max_parents as u64).to_le_bytes());
    h.update(max_blue_score_diff.to_le_bytes());
    h.update(pruning_window.to_le_bytes());
    h.update(finality_depth.to_le_bytes());
    h.update((block.embedded_models.len() as u64).to_le_bytes());
    for m in &block.embedded_models {
        put_embedded(&mut h, m);
    }
    h.update((block.required_pins.len() as u64).to_le_bytes());
    for m in &block.required_pins {
        put_required(&mut h, m);
    }
    put_opt_f32s(&mut h, &block.learning_embedding);
    put_opt_f32s(&mut h, &block.learning_confidence);
    match &block.gradient_commitment {
        Some(c) => {
            h.update([1u8]);
            h.update(c);
        }
        None => h.update([0u8]),
    }
    h.update(block.learning_root.as_bytes());
    Hash::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ModelId, ModelMetadata};

    fn full() -> Block {
        let mut b = crate::types::BlockBuilder::new().build_unhashed();
        b.learning_embedding = Some(vec![1.0, 2.0]);
        b.learning_confidence = Some(vec![0.5]);
        b.gradient_commitment = Some([7; 32]);
        b.learning_root = Hash::new([9; 32]);
        b.embedded_models = vec![EmbeddedModel {
            model_id: ModelId("m".into()),
            model_type: ModelType::TinyLLM,
            weights_sha256: Hash::new([1; 32]),
            metadata: ModelMetadata {
                name: "n".into(),
                version: "1".into(),
                context_length: 8,
                embedding_dim: Some(4),
                license: "l".into(),
                framework: Some("f".into()),
            },
        }];
        b.required_pins = vec![RequiredModel {
            model_id: ModelId("r".into()),
            ipfs_cid: "cid".into(),
            sha256_hash: Hash::new([2; 32]),
            size_bytes: 3,
            must_pin: true,
            slash_penalty: 4,
            grace_period_hours: 5,
        }];
        b
    }

    /// Every sub-field of every sidecar is in the commitment: changing any one
    /// of them, from one non-empty value to another, changes it.
    #[test]
    fn commitment_covers_every_sub_field() {
        type M = fn(&mut Block);
        let muts: &[(&str, M)] = &[
            ("embedding value", |b| {
                b.learning_embedding = Some(vec![1.0, 3.0])
            }),
            ("confidence value", |b| {
                b.learning_confidence = Some(vec![0.25])
            }),
            ("gradient", |b| b.gradient_commitment = Some([8; 32])),
            ("learning_root", |b| b.learning_root = Hash::new([6; 32])),
            ("k", |b| b.ghostdag_params.k += 1),
            ("max_parents", |b| b.ghostdag_params.max_parents += 1),
            ("blue diff", |b| b.ghostdag_params.max_blue_score_diff += 1),
            ("pruning", |b| b.ghostdag_params.pruning_window += 1),
            ("finality", |b| b.ghostdag_params.finality_depth += 1),
            ("model id", |b| {
                b.embedded_models[0].model_id = ModelId("x".into())
            }),
            ("type Embeddings", |b| {
                b.embedded_models[0].model_type = ModelType::Embeddings
            }),
            ("type GeneralLLM", |b| {
                b.embedded_models[0].model_type = ModelType::GeneralLLM
            }),
            ("weights", |b| {
                b.embedded_models[0].weights_sha256 = Hash::new([3; 32])
            }),
            ("name", |b| b.embedded_models[0].metadata.name = "o".into()),
            ("version", |b| {
                b.embedded_models[0].metadata.version = "2".into()
            }),
            ("ctx", |b| b.embedded_models[0].metadata.context_length = 9),
            ("dim", |b| {
                b.embedded_models[0].metadata.embedding_dim = Some(5)
            }),
            ("dim none", |b| {
                b.embedded_models[0].metadata.embedding_dim = None
            }),
            ("license", |b| {
                b.embedded_models[0].metadata.license = "m".into()
            }),
            ("framework", |b| {
                b.embedded_models[0].metadata.framework = Some("g".into())
            }),
            ("framework none", |b| {
                b.embedded_models[0].metadata.framework = None
            }),
            ("pin id", |b| {
                b.required_pins[0].model_id = ModelId("s".into())
            }),
            ("cid", |b| b.required_pins[0].ipfs_cid = "cie".into()),
            ("pin sha", |b| {
                b.required_pins[0].sha256_hash = Hash::new([4; 32])
            }),
            ("size", |b| b.required_pins[0].size_bytes = 4),
            ("must_pin", |b| b.required_pins[0].must_pin = false),
            ("slash", |b| b.required_pins[0].slash_penalty = 5),
            ("grace", |b| b.required_pins[0].grace_period_hours = 6),
        ];
        let base = commitment(&full());
        for (name, m) in muts {
            let mut b = full();
            m(&mut b);
            assert_ne!(commitment(&b), base, "{name} must be committed");
        }
        // The model-type tags are distinct per variant.
        let tags = [
            ModelType::Embeddings,
            ModelType::TinyLLM,
            ModelType::GeneralLLM,
            ModelType::CodeLLM,
            ModelType::VisionLLM,
            ModelType::Diffusion,
        ]
        .map(model_type_tag);
        assert_eq!(tags, [0, 1, 2, 3, 4, 5]);
    }

    /// The canonical empty GhostDAG params are pinned values, not whatever
    /// `GhostDagParams::default()` returns in a later release.
    #[test]
    fn canonical_empty_params_are_pinned() {
        let GhostDagParams {
            k,
            max_parents,
            max_blue_score_diff,
            pruning_window,
            finality_depth,
        } = CANONICAL_EMPTY_PARAMS;
        assert_eq!(
            (
                k,
                max_parents,
                max_blue_score_diff,
                pruning_window,
                finality_depth
            ),
            (18, 10, 1000, 100_000, 100)
        );
        let mut b = full();
        strip(&mut b);
        assert!(is_canonical_empty(&b));
        for m in [
            |p: &mut GhostDagParams| p.k += 1,
            |p: &mut GhostDagParams| p.max_parents += 1,
            |p: &mut GhostDagParams| p.max_blue_score_diff += 1,
            |p: &mut GhostDagParams| p.pruning_window += 1,
            |p: &mut GhostDagParams| p.finality_depth += 1,
        ] {
            let mut x = b.clone();
            m(&mut x.ghostdag_params);
            assert!(!is_canonical_empty(&x));
        }
    }

    /// `compute_hash_for`: legacy below H and for empty sidecars; the
    /// commitment is appended from H (the height itself included).
    #[test]
    fn compute_hash_for_commits_from_h() {
        use crate::hardening::PbaHardening;
        let mut b = full();
        b.header.height = 10;
        let mut empty = b.clone();
        strip(&mut empty);
        let off = PbaHardening::off();
        for h in [PbaHardening::at(10), PbaHardening::at(9)] {
            assert_ne!(b.compute_hash_for(h), b.compute_hash_for(off));
            assert_eq!(empty.compute_hash_for(h), empty.compute_hash_for(off));
        }
        assert_eq!(
            b.compute_hash_for(PbaHardening::at(11)),
            b.compute_hash_for(off)
        );
        // Every non-empty field on its own is enough to append the commitment.
        type M = fn(&mut Block);
        let singles: [M; 7] = [
            |x| x.ghostdag_params.k = 1,
            |x| x.embedded_models = full().embedded_models,
            |x| x.required_pins = full().required_pins,
            |x| x.learning_embedding = Some(vec![]),
            |x| x.learning_confidence = Some(vec![]),
            |x| x.gradient_commitment = Some([0; 32]),
            |x| x.learning_root = Hash::new([1; 32]),
        ];
        for m in singles {
            let mut x = empty.clone();
            m(&mut x);
            assert_ne!(
                x.compute_hash_for(PbaHardening::at(10)),
                x.compute_hash_for(off)
            );
        }
    }

    /// `verify_hash_for` accepts exactly the hash `compute_hash_for` gives
    /// under the same activation height.
    #[test]
    fn verify_hash_for_matches_compute_hash_for() {
        use crate::hardening::PbaHardening;
        let mut b = full();
        b.header.height = 10;
        let at = PbaHardening::at(10);
        b.header.block_hash = b.compute_hash_for(at);
        assert!(b.verify_hash_for(at));
        assert!(!b.verify_hash_for(PbaHardening::off()));
        b.header.block_hash = Hash::new([0xAB; 32]);
        assert!(!b.verify_hash_for(at));
    }

    /// Length prefixes keep adjacent variable fields from trading bytes.
    #[test]
    fn variable_fields_are_length_prefixed() {
        let mut a = full();
        a.embedded_models[0].metadata.name = "ab".into();
        a.embedded_models[0].metadata.version = "c".into();
        let mut b = full();
        b.embedded_models[0].metadata.name = "a".into();
        b.embedded_models[0].metadata.version = "bc".into();
        assert_ne!(commitment(&a), commitment(&b));
    }
}
