//! Cross-implementation check: a round the compute-pool coordinator aggregated
//! through a devnet node's 0x0110 (fixture: `tests/fixtures/devnet-round-0`)
//! replays clean under this crate's independent implementation, and every kind
//! of tampering is reported rather than tolerated.

use std::path::{Path, PathBuf};

use citrate_fl_replay::{replay, Bundle, ChainRules, Inputs, Report};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/devnet-round-0")
}

fn load_bundle(dir: &Path) -> Bundle {
    serde_json::from_slice(&std::fs::read(dir.join("bundle.json")).expect("bundle")).expect("parse")
}

fn rules() -> ChainRules {
    ChainRules {
        min_participants: 3,
        chunk_dim: 16,
        value_scale_log2: 8,
        threshold_pos: 32768,
        threshold_neg: -32768,
    }
}

fn run(
    bundle: &Bundle,
    deltas: &Path,
    start: &[u8],
    merged: &[u8],
    r: Option<ChainRules>,
) -> Report {
    replay(&Inputs {
        bundle,
        deltas,
        start_adapter: Some(start),
        merged_adapter: Some(merged),
        chain_rules: r,
    })
    .expect("replay runs")
}

/// A scratch copy of the fixture to tamper with.
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fl-replay-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("deltas")).expect("dir");
    for e in std::fs::read_dir(fixture().join("deltas")).expect("deltas") {
        let e = e.expect("entry");
        std::fs::copy(e.path(), d.join("deltas").join(e.file_name())).expect("copy");
    }
    d
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture().join(name)).expect(name)
}

#[test]
fn the_devnet_round_replays_clean() {
    let b = load_bundle(&fixture());
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        Some(rules()),
    );
    assert!(rep.ok(), "{:?}", rep.mismatches);
    assert!(rep.merged_adapter_checked);
    assert_eq!(rep.participants, 3);
    assert_eq!(rep.chunks, 72);
    assert_eq!(rep.record_digest, b.record_digest);
    assert_eq!(rep.output_root, b.output_root);
}

#[test]
fn a_lying_output_leaf_is_caught_by_the_kernel() {
    let mut b = load_bundle(&fixture());
    b.output_hashes[5] = format!("0x{}", "ab".repeat(32));
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        None,
    );
    assert!(rep
        .mismatches
        .iter()
        .any(|m| m.contains("chunk 5") && m.contains("0x0110")));
}

#[test]
fn an_edited_delta_artifact_is_caught() {
    let d = scratch("delta");
    let b = load_bundle(&fixture());
    let name = format!(
        "{}.fld",
        b.participants[1].delta_sha256.trim_start_matches("0x")
    );
    let p = d.join("deltas").join(&name);
    let mut bytes = std::fs::read(&p).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&p, bytes).expect("write");
    let rep = run(
        &b,
        &d.join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        None,
    );
    assert!(rep
        .mismatches
        .iter()
        .any(|m| m.contains("participant 1") && m.contains("does not hash")));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn reordered_participants_are_caught() {
    let mut b = load_bundle(&fixture());
    b.participants.swap(0, 1);
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        None,
    );
    assert!(rep.mismatches.iter().any(|m| m.contains("ascending")));
    assert!(rep
        .mismatches
        .iter()
        .any(|m| m.contains("participants root")));
}

#[test]
fn a_merged_adapter_that_is_not_start_plus_aggregate_is_caught() {
    let mut merged = read("merged.gguf");
    // Flip a low mantissa bit in the last tensor value.
    let n = merged.len();
    merged[n - 4] ^= 0x01;
    let b = load_bundle(&fixture());
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &merged,
        None,
    );
    assert!(rep.mismatches.iter().any(|m| m.contains("merged adapter")));
}

#[test]
fn a_config_that_disagrees_with_the_chain_is_caught() {
    let b = load_bundle(&fixture());
    let mut r = rules();
    r.chunk_dim = 32;
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        Some(r),
    );
    assert!(rep.mismatches.iter().any(|m| m.contains("rules")));
}

#[test]
fn a_forged_signature_is_caught() {
    let mut b = load_bundle(&fixture());
    let s = &mut b.participants[2].result.signature;
    // Change one byte of s; the signature then recovers to someone else (or nobody).
    let mut raw = hex::decode(s.trim_start_matches("0x")).expect("hex");
    raw[40] ^= 0x01;
    *s = format!("0x{}", hex::encode(raw));
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        None,
    );
    assert!(rep
        .mismatches
        .iter()
        .any(|m| m.contains("participant 2") && m.contains("signature")));
}

#[test]
fn too_few_participants_is_caught() {
    let mut b = load_bundle(&fixture());
    b.participants.pop();
    let rep = run(
        &b,
        &fixture().join("deltas"),
        &read("start.gguf"),
        &read("merged.gguf"),
        None,
    );
    assert!(rep
        .mismatches
        .iter()
        .any(|m| m.contains("below the minimum")));
}
