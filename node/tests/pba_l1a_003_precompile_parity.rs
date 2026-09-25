// PBA-L1a-003 tripwire: the node binary's precompile results must be identical
// on every build path. Feature-dependent precompiles (0x0130 needs
// `commd-fold-verify`, 0x0108 needs `halo2-substrate`) used to return an error
// on one build and a verified result on another, so one unprivileged
// transaction split validators built by release.yml (feature off) from those
// built by the reroll runbook (feature on).
//
// This test runs in the node crate, i.e. under citrate-node's DEFAULT feature
// set (the only set any shipped build uses; see
// scripts/ci/check_pba_exec_tripwires.sh). It folds every bridged pure
// precompile's result over a fixed corpus into one digest and pins it. A build
// with a different consensus feature set flips the feature-absent class of
// 0x0130 / 0x0108 and fails here: the "CI diff of precompile outputs".

use citrate_execution::precompiles::{execute_pure_at, PURE_PRECOMPILE_ADDRESSES};
use citrate_execution::types::Address;
use sha3::{Digest, Sha3_256};

/// Pinned digest for the canonical (default-feature) node build.
const PINNED: &str = "bdacb6ff8757e42fde5ed4c402f507acf7010ef33e453dae4fbb9a9a74c7eb65";

fn corpus() -> Vec<Vec<u8>> {
    // A well-formed 0x0130 head with empty tails (decodes; the verifier then
    // rejects) — distinguishes "feature absent" from "verifier ran".
    let mut fold = vec![0u8; 4];
    for v in [128usize, 1, 0, 160] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(v as u64).to_be_bytes());
        fold.extend_from_slice(&w);
    }
    fold.extend_from_slice(&[0u8; 64]);
    vec![vec![], vec![0xde, 0xad], vec![0x01; 200], fold]
}

/// Error class that is part of the consensus surface across builds: which
/// feature gate (if any) refused the call.
fn error_class(msg: &str) -> u8 {
    if msg.contains("requires the `commd-fold-verify` feature") {
        1
    } else if msg.contains("requires halo2-substrate") || msg.contains("SubstrateAbsent") {
        2
    } else {
        0
    }
}

fn precompile_digest() -> String {
    let mut h = Sha3_256::new();
    for raw in PURE_PRECOMPILE_ADDRESSES {
        for input in corpus() {
            for hardened in [false, true] {
                h.update(raw);
                h.update([hardened as u8]);
                match execute_pure_at(&Address(raw), &input, 30_000_000, hardened) {
                    Ok(r) => {
                        h.update([1u8, r.success as u8]);
                        h.update(r.gas_used.to_le_bytes());
                        h.update(&r.output);
                    }
                    Err(e) => h.update([0u8, error_class(&e.to_string())]),
                }
            }
        }
    }
    hex::encode(h.finalize())
}

#[test]
fn pba_l1a_003_precompile_outputs_match_the_canonical_build() {
    let d = precompile_digest();
    println!("PBA-L1a-003 precompile digest: {d}");
    assert_eq!(
        d, PINNED,
        "precompile results differ from the canonical citrate-node build — a mixed \
         consensus feature set forks the chain (PBA-L1a-003)"
    );
}

#[test]
fn pba_l1a_003_fold_verifier_is_live_in_the_node_build() {
    let fold = corpus().pop().expect("fold input");
    let mut addr = [0u8; 20];
    addr[18] = 0x01;
    addr[19] = 0x30;
    let err = execute_pure_at(&Address(addr), &fold, 30_000_000, false)
        .expect_err("empty proof is rejected");
    assert_eq!(
        error_class(&err.to_string()),
        0,
        "0x0130 must reach the verifier in the node build, not the feature-absent stub: {err}"
    );
}
