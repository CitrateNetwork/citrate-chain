// citrate/core/execution/benches/agent_precompiles_bench.rs
//
// HUP-S7.2: wall-clock cost of the agent precompile fork's worst-case inputs,
// next to the precompile whose gas price is the Ethereum reference (one
// secp256k1 recovery = 3000 gas, here AGENT_OPS DEVICE_REVOCATION_VERIFY).
//
// Purpose: evidence for the owner's sign-off of the placeholder gas schedule in
// `docs/precompiles/AGENT_PRECOMPILES.md`. A schedule is safe when no input
// buys more wall-clock time per unit of gas than the reference does, so every
// case prints its gas next to its time; compare the "ns per gas" figures.
//
//   cargo bench -p citrate-execution --bench agent_precompiles_bench
//
// The inputs are deterministic; no keys or literals that resemble credentials
// (test keys are built from a small integer at run time).

use citrate_execution::precompiles::{agent_ops, lora, memory_anchor, q16::Q16, tensor_format};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// A Q16.16 tensor whose elements are large enough to exercise the saturating
/// paths (every multiply-add runs at full i128 width).
fn q16_tensor(shape: &[u32], seed: i64) -> Vec<u8> {
    let n: usize = shape.iter().map(|d| *d as usize).product::<usize>().max(1);
    let mut bytes = Vec::with_capacity(n * 8);
    for i in 0..n {
        let v = Q16((seed.wrapping_mul(i as i64 + 7) % 50_000_000) - 25_000_000);
        bytes.extend_from_slice(&v.0.to_le_bytes());
    }
    tensor_format::encode(shape, tensor_format::Dtype::Q16_16, &bytes).unwrap_or_default()
}

fn scalar(v: i32) -> Vec<u8> {
    let bytes = Q16::from_int(v).0.to_le_bytes();
    tensor_format::encode(&[], tensor_format::Dtype::Q16_16, &bytes).unwrap_or_default()
}

/// LORA_APPLY at the caps: d = k = 256, r = 64.
fn apply_worst() -> Vec<u8> {
    [
        q16_tensor(&[256, 256], 3),
        q16_tensor(&[256, 64], 5),
        q16_tensor(&[64, 256], 11),
        scalar(16),
    ]
    .concat()
}

/// LORA_MERGE with `n` adapters at the caps.
fn merge_input(n: u8) -> Vec<u8> {
    let mut out = vec![n];
    for i in 0..n {
        let s = i64::from(i) + 13;
        out.extend(q16_tensor(&[256, 64], s));
        out.extend(q16_tensor(&[64, 256], s + 1));
        out.extend(scalar(16));
        out.extend(scalar(1));
    }
    out
}

/// MEMORY_ANCHOR_VERIFY with the longest path (64 siblings). The proof does
/// not verify, but the walk runs every step before the comparison.
fn anchor_worst() -> Vec<u8> {
    let path: Vec<[u8; 32]> = (0..64u8).map(|i| [i; 32]).collect();
    memory_anchor::encode_input(
        1,
        20_362,
        0,
        u64::MAX - 1,
        u64::MAX,
        &[7u8; 32],
        u64::MAX - 2,
        u64::MAX - 2,
        &[9u8; 32],
        &path,
    )
    .unwrap_or_default()
}

fn key(n: u8) -> Option<SigningKey> {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar[0] = 0x33;
    SigningKey::from_bytes((&scalar).into()).ok()
}

fn address(k: &SigningKey) -> [u8; 20] {
    let point = k.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn sign(k: &SigningKey, message: &str) -> [u8; 65] {
    let digest = agent_ops::eip191_digest(message.as_bytes());
    let mut out = [0u8; 65];
    if let Ok((sig, recid)) = k.sign_prehash_recoverable(&digest) {
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
    }
    out
}

/// A valid three-signature DeviceLink with a 48-byte label (all three
/// recoveries run).
fn device_link_worst() -> Vec<u8> {
    let (Some(mk), Some(dk), Some(wk)) = (key(1), key(2), key(3)) else {
        return Vec::new();
    };
    let (m, d, w) = (address(&mk), address(&dk), address(&wk));
    let label = "x".repeat(agent_ops::MAX_LABEL_LEN);
    let msg = agent_ops::device_link_message(&m, &d, &w, 1023, &label, u64::MAX);
    agent_ops::encode_device_link(
        &m,
        &d,
        &w,
        1023,
        label.as_bytes(),
        u64::MAX,
        &sign(&mk, &msg),
        &sign(&dk, &msg),
        &sign(&wk, &msg),
    )
    .unwrap_or_default()
}

/// The reference: one secp256k1 recovery, priced like `ecrecover`.
fn revocation() -> Vec<u8> {
    let Some(mk) = key(1) else {
        return Vec::new();
    };
    let m = address(&mk);
    let d = [0x44u8; 20];
    let msg = agent_ops::device_revocation_message(&m, &d, 1_790_000_000);
    agent_ops::encode_device_revocation(&m, &d, 1_790_000_000, &sign(&mk, &msg))
}

/// The chain's own `ecrecover` (0x01) as REVM runs it in this build: the
/// Ethereum-priced reference (3000 gas per recovery).
fn ecrecover_input() -> Vec<u8> {
    let Some(mk) = key(1) else {
        return Vec::new();
    };
    let digest = agent_ops::eip191_digest(b"reference");
    let mut out = digest.to_vec();
    let mut v = [0u8; 32];
    if let Ok((sig, recid)) = mk.sign_prehash_recoverable(&digest) {
        v[31] = 27 + recid.to_byte();
        out.extend_from_slice(&v);
        out.extend_from_slice(&sig.to_bytes());
    }
    out
}

fn revm_ecrecover(
    input: &[u8],
    gas_limit: u64,
) -> anyhow::Result<citrate_execution::PrecompileResult> {
    let bytes = revm::primitives::Bytes::copy_from_slice(input);
    match revm::precompile::secp256k1::ec_recover_run(&bytes, gas_limit) {
        Ok(out) => Ok(citrate_execution::PrecompileResult {
            success: out.bytes.len() == 32,
            gas_used: out.gas_used,
            output: out.bytes.to_vec(),
        }),
        Err(e) => Err(anyhow::anyhow!("ecrecover: {e:?}")),
    }
}

type Precompile = fn(&[u8], u64) -> anyhow::Result<citrate_execution::PrecompileResult>;

fn agent_precompiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("agent_precompiles");
    group.sample_size(10);
    let cases: Vec<(&str, Precompile, Vec<u8>)> = vec![
        ("ref_revm_ecrecover_0x01", revm_ecrecover, ecrecover_input()),
        ("ref_revocation_1_recover", agent_ops::execute, revocation()),
        (
            "device_link_3_recovers",
            agent_ops::execute,
            device_link_worst(),
        ),
        (
            "memory_anchor_path_64",
            memory_anchor::execute,
            anchor_worst(),
        ),
        ("lora_apply_256x64x256", lora::apply, apply_worst()),
        ("lora_merge_1_adapter", lora::merge, merge_input(1)),
        ("lora_merge_16_adapters", lora::merge, merge_input(16)),
    ];
    for (name, f, input) in cases {
        let gas = match f(&input, u64::MAX) {
            Ok(r) if r.success => r.gas_used,
            Ok(_) | Err(_) => {
                eprintln!("{name}: input rejected, case skipped");
                continue;
            }
        };
        eprintln!("{name}: {} input bytes, {gas} gas", input.len());
        group.bench_function(format!("{name} [{gas} gas]"), |b| {
            b.iter(|| f(black_box(&input), black_box(u64::MAX)))
        });
    }
    group.finish();
}

criterion_group!(benches, agent_precompiles);
criterion_main!(benches);
