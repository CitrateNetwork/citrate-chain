// citrate/core/execution/tests/agent_precompile_vectors.rs
//
// HUP-S7.2 follow-up (US-7.5): the cross-repo test vectors for the agent
// precompile fork (0x0112 LORA_APPLY, 0x0113 LORA_MERGE, 0x0121
// MEMORY_ANCHOR_VERIFY, 0x0122 AGENT_OPS).
//
// Every vector is built with THIS crate's encoders (`tensor_format::encode`,
// `memory_anchor::encode_input`, `agent_ops::encode_device_link`,
// `agent_ops::encode_device_revocation`) and answered by THIS crate's
// precompile functions. The result is pinned in
// `tests/fixtures/agent_precompile_vectors.json`, which other repos copy:
//
//   * citrate-core `src-tauri/src/agent_precompiles.rs` encodes the same fields
//     and must produce the same input bytes, and decodes the pinned outputs;
//   * `scripts/devnet-precompile-check.sh` sends the same inputs to a devnet
//     node through `PrecompileCaller` and expects the pinned outputs.
//
// A change to any encoder or to a precompile's answer fails here first. To
// regenerate after an intended change (which is a consensus change, so a new
// fork): CITRATE_REGEN_AGENT_VECTORS=1 cargo test -p citrate-execution --test
// agent_precompile_vectors, then copy the file to the consumers.

use citrate_execution::precompiles::{agent_ops, lora, memory_anchor, q16::Q16, tensor_format};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/agent_precompile_vectors.json"
);

/// Plenty: every vector here is far below its schedule.
const GAS: u64 = 30_000_000;

fn q(v: f64) -> i64 {
    // Exact for the values used below (multiples of 1/4 and small integers).
    (v * 65_536.0) as i64
}

fn tensor(shape: &[u32], raw: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(raw.len() * 8);
    for v in raw {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    tensor_format::encode(shape, tensor_format::Dtype::Q16_16, &bytes).expect("tensor")
}

fn tjson(shape: &[u32], raw: &[i64]) -> Value {
    json!({"shape": shape, "q16": raw})
}

/// Decode a Q16 output tensor with the crate's own decoder.
fn out_json(bytes: &[u8]) -> Value {
    let view = tensor_format::decode_exact(bytes).expect("output tensor");
    assert_eq!(view.dtype, tensor_format::Dtype::Q16_16);
    let raw: Vec<i64> = view
        .data
        .chunks_exact(8)
        .map(|c| i64::from_le_bytes(c.try_into().expect("8 bytes")))
        .collect();
    json!({"shape": view.shape, "q16": raw})
}

struct T {
    shape: Vec<u32>,
    raw: Vec<i64>,
}

fn t(shape: &[u32], raw: &[i64]) -> T {
    T {
        shape: shape.to_vec(),
        raw: raw.to_vec(),
    }
}

fn lora_apply_vector(name: &str, w: T, b: T, a: T, alpha: i64) -> Value {
    let input = [
        tensor(&w.shape, &w.raw),
        tensor(&b.shape, &b.raw),
        tensor(&a.shape, &a.raw),
        tensor(&[], &[alpha]),
    ]
    .concat();
    let r = lora::apply(&input, GAS).expect("LORA_APPLY answers");
    json!({
        "name": name,
        "w": tjson(&w.shape, &w.raw),
        "b": tjson(&b.shape, &b.raw),
        "a": tjson(&a.shape, &a.raw),
        "alpha": alpha,
        "input": hex::encode(&input),
        "gas": r.gas_used,
        "output": hex::encode(&r.output),
        "out": out_json(&r.output),
    })
}

struct Adapter {
    b: T,
    a: T,
    alpha: i64,
    weight: i64,
}

fn lora_merge_vector(name: &str, adapters: Vec<Adapter>) -> Value {
    let mut input = vec![u8::try_from(adapters.len()).expect("count")];
    let mut js = Vec::new();
    for ad in &adapters {
        input.extend(tensor(&ad.b.shape, &ad.b.raw));
        input.extend(tensor(&ad.a.shape, &ad.a.raw));
        input.extend(tensor(&[], &[ad.alpha]));
        input.extend(tensor(&[], &[ad.weight]));
        js.push(json!({
            "b": tjson(&ad.b.shape, &ad.b.raw),
            "a": tjson(&ad.a.shape, &ad.a.raw),
            "alpha": ad.alpha,
            "weight": ad.weight,
        }));
    }
    let r = lora::merge(&input, GAS).expect("LORA_MERGE answers");
    json!({
        "name": name,
        "adapters": js,
        "input": hex::encode(&input),
        "gas": r.gas_used,
        "output": hex::encode(&r.output),
        "out": out_json(&r.output),
    })
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Sha256;
    let mut h = Sha256::new();
    for p in parts {
        sha2::Digest::update(&mut h, p);
    }
    sha2::Digest::finalize(h).into()
}

fn hx(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    v.as_slice().try_into().expect("32")
}

#[allow(clippy::too_many_arguments)]
fn anchor_vector(
    name: &str,
    v: u32,
    day: u64,
    first_seq: u64,
    last_seq: u64,
    count: u64,
    root: [u8; 32],
    seq: u64,
    leaf_index: u64,
    record: [u8; 32],
    path: &[[u8; 32]],
) -> Value {
    let input = memory_anchor::encode_input(
        v, day, first_seq, last_seq, count, &root, seq, leaf_index, &record, path,
    )
    .expect("encode");
    let r = memory_anchor::execute(&input, GAS).expect("MEMORY_ANCHOR_VERIFY answers");
    let valid = r.output != [0u8; 32];
    json!({
        "name": name,
        "v": v,
        "day": day,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "count": count,
        "tree_root": hex::encode(root),
        "seq": seq,
        "leaf_index": leaf_index,
        "record_hash": hex::encode(record),
        "path": path.iter().map(hex::encode).collect::<Vec<_>>(),
        "commitment": hex::encode(memory_anchor::day_commitment(v, day, first_seq, last_seq, count, &root)),
        "input": hex::encode(&input),
        "gas": r.gas_used,
        "output": hex::encode(&r.output),
        "valid": valid,
    })
}

/// Throwaway secp256k1 signers built at run time from a small integer.
fn signer(n: u8) -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar[0] = 0x33;
    SigningKey::from_bytes((&scalar).into()).expect("scalar")
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
    let (sig, recid) = k.sign_prehash_recoverable(&digest).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

fn word_flag(out: &[u8]) -> bool {
    assert_eq!(out.len(), 32, "AGENT_OPS answers one word");
    assert!(out[..31].iter().all(|b| *b == 0));
    assert!(out[31] <= 1);
    out[31] == 1
}

#[allow(clippy::too_many_arguments)]
fn device_link_vector(
    name: &str,
    signers: (u8, u8, u8),
    index: u32,
    signed_label: &str,
    sent_label: &str,
    issued_at: u64,
) -> Value {
    let (mk, dk, wk) = (signer(signers.0), signer(signers.1), signer(signers.2));
    let (m, d, w) = (address(&mk), address(&dk), address(&wk));
    let msg = agent_ops::device_link_message(&m, &d, &w, index, signed_label, issued_at);
    let (ms, ds, ws) = (sign(&mk, &msg), sign(&dk, &msg), sign(&wk, &msg));
    let input = agent_ops::encode_device_link(
        &m,
        &d,
        &w,
        index,
        sent_label.as_bytes(),
        issued_at,
        &ms,
        &ds,
        &ws,
    )
    .expect("encode");
    let r = agent_ops::execute(&input, GAS).expect("AGENT_OPS answers");
    json!({
        "name": name,
        "member": hex::encode(m),
        "device": hex::encode(d),
        "wallet": hex::encode(w),
        "index": index,
        "label": sent_label,
        "issued_at": issued_at,
        "message": agent_ops::device_link_message(&m, &d, &w, index, sent_label, issued_at),
        "member_sig": hex::encode(ms),
        "device_sig": hex::encode(ds),
        "wallet_sig": hex::encode(ws),
        "input": hex::encode(&input),
        "gas": r.gas_used,
        "output": hex::encode(&r.output),
        "valid": word_flag(&r.output),
    })
}

fn device_revocation_vector(name: &str, signer_n: u8, revoked_at: u64, signed_at: u64) -> Value {
    let mk = signer(signer_n);
    let m = address(&mk);
    let d = address(&signer(signer_n + 1));
    let ms = sign(
        &mk,
        &agent_ops::device_revocation_message(&m, &d, signed_at),
    );
    let input = agent_ops::encode_device_revocation(&m, &d, revoked_at, &ms);
    let r = agent_ops::execute(&input, GAS).expect("AGENT_OPS answers");
    json!({
        "name": name,
        "member": hex::encode(m),
        "device": hex::encode(d),
        "revoked_at": revoked_at,
        "message": agent_ops::device_revocation_message(&m, &d, revoked_at),
        "member_sig": hex::encode(ms),
        "input": hex::encode(&input),
        "gas": r.gas_used,
        "output": hex::encode(&r.output),
        "valid": word_flag(&r.output),
    })
}

fn vectors() -> Value {
    let one = Q16::ONE.0;
    let lora_apply = vec![
        lora_apply_vector(
            "integers 2x2 rank 1",
            t(&[2, 2], &[one, one, one, one]),
            t(&[2, 1], &[one, 2 * one]),
            t(&[1, 2], &[3 * one, 4 * one]),
            2 * one,
        ),
        lora_apply_vector(
            "fractions and negatives 2x3 rank 2",
            t(&[2, 3], &[q(0.5), q(-1.25), 0, q(3.0), q(0.25), q(-0.75)]),
            t(&[2, 2], &[q(1.5), q(-0.5), q(0.25), q(2.0)]),
            t(
                &[2, 3],
                &[q(-1.0), q(0.5), q(0.75), q(2.0), q(-0.25), q(1.0)],
            ),
            q(4.0),
        ),
        lora_apply_vector(
            "saturating 1x1 rank 1",
            t(&[1, 1], &[i64::MAX - 7]),
            t(&[1, 1], &[i64::MAX / 2]),
            t(&[1, 1], &[q(16.0)]),
            q(8.0),
        ),
    ];
    let lora_merge = vec![
        lora_merge_vector(
            "two adapters, mixed ranks 1x2",
            vec![
                Adapter {
                    b: t(&[1, 1], &[2 * one]),
                    a: t(&[1, 2], &[3 * one, one]),
                    alpha: one,
                    weight: one,
                },
                Adapter {
                    b: t(&[1, 2], &[one, one]),
                    a: t(&[2, 2], &[one, 0, 0, one]),
                    alpha: 4 * one,
                    weight: q(0.5),
                },
            ],
        ),
        lora_merge_vector(
            "one adapter, weight 1, equals LORA_APPLY on a zero base",
            vec![Adapter {
                b: t(&[2, 1], &[one, 2 * one]),
                a: t(&[1, 2], &[3 * one, 4 * one]),
                alpha: 2 * one,
                weight: one,
            }],
        ),
    ];

    // The shared 5-record day (precompiles::memory_anchor tests, runtime crate
    // `citrate-agent-anchor`): day 20362, seq 40..=44, record i = SHA-256("rec-i").
    let root = hx("e31cc748d04dce3c6ecfcb00dff52dd853d551e0f57bf3f2e516c2f65882a8e4");
    let path = [
        hx("dd6b83ae1d8223d23ed4869464289c9952b6caf38b53cc4da7c87cc1f2462717"),
        hx("196bea1e49292cc96d0437940e2437d904130a222cb6812e6bfa53aae78871da"),
        hx("2fa07631df4d01d859eb3e78061cfb4b17ed553b410ce58c7d2b76a04d0c87cf"),
    ];
    let rec3 = sha(&[b"rec-3"]);
    let memory_anchor = vec![
        anchor_vector(
            "shared day, record 3",
            1,
            20_362,
            40,
            44,
            5,
            root,
            43,
            3,
            rec3,
            &path,
        ),
        anchor_vector(
            "wrong record hash",
            1,
            20_362,
            40,
            44,
            5,
            root,
            43,
            3,
            sha(&[b"rec-9"]),
            &path,
        ),
        anchor_vector(
            "sequence does not match the leaf",
            1,
            20_362,
            40,
            44,
            5,
            root,
            44,
            3,
            rec3,
            &path,
        ),
        anchor_vector(
            "single-record day",
            1,
            20_400,
            7,
            7,
            1,
            {
                // RFC 6962: a one-leaf tree's root is the leaf hash.
                let r = sha(&[b"only"]);
                sha(&[&[0u8], &r])
            },
            7,
            0,
            sha(&[b"only"]),
            &[],
        ),
    ];

    let device_link = vec![
        device_link_vector(
            "valid link",
            (1, 2, 3),
            2,
            "Linux box",
            "Linux box",
            1_790_000_000,
        ),
        device_link_vector(
            "label changed after signing",
            (1, 2, 3),
            2,
            "Linux box",
            "Linux Box",
            1_790_000_000,
        ),
        device_link_vector(
            "valid link, top index",
            (4, 5, 6),
            1023,
            "Mac's laptop-2.0",
            "Mac's laptop-2.0",
            1_800_000_000,
        ),
    ];
    let device_revocation = vec![
        device_revocation_vector("valid revocation", 7, 1_795_000_000, 1_795_000_000),
        device_revocation_vector(
            "time changed after signing",
            7,
            1_795_000_001,
            1_795_000_000,
        ),
    ];

    json!({
        "version": 1,
        "generator": "citrate-chain core/execution/tests/agent_precompile_vectors.rs",
        "spec": "citrate-chain docs/precompiles/AGENT_PRECOMPILES.md",
        "addresses": {
            "LORA_APPLY": "0x0000000000000000000000000000000000000112",
            "LORA_MERGE": "0x0000000000000000000000000000000000000113",
            "MEMORY_ANCHOR_VERIFY": "0x0000000000000000000000000000000000000121",
            "AGENT_OPS": "0x0000000000000000000000000000000000000122",
        },
        "lora_apply": lora_apply,
        "lora_merge": lora_merge,
        "memory_anchor": memory_anchor,
        "device_link": device_link,
        "device_revocation": device_revocation,
    })
}

#[test]
fn pinned_vectors_match_the_encoders_and_the_precompiles() {
    let now = vectors();
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&now).expect("serialize")
    );
    if std::env::var_os("CITRATE_REGEN_AGENT_VECTORS").is_some() {
        std::fs::write(FIXTURE, &text).expect("write fixture");
    }
    let pinned = std::fs::read_to_string(FIXTURE).expect("read fixture");
    let pinned: Value = serde_json::from_str(&pinned).expect("fixture is JSON");
    assert_eq!(
        pinned, now,
        "the pinned agent precompile vectors no longer match the encoders or the precompiles"
    );
}

#[test]
fn vectors_cover_both_answers_of_every_verifier() {
    let v = vectors();
    for (kind, want) in [
        ("memory_anchor", [true, false]),
        ("device_link", [true, false]),
        ("device_revocation", [true, false]),
    ] {
        for flag in want {
            assert!(
                v[kind]
                    .as_array()
                    .expect("array")
                    .iter()
                    .any(|x| x["valid"] == flag),
                "{kind} has no vector with valid = {flag}"
            );
        }
    }
    // An invalid anchor proof answers zero; a valid one answers its commitment.
    for x in v["memory_anchor"].as_array().expect("array") {
        if x["valid"] == true {
            assert_eq!(x["output"], x["commitment"]);
        } else {
            assert_eq!(x["output"], json!("0".repeat(64)));
        }
    }
    // The single-adapter merge equals LORA_APPLY of the same adapter onto a zero base
    // (the first apply vector differs only in its base W of ones).
    let merged = &v["lora_merge"][1]["out"]["q16"];
    let applied = &v["lora_apply"][0]["out"]["q16"];
    let one = Q16::ONE.0;
    for (m, a) in merged
        .as_array()
        .expect("array")
        .iter()
        .zip(applied.as_array().expect("array"))
    {
        assert_eq!(m.as_i64().expect("i64") + one, a.as_i64().expect("i64"));
    }
}

#[test]
fn shared_day_vector_is_the_published_commitment() {
    let v = vectors();
    assert_eq!(
        v["memory_anchor"][0]["output"],
        json!("26f10b854266080ba2d272d4042ef80c9a9eb85a90de744e71b4b10c7f9998e8")
    );
}
