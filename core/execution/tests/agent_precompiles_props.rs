// citrate/core/execution/tests/agent_precompiles_props.rs
//
// HUP-S7.2 (federation F-2 / F-3): property tests (proptest fuzzing) for the
// agent precompile fork's pure functions.
//
//   * Totality: arbitrary input bytes and gas never panic any of the four
//     precompiles; they answer Ok or Err.
//   * LoRA: MERGE of one adapter with weight 1 equals APPLY onto a zero base;
//     output shape and gas follow the schedule.
//   * Memory anchor: for random day batches, every record's RFC 6962 proof
//     (built by an independent reference in this file) returns the day
//     commitment, and any single-byte change makes it fail, except a change to
//     the day, which yields that other day's commitment (never the anchored one).
//   * Agent ops: a correctly signed DeviceLink verifies iff its label obeys the
//     cluster label rule.

use citrate_execution::precompiles::{agent_ops, lora, memory_anchor, q16::Q16, tensor_format};
use k256::ecdsa::SigningKey;
use proptest::prelude::*;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

fn q16_tensor(shape: &[u32], vals: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for v in vals {
        bytes.extend_from_slice(&Q16(*v).0.to_le_bytes());
    }
    tensor_format::encode(shape, tensor_format::Dtype::Q16_16, &bytes).expect("tensor")
}

// ---- independent RFC 6962 reference ----

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return sha(&[&[0u8], &leaves[0]]);
    }
    let mut k = 1;
    while k * 2 < leaves.len() {
        k *= 2;
    }
    sha(&[&[1u8], &mth(&leaves[..k]), &mth(&leaves[k..])])
}

fn path(leaves: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
    if leaves.len() < 2 {
        return Vec::new();
    }
    let mut k = 1;
    while k * 2 < leaves.len() {
        k *= 2;
    }
    if i < k {
        let mut p = path(&leaves[..k], i);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(&leaves[k..], i - k);
        p.push(mth(&leaves[..k]));
        p
    }
}

// ---- keys for DeviceLink signatures (built at run time) ----

fn key(n: u8) -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar[0] = 0x44;
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

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn precompiles_are_total_on_arbitrary_input(input in proptest::collection::vec(any::<u8>(), 0..600), gas in 0u64..2_000_000) {
        let _ = lora::apply(&input, gas);
        let _ = lora::merge(&input, gas);
        let _ = memory_anchor::execute(&input, gas);
        let _ = agent_ops::execute(&input, gas);
        // Structured-looking prefixes reach deeper code paths.
        let mut op1 = vec![agent_ops::OP_DEVICE_LINK_VERIFY];
        op1.extend_from_slice(&input);
        let _ = agent_ops::execute(&op1, gas);
        let mut n = vec![(input.len() % 18) as u8];
        n.extend_from_slice(&input);
        let _ = lora::merge(&n, gas);
    }

    #[test]
    fn merge_of_one_unit_weight_adapter_equals_apply_on_zero_base(
        d in 1u32..6, r in 1u32..5, k in 1u32..6,
        seed in proptest::collection::vec(-(1i64 << 22)..(1i64 << 22), 64),
        alpha in -(8i64 << 16)..(8i64 << 16),
    ) {
        let bvals: Vec<i64> = (0..(d * r) as usize).map(|i| seed[i % seed.len()]).collect();
        let avals: Vec<i64> = (0..(r * k) as usize).map(|i| seed[(i * 7 + 3) % seed.len()]).collect();
        let b = q16_tensor(&[d, r], &bvals);
        let a = q16_tensor(&[r, k], &avals);
        let al = q16_tensor(&[], &[alpha]);
        let zero = q16_tensor(&[d, k], &vec![0; (d * k) as usize]);
        let one = q16_tensor(&[], &[1 << 16]);
        let applied = lora::apply(&[zero, b.clone(), a.clone(), al.clone()].concat(), u64::MAX).expect("apply");
        let merged = lora::merge(&[vec![1u8], b, a, al, one].concat(), u64::MAX).expect("merge");
        prop_assert_eq!(&applied.output, &merged.output);
        let (d64, r64, k64) = (u64::from(d), u64::from(r), u64::from(k));
        prop_assert_eq!(applied.gas_used, 3_000 + 4 * d64 * r64 * k64 + 3 * d64 * k64);
        prop_assert_eq!(merged.gas_used, 3_000 + 4 * d64 * r64 * k64 + 4 * d64 * k64);
        let (view, used) = tensor_format::decode_one(&applied.output).expect("decodes");
        prop_assert_eq!(used, applied.output.len());
        prop_assert_eq!(view.shape, vec![d, k]);
    }

    #[test]
    fn every_record_of_a_random_day_proves_and_any_byte_flip_breaks_it(
        count in 1usize..40,
        first_seq in 0u64..1_000_000,
        day in 0u64..40_000,
        pick in any::<prop::sample::Index>(),
        flip in any::<prop::sample::Index>(),
    ) {
        let leaves: Vec<[u8; 32]> = (0..count).map(|i| sha(&[&(i as u64).to_be_bytes(), b"leaf"])).collect();
        let root = mth(&leaves);
        let last = first_seq + count as u64 - 1;
        let commitment = memory_anchor::day_commitment(1, day, first_seq, last, count as u64, &root);
        let i = pick.index(count);
        let p = path(&leaves, i);
        let input = memory_anchor::encode_input(1, day, first_seq, last, count as u64, &root,
            first_seq + i as u64, i as u64, &leaves[i], &p).expect("encode");
        let out = memory_anchor::execute(&input, u64::MAX).expect("answers");
        prop_assert_eq!(out.output, commitment.to_vec());
        // Flip one byte anywhere except the path-length byte (which changes the
        // input's shape and is an error instead).
        let mut bad = input.clone();
        let mut at = flip.index(bad.len());
        if at == memory_anchor::FIXED_LEN - 1 {
            at = 0;
        }
        bad[at] ^= 0x01;
        let res = memory_anchor::execute(&bad, u64::MAX).expect("answers");
        if (4..12).contains(&at) {
            // The day is not part of the tree, only of the commitment: the proof
            // still verifies, but for a DIFFERENT day's commitment, which is not
            // the anchored value.
            let bad_day = u64::from_be_bytes(bad[4..12].try_into().expect("8 bytes"));
            let other = memory_anchor::day_commitment(1, bad_day, first_seq, last, count as u64, &root);
            prop_assert_eq!(&res.output, &other.to_vec());
            prop_assert_ne!(res.output, commitment.to_vec());
        } else {
            prop_assert_eq!(res.output, vec![0u8; 32]);
        }
    }

    #[test]
    fn signed_link_verifies_iff_label_is_valid(label in "[ -~]{0,52}") {
        let (mk, dk, wk) = (key(1), key(2), key(3));
        let (m, d, w) = (address(&mk), address(&dk), address(&wk));
        let msg = agent_ops::device_link_message(&m, &d, &w, 1, &label, 1_790_000_000);
        let input = agent_ops::encode_device_link(&m, &d, &w, 1, label.as_bytes(), 1_790_000_000,
            &sign(&mk, &msg), &sign(&dk, &msg), &sign(&wk, &msg)).expect("encode");
        let out = agent_ops::execute(&input, u64::MAX).expect("answers").output;
        let expect = agent_ops::label_is_valid(label.as_bytes());
        prop_assert_eq!(out[31] == 1, expect);
    }
}
