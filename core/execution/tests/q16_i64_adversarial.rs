//! I64-S1 Phase D (WP-D3 adversarial + WP-D4 cross-build) — the widened Q16
//! precompile wire formats under attack.
//!
//! The Q16 `i32 → i64` widening doubled every on-wire element from 4 to 8 bytes
//! and bumped both headers (belnap `HEADER_LEN` 16→24; routing `ARCH_VERSION`
//! 1→2). A wire-format deserializer is the classic consensus attack surface: a
//! single out-of-bounds read or arithmetic wrap in a precompile decoder is a
//! chain-halting panic that every validator hits identically. Per the program's
//! blast-radius rule, the widened deserializers get a full adversarial pass.
//!
//! This suite targets the surface the widening specifically created — it is NOT
//! a re-run of the in-module reject tests. The load-bearing new invariant is:
//!   **a buffer sized for the OLD i32 wire format must FAIL-CLOSED under the i64
//!   decoder** — rejected cleanly, never mis-read as a smaller-but-valid input.
//!
//! WP-D4 cross-build: this file is designed to be run under BOTH `cargo test`
//! (debug, overflow-checks on) AND `cargo test --release` (the chain's release
//! profile also sets overflow-checks = true). The saturation assertions below
//! would PANIC on any wrapping arithmetic, so green-in-both-profiles is the
//! profile-determinism proof — the i64 Q16 contract is pure integer math with
//! explicit saturation, identical across profiles.

use citrate_execution::precompiles::q16::{belnap, routing, Q16};
use proptest::prelude::*;

/// Generous gas so the decode/forward path under test is never short-circuited
/// by a gas check before we reach the parser.
const GAS: u64 = u64::MAX;

fn push_i64(buf: &mut Vec<u8>, raw: i64) {
    buf.extend_from_slice(&raw.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Canonical-valid buffers, built from the PUBLIC wire format only.
// ---------------------------------------------------------------------------

/// A belnap (0x0110) buffer the decoder accepts. Layout (all big-endian):
///   dim:u32 | n:u32 | emb[n*dim i64] | conf[n*dim i64] | w[n i64] | thr_pos:i64 | thr_neg:i64
/// Total = 24 + 16*n*dim + 8*n.
fn belnap_valid(dim: usize, n: usize, fill: i64) -> Vec<u8> {
    let mut b = Vec::with_capacity(24 + 16 * n * dim + 8 * n);
    b.extend_from_slice(&(dim as u32).to_be_bytes());
    b.extend_from_slice(&(n as u32).to_be_bytes());
    for _ in 0..(n * dim) {
        push_i64(&mut b, fill); // embeddings
    }
    for _ in 0..(n * dim) {
        push_i64(&mut b, fill); // confidences
    }
    for _ in 0..n {
        push_i64(&mut b, Q16::from_int(1).0); // weights = 1.0
    }
    push_i64(&mut b, 0); // threshold_pos
    push_i64(&mut b, 0); // threshold_neg
    b
}

/// A routing (0x0111) buffer the decoder accepts: ARCH_VERSION 2, the locked V1
/// shape (768/128/3), body of `body_q16_count` i64s. Zero weights are a fine
/// canonical input (forward must still run without panic).
fn routing_valid() -> Vec<u8> {
    let i = routing::ARCH_V1_INPUT_DIM as usize;
    let h = routing::ARCH_V1_HIDDEN_DIM as usize;
    let o = routing::ARCH_V1_OUTPUT_DIM as usize;
    let count = i + h * i + h + h * h + h + o * h + o;
    let mut b = Vec::with_capacity(16 + count * 8);
    b.extend_from_slice(&routing::ARCH_VERSION.to_be_bytes()); // 2
    b.extend_from_slice(&(i as u32).to_be_bytes());
    b.extend_from_slice(&(h as u32).to_be_bytes());
    b.extend_from_slice(&(o as u32).to_be_bytes());
    for _ in 0..count {
        push_i64(&mut b, 0);
    }
    b
}

// ---------------------------------------------------------------------------
// Sanity anchors — the valid buffers actually execute.
// ---------------------------------------------------------------------------

#[test]
fn belnap_valid_input_executes() {
    let r = belnap::execute(&belnap_valid(4, 3, Q16::from_int(1).0), GAS)
        .expect("valid belnap input should decode + execute");
    assert!(r.success, "valid belnap execution should report success");
    assert!(!r.output.is_empty(), "valid belnap execution should produce output");
}

#[test]
fn routing_valid_input_executes() {
    let r = routing::execute(&routing_valid(), GAS)
        .expect("valid routing input should decode + execute");
    assert!(r.success, "valid routing execution should report success");
    assert!(!r.output.is_empty(), "valid routing execution should produce output");
}

// ---------------------------------------------------------------------------
// WP-D3 — the load-bearing widening regression: OLD i32-width buffers must
// fail-closed under the i64 decoder, never be mis-read as a smaller valid input.
// ---------------------------------------------------------------------------

#[test]
fn belnap_rejects_old_i32_width_buffer() {
    // The OLD (i32) format for the same (dim, n): 16-byte header (dim+n + two
    // i32 thresholds) + 4-byte elements → 16 + 8*n*dim + 4*n bytes. The new
    // decoder reads the same dim,n from the first 8 bytes, computes the i64
    // expected_total (24 + 16*n*dim + 8*n), finds the buffer too short, and
    // must reject — NOT read past the end or accept a truncated body.
    let (dim, n) = (4usize, 3usize);
    let old_total = 16 + 8 * n * dim + 4 * n;
    let mut old = vec![0u8; old_total];
    old[0..4].copy_from_slice(&(dim as u32).to_be_bytes());
    old[4..8].copy_from_slice(&(n as u32).to_be_bytes());

    assert!(belnap::decode(&old).is_err(), "old i32-width belnap buffer must be rejected by decode");
    let r = belnap::execute(&old, GAS);
    assert!(
        r.is_err() || !r.expect("checked").success,
        "old i32-width belnap buffer must fail-closed through execute",
    );
}

#[test]
fn routing_rejects_old_arch_version_1() {
    // ARCH_VERSION 1 was the pre-widening registered version. Post-hardfork only
    // version 2 is registered; a v1 header must be rejected (ArchVersionUnregistered),
    // not interpreted under the new shape/width.
    let mut buf = routing_valid();
    buf[0..4].copy_from_slice(&1u32.to_be_bytes()); // arch_version = 1 (old)
    let r = routing::execute(&buf, GAS);
    assert!(
        r.is_err() || !r.expect("checked").success,
        "old ARCH_VERSION 1 routing buffer must fail-closed",
    );
}

#[test]
fn routing_rejects_old_i32_width_body() {
    // ARCH_VERSION 2 header but a body sized for 4-byte (i32) elements: half the
    // bytes the i64 decoder expects → LengthMismatch, fail-closed.
    let i = routing::ARCH_V1_INPUT_DIM as usize;
    let h = routing::ARCH_V1_HIDDEN_DIM as usize;
    let o = routing::ARCH_V1_OUTPUT_DIM as usize;
    let count = i + h * i + h + h * h + h + o * h + o;
    let mut buf = Vec::with_capacity(16 + count * 4);
    buf.extend_from_slice(&routing::ARCH_VERSION.to_be_bytes());
    buf.extend_from_slice(&(i as u32).to_be_bytes());
    buf.extend_from_slice(&(h as u32).to_be_bytes());
    buf.extend_from_slice(&(o as u32).to_be_bytes());
    buf.resize(16 + count * 4, 0); // i32-width body
    let r = routing::execute(&buf, GAS);
    assert!(
        r.is_err() || !r.expect("checked").success,
        "ARCH_VERSION 2 with i32-width body must fail-closed",
    );
}

// ---------------------------------------------------------------------------
// WP-D3 — misalignment: ± the widening delta (4 bytes) breaks the 8-byte
// element grid and must fail-closed, not round down.
// ---------------------------------------------------------------------------

#[test]
fn belnap_misaligned_by_widening_delta_rejected() {
    let base = belnap_valid(4, 3, Q16::from_int(1).0);

    let mut plus4 = base.clone();
    plus4.extend_from_slice(&[0u8; 4]); // body no longer matches expected_total
    assert!(belnap::decode(&plus4).is_err(), "+4 misaligned belnap must be rejected");

    let mut minus4 = base.clone();
    minus4.truncate(minus4.len() - 4);
    assert!(belnap::decode(&minus4).is_err(), "-4 misaligned belnap must be rejected");
}

// ---------------------------------------------------------------------------
// WP-D3 — saturation at the NEW i64 bounds: extreme Q16 raws through the full
// aggregation must saturate (i128 intermediates), never overflow-panic. Under
// overflow-checks = true (both profiles), a wrapping mul here would panic.
// ---------------------------------------------------------------------------

#[test]
fn belnap_saturation_at_i64_extremes_no_panic() {
    for &extreme in &[i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
        // Fill embeddings + confidences with the extreme raw; weights stay 1.0.
        let buf = belnap_valid(8, 4, extreme);
        let r = belnap::execute(&buf, GAS);
        assert!(
            r.is_ok(),
            "belnap must saturate (not panic) on i64-extreme embeddings ({extreme})",
        );
    }
}

#[test]
fn q16_ops_saturate_at_i64_bounds() {
    // The explicit cross-build invariant: i128 intermediates keep these in range.
    assert_eq!(Q16::MAX.saturating_mul(Q16::from_int(2)), Q16::MAX);
    assert_eq!(Q16::MIN.saturating_mul(Q16::from_int(2)), Q16::MIN);
    assert_eq!(Q16::MAX.saturating_add(Q16::from_int(1)), Q16::MAX);
    assert_eq!(Q16::MIN.saturating_add(Q16::from_int(-1)), Q16::MIN);
    // div-by-zero saturates by numerator sign (no panic).
    assert_eq!(Q16::from_int(5).saturating_div(Q16::from_raw(0)), Q16::MAX);
    assert_eq!(Q16::from_int(-5).saturating_div(Q16::from_raw(0)), Q16::MIN);
}

// ---------------------------------------------------------------------------
// WP-D3 — truncation sweep: every prefix of a valid buffer is Ok-or-Err, never
// a panic; everything below the header is rejected.
// ---------------------------------------------------------------------------

#[test]
fn belnap_truncation_sweep_never_panics() {
    let full = belnap_valid(6, 4, Q16::from_int(1).0);
    for k in 0..=full.len() {
        // Must not panic for any prefix length; just exercising the path.
        let _ = belnap::execute(&full[..k], GAS);
    }
    // Sub-header prefixes specifically reject.
    assert!(belnap::decode(&full[..23]).is_err(), "sub-24-byte belnap must be InputTooShort");
}

// ---------------------------------------------------------------------------
// WP-D3 — property fuzz at the executor boundary: arbitrary bytes never panic,
// and decoding is deterministic (same bytes → same verdict + same output).
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn belnap_execute_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // The assertion is simply that the call RETURNS (proptest fails the
        // property on any panic unwind).
        let _ = belnap::execute(&bytes, GAS);
    }

    #[test]
    fn routing_execute_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = routing::execute(&bytes, GAS);
    }

    #[test]
    fn belnap_execute_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let a = belnap::execute(&bytes, GAS);
        let b = belnap::execute(&bytes, GAS);
        match (a, b) {
            (Ok(ra), Ok(rb)) => {
                prop_assert_eq!(ra.success, rb.success);
                prop_assert_eq!(ra.output, rb.output);
                prop_assert_eq!(ra.gas_used, rb.gas_used);
            }
            (Err(_), Err(_)) => {} // both reject — deterministic verdict
            _ => prop_assert!(false, "non-deterministic Ok/Err for identical input"),
        }
    }

    #[test]
    fn routing_execute_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let a = routing::execute(&bytes, GAS);
        let b = routing::execute(&bytes, GAS);
        match (a, b) {
            (Ok(ra), Ok(rb)) => {
                prop_assert_eq!(ra.success, rb.success);
                prop_assert_eq!(ra.output, rb.output);
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "non-deterministic Ok/Err for identical input"),
        }
    }
}
