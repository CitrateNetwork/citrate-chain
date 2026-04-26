//! RM-K / WP-K1.5 — canonical address parsing and EIP-55 checksum.
//!
//! The 2026-04-26 Codex re-audit (residual / sibling-cluster review)
//! flagged that `wallet-core::SessionManager` and several wallet/GUI
//! call sites use raw `&str` address inputs as `HashMap` keys without
//! canonicalization. Two strings that name the same on-chain account
//! (`"0xABCDEF..."` vs `"0xabcdef..."` vs `"abcdef..."`) hash to three
//! different keys, which means a session lock for one form does not
//! lock the others. Worse, EIP-55 mixed-case input that fails the
//! checksum is silently accepted today.
//!
//! This module provides:
//!   - `canonicalize`: parse any acceptable input shape, validate, and
//!     return a single canonical form (`0x`-prefixed, all-lowercase, 40
//!     hex chars). Mixed-case input MUST validate as EIP-55 or the
//!     parse fails.
//!   - `to_eip55_checksum`: render a canonical lowercase address as the
//!     EIP-55 checksummed display form.
//!   - `AddressError`: explicit error enum so callers can distinguish
//!     "wrong length" from "checksum mismatch" from "non-hex".
//!
//! Trust boundary: this module is the single canonicalizer wallet-core
//! callers must route address inputs through before using them as
//! storage keys, lockout keys, freshness keys, or display strings.

use sha3::{Digest, Keccak256};

/// Errors produced by address parsing / canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// The input was not 40 hex characters (with or without `0x`
    /// prefix).
    InvalidLength { got: usize },
    /// The input contained non-hex characters.
    NonHex { offending: char },
    /// The input was mixed-case (had at least one uppercase and one
    /// lowercase hex letter) but the EIP-55 checksum did not validate.
    /// This is the load-bearing K1.5 case: silent acceptance of
    /// mixed-case-but-wrong-checksum input is the phishing vector the
    /// rule rejects.
    InvalidEip55Checksum,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::InvalidLength { got } => write!(
                f,
                "address must be 40 hex characters (with optional 0x prefix); got {} characters",
                got
            ),
            AddressError::NonHex { offending } => {
                write!(f, "address contains non-hex character {:?}", offending)
            }
            AddressError::InvalidEip55Checksum => write!(
                f,
                "address is mixed-case but the EIP-55 checksum is invalid; \
                 either use all-lowercase, all-uppercase, or a correctly \
                 checksummed mixed-case form"
            ),
        }
    }
}

impl std::error::Error for AddressError {}

/// Parse an arbitrary user-provided address string and return the
/// canonical form (`0x`-prefixed, all-lowercase, 40 hex chars).
///
/// Acceptable input shapes:
///   - `"0xabcdef0123..."` (40 hex chars after `0x`)
///   - `"0xABCDEF0123..."` (all-uppercase)
///   - `"abcdef0123..."` (no prefix)
///   - `"0xAbCdEf0123..."` (mixed-case) — only accepted if EIP-55
///     checksum validates.
///
/// Rejects:
///   - Wrong length.
///   - Non-hex characters.
///   - Mixed-case strings whose EIP-55 checksum is wrong (the K1.5
///     phishing-room defense).
pub fn canonicalize(input: &str) -> Result<String, AddressError> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if body.len() != 40 {
        return Err(AddressError::InvalidLength { got: body.len() });
    }

    // Validate every char is hex AND classify case.
    let mut has_upper = false;
    let mut has_lower = false;
    for ch in body.chars() {
        match ch {
            '0'..='9' => {}
            'a'..='f' => has_lower = true,
            'A'..='F' => has_upper = true,
            other => return Err(AddressError::NonHex { offending: other }),
        }
    }

    let lowercase: String = body.to_ascii_lowercase();

    // Pure-lowercase or pure-uppercase (or no letters at all): accept
    // as raw form.
    if !(has_upper && has_lower) {
        return Ok(format!("0x{}", lowercase));
    }

    // Mixed-case: must validate as EIP-55.
    let expected = eip55_checksum_body(&lowercase);
    if expected == body {
        Ok(format!("0x{}", lowercase))
    } else {
        Err(AddressError::InvalidEip55Checksum)
    }
}

/// Return the EIP-55 checksummed display form of a canonical address.
///
/// Input must already be canonical (`canonicalize` output shape:
/// `0x`-prefixed, all-lowercase, 40 hex chars). For non-canonical
/// inputs the function still computes a sensible result by lowercasing
/// first, but callers should prefer to canonicalize at the trust
/// boundary and pass the canonical form here.
pub fn to_eip55_checksum(canonical: &str) -> String {
    let body_lower = canonical
        .strip_prefix("0x")
        .or_else(|| canonical.strip_prefix("0X"))
        .unwrap_or(canonical)
        .to_ascii_lowercase();
    let checksum_body = eip55_checksum_body(&body_lower);
    format!("0x{}", checksum_body)
}

/// EIP-55 checksum encoding of a 40-char lowercase hex body.
/// Returns the 40-char mixed-case body (no `0x` prefix).
fn eip55_checksum_body(lowercase_body: &str) -> String {
    debug_assert_eq!(lowercase_body.len(), 40, "EIP-55 input must be 40 hex chars");
    let hash = Keccak256::digest(lowercase_body.as_bytes());
    let mut out = String::with_capacity(40);
    for (i, ch) in lowercase_body.chars().enumerate() {
        let nib = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if ch.is_ascii_alphabetic() && nib >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical test vector from EIP-55 itself:
    //   raw:        0x52908400098527886e0f7030069857d2e4169ee7
    //   checksummed:0x52908400098527886E0F7030069857D2E4169EE7
    // (this address is all-uppercase or all-numeric so the checksum
    // is degenerate; pick another with mixed letters).
    //
    // EIP-55 examples (from the spec):
    //   0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed   (mixed case)
    //   0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359   (mixed case)
    //   0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB   (mixed case)
    //   0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb   (mixed case)
    const VEC1: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const VEC2: &str = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

    #[test]
    fn test_k1_5_accepts_lowercase_address() {
        let canonical = canonicalize("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .expect("lowercase must canonicalize");
        assert_eq!(canonical, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    }

    #[test]
    fn test_k1_5_accepts_uppercase_address() {
        let canonical = canonicalize("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED")
            .expect("uppercase must canonicalize");
        assert_eq!(canonical, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    }

    #[test]
    fn test_k1_5_accepts_no_prefix() {
        let canonical = canonicalize("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .expect("no-prefix lowercase must canonicalize");
        assert_eq!(canonical, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    }

    #[test]
    fn test_k1_5_accepts_correct_eip55_checksum() {
        let canonical = canonicalize(VEC1).expect("valid EIP-55 mixed case must canonicalize");
        assert_eq!(canonical, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    }

    #[test]
    fn test_k1_5_accepts_correct_eip55_checksum_vec2() {
        let canonical = canonicalize(VEC2).expect("valid EIP-55 mixed case must canonicalize");
        assert_eq!(canonical, "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359");
    }

    #[test]
    fn test_k1_5_rejects_invalid_eip55_checksum() {
        // Take VEC1 and flip one letter's case: that destroys the
        // checksum. The parse MUST reject — this is the K1.5 phishing
        // defense.
        let bad = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let err = canonicalize(bad).expect_err("flipped-case must fail EIP-55 check");
        assert_eq!(err, AddressError::InvalidEip55Checksum);
    }

    #[test]
    fn test_k1_5_rejects_short_address() {
        let err =
            canonicalize("0xabc").expect_err("too-short address must be rejected");
        assert!(matches!(err, AddressError::InvalidLength { .. }));
    }

    #[test]
    fn test_k1_5_rejects_long_address() {
        let err = canonicalize("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaedDEADBEEF")
            .expect_err("too-long address must be rejected");
        assert!(matches!(err, AddressError::InvalidLength { .. }));
    }

    #[test]
    fn test_k1_5_rejects_non_hex() {
        let err = canonicalize("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beazz")
            .expect_err("non-hex must be rejected");
        assert!(matches!(err, AddressError::NonHex { .. }));
    }

    #[test]
    fn test_k1_5_canonicalize_idempotent() {
        let once = canonicalize(VEC1).expect("first canonicalize");
        let twice = canonicalize(&once).expect("second canonicalize");
        assert_eq!(once, twice);
    }

    #[test]
    fn test_k1_5_to_eip55_matches_canonical_form() {
        let canonical = canonicalize(VEC1).expect("canonicalize");
        let display = to_eip55_checksum(&canonical);
        assert_eq!(display, VEC1);
    }

    #[test]
    fn test_k1_5_to_eip55_round_trip_vec2() {
        let canonical = canonicalize(VEC2).expect("canonicalize");
        let display = to_eip55_checksum(&canonical);
        assert_eq!(display, VEC2);
    }

    #[test]
    fn test_k1_5_handles_whitespace() {
        let canonical = canonicalize("  0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed  ")
            .expect("trims whitespace");
        assert_eq!(canonical, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    }

    #[test]
    fn test_k1_5_lowercase_and_uppercase_collide_to_same_canonical() {
        let lo = canonicalize("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").expect("lo");
        let up = canonicalize("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED").expect("up");
        let cs = canonicalize(VEC1).expect("eip55");
        let np = canonicalize("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").expect("noprefix");
        assert_eq!(lo, up);
        assert_eq!(lo, cs);
        assert_eq!(lo, np);
    }
}
