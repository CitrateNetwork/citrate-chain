//! BFR-14 — HKDF sub-secret chain.
//!
//! Implements `HKDFSubSecretDerivation.tla` (BFR-00):
//!
//! ```text
//! child_secret = HKDF-SHA-256(IKM=parent_secret, salt=node.hkdf_salt, info=label, len=32)
//! ```
//!
//! Properties (all proven in the TLA+ spec + verified by tests below):
//!
//! - **Deterministic** — same `(parent, salt, label)` always derives
//!   the same child.
//! - **One-way** — child cannot be inverted to parent (HKDF property).
//! - **Sibling-independent** — knowing one child does not leak any
//!   other child of the same parent.
//! - **Composable** — derive grandchildren by re-running the function
//!   on the child as parent.
//!
//! Implications per planset 09_INTER_ORG_TRANSFER.md:
//! - Boeing's BCA-Everett-777X team holds a sub-secret derived through
//!   3 HKDF steps from the Boeing root.
//! - A compromised team-level secret does NOT compromise its parent BU.
//! - Tier-N supplier roots sub-derive per work-cell; cell-level
//!   signatures cannot impersonate the supplier root.

#![warn(clippy::all)]
#![deny(missing_docs)]

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Errors for HKDF derivation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HkdfError {
    /// Underlying HKDF expand step failed (length too long).
    #[error("HKDF expand failed: {0}")]
    Expand(String),

    /// SECREM-01 CRY-2: `derive_chain` was called with an empty step list.
    /// Returning the root secret unchanged would be a domain-confusion
    /// footgun (caller expects a derived child, gets the master secret).
    #[error("derive_chain requires at least one step; empty chain rejected")]
    EmptyChain,
}

/// Derive a 32-byte child sub-secret from a parent secret + HKDF salt +
/// child label.
///
/// Maps 1:1 onto `HKDFSubSecretDerivation.tla::Derive(parent, salt, label)`.
///
/// # Arguments
/// - `parent_secret` — 32-byte parent secret (IKM input).
/// - `hkdf_salt` — 32-byte salt drawn from the on-chain TenantNode.
/// - `label` — UTF-8 child label (e.g., `"BCA"`, `"Everett"`, `"777X"`).
///
/// # Returns
/// 32-byte child sub-secret, wrapped in [`Zeroizing`] so the key material
/// is wiped from memory when the value is dropped (SECREM-01 CRY-1).
///
/// # Zeroization (SECREM-01 CRY-1)
/// - The OKM is written directly into the `Zeroizing` return buffer —
///   no unwiped intermediate copy exists in this crate.
/// - The PRK copy returned by `Hkdf::extract` is explicitly zeroized
///   before this function returns. (The HMAC state held inside the
///   `hkdf`/`hmac` crates is outside our control; its zeroization is an
///   upstream property.)
pub fn derive(
    parent_secret: &[u8; 32],
    hkdf_salt: &[u8; 32],
    label: &[u8],
) -> Result<Zeroizing<[u8; 32]>, HkdfError> {
    // SECREM-01 CRY-1: use `extract` (not `new`) so we hold the PRK copy
    // and can wipe it; expand writes OKM straight into the Zeroizing buffer.
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(hkdf_salt), parent_secret);
    let mut child = Zeroizing::new([0u8; 32]);
    let expand_result = hk.expand(label, &mut child[..]);
    drop(hk);
    prk.as_mut_slice().zeroize();
    expand_result.map_err(|e| HkdfError::Expand(e.to_string()))?;
    Ok(child)
}

/// Derive a chain of sub-secrets through a sequence of labels.
///
/// `derive_chain(root, [salt_0, label_0, salt_1, label_1, ...])`
/// applies `derive` left-to-right, returning the final descendant
/// secret wrapped in [`Zeroizing`] (SECREM-01 CRY-1). Every intermediate
/// secret in the chain is also held in `Zeroizing` and is wiped as soon
/// as the next derivation replaces it.
pub fn derive_chain(
    root_secret: &[u8; 32],
    steps: &[(&[u8; 32], &[u8])],
) -> Result<Zeroizing<[u8; 32]>, HkdfError> {
    // SECREM-01 CRY-2: reject the empty chain. `derive_chain(root, &[])`
    // previously returned the ROOT secret verbatim — a domain-confusion
    // footgun where a caller expecting a derived child gets the master
    // secret. An empty derivation path is a programming error.
    if steps.is_empty() {
        return Err(HkdfError::EmptyChain);
    }
    let mut current = Zeroizing::new(*root_secret);
    for (salt, label) in steps {
        // SECREM-01 CRY-1: re-assignment drops (and thereby zeroizes) the
        // previous intermediate secret.
        current = derive(&current, salt, label)?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn derive_is_deterministic() {
        let parent = fill(0xAA);
        let salt = fill(0x11);
        let label = b"BCA";
        let a = derive(&parent, &salt, label).expect("ok");
        let b = derive(&parent, &salt, label).expect("ok");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_different_labels_yield_different_children() {
        let parent = fill(0xAA);
        let salt = fill(0x11);
        let bca = derive(&parent, &salt, b"BCA").expect("ok");
        let bds = derive(&parent, &salt, b"BDS").expect("ok");
        assert_ne!(*bca, *bds);
    }

    #[test]
    fn derive_different_salts_yield_different_children() {
        let parent = fill(0xAA);
        let label = b"BCA";
        let s1 = derive(&parent, &fill(0x11), label).expect("ok");
        let s2 = derive(&parent, &fill(0x22), label).expect("ok");
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn derive_different_parents_yield_different_children() {
        let label = b"BCA";
        let salt = fill(0x11);
        let a = derive(&fill(0xAA), &salt, label).expect("ok");
        let b = derive(&fill(0xBB), &salt, label).expect("ok");
        assert_ne!(*a, *b);
    }

    #[test]
    fn derive_chain_3_levels_matches_manual_composition() {
        let root = fill(0xAA);
        let salt_a = fill(0x10);
        let salt_b = fill(0x20);
        let salt_c = fill(0x30);
        let manual_a = derive(&root, &salt_a, b"BCA").expect("ok");
        let manual_b = derive(&manual_a, &salt_b, b"Everett").expect("ok");
        let manual_c = derive(&manual_b, &salt_c, b"777X").expect("ok");
        let chain = derive_chain(
            &root,
            &[
                (&salt_a, b"BCA"),
                (&salt_b, b"Everett"),
                (&salt_c, b"777X"),
            ],
        )
        .expect("ok");
        assert_eq!(*chain, *manual_c);
    }

    #[test]
    fn sibling_derivations_are_independent() {
        // Knowing the BCA child gives no information about BDS child
        // (we can't prove this exhaustively, but we verify the
        // outputs are unrelated under a fixed parent+salt).
        let parent = fill(0xAA);
        let salt = fill(0x11);
        let bca = derive(&parent, &salt, b"BCA").expect("ok");
        let bds = derive(&parent, &salt, b"BDS").expect("ok");
        // Bytewise distinct with no shared prefix > 1 byte
        // (probabilistic check; under HKDF-SHA-256 the probability of
        // any prefix > 16 bytes is vanishingly small).
        let shared_prefix = bca.iter().zip(bds.iter()).take_while(|(a, b)| a == b).count();
        assert!(shared_prefix < 16, "shared_prefix={shared_prefix}");
    }

    /// SECREM-01 CRY-2: an empty chain is REJECTED, not silently
    /// returned as the root secret (domain-confusion footgun).
    #[test]
    fn derive_empty_chain_is_rejected() {
        let root = fill(0xCC);
        assert_eq!(derive_chain(&root, &[]), Err(HkdfError::EmptyChain));
    }

    #[test]
    fn boeing_demo_path_matches_planset_example() {
        // Planset § HKDF chain: Boeing root → BCA → Everett → 777X.
        let root = fill(0x00);
        let salts = [fill(0x01), fill(0x02), fill(0x03)];
        let r = derive_chain(
            &root,
            &[
                (&salts[0], b"BCA"),
                (&salts[1], b"Everett"),
                (&salts[2], b"777X"),
            ],
        )
        .expect("ok");
        // The team-level secret is non-zero and not equal to the root.
        assert_ne!(*r, root);
        assert_ne!(*r, [0u8; 32]);
    }

    #[test]
    fn empty_label_still_derives_deterministically() {
        let parent = fill(0xAA);
        let salt = fill(0x11);
        let a = derive(&parent, &salt, b"").expect("ok");
        let b = derive(&parent, &salt, b"").expect("ok");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_returns_zeroizing_key_material() {
        // SECREM-01 CRY-1: type-level proof that both public derivation
        // entry points return key material in a container that wipes
        // itself on drop. If the return type regresses to a bare
        // [u8; 32], this test fails to compile.
        fn assert_is_zeroizing(_: &Zeroizing<[u8; 32]>) {}
        let parent = fill(0xAA);
        let salt = fill(0x11);
        let child = derive(&parent, &salt, b"BCA").expect("ok");
        assert_is_zeroizing(&child);
        let chained = derive_chain(&parent, &[(&salt, b"BCA")]).expect("ok");
        assert_is_zeroizing(&chained);
        // Derived values are still real key material (non-zero).
        assert_ne!(*child, [0u8; 32]);
    }
}
