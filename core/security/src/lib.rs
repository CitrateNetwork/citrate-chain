//! Citrate security primitives — AEAD wrapper.
//!
//! ## Why this crate exists
//!
//! Audit findings `WAL-02` (HIGH) and `GUI-L-01` (HIGH) — see
//! `.audit/2026-04-24-full-repo-adversarial-audit/` — both stemmed
//! from the same defect: callers used the raw
//! `aes_gcm::Aes256Gcm::encrypt(nonce, plaintext)` API which does not
//! bind any associated authenticated data (AAD) into the GCM tag. A
//! file-system-write-capable attacker could substitute ciphertexts
//! across records and decrypt to wrong context.
//!
//! Sprint RM-A3 / WP-A3.1 + WP-A3.2 fixed each call site individually.
//! This crate (WP-A3.3) consolidates the fix into a single typed
//! wrapper so:
//!
//!   * The error-prone two-arg `encrypt(nonce, plaintext)` shape is no
//!     longer reachable from production code via this API. Callers
//!     receive a [`Aead`] handle whose `seal` and `open` methods take
//!     AAD as a *required* parameter.
//!   * One canonical implementation; one set of tests; one mutation
//!     campaign. Bugs found here are fixed everywhere.
//!   * The Semgrep rule `wal-02-aead-no-aad.yaml` flags any direct
//!     `cipher.encrypt(nonce, plaintext)` outside this crate's
//!     internals — production paths must route through [`Aead::seal`].
//!
//! ## Usage
//!
//! ```no_run
//! use citrate_security::aead::{Aead, AeadError};
//! use zeroize::Zeroizing;
//!
//! let key: Zeroizing<[u8; 32]> = Zeroizing::new([0x42; 32]);
//! let aead = Aead::new(&key)?;
//! let nonce: [u8; 12] = [0x11; 12];
//! let aad = b"citrate-keystore-v2:0xdeadbeef";
//!
//! let ciphertext = aead.seal(&nonce, b"plaintext bytes", aad)?;
//! let plaintext  = aead.open(&nonce, &ciphertext, aad)?;
//! assert_eq!(plaintext, b"plaintext bytes");
//! # Ok::<_, AeadError>(())
//! ```
//!
//! ## Threat model
//!
//! - **Substitution attacks**: AAD is bound into the GCM tag. A
//!   `(ciphertext, nonce)` pair sealed under one AAD will fail to
//!   open under a different AAD.
//! - **Tag forgery**: Inherited from `aes-gcm`'s underlying primitive.
//!   Out of scope for this wrapper.
//! - **Nonce reuse**: Out of scope for this wrapper. Callers must
//!   supply a unique nonce per (key, message) pair. Wallet keystore
//!   uses 12 random bytes per encryption; the birthday bound at
//!   2^32 messages is well above realistic keystore turnover.
//! - **Side-channel resistance**: `aes-gcm`'s tag verification is
//!   constant-time. Other comparisons (e.g., MAC checks in caller
//!   code) must use [`subtle::ConstantTimeEq`].

#![deny(missing_docs)]

/// AEAD seal/open API.
pub mod aead;

pub use aead::{Aead, AeadError};
