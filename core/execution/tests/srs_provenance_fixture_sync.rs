//! PIN-P1 (f.4) — couple `srs::PINNED` ↔ `srs_provenance_v1.json`.
//!
//! Drift between the Rust table and the JSON fixture has caused real
//! provenance incidents (a hash gets pinned in one place but not the
//! other). This integration test pulls both into one process and
//! asserts every entry agrees.
//!
//! - `pinned: true` ⇒ JSON `sha256` MUST equal `PINNED[k].expected_sha256`
//! - `pinned: false` ⇒ JSON `sha256` MUST be `null` AND
//!   `PINNED[k].expected_sha256` MUST be `None`
//! - Per-entry `source_url` MUST equal `PINNED[k].canonical_url`
//! - The set of `k` values in both MUST match exactly (no orphan entries
//!   in either direction)

#![cfg(feature = "halo2-substrate")]

use citrate_execution::zkp::halo2::srs::{pinned_entry_for, PINNED};
use std::collections::BTreeSet;

#[derive(serde::Deserialize)]
struct Fixture {
    entries: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    k: u32,
    sha256: Option<String>,
    pinned: bool,
    source_url: String,
}

fn load_fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/srs_provenance_v1.json"
    );
    let bytes = std::fs::read(path).expect("fixture file present");
    serde_json::from_slice(&bytes).expect("fixture parses as schema")
}

#[test]
fn fixture_k_set_matches_pinned_table() {
    let fixture = load_fixture();
    let fix_ks: BTreeSet<u32> = fixture.entries.iter().map(|e| e.k).collect();
    let rust_ks: BTreeSet<u32> = PINNED.iter().map(|p| p.k).collect();
    assert_eq!(
        fix_ks, rust_ks,
        "set of pinned k values must match between fixture and srs::PINNED"
    );
}

#[test]
fn fixture_pinned_flag_matches_rust_table() {
    let fixture = load_fixture();
    for entry in &fixture.entries {
        let rust = pinned_entry_for(entry.k).expect("entry exists in PINNED");
        match (entry.pinned, rust.expected_sha256) {
            (true, Some(_)) | (false, None) => {}
            (true, None) => panic!(
                "k={}: fixture says pinned=true but srs::PINNED has expected_sha256=None",
                entry.k
            ),
            (false, Some(_)) => panic!(
                "k={}: fixture says pinned=false but srs::PINNED has expected_sha256=Some(..)",
                entry.k
            ),
        }
    }
}

#[test]
fn fixture_sha256_matches_rust_table_when_pinned() {
    let fixture = load_fixture();
    for entry in &fixture.entries {
        if !entry.pinned {
            continue;
        }
        let rust = pinned_entry_for(entry.k).expect("entry exists in PINNED");
        let rust_hex = hex::encode(rust.expected_sha256.expect("hash present"));
        let fix_hex = entry
            .sha256
            .as_ref()
            .expect("pinned entry has non-null sha256");
        assert_eq!(
            rust_hex, *fix_hex,
            "k={}: rust hash {rust_hex} ≠ fixture hash {fix_hex}",
            entry.k
        );
    }
}

#[test]
fn fixture_source_url_matches_rust_table() {
    let fixture = load_fixture();
    for entry in &fixture.entries {
        let rust = pinned_entry_for(entry.k).expect("entry exists in PINNED");
        assert_eq!(
            rust.canonical_url, entry.source_url,
            "k={}: canonical_url mismatch between PINNED ({}) and fixture ({})",
            entry.k, rust.canonical_url, entry.source_url
        );
    }
}
