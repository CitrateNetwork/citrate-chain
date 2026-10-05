//! HUP-S6.10: the coverage table is derived from the node's precompile list, address by
//! address, and says plainly which precompiles the fork cannot reproduce.
use citrate_fork::table::{coverage, real_addresses, short_address, table, Coverage};

fn short(raw: &[u8; 20]) -> u16 {
    (u16::from(raw[18]) << 8) | u16::from(raw[19])
}

#[test]
fn every_address_the_node_bridges_is_real_below_hardening() {
    for raw in citrate_execution::precompiles::PURE_PRECOMPILE_ADDRESSES.iter() {
        let v = short(raw);
        assert_eq!(coverage(v, false).0, Coverage::Real, "0x{v:04x}");
    }
    assert_eq!(
        real_addresses(false).len(),
        citrate_execution::precompiles::PURE_PRECOMPILE_ADDRESSES.len()
    );
}

#[test]
fn inference_reserved_and_tx_level_precompiles_are_unavailable() {
    for v in 0x0100..=0x0106u16 {
        let (c, note) = coverage(v, false);
        assert_eq!(c, Coverage::Unavailable, "0x{v:04x}");
        assert!(note.contains("inference"), "{note}");
    }
    for v in [0x0112u16, 0x013F, 0x0203, 0x0209] {
        assert_eq!(coverage(v, true).0, Coverage::Unavailable, "0x{v:04x}");
    }
    for v in [0x1000u16, 0x1002, 0x1003] {
        let (c, note) = coverage(v, false);
        assert_eq!(c, Coverage::Unavailable);
        assert!(note.contains("top-level transaction"), "{note}");
    }
}

#[test]
fn fold_verify_at_a_hardened_height_matches_the_build() {
    let (c, _) = coverage(0x0130, true);
    let expected = if citrate_execution::build_features::COMMD_FOLD_VERIFY {
        Coverage::Real
    } else {
        Coverage::Unavailable
    };
    assert_eq!(c, expected);
    assert_eq!(
        coverage(0x0130, false).0,
        Coverage::Real,
        "below hardening it fails on chain too"
    );
}

#[test]
fn the_table_covers_every_citrate_address_once() {
    let t = table(false);
    assert_eq!(t.len(), 0x40 + 10 + 3);
    let mut seen = std::collections::BTreeSet::new();
    for r in &t {
        assert!(seen.insert(r.address.clone()), "duplicate {}", r.address);
        assert!(!r.note.is_empty());
    }
}

#[test]
fn short_address_only_matches_citrate_precompiles() {
    let mut a = [0u8; 20];
    a[18] = 0x01;
    a[19] = 0x10;
    assert_eq!(short_address(&a), Some(0x0110));
    a[19] = 0x40;
    assert_eq!(short_address(&a), None, "0x0140 is outside the family");
    let mut std1 = [0u8; 20];
    std1[19] = 1;
    assert_eq!(
        short_address(&std1),
        None,
        "ecrecover is not a Citrate precompile"
    );
    let mut far = [0u8; 20];
    far[0] = 1;
    far[18] = 0x01;
    far[19] = 0x10;
    assert_eq!(short_address(&far), None);
}
