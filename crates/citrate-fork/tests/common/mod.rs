//! Shared helpers for the citrate-fork integration tests.
#![allow(dead_code)]

use citrate_fork::run::{pinned_hardening, ForkConfig, StateSource};
use citrate_fork::ForkBlock;
use revm::primitives::{Address, U256};

pub const FIXTURES: &str = include_str!("../fixtures/probes.json");

pub fn fixture(name: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    v.get(name)
        .and_then(|s| s.as_str())
        .expect("fixture present")
        .to_string()
}

/// A sender with no special meaning (a fixed test address, no key behind it).
pub fn sender() -> Address {
    Address::from_slice(&[0x5e; 20])
}

pub fn addr_hex(a: Address) -> String {
    format!("{a:#x}")
}

/// One ABI word for an address.
pub fn word_addr(a: &[u8; 20]) -> String {
    format!("{:0>64}", hex::encode(a))
}

pub fn word_u(v: u64) -> String {
    format!("{v:064x}")
}

/// `abi.encode(address, bytes)`.
pub fn encode_addr_bytes(a: &[u8; 20], data: &[u8]) -> String {
    let mut s = word_addr(a);
    s.push_str(&word_u(0x40));
    s.push_str(&word_u(data.len() as u64));
    let mut d = hex::encode(data);
    while !d.len().is_multiple_of(64) {
        d.push('0');
    }
    s.push_str(&d);
    s
}

/// A short Citrate precompile address as 20 bytes.
pub fn precompile(v: u16) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[18] = (v >> 8) as u8;
    a[19] = (v & 0xff) as u8;
    a
}

/// Init code of `PrecompileProbe(precompile, input)`.
pub fn probe_initcode(v: u16, input: &[u8]) -> String {
    format!(
        "{}{}",
        fixture("PrecompileProbe"),
        encode_addr_bytes(&precompile(v), input)
    )
}

/// A valid BELNAP_AGGREGATE (0x0110) input: dim 1, n 1, one confident positive vote.
pub fn belnap_input() -> Vec<u8> {
    let one: i64 = 1 << 16;
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_be_bytes()); // dim
    b.extend_from_slice(&1u32.to_be_bytes()); // n
    b.extend_from_slice(&one.to_be_bytes()); // embedding
    b.extend_from_slice(&one.to_be_bytes()); // confidence
    b.extend_from_slice(&one.to_be_bytes()); // weight
    b.extend_from_slice(&(one / 2).to_be_bytes()); // threshold_pos
    b.extend_from_slice(&(-(one / 2)).to_be_bytes()); // threshold_neg
    b
}

/// An empty-state 40204 config at `block` (the hardening height is the release pin).
pub fn config_at(block: u64) -> ForkConfig {
    ForkConfig {
        chain_id: 40204,
        block: ForkBlock {
            number: block,
            timestamp: 1_790_000_000,
            hash: None,
            coinbase: Address::ZERO,
        },
        hardening_height: pinned_hardening(40204),
        hardening_source: "release pin".into(),
        source: StateSource::Empty,
    }
}

/// One ether-like unit (10^18 wei) times `n`.
pub fn salt(n: u64) -> U256 {
    U256::from(n) * U256::from(1_000_000_000_000_000_000u64)
}

/// Decodes an ABI `bytes` return value.
pub fn abi_bytes(out_hex: &str) -> Vec<u8> {
    let raw = hex::decode(out_hex.trim_start_matches("0x")).expect("hex");
    assert!(raw.len() >= 64, "abi bytes too short");
    let len = u64::from_be_bytes(raw[56..64].try_into().expect("8 bytes")) as usize;
    raw[64..64 + len].to_vec()
}

/// Decodes an ABI word as U256.
pub fn abi_u256(out_hex: &str) -> U256 {
    let raw = hex::decode(out_hex.trim_start_matches("0x")).expect("hex");
    assert_eq!(raw.len(), 32, "one word");
    U256::from_be_slice(&raw)
}
