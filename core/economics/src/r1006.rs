//! The `r1006` genesis profile: block 0 already holds the genesis contracts.
//!
//! r1006's genesis is built from ceremony state ("genesis from ceremony state"): the real
//! contract ceremony (P0-P5) runs on a private Citrate devnet, the devnet's post-ceremony
//! state is dumped, and that dump is this profile's allocation
//! (`assets/r1006/alloc.json`, written by `scripts/genesis/r1006/build_r1006_genesis.sh`).
//! On top of it come the base allocations (the testnet_beta set r1005 shipped), the
//! genesis note (the "seed planted" message, in state at [`GENESIS_NOTE_ADDRESS`]). The
//! OrangeSeed accounts arrive inside the allocation (`emit_alloc.py --orangeseed`).
//!
//! Fail closed. Three inputs are owner-supplied and may still be placeholders: the ceremony
//! inputs (council holders, signers: A-3), the producer set ([`R1006_VALIDATORS_JSON`],
//! filled by `scripts/genesis/r1006/fill_producers.py`) and the OrangeSeed artifacts.
//! [`readiness`] reports them; a node refuses to create or run an r1006 genesis that is
//! not release-ready unless it is explicitly a rehearsal (see the node's genesis module).

use crate::genesis::{GenesisAccount, GenesisConfig, GenesisError};
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashSet};

/// The ceremony-state allocation (see the module docs).
pub const R1006_ALLOC_JSON: &str = include_str!("../assets/r1006/alloc.json");
/// The producer set the ceremony registered (status `placeholder` until filled).
pub const R1006_VALIDATORS_JSON: &str = include_str!("../assets/r1006/validators.json");

/// Number of producers r1006 starts with.
pub const R1006_PRODUCER_COUNT: usize = 7;

/// Where the genesis note lives: an account with no code whose storage holds the note as a
/// Solidity `string` at slot 0 (so `eth_getStorageAt` and any ABI decoder read it).
/// `0x000000000000000000000000000000C17A7E1006`: "citrate r1006".
pub const GENESIS_NOTE_ADDRESS: Address = Address([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC1, 0x7A, 0x7E, 0x10, 0x06,
]);

/// The block-0 message, in the orchard voice. It is part of the genesis state, so it is
/// part of the genesis hash.
pub const GENESIS_NOTE: &str =
    "Citrate r1006. The seed is planted: every contract was grown in the open, at block zero. Tend the orchard; share the harvest.";

/// The OrangeSeed proxy address (owner-confirmed 2026-10-26, as the 20-byte
/// `0x000000000000000000000000000000C17A7E5EED`).
pub const ORANGESEED_ADDRESS: Address = Address([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC1, 0x7A, 0x7E, 0x5E, 0xED,
]);

/// What the r1006 genesis still waits for. Release-ready only when nothing is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// The ceremony ran with the owner's final A-3 inputs.
    pub inputs_final: bool,
    /// The producer set is filled and is the one the ceremony registered.
    pub validators_final: bool,
    /// The OrangeSeed accounts are in the genesis.
    pub orangeseed_present: bool,
}

impl Readiness {
    pub fn is_release_ready(&self) -> bool {
        self.inputs_final && self.validators_final && self.orangeseed_present
    }

    /// The missing pieces, by name (empty when release-ready).
    pub fn missing(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if !self.inputs_final {
            m.push("ceremony inputs are placeholders (A-3 addresses)");
        }
        if !self.validators_final {
            m.push("producer set is a placeholder (fill_producers.py, then rebuild)");
        }
        if !self.orangeseed_present {
            m.push("OrangeSeed artifacts are not in the genesis yet");
        }
        m
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AllocFile {
    format: String,
    profile: String,
    inputs_status: String,
    #[allow(dead_code)]
    inputs_sha256: String,
    /// The ceremony's ValidatorRegistry (the producer set is registered there).
    validator_registry: String,
    /// TYPED SLOT for the OrangeSeed accounts: `null` until the OrangeSeed artifacts
    /// (proxy + implementation code and storage, from its PR's GenesisOrangeSeed script)
    /// are merged in by `emit_alloc.py --orangeseed`. While `null` the genesis is not
    /// release-ready.
    orangeseed: Option<OrangeSeedRecord>,
    #[allow(dead_code)]
    deployer: String,
    accounts: Vec<AllocAccount>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrangeSeedRecord {
    proxy: String,
    implementation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocAccount {
    address: String,
    balance: String,
    nonce: u64,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    storage: BTreeMap<String, String>,
}

/// The producer set file (`assets/r1006/validators.json`, schema `r1006-validators/1`),
/// written by `scripts/genesis/r1006/fill_producers.py`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorsFile {
    #[serde(rename = "_doc", default)]
    #[allow(dead_code)]
    doc: Option<String>,
    schema: String,
    status: String,
    #[serde(rename = "validatorRegistry")]
    validator_registry: Option<String>,
    validators: Vec<ValidatorEntry>,
    /// The registry's state after registering `validators` at block 0, computed by
    /// running the registry's own code (contracts/script/GenesisValidators.s.sol).
    registry: Option<RegistryDelta>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorEntry {
    #[allow(dead_code)]
    name: String,
    proposer_pubkey: String,
    staker: String,
    stake_wei: String,
    /// The staker's liquid balance at genesis (gas), wei.
    liquid_wei: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RegistryDelta {
    balance: String,
    #[allow(dead_code)]
    activation_epoch: u64,
    storage: BTreeMap<String, String>,
}

fn decimal(s: &str, what: &str) -> Result<U256, GenesisError> {
    U256::from_dec_str(s).map_err(|e| invalid(format!("{what} {s}: {e:?}")))
}

fn parse_validators() -> Result<ValidatorsFile, GenesisError> {
    let v: ValidatorsFile = serde_json::from_str(R1006_VALIDATORS_JSON)
        .map_err(|e| invalid(format!("validators.json: {e}")))?;
    if v.schema != "r1006-validators/1" {
        return Err(invalid("validators.json: not r1006-validators/1"));
    }
    Ok(v)
}

fn invalid(msg: impl Into<String>) -> GenesisError {
    GenesisError::Invalid(format!("r1006 alloc: {}", msg.into()))
}

fn hex_bytes(s: &str, what: &str) -> Result<Vec<u8>, GenesisError> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{what}: no 0x prefix")))?;
    if h.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(invalid(format!("{what}: not lowercase")));
    }
    hex::decode(h).map_err(|e| invalid(format!("{what}: {e}")))
}

fn word(s: &str, what: &str) -> Result<[u8; 32], GenesisError> {
    let b = hex_bytes(s, what)?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| invalid(format!("{what}: not 32 bytes")))
}

fn address(s: &str) -> Result<Address, GenesisError> {
    let b = hex_bytes(s, "address")?;
    <[u8; 20]>::try_from(b.as_slice())
        .map(Address)
        .map_err(|_| invalid(format!("address {s}: not 20 bytes")))
}

fn quantity(s: &str) -> Result<U256, GenesisError> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("balance {s}: no 0x prefix")))?;
    U256::from_str_radix(h, 16).map_err(|e| invalid(format!("balance {s}: {e}")))
}

/// The storage of a Solidity `string` at slot 0 holding `s`.
pub fn solidity_string_slots(s: &str) -> Vec<([u8; 32], [u8; 32])> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    if b.len() < 32 {
        let mut v = [0u8; 32];
        for (d, x) in v.iter_mut().zip(b.iter()) {
            *d = *x;
        }
        if let Some(last) = v.last_mut() {
            *last = (b.len() as u8).saturating_mul(2);
        }
        out.push(([0u8; 32], v));
        return out;
    }
    let len_word = U256::from(b.len())
        .saturating_mul(U256::from(2u8))
        .saturating_add(U256::one());
    let mut lw = [0u8; 32];
    len_word.to_big_endian(&mut lw);
    out.push(([0u8; 32], lw));
    let base = U256::from_big_endian(&Keccak256::digest([0u8; 32]));
    for (i, chunk) in b.chunks(32).enumerate() {
        let mut v = [0u8; 32];
        for (d, x) in v.iter_mut().zip(chunk.iter()) {
            *d = *x;
        }
        let mut k = [0u8; 32];
        base.overflowing_add(U256::from(i)).0.to_big_endian(&mut k);
        out.push((k, v));
    }
    out
}

fn parse_alloc() -> Result<(AllocFile, Vec<GenesisAccount>), GenesisError> {
    let f: AllocFile =
        serde_json::from_str(R1006_ALLOC_JSON).map_err(|e| invalid(format!("parse: {e}")))?;
    if f.format != "citrate-genesis-alloc-v1" || f.profile != "r1006" {
        return Err(invalid("not a citrate-genesis-alloc-v1 file for r1006"));
    }
    let mut accounts = Vec::with_capacity(f.accounts.len());
    let mut prev: Option<[u8; 20]> = None;
    for a in &f.accounts {
        let addr = address(&a.address)?;
        if prev.is_some_and(|p| p >= addr.0) {
            return Err(invalid(format!(
                "{}: accounts not strictly sorted",
                a.address
            )));
        }
        prev = Some(addr.0);
        let code = match &a.code {
            Some(c) => Some(hex_bytes(c, "code")?),
            None => None,
        };
        let mut storage = Vec::with_capacity(a.storage.len());
        for (k, v) in &a.storage {
            let v = word(v, "storage value")?;
            if v == [0u8; 32] {
                return Err(invalid(format!("{}: a zero storage value", a.address)));
            }
            storage.push((word(k, "storage slot")?, v));
        }
        accounts.push(GenesisAccount {
            address: addr,
            balance: quantity(&a.balance)?,
            nonce: a.nonce,
            code,
            storage,
        });
    }
    Ok((f, accounts))
}

/// What the compiled r1006 genesis still waits for.
pub fn readiness() -> Result<Readiness, GenesisError> {
    let (f, accounts) = parse_alloc()?;
    let has_code = |a: &Address| {
        accounts
            .iter()
            .any(|x| x.address == *a && x.code.as_ref().is_some_and(|c| !c.is_empty()))
    };
    let orangeseed_present = match &f.orangeseed {
        None => false,
        Some(o) => {
            let proxy = address(&o.proxy)?;
            let implementation = address(&o.implementation)?;
            if proxy != ORANGESEED_ADDRESS {
                return Err(invalid(
                    "the OrangeSeed proxy is not at its confirmed address",
                ));
            }
            if !has_code(&proxy) || !has_code(&implementation) {
                return Err(invalid(
                    "the OrangeSeed record names an account without code",
                ));
            }
            true
        }
    };
    let v = parse_validators()?;
    let vr = address(&f.validator_registry)?;
    let validators_final = v.status == "final"
        && v.validators.len() == R1006_PRODUCER_COUNT
        && v.registry.is_some()
        && v.validator_registry.as_deref().map(address).transpose()? == Some(vr);
    Ok(Readiness {
        inputs_final: f.inputs_status == "final",
        validators_final,
        orangeseed_present,
    })
}

impl GenesisConfig {
    /// The r1006 genesis configuration (chain 40204): the base allocations, the ceremony
    /// state, the genesis note and the OrangeSeed accounts. A ceremony account replaces a
    /// base account at the same address (the Arachnid factory, whose nonce the ceremony
    /// moved). The mining pool is what the 1T supply leaves after every pre-allocation.
    pub fn r1006() -> Result<Self, GenesisError> {
        let (f, mut ceremony) = parse_alloc()?;
        let v = parse_validators()?;
        if let Some(reg) = &v.registry {
            let vr = address(&f.validator_registry)?;
            if v.validator_registry.as_deref().map(address).transpose()? != Some(vr) {
                return Err(invalid(
                    "validators.json was filled for another ValidatorRegistry",
                ));
            }
            let acct = ceremony
                .iter_mut()
                .find(|a| a.address == vr)
                .ok_or_else(|| invalid("the ValidatorRegistry is not in the alloc"))?;
            acct.balance = decimal(&reg.balance, "registry balance")?;
            let mut slots: BTreeMap<[u8; 32], [u8; 32]> = acct.storage.iter().copied().collect();
            for (k, val) in &reg.storage {
                let val = word(val, "registry storage value")?;
                let k = word(k, "registry storage slot")?;
                if val == [0u8; 32] {
                    slots.remove(&k);
                } else {
                    slots.insert(k, val);
                }
            }
            acct.storage = slots.into_iter().collect();
        }
        let mut extra = ceremony;
        for e in &v.validators {
            let _ = word(&e.proposer_pubkey, "proposer_pubkey")?;
            let _ = decimal(&e.stake_wei, "stake_wei")?;
            extra.push(GenesisAccount {
                address: address(&e.staker)?,
                balance: decimal(&e.liquid_wei, "liquid_wei")?,
                nonce: 0,
                code: None,
                storage: vec![],
            });
        }
        extra.push(GenesisAccount {
            address: GENESIS_NOTE_ADDRESS,
            balance: U256::zero(),
            nonce: 1,
            code: None,
            storage: solidity_string_slots(GENESIS_NOTE),
        });
        let taken: HashSet<[u8; 20]> = extra.iter().map(|a| a.address.0).collect();
        let base = GenesisConfig::testnet_beta();
        let mut accounts: Vec<GenesisAccount> = base
            .accounts
            .into_iter()
            .filter(|a| !taken.contains(&a.address.0))
            .collect();
        accounts.extend(extra);
        let mut cfg = GenesisConfig {
            chain_id: 40204,
            accounts,
            treasury_address: base.treasury_address,
            team_allocations: base.team_allocations,
            ecosystem_fund: base.ecosystem_fund,
            mining_pool_max: U256::zero(),
        };
        let supply = U256::from(crate::TOTAL_SUPPLY)
            .checked_mul(crate::wei_per_salt())
            .ok_or(GenesisError::ExceedsSupply)?;
        let pre = cfg
            .total_preallocation()
            .ok_or(GenesisError::ExceedsSupply)?;
        cfg.mining_pool_max = supply.checked_sub(pre).ok_or(GenesisError::ExceedsSupply)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

/// Block 0's hash for `cfg`, built exactly as a node builds it (shared genesis state
/// on a fresh executor, the canonical genesis block, its state root).
pub fn genesis_block_hash(cfg: &GenesisConfig) -> Result<[u8; 32], GenesisError> {
    use citrate_execution::executor::Executor;
    use citrate_execution::state::state_db::StateDB;
    use std::sync::Arc;
    let ex = Arc::new(Executor::with_chain_id(
        Arc::new(StateDB::new()),
        cfg.chain_id,
    ));
    let root = crate::genesis::initialize_shared_genesis_state(&ex, cfg)?;
    let mut b =
        crate::genesis::create_canonical_genesis_block(crate::genesis::CANONICAL_GENESIS_TIMESTAMP);
    b.state_root = citrate_consensus::types::Hash::new(root);
    Ok(*crate::genesis::calculate_canonical_block_hash(&b).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_note_is_a_solidity_string_at_slot_zero() {
        let short = solidity_string_slots("seed");
        assert_eq!(short.len(), 1);
        assert_eq!(&short[0].1[..4], b"seed");
        assert_eq!(short[0].1[31], 8);
        let long = solidity_string_slots(GENESIS_NOTE);
        let n = GENESIS_NOTE.len();
        assert!(n >= 32);
        assert_eq!(long.len(), 1 + n.div_ceil(32));
        assert_eq!(U256::from_big_endian(&long[0].1), U256::from(n * 2 + 1));
        let mut joined = Vec::new();
        for (_, v) in &long[1..] {
            joined.extend_from_slice(v);
        }
        assert_eq!(&joined[..n], GENESIS_NOTE.as_bytes());
        // keccak256(bytes32(0)), the data slot of a string at slot 0.
        assert_eq!(
            hex::encode(long[1].0),
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    fn the_profile_builds_and_keeps_the_supply_cap() {
        let cfg = GenesisConfig::r1006().expect("r1006 builds");
        assert_eq!(cfg.chain_id, 40204);
        cfg.validate().expect("valid");
        let supply = U256::from(crate::TOTAL_SUPPLY) * crate::wei_per_salt();
        assert_eq!(
            cfg.total_preallocation().expect("sum") + cfg.mining_pool_max,
            supply
        );
        assert!(cfg
            .accounts
            .iter()
            .any(|a| a.address == GENESIS_NOTE_ADDRESS && !a.storage.is_empty()));
    }

    fn genesis_hash_of(cfg: &GenesisConfig) -> [u8; 32] {
        genesis_block_hash(cfg).expect("genesis")
    }

    /// The compiled profile builds exactly the block 0 the release pins, twice over.
    #[test]
    fn r1006_genesis_hash_is_pinned_and_reproducible() {
        let a = genesis_hash_of(&GenesisConfig::r1006().expect("r1006"));
        let b = genesis_hash_of(&GenesisConfig::r1006().expect("r1006"));
        assert_eq!(a, b, "two builds of the r1006 genesis differ");
        assert_eq!(
            a,
            citrate_consensus::hardening::R1006_GENESIS,
            "R1006_GENESIS is stale: the compiled r1006 profile builds 0x{}",
            hex::encode(a)
        );
        assert_ne!(
            a,
            citrate_consensus::hardening::RELEASE_GENESIS[0].1,
            "r1006 must not be r1005"
        );
    }

    /// Every account in the ceremony alloc reaches the genesis byte for byte.
    #[test]
    fn every_alloc_account_is_in_the_profile_unchanged() {
        let (f, alloc) = parse_alloc().expect("alloc");
        let cfg = GenesisConfig::r1006().expect("r1006");
        let vr = address(&f.validator_registry).expect("vr");
        let filled = parse_validators().expect("validators").registry.is_some();
        for a in alloc.iter().filter(|a| !(filled && a.address == vr)) {
            let g = cfg
                .accounts
                .iter()
                .find(|x| x.address == a.address)
                .expect("alloc account in the profile");
            assert_eq!(g.code, a.code);
            assert_eq!(g.storage, a.storage);
            assert_eq!((g.balance, g.nonce), (a.balance, a.nonce));
        }
        let mut seen = HashSet::new();
        assert!(
            cfg.accounts.iter().all(|a| seen.insert(a.address.0)),
            "no duplicates"
        );
    }

    #[test]
    fn readiness_names_every_missing_piece() {
        let r = Readiness {
            inputs_final: false,
            validators_final: false,
            orangeseed_present: false,
        };
        assert!(!r.is_release_ready());
        assert_eq!(r.missing().len(), 3);
        let ok = Readiness {
            inputs_final: true,
            validators_final: true,
            orangeseed_present: true,
        };
        assert!(ok.is_release_ready() && ok.missing().is_empty());
        for (i, f) in [
            Readiness {
                inputs_final: false,
                ..ok.clone()
            },
            Readiness {
                validators_final: false,
                ..ok.clone()
            },
            Readiness {
                orangeseed_present: false,
                ..ok.clone()
            },
        ]
        .iter()
        .enumerate()
        {
            assert!(!f.is_release_ready(), "case {i}");
            assert_eq!(f.missing().len(), 1, "case {i}");
        }
    }

    #[test]
    fn the_compiled_genesis_is_not_release_ready_while_placeholders_remain() {
        let (f, _) = parse_alloc().expect("alloc");
        let r = readiness().expect("readiness");
        assert_eq!(r.orangeseed_present, f.orangeseed.is_some());
        assert_eq!(r.inputs_final, f.inputs_status == "final");
        if f.orangeseed.is_none() || f.inputs_status != "final" {
            assert!(!r.is_release_ready());
        }
    }

    #[test]
    fn the_reserved_addresses_are_the_confirmed_ones() {
        assert_eq!(
            hex::encode(ORANGESEED_ADDRESS.0),
            "000000000000000000000000000000c17a7e5eed"
        );
        assert_eq!(
            hex::encode(GENESIS_NOTE_ADDRESS.0),
            "000000000000000000000000000000c17a7e1006"
        );
    }
}
