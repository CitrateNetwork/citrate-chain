//! The `r1007` genesis profile: the r1006 ceremony state, a new block 0 (S3-6).
//!
//! Owner decisions (ADR-2026-11-03 Q-1, Q-3; 2026-11-03 and 2026-11-07):
//! * r1007 is a new-genesis **rehearsal** of chain 40204 (not the ceremony genesis);
//! * from the **same validator set** and the same producer keys (owner 2026-11-09), with **today's contract set**: block 0 is laid
//!   out from the r1006 block-0 state (`assets/r1006/alloc.json` and
//!   `assets/r1006/validators.json`, read in place: one source of truth, Rule 9), so
//!   every block-0 contract address, the membership SBT and vault included, is the
//!   same as on r1006;
//! * **D-K3 (owner 2026-11-10): every non-producer EVM key is rotated** at the r1007
//!   ceremony (treasury, faucet, team, deployer, grantor, signers, relayer, AA keys,
//!   governance and guardian owners; [`ROTATED_R1006_KEYS`]). The owner generated the
//!   fresh keys on 2026-11-11: block 0 is the r1006 block-0 state with each of them
//!   replaced ([`R1007_ALLOC_JSON`], `scripts/genesis/r1007/rotate_keys.py`). Producer keys
//!   and stakers stay;
//! * membership grants are **re-issued by script** after genesis (they were
//!   post-genesis transactions on r1006 and are not in block 0; see
//!   `docs/consensus/R1007_GENESIS.md` §4);
//! * the 0.6.0 contracts go into the later ceremony genesis, not here.
//!
//! What differs from r1006 is the genesis note (its own text, at its own address) and
//! the rules block 0 is built under: r1007's block 0 is rooted by the standard MPT state
//! root (CV-14, `citrate_execution::mpt_state_root`, active from 0, block 0 included).
//! The shared genesis function refuses to build this profile with that rule unpublished
//! ([`crate::genesis::initialize_shared_genesis_state`]), so a GUI or light node that
//! forgets the publication fails closed instead of building another block 0.

use crate::genesis::{GenesisAccount, GenesisConfig, GenesisError};
use crate::r1006;
use citrate_execution::types::Address;
use primitive_types::U256;

/// Where the r1007 genesis note lives (same layout as r1006's: a Solidity `string` at
/// slot 0 of an account with no code). `0x000000000000000000000000000000C17A7E1007`:
/// "citrate r1007".
pub const GENESIS_NOTE_ADDRESS: Address = Address([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC1, 0x7A, 0x7E, 0x10, 0x07,
]);

/// The r1007 block-0 message (owner decision 2026-11-09). It is part of the genesis state,
/// so it is part of the genesis hash.
pub const GENESIS_NOTE: &str = "Citrate r1007: rehearsal genesis for chain 40204";

/// The r1007 block-0 timestamp (unix seconds). Stamped at ceremony time by
/// `scripts/genesis/r1007/stamp_genesis.py` (owner 2026-11-11), which re-pins
/// `R1007_GENESIS` with it; the ceremony render refuses a stamp more than 1 h from its run.
/// Until stamped it is the shared canonical timestamp.
pub const GENESIS_TIMESTAMP: u64 = 1794502800;

/// Whether `cfg` is the r1007 genesis: it carries the r1007 note account. Used by the
/// shared genesis function to require the MPT rule for this profile.
pub fn is_r1007_config(cfg: &GenesisConfig) -> bool {
    cfg.accounts
        .iter()
        .any(|a| a.address == GENESIS_NOTE_ADDRESS)
}

/// A non-producer EVM key of the r1006 ceremony that the r1007 ceremony rotates (D-K3,
/// owner 2026-11-10). Public addresses only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotatedKey {
    /// The role, as the r1006 ceremony inputs name it (`inputs.r1006.env`; owner lists
    /// numbered in order).
    pub role: &'static str,
    /// The r1006 address r1007 must not reuse.
    pub r1006_address: [u8; 20],
    /// Where the r1006 block 0 uses it.
    pub r1006_use: &'static str,
}

/// Every non-producer key the r1006 block 0 names: the addresses of
/// `scripts/genesis/r1006/inputs.r1006.env` and the ceremony deployer (bound to those
/// files by `the_rotated_keys_are_every_r1006_non_producer_key`). Producer proposer and
/// staker keys are not here: they stay (owner 2026-11-09, reconfirmed with D-K3).
pub const ROTATED_R1006_KEYS: &[RotatedKey] = &[
    RotatedKey {
        role: "GOV_OWNER_1",
        r1006_address: [0xb4, 0xe1, 0x86, 0xcb, 0xea, 0xb8, 0x8c, 0x82, 0x20, 0xf3, 0xd6, 0x9f, 0x42, 0x63, 0xff, 0xfc, 0xf4, 0xc6, 0xad, 0xa9],
        r1006_use: "GovernanceMultisig owner",
    },
    RotatedKey {
        role: "GOV_OWNER_2",
        r1006_address: [0xa6, 0xbb, 0x94, 0x5b, 0xd7, 0x26, 0x84, 0x95, 0x17, 0x21, 0xff, 0x99, 0xae, 0xcf, 0xdd, 0xb4, 0x8a, 0xe2, 0x2b, 0x8b],
        r1006_use: "GovernanceMultisig owner",
    },
    RotatedKey {
        role: "GOV_OWNER_3",
        r1006_address: [0xe1, 0x54, 0xaf, 0x73, 0xbb, 0x03, 0xbc, 0x60, 0x73, 0xa4, 0xf0, 0x8d, 0x68, 0x68, 0x18, 0x47, 0x74, 0x01, 0x4d, 0xaf],
        r1006_use: "GovernanceMultisig owner",
    },
    RotatedKey {
        role: "GOV_OWNER_4",
        r1006_address: [0x9c, 0x0e, 0xc4, 0x78, 0x95, 0x47, 0x1a, 0x3d, 0xdf, 0x0c, 0xb9, 0x46, 0x13, 0x6a, 0x90, 0x76, 0x01, 0xc7, 0x6c, 0xd8],
        r1006_use: "GovernanceMultisig owner",
    },
    RotatedKey {
        role: "GOV_OWNER_5",
        r1006_address: [0x0f, 0x26, 0xed, 0x94, 0xb5, 0xd7, 0x83, 0x74, 0xd1, 0x79, 0x7b, 0xe0, 0x4f, 0xda, 0xa4, 0xea, 0x2e, 0xa7, 0xcc, 0x47],
        r1006_use: "GovernanceMultisig owner",
    },
    RotatedKey {
        role: "GRD_OWNER_1",
        r1006_address: [0xcc, 0x9e, 0xe1, 0xf2, 0xc1, 0x1c, 0x53, 0xe2, 0xb9, 0xc3, 0x0c, 0x61, 0x84, 0x8e, 0xe5, 0x0f, 0x12, 0xa6, 0x90, 0xdc],
        r1006_use: "GuardianMultisig owner",
    },
    RotatedKey {
        role: "GRD_OWNER_2",
        r1006_address: [0x1b, 0x0c, 0x84, 0xe4, 0x57, 0x60, 0x5a, 0x06, 0x5b, 0xeb, 0x0b, 0x23, 0x06, 0xef, 0xa0, 0xfb, 0x54, 0xb3, 0x3e, 0x8a],
        r1006_use: "GuardianMultisig owner",
    },
    RotatedKey {
        role: "GRD_OWNER_3",
        r1006_address: [0x85, 0x47, 0xd4, 0x7d, 0x14, 0x48, 0x77, 0xa7, 0x5d, 0xe0, 0x09, 0x7d, 0x5e, 0x35, 0xda, 0x8a, 0x35, 0x5c, 0x8e, 0x3f],
        r1006_use: "GuardianMultisig owner",
    },
    RotatedKey {
        role: "MEMBERSHIP_GRANTOR",
        r1006_address: [0x57, 0xb0, 0x6e, 0x5d, 0xe4, 0x28, 0x1c, 0xfa, 0x4d, 0xfb, 0xac, 0x67, 0x27, 0x26, 0x2c, 0x44, 0x3a, 0x24, 0xba, 0x2a],
        r1006_use: "CitrateMemberSBT and MembershipStakeVault grantor",
    },
    RotatedKey {
        role: "SIGNER_1",
        r1006_address: [0xc0, 0x90, 0x7b, 0xee, 0x2b, 0x30, 0xd0, 0xf0, 0x9e, 0xc9, 0x21, 0xb7, 0xf3, 0x9c, 0x7a, 0x06, 0x5e, 0xd9, 0xb6, 0x41],
        r1006_use: "InstitutionalVault signer",
    },
    RotatedKey {
        role: "SIGNER_2",
        r1006_address: [0x5c, 0xcd, 0x30, 0xc2, 0x45, 0x78, 0x74, 0xce, 0x5a, 0x72, 0xd4, 0x2b, 0xe4, 0xb3, 0xeb, 0xf8, 0xbf, 0x1e, 0xe0, 0x93],
        r1006_use: "InstitutionalVault signer",
    },
    RotatedKey {
        role: "SIGNER_3",
        r1006_address: [0x7d, 0xcc, 0x55, 0xd9, 0x92, 0x8e, 0xa5, 0x31, 0x65, 0x8c, 0x5a, 0x2d, 0x4f, 0x78, 0x78, 0x41, 0x9a, 0xb8, 0xf9, 0x8b],
        r1006_use: "InstitutionalVault signer",
    },
    RotatedKey {
        role: "RELAYER",
        r1006_address: [0x6c, 0x91, 0xdd, 0x6b, 0xb4, 0xb5, 0x61, 0xd6, 0xa0, 0xe0, 0x58, 0x41, 0x94, 0x68, 0xd5, 0x47, 0xc4, 0x91, 0x63, 0x4f],
        r1006_use: "EIP-2771 relayer",
    },
    RotatedKey {
        role: "CITRATE_AA_OWNER",
        r1006_address: [0xc0, 0xad, 0x05, 0x54, 0x23, 0x5a, 0xf5, 0xff, 0xf6, 0x78, 0x82, 0xd8, 0x41, 0x22, 0x16, 0x35, 0xda, 0xda, 0x9e, 0x74],
        r1006_use: "CitratePaymaster and CitrateWalletFactory owner",
    },
    RotatedKey {
        role: "CITRATE_AA_IDENTITY_SIGNER",
        r1006_address: [0x59, 0xf4, 0x88, 0xdc, 0xf0, 0x67, 0x79, 0xfd, 0x93, 0x36, 0x18, 0x3d, 0xdd, 0xc6, 0x47, 0x1f, 0x8b, 0x3d, 0xad, 0x6c],
        r1006_use: "CitrateWalletFactory identity signer",
    },
    RotatedKey {
        role: "CITRATE_AA_SPONSOR_SIGNER",
        r1006_address: [0x07, 0xed, 0x64, 0x45, 0xf3, 0x6b, 0xb0, 0xa5, 0xc4, 0xef, 0x51, 0x21, 0x8a, 0xe7, 0x90, 0xdd, 0xf4, 0x83, 0xca, 0xf0],
        r1006_use: "CitratePaymaster sponsor signer",
    },
    RotatedKey {
        role: "TREASURY",
        r1006_address: [0xeb, 0x60, 0x82, 0xdb, 0x09, 0xc5, 0x38, 0x34, 0x89, 0xa0, 0xb7, 0x50, 0x57, 0xc7, 0x39, 0x81, 0x8b, 0xf3, 0x34, 0x40],
        r1006_use: "base allocation; fee recipient of X402Facilitator, ComputeMarketplace, ModelMarketplace",
    },
    RotatedKey {
        role: "FAUCET",
        r1006_address: [0xd7, 0x5b, 0x8b, 0x37, 0x76, 0x53, 0x2e, 0xa3, 0x8f, 0x76, 0x83, 0xfd, 0xdd, 0xc9, 0x44, 0x01, 0xd0, 0x71, 0x9b, 0x59],
        r1006_use: "base allocation",
    },
    RotatedKey {
        role: "TEAM",
        r1006_address: [0x75, 0xd5, 0xb9, 0x6c, 0xa2, 0xa4, 0x07, 0xc0, 0x92, 0xc6, 0xb6, 0xcc, 0x11, 0x8b, 0x72, 0x71, 0x0a, 0x0e, 0xf5, 0x6c],
        r1006_use: "base allocation; TeamVesting beneficiary",
    },
    RotatedKey {
        role: "DEPLOYER",
        r1006_address: [0xe4, 0x03, 0x25, 0xba, 0x1f, 0x4c, 0xf3, 0x62, 0xb2, 0x03, 0xd9, 0xfe, 0x2b, 0x81, 0x60, 0x31, 0x2e, 0x92, 0x6c, 0x11],
        r1006_use: "the ceremony deployer account (nonce 92)",
    },
];

/// What a rotated key is found as in a genesis layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// The account itself (its balance or nonce).
    Account,
    /// A storage word of `account` holds the address.
    StorageWord,
}

/// One plain occurrence of a rotated key in a genesis layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLocation {
    pub role: &'static str,
    /// The account holding it (the key's own account for [`KeyUse::Account`]).
    pub account: [u8; 20],
    pub kind: KeyUse,
}

/// The plain occurrences of every [`ROTATED_R1006_KEYS`] entry in `cfg`: an account at
/// the key's address, or a storage word that holds the address at any byte offset (a
/// packed slot included). A key held only under a hashed mapping slot is not visible to
/// this scan, so it is a check on a layout, not a proof that a layout is clean.
pub fn rotated_key_locations(cfg: &GenesisConfig) -> Vec<KeyLocation> {
    let mut out = Vec::new();
    for k in ROTATED_R1006_KEYS {
        for a in &cfg.accounts {
            if a.address.0 == k.r1006_address {
                out.push(KeyLocation {
                    role: k.role,
                    account: a.address.0,
                    kind: KeyUse::Account,
                });
            }
            if a.storage
                .iter()
                .any(|(_, v)| v.windows(20).any(|w| w == k.r1006_address))
            {
                out.push(KeyLocation {
                    role: k.role,
                    account: a.address.0,
                    kind: KeyUse::StorageWord,
                });
            }
        }
    }
    out
}

/// The r1007 ceremony allocation (D-K3, keys generated 2026-11-11): the r1006 block-0
/// state with every rotated role key replaced by its fresh r1007 key, built by
/// `scripts/genesis/r1007/rotate_keys.py` from `inputs.r1007.env` (public addresses).
pub const R1007_ALLOC_JSON: &str = include_str!("../assets/r1007/alloc.json");

/// The fresh r1007 role keys, as `(role, address)` in file order: the public inputs the
/// r1007 alloc was built from (`scripts/genesis/r1007/inputs.r1007.env`).
pub const R1007_INPUTS_ENV: &str = include_str!("../../../scripts/genesis/r1007/inputs.r1007.env");

/// [`R1007_INPUTS_ENV`] parsed: one `(role, address)` per ROTATED_R1006_KEYS role.
pub fn r1007_role_keys() -> Result<Vec<(String, [u8; 20])>, GenesisError> {
    let mut out = Vec::new();
    for line in R1007_INPUTS_ENV.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k == "R1007_INPUTS_STATUS" {
            if v != "final" {
                return Err(GenesisError::Invalid(format!(
                    "inputs.r1007.env: R1007_INPUTS_STATUS is {v}, not final"
                )));
            }
            continue;
        }
        let bytes = hex::decode(v.trim_start_matches("0x"))
            .map_err(|e| GenesisError::Invalid(format!("inputs.r1007.env {k}: {e}")))?;
        let addr: [u8; 20] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| GenesisError::Invalid(format!("inputs.r1007.env {k}: not 20 bytes")))?;
        out.push((k.to_string(), addr));
    }
    Ok(out)
}

/// What the compiled r1007 genesis still waits for: read from the r1007 alloc (its inputs
/// status and OrangeSeed record) and the shared producer set.
pub fn readiness() -> Result<r1006::Readiness, GenesisError> {
    r1006::readiness_of(R1007_ALLOC_JSON, "r1007")
}

/// The ValidatorRegistry the r1007 genesis registers its producers in, and the
/// activation height of the stake-gated producer set: the r1006 ones, since block 0
/// holds the same registry state (`None` while the producer set is a placeholder).
pub fn validator_set_binding() -> Result<Option<([u8; 20], u64)>, GenesisError> {
    r1006::validator_set_binding_of(R1007_ALLOC_JSON, "r1007")
}

impl GenesisConfig {
    /// The r1007 genesis configuration (chain 40204): the r1007 ceremony allocation
    /// ([`R1007_ALLOC_JSON`], the r1006 block-0 state with the D-K3 fresh role keys), the
    /// shared producer set, and the r1007 note in place of the r1006 note. Fail closed: it
    /// refuses if any rotated r1006 key is still named ([`rotated_key_locations`]).
    pub fn r1007() -> Result<Self, GenesisError> {
        let cfg = with_r1007_note(r1006::config_from_alloc(R1007_ALLOC_JSON, "r1007")?)?;
        let found = rotated_key_locations(&cfg);
        if !found.is_empty() {
            let roles: Vec<&str> = found.iter().map(|l| l.role).collect();
            return Err(GenesisError::Invalid(format!(
                "r1007: the r1007 alloc still names rotated r1006 keys (D-K3): {}",
                roles.join(", ")
            )));
        }
        Ok(cfg)
    }
}

/// The r1007 layout over r1006's role keys: the r1006 genesis configuration with the
/// r1006 note replaced by the r1007 note. Balances, nonces, code and storage of every
/// other account are r1006's byte for byte, and the supply split is unchanged (the note
/// holds no balance). **Never a node genesis** under D-K3: it names the rotated r1006
/// keys ([`rotated_key_locations`]). It is the pre-D-K3 candidate whose hash is
/// `R1007_GENESIS` today, kept so the genesis-keyed tables stay testable and so the
/// fresh-keys alloc can be diffed against it.
pub fn candidate_layout_with_r1006_role_keys() -> Result<GenesisConfig, GenesisError> {
    with_r1007_note(GenesisConfig::r1006()?)
}

/// `base` with the r1006 note replaced by the r1007 note (balances, nonces, code and
/// storage of every other account unchanged; the note holds no balance).
fn with_r1007_note(base: GenesisConfig) -> Result<GenesisConfig, GenesisError> {
    let mut accounts: Vec<GenesisAccount> = base
        .accounts
        .into_iter()
        .filter(|a| a.address != r1006::GENESIS_NOTE_ADDRESS)
        .collect();
    if accounts.iter().any(|a| a.address == GENESIS_NOTE_ADDRESS) {
        return Err(GenesisError::Invalid(
            "r1007: the r1006 state already holds an account at the r1007 note address".into(),
        ));
    }
    accounts.push(GenesisAccount {
        address: GENESIS_NOTE_ADDRESS,
        balance: U256::zero(),
        nonce: 1,
        code: None,
        storage: r1006::solidity_string_slots(GENESIS_NOTE),
    });
    let cfg = GenesisConfig { accounts, ..base };
    cfg.validate()?;
    Ok(cfg)
}

/// Block 0's hash for the r1007 configuration, built exactly as a node builds it. The
/// MPT rule must be published (active from 0) first; otherwise this fails closed.
pub fn genesis_block_hash(cfg: &GenesisConfig) -> Result<[u8; 32], GenesisError> {
    genesis_block_hash_at(cfg, GENESIS_TIMESTAMP)
}

/// Block 0's hash for `cfg` stamped `timestamp` (what [`GENESIS_TIMESTAMP`] would give).
pub fn genesis_block_hash_at(
    cfg: &GenesisConfig,
    timestamp: u64,
) -> Result<[u8; 32], GenesisError> {
    Ok(*r1006::genesis_block_at(cfg, timestamp)?
        .header
        .block_hash
        .as_bytes())
}

/// Block 0 for `cfg` at [`GENESIS_TIMESTAMP`], as a node builds it (the MPT rule must be
/// published first).
pub fn genesis_block(cfg: &GenesisConfig) -> Result<citrate_consensus::types::Block, GenesisError> {
    r1006::genesis_block_at(cfg, GENESIS_TIMESTAMP)
}

/// The ceremony step that first computes `R1007_GENESIS` (STATE_ROOT_MPT.md §1 step 3):
/// the MPT rule on from 0 for this process, then the shared genesis function. Used by
/// `examples/r1007_genesis_hash.rs`; never called by a node, which publishes the rule
/// through the genesis-keyed table for the block 0 it builds. Refuses while
/// [`GenesisConfig::r1007`] is pending (D-K3).
pub fn compute_genesis_hash_for_ceremony() -> Result<[u8; 32], GenesisError> {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
    genesis_block_hash(&GenesisConfig::r1007()?)
}
