//! The `r1007` genesis profile: the r1006 ceremony state, a new block 0 (S3-6).
//!
//! Owner decisions (ADR-2026-11-03 Q-1, Q-3; 2026-11-03 and 2026-11-07):
//! * r1007 is a new-genesis **rehearsal** of chain 40204 (not the ceremony genesis);
//! * from the **same validator set** and the same producer keys (owner 2026-11-09), with **today's contract set**: block 0 holds
//!   exactly the r1006 block-0 state (`assets/r1006/alloc.json` and
//!   `assets/r1006/validators.json`, read in place: one source of truth, Rule 9), so
//!   every block-0 contract address, the membership SBT and vault included, is the
//!   same as on r1006;
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

/// Whether `cfg` is the r1007 genesis: it carries the r1007 note account. Used by the
/// shared genesis function to require the MPT rule for this profile.
pub fn is_r1007_config(cfg: &GenesisConfig) -> bool {
    cfg.accounts
        .iter()
        .any(|a| a.address == GENESIS_NOTE_ADDRESS)
}

/// What the compiled r1007 genesis still waits for: the r1006 ceremony inputs, producer
/// set and OrangeSeed artifacts it is built from.
pub fn readiness() -> Result<r1006::Readiness, GenesisError> {
    r1006::readiness()
}

/// The ValidatorRegistry the r1007 genesis registers its producers in, and the
/// activation height of the stake-gated producer set: the r1006 ones, since block 0
/// holds the same registry state (`None` while the producer set is a placeholder).
pub fn validator_set_binding() -> Result<Option<([u8; 20], u64)>, GenesisError> {
    r1006::validator_set_binding()
}

impl GenesisConfig {
    /// The r1007 genesis configuration (chain 40204): the r1006 genesis configuration
    /// with the r1006 note replaced by the r1007 note. Balances, nonces, code and
    /// storage of every other account are r1006's byte for byte, and the supply split
    /// is unchanged (the note holds no balance).
    pub fn r1007() -> Result<Self, GenesisError> {
        let base = GenesisConfig::r1006()?;
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
}

/// Block 0's hash for the r1007 configuration, built exactly as a node builds it. The
/// MPT rule must be published (active from 0) first; otherwise this fails closed.
pub fn genesis_block_hash(cfg: &GenesisConfig) -> Result<[u8; 32], GenesisError> {
    r1006::genesis_block_hash(cfg)
}

/// The ceremony step that first computes `R1007_GENESIS` (STATE_ROOT_MPT.md §1 step 3):
/// the MPT rule on from 0 for this process, then the shared genesis function. Used by
/// `examples/r1007_genesis_hash.rs`; never called by a node, which publishes the rule
/// through the genesis-keyed table for the block 0 it builds.
pub fn compute_genesis_hash_for_ceremony() -> Result<[u8; 32], GenesisError> {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
    genesis_block_hash(&GenesisConfig::r1007()?)
}
