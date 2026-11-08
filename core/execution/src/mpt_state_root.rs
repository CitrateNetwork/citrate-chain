// citrate/core/execution/src/mpt_state_root.rs
//
// The activation height of the standard MPT state root (ADR-2026-11-03 CV-14
// (a)+(b), accepted 2026-11-07 as an r1007 genesis rule).
//
// WHAT SWITCHES ON
//
// For the post-state of a block at and after this height the state root is the
// root of a standard Ethereum secure Merkle Patricia Trie
// (`crate::state::mpt`, encoding rules in `crate::state::mpt_state`):
//
//   * accounts keyed by keccak256(address), storage slots by keccak256(slot key);
//   * a child node whose RLP is 32 bytes or longer is referenced by its keccak
//     hash, a shorter one is embedded (Yellow Paper appendix D);
//   * the root is computed incrementally: only the paths a block changed are
//     re-hashed. It stays a pure function of the state (the same state gives
//     the same root whatever was cached), and the from-scratch builder
//     (`StateDB::reference_state_root`) is the test and replay reference.
//
// This changes every root value, so it is a genesis rule: r1005 and r1006 never
// get it (their geneses have no height for it), and the r1007 genesis entry in
// `citrate_consensus::hardening::GENESIS_ACTIVATIONS` sets it to 0.
//
// Below the height nothing changes: the legacy root (`Trie::legacy_root_hash`,
// rebuilt from scratch every block) is reproduced byte for byte.
//
// RELEASE DEFAULT
//
//   * A release genesis with an entry in the shared table: that entry's height
//     (r1006: unset). A per-node env or config value must agree with it.
//   * Chain 40204 on a release genesis without an entry (r1005), or with no
//     genesis known yet: unset, and a per-node height is REFUSED.
//   * Any other genesis (devnets, rehearsals, tests): unset unless
//     `[chain] mpt_state_root_height` or `CITRATE_MPT_STATE_ROOT_HEIGHT` sets it.
//     `0` activates it for every block after genesis.
//   * Genesis (height 0) is never re-judged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release genesis.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different values
/// compute different state roots from the first block at the height.
pub const MPT_STATE_ROOT_ENV: &str = "CITRATE_MPT_STATE_ROOT_HEIGHT";

const UNSET: u64 = u64::MAX;

static MPT_STATE_ROOT_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the process-wide activation height. `None` = not activated.
pub fn set_mpt_state_root_height(height: Option<u64>) {
    MPT_STATE_ROOT_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn mpt_state_root_height() -> Option<u64> {
    match MPT_STATE_ROOT_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Whether the rule applies to the post-state of a block at `height` under
/// `activation` (pure). Genesis is never re-judged; the boundary is inclusive.
pub fn active_at(activation: Option<u64>, height: u64) -> bool {
    match activation {
        Some(a) => height > 0 && height >= a,
        None => false,
    }
}

/// Whether the rule applies to the post-state of a block at `height` on this
/// node.
pub fn mpt_state_root_active(height: u64) -> bool {
    active_at(mpt_state_root_height(), height)
}

/// The schedule for this rule on `chain_id` with block 0 `genesis`, from the
/// shared (chain id, genesis hash) table.
pub fn pin_for_genesis(chain_id: u64, genesis: Option<&[u8; 32]>) -> Option<Option<u64>> {
    citrate_consensus::hardening::genesis_rule_pin(chain_id, genesis, |a| a.mpt_state_root)
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptStateRootSource {
    ReleasePin,
    Env,
    Config,
    Unset,
}

impl std::fmt::Display for MptStateRootSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_MPT_STATE_ROOT_HEIGHT",
            Self::Config => "config [chain] mpt_state_root_height",
            Self::Unset => "unset",
        })
    }
}

/// Parse an env/config override. `Ok(None)` = explicitly off.
pub fn parse_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{MPT_STATE_ROOT_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{MPT_STATE_ROOT_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Resolve the height from its inputs (pure). The same rules as every other
/// genesis-keyed activation (`crate::storage_root_hardening::resolve`).
pub fn resolve(
    pin: Option<Option<u64>>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, MptStateRootSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{MPT_STATE_ROOT_ENV} conflicts with the MPT state root height {p} \
                         pinned in this release for this genesis. Remove the override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] mpt_state_root_height = {c} conflicts with the height {p} \
                         pinned in this release for this genesis. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), MptStateRootSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{MPT_STATE_ROOT_ENV}={h}: the MPT state root is not scheduled for this \
                     release network. A per-node height would fork this node."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] mpt_state_root_height = {c}: the MPT state root is not scheduled \
                     for this release network. Remove the setting."
                ));
            }
            Ok((None, MptStateRootSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, MptStateRootSource::Env)),
            (None, Some(c)) => Ok((Some(c), MptStateRootSource::Config)),
            (None, None) => Ok((None, MptStateRootSource::Unset)),
        },
    }
}

/// `resolve` with the genesis-keyed schedule and the process env.
pub fn resolve_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, MptStateRootSource), String> {
    let env_raw = match std::env::var(MPT_STATE_ROOT_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{MPT_STATE_ROOT_ENV}: {e}")),
    };
    resolve(
        pin_for_genesis(chain_id, genesis),
        env_raw.as_deref(),
        config_value,
    )
}

/// Resolve and publish process-wide. The node calls this once at start-up,
/// after it knows its block 0 and before any state root is computed.
pub fn init_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, MptStateRootSource), String> {
    let r = resolve_for_genesis(chain_id, genesis, config_value)?;
    set_mpt_state_root_height(r.0);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::hardening::{R1006_GENESIS, RELEASE_GENESIS};

    /// r1005 and r1006 never get the rule (it changes every root); an unknown
    /// genesis (a devnet, the r1007 rehearsal before its entry exists) is local.
    #[test]
    fn release_geneses_never_get_it_unknown_genesis_is_local() {
        assert_eq!(pin_for_genesis(40204, Some(&R1006_GENESIS)), Some(None));
        assert_eq!(
            pin_for_genesis(40204, Some(&RELEASE_GENESIS[0].1)),
            Some(None)
        );
        assert!(resolve(
            pin_for_genesis(40204, Some(&R1006_GENESIS)),
            Some("0"),
            None
        )
        .is_err());
        assert!(resolve(pin_for_genesis(40204, Some(&R1006_GENESIS)), None, Some(0)).is_err());
        assert_eq!(pin_for_genesis(40204, Some(&[0x42; 32])), None);
        assert_eq!(
            resolve(None, None, Some(0)),
            Ok((Some(0), MptStateRootSource::Config))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(0)),
            Ok((None, MptStateRootSource::Env))
        );
        assert!(resolve(None, Some("soon"), None).is_err());
    }

    #[test]
    fn genesis_is_never_rejudged_and_the_boundary_is_inclusive() {
        assert!(!active_at(None, 1));
        assert!(!active_at(Some(0), 0));
        assert!(active_at(Some(0), 1));
        assert!(!active_at(Some(10), 9));
        assert!(active_at(Some(10), 10));
    }
}
