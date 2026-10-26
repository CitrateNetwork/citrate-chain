// citrate/core/execution/src/storage_root_hardening.rs
//
// The activation height of the storage-root hardening fork.
//
// WHAT SWITCHES ON
//
// For the post-state of a block at and after this height:
//
//   * A contract's `storage_root` is a function of its final slot set only. It
//     no longer depends on the order of the writes and deletes that produced
//     that set, so a node that executed a slot delete and a node that rebuilt
//     the same slots on restart fold the same state root.
//   * Restart hydration returns every persisted storage record with its exact
//     key and value bytes. Below the height a restarted node keeps the legacy
//     view (32-byte keys only, values padded or truncated to 32 bytes).
//
// Below the height nothing changes, so every historical block replays to the
// root it was produced with.
//
// RELEASE DEFAULT: NOT SCHEDULED ON 40204
//
//   * Chain 40204: the release pin is `None` (release network, not scheduled).
//     An upgraded binary changes nothing on 40204 by itself. A per-node env or
//     config height is REFUSED there; the owner schedules the fork by setting
//     the pin in a release (a future height, or `Some(0)` with a new genesis).
//   * Any other chain (local devnets, test chains, a new genesis): unset unless
//     `[chain] storage_root_hardening_height` or
//     `CITRATE_STORAGE_ROOT_HARDENING_HEIGHT` sets it. `0` activates it for
//     every block after genesis.
//   * Genesis (height 0) is never re-judged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release chain.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different values
/// compute different state roots once a storage slot has been deleted.
pub const STORAGE_ROOT_HARDENING_ENV: &str = "CITRATE_STORAGE_ROOT_HARDENING_HEIGHT";


const UNSET: u64 = u64::MAX;

static STORAGE_ROOT_HARDENING_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the process-wide activation height. `None` = not activated.
pub fn set_storage_root_hardening_height(height: Option<u64>) {
    STORAGE_ROOT_HARDENING_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn storage_root_hardening_height() -> Option<u64> {
    match STORAGE_ROOT_HARDENING_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Whether the fork applies to the post-state of a block at `height` under
/// `activation` (pure). Genesis is never re-judged; the boundary is inclusive.
pub fn active_at(activation: Option<u64>, height: u64) -> bool {
    match activation {
        Some(a) => height > 0 && height >= a,
        None => false,
    }
}

/// Whether the fork applies to the post-state of a block at `height` on this
/// node.
pub fn storage_root_hardening_active(height: u64) -> bool {
    active_at(storage_root_hardening_height(), height)
}

/// The schedule for this rule on `chain_id` with block 0 `genesis`, from the shared
/// (chain id, genesis hash) table (`citrate_consensus::hardening::genesis_rule_pin`). There is no
/// per-chain pin table for this rule (scripts/ci/genesis_keyed_pins_tripwire.sh).
pub fn pin_for_genesis(chain_id: u64, genesis: Option<&[u8; 32]>) -> Option<Option<u64>> {
    citrate_consensus::hardening::genesis_rule_pin(chain_id, genesis, |a| a.storage_root_hardening)
}

/// Parse an env/config override. `Ok(None)` = explicitly off.
pub fn parse_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{STORAGE_ROOT_HARDENING_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{STORAGE_ROOT_HARDENING_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRootHardeningSource {
    /// Compiled into this release for the running chain id.
    ReleasePin,
    /// `CITRATE_STORAGE_ROOT_HARDENING_HEIGHT`.
    Env,
    /// `[chain] storage_root_hardening_height`.
    Config,
    /// Nothing set: not activated.
    Unset,
}

impl std::fmt::Display for StorageRootHardeningSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_STORAGE_ROOT_HARDENING_HEIGHT",
            Self::Config => "config [chain] storage_root_hardening_height",
            Self::Unset => "unset",
        })
    }
}

/// Resolve the height from its inputs. Pure: the caller supplies the pin
/// lookup result, the raw env value and the config value.
///
/// * Release network with a pinned height: the pin wins; an env or config
///   value is allowed only when it equals the pin.
/// * Release network with no pinned height: not activated, and any env or
///   config height is an error (`off` is accepted).
/// * Any other chain: env override, then config, then unset. An unparseable
///   env value is an error, never ignored.
pub fn resolve(
    pin: Option<Option<u64>>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, StorageRootHardeningSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{STORAGE_ROOT_HARDENING_ENV} conflicts with the storage root hardening \
                         fork height {p} pinned in this release for this chain. Remove the \
                         override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] storage_root_hardening_height = {c} conflicts with the height \
                         {p} pinned in this release for this chain. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), StorageRootHardeningSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{STORAGE_ROOT_HARDENING_ENV}={h}: the storage root hardening fork is not \
                     scheduled for this release network. A per-node height would fork this \
                     node; the height is set only by a release pin."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] storage_root_hardening_height = {c}: the storage root hardening \
                     fork is not scheduled for this release network. Remove the setting."
                ));
            }
            Ok((None, StorageRootHardeningSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, StorageRootHardeningSource::Env)),
            (None, Some(c)) => Ok((Some(c), StorageRootHardeningSource::Config)),
            (None, None) => Ok((None, StorageRootHardeningSource::Unset)),
        },
    }
}

/// `resolve` with the genesis-keyed schedule and the process env.
pub fn resolve_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, StorageRootHardeningSource), String> {
    let env_raw = match std::env::var(STORAGE_ROOT_HARDENING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{STORAGE_ROOT_HARDENING_ENV}: {e}")),
    };
    resolve(pin_for_genesis(chain_id, genesis), env_raw.as_deref(), config_value)
}

/// Resolve and publish process-wide. The node calls this once at start-up, after it
/// knows its block 0 and before any component that captures the height exists.
pub fn init_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, StorageRootHardeningSource), String> {
    let r = resolve_for_genesis(chain_id, genesis, config_value)?;
    set_storage_root_hardening_height(r.0);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// r1006's genesis schedules the rule from block 1 in the shared table; r1005's
    /// genesis keeps it unset and refuses a per-node height; an unknown genesis is local.
    #[test]
    fn genesis_keyed_schedule_r1006_zero_r1005_unset_unknown_local() {
        use citrate_consensus::hardening::{R1006_GENESIS, RELEASE_GENESIS};
        assert_eq!(pin_for_genesis(40204, Some(&R1006_GENESIS)), Some(Some(0)));
        assert_eq!(pin_for_genesis(40204, Some(&RELEASE_GENESIS[0].1)), Some(None));
        assert!(resolve(pin_for_genesis(40204, Some(&RELEASE_GENESIS[0].1)), None, Some(0)).is_err());
        assert_eq!(pin_for_genesis(40204, Some(&[0x42; 32])), None);
    }

    #[test]
    fn unset_never_activates_and_genesis_is_never_rejudged() {
        assert!(!active_at(None, 1));
        assert!(!active_at(None, u64::MAX));
        assert!(!active_at(Some(0), 0), "genesis is never re-judged");
        assert!(active_at(Some(0), 1));
        assert!(!active_at(Some(100), 99));
        assert!(active_at(Some(100), 100), "the boundary is inclusive");
        assert!(active_at(Some(100), 101));
    }

    #[test]
    fn chain_40204_ships_unscheduled_and_refuses_per_node_heights() {
        assert_eq!(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), Some(None));
        assert_eq!(pin_for_genesis(1337, None), None, "devnet is not a release network");
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), None, None),
            Ok((None, StorageRootHardeningSource::Unset))
        );
        assert!(resolve(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), Some("100"), None).is_err());
        assert!(resolve(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), Some("0"), None).is_err());
        assert!(resolve(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), None, Some(0)).is_err());
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&citrate_consensus::hardening::RELEASE_GENESIS[0].1)), Some("off"), None),
            Ok((None, StorageRootHardeningSource::Unset))
        );
    }

    #[test]
    fn release_pin_wins_and_disagreeing_values_refuse_to_start() {
        let pin = Some(Some(0));
        assert_eq!(
            resolve(pin, None, None),
            Ok((Some(0), StorageRootHardeningSource::ReleasePin))
        );
        assert_eq!(
            resolve(pin, Some("0"), Some(0)),
            Ok((Some(0), StorageRootHardeningSource::ReleasePin))
        );
        assert!(resolve(pin, Some("1"), None).is_err());
        assert!(resolve(pin, Some("off"), None).is_err());
        assert!(resolve(pin, None, Some(5)).is_err());
    }

    #[test]
    fn new_genesis_resolution_order() {
        assert_eq!(
            resolve(None, None, None),
            Ok((None, StorageRootHardeningSource::Unset))
        );
        assert_eq!(
            resolve(None, None, Some(0)),
            Ok((Some(0), StorageRootHardeningSource::Config)),
            "a new genesis activates from block 1 with 0"
        );
        assert_eq!(
            resolve(None, Some("9"), Some(0)),
            Ok((Some(9), StorageRootHardeningSource::Env))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(0)),
            Ok((None, StorageRootHardeningSource::Env))
        );
        assert!(resolve(None, Some("soon"), None).is_err());
        assert!(resolve(None, Some("18446744073709551615"), None).is_err());
    }
}
