// citrate/core/execution/src/supply_hardening.rs
//
// The activation height of the supply-accounting hardening fork.
//
// WHAT SWITCHES ON
//
// At and after this height two state-transition rules change:
//
//   * Model-access fees (`AccessPolicy::PayPerUse`) and the inference provider
//     fee move value through the per-transaction journal, like every other
//     value movement in the executor. The payer debit and the owner, treasury
//     and provider credits then commit together on success and are discarded
//     together when the transaction reverts.
//   * The block reward's bonus arms are computed from the block's EXECUTED
//     results (its receipts), not from calldata: only a transaction that
//     executed successfully as the qualifying operation counts. Every bonus
//     arm follows the base subsidy's halving schedule, and the combined bonus
//     is capped at the base subsidy for the height.
//
// Below the height nothing changes, so every historical block replays to the
// root it was produced with.
//
// WHY A SEPARATE HEIGHT
//
// Both rules change balances that a live chain has already committed under
// the old rules. They switch on together, at one height every node agrees on.
// One store, here, for this one fork: nothing else may keep a second copy (two
// stores can disagree, and a node whose stores disagree forks at the height).
//
// RELEASE DEFAULT: NOT SCHEDULED ON 40204
//
//   * Chain 40204: the release pin is `None` (release network, not scheduled).
//     An upgraded binary changes nothing on 40204 by itself. A per-node env or
//     config height is REFUSED there; the owner schedules the fork by setting
//     the pin in a release (a future height, or `Some(0)` for a reroll).
//   * Any other chain (local devnets, test chains): unset unless
//     `[chain] supply_hardening_height` or `CITRATE_SUPPLY_HARDENING_HEIGHT`
//     sets it.
//   * Genesis (height 0) is never re-judged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release chain.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different values
/// disagree about fee settlement, in-tx writes and block rewards from the
/// height on.
pub const SUPPLY_HARDENING_ENV: &str = "CITRATE_SUPPLY_HARDENING_HEIGHT";

/// Activation heights compiled into this release, per release chain id.
///
/// 40204: `None`, a release network with no height scheduled. OWNER STEP
/// (release PR): replace `None` with `Some(H)` for the height agreed for the
/// fleet, or `Some(0)` when the fork ships with a reroll's new genesis.
pub const SUPPLY_HARDENING_PINS: &[(u64, Option<u64>)] = &[(40204, None)];

const UNSET: u64 = u64::MAX;

static SUPPLY_HARDENING_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the process-wide activation height. `None` = not activated.
pub fn set_supply_hardening_height(height: Option<u64>) {
    SUPPLY_HARDENING_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn supply_hardening_height() -> Option<u64> {
    match SUPPLY_HARDENING_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Whether the fork applies to a block at `height` under `activation` (pure).
/// Genesis is never re-judged; the boundary is inclusive.
pub fn active_at(activation: Option<u64>, height: u64) -> bool {
    match activation {
        Some(a) => height > 0 && height >= a,
        None => false,
    }
}

/// Whether the fork applies to a block at `height` on this node.
pub fn supply_hardening_active(height: u64) -> bool {
    active_at(supply_hardening_height(), height)
}

/// The pinned height for `chain_id`: `None` when the chain is not a release
/// network, `Some(None)` when it is one with no height scheduled.
pub fn pinned_for(chain_id: u64) -> Option<Option<u64>> {
    SUPPLY_HARDENING_PINS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, h)| *h)
}

/// Parse an env/config override. `Ok(None)` = explicitly off.
pub fn parse_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{SUPPLY_HARDENING_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{SUPPLY_HARDENING_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyHardeningSource {
    /// Compiled into this release for the running chain id.
    ReleasePin,
    /// `CITRATE_SUPPLY_HARDENING_HEIGHT`.
    Env,
    /// `[chain] supply_hardening_height`.
    Config,
    /// Nothing set: not activated.
    Unset,
}

impl std::fmt::Display for SupplyHardeningSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_SUPPLY_HARDENING_HEIGHT",
            Self::Config => "config [chain] supply_hardening_height",
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
///   config height is an error (`off` is accepted). A node must not schedule a
///   fork on a release network by itself.
/// * Any other chain: env override, then config, then unset. An unparseable
///   env value is an error, never ignored.
pub fn resolve(
    pin: Option<Option<u64>>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, SupplyHardeningSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{SUPPLY_HARDENING_ENV} conflicts with the supply hardening fork height \
                         {p} pinned in this release for this chain. Remove the override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] supply_hardening_height = {c} conflicts with the height {p} \
                         pinned in this release for this chain. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), SupplyHardeningSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{SUPPLY_HARDENING_ENV}={h}: the supply hardening fork is not scheduled \
                     for this release network. A per-node height would fork this node; the \
                     height is set only by a release pin."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] supply_hardening_height = {c}: the supply hardening fork is not \
                     scheduled for this release network. Remove the setting."
                ));
            }
            Ok((None, SupplyHardeningSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, SupplyHardeningSource::Env)),
            (None, Some(c)) => Ok((Some(c), SupplyHardeningSource::Config)),
            (None, None) => Ok((None, SupplyHardeningSource::Unset)),
        },
    }
}

/// Resolve for the running chain (release pin, env override, config value)
/// without publishing.
pub fn resolve_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, SupplyHardeningSource), String> {
    let env_raw = match std::env::var(SUPPLY_HARDENING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{SUPPLY_HARDENING_ENV}: {e}")),
    };
    resolve(pinned_for(chain_id), env_raw.as_deref(), config_value)
}

/// Resolve for the running chain and publish process-wide. The node calls this
/// once at start-up, before constructing any execution component.
pub fn init_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, SupplyHardeningSource), String> {
    let r = resolve_for_chain(chain_id, config_value)?;
    set_supply_hardening_height(r.0);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            pinned_for(40204),
            Some(None),
            "40204 is a release network with no height scheduled"
        );
        assert_eq!(pinned_for(1337), None, "devnet is not a release network");
        assert_eq!(
            resolve(pinned_for(40204), None, None),
            Ok((None, SupplyHardeningSource::Unset))
        );
        // A per-node height on 40204 would fork that node: refused.
        assert!(resolve(pinned_for(40204), Some("100"), None).is_err());
        assert!(resolve(pinned_for(40204), None, Some(1)).is_err());
        assert_eq!(
            resolve(pinned_for(40204), Some("off"), None),
            Ok((None, SupplyHardeningSource::Unset))
        );
    }

    #[test]
    fn release_network_without_pin_refuses_per_node_heights() {
        let pin = Some(None);
        assert!(resolve(pin, Some("100"), None).is_err());
        assert!(resolve(pin, None, Some(100)).is_err());
        assert_eq!(
            resolve(pin, Some("off"), None),
            Ok((None, SupplyHardeningSource::Unset))
        );
    }

    #[test]
    fn release_pin_wins_and_disagreeing_values_refuse_to_start() {
        let pin = Some(Some(500));
        assert_eq!(
            resolve(pin, None, None),
            Ok((Some(500), SupplyHardeningSource::ReleasePin))
        );
        assert_eq!(
            resolve(pin, Some("500"), Some(500)),
            Ok((Some(500), SupplyHardeningSource::ReleasePin))
        );
        assert!(resolve(pin, Some("501"), None).is_err());
        assert!(resolve(pin, Some("off"), None).is_err());
        assert!(resolve(pin, None, Some(499)).is_err());
    }

    #[test]
    fn dev_chain_resolution_order() {
        assert_eq!(
            resolve(None, None, None),
            Ok((None, SupplyHardeningSource::Unset))
        );
        assert_eq!(
            resolve(None, None, Some(7)),
            Ok((Some(7), SupplyHardeningSource::Config))
        );
        assert_eq!(
            resolve(None, Some("9"), Some(7)),
            Ok((Some(9), SupplyHardeningSource::Env))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(7)),
            Ok((None, SupplyHardeningSource::Env))
        );
        assert!(
            resolve(None, Some("soon"), None).is_err(),
            "never silently ignored"
        );
        assert!(resolve(None, Some("18446744073709551615"), None).is_err());
    }
}
