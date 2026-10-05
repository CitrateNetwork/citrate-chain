// citrate/core/execution/src/agent_fork.rs
//
// HUP-S7.2 (federation F-2 / F-3): the activation height of the agent
// precompile fork.
//
// WHAT SWITCHES ON
//
// At and after this height the REVM bridge exposes four new pure precompiles to
// contract code (spec: `docs/precompiles/AGENT_PRECOMPILES.md`):
//
//   * 0x0112 LORA_APPLY            W' = W + (alpha / r) * (B . A), Q16.16
//   * 0x0113 LORA_MERGE            sum_i w_i * (alpha_i / r_i) * (B_i . A_i), Q16.16
//   * 0x0121 MEMORY_ANCHOR_VERIFY  nightly anchor inclusion proof -> day commitment
//   * 0x0122 AGENT_OPS             DeviceLink / DeviceRevocation signature checks
//
// Below the height nothing changes: the four addresses keep exactly the
// behaviour they have today (an empty account before `pba_hardening_height`,
// a reserved always-failing address after it), the precompile SET is the same,
// so EIP-2929 warm/cold gas for those addresses is the same, and every
// historical block replays to the root it was produced with.
//
// WHY A SEPARATE HEIGHT (not `pba_hardening_height`)
//
// The PBA hardening is a fixed set of validity fixes with its own pinned height.
// This fork adds new behaviour on its own schedule, chosen by the owner. Tying
// it to the PBA height would either delay the fixes or ship the new
// precompiles with them. One store, here, for this one fork: nothing else may
// keep a second copy (two stores can disagree, and a node whose stores
// disagree forks at the height).
//
// RELEASE DEFAULT: ACTIVE FROM GENESIS ON 40204
//
//   * Chain 40204: the release pin is `Some(0)` (owner decision 2026-10-04,
//     for the 2026-10-05 reroll): the four precompiles are live from block 1
//     of the new genesis, so no mid-chain activation is ever scheduled. An env
//     or config height that disagrees with the pin is REFUSED (the node stops
//     at start-up), because a per-node height on a release network would fork
//     that node. This binary is for the new genesis only: it must not replay a
//     chain produced without the fork.
//   * Any other chain (local devnets, anvil-like test chains): unset unless
//     `[chain] agent_precompiles_height` or `CITRATE_AGENT_PRECOMPILES_HEIGHT`
//     sets it. Nothing in the shipped configs sets it.
//   * Genesis (height 0) is never re-judged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release chain.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different values
/// disagree about the result of any transaction that calls the new addresses.
pub const AGENT_PRECOMPILES_ENV: &str = "CITRATE_AGENT_PRECOMPILES_HEIGHT";

/// Activation heights compiled into this release, per release chain id.
///
/// 40204: `Some(0)`, active from genesis of the 2026-10-05 reroll (owner
/// decision 2026-10-04; the placeholder gas schedule in
/// `docs/precompiles/AGENT_PRECOMPILES.md` is owner-signed). A pin of `None`
/// would mean "release network, not scheduled".
pub const AGENT_PRECOMPILES_PINS: &[(u64, Option<u64>)] = &[(40204, Some(0))];

const UNSET: u64 = u64::MAX;

static AGENT_PRECOMPILES_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the process-wide activation height. `None` = not activated.
pub fn set_agent_precompiles_height(height: Option<u64>) {
    AGENT_PRECOMPILES_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn agent_precompiles_height() -> Option<u64> {
    match AGENT_PRECOMPILES_HEIGHT.load(Ordering::SeqCst) {
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
pub fn agent_precompiles_active(height: u64) -> bool {
    active_at(agent_precompiles_height(), height)
}

/// The pinned height for `chain_id`: `None` when the chain is not a release
/// network, `Some(None)` when it is one with no height scheduled.
pub fn pinned_for(chain_id: u64) -> Option<Option<u64>> {
    AGENT_PRECOMPILES_PINS
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
            "{AGENT_PRECOMPILES_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{AGENT_PRECOMPILES_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentForkSource {
    /// Compiled into this release for the running chain id.
    ReleasePin,
    /// `CITRATE_AGENT_PRECOMPILES_HEIGHT`.
    Env,
    /// `[chain] agent_precompiles_height`.
    Config,
    /// Nothing set: not activated.
    Unset,
}

impl std::fmt::Display for AgentForkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_AGENT_PRECOMPILES_HEIGHT",
            Self::Config => "config [chain] agent_precompiles_height",
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
) -> Result<(Option<u64>, AgentForkSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{AGENT_PRECOMPILES_ENV} conflicts with the agent precompile fork height \
                         {p} pinned in this release for this chain. Remove the override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] agent_precompiles_height = {c} conflicts with the height {p} \
                         pinned in this release for this chain. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), AgentForkSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{AGENT_PRECOMPILES_ENV}={h}: the agent precompile fork is not scheduled \
                     for this release network. A per-node height would fork this node; the \
                     height is set only by a release pin."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] agent_precompiles_height = {c}: the agent precompile fork is not \
                     scheduled for this release network. Remove the setting."
                ));
            }
            Ok((None, AgentForkSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, AgentForkSource::Env)),
            (None, Some(c)) => Ok((Some(c), AgentForkSource::Config)),
            (None, None) => Ok((None, AgentForkSource::Unset)),
        },
    }
}

/// Resolve for the running chain (release pin, env override, config value)
/// without publishing.
pub fn resolve_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, AgentForkSource), String> {
    let env_raw = match std::env::var(AGENT_PRECOMPILES_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{AGENT_PRECOMPILES_ENV}: {e}")),
    };
    resolve(pinned_for(chain_id), env_raw.as_deref(), config_value)
}

/// Resolve for the running chain and publish process-wide. The node calls this
/// once at start-up, before constructing any execution component.
pub fn init_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, AgentForkSource), String> {
    let r = resolve_for_chain(chain_id, config_value)?;
    set_agent_precompiles_height(r.0);
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
    fn chain_40204_ships_active_from_genesis() {
        assert_eq!(
            pinned_for(40204),
            Some(Some(0)),
            "40204 is a release network, active from genesis"
        );
        assert_eq!(pinned_for(1337), None, "devnet is not a release network");
        assert_eq!(
            resolve(pinned_for(40204), None, None),
            Ok((Some(0), AgentForkSource::ReleasePin))
        );
        let (h, _) =
            resolve(pinned_for(40204), None, None).unwrap_or((None, AgentForkSource::Unset));
        assert!(!active_at(h, 0), "genesis is never re-judged");
        assert!(active_at(h, 1), "live from the first block");
        assert!(active_at(h, u64::MAX));
        // A matching override is accepted; any other value, or `off`, stops the node.
        assert_eq!(
            resolve(pinned_for(40204), Some("0"), Some(0)),
            Ok((Some(0), AgentForkSource::ReleasePin))
        );
        assert!(resolve(pinned_for(40204), Some("100"), None).is_err());
        assert!(resolve(pinned_for(40204), Some("off"), None).is_err());
        assert!(resolve(pinned_for(40204), None, Some(1)).is_err());
    }

    #[test]
    fn release_network_without_pin_refuses_per_node_heights() {
        let pin = Some(None);
        assert!(resolve(pin, Some("100"), None).is_err());
        assert!(resolve(pin, None, Some(100)).is_err());
        assert_eq!(
            resolve(pin, Some("off"), None),
            Ok((None, AgentForkSource::Unset))
        );
    }

    #[test]
    fn release_pin_wins_and_disagreeing_values_refuse_to_start() {
        let pin = Some(Some(500));
        assert_eq!(
            resolve(pin, None, None),
            Ok((Some(500), AgentForkSource::ReleasePin))
        );
        assert_eq!(
            resolve(pin, Some("500"), Some(500)),
            Ok((Some(500), AgentForkSource::ReleasePin))
        );
        assert!(resolve(pin, Some("501"), None).is_err());
        assert!(resolve(pin, Some("off"), None).is_err());
        assert!(resolve(pin, None, Some(499)).is_err());
    }

    #[test]
    fn dev_chain_resolution_order() {
        assert_eq!(
            resolve(None, None, None),
            Ok((None, AgentForkSource::Unset))
        );
        assert_eq!(
            resolve(None, None, Some(7)),
            Ok((Some(7), AgentForkSource::Config))
        );
        assert_eq!(
            resolve(None, Some("9"), Some(7)),
            Ok((Some(9), AgentForkSource::Env))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(7)),
            Ok((None, AgentForkSource::Env))
        );
        assert!(
            resolve(None, Some("soon"), None).is_err(),
            "never silently ignored"
        );
        assert!(resolve(None, Some("18446744073709551615"), None).is_err());
    }
}
