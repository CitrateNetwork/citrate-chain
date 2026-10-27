// citrate/core/execution/src/exact_code.rs
//
// The activation height of the exact-created-code rule.
//
// WHAT SWITCHES ON
//
// When a contract is created by CREATE or CREATE2 from inside a call (a factory
// deploy, a constructor that deploys a child), REVM hands the new account's
// code to `DatabaseCommit::commit` in its ANALYSED form: the original runtime
// bytes followed by 33 zero bytes of interpreter padding. Below this height
// `commit` stores those padded bytes, so `eth_getCode`, EXTCODESIZE and
// EXTCODEHASH of every factory-created contract report 33 extra trailing zero
// bytes and a code hash that differs from every other EVM chain's.
//
// At and after this height `commit` stores the ORIGINAL bytes (exactly the
// init code's return data), so the stored code, its length and its hash match
// the EVM specification and REVM's own reference database.
//
// Top-level create transactions are unaffected either way: the executor
// rewrites their code from REVM's `Output::Create` bytes, which are original.
// Contracts already stored padded stay as they are: code is only ever written
// at creation, so the rule never rewrites existing state.
//
// CONSENSUS
//
// The rule changes the stored code bytes and the account's code hash (and so
// the state root) of every block that creates a contract from inside a call.
// It is height-gated like the other execution forks. One store, here: nothing
// else may keep a second copy (two stores can disagree, and a node whose
// stores disagree forks at the height).
//
// SCHEDULE: KEYED BY GENESIS (citrate_consensus::hardening::genesis_rule_pin)
//
//   * r1006's genesis (40204 + R1006_GENESIS) is 0 in the shared
//     GENESIS_ACTIVATIONS table: the exact rule from block 1.
//   * r1005's genesis (and 40204 with no genesis known) is unset and refuses a
//     per-node height: the running r1005 chain was produced with the padded rule,
//     and a node that applied the exact rule to its history would fork.
//   * Any other genesis (the r1006 build devnet, a rehearsal) is local: the env or
//     `[chain] exact_create_code_height` decides.
//   * There is no per-chain pin table for this rule (a tripwire enforces it).
//   * Genesis (height 0) is never re-judged.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release chain.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different values
/// compute different state roots for any block that creates a contract from
/// inside a call.
pub const EXACT_CREATE_CODE_ENV: &str = "CITRATE_EXACT_CREATE_CODE_HEIGHT";

const UNSET: u64 = u64::MAX;

static EXACT_CREATE_CODE_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the activation height process-wide. `None` = not activated.
pub fn set_exact_create_code_height(height: Option<u64>) {
    EXACT_CREATE_CODE_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height (`None` = not activated).
pub fn exact_create_code_height() -> Option<u64> {
    match EXACT_CREATE_CODE_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Whether the rule applies to a block at `height` under `activation` (pure).
/// Genesis is never re-judged; the boundary is inclusive.
pub fn active_at(activation: Option<u64>, height: u64) -> bool {
    match activation {
        Some(a) => height > 0 && height >= a,
        None => false,
    }
}

/// Whether a block at `height` stores created code exactly, on this node.
pub fn exact_create_code_active(height: u64) -> bool {
    active_at(exact_create_code_height(), height)
}

/// Parse the env override: a decimal height, or `off` / `none`.
pub fn parse_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{EXACT_CREATE_CODE_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{EXACT_CREATE_CODE_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactCodeSource {
    ReleasePin,
    Env,
    Config,
    Unset,
}

impl std::fmt::Display for ExactCodeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_EXACT_CREATE_CODE_HEIGHT",
            Self::Config => "config [chain] exact_create_code_height",
            Self::Unset => "unset",
        })
    }
}

/// Resolve the height from the release pin, the env override and the config
/// value. On a release network only the pin decides; a disagreeing env or
/// config value is an error (the node refuses to start rather than fork).
pub fn resolve(
    pin: Option<Option<u64>>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, ExactCodeSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{EXACT_CREATE_CODE_ENV} conflicts with the exact-created-code height \
                         {p} pinned in this release for this chain. Remove the override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] exact_create_code_height = {c} conflicts with the height {p} \
                         pinned in this release for this chain. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), ExactCodeSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{EXACT_CREATE_CODE_ENV}={h}: the exact-created-code rule is not \
                     scheduled for this release network. A per-node height would fork this \
                     node; the height is set only by a release pin."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] exact_create_code_height = {c}: the exact-created-code rule is \
                     not scheduled for this release network. Remove the setting."
                ));
            }
            Ok((None, ExactCodeSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, ExactCodeSource::Env)),
            (None, Some(c)) => Ok((Some(c), ExactCodeSource::Config)),
            (None, None) => Ok((None, ExactCodeSource::Unset)),
        },
    }
}

/// The schedule for this rule on `chain_id` with block 0 `genesis` (the shared table).
pub fn pin_for_genesis(chain_id: u64, genesis: Option<&[u8; 32]>) -> Option<Option<u64>> {
    citrate_consensus::hardening::genesis_rule_pin(chain_id, genesis, |a| a.exact_create_code)
}

/// [`resolve`] with the genesis-keyed schedule and the process env.
pub fn resolve_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, ExactCodeSource), String> {
    let env_raw = match std::env::var(EXACT_CREATE_CODE_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{EXACT_CREATE_CODE_ENV}: {e}")),
    };
    resolve(
        pin_for_genesis(chain_id, genesis),
        env_raw.as_deref(),
        config_value,
    )
}

/// Resolve and publish process-wide. The node calls this once at start-up, after it knows
/// its block 0 and before any execution component exists.
pub fn init_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, ExactCodeSource), String> {
    let r = resolve_for_genesis(chain_id, genesis, config_value)?;
    set_exact_create_code_height(r.0);
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
    fn r1005_keeps_the_padded_rule_r1006_is_exact_from_block_one() {
        use citrate_consensus::hardening::{R1006_GENESIS, RELEASE_GENESIS};
        let r1005 = RELEASE_GENESIS[0].1;
        // r1005 + the new binary: unset, and a per-node height is refused.
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&r1005)), None, None),
            Ok((None, ExactCodeSource::Unset))
        );
        assert!(resolve(pin_for_genesis(40204, Some(&r1005)), None, Some(0)).is_err());
        // r1006: 0 from the shared table.
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&R1006_GENESIS)), None, None),
            Ok((Some(0), ExactCodeSource::ReleasePin))
        );
        // A build devnet / rehearsal genesis opts in from block 1 by config.
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&[0x42; 32])), None, Some(0)),
            Ok((Some(0), ExactCodeSource::Config))
        );
        assert_eq!(
            resolve(pin_for_genesis(1337, None), None, None),
            Ok((None, ExactCodeSource::Unset))
        );
    }

    #[test]
    fn release_network_without_schedule_refuses_per_node_heights() {
        let pin = Some(None);
        assert!(resolve(pin, Some("0"), None).is_err());
        assert!(resolve(pin, None, Some(0)).is_err());
        assert_eq!(
            resolve(pin, Some("off"), None),
            Ok((None, ExactCodeSource::Unset))
        );
    }

    #[test]
    fn release_pin_wins_and_disagreeing_values_refuse_to_start() {
        let pin = Some(Some(0));
        assert_eq!(
            resolve(pin, None, None),
            Ok((Some(0), ExactCodeSource::ReleasePin))
        );
        assert_eq!(
            resolve(pin, Some("0"), Some(0)),
            Ok((Some(0), ExactCodeSource::ReleasePin))
        );
        assert!(resolve(pin, Some("5"), None).is_err());
        assert!(resolve(pin, Some("off"), None).is_err());
        assert!(resolve(pin, None, Some(5)).is_err());
    }

    #[test]
    fn dev_chains_take_env_then_config() {
        assert_eq!(
            resolve(None, Some("7"), Some(9)),
            Ok((Some(7), ExactCodeSource::Env))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(9)),
            Ok((None, ExactCodeSource::Env))
        );
        assert_eq!(
            resolve(None, None, Some(0)),
            Ok((Some(0), ExactCodeSource::Config))
        );
        assert_eq!(
            resolve(None, None, None),
            Ok((None, ExactCodeSource::Unset))
        );
        assert!(resolve(None, Some("abc"), None).is_err());
        assert!(resolve(None, Some(&u64::MAX.to_string()), None).is_err());
    }
}
