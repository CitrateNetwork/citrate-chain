// citrate/core/consensus/src/vrf_encoding.rs
//
// Activation height for canonical ECVRF proof encoding.
//
// WHAT SWITCHES ON
//
// From this height a block's ECVRF proof must carry its two curve points (the
// prover's P-256 key and Gamma) in canonical SEC1 compressed form: tag 0x02 or
// 0x03 followed by the 32-byte x coordinate, the exact bytes the point
// re-encodes to (RFC 9381 §5.5, `string_to_point` for P-256). The decoder used
// below the height also accepts other 33-byte SEC1 forms of the same point.
// Above it, those are invalid.
//
// Honest producers are unaffected: `ecvrf::prove` + `EcvrfProof::to_bytes`
// always emit the canonical compressed form (`to_encoded_point(true)`), so
// every proof the shipped producer has ever made satisfies the stricter rule.
// The height exists because the rule changes block validity: a node that
// enforced it while a peer did not would disagree about any block carrying a
// non-canonical proof, and re-judging history that might contain one would
// fork a replaying node. Below the height, validity is exactly as before.
//
// RELEASE DEFAULT
//
//   * Scheduled per genesis in the shared (chain id, genesis hash) table
//     (`hardening::GENESIS_ACTIVATIONS`): r1006's genesis is 0 (active from
//     block 1). r1005's genesis on 40204 (and 40204 with no genesis known) is
//     not scheduled, and an env or config height there refuses to start.
//   * Any other chain: unset unless `[chain] vrf_canonical_encoding_height` or
//     `CITRATE_VRF_CANONICAL_ENCODING_HEIGHT` sets it. The shipped devnet
//     profiles set `0` (active from genesis).
//   * Genesis (height 0) is never re-judged.
//
// One store, here. Nothing else keeps a second copy: two stores can disagree,
// and a node whose stores disagree forks at the height.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height on a non-release chain.
/// Accepts a decimal height, or `off` / `none`.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different
/// values disagree about the validity of a block whose proof is not in
/// canonical form.
pub const VRF_CANONICAL_ENCODING_ENV: &str = "CITRATE_VRF_CANONICAL_ENCODING_HEIGHT";


const UNSET: u64 = u64::MAX;

static VRF_CANONICAL_ENCODING_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Publish the process-wide activation height. `None` = not activated.
pub fn set_vrf_canonical_encoding_height(height: Option<u64>) {
    VRF_CANONICAL_ENCODING_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn vrf_canonical_encoding_height() -> Option<u64> {
    match VRF_CANONICAL_ENCODING_HEIGHT.load(Ordering::SeqCst) {
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

/// The schedule for this rule on `chain_id` with block 0 `genesis`, from the shared
/// (chain id, genesis hash) table (`crate::hardening::genesis_rule_pin`). There is no
/// per-chain pin table for this rule (scripts/ci/genesis_keyed_pins_tripwire.sh).
pub fn pin_for_genesis(chain_id: u64, genesis: Option<&[u8; 32]>) -> Option<Option<u64>> {
    crate::hardening::genesis_rule_pin(chain_id, genesis, |a| a.vrf_canonical_encoding)
}

/// Parse an env/config override. `Ok(None)` = explicitly off.
pub fn parse_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{VRF_CANONICAL_ENCODING_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{VRF_CANONICAL_ENCODING_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// Where the resolved height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfEncodingSource {
    /// Compiled into this release for the running chain id.
    ReleasePin,
    /// `CITRATE_VRF_CANONICAL_ENCODING_HEIGHT`.
    Env,
    /// `[chain] vrf_canonical_encoding_height`.
    Config,
    /// Nothing set: not activated.
    Unset,
}

impl std::fmt::Display for VrfEncodingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_VRF_CANONICAL_ENCODING_HEIGHT",
            Self::Config => "config [chain] vrf_canonical_encoding_height",
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
///   config height is an error (`off` is accepted). A node must not schedule
///   a validity change on a release network by itself.
/// * Any other chain: env override, then config, then unset. An unparseable
///   env value is an error, never ignored.
pub fn resolve(
    pin: Option<Option<u64>>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, VrfEncodingSource), String> {
    let env_value = env_raw.map(parse_override).transpose()?;
    match pin {
        Some(Some(p)) => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{VRF_CANONICAL_ENCODING_ENV} conflicts with the canonical VRF encoding \
                         height {p} pinned in this release for this chain. Remove the override."
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] vrf_canonical_encoding_height = {c} conflicts with the height \
                         {p} pinned in this release for this chain. Remove the setting."
                    ));
                }
            }
            Ok((Some(p), VrfEncodingSource::ReleasePin))
        }
        Some(None) => {
            if let Some(Some(h)) = env_value {
                return Err(format!(
                    "{VRF_CANONICAL_ENCODING_ENV}={h}: canonical VRF encoding is not scheduled \
                     for this release network. A per-node height would fork this node; the \
                     height is set only by a release pin."
                ));
            }
            if let Some(c) = config_value {
                return Err(format!(
                    "[chain] vrf_canonical_encoding_height = {c}: canonical VRF encoding is not \
                     scheduled for this release network. Remove the setting."
                ));
            }
            Ok((None, VrfEncodingSource::Unset))
        }
        None => match (env_value, config_value) {
            (Some(v), _) => Ok((v, VrfEncodingSource::Env)),
            (None, Some(c)) => Ok((Some(c), VrfEncodingSource::Config)),
            (None, None) => Ok((None, VrfEncodingSource::Unset)),
        },
    }
}

/// `resolve` with the genesis-keyed schedule and the process env.
pub fn resolve_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, VrfEncodingSource), String> {
    let env_raw = match std::env::var(VRF_CANONICAL_ENCODING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{VRF_CANONICAL_ENCODING_ENV}: {e}")),
    };
    resolve(pin_for_genesis(chain_id, genesis), env_raw.as_deref(), config_value)
}

/// Resolve and publish process-wide. The node calls this once at start-up, after it
/// knows its block 0 and before any component that captures the height exists.
pub fn init_for_genesis(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    config_value: Option<u64>,
) -> Result<(Option<u64>, VrfEncodingSource), String> {
    let r = resolve_for_genesis(chain_id, genesis, config_value)?;
    set_vrf_canonical_encoding_height(r.0);
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
    fn chain_40204_ships_unscheduled() {
        // r1006's genesis (the shared table) schedules it from block 1.
        assert_eq!(
            pin_for_genesis(40204, Some(&crate::hardening::R1006_GENESIS)),
            Some(Some(0))
        );
        assert_eq!(
            pin_for_genesis(40204, Some(&crate::hardening::RELEASE_GENESIS[0].1)),
            Some(None),
            "40204 is a release network with no height scheduled"
        );
        assert_eq!(pin_for_genesis(1337, None), None, "devnet is not a release network");
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&crate::hardening::RELEASE_GENESIS[0].1)), None, None),
            Ok((None, VrfEncodingSource::Unset))
        );
        // A per-node height on 40204 refuses to start; `off` is accepted.
        assert!(resolve(pin_for_genesis(40204, Some(&crate::hardening::RELEASE_GENESIS[0].1)), Some("0"), None).is_err());
        assert!(resolve(pin_for_genesis(40204, Some(&crate::hardening::RELEASE_GENESIS[0].1)), None, Some(0)).is_err());
        assert_eq!(
            resolve(pin_for_genesis(40204, Some(&crate::hardening::RELEASE_GENESIS[0].1)), Some("off"), None),
            Ok((None, VrfEncodingSource::Unset))
        );
    }

    #[test]
    fn release_pin_wins_and_disagreeing_values_refuse_to_start() {
        let pin = Some(Some(500));
        assert_eq!(
            resolve(pin, None, None),
            Ok((Some(500), VrfEncodingSource::ReleasePin))
        );
        assert_eq!(
            resolve(pin, Some("500"), Some(500)),
            Ok((Some(500), VrfEncodingSource::ReleasePin))
        );
        assert!(resolve(pin, Some("501"), None).is_err());
        assert!(resolve(pin, Some("off"), None).is_err());
        assert!(resolve(pin, None, Some(499)).is_err());
    }

    #[test]
    fn dev_chain_resolution_order() {
        assert_eq!(
            resolve(None, None, None),
            Ok((None, VrfEncodingSource::Unset))
        );
        assert_eq!(
            resolve(None, None, Some(0)),
            Ok((Some(0), VrfEncodingSource::Config))
        );
        assert_eq!(
            resolve(None, Some("9"), Some(7)),
            Ok((Some(9), VrfEncodingSource::Env))
        );
        assert_eq!(
            resolve(None, Some("off"), Some(7)),
            Ok((None, VrfEncodingSource::Env))
        );
        assert!(
            resolve(None, Some("soon"), None).is_err(),
            "never silently ignored"
        );
        assert!(resolve(None, Some("18446744073709551615"), None).is_err());
    }
}
