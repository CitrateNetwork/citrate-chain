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
//   * Chain 40204: the release pin is `None` (release network, not
//     scheduled). An upgraded binary changes nothing on 40204 by itself; an
//     env or config height there refuses to start. The owner schedules it by
//     setting the pin in a release (a fresh genesis can pin `Some(0)`).
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

/// Activation heights compiled into this release, per release chain id.
///
/// 40204: `None` — release network, not scheduled.
///
/// OWNER STEP (release PR): set `Some(H)` for 40204 once the fleet agrees on
/// H, or `Some(0)` for a release that starts a fresh genesis.
pub const VRF_CANONICAL_ENCODING_PINS: &[(u64, Option<u64>)] = &[(40204, None)];

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

/// The pinned height for `chain_id`: `None` when the chain is not a release
/// network, `Some(None)` when it is one with no height scheduled.
pub fn pinned_for(chain_id: u64) -> Option<Option<u64>> {
    VRF_CANONICAL_ENCODING_PINS
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

/// Resolve for the running chain (release pin, env override, config value)
/// without publishing.
pub fn resolve_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, VrfEncodingSource), String> {
    let env_raw = match std::env::var(VRF_CANONICAL_ENCODING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{VRF_CANONICAL_ENCODING_ENV}: {e}")),
    };
    resolve(pinned_for(chain_id), env_raw.as_deref(), config_value)
}

/// Resolve for the running chain and publish process-wide. The node calls
/// this once at start-up, before constructing any consensus component.
pub fn init_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
) -> Result<(Option<u64>, VrfEncodingSource), String> {
    let r = resolve_for_chain(chain_id, config_value)?;
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
        assert_eq!(
            pinned_for(40204),
            Some(None),
            "40204 is a release network with no height scheduled"
        );
        assert_eq!(pinned_for(1337), None, "devnet is not a release network");
        assert_eq!(
            resolve(pinned_for(40204), None, None),
            Ok((None, VrfEncodingSource::Unset))
        );
        // A per-node height on 40204 refuses to start; `off` is accepted.
        assert!(resolve(pinned_for(40204), Some("0"), None).is_err());
        assert!(resolve(pinned_for(40204), None, Some(0)).is_err());
        assert_eq!(
            resolve(pinned_for(40204), Some("off"), None),
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
