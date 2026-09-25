// citrate/core/consensus/src/hardening.rs
//
// PBA-R2 — the single activation height for the pre-bounty block-validity
// hardening (PBA-L1b-001 / -002 / -003, with PBA-L1a-006's import half).
//
// WHY ONE NAMED HEIGHT
//
// Three rules change which blocks are valid:
//
//   * PBA-L1b-001 — every transaction in an imported block must carry a
//     signature that THIS node verifies (never the wire `ecdsa_verified`
//     flag), and its `hash` must be the canonical id of its contents.
//   * PBA-L1b-002 — `tx_root` commits to each transaction's full contents
//     (`types::tx_root_v2`), not to the peer-supplied `tx.hash` field.
//   * PBA-L1b-003 — a block's timestamp may not run more than
//     `MAX_BLOCK_TIMESTAMP_ADVANCE_SECS` past its selected parent's.
//
// A node enforcing any of them while a peer does not disagrees about block
// validity, which is a fork. So all three switch on together, at one height,
// and every node must agree on that height. Blocks below it are judged by the
// old rules forever (re-judging history under a new rule forks just as surely).
//
// DEFAULTS
//
//   * Chain 40204 (every shipped testnet/mainnet profile): UNSET. The rules are
//     off until the owner schedules a height (see `docs/consensus/
//     PBA_HARDENING_ACTIVATION.md`). An upgraded binary changes nothing on
//     40204 by itself.
//   * Dev profiles (`NodeConfig::devnet()`, `node/config/devnet.toml`,
//     `devnet-config.toml`) set `chain.pba_hardening_height = 0`: active from
//     genesis.
//   * Unit tests construct components with an explicit [`PbaHardening`], so
//     both sides of the boundary are exercised.
//
// Genesis (height 0) is never re-judged: [`PbaHardening::active_at`] is false
// for height 0 even when the activation height is 0. Genesis is built locally
// by every node from the same profile, it is never received.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height, read by the node at start
/// (after the config file). Accepts a decimal height, or `off`/`none` to force
/// the rules off.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different
/// values disagree about block validity. Set it fleet-wide or not at all.
pub const PBA_HARDENING_ENV: &str = "CITRATE_PBA_HARDENING_HEIGHT";

/// Upper bound on how far a block's timestamp may run ahead of its selected
/// parent's (PBA-L1b-003), once the hardening is active.
///
/// Why a parent-relative bound and not only a wall-clock one: a wall-clock
/// check is local policy (two nodes with different clocks disagree), so it
/// cannot be a validity rule. A parent-relative bound is deterministic. It
/// caps how far one proposer can push the chain's clock per block, so a
/// `u64::MAX` timestamp is invalid on every node.
///
/// Liveness after an outage: the producer stamps
/// `clamp(now, parent.ts, parent.ts + MAX)` (see [`producer_timestamp`]), so
/// even after a halt longer than this bound the next block is valid; the
/// chain's clock then catches up by up to this much per block.
pub const MAX_BLOCK_TIMESTAMP_ADVANCE_SECS: u64 = 3_600;

/// Wall-clock future-drift tolerance applied at every block ingress (gossip,
/// sync). The same value gossip has always used. This one is local policy
/// (it depends on the local clock), so it is NOT height-gated: a block
/// rejected for it now is accepted once its time arrives.
pub const MAX_FUTURE_BLOCK_DRIFT_SECS: u64 = 900;

const UNSET: u64 = u64::MAX;

/// Process-wide activation height, set once by the node from config/env
/// before any consensus component is constructed. `UNSET` = rules off.
static PBA_HARDENING_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Set the process-wide activation height. `None` turns the rules off.
pub fn set_pba_hardening_height(height: Option<u64>) {
    PBA_HARDENING_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn pba_hardening_height() -> Option<u64> {
    match PBA_HARDENING_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Parse an env/config override. `Ok(None)` = rules explicitly off.
pub fn parse_pba_hardening_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{PBA_HARDENING_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{PBA_HARDENING_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// The pin-unaware resolution order (env override, else config). The node
/// resolves through [`init_pba_hardening_for_chain`], which also applies the
/// release pin for the running chain id; this remains for callers with no
/// chain id.
///
/// Order:
/// the `CITRATE_PBA_HARDENING_HEIGHT` env override when set (a height, or
/// `off`), otherwise the config value (`[chain] pba_hardening_height`). An
/// unparseable override is an error, never ignored: a node that silently
/// dropped a consensus parameter would fork at the activation height.
pub fn resolve_pba_hardening_height(config_value: Option<u64>) -> Result<Option<u64>, String> {
    match std::env::var(PBA_HARDENING_ENV) {
        Ok(raw) => parse_pba_hardening_override(&raw),
        Err(std::env::VarError::NotPresent) => Ok(config_value),
        Err(e) => Err(format!("{PBA_HARDENING_ENV}: {e}")),
    }
}

/// Resolve (see [`resolve_pba_hardening_height`]) and publish process-wide in
/// one step. Call once at start-up, before constructing any consensus or
/// execution component.
pub fn init_pba_hardening_height(config_value: Option<u64>) -> Result<Option<u64>, String> {
    let h = resolve_pba_hardening_height(config_value)?;
    set_pba_hardening_height(h);
    Ok(h)
}

/// Activation heights compiled into this release, per chain id.
///
/// When a chain has a pinned height, every node built from this release uses
/// it: an env or config value that disagrees refuses to start (see
/// [`resolve_activation`]). This removes the per-host setting as a way for a
/// node to fork off at the activation height.
///
/// OWNER STEP (release PR): replace `None` with `Some(H)` for 40204, where H is
/// the height agreed for the fleet.
pub const PINNED_ACTIVATIONS: &[(u64, Option<u64>)] = &[(40204, None)];

/// The activation height this release pins for `chain_id`, if any.
pub fn pinned_activation(chain_id: u64) -> Option<u64> {
    pinned_in(PINNED_ACTIVATIONS, chain_id)
}

fn pinned_in(table: &[(u64, Option<u64>)], chain_id: u64) -> Option<u64> {
    table
        .iter()
        .find(|(id, _)| *id == chain_id)
        .and_then(|(_, h)| *h)
}

/// Where the resolved activation height came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationSource {
    /// The height compiled into this release for the running chain id.
    ReleasePin,
    /// The `CITRATE_PBA_HARDENING_HEIGHT` env override.
    Env,
    /// `[chain] pba_hardening_height` in the node config.
    Config,
    /// Nothing set: the rules are off.
    Unset,
}

impl std::fmt::Display for ActivationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReleasePin => "release pin",
            Self::Env => "env CITRATE_PBA_HARDENING_HEIGHT",
            Self::Config => "config [chain] pba_hardening_height",
            Self::Unset => "unset",
        })
    }
}

/// The activation height a node runs with, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedActivation {
    pub chain_id: u64,
    pub height: Option<u64>,
    pub source: ActivationSource,
    /// The node runs a dev profile, so the release pin was not applied.
    pub dev_profile: bool,
}

impl ResolvedActivation {
    /// One line for the start-up banner.
    pub fn describe(&self) -> String {
        let h = match self.height {
            Some(h) => h.to_string(),
            None => "unset (rules off)".to_string(),
        };
        let dev = if self.dev_profile {
            ", dev profile: release pin not applied"
        } else {
            ""
        };
        format!(
            "chain {} pba_hardening_height {} (source: {}{})",
            self.chain_id, h, self.source, dev
        )
    }

    /// A fingerprint over the binary's consensus fingerprint plus the resolved
    /// activation. Two nodes with equal values run the same code with the
    /// same activation height on the same chain.
    pub fn fingerprint(&self, consensus_fingerprint: &str) -> String {
        use sha3::{Digest, Sha3_256};
        let h = match self.height {
            Some(h) => h.to_string(),
            None => "unset".to_string(),
        };
        let pre = format!(
            "citrate-activation-v1\nconsensus={consensus_fingerprint}\nchain_id={}\n\
             pba_hardening_height={h}\n",
            self.chain_id
        );
        let d = Sha3_256::digest(pre.as_bytes());
        format!("0x{}", hex::encode(&d[..16]))
    }
}

/// Resolve the activation height from its three inputs. Pure: the caller
/// supplies the pin, the raw env value and the config value.
///
/// * A dev profile, or a chain with no pin: the legacy order. The env
///   override wins over the config value, and an unparseable env value is an
///   error.
/// * A pinned chain: the pin is the height. An env or config value is allowed
///   only if it equals the pin; anything else (including `off`) is an error,
///   so the node refuses to start instead of forking at the pinned height.
pub fn resolve_activation(
    pin: Option<u64>,
    env_raw: Option<&str>,
    config_value: Option<u64>,
    dev_profile: bool,
) -> Result<(Option<u64>, ActivationSource), String> {
    let env_value = env_raw.map(parse_pba_hardening_override).transpose()?;
    match pin {
        Some(p) if !dev_profile => {
            if let Some(v) = env_value {
                if v != Some(p) {
                    return Err(format!(
                        "{PBA_HARDENING_ENV}={} conflicts with the activation height {p} \
                         pinned in this release for this chain. Remove the override \
                         (or set it to {p}).",
                        env_raw.unwrap_or_default().trim()
                    ));
                }
            }
            if let Some(c) = config_value {
                if c != p {
                    return Err(format!(
                        "[chain] pba_hardening_height = {c} conflicts with the activation \
                         height {p} pinned in this release for this chain. Remove the \
                         setting (or set it to {p})."
                    ));
                }
            }
            Ok((Some(p), ActivationSource::ReleasePin))
        }
        _ => match (env_value, config_value) {
            (Some(v), _) => Ok((v, ActivationSource::Env)),
            (None, Some(c)) => Ok((Some(c), ActivationSource::Config)),
            (None, None) => Ok((None, ActivationSource::Unset)),
        },
    }
}

/// Resolve for the running chain: the release pin for `chain_id`, the env
/// override and the config value (see [`resolve_activation`]). `chain_id`
/// must be the node's configured chain id.
pub fn resolve_pba_hardening_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
    dev_profile: bool,
) -> Result<ResolvedActivation, String> {
    let env_raw = match std::env::var(PBA_HARDENING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{PBA_HARDENING_ENV}: {e}")),
    };
    let (height, source) = resolve_activation(
        pinned_activation(chain_id),
        env_raw.as_deref(),
        config_value,
        dev_profile,
    )?;
    Ok(ResolvedActivation {
        chain_id,
        height,
        source,
        dev_profile,
    })
}

/// Resolve for the running chain and publish process-wide. The node calls
/// this once at start-up, before constructing any consensus or execution
/// component.
pub fn init_pba_hardening_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
    dev_profile: bool,
) -> Result<ResolvedActivation, String> {
    let r = resolve_pba_hardening_for_chain(chain_id, config_value, dev_profile)?;
    set_pba_hardening_height(r.height);
    Ok(r)
}

/// The chain id the pin is keyed on is the node's configured one. The
/// execution layer historically read `CITRATE_CHAIN_ID` from the environment
/// on its own; a node where the two disagree would key the pin, the mempool
/// and block validation on different chains. Refuse that at start-up.
pub fn check_chain_id_env(config_chain_id: u64, env_raw: Option<&str>) -> Result<(), String> {
    let Some(raw) = env_raw else {
        return Ok(());
    };
    match raw.trim().parse::<u64>() {
        Ok(v) if v == config_chain_id => Ok(()),
        Ok(v) => Err(format!(
            "CITRATE_CHAIN_ID={v} disagrees with the configured chain id {config_chain_id}. \
             Set them to the same value or unset CITRATE_CHAIN_ID."
        )),
        Err(e) => Err(format!(
            "CITRATE_CHAIN_ID={}: not a chain id: {e}",
            raw.trim()
        )),
    }
}

/// A component's view of the activation height.
///
/// Components capture it at construction ([`PbaHardening::from_process`]);
/// tests pass an explicit one ([`PbaHardening::at`] / [`PbaHardening::off`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PbaHardening {
    activation: Option<u64>,
}

impl Default for PbaHardening {
    fn default() -> Self {
        Self::from_process()
    }
}

impl PbaHardening {
    /// The process-wide value (see [`set_pba_hardening_height`]).
    pub fn from_process() -> Self {
        Self {
            activation: pba_hardening_height(),
        }
    }

    /// Active from `height` onward.
    pub const fn at(height: u64) -> Self {
        Self {
            activation: Some(height),
        }
    }

    /// Never active.
    pub const fn off() -> Self {
        Self { activation: None }
    }

    pub fn activation_height(&self) -> Option<u64> {
        self.activation
    }

    /// Whether the hardened validity rules apply to a block at `height`.
    /// Genesis (height 0) is never re-judged.
    pub fn active_at(&self, height: u64) -> bool {
        match self.activation {
            Some(a) => height > 0 && height >= a,
            None => false,
        }
    }
}

/// The timestamp an honest producer stamps on a child of a parent with
/// timestamp `parent_ts` (PBA-L1b-003).
///
/// `max(now, parent_ts)` keeps the parent-monotonic rule satisfiable even when
/// the parent is ahead of the local clock (the pre-fix producer stamped `now`
/// and every child of a future-dated tip was rejected: a permanent halt).
/// The upper clamp keeps the result inside the parent-relative bound, so a
/// long outage never leaves the producer unable to build a valid block.
pub fn producer_timestamp(now: u64, parent_ts: u64) -> u64 {
    now.max(parent_ts)
        .min(parent_ts.saturating_add(MAX_BLOCK_TIMESTAMP_ADVANCE_SECS))
}

/// Whether `ts` is acceptable at ingress against the local clock.
pub fn within_future_drift(ts: u64, now: u64) -> bool {
    ts <= now.saturating_add(MAX_FUTURE_BLOCK_DRIFT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_never_rejudged_and_boundary_is_inclusive() {
        let h = PbaHardening::at(0);
        assert!(!h.active_at(0), "genesis is never re-judged");
        assert!(h.active_at(1));
        let h = PbaHardening::at(100);
        assert!(!h.active_at(99));
        assert!(h.active_at(100));
        assert!(h.active_at(101));
        assert!(!PbaHardening::off().active_at(u64::MAX - 1));
    }

    #[test]
    fn override_parsing() {
        assert_eq!(parse_pba_hardening_override("off"), Ok(None));
        assert_eq!(parse_pba_hardening_override(" NONE "), Ok(None));
        assert_eq!(parse_pba_hardening_override("0"), Ok(Some(0)));
        assert_eq!(parse_pba_hardening_override("123456"), Ok(Some(123_456)));
        assert!(parse_pba_hardening_override("18446744073709551615").is_err());
        assert!(parse_pba_hardening_override("soon").is_err());
    }

    #[test]
    fn producer_timestamp_never_precedes_parent_and_never_exceeds_bound() {
        // Parent in the past: stamp now.
        assert_eq!(producer_timestamp(1_000, 900), 1_000);
        // Parent ahead of our clock (the halt shape): stamp the parent's ts.
        assert_eq!(producer_timestamp(1_000, 5_000), 5_000);
        // Long outage: clamp to the parent-relative bound.
        assert_eq!(
            producer_timestamp(1_000_000, 10),
            10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS
        );
        // Exactly at the bound.
        assert_eq!(
            producer_timestamp(10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS, 10),
            10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS
        );
        // u64::MAX parent: saturates, never panics.
        assert_eq!(producer_timestamp(1_000, u64::MAX), u64::MAX);
    }

    #[test]
    fn future_drift_window() {
        assert!(within_future_drift(1_900, 1_000));
        assert!(!within_future_drift(1_901, 1_000));
        assert!(!within_future_drift(u64::MAX, 1_000));
        assert!(within_future_drift(u64::MAX, u64::MAX));
    }

    // ---- release pin ----------------------------------------------------

    const PIN: Option<u64> = Some(500);

    #[test]
    fn pin_equal_to_env_is_accepted() {
        assert_eq!(
            resolve_activation(PIN, Some("500"), None, false),
            Ok((Some(500), ActivationSource::ReleasePin))
        );
        assert_eq!(
            resolve_activation(PIN, Some(" 500 "), Some(500), false),
            Ok((Some(500), ActivationSource::ReleasePin))
        );
    }

    #[test]
    fn pin_different_from_env_refuses_to_start() {
        let e = resolve_activation(PIN, Some("499"), None, false).unwrap_err();
        assert!(e.contains("conflicts") && e.contains("500"), "{e}");
        assert!(resolve_activation(PIN, Some("501"), None, false).is_err());
        // `off` on a pinned chain is a disagreement too.
        assert!(resolve_activation(PIN, Some("off"), None, false).is_err());
        // Garbage is still an error, never ignored.
        assert!(resolve_activation(PIN, Some("soon"), None, false).is_err());
    }

    #[test]
    fn pin_different_from_config_refuses_to_start() {
        let e = resolve_activation(PIN, None, Some(0), false).unwrap_err();
        assert!(e.contains("pba_hardening_height = 0"), "{e}");
        assert!(resolve_activation(PIN, None, Some(501), false).is_err());
        // Env equal to the pin does not excuse a conflicting config value.
        assert!(resolve_activation(PIN, Some("500"), Some(7), false).is_err());
    }

    #[test]
    fn pin_with_nothing_set_uses_the_pin() {
        assert_eq!(
            resolve_activation(PIN, None, None, false),
            Ok((Some(500), ActivationSource::ReleasePin))
        );
    }

    #[test]
    fn no_pin_keeps_the_legacy_order() {
        assert_eq!(
            resolve_activation(None, Some("7"), Some(42), false),
            Ok((Some(7), ActivationSource::Env))
        );
        assert_eq!(
            resolve_activation(None, Some("off"), Some(42), false),
            Ok((None, ActivationSource::Env))
        );
        assert_eq!(
            resolve_activation(None, None, Some(42), false),
            Ok((Some(42), ActivationSource::Config))
        );
        assert_eq!(
            resolve_activation(None, None, None, false),
            Ok((None, ActivationSource::Unset))
        );
        assert!(resolve_activation(None, Some("soon"), Some(42), false).is_err());
    }

    #[test]
    fn dev_profile_is_unchanged_by_a_pin() {
        assert_eq!(
            resolve_activation(PIN, None, Some(0), true),
            Ok((Some(0), ActivationSource::Config))
        );
        assert_eq!(
            resolve_activation(PIN, Some("3"), Some(0), true),
            Ok((Some(3), ActivationSource::Env))
        );
        assert_eq!(
            resolve_activation(PIN, None, None, true),
            Ok((None, ActivationSource::Unset))
        );
    }

    #[test]
    fn pin_table_lookup() {
        // Every entry resolves to its own value, ids are unique, and no entry
        // uses the reserved "unset" encoding.
        for (i, (id, h)) in PINNED_ACTIVATIONS.iter().enumerate() {
            assert_eq!(pinned_activation(*id), *h);
            assert_ne!(*h, Some(u64::MAX));
            assert!(PINNED_ACTIVATIONS[i + 1..].iter().all(|(o, _)| o != id));
        }
        // Chains the release does not list have no pin.
        assert_eq!(pinned_activation(1), None);
        assert_eq!(pinned_activation(1337), None);
        assert!(PINNED_ACTIVATIONS.iter().any(|(id, _)| *id == 40204));
    }

    #[test]
    fn pin_lookup_picks_the_running_chain() {
        let table = [(1, Some(10)), (40204, Some(500)), (7, None)];
        assert_eq!(pinned_in(&table, 40204), Some(500));
        assert_eq!(pinned_in(&table, 1), Some(10));
        assert_eq!(pinned_in(&table, 7), None);
        assert_eq!(pinned_in(&table, 2), None);
    }

    #[test]
    fn chain_id_env_must_match_config() {
        assert_eq!(check_chain_id_env(40204, None), Ok(()));
        assert_eq!(check_chain_id_env(40204, Some("40204")), Ok(()));
        assert_eq!(check_chain_id_env(40204, Some(" 40204\n")), Ok(()));
        assert!(check_chain_id_env(40204, Some("1337")).is_err());
        assert!(check_chain_id_env(1337, Some("40204")).is_err());
        assert!(check_chain_id_env(40204, Some("mainnet")).is_err());
    }

    #[test]
    fn banner_and_fingerprint_name_height_and_source() {
        let a = ResolvedActivation {
            chain_id: 40204,
            height: Some(500),
            source: ActivationSource::ReleasePin,
            dev_profile: false,
        };
        let d = a.describe();
        assert!(
            d.contains("chain 40204") && d.contains("500") && d.contains("release pin"),
            "{d}"
        );
        let off = ResolvedActivation {
            height: None,
            source: ActivationSource::Unset,
            ..a
        };
        assert!(off.describe().contains("unset"));
        let dev = ResolvedActivation {
            dev_profile: true,
            ..a
        };
        assert!(dev.describe().contains("dev profile"));
        // The fingerprint moves with the height, the chain and the binary.
        let f = a.fingerprint("0xabc");
        assert!(f.starts_with("0x") && f.len() == 34, "{f}");
        assert_eq!(f, a.fingerprint("0xabc"));
        assert_ne!(f, off.fingerprint("0xabc"));
        assert_ne!(
            f,
            ResolvedActivation {
                height: Some(501),
                ..a
            }
            .fingerprint("0xabc")
        );
        assert_ne!(
            f,
            ResolvedActivation { chain_id: 1, ..a }.fingerprint("0xabc")
        );
        assert_ne!(f, a.fingerprint("0xabd"));
        for s in [
            ActivationSource::ReleasePin,
            ActivationSource::Env,
            ActivationSource::Config,
            ActivationSource::Unset,
        ] {
            assert!(!s.to_string().is_empty());
        }
    }
}
