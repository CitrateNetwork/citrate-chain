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
//     `devnet-config.toml`) run on their own chain id (1337) with the devnet
//     genesis and set `chain.pba_hardening_height = 0`: active from genesis.
//     `dev_profile` is refused on a release network.
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
///
/// 40204 is `Some(0)`: the rules are active from the first block after genesis
/// of the chain this release starts (the PANIC-S1 reroll). A reroll resets the
/// height but not this table, so every reroll must re-check it. This release
/// must never run on a data directory from the previous 40204 genesis: it
/// would re-judge that chain's history from block 1 and fork off.
pub const PINNED_ACTIVATIONS: &[(u64, Option<u64>)] = &[(40204, Some(0))];

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

/// Genesis block hashes of the release networks, by chain id.
///
/// The genesis block does not commit to the chain id, so without this a node
/// could run a release network's genesis under another chain id and escape
/// that chain's pin while still passing the handshake's genesis check.
pub const RELEASE_GENESIS: &[(u64, [u8; 32])] = &[
    // testnet_beta (also the profile a 40204 config with no profile uses)
    // Re-pinned 2026-10-05 for the r1005 fresh-keys reroll (new genesis role addresses
    // move the genesis state root).
    (
        40204,
        hex32("1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"),
    ),
    // team_testnet (re-pinned 2026-10-05 for the r1005 fresh-keys reroll)
    (
        40204,
        hex32("90044175c36a6491309d769bd0fa684afbf7b90b64136446db8e2e6ff0927553"),
    ),
    // r1006 (profile `r1006`: genesis from ceremony state)
    (40204, R1006_GENESIS),
    // mainnet
    (
        40204,
        hex32("ba93d716ab8b005f1d7e61d369a65fc1d6a358d6a479e11b640815c74388ab01"),
    ),
];

/// The r1006 genesis block (profile `r1006`: block 0 holds the ceremony's contracts).
/// Pinned by `r1006_genesis_hash_is_pinned` in citrate-economics, which rebuilds it from
/// the compiled profile; any change to the allocation moves it, on purpose.
pub const R1006_GENESIS: [u8; 32] =
    hex32("a3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4");

/// Activation heights compiled into this release for ONE genesis, keyed by its block-0
/// hash rather than by chain id. r1005 and r1006 share chain id 40204, so a per-chain pin
/// `(40204, Some(0))` would also switch the rule on for an r1005 node rebuilt from this
/// release and fork it off the live r1005 chain. Keying by genesis keeps r1005's rules
/// exactly as they are (its genesis has no entry here) and gives r1006 its own.
///
/// ONE mechanism for every height-gated rule: a module resolves its height with
/// [`rules_for_genesis`] for the genesis the node actually loaded, and only falls back to
/// its per-chain pin table when that returns `None`. A field whose rule is not in this
/// build is a typed slot: it records the owner's schedule, and the PR that adds the rule
/// reads it from here (see [`GenesisActivations::WIRED`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisActivations {
    /// Block-validity hardening (this module, `PINNED_ACTIVATIONS`).
    pub pba_hardening: Option<u64>,
    /// Exact created code (`citrate_execution::exact_code`).
    pub exact_create_code: Option<u64>,
    /// Canonical ECVRF point encoding (`crate::vrf_encoding`, resolved through its
    /// `pin_for_genesis`).
    pub vrf_canonical_encoding: Option<u64>,
    /// Storage root from the slot set (`citrate_execution::storage_root_hardening`,
    /// resolved through its `pin_for_genesis`).
    pub storage_root_hardening: Option<u64>,
    /// Journaled fee settlement, rewards from executed state and journaled in-tx writes,
    /// one height (`citrate_execution::supply_hardening`, resolved through its
    /// `pin_for_genesis`).
    pub supply_hardening: Option<u64>,
}

impl GenesisActivations {
    /// Every rule, by name, with its height, in a fixed order (for logs and the
    /// consensus fingerprint).
    pub fn entries(&self) -> [(&'static str, Option<u64>); 5] {
        [
            ("pba_hardening", self.pba_hardening),
            ("exact_create_code", self.exact_create_code),
            ("vrf_canonical_encoding", self.vrf_canonical_encoding),
            ("storage_root_hardening", self.storage_root_hardening),
            ("supply_hardening", self.supply_hardening),
        ]
    }

    /// The rules this build enforces from these heights. The others are recorded only,
    /// until their module (a separate PR) consults [`rules_for_genesis`].
    pub const WIRED: &'static [&'static str] = &[
        "pba_hardening",
        "exact_create_code",
        "vrf_canonical_encoding",
        "storage_root_hardening",
        "supply_hardening",
    ];
}

/// r1006's rules: the owner's decision (2026-10-26) is EVERY new hardening rule active
/// from the first block after genesis. ONE place: changing a rule's schedule for r1006 is
/// a one-line change here (and moves the consensus fingerprint).
pub const R1006_ACTIVATIONS: GenesisActivations = GenesisActivations {
    pba_hardening: Some(0),
    exact_create_code: Some(0),
    vrf_canonical_encoding: Some(0),
    storage_root_hardening: Some(0),
    supply_hardening: Some(0),
};

/// Per-genesis activations compiled into this release, keyed by (chain id, block-0 hash),
/// beside [`RELEASE_GENESIS`]. The ONLY place a new rule gets a height: r1005's genesis has
/// no entry, so every new rule stays unset there (replay-identical).
pub const GENESIS_ACTIVATIONS: &[(u64, [u8; 32], GenesisActivations)] =
    &[(40204, R1006_GENESIS, R1006_ACTIVATIONS)];

/// The genesis-keyed rules for a node on `chain_id` whose loaded block 0 is `genesis`:
///
/// * the (chain id, genesis) pair of a compiled entry (40204 + r1006's block 0): `Some`
///   of its activations (a per-chain pin never overrides them);
/// * any other genesis, including r1005's and an unknown one: `None`, explicitly. The
///   module then uses its per-chain pin table exactly as before, so an r1005 node rebuilt
///   from this release replays its chain unchanged.
///
/// An unknown genesis on 40204 gets `None` rather than a refusal: the r1006 ceremony
/// devnet and every local rehearsal run 40204 with their own genesis, and such a node
/// cannot pass for a release network (the handshake compares genesis hashes, and
/// `check_genesis_chain` binds the release geneses to their chain). A node that asks
/// for the r1006 profile but loads another genesis IS refused, by the node at start-up.
pub fn rules_for_genesis(chain_id: u64, genesis: &[u8; 32]) -> Option<GenesisActivations> {
    GENESIS_ACTIVATIONS
        .iter()
        .find(|(c, g, _)| *c == chain_id && g == genesis)
        .map(|(_, _, a)| *a)
}

/// The schedule a genesis-keyed rule resolves with, as the `pin` its module's resolver
/// takes (`Option<Option<u64>>`), from the ONE shared table [`GENESIS_ACTIVATIONS`]:
///
/// * `Some(h)` inside `Some`: the (chain id, genesis) pair has a compiled entry; the rule's
///   height there is the pin, and a per-node env/config value must agree with it;
/// * `Some(None)`: a release chain id on one of its release geneses without an entry
///   (r1005), or with no genesis known yet: the rule is not scheduled and a per-node
///   height is refused (it would fork the node off that chain);
/// * `None`: any other genesis (the r1006 build devnet, a local rehearsal): not a release
///   chain, so the env/config value decides.
///
/// There are no per-module chain-id pin tables for these rules; a tripwire
/// (`scripts/ci/genesis_keyed_pins_tripwire.sh`) keeps it that way.
pub fn genesis_rule_pin(
    chain_id: u64,
    genesis: Option<&[u8; 32]>,
    rule: fn(&GenesisActivations) -> Option<u64>,
) -> Option<Option<u64>> {
    if let Some(g) = genesis {
        if let Some(a) = rules_for_genesis(chain_id, g) {
            return Some(rule(&a));
        }
    }
    let on_release_genesis = match genesis {
        None => true,
        Some(g) => RELEASE_GENESIS
            .iter()
            .any(|(c, r)| *c == chain_id && r == g),
    };
    if is_release_network(chain_id) && on_release_genesis {
        Some(None)
    } else {
        None
    }
}

/// The activations compiled for `genesis` on any chain id (logs and the fingerprint).
/// Rule resolution uses [`rules_for_genesis`] / [`genesis_rule_pin`], which also match the chain id.
pub fn genesis_activations(genesis: &[u8; 32]) -> Option<GenesisActivations> {
    GENESIS_ACTIVATIONS
        .iter()
        .find(|(_, g, _)| g == genesis)
        .map(|(_, _, a)| *a)
}

/// Canonical blocks compiled into this release, by release genesis: at each
/// listed height the listed hash is the only block a node admits, so any other
/// block at that height, and everything built on it, is refused from any peer.
///
/// An operator rollback (`citrate rollback`) records the withdrawn blocks only
/// in the database of the node it ran on. A checkpoint carries the same
/// decision to every node built from this release: a fresh node, a desktop
/// node, or a fleet node restored from a copy.
///
/// 40204 (testnet_beta genesis): the 2026-10-15 rollback kept 365,784 =
/// `0x63dcd4a8…2c56`; the network continued with 365,785 = `0x51482ff9…f3d2`.
/// Heights are strictly increasing per genesis.
pub const CANONICAL_CHECKPOINTS: &[([u8; 32], u64, [u8; 32])] = &[
    (
        hex32("1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"),
        365_784,
        hex32("63dcd4a8c7cd701080e242e5949402da93143bfd0659b3012e57998da4aa2c56"),
    ),
    (
        hex32("1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"),
        365_785,
        hex32("51482ff9724a2f0cbf4fe678f3ce556f6222334d5b2a3f5eba8a2b52af0cf3d2"),
    ),
];

/// The canonical checkpoints for the chain whose genesis block is `genesis`,
/// as `(height, hash)` in height order; empty for any other genesis.
pub fn canonical_checkpoints(genesis: &[u8; 32]) -> Vec<(u64, [u8; 32])> {
    CANONICAL_CHECKPOINTS
        .iter()
        .filter(|(g, _, _)| g == genesis)
        .map(|(_, h, b)| (*h, *b))
        .collect()
}

// INVARIANT: compile-time only. Every call is inside a `const` item, so a bad
// literal is a BUILD error, never a runtime panic. Pinned by the build itself and
// by the release-genesis constants test in this module.
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
const fn hex32(s: &str) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex32: lowercase hex only"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex32: 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Whether `chain_id` is a release network: one this release lists in
/// [`PINNED_ACTIVATIONS`], whether or not its height is set yet.
pub fn is_release_network(chain_id: u64) -> bool {
    PINNED_ACTIVATIONS.iter().any(|(id, _)| *id == chain_id)
}

/// A release network's genesis must run under that network's chain id.
pub fn check_genesis_chain(chain_id: u64, genesis: &[u8; 32]) -> Result<(), String> {
    match RELEASE_GENESIS.iter().find(|(_, g)| g == genesis) {
        Some((network, _)) if *network != chain_id => Err(format!(
            "this data directory holds the genesis of chain {network}, but the node is \
             configured for chain {chain_id}. Set [chain] chain_id = {network}, or use a \
             data directory with its own genesis for a different chain."
        )),
        _ => Ok(()),
    }
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
    /// The node runs a dev profile (only possible on a non-release chain).
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
            ", dev profile"
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
        format!(
            "0x{}",
            d.first_chunk::<16>().map(hex::encode).unwrap_or_default()
        )
    }
}

/// Resolve the activation height from its three inputs. Pure: the caller
/// supplies the pin, the raw env value and the config value.
///
/// * A dev profile on a pinned chain: refused. Dev profiles run on their own
///   chain id.
/// * A chain with no pin: the legacy order. The env
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
    if dev_profile && pin.is_some() {
        return Err(dev_profile_refusal());
    }
    match pin {
        Some(p) => {
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

fn dev_profile_refusal() -> String {
    "[chain] dev_profile = true is not allowed on a release network. Dev profiles run on \
     their own chain id (the shipped ones use 1337); remove dev_profile to join this \
     network."
        .to_string()
}

/// Resolve for the running chain: the release pin for `chain_id`, the env
/// override and the config value (see [`resolve_activation`]). `chain_id`
/// must be the node's configured chain id.
pub fn resolve_pba_hardening_for_chain(
    chain_id: u64,
    config_value: Option<u64>,
    dev_profile: bool,
) -> Result<ResolvedActivation, String> {
    if dev_profile && is_release_network(chain_id) {
        return Err(format!("chain {chain_id}: {}", dev_profile_refusal()));
    }
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

/// [`init_pba_hardening_for_chain`], but a per-genesis pin ([`genesis_activations`])
/// replaces the chain-id pin. The node calls this once it knows its block 0.
pub fn init_pba_hardening_for_genesis(
    chain_id: u64,
    genesis: Option<&GenesisActivations>,
    config_value: Option<u64>,
    dev_profile: bool,
) -> Result<ResolvedActivation, String> {
    let Some(g) = genesis else {
        return init_pba_hardening_for_chain(chain_id, config_value, dev_profile);
    };
    if dev_profile {
        return Err(format!("chain {chain_id}: {}", dev_profile_refusal()));
    }
    let env_raw = match std::env::var(PBA_HARDENING_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => return Err(format!("{PBA_HARDENING_ENV}: {e}")),
    };
    let (height, source) =
        resolve_activation(g.pba_hardening, env_raw.as_deref(), config_value, false)?;
    set_pba_hardening_height(height);
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
    fn dev_profile_is_refused_on_a_pinned_chain() {
        for (env, cfg) in [
            (None, Some(0)),
            (Some("3"), Some(0)),
            (None, None),
            (Some("500"), None),
        ] {
            let e = resolve_activation(PIN, env, cfg, true).unwrap_err();
            assert!(e.contains("dev_profile"), "{e}");
        }
        // A chain with no pin keeps the legacy order for dev profiles.
        assert_eq!(
            resolve_activation(None, None, Some(0), true),
            Ok((Some(0), ActivationSource::Config))
        );
    }

    #[test]
    fn dev_profile_is_refused_on_every_release_network_even_before_it_is_pinned() {
        // 40204 is a release network whether or not its height is set yet.
        assert!(is_release_network(40204));
        assert!(!is_release_network(1337));
        std::env::remove_var(PBA_HARDENING_ENV);
        let e = resolve_pba_hardening_for_chain(40204, Some(0), true).unwrap_err();
        assert!(e.contains("dev_profile") && e.contains("40204"), "{e}");
        let ok = resolve_pba_hardening_for_chain(1337, Some(0), true).expect("dev chain");
        assert_eq!(ok.height, Some(0));
    }

    #[test]
    fn release_genesis_hex_decodes_exactly() {
        let mut want = [0u8; 32];
        for (i, b) in want.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(9);
        }
        let text: String = want.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex32(&text), want);
        assert_eq!(
            hex32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")[..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(RELEASE_GENESIS[0].1[..4], [0x1d, 0xcf, 0xc4, 0x90]);
        assert_eq!(RELEASE_GENESIS[0].1[31], 0xf1);
    }

    #[test]
    fn a_release_genesis_only_runs_under_its_own_chain_id() {
        let (id, g) = RELEASE_GENESIS[0];
        assert_eq!(check_genesis_chain(id, &g), Ok(()));
        let e = check_genesis_chain(id + 1, &g).unwrap_err();
        assert!(e.contains(&id.to_string()), "{e}");
        assert!(check_genesis_chain(1337, &g).is_err());
        // Any other genesis (a local dev chain) is unconstrained.
        assert_eq!(check_genesis_chain(1337, &[0x42; 32]), Ok(()));
        assert_eq!(check_genesis_chain(40204, &[0x42; 32]), Ok(()));
        for (id, g) in RELEASE_GENESIS {
            assert!(is_release_network(*id));
            assert_eq!(check_genesis_chain(*id, g), Ok(()));
        }
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

    /// The reroll starts 40204 with the hardening on: every block after genesis
    /// is judged by the hardened rules, and genesis itself never is.
    #[test]
    fn chain_40204_hardening_active_from_genesis() {
        assert_eq!(pinned_activation(40204), Some(0));
        let (height, source) = resolve_activation(pinned_activation(40204), None, None, false)
            .expect("pinned chain resolves");
        assert_eq!((height, source), (Some(0), ActivationSource::ReleasePin));
        let h = PbaHardening::at(0);
        assert!(!h.active_at(0), "genesis is never re-judged");
        assert!(h.active_at(1));
        assert!(h.active_at(u64::MAX));
        // A host value that disagrees with the pin still refuses to start.
        assert!(resolve_activation(Some(0), Some("247436"), None, false).is_err());
        assert!(resolve_activation(Some(0), Some("off"), None, false).is_err());
        assert!(resolve_activation(Some(0), None, Some(247_436), false).is_err());
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

    #[test]
    fn the_40204_genesis_pins_the_block_above_the_rollback_cut() {
        let g = RELEASE_GENESIS[0].1;
        let cps = canonical_checkpoints(&g);
        assert_eq!(
            cps,
            vec![
                (
                    365_784,
                    hex32("63dcd4a8c7cd701080e242e5949402da93143bfd0659b3012e57998da4aa2c56")
                ),
                (
                    365_785,
                    hex32("51482ff9724a2f0cbf4fe678f3ce556f6222334d5b2a3f5eba8a2b52af0cf3d2")
                ),
            ],
            "365,784 is the kept block of the 2026-10-15 rollback; 365,785 the first block on it"
        );
    }

    #[test]
    fn r1006_rules_are_keyed_by_its_genesis_not_by_the_chain_id() {
        let r1005 = RELEASE_GENESIS[0].1;
        assert_ne!(R1006_GENESIS, r1005, "r1006 has its own block 0");
        assert_eq!(genesis_activations(&R1006_GENESIS), Some(R1006_ACTIVATIONS));
        assert_eq!(
            genesis_activations(&r1005),
            None,
            "r1006's rules never reach r1005"
        );
        assert!(
            canonical_checkpoints(&R1006_GENESIS).is_empty(),
            "r1005's compiled checkpoints never reach r1006"
        );
        assert!(RELEASE_GENESIS.contains(&(40204, R1006_GENESIS)));
        for (name, h) in R1006_ACTIVATIONS.entries() {
            assert_eq!(
                h,
                Some(0),
                "{name}: the owner set every new rule to 0 on r1006"
            );
        }
        let names: Vec<&str> = R1006_ACTIVATIONS.entries().iter().map(|e| e.0).collect();
        assert_eq!(
            names,
            [
                "pba_hardening",
                "exact_create_code",
                "vrf_canonical_encoding",
                "storage_root_hardening",
                "supply_hardening"
            ]
        );
        for w in GenesisActivations::WIRED {
            assert!(
                R1006_ACTIVATIONS.entries().iter().any(|(n, _)| n == w),
                "{w} is a field"
            );
        }
    }

    /// r1005's genesis on the new binary: no genesis-keyed rule, so every module keeps its
    /// per-chain pin (the new rules stay unset: replay-identical). r1006's genesis: every
    /// rule at 0. An unknown genesis on 40204: `None`, explicitly.
    #[test]
    fn genesis_keyed_rules_r1005_none_r1006_zero_unknown_none() {
        let r1005 = RELEASE_GENESIS[0].1;
        assert_eq!(rules_for_genesis(40204, &r1005), None);
        for (_, g) in RELEASE_GENESIS.iter().filter(|(_, g)| *g != R1006_GENESIS) {
            assert_eq!(rules_for_genesis(40204, g), None, "{}", hex::encode(g));
        }
        let r = rules_for_genesis(40204, &R1006_GENESIS).expect("r1006 has rules");
        assert!(r.entries().iter().all(|(_, h)| *h == Some(0)), "{r:?}");
        assert_eq!(
            rules_for_genesis(40204, &[0x42; 32]),
            None,
            "unknown genesis"
        );
        assert_eq!(
            rules_for_genesis(1337, &R1006_GENESIS),
            None,
            "keyed by (chain id, genesis): r1006's block 0 under another chain id gets nothing"
        );
    }

    #[test]
    fn genesis_rule_pin_r1005_refuses_r1006_zero_unknown_local() {
        let exact = |a: &GenesisActivations| a.exact_create_code;
        let r1005 = RELEASE_GENESIS[0].1;
        assert_eq!(
            genesis_rule_pin(40204, Some(&r1005), exact),
            Some(None),
            "r1005: unset, per-node refused"
        );
        assert_eq!(
            genesis_rule_pin(40204, None, exact),
            Some(None),
            "no genesis known"
        );
        assert_eq!(
            genesis_rule_pin(40204, Some(&R1006_GENESIS), exact),
            Some(Some(0)),
            "r1006: 0"
        );
        assert_eq!(
            genesis_rule_pin(40204, Some(&[0x42; 32]), exact),
            None,
            "unknown: local"
        );
        assert_eq!(
            genesis_rule_pin(1337, None, exact),
            None,
            "dev chain: local"
        );
        let picks: [fn(&GenesisActivations) -> Option<u64>; 3] = [
            |a| a.vrf_canonical_encoding,
            |a| a.storage_root_hardening,
            |a| a.supply_hardening,
        ];
        for pick in picks {
            assert_eq!(
                genesis_rule_pin(40204, Some(&R1006_GENESIS), pick),
                Some(Some(0))
            );
            assert_eq!(genesis_rule_pin(40204, Some(&r1005), pick), Some(None));
        }
    }

    #[test]
    fn a_genesis_pin_refuses_a_disagreeing_config() {
        let g = R1006_ACTIVATIONS;
        assert_eq!(
            resolve_activation(g.pba_hardening, None, Some(5), false).map(|r| r.0),
            Err(resolve_activation(Some(0), None, Some(5), false)
                .err()
                .unwrap_or_default())
        );
        assert_eq!(
            resolve_activation(g.pba_hardening, None, Some(0), false),
            Ok((Some(0), ActivationSource::ReleasePin))
        );
        assert!(init_pba_hardening_for_genesis(40204, Some(&g), None, true).is_err());
    }

    #[test]
    fn another_genesis_has_no_checkpoints() {
        assert!(canonical_checkpoints(&[0x5A; 32]).is_empty());
        for (_, g) in &RELEASE_GENESIS[1..] {
            assert!(
                canonical_checkpoints(g).is_empty(),
                "only the live 40204 genesis is pinned"
            );
        }
    }

    #[test]
    fn checkpoint_heights_are_strictly_increasing_per_genesis() {
        for (g, _, _) in CANONICAL_CHECKPOINTS {
            let hs: Vec<u64> = canonical_checkpoints(g).iter().map(|(h, _)| *h).collect();
            assert!(hs.windows(2).all(|w| w[0] < w[1]), "{hs:?}");
            assert!(
                RELEASE_GENESIS.iter().any(|(_, r)| r == g),
                "a checkpoint names a release genesis"
            );
        }
    }
}
