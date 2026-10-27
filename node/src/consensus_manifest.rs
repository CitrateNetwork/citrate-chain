//! Consensus-alignment manifest (package-alignment hardening).
//!
//! Two Citrate node binaries produce identical state roots ONLY if they share the
//! same consensus code, the same consensus-affecting build features, and the same
//! consensus constants. The app-bundled node and the DigitalOcean fleet producer
//! have silently drifted before — computing different roots at the VALIDATOR-S1
//! activation and wedging every cold-syncing node (the 2,580 divergence class).
//!
//! This manifest makes that drift VISIBLE and diffable. `citrate consensus --json`
//! on any binary prints a stable, self-describing stamp; two binaries with the same
//! `fingerprint` are consensus-aligned. The reroll ceremony diffs the app binary's
//! fingerprint against the fleet binary's before trusting them to co-produce.
//!
//! NOTE: this stamp covers the *compile-time* consensus surface (code + features +
//! constants). The *runtime* consensus env — `CITRATE_VALIDATOR_REGISTRY`,
//! `CITRATE_VALIDATOR_ACTIVATION_HEIGHT`, `CITRATE_BLOCK_V2`, chain id — is supplied
//! per process; the fleet-alignment contract for those lives in the app spawn
//! (`citrate-core/src-tauri/src/node.rs`) and the reroll runbook.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::registry_sync::{EPOCH, SNAPSHOT_LAG};
use citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS;

/// Every value the consensus fingerprint is computed from. The fingerprint is a
/// pure function of these fields (see [`fingerprint_preimage`]), so tests can vary
/// one input at a time, including the compile-time feature flags.
#[derive(Debug, Clone, Copy)]
pub struct FingerprintInputs<'a> {
    pub git_sha: &'a str,
    pub feat_halo2_verifier: bool,
    /// Rendered as the 0x0130 mode: `gated` when compiled in, else `absent`.
    pub feat_commd_fold_verify: bool,
    pub activation_gated: &'a [&'a str],
    pub pba_hardening_height: Option<u64>,
    pub agent_precompiles_height: Option<u64>,
    /// Appended to the pre-image only when set (chain#387).
    pub exact_create_code_height: Option<u64>,
    /// Appended to the pre-image only when set (chain#384).
    pub vrf_canonical_encoding_height: Option<u64>,
    /// Appended to the pre-image only when set (chain#391).
    pub supply_hardening_height: Option<u64>,
    /// Appended to the pre-image only when set (chain#392).
    pub storage_root_hardening_height: Option<u64>,
    pub value_transfer_activation_height: u64,
    pub create_nonce_fix_activation_height: u64,
    pub merge_depth_activation_height: u64,
    pub canonical_base_fee_per_gas: u64,
    pub epoch: u64,
    pub snapshot_lag: u64,
    /// The chain this process runs: `(block-0 hash hex, per-genesis rule schedule)`, set
    /// only for a genesis with compiled per-genesis rules (r1006). `None` otherwise (r1005,
    /// any other genesis, or no chain bound): the pre-image is then exactly the v3 one,
    /// byte-identical to the unbound form. `Some` switches the tag to v4 and appends the
    /// binding, so two binaries aligned on code but run against r1005 and r1006 (which
    /// share chain id 40204) print different fingerprints. The configured profile NAME is
    /// never part of it: two nodes on the same block 0 agree whatever they call it.
    pub genesis_binding: Option<GenesisBinding<'a>>,
}

/// See [`FingerprintInputs::genesis_binding`].
#[derive(Debug, Clone, Copy)]
pub struct GenesisBinding<'a> {
    pub genesis_hash: &'a str,
    /// `name:height|...` from the genesis's compiled activations (`-` for none).
    pub genesis_rules: &'a str,
}

/// Canonical, order-stable pre-image of the consensus-affecting surface.
/// Deliberately EXCLUDES build_target (arch must not change consensus) and
/// git_dirty (provenance, surfaced separately as a hard blocker).
///
/// v2 pre-image: v1's fields, with 0x0130 reported as activation-gated and the
/// gated rule set listed, so a diff against a v1 (fleet) manifest shows exactly
/// which differences wait for the height. Changing this text changes every
/// fingerprint: `fingerprint_golden_vector_is_pinned` fails until it is updated
/// on purpose.
pub fn fingerprint_preimage(i: &FingerprintInputs<'_>) -> String {
    let commd_mode = if i.feat_commd_fold_verify {
        "gated"
    } else {
        "absent"
    };
    let preimage = format!(
        "citrate-consensus-v3\ngit_sha={}\nhalo2_verifier={}\n\
         commd_fold_verify={commd_mode}\nactivation_gated={}\n\
         pba_hardening_height={}\n\
         value_transfer_height={}\n\
         create_nonce_fix_height={}\n\
         merge_depth_height={}\n\
         base_fee={}\nepoch={}\nsnapshot_lag={}\n",
        i.git_sha,
        i.feat_halo2_verifier,
        i.activation_gated.join("|"),
        i.pba_hardening_height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "unset".to_string()),
        i.value_transfer_activation_height,
        i.create_nonce_fix_activation_height,
        i.merge_depth_activation_height,
        i.canonical_base_fee_per_gas,
        i.epoch,
        i.snapshot_lag,
    );
    // HUP-S7.2: appended only when scheduled, so an unset fork keeps the
    // pre-image (and the fingerprint) byte-identical to the previous form.
    let preimage = match i.agent_precompiles_height {
        Some(h) => format!("{preimage}agent_precompiles_height={h}\n"),
        None => preimage,
    };
    // Likewise appended only when scheduled.
    let preimage = match i.exact_create_code_height {
        Some(h) => format!("{preimage}exact_create_code_height={h}\n"),
        None => preimage,
    };
    let preimage = match i.vrf_canonical_encoding_height {
        Some(h) => format!("{preimage}vrf_canonical_encoding_height={h}\n"),
        None => preimage,
    };
    let preimage = match i.supply_hardening_height {
        Some(h) => format!("{preimage}supply_hardening_height={h}\n"),
        None => preimage,
    };
    let preimage = match i.storage_root_hardening_height {
        Some(h) => format!("{preimage}storage_root_hardening_height={h}\n"),
        None => preimage,
    };
    match i.genesis_binding {
        None => preimage,
        Some(b) => format!(
            "citrate-consensus-v4{}genesis_hash={}\ngenesis_rules={}\n",
            preimage
                .strip_prefix("citrate-consensus-v3")
                .unwrap_or(&preimage),
            b.genesis_hash,
            b.genesis_rules
        ),
    }
}

/// `0x` + the first 16 bytes of sha256 over [`fingerprint_preimage`].
pub fn fingerprint_of(i: &FingerprintInputs<'_>) -> String {
    let digest = Sha256::digest(fingerprint_preimage(i).as_bytes());
    format!("0x{}", hex::encode(digest.get(..16).unwrap_or(&digest)))
}

/// The compile-time consensus surface of this binary.
#[derive(Debug, Clone, Serialize)]
pub struct ConsensusManifest {
    /// Crate version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Short git commit the binary was built from (`unknown` if git was absent).
    pub git_sha: &'static str,
    /// `true` if the working tree had uncommitted tracked changes at build time.
    /// A dirty build is NOT reproducibly aligned and must never co-produce.
    pub git_dirty: bool,
    /// Build target triple (e.g. `x86_64-unknown-linux-gnu` vs
    /// `aarch64-apple-darwin`) — recorded for provenance, NOT part of the
    /// consensus fingerprint (cross-arch builds are required to agree).
    pub build_target: &'static str,
    /// halo2-verifier feature: changes 0x0108 precompile behaviour. Mixed on/off
    /// builds diverge on any tx that exercises the ZK verifier. Consensus-affecting.
    pub feat_halo2_verifier: bool,
    /// commd-fold-verify feature compiled in. Its 0x0130 behaviour is
    /// activation-gated: below `pba_hardening_height` 0x0130 behaves exactly
    /// like a build without the feature (the 40204 fleet), so this flag alone
    /// does not change historical replay.
    pub feat_commd_fold_verify: bool,
    /// Execution behaviours that differ from the fleet build only at/after the
    /// activation height (`citrate_execution::build_features::ACTIVATION_GATED`).
    pub activation_gated: Vec<&'static str>,
    /// The activation height this process resolved (`None` = legacy rules
    /// everywhere; set by start_node before the manifest is printed, or by
    /// `CITRATE_PBA_HARDENING_HEIGHT` for `citrate consensus`).
    pub pba_hardening_height: Option<u64>,
    /// HUP-S7.2: the agent precompile fork height this process resolved
    /// (`citrate_execution::agent_fork`; `None` = not activated). Part of the
    /// fingerprint only when set, so an unscheduled fork leaves the pre-image
    /// exactly as it was.
    pub agent_precompiles_height: Option<u64>,
    /// The exact-created-code height this process resolved
    /// (`citrate_execution::exact_code`; `None` = not activated, created code
    /// is stored in the legacy padded form). Part of the fingerprint only when
    /// set, so an unscheduled rule leaves the pre-image exactly as it was.
    pub exact_create_code_height: Option<u64>,
    /// The canonical ECVRF proof encoding height this process resolved
    /// (`citrate_consensus::vrf_encoding`; `None` = not activated). Part of
    /// the fingerprint only when set, so an unscheduled rule leaves the
    /// pre-image exactly as it was.
    pub vrf_canonical_encoding_height: Option<u64>,
    /// Supply hardening fork height (`citrate_execution::supply_hardening`);
    /// `None` = not activated. Part of the fingerprint only when set.
    pub supply_hardening_height: Option<u64>,
    /// Storage-root hardening fork height
    /// (`citrate_execution::storage_root_hardening`); `None` = not activated.
    /// Part of the fingerprint only when set.
    pub storage_root_hardening_height: Option<u64>,
    /// Execution/consensus rules that switch on by height, as this process
    /// resolved them (compiled default or devnet env override). A node whose
    /// env overrides one of these computes different roots, so they are in the
    /// fingerprint.
    pub value_transfer_activation_height: u64,
    pub create_nonce_fix_activation_height: u64,
    pub merge_depth_activation_height: u64,
    /// Canonical EIP-1559 base fee committed into every block (reroll constant).
    pub canonical_base_fee_per_gas: u64,
    /// Validator-registry snapshot epoch length (blocks).
    pub epoch: u64,
    /// Validator-registry snapshot lag (blocks before the epoch boundary).
    pub snapshot_lag: u64,
    /// The genesis profile named in this process's config. Display only: NOT part of the
    /// fingerprint (see [`FingerprintInputs::genesis_binding`]).
    pub genesis_profile: Option<String>,
    /// Block-0 hash this process runs (`None` = not known). Part of the fingerprint only
    /// when the genesis has compiled per-genesis rules (`genesis_rules` is then set).
    pub genesis_hash: Option<String>,
    /// The genesis's compiled rule schedule (`name:height|...`), when bound.
    pub genesis_rules: Option<String>,
    /// Stable hash over the consensus-affecting fields (NOT build_target). Two
    /// binaries with equal fingerprints compute equal state roots for equal input.
    pub fingerprint: String,
}

impl ConsensusManifest {
    pub fn current() -> Self {
        let height = citrate_consensus::hardening::pba_hardening_height().or_else(|| {
            citrate_consensus::hardening::resolve_pba_hardening_height(None)
                .ok()
                .flatten()
        });
        Self::for_height(height)
    }

    /// The manifest for this binary under a given PBA height (every other height is
    /// read from its process store).
    pub fn for_height(pba_hardening_height: Option<u64>) -> Self {
        Self::for_heights(
            pba_hardening_height,
            citrate_execution::agent_fork::agent_precompiles_height(),
        )
    }

    /// Explicit PBA and agent-fork heights; the rest from the process stores.
    pub fn for_heights(
        pba_hardening_height: Option<u64>,
        agent_precompiles_height: Option<u64>,
    ) -> Self {
        Self::for_activations(
            pba_hardening_height,
            agent_precompiles_height,
            citrate_execution::exact_code::exact_create_code_height(),
        )
    }

    /// Explicit PBA, agent-fork, supply and storage-root heights (chain#391/#392 tests).
    #[cfg(test)]
    pub fn for_supply_heights(
        pba_hardening_height: Option<u64>,
        agent_precompiles_height: Option<u64>,
        supply_hardening_height: Option<u64>,
        storage_root_hardening_height: Option<u64>,
    ) -> Self {
        Self::for_all(
            pba_hardening_height,
            agent_precompiles_height,
            citrate_execution::exact_code::exact_create_code_height(),
            citrate_consensus::vrf_encoding::vrf_canonical_encoding_height(),
            supply_hardening_height,
            storage_root_hardening_height,
        )
    }

    /// Explicit PBA, agent-fork and exact-created-code heights.
    pub fn for_activations(
        pba_hardening_height: Option<u64>,
        agent_precompiles_height: Option<u64>,
        exact_create_code_height: Option<u64>,
    ) -> Self {
        Self::for_every_height(
            pba_hardening_height,
            agent_precompiles_height,
            exact_create_code_height,
            citrate_consensus::vrf_encoding::vrf_canonical_encoding_height(),
        )
    }

    /// Explicit PBA, agent, exact-code and VRF heights; supply and storage-root from
    /// their process stores.
    pub fn for_every_height(
        pba_hardening_height: Option<u64>,
        agent_precompiles_height: Option<u64>,
        exact_create_code_height: Option<u64>,
        vrf_canonical_encoding_height: Option<u64>,
    ) -> Self {
        Self::for_all(
            pba_hardening_height,
            agent_precompiles_height,
            exact_create_code_height,
            vrf_canonical_encoding_height,
            citrate_execution::supply_hardening::supply_hardening_height(),
            citrate_execution::storage_root_hardening::storage_root_hardening_height(),
        )
    }

    /// The manifest under every explicit activation height.
    pub fn for_all(
        pba_hardening_height: Option<u64>,
        agent_precompiles_height: Option<u64>,
        exact_create_code_height: Option<u64>,
        vrf_canonical_encoding_height: Option<u64>,
        supply_hardening_height: Option<u64>,
        storage_root_hardening_height: Option<u64>,
    ) -> Self {
        let version = env!("CARGO_PKG_VERSION");
        let git_sha = env!("CITRATE_GIT_SHA");
        let git_dirty = env!("CITRATE_GIT_DIRTY") == "1";
        let build_target = env!("CITRATE_BUILD_TARGET");
        // PBA-L1a-003: read the execution crate's actual feature set (a
        // dependency-feature build does not show up in this crate's cargo
        // features), OR-ed with this crate's own forwarding features.
        let feat_halo2_verifier =
            env!("CITRATE_FEAT_HALO2") == "1" || citrate_execution::build_features::HALO2_SUBSTRATE;
        let feat_commd_fold_verify = env!("CITRATE_FEAT_COMMD_FOLD") == "1"
            || citrate_execution::build_features::COMMD_FOLD_VERIFY;

        // The pre-image is built by `fingerprint_preimage` from these values only.
        let activation_gated: Vec<&'static str> =
            citrate_execution::build_features::ACTIVATION_GATED.to_vec();
        let value_transfer_activation_height =
            citrate_execution::executor::value_transfer_activation_height();
        let create_nonce_fix_activation_height =
            citrate_execution::executor::create_nonce_fix_activation_height();
        let merge_depth_activation_height =
            citrate_consensus::ghostdag::merge_depth_activation_height();
        let fingerprint = fingerprint_of(&FingerprintInputs {
            git_sha,
            feat_halo2_verifier,
            feat_commd_fold_verify,
            activation_gated: &activation_gated,
            pba_hardening_height,
            agent_precompiles_height,
            exact_create_code_height,
            vrf_canonical_encoding_height,
            supply_hardening_height,
            storage_root_hardening_height,
            value_transfer_activation_height,
            create_nonce_fix_activation_height,
            merge_depth_activation_height,
            canonical_base_fee_per_gas: CANONICAL_BASE_FEE_PER_GAS,
            epoch: EPOCH,
            snapshot_lag: SNAPSHOT_LAG,
            genesis_binding: None,
        });

        Self {
            version,
            git_sha,
            git_dirty,
            build_target,
            feat_halo2_verifier,
            feat_commd_fold_verify,
            activation_gated,
            pba_hardening_height,
            agent_precompiles_height,
            exact_create_code_height,
            vrf_canonical_encoding_height,
            supply_hardening_height,
            storage_root_hardening_height,
            value_transfer_activation_height,
            create_nonce_fix_activation_height,
            merge_depth_activation_height,
            canonical_base_fee_per_gas: CANONICAL_BASE_FEE_PER_GAS,
            epoch: EPOCH,
            snapshot_lag: SNAPSHOT_LAG,
            genesis_profile: None,
            genesis_hash: None,
            genesis_rules: None,
            fingerprint,
        }
    }

    /// THE manifest a node reports, in its boot log, its node-identity RPC and
    /// `citrate consensus`: every height from its process store (published at start-up),
    /// bound (v4) to the genesis the node runs when that genesis has compiled per-genesis
    /// rules. The profile name and an unscheduled genesis's hash are recorded for display
    /// only, so they never move the fingerprint.
    pub fn for_node(profile: Option<&str>, genesis: Option<&[u8; 32]>) -> Self {
        let mut m = match genesis {
            Some(g) if citrate_consensus::hardening::genesis_activations(g).is_some() => {
                Self::current().bound(g)
            }
            Some(g) => {
                let mut m = Self::current();
                m.genesis_hash = Some(format!("0x{}", hex::encode(g)));
                m
            }
            None => Self::current(),
        };
        m.genesis_profile = profile.map(str::to_string);
        m
    }

    /// The rule schedule string for a genesis (`-` when it has no compiled activations).
    pub fn genesis_rules_of(genesis: &[u8; 32]) -> String {
        match citrate_consensus::hardening::genesis_activations(genesis) {
            None => "-".to_string(),
            Some(a) => a
                .entries()
                .iter()
                .map(|(n, h)| {
                    format!(
                        "{n}:{}",
                        h.map(|h| h.to_string()).unwrap_or_else(|| "unset".into())
                    )
                })
                .collect::<Vec<_>>()
                .join("|"),
        }
    }

    /// This manifest bound to a chain: the v4 fingerprint over the same fields plus the
    /// block-0 hash and the genesis's compiled rule schedule.
    pub fn bound(mut self, genesis: &[u8; 32]) -> Self {
        let hash = format!("0x{}", hex::encode(genesis));
        let rules = Self::genesis_rules_of(genesis);
        self.fingerprint = fingerprint_of(&FingerprintInputs {
            git_sha: self.git_sha,
            feat_halo2_verifier: self.feat_halo2_verifier,
            feat_commd_fold_verify: self.feat_commd_fold_verify,
            activation_gated: &self.activation_gated,
            pba_hardening_height: self.pba_hardening_height,
            agent_precompiles_height: self.agent_precompiles_height,
            exact_create_code_height: self.exact_create_code_height,
            vrf_canonical_encoding_height: self.vrf_canonical_encoding_height,
            supply_hardening_height: self.supply_hardening_height,
            storage_root_hardening_height: self.storage_root_hardening_height,
            value_transfer_activation_height: self.value_transfer_activation_height,
            create_nonce_fix_activation_height: self.create_nonce_fix_activation_height,
            merge_depth_activation_height: self.merge_depth_activation_height,
            canonical_base_fee_per_gas: self.canonical_base_fee_per_gas,
            epoch: self.epoch,
            snapshot_lag: self.snapshot_lag,
            genesis_binding: Some(GenesisBinding {
                genesis_hash: &hash,
                genesis_rules: &rules,
            }),
        });
        self.genesis_hash = Some(hash);
        self.genesis_rules = Some(rules);
        self
    }

    /// Human-readable stamp for `citrate consensus`.
    pub fn print_human(&self) {
        println!("citrate consensus manifest");
        println!("  version            {}", self.version);
        println!(
            "  git                {}{}",
            self.git_sha,
            if self.git_dirty { " (DIRTY)" } else { "" }
        );
        println!("  build target       {}", self.build_target);
        println!("  halo2-verifier     {}", self.feat_halo2_verifier);
        println!(
            "  commd-fold-verify  {} (0x0130 live only from the activation height)",
            self.feat_commd_fold_verify
        );
        println!(
            "  activation height  {}",
            self.pba_hardening_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "unset (legacy rules)".to_string())
        );
        println!(
            "  agent precompiles  {}",
            self.agent_precompiles_height
                .map(|h| format!("from height {h} (0x0112 0x0113 0x0121 0x0122)"))
                .unwrap_or_else(|| "not activated".to_string())
        );
        println!(
            "  exact create code  {}",
            self.exact_create_code_height
                .map(|h| format!("from height {h}"))
                .unwrap_or_else(|| "not activated (legacy padded form)".to_string())
        );
        println!(
            "  vrf encoding       {}",
            self.vrf_canonical_encoding_height
                .map(|h| format!("canonical from height {h}"))
                .unwrap_or_else(|| "not scheduled".to_string())
        );
        println!(
            "  supply hardening   {}",
            self.supply_hardening_height
                .map(|h| format!("from height {h}"))
                .unwrap_or_else(|| "not activated".to_string())
        );
        println!(
            "  storage root       {}",
            self.storage_root_hardening_height
                .map(|h| format!("hardened from height {h}"))
                .unwrap_or_else(|| "not activated".to_string())
        );
        println!(
            "  value transfer     from height {}",
            self.value_transfer_activation_height
        );
        println!(
            "  create-nonce fix   from height {}",
            self.create_nonce_fix_activation_height
        );
        println!(
            "  merge depth        from height {}",
            self.merge_depth_activation_height
        );
        for r in &self.activation_gated {
            println!("  gated              {r}");
        }
        println!(
            "  canonical base fee {} wei",
            self.canonical_base_fee_per_gas
        );
        println!(
            "  epoch / lag        {} / {}",
            self.epoch, self.snapshot_lag
        );
        if let Some(g) = &self.genesis_hash {
            let p = self.genesis_profile.as_deref().unwrap_or("-");
            println!("  genesis            {p} {g}");
            if let Some(r) = &self.genesis_rules {
                println!("  genesis rules      {r}");
            }
        }
        println!("  fingerprint        {}", self.fingerprint);
        if self.git_dirty {
            println!(
                "\n  WARNING: built from a DIRTY tree — not reproducibly aligned; \
                 do not co-produce with the fleet."
            );
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_prefixed() {
        let a = ConsensusManifest::for_height(None);
        let b = ConsensusManifest::for_height(None);
        assert_eq!(
            a.fingerprint, b.fingerprint,
            "fingerprint must be deterministic"
        );
        assert!(a.fingerprint.starts_with("0x"));
        assert_eq!(a.fingerprint.len(), 2 + 32, "16-byte hex fingerprint");
        assert_eq!(a.canonical_base_fee_per_gas, CANONICAL_BASE_FEE_PER_GAS);
        assert_eq!(a.epoch, EPOCH);
        assert_eq!(a.snapshot_lag, SNAPSHOT_LAG);
    }

    /// The resolved activation height is part of the fingerprint.
    #[test]
    fn fingerprint_depends_on_activation_height() {
        let a = ConsensusManifest::for_height(Some(123_456));
        let b = ConsensusManifest::for_height(Some(123_457));
        let u = ConsensusManifest::for_height(None);
        assert_eq!(a.pba_hardening_height, Some(123_456));
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_ne!(
            a.fingerprint, u.fingerprint,
            "unset differs from a scheduled height"
        );
        assert_eq!(
            a.fingerprint,
            ConsensusManifest::for_height(Some(123_456)).fingerprint
        );
    }

    /// HUP-S7.2: an unscheduled agent fork leaves the fingerprint exactly as
    /// before; a scheduled one is part of it.
    #[test]
    fn agent_fork_height_enters_the_fingerprint_only_when_set() {
        let unset = ConsensusManifest::for_supply_heights(Some(10), None, None, None);
        let a = ConsensusManifest::for_supply_heights(Some(10), Some(500), None, None);
        let b = ConsensusManifest::for_supply_heights(Some(10), Some(501), None, None);
        assert_eq!(a.agent_precompiles_height, Some(500));
        assert_ne!(a.fingerprint, unset.fingerprint);
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_eq!(
            unset.fingerprint,
            ConsensusManifest::for_supply_heights(Some(10), None, None, None).fingerprint
        );
    }

    #[test]
    fn supply_hardening_height_enters_the_fingerprint_only_when_scheduled() {
        let unset = ConsensusManifest::for_supply_heights(Some(10), None, None, None);
        let a = ConsensusManifest::for_supply_heights(Some(10), None, Some(700), None);
        let b = ConsensusManifest::for_supply_heights(Some(10), None, Some(701), None);
        assert_eq!(a.supply_hardening_height, Some(700));
        assert_ne!(a.fingerprint, unset.fingerprint);
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn storage_root_hardening_height_enters_the_fingerprint_only_when_scheduled() {
        let unset = ConsensusManifest::for_supply_heights(Some(10), None, None, None);
        let zero = ConsensusManifest::for_supply_heights(Some(10), None, None, Some(0));
        let later = ConsensusManifest::for_supply_heights(Some(10), None, None, Some(900));
        assert_eq!(zero.storage_root_hardening_height, Some(0));
        assert_ne!(zero.fingerprint, unset.fingerprint);
        assert_ne!(zero.fingerprint, later.fingerprint);
        // Distinct from the supply fork at the same height.
        assert_ne!(
            later.fingerprint,
            ConsensusManifest::for_supply_heights(Some(10), None, Some(900), None).fingerprint
        );
    }

    /// An unscheduled exact-created-code rule leaves the fingerprint exactly
    /// as before; a scheduled one is part of it.
    #[test]
    fn exact_create_code_height_enters_the_fingerprint_only_when_set() {
        let unset = ConsensusManifest::for_activations(Some(10), None, None);
        let a = ConsensusManifest::for_activations(Some(10), None, Some(0));
        let b = ConsensusManifest::for_activations(Some(10), None, Some(1));
        assert_eq!(a.exact_create_code_height, Some(0));
        assert_ne!(a.fingerprint, unset.fingerprint);
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_eq!(
            unset.fingerprint,
            ConsensusManifest::for_heights(Some(10), None).fingerprint,
            "unset: byte-identical to the two-height form"
        );
    }

    const SAMPLE_GATED: &[&str] = &["rule-a", "rule-b"];

    /// Fixed inputs for the pure-function tests (independent of the build).
    fn sample(feat_commd_fold_verify: bool) -> FingerprintInputs<'static> {
        FingerprintInputs {
            git_sha: "0123abc",
            feat_halo2_verifier: false,
            feat_commd_fold_verify,
            activation_gated: SAMPLE_GATED,
            pba_hardening_height: Some(1000),
            agent_precompiles_height: None,
            exact_create_code_height: None,
            vrf_canonical_encoding_height: None,
            supply_hardening_height: None,
            storage_root_hardening_height: None,
            value_transfer_activation_height: 1,
            create_nonce_fix_activation_height: 2,
            merge_depth_activation_height: 3,
            canonical_base_fee_per_gas: 1_000_000_000,
            epoch: 1000,
            snapshot_lag: 200,
            genesis_binding: None,
        }
    }

    /// The 0x0130 mode is part of the pre-image: the two modes are written out
    /// and give different fingerprints. A build with and without
    /// commd-fold-verify must never report the same fingerprint.
    #[test]
    fn commd_mode_enters_the_fingerprint() {
        let gated = sample(true);
        let absent = sample(false);
        assert!(
            fingerprint_preimage(&gated).contains("\ncommd_fold_verify=gated\n"),
            "pre-image must name the 0x0130 mode when the feature is compiled in"
        );
        assert!(
            fingerprint_preimage(&absent).contains("\ncommd_fold_verify=absent\n"),
            "pre-image must name the 0x0130 mode when the feature is absent"
        );
        assert_ne!(
            fingerprint_of(&gated),
            fingerprint_of(&absent),
            "the two 0x0130 modes must not share a fingerprint"
        );
    }

    /// Golden vectors: the exact pre-image text and fingerprint for fixed inputs.
    /// The expected digests were computed independently (python3 hashlib.sha256
    /// over the literal pre-image below). Any change to what the fingerprint
    /// covers, or how it is written, fails here and must be made on purpose.
    #[test]
    fn fingerprint_golden_vector_is_pinned() {
        let expected_gated = "citrate-consensus-v3\ngit_sha=0123abc\nhalo2_verifier=false\n\
            commd_fold_verify=gated\nactivation_gated=rule-a|rule-b\n\
            pba_hardening_height=1000\nvalue_transfer_height=1\ncreate_nonce_fix_height=2\n\
            merge_depth_height=3\nbase_fee=1000000000\nepoch=1000\nsnapshot_lag=200\n";
        assert_eq!(fingerprint_preimage(&sample(true)), expected_gated);
        assert_eq!(
            fingerprint_of(&sample(true)),
            "0x997452c0b05b6e1c5872e0735dade13b"
        );
        assert_eq!(
            fingerprint_of(&sample(false)),
            "0xf94e43b6bcacef7a0c72088f5cc57a49"
        );
    }

    /// Every input moves the fingerprint, and no two single-field changes
    /// collide with each other or with the base.
    #[test]
    fn every_fingerprint_input_changes_the_fingerprint() {
        let base = sample(true);
        let other_gated: &[&str] = &["rule-a"];
        let variants: Vec<(&str, FingerprintInputs<'_>)> = vec![
            (
                "git_sha",
                FingerprintInputs {
                    git_sha: "0123abd",
                    ..base
                },
            ),
            (
                "halo2",
                FingerprintInputs {
                    feat_halo2_verifier: true,
                    ..base
                },
            ),
            (
                "commd mode",
                FingerprintInputs {
                    feat_commd_fold_verify: false,
                    ..base
                },
            ),
            (
                "activation_gated",
                FingerprintInputs {
                    activation_gated: other_gated,
                    ..base
                },
            ),
            (
                "pba height",
                FingerprintInputs {
                    pba_hardening_height: Some(1001),
                    ..base
                },
            ),
            (
                "pba unset",
                FingerprintInputs {
                    pba_hardening_height: None,
                    ..base
                },
            ),
            (
                "agent height",
                FingerprintInputs {
                    agent_precompiles_height: Some(5),
                    ..base
                },
            ),
            (
                "exact create code height",
                FingerprintInputs {
                    exact_create_code_height: Some(0),
                    ..base
                },
            ),
            (
                "value transfer",
                FingerprintInputs {
                    value_transfer_activation_height: 9,
                    ..base
                },
            ),
            (
                "create nonce",
                FingerprintInputs {
                    create_nonce_fix_activation_height: 9,
                    ..base
                },
            ),
            (
                "merge depth",
                FingerprintInputs {
                    merge_depth_activation_height: 9,
                    ..base
                },
            ),
            (
                "base fee",
                FingerprintInputs {
                    canonical_base_fee_per_gas: 7,
                    ..base
                },
            ),
            ("epoch", FingerprintInputs { epoch: 999, ..base }),
            (
                "snapshot lag",
                FingerprintInputs {
                    snapshot_lag: 199,
                    ..base
                },
            ),
        ];
        let mut seen = std::collections::HashMap::new();
        seen.insert(fingerprint_of(&base), "base");
        for (name, v) in &variants {
            if let Some(prev) = seen.insert(fingerprint_of(v), name) {
                panic!("changing `{name}` gives the same fingerprint as `{prev}`");
            }
        }
    }

    /// The manifest's own fingerprint is exactly the pure function over the
    /// fields it reports, so the tests above cover the shipped value and a
    /// field cannot be reported while a different value is hashed.
    #[test]
    fn manifest_fingerprint_is_the_pure_function_of_its_fields() {
        for (p, a) in [(None, None), (Some(0), None), (Some(10), Some(500))] {
            let m = ConsensusManifest::for_heights(p, a);
            let inputs = FingerprintInputs {
                git_sha: m.git_sha,
                feat_halo2_verifier: m.feat_halo2_verifier,
                feat_commd_fold_verify: m.feat_commd_fold_verify,
                activation_gated: &m.activation_gated,
                pba_hardening_height: m.pba_hardening_height,
                agent_precompiles_height: m.agent_precompiles_height,
                exact_create_code_height: m.exact_create_code_height,
                vrf_canonical_encoding_height: m.vrf_canonical_encoding_height,
                supply_hardening_height: m.supply_hardening_height,
                storage_root_hardening_height: m.storage_root_hardening_height,
                value_transfer_activation_height: m.value_transfer_activation_height,
                create_nonce_fix_activation_height: m.create_nonce_fix_activation_height,
                merge_depth_activation_height: m.merge_depth_activation_height,
                canonical_base_fee_per_gas: m.canonical_base_fee_per_gas,
                epoch: m.epoch,
                snapshot_lag: m.snapshot_lag,
                genesis_binding: None,
            };
            assert_eq!(
                m.fingerprint,
                fingerprint_of(&inputs),
                "heights {p:?} {a:?}"
            );
            // Flipping only the reported 0x0130 mode must not reproduce it.
            let flipped = FingerprintInputs {
                feat_commd_fold_verify: !m.feat_commd_fold_verify,
                ..inputs
            };
            assert_ne!(
                m.fingerprint,
                fingerprint_of(&flipped),
                "heights {p:?} {a:?}"
            );
        }
    }

    /// v4: a bound manifest names the block-0 hash and the genesis's rule schedule (not the
    /// profile name); the unbound pre-image is byte-identical to v3 (golden vector above).
    #[test]
    fn genesis_binding_enters_the_fingerprint_as_v4() {
        let b = GenesisBinding {
            genesis_hash: "0xabc",
            genesis_rules: "pba_hardening:0",
        };
        let bound = FingerprintInputs {
            genesis_binding: Some(b),
            ..sample(true)
        };
        let pre = fingerprint_preimage(&bound);
        assert!(
            pre.starts_with("citrate-consensus-v4\ngit_sha=0123abc\n"),
            "{pre}"
        );
        assert!(
            pre.ends_with("snapshot_lag=200\ngenesis_hash=0xabc\ngenesis_rules=pba_hardening:0\n")
        );
        assert_eq!(
            pre,
            fingerprint_preimage(&sample(true)).replacen(
                "citrate-consensus-v3",
                "citrate-consensus-v4",
                1
            ) + "genesis_hash=0xabc\ngenesis_rules=pba_hardening:0\n"
        );
        let base = fingerprint_of(&sample(true));
        let mut seen = std::collections::HashSet::new();
        seen.insert(base.clone());
        for v in [
            b,
            GenesisBinding {
                genesis_hash: "0xabd",
                ..b
            },
            GenesisBinding {
                genesis_rules: "pba_hardening:1",
                ..b
            },
        ] {
            let f = fingerprint_of(&FingerprintInputs {
                genesis_binding: Some(v),
                ..sample(true)
            });
            assert!(seen.insert(f), "{v:?} collides");
        }
    }

    /// r1005 and r1006 run on one chain id with the same binary: they differ. r1006 (the
    /// genesis with compiled rules) is bound; r1005 stays the unbound v3 manifest.
    #[test]
    fn r1005_and_r1006_bound_manifests_differ() {
        use citrate_consensus::hardening::{R1006_GENESIS, RELEASE_GENESIS};
        let m = ConsensusManifest::current();
        let r1005 = ConsensusManifest::for_node(Some("testnet_beta"), Some(&RELEASE_GENESIS[0].1));
        let r1006 = ConsensusManifest::for_node(Some("r1006"), Some(&R1006_GENESIS));
        assert_ne!(r1005.fingerprint, r1006.fingerprint);
        assert_eq!(r1005.fingerprint, m.fingerprint, "r1005 is unbound (v3)");
        assert_ne!(r1006.fingerprint, m.fingerprint, "r1006 is bound (v4)");
        assert_eq!(r1005.genesis_rules, None);
        assert_eq!(
            r1006.fingerprint,
            m.clone().bound(&R1006_GENESIS).fingerprint
        );
        assert!(r1006.genesis_rules.as_deref().is_some_and(
            |r| r.contains("exact_create_code:0") && r.contains("vrf_canonical_encoding:0")
        ));
        // A different block 0 under the same compiled rules would bind differently.
        let other = m.clone().bound(&[7u8; 32]);
        assert_ne!(other.fingerprint, r1006.fingerprint);
    }

    /// The fingerprint follows the chain a node runs, never what its config calls it:
    /// naming the genesis profile or not gives the same fingerprint, on r1005 and on
    /// r1006. On r1005 (no compiled per-genesis rules) it stays exactly the v3 one
    /// (main's pre-image), so r1005 fleet comparisons are unchanged.
    #[test]
    fn fingerprint_does_not_depend_on_the_profile_name() {
        use citrate_consensus::hardening::{R1006_GENESIS, RELEASE_GENESIS};
        let r1005 = RELEASE_GENESIS[0].1;
        for (named, g) in [("testnet_beta", r1005), ("r1006", R1006_GENESIS)] {
            assert_eq!(
                ConsensusManifest::for_node(Some(named), Some(&g)).fingerprint,
                ConsensusManifest::for_node(None, Some(&g)).fingerprint,
                "{named}: the profile name moved the fingerprint"
            );
            assert_eq!(
                ConsensusManifest::for_node(Some(named), Some(&g)).fingerprint,
                ConsensusManifest::for_node(Some("some-other-name"), Some(&g)).fingerprint,
                "{named}: a renamed profile moved the fingerprint"
            );
        }
        assert_eq!(
            ConsensusManifest::for_node(Some("testnet_beta"), Some(&r1005)).fingerprint,
            ConsensusManifest::current().fingerprint,
            "r1005 keeps the unbound v3 fingerprint"
        );
        assert_ne!(
            ConsensusManifest::for_node(None, Some(&R1006_GENESIS)).fingerprint,
            ConsensusManifest::for_node(None, Some(&r1005)).fingerprint,
            "r1006 still differs from r1005"
        );
    }

    /// An unscheduled canonical VRF encoding rule leaves the fingerprint exactly as
    /// before; a scheduled one is part of it (chain#384).
    #[test]
    fn vrf_encoding_height_enters_the_fingerprint_only_when_set() {
        let unset = ConsensusManifest::for_every_height(Some(10), None, None, None);
        let a = ConsensusManifest::for_every_height(Some(10), None, None, Some(0));
        let b = ConsensusManifest::for_every_height(Some(10), None, None, Some(1));
        assert_eq!(a.vrf_canonical_encoding_height, Some(0));
        assert_ne!(a.fingerprint, unset.fingerprint);
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    /// The boot log, the node-identity RPC and `citrate consensus` report ONE fingerprint:
    /// all three take it from `for_node`, and nothing else in those paths builds one.
    #[test]
    fn boot_log_identity_rpc_and_consensus_command_share_one_fingerprint() {
        let main = include_str!("main.rs");
        let start = main.find("async fn start_node(").expect("start_node");
        let body = &main[start..];
        let end = body.find("\nasync fn ").unwrap_or(body.len());
        let body = &body[..end];
        assert_eq!(
            body.matches("ConsensusManifest::for_node(").count(),
            2,
            "start_node: the boot stamp and the identity fallback, both for_node"
        );
        assert!(
            body.contains("let manifest = node_manifest.clone()"),
            "the RPC reuses the boot manifest"
        );
        for other in [
            "ConsensusManifest::current()",
            "ConsensusManifest::for_height(",
            "ConsensusManifest::for_all(",
        ] {
            assert!(
                !body.contains(other),
                "start_node builds a second manifest via {other}"
            );
        }
        let cmd = &main[main
            .find("Some(Commands::Consensus { json })")
            .expect("consensus cmd")..];
        let cmd = &cmd[..cmd.find("return Ok(());").expect("end")];
        assert!(
            cmd.contains("ConsensusManifest::for_node("),
            "citrate consensus uses for_node"
        );
        assert!(!cmd.contains("ConsensusManifest::for_all("));
        // for_node is the current manifest, bound to a scheduled genesis exactly as bound() does.
        let g = citrate_consensus::hardening::R1006_GENESIS;
        assert_eq!(
            ConsensusManifest::for_node(Some("r1006"), Some(&g)).fingerprint,
            ConsensusManifest::current().bound(&g).fingerprint
        );
        assert_eq!(
            ConsensusManifest::for_node(None, None).fingerprint,
            ConsensusManifest::current().fingerprint
        );
    }

    #[test]
    fn json_roundtrips_key_fields() {
        let m = ConsensusManifest::current();
        let j = m.to_json();
        assert!(j.contains("\"fingerprint\""));
        assert!(j.contains("\"feat_halo2_verifier\""));
        assert!(j.contains("\"feat_commd_fold_verify\""));
        assert!(j.contains("\"activation_gated\""));
        assert!(j.contains("0x0130 fold-verify"));
        assert!(j.contains("\"canonical_base_fee_per_gas\""));
        assert!(j.contains("\"create_nonce_fix_activation_height\""));
    }

    /// The 2026-10 reroll runs every height-gated execution rule from genesis.
    #[test]
    fn reroll_execution_rules_are_active_from_genesis() {
        let m = ConsensusManifest::for_height(Some(0));
        if std::env::var_os(citrate_execution::executor::VALUE_TRANSFER_ACTIVATION_ENV).is_none() {
            assert_eq!(m.value_transfer_activation_height, 0);
        }
        if std::env::var_os(citrate_execution::executor::CREATE_NONCE_FIX_ACTIVATION_ENV).is_none()
        {
            assert_eq!(m.create_nonce_fix_activation_height, 0);
        }
        if std::env::var_os(citrate_consensus::ghostdag::MERGE_DEPTH_ACTIVATION_ENV).is_none() {
            assert_eq!(m.merge_depth_activation_height, 0);
        }
    }

    /// PBA-L1a-003 tripwire: the node's consensus feature set is fixed. Every
    /// shipped build path (release.yml, release-tier2.yml, Dockerfile, scripts,
    /// the reroll runbook) builds `-p citrate-node` with the DEFAULT features,
    /// which enable commd-fold-verify (0x0130 live, as the reroll activated it)
    /// and leave halo2-verifier (0x0108) off. A build that differs would compute
    /// different precompile results and fork.
    #[test]
    fn consensus_feature_set_is_canonical() {
        let m = ConsensusManifest::current();
        assert!(
            m.feat_commd_fold_verify,
            "citrate-node must be built with commd-fold-verify (default features)"
        );
        assert!(
            !m.feat_halo2_verifier,
            "halo2-verifier changes 0x0108 results and is not activated on any chain"
        );
        assert_eq!(env!("CITRATE_CONSENSUS_FEATURES"), "commd-fold-verify");
    }
}
