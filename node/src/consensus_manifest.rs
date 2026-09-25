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
    /// Canonical EIP-1559 base fee committed into every block (reroll constant).
    pub canonical_base_fee_per_gas: u64,
    /// Validator-registry snapshot epoch length (blocks).
    pub epoch: u64,
    /// Validator-registry snapshot lag (blocks before the epoch boundary).
    pub snapshot_lag: u64,
    /// Stable hash over the consensus-affecting fields (NOT build_target). Two
    /// binaries with equal fingerprints compute equal state roots for equal input.
    pub fingerprint: String,
}

impl ConsensusManifest {
    pub fn current() -> Self {
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

        // Canonical, order-stable pre-image of the consensus-affecting surface.
        // Deliberately EXCLUDES build_target (arch must not change consensus) and
        // git_dirty (provenance, surfaced separately as a hard blocker).
        let activation_gated: Vec<&'static str> =
            citrate_execution::build_features::ACTIVATION_GATED.to_vec();
        // v2 pre-image: v1's fields, with 0x0130 reported as activation-gated
        // and the gated rule set listed, so a diff against a v1 (fleet)
        // manifest shows exactly which differences wait for the height.
        let commd_mode = if feat_commd_fold_verify {
            "gated"
        } else {
            "absent"
        };
        let preimage = format!(
            "citrate-consensus-v2\ngit_sha={git_sha}\nhalo2_verifier={feat_halo2_verifier}\n\
             commd_fold_verify={commd_mode}\nactivation_gated={}\n\
             base_fee={CANONICAL_BASE_FEE_PER_GAS}\nepoch={EPOCH}\nsnapshot_lag={SNAPSHOT_LAG}\n",
            activation_gated.join("|"),
        );
        let pba_hardening_height =
            citrate_consensus::hardening::pba_hardening_height().or_else(|| {
                citrate_consensus::hardening::resolve_pba_hardening_height(None)
                    .ok()
                    .flatten()
            });
        let digest = Sha256::digest(preimage.as_bytes());
        let fingerprint = format!("0x{}", hex::encode(&digest[..16]));

        Self {
            version,
            git_sha,
            git_dirty,
            build_target,
            feat_halo2_verifier,
            feat_commd_fold_verify,
            activation_gated,
            pba_hardening_height,
            canonical_base_fee_per_gas: CANONICAL_BASE_FEE_PER_GAS,
            epoch: EPOCH,
            snapshot_lag: SNAPSHOT_LAG,
            fingerprint,
        }
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
        let a = ConsensusManifest::current();
        let b = ConsensusManifest::current();
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
