//! Build-time consensus-alignment stamp (package-alignment hardening).
//!
//! Embeds the git commit + build target + consensus-affecting feature flags into
//! the binary so `citrate consensus` can report exactly what code and feature set
//! a running node was built from. Two node binaries that disagree on any of these
//! can silently compute different state roots and wedge cold-sync (the 2,580 /
//! VALIDATOR-S1 divergence class). Making the stamp introspectable lets the app
//! node and the fleet producer be diffed before a reroll.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_string())
}

fn main() {
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CITRATE_GIT_SHA={sha}");

    // Working-tree dirty flag: a dirty build is NOT reproducibly aligned.
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    println!(
        "cargo:rustc-env=CITRATE_GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );

    println!(
        "cargo:rustc-env=CITRATE_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );

    // Consensus-affecting build features (cargo sets CARGO_FEATURE_<NAME> when on).
    // halo2-verifier changes the 0x0108 precompile behaviour: mixed builds diverge.
    let halo2 = std::env::var("CARGO_FEATURE_HALO2_VERIFIER").is_ok();
    println!(
        "cargo:rustc-env=CITRATE_FEAT_HALO2={}",
        if halo2 { "1" } else { "0" }
    );

    // PBA-L1a-003: commd-fold-verify changes the 0x0130 precompile result
    // (feature off => Err for every proof; on => Ok for a valid proof). It was
    // missing from this stamp, so a runbook-built validator (feature on) and a
    // release-built follower (feature off) reported the SAME fingerprint while
    // disagreeing on consensus.
    let commd = std::env::var("CARGO_FEATURE_COMMD_FOLD_VERIFY").is_ok();
    println!(
        "cargo:rustc-env=CITRATE_FEAT_COMMD_FOLD={}",
        if commd { "1" } else { "0" }
    );
    let mut feats: Vec<&str> = Vec::new();
    if commd {
        feats.push("commd-fold-verify");
    }
    if halo2 {
        feats.push("halo2-verifier");
    }
    println!(
        "cargo:rustc-env=CITRATE_CONSENSUS_FEATURES={}",
        if feats.is_empty() {
            "none".to_string()
        } else {
            feats.join(",")
        }
    );

    // Rebuild the stamp when HEAD moves (best-effort across layouts).
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=.git/HEAD");
}
