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

    // Rebuild the stamp when HEAD moves (best-effort across layouts).
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=.git/HEAD");
}
