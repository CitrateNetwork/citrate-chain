//! Build-profile tripwire: the relaxed `devnet` validation branch of the
//! mempool must never be part of a default build.
//!
//! Turning `devnet` on compiles out the production signature gate in
//! `Mempool::validate_transaction` and the tests that exercise it. The rest of
//! this suite stays green when `devnet` becomes a default feature, because the
//! unconditional sender-recovery check still rejects the forged inputs it
//! uses. So the build profile itself is pinned here: the crate's default
//! feature list, and every in-repo dependent, must leave `devnet` off.
//!
//! The check reads manifests (not `cfg!`), so it holds under any
//! `--features` selection of this test run.

use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Entries of `default = [...]` in the `[features]` table of `manifest`.
fn default_features(manifest: &str) -> Vec<String> {
    let mut in_features = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if in_features && t.starts_with("default") {
            let rhs = t.split_once('=').map(|(_, r)| r).unwrap_or("");
            return rhs
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

#[test]
fn devnet_is_not_a_default_feature() {
    let manifest = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains("[features]") && manifest.contains("devnet"),
        "the sequencer manifest must still declare its features"
    );
    let defaults = default_features(&manifest);
    assert!(
        !defaults.iter().any(|f| f == "devnet"),
        "citrate-sequencer must not enable `devnet` by default, got default = {defaults:?}"
    );
}

#[test]
fn no_in_repo_dependent_enables_devnet() {
    let root = manifest_dir().join("../..");
    let dependents = [
        "node/Cargo.toml",
        "node-app/Cargo.toml",
        "core/api/Cargo.toml",
        "core/network/Cargo.toml",
    ];
    let mut checked = 0;
    for rel in dependents {
        let path: PathBuf = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines().filter(|l| l.contains("citrate-sequencer")) {
            checked += 1;
            assert!(
                !line.contains("devnet"),
                "{} enables the sequencer `devnet` feature: {line}",
                Path::new(rel).display()
            );
        }
        // A forwarding feature like `devnet = ["citrate-sequencer/devnet"]` in a
        // DEFAULT list would do the same thing indirectly.
        let defaults = default_features(&text);
        assert!(
            !defaults
                .iter()
                .any(|f| f.contains("citrate-sequencer/devnet")),
            "{rel} turns on citrate-sequencer/devnet by default"
        );
    }
    assert!(
        checked >= 3,
        "expected the node, api and network dependents, saw {checked}"
    );
}

/// Negative control for the parser: a manifest with `devnet` in its defaults
/// is detected.
#[test]
fn default_feature_parser_detects_devnet() {
    let bad = "[package]\nname = \"x\"\n\n[features]\ndefault = [\"devnet\"]\ndevnet = []\n";
    assert_eq!(default_features(bad), vec!["devnet".to_string()]);
    let good = "[features]\ndefault = []\ndevnet = []\n";
    assert!(default_features(good).is_empty());
}

/// Red-first: the manifest spellings below each enable `devnet` and must be
/// flagged by the tripwire.
#[test]
fn tripwire_flags_every_devnet_spelling() {
    let mut missed = Vec::new();
    let multi_line_default = "[features]\ndefault = [\n    \"devnet\",\n]\ndevnet = []\n";
    if !default_features(multi_line_default)
        .iter()
        .any(|f| f == "devnet")
    {
        missed.push("multi-line default list");
    }
    let table_form =
        "[dependencies.citrate-sequencer]\npath = \"../core/sequencer\"\nfeatures = [\"devnet\"]\n";
    if !table_form
        .lines()
        .filter(|l| l.contains("citrate-sequencer"))
        .any(|l| l.contains("devnet"))
    {
        missed.push("table-form dependency");
    }
    let forwarded = "[dependencies]\ncitrate-sequencer = { path = \"../core/sequencer\" }\n\n[features]\ndefault = [\"dev\"]\ndev = [\"citrate-sequencer/devnet\"]\n";
    if !default_features(forwarded)
        .iter()
        .any(|f| f.contains("citrate-sequencer/devnet"))
    {
        missed.push("forwarded alias");
    }
    assert!(missed.is_empty(), "tripwire missed: {missed:?}");
}
