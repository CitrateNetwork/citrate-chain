//! Build-profile tripwire: the relaxed `devnet` validation branch of the
//! mempool must never be part of an in-repo build.
//!
//! Turning `devnet` on compiles out the production signature gate in
//! `Mempool::validate_transaction` and the tests that exercise it. The rest of
//! this suite stays green when `devnet` becomes a default feature, because the
//! unconditional sender-recovery check still rejects the forged inputs it
//! uses. So the build profile itself is pinned here.
//!
//! The check lives in `scripts/ci/sequencer_devnet_tripwire.py`: it parses
//! every Cargo.toml as TOML and resolves features across the in-repo crates
//! (default lists, inline and table-form dependency specs, `workspace = true`
//! inheritance, renames, and features forwarded through other features). These
//! tests run it on the tree, run its self-test, and feed it each manifest
//! spelling that a line-based reader missed. It reads manifests (not `cfg!`),
//! so it holds under any `--features` selection of this test run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tripwire(args: &[&str], root: Option<&Path>) -> Output {
    let script = repo_root().join("scripts/ci/sequencer_devnet_tripwire.py");
    let mut cmd = Command::new("python3");
    cmd.arg(script).args(args);
    match root {
        Some(r) => cmd.env("SEQ_DEVNET_TRIPWIRE_ROOT", r),
        None => cmd.env_remove("SEQ_DEVNET_TRIPWIRE_ROOT"),
    };
    cmd.output()
        .expect("python3 must be available to run the tripwire")
}

fn describe(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Writes a two-crate fixture workspace (sequencer + one dependent) under this
/// test binary's scratch dir and returns its root.
fn fixture(name: &str, seq_features: &str, app_tail: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("seq-devnet-guard")
        .join(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("clear stale fixture");
    }
    std::fs::create_dir_all(root.join("seq")).expect("mkdir seq");
    std::fs::create_dir_all(root.join("app")).expect("mkdir app");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"seq\", \"app\"]\n",
    )
    .expect("write root");
    std::fs::write(
        root.join("seq/Cargo.toml"),
        format!(
            "[package]\nname = \"citrate-sequencer\"\nversion = \"0.1.0\"\n\n[features]\n{seq_features}"
        ),
    )
    .expect("write seq");
    std::fs::write(
        root.join("app/Cargo.toml"),
        format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n{app_tail}"),
    )
    .expect("write app");
    root
}

#[test]
fn no_in_repo_build_enables_devnet() {
    let out = tripwire(&[], None);
    assert!(out.status.success(), "{}", describe(&out));
}

#[test]
fn tripwire_self_test_passes() {
    let out = tripwire(&["--self-test"], None);
    assert!(out.status.success(), "{}", describe(&out));
}

/// Each manifest spelling below enables `devnet`; every one must be flagged,
/// and the clean control must pass.
#[test]
fn tripwire_flags_every_devnet_spelling() {
    let clean = "default = []\ndevnet = []\n";
    let cases = [
        (
            "multi-line default list",
            "default = [\n    \"devnet\",\n]\ndevnet = []\n",
            String::new(),
        ),
        (
            "table-form dependency",
            clean,
            "[dependencies.citrate-sequencer]\npath = \"../seq\"\nfeatures = [\"devnet\"]\n"
                .to_string(),
        ),
        (
            "forwarded alias",
            clean,
            "[dependencies]\ncitrate-sequencer = { path = \"../seq\" }\n\n[features]\ndefault = [\"dev\"]\ndev = [\"citrate-sequencer/devnet\"]\n"
                .to_string(),
        ),
    ];
    let mut missed = Vec::new();
    for (i, (label, seq, app)) in cases.iter().enumerate() {
        let root = fixture(&format!("bad{i}"), seq, app);
        let out = tripwire(&[], Some(&root));
        if out.status.code() != Some(1) {
            missed.push(format!("{label}: {}", describe(&out)));
        }
    }
    assert!(missed.is_empty(), "tripwire missed: {missed:#?}");

    let root = fixture(
        "clean",
        clean,
        "[dependencies]\ncitrate-sequencer = { path = \"../seq\" }\n",
    );
    let out = tripwire(&[], Some(&root));
    assert!(
        out.status.success(),
        "clean control flagged: {}",
        describe(&out)
    );
}

/// A renamed feature would make the check vacuous, so the tripwire refuses a
/// tree where citrate-sequencer no longer declares `devnet`.
#[test]
fn tripwire_fails_closed_without_devnet_feature() {
    let root = fixture("undeclared", "default = []\n", "");
    let out = tripwire(&[], Some(&root));
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
}
