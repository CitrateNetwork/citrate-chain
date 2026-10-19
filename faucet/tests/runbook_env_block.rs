//! Runs the env-file update block from `docs/ops/FAUCET_POLICY.md` §4.3 — the exact text an
//! operator pastes — against a throwaway env file, and checks that it updates the file on the
//! happy path and leaves it byte-for-byte unchanged (with no temporary file left behind) when any
//! step fails. Linux only: the block uses GNU `stat -c` and `chown --reference`.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const KEY_LINE: &str = "FAUCET_PRIVATE_KEY=dummy-not-a-key";

/// The bash fence in §4.3 (the one that writes `FAUCET_REQUIRE_GATES=true`).
fn runbook_block() -> String {
    let doc = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/ops/FAUCET_POLICY.md");
    let text = std::fs::read_to_string(&doc).expect("read FAUCET_POLICY.md");
    let mut rest = text.as_str();
    while let Some(i) = rest.find("```bash\n") {
        let body = &rest[i + "```bash\n".len()..];
        let end = body.find("\n```").expect("closed fence");
        let block = &body[..end];
        if block.contains("FAUCET_REQUIRE_GATES=true") {
            return format!("{block}\n");
        }
        rest = &body[end..];
    }
    panic!("no §4.3 env block in FAUCET_POLICY.md");
}

struct Case {
    _dir: TempDir,
    env: PathBuf,
    state: PathBuf,
    shims: PathBuf,
    script: PathBuf,
    original: Vec<u8>,
}

fn case(contents: &str, mode: u32) -> Case {
    let dir = TempDir::new().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir(&etc).expect("etc");
    let env = etc.join("citrate-faucet.env");
    std::fs::write(&env, contents).expect("env");
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(mode)).expect("chmod");
    let shims = dir.path().join("shims");
    std::fs::create_dir(&shims).expect("shims");
    let script = dir.path().join("block.sh");
    std::fs::write(&script, runbook_block()).expect("script");
    Case {
        state: dir.path().join("state"),
        env,
        shims,
        script,
        original: contents.as_bytes().to_vec(),
        _dir: dir,
    }
}

impl Case {
    /// Replace `cmd` on PATH with a script body (e.g. one that fails).
    fn shim(&self, cmd: &str, body: &str) {
        let p = self.shims.join(cmd);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("shim");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    }

    fn run(&self) -> Output {
        let path = format!(
            "{}:{}",
            self.shims.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("bash")
            .arg(&self.script)
            .env("PATH", path)
            .env("FAUCET_ENV", &self.env)
            .env("FAUCET_STATE_DIR", &self.state)
            .output()
            .expect("run bash")
    }

    fn leftovers(&self) -> Vec<String> {
        std::fs::read_dir(self.env.parent().expect("etc"))
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".new."))
            .collect()
    }

    fn assert_unchanged(&self, out: &Output, why: &str) {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            std::fs::read(&self.env).expect("env"),
            self.original,
            "{why}: env file changed\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !stdout.contains("env updated"),
            "{why}: reported success\n{stdout}"
        );
        assert!(
            stderr.contains("env NOT changed"),
            "{why}: no failure report\n{stderr}"
        );
        assert!(
            self.leftovers().is_empty(),
            "{why}: temporary file left: {:?}",
            self.leftovers()
        );
        assert!(
            !stdout.contains("dummy-not-a-key") && !stderr.contains("dummy-not-a-key"),
            "{why}: key material printed"
        );
    }
}

fn base_env() -> String {
    format!("RPC_URL=http://127.0.0.1:8545\n{KEY_LINE}\nFAUCET_REQUIRE_GATES=false\nFAUCET_MAX_DRIPS_PER_HOUR=999\n")
}

#[test]
fn env_block_updates_a_private_env_file() {
    let c = case(&base_env(), 0o600);
    let out = c.run();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("env updated"),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = std::fs::read_to_string(&c.env).expect("env");
    assert_eq!(after.matches(KEY_LINE).count(), 1, "{after}");
    assert!(after.contains("RPC_URL=http://127.0.0.1:8545\n"));
    assert!(after.contains("FAUCET_REQUIRE_GATES=true\n"));
    assert!(!after.contains("FAUCET_REQUIRE_GATES=false"));
    assert!(!after.contains("FAUCET_MAX_DRIPS_PER_HOUR=999"));
    assert!(after.contains("FAUCET_COOLDOWN_FILE=/var/lib/citrate-faucet/cooldowns.json\n"));
    let mode = std::fs::metadata(&c.env)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let backup = c.env.with_file_name("citrate-faucet.env.pre-g4");
    assert_eq!(std::fs::read(&backup).expect("backup"), c.original);
    let state_mode = std::fs::metadata(&c.state)
        .expect("state dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(state_mode, 0o700);
    assert!(c.leftovers().is_empty(), "{:?}", c.leftovers());
    assert!(!stdout.contains("dummy-not-a-key"));
}

#[test]
fn env_block_refuses_a_world_readable_env_file() {
    let c = case(&base_env(), 0o644);
    let out = c.run();
    c.assert_unchanged(&out, "mode 0644");
    assert!(!c.env.with_file_name("citrate-faucet.env.pre-g4").exists());
}

#[test]
fn env_block_refuses_when_the_key_line_is_missing_or_duplicated() {
    let c = case("RPC_URL=x\nFAUCET_REQUIRE_GATES=false\n", 0o600);
    c.assert_unchanged(&c.run(), "no key line");
    let c = case(&format!("{KEY_LINE}\n{KEY_LINE}\n"), 0o600);
    c.assert_unchanged(&c.run(), "two key lines");
}

/// Every step before the `mv` stops the block when it fails — including a filter that writes a
/// partial file and then fails, which the old `( ... ) && ... || ...` form let through.
#[test]
fn env_block_stops_on_every_failed_step() {
    let failures: &[(&str, &str)] = &[
        ("install", "exit 1"),
        ("cp", "exit 1"),
        ("mktemp", "exit 1"),
        (
            "grep",
            // Partial output, then failure; the count call fails the same way.
            "echo FAUCET_PRIVATE_KEY=partial; exit 2",
        ),
        ("cat", "exit 1"),
        ("chown", "exit 1"),
        ("chmod", "exit 1"),
        ("mv", "exit 1"),
    ];
    for (cmd, body) in failures {
        let c = case(&base_env(), 0o600);
        c.shim(cmd, body);
        c.assert_unchanged(&c.run(), &format!("failing {cmd}"));
    }
}

/// The rollback copy is written once. A second run (after a success, then after a failure) keeps
/// the copy of the env from before the first run, so §4.6 rollback never restores a G4 env.
#[test]
fn env_block_rerun_keeps_the_first_rollback_copy() {
    let c = case(&base_env(), 0o600);
    let backup = c.env.with_file_name("citrate-faucet.env.pre-g4");

    let first = c.run();
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("env updated"),
        "first run: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(std::fs::read(&backup).expect("backup"), c.original);
    let after_first = std::fs::read(&c.env).expect("env");
    assert_ne!(after_first, c.original);

    // Rerun that succeeds: the env is rewritten, the rollback copy is not.
    let second = c.run();
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("env updated"), "second run: {stdout}");
    assert!(
        stdout.contains("keeping the existing rollback copy"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(&backup).expect("backup"), c.original);
    assert_eq!(std::fs::read(&c.env).expect("env"), after_first);

    // Rerun that fails late: env unchanged from the first run, rollback copy still the original.
    c.shim("chmod", "exit 1");
    let third = c.run();
    assert!(
        String::from_utf8_lossy(&third.stderr).contains("env NOT changed"),
        "third run: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    assert_eq!(std::fs::read(&backup).expect("backup"), c.original);
    assert_eq!(std::fs::read(&c.env).expect("env"), after_first);
    assert!(c.leftovers().is_empty(), "{:?}", c.leftovers());
}

/// A rollback copy that is a symlink (or not a regular file) is refused, not followed.
#[test]
fn env_block_refuses_a_rollback_copy_that_is_not_a_regular_file() {
    let c = case(&base_env(), 0o600);
    let elsewhere = c.env.with_file_name("elsewhere");
    std::fs::write(&elsewhere, "untouched\n").expect("elsewhere");
    let backup = c.env.with_file_name("citrate-faucet.env.pre-g4");
    std::os::unix::fs::symlink(&elsewhere, &backup).expect("symlink");
    let out = c.run();
    c.assert_unchanged(&out, "symlinked rollback copy");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a regular file"));
    assert_eq!(
        std::fs::read_to_string(&elsewhere).expect("elsewhere"),
        "untouched\n"
    );
    assert!(std::fs::symlink_metadata(&backup)
        .expect("meta")
        .file_type()
        .is_symlink());

    let c = case(&base_env(), 0o600);
    std::fs::create_dir(c.env.with_file_name("citrate-faucet.env.pre-g4")).expect("dir");
    c.assert_unchanged(&c.run(), "directory rollback copy");
}
