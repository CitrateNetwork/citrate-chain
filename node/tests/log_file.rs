use std::fs;
use std::process::Command;

#[test]
fn invalid_log_parent_is_nonfatal_for_version() {
    let temp = tempfile::tempdir().expect("temp directory");
    let blocked_parent = temp.path().join("not-a-directory");
    fs::write(&blocked_parent, "occupied").expect("create blocking file");
    let log_path = blocked_parent.join("node.log");

    let output = Command::new(env!("CARGO_BIN_EXE_citrate"))
        .arg("--version")
        .env("LOG_FILE", &log_path)
        .output()
        .expect("run citrate --version");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to initialize structured logging"));
    assert!(stderr.contains(&log_path.display().to_string()));
    assert!(stderr.contains("not-a-directory"));
}
