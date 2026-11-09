// Fixture (installer-test-sandbox, negative): the deploy script runs with HOME inside a temp
// dir. Nothing here may be flagged.
use std::process::Command;

#[test]
fn deploy_script_bails_without_version() {
    let tmp = tempfile::TempDir::new().expect("tmp");
    let out = Command::new("bash")
        .arg("../scripts/deploy_testnet.sh")
        .env("HOME", tmp.path())
        .output()
        .expect("run");
    let _refused = !out.status.success();
}
