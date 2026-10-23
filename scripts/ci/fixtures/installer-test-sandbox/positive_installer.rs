// Fixture (installer-test-sandbox, positive): a Rust integration test that runs the deploy
// script without a HOME override. The marked line must be flagged.
use std::process::Command;

#[test]
fn deploy_script_bails_without_version() {
    let out = Command::new("bash")
        .arg("../scripts/deploy_testnet.sh") // FLAG
        .arg("--coinbase")
        .output()
        .expect("run");
    let _refused = !out.status.success();
}
