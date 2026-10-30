//! `DocusignConfig::from_env` hard-fails on a missing or unparsable
//! `DOCUSIGN_CLEAR_RBV_ENABLED`, like every sibling variable, instead of
//! falling back to the weaker mode. The process environment is global, so all
//! cases run sequentially inside ONE test in this dedicated test binary.
//! Only `DOCUSIGN_*` variables of this process are touched; values are dummies.

use citrate_signing::providers::docusign::DocusignConfig;
use citrate_signing::SigningError;

const VARS: [(&str, &str); 4] = [
    ("DOCUSIGN_BASE_URL", "https://demo.docusign.net/restapi"),
    ("DOCUSIGN_ACCOUNT_ID", "acct"),
    ("DOCUSIGN_ACCESS_TOKEN", "dummy-token"),
    ("DOCUSIGN_WEBHOOK_SECRET", "dummy-secret"),
];
const RBV: &str = "DOCUSIGN_CLEAR_RBV_ENABLED";

fn expect_config_error(what: &str) {
    match DocusignConfig::from_env() {
        Err(SigningError::Config(msg)) => assert!(msg.contains(RBV), "{what}: {msg}"),
        Err(other) => panic!("{what}: expected a Config error, got {other:?}"),
        Ok(cfg) => panic!(
            "{what}: must hard-fail, got clear_rbv_enabled={}",
            cfg.clear_rbv_enabled
        ),
    }
}

#[test]
fn clear_rbv_flag_is_required_and_strictly_parsed() {
    for (k, v) in VARS {
        std::env::set_var(k, v);
    }

    std::env::remove_var(RBV);
    expect_config_error("unset");

    for bad in ["", "yes", "enabled", "flase", "2"] {
        std::env::set_var(RBV, bad);
        expect_config_error(&format!("value {bad:?}"));
    }

    for (val, want) in [
        ("true", true),
        ("1", true),
        ("TRUE", true),
        ("false", false),
        (" 0 ", false),
    ] {
        std::env::set_var(RBV, val);
        let cfg = DocusignConfig::from_env().unwrap_or_else(|e| panic!("{val:?}: {e:?}"));
        assert_eq!(cfg.clear_rbv_enabled, want, "value {val:?}");
    }

    std::env::remove_var(RBV);
    for (k, _) in VARS {
        std::env::remove_var(k);
    }
}
