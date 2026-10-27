//! G4 (genesis faucet policy): an operator switch that makes the betanet limits mandatory.
//!
//! The global cap (`limits.rs`), the membership-SBT gate (`membership.rs`) and cooldown
//! persistence (`cooldowns.rs`) are each off unless their variable is set. That default keeps
//! old deployments unchanged, but it also means a deploy that forgets one variable starts
//! quietly with that limit off. `FAUCET_REQUIRE_GATES=true` turns the omission into a startup
//! error that names every missing setting, so the faucet either runs with the whole policy or
//! does not run.
//!
//! The policy itself is written up in `docs/ops/FAUCET_POLICY.md`.
//!
//! **Off unless the operator sets it.** Unset, blank or `false` keeps the old behaviour.

/// What the faucet was configured with, as far as the required gates are concerned.
#[derive(Debug, Clone, Copy, Default)]
pub struct GateConfig {
    /// `FAUCET_MAX_DRIPS_PER_HOUR` is set.
    pub global_cap: bool,
    /// `FAUCET_MEMBER_SBT` is set.
    pub member_sbt: bool,
    /// `FAUCET_COOLDOWN_FILE` is set, so a restart cannot reset the per-address window.
    pub cooldown_file: bool,
}

/// Parse `FAUCET_REQUIRE_GATES`. Unset or blank: `Ok(false)`. Only `true`/`1` and
/// `false`/`0` (any case) are accepted; anything else is a startup error, because a typo here
/// would otherwise silently drop the guard.
pub fn parse_require_gates(raw: Option<&str>) -> Result<bool, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!(
            "FAUCET_REQUIRE_GATES must be true, false, 1 or 0, got {s:?}"
        )),
    }
}

/// With the switch on, every gate must be configured. The error names each missing variable.
pub fn check_required_gates(required: bool, cfg: GateConfig) -> Result<(), String> {
    if !required {
        return Ok(());
    }
    let mut missing = Vec::new();
    if !cfg.global_cap {
        missing.push("FAUCET_MAX_DRIPS_PER_HOUR");
    }
    if !cfg.member_sbt {
        missing.push("FAUCET_MEMBER_SBT");
    }
    if !cfg.cooldown_file {
        missing.push("FAUCET_COOLDOWN_FILE");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "FAUCET_REQUIRE_GATES is on but these are not set: {}. See docs/ops/FAUCET_POLICY.md.",
            missing.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: GateConfig = GateConfig {
        global_cap: true,
        member_sbt: true,
        cooldown_file: true,
    };

    #[test]
    fn switch_parsing_is_strict() {
        assert!(!parse_require_gates(None).expect("unset"));
        assert!(!parse_require_gates(Some(" ")).expect("blank"));
        for on in ["true", "TRUE", "1", " True "] {
            assert!(parse_require_gates(Some(on)).expect(on), "{on}");
        }
        for off in ["false", "0", "False"] {
            assert!(!parse_require_gates(Some(off)).expect(off), "{off}");
        }
        for bad in ["yes", "on", "2", "ture"] {
            assert!(
                parse_require_gates(Some(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn off_accepts_any_configuration() {
        check_required_gates(false, GateConfig::default()).expect("off");
    }

    #[test]
    fn on_accepts_the_full_policy() {
        check_required_gates(true, ALL).expect("all set");
    }

    #[test]
    fn on_names_every_missing_gate() {
        let e = check_required_gates(true, GateConfig::default()).expect_err("none set");
        for v in [
            "FAUCET_MAX_DRIPS_PER_HOUR",
            "FAUCET_MEMBER_SBT",
            "FAUCET_COOLDOWN_FILE",
        ] {
            assert!(e.contains(v), "{e} should name {v}");
        }
        let e = check_required_gates(
            true,
            GateConfig {
                member_sbt: false,
                ..ALL
            },
        )
        .expect_err("sbt missing");
        assert!(e.contains("FAUCET_MEMBER_SBT"));
        assert!(!e.contains("FAUCET_MAX_DRIPS_PER_HOUR"));
        assert!(!e.contains("FAUCET_COOLDOWN_FILE"));
    }
}
