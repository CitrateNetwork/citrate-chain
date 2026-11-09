//! Source tripwires for three block-producer / startup call sites.
//!
//! `citrate-node` is a binary crate, so these call sites cannot be driven from
//! an integration test, and the in-crate suites stay green when they regress:
//!
//! * the producer's import-rule filter (`produce_block`): a candidate that
//!   fails `tx_auth::verify_for_block` must be left out of the block, never
//!   kept;
//! * the producer's header timestamp: it must be
//!   `hardening::producer_timestamp(now, parent_ts)`, not wall-clock `now`;
//! * the startup resolution of `CITRATE_REQUIRE_VALID_SIGNATURE`: it must be
//!   passed the real mining flag and the real `devnet` cfg.
//!
//! The helpers below verify the exact shape of each call site. Each check has
//! a negative control that feeds it a regressed copy of the source.

const PRODUCER: &str = include_str!("../src/producer.rs");
const MAIN: &str = include_str!("../src/main.rs");

/// Collapse all whitespace runs to one space.
fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text between `start` and the next `end` after it.
fn region<'a>(src: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let a = src
        .find(start)
        .ok_or_else(|| format!("anchor not found: {start}"))?;
    let rest = &src[a..];
    let b = rest
        .find(end)
        .ok_or_else(|| format!("end anchor not found: {end}"))?;
    Ok(&rest[..b])
}

fn check_import_filter(src: &str) -> Result<(), String> {
    let r = norm(region(
        src,
        "// PBA-L1b-001: from the activation height every follower rejects",
        "// Blue score and work are already calculated above",
    )?);
    if !r.contains(".active_at(next_height)") {
        return Err("filter is not keyed on the next block's height".into());
    }
    if !r.contains("match citrate_consensus::tx_auth::verify_for_block(&t, chain_id) {") {
        return Err("candidates are not checked with tx_auth::verify_for_block".into());
    }
    if !r.contains("Ok(_) => keep.push(t),") {
        return Err("an authenticated candidate is not kept".into());
    }
    if r.matches("keep.push").count() != 1 {
        return Err("a candidate that fails verify_for_block is kept".into());
    }
    let err_arm = r
        .split("Err(e) => {")
        .nth(1)
        .ok_or("no Err arm in the filter")?;
    if !err_arm.contains("self.mempool.remove_transaction(&t.hash)") {
        return Err("a refused candidate is not removed from the mempool".into());
    }
    Ok(())
}

fn check_header_timestamp(src: &str) -> Result<(), String> {
    let r = norm(region(
        src,
        "// PBA-L1b-003: never stamp before the selected parent",
        "height: next_height,",
    )?);
    let want = "match parent_ts { Some(pts) => citrate_consensus::hardening::producer_timestamp(now, pts), None => now, }";
    if !r.contains(want) {
        return Err(format!(
            "header timestamp is not producer_timestamp(now, parent_ts): {r}"
        ));
    }
    Ok(())
}

fn check_signature_switch(src: &str) -> Result<(), String> {
    let r = norm(region(
        src,
        "let require_valid_signature = startup_guards::resolve_require_valid_signature(",
        ".map_err(",
    )?);
    let want = "let require_valid_signature = startup_guards::resolve_require_valid_signature( \
                std::env::var(\"CITRATE_REQUIRE_VALID_SIGNATURE\") .ok() .as_deref(), \
                config.mining.enabled, cfg!(feature = \"devnet\"), )";
    if r != want {
        return Err(format!("signature-switch resolution changed: {r}"));
    }
    Ok(())
}

#[test]
fn producer_leaves_out_candidates_that_fail_the_import_rule() {
    check_import_filter(PRODUCER).unwrap();
}

#[test]
fn producer_stamps_headers_with_the_parent_bounded_timestamp() {
    check_header_timestamp(PRODUCER).unwrap();
}

#[test]
fn signature_switch_is_resolved_with_the_real_mining_flag_and_build_cfg() {
    check_signature_switch(MAIN).unwrap();
}

// ---- negative controls ---------------------------------------------------

#[test]
fn import_filter_check_catches_a_kept_failing_candidate() {
    let bad = PRODUCER.replacen(
        "let _ = self.mempool.remove_transaction(&t.hash).await;",
        "let _ = self.mempool.remove_transaction(&t.hash).await;\n keep.push(t);",
        1,
    );
    assert_ne!(bad, PRODUCER, "control did not apply");
    assert!(check_import_filter(&bad).is_err());
}

#[test]
fn timestamp_check_catches_a_wall_clock_stamp() {
    let bad = PRODUCER.replacen(
        "Some(pts) => citrate_consensus::hardening::producer_timestamp(now, pts),",
        "Some(pts) => { let _ = citrate_consensus::hardening::producer_timestamp(now, pts); now }",
        1,
    );
    assert_ne!(bad, PRODUCER, "control did not apply");
    assert!(check_header_timestamp(&bad).is_err());
}

#[test]
fn signature_switch_check_catches_a_hardcoded_mining_flag() {
    let bad = MAIN.replacen(
        "config.mining.enabled,\n        cfg!(feature = \"devnet\")",
        "false,\n        cfg!(feature = \"devnet\")",
        1,
    );
    assert_ne!(bad, MAIN, "control did not apply");
    assert!(check_signature_switch(&bad).is_err());
}
