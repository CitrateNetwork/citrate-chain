//! The Homebrew formula that ships this CLI must fetch from the canonical
//! release location, at the workspace version, and never install an artifact
//! it cannot verify. Read-only: parses `homebrew/citrate.rb` from the repo.

use std::path::PathBuf;

fn formula() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../homebrew/citrate.rb");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn quoted_values(src: &str, key: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix(key))
        .filter_map(|rest| {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('"')?;
            Some(rest.split('"').next()?.to_string())
        })
        .collect()
}

#[test]
fn every_download_url_is_a_canonical_release_asset() {
    let src = formula();
    let urls = quoted_values(&src, "url ");
    assert!(!urls.is_empty(), "formula has no url lines");
    for u in &urls {
        assert!(
            u.starts_with(
                "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/"
            ),
            "non-canonical or unpinned download url: {u}"
        );
    }
}

#[test]
fn every_url_has_a_digest_that_fails_closed() {
    let src = formula();
    let code: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(
        !code.iter().any(|l| l.contains(":no_check")),
        "formula disables checksum verification"
    );
    let urls = quoted_values(&src, "url ");
    let digests = quoted_values(&src, "sha256 ");
    assert_eq!(digests.len(), urls.len(), "one sha256 per download url");
    for d in &digests {
        let is_hex = d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit());
        assert!(
            is_hex || d == "PENDING_RELEASE_DIGEST",
            "sha256 must be a real digest or the fail-closed marker, got {d:?}"
        );
    }
}

#[test]
fn formula_version_matches_the_workspace() {
    let src = formula();
    let versions = quoted_values(&src, "version ");
    assert_eq!(
        versions,
        vec![env!("CARGO_PKG_VERSION").to_string()],
        "formula version drifted from the workspace"
    );
    assert!(
        src.contains("class Citrate < Formula"),
        "formula class must be Citrate"
    );
}
