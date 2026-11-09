//! Tripwire: allocation capacity must not be taken directly from a decoded
//! manifest / size field.
//!
//! Scans the non-test source of every crate under `core/` for
//! `Vec::with_capacity(..)` and `vec![..; ..]` whose size expression names a
//! manifest-declared size (`manifest.`, `total_size`, `size_bytes`). Such
//! sizes must go through a validating type (for model weights,
//! `citrate_mcp::chunk_assembly::ChunkAssembler`) first.

use std::fs;
use std::path::{Path, PathBuf};

/// Size-expression tokens that indicate a manifest-declared length.
const TAINTED_TOKENS: &[&str] = &["manifest.", "total_size", "size_bytes"];

/// Reviewed exceptions: (path suffix under core/, token, reason).
const ALLOWLIST: &[(&str, &str, &str)] = &[(
    "storage/src/ipfs/chunking.rs",
    "total_size",
    "reconstruct_model sums in-memory Chunk.size; only caller is its own unit test",
)];

/// Return the size expressions of allocation sites in `src` that mention a
/// tainted token, as (token, expression).
fn flagged_sites(src: &str) -> Vec<(&'static str, String)> {
    // Only production code: stop at the first test module.
    let prod = match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    };
    let mut out = Vec::new();
    for (opener, close) in [("Vec::with_capacity(", ')'), ("vec![", ']')] {
        let mut rest = prod;
        while let Some(i) = rest.find(opener) {
            let after = &rest[i + opener.len()..];
            let open = if close == ')' { '(' } else { '[' };
            let mut depth = 1usize;
            let mut end = after.len();
            for (j, ch) in after.char_indices() {
                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                }
            }
            let expr = &after[..end];
            // For `vec![x; n]` only the length part matters.
            let size_expr = if close == ']' {
                match expr.rsplit_once(';') {
                    Some((_, n)) => n,
                    None => "",
                }
            } else {
                expr
            };
            for tok in TAINTED_TOKENS {
                if size_expr.contains(tok) {
                    out.push((*tok, size_expr.trim().to_string()));
                }
            }
            rest = after;
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if matches!(name, "target" | "tests" | "benches" | "examples") {
                continue;
            }
            rust_files(&p, out);
        } else if name.ends_with(".rs") && !name.ends_with("_test.rs") {
            out.push(p);
        }
    }
}

#[test]
fn negative_control_detector_flags_the_unbounded_pattern() {
    let bad = "fn f(manifest: M) { let mut a = Vec::with_capacity(manifest.total_size as usize); }";
    assert!(
        !flagged_sites(bad).is_empty(),
        "detector missed the bad pattern"
    );
    let bad_vec = "fn f(m: M) { let b = vec![0u8; m.size_bytes as usize]; }";
    assert!(
        !flagged_sites(bad_vec).is_empty(),
        "detector missed vec! form"
    );
    let bad_multiline =
        "let a = Vec::with_capacity(\n    (manifest.total_size as usize)\n        .min(1),\n);";
    assert!(
        !flagged_sites(bad_multiline).is_empty(),
        "detector missed multi-line form"
    );
    let good = "let mut assembler = ChunkAssembler::new(&manifest)?; let v = Vec::with_capacity(planned_capacity);";
    assert!(
        flagged_sites(good).is_empty(),
        "detector flagged the bounded form"
    );
    let test_only =
        "#[cfg(test)]\nmod tests { fn t() { Vec::with_capacity(manifest.total_size as usize); } }";
    assert!(
        flagged_sites(test_only).is_empty(),
        "detector scanned test code"
    );
}

#[test]
fn no_allocation_sized_from_manifest_fields_in_core() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core/ dir")
        .to_path_buf();
    let mut files = Vec::new();
    rust_files(&core, &mut files);
    assert!(
        files.len() > 50,
        "scan found too few files: {}",
        files.len()
    );

    let mut violations = Vec::new();
    for f in &files {
        let Ok(src) = fs::read_to_string(f) else {
            continue;
        };
        let rel = f
            .strip_prefix(&core)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        for (tok, expr) in flagged_sites(&src) {
            let allowed = ALLOWLIST
                .iter()
                .any(|(path, t, _)| rel.ends_with(path) && *t == tok);
            if !allowed {
                violations.push(format!("{rel}: `{expr}` (token `{tok}`)"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "allocation sized from a manifest-declared field; validate it first:\n{}",
        violations.join("\n")
    );
}

#[test]
fn model_loader_routes_manifests_through_the_assembler() {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/execution.rs"))
        .expect("read execution.rs");
    assert!(
        src.contains("ChunkAssembler::new(&manifest)"),
        "load_model must validate the chunk manifest via ChunkAssembler"
    );
}
