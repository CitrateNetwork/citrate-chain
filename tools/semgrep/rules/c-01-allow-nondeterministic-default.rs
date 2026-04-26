// C-01 / REM-N-03 — fixture for c-01-allow-nondeterministic-default.yaml
//
// Run via: `semgrep --config c-01-allow-nondeterministic-default.yaml \
//                   c-01-allow-nondeterministic-default.rs`
// Both `ruleid:` markers must produce findings; both `ok:` markers must not.
//
// This file is NOT compiled — it is fixture data only.

#![cfg(any())] // never compiled

struct InferencePrecompile {
    allow_nondeterministic_inference: bool,
}

// ============================================================================
// POSITIVES — these patterns must be flagged
// ============================================================================

fn bad_struct_literal_default() -> InferencePrecompile {
    // ruleid: c-01-allow-nondeterministic-default
    InferencePrecompile {
        allow_nondeterministic_inference: true,
    }
}

fn bad_field_assignment(p: &mut InferencePrecompile) {
    // ruleid: c-01-allow-nondeterministic-default
    p.allow_nondeterministic_inference = true;
}

// ============================================================================
// NEGATIVES — these patterns must NOT be flagged
// ============================================================================

// ok: c-01-allow-nondeterministic-default
// Strict-by-default is the production posture (REM-N-03 closure).
fn good_strict_default() -> InferencePrecompile {
    InferencePrecompile {
        allow_nondeterministic_inference: false,
    }
}

// ok: c-01-allow-nondeterministic-default
// Mode-driven construction never inlines `: true` against the field.
fn good_mode_driven(mode: InferenceMode) -> InferencePrecompile {
    InferencePrecompile {
        allow_nondeterministic_inference: matches!(mode, InferenceMode::AllowNonDeterministic),
    }
}

// Note: the regex engine cannot see `#[cfg(...)]` attributes from a
// pattern-regex expression. Production code that legitimately needs
// to set `allow_nondeterministic_inference = true` under a `cfg(test)`
// or `cfg(feature = "dev-mode")` guard MUST add a `// nosem` comment
// on the offending line. Today no such call site exists — the
// canonical construction path is `InferencePrecompile::new_with_mode(
// runtime, InferenceMode::AllowNonDeterministic)`, which uses
// `matches!(mode, InferenceMode::AllowNonDeterministic)` rather than a
// literal `= true`. The fixture cases below document the intent; in
// the unlikely event a future refactor reintroduces a literal, the
// `// nosem: c-01-allow-nondeterministic-default` marker is the
// documented escape hatch.

// Devnet opt-in is gated behind the `dev-mode` cargo feature.
#[cfg(feature = "dev-mode")]
fn devnet_opt_in() -> InferencePrecompile {
    InferencePrecompile {
        // nosem: c-01-allow-nondeterministic-default
        allow_nondeterministic_inference: true,
    }
}

// Tests are excluded by `paths.exclude`.
#[cfg(test)]
fn test_helper() -> InferencePrecompile {
    InferencePrecompile {
        // nosem: c-01-allow-nondeterministic-default
        allow_nondeterministic_inference: true,
    }
}

enum InferenceMode {
    Strict,
    AllowNonDeterministic,
}
