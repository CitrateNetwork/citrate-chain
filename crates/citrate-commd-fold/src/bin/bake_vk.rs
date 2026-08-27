//! bake_vk (citrate-chain#170, M3) — generate the SINGLE baked verifier key for the fixed-arity CommD
//! fold circuit, the artifact the `0x0130` precompile embeds via `include_bytes!`.
//!
//! Because the circuit has a constant arity (`MAX_DEPTH`), ONE key verifies proofs for every file.
//!
//! Usage:
//!   # PRODUCTION — commitment key from a trusted-setup ceremony .ptau directory:
//!   cargo run --release --bin bake_vk -- --ptau-dir /path/to/ptau --out artifacts/commd_fold_vk.bin
//!
//!   # DEV / CI only — insecure deterministic `test-utils` SRS (reproducible toxic waste; NEVER ship):
//!   cargo run --release --bin bake_vk -- --dev --out /tmp/commd_fold_vk.dev.bin
//!
//! The output is bincode(`CompressedSNARK` VerifierKey), byte-compatible with
//! `citrate-commd-verify::verify_fold_proof`. The tool prints the key's size and a BLAKE3 digest so
//! the baked artifact can be pinned in review (the digest goes in the ADR / the precompile's comment).

use std::path::PathBuf;
use std::process::ExitCode;

use citrate_commd_fold::commd_fixed_fold::{
    compressed_verifier_key, fixed_public_params, fixed_public_params_ptau, MAX_DEPTH,
};

fn usage() -> &'static str {
    "usage: bake_vk (--ptau-dir <dir> | --dev) --out <file>"
}

fn main() -> ExitCode {
    let mut ptau_dir: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut dev = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ptau-dir" => match args.next() {
                Some(v) => ptau_dir = Some(PathBuf::from(v)),
                None => return fail("--ptau-dir needs a value"),
            },
            "--out" => match args.next() {
                Some(v) => out = Some(PathBuf::from(v)),
                None => return fail("--out needs a value"),
            },
            "--dev" => dev = true,
            other => return fail(&format!("unknown arg {other}\n{}", usage())),
        }
    }

    let out = match out {
        Some(o) => o,
        None => return fail(&format!("--out is required\n{}", usage())),
    };
    if dev == ptau_dir.is_some() {
        return fail(&format!(
            "pass EXACTLY one of --ptau-dir <dir> (production) or --dev (insecure)\n{}",
            usage()
        ));
    }

    eprintln!("bake_vk: fixed-arity CommD fold circuit, MAX_DEPTH={MAX_DEPTH}");
    let pp = if dev {
        eprintln!("bake_vk: ⚠️  DEV mode — insecure deterministic test-utils SRS. DO NOT SHIP.");
        fixed_public_params()
    } else {
        let dir = ptau_dir.as_ref().expect("checked above");
        eprintln!("bake_vk: production SRS from ptau dir {}", dir.display());
        fixed_public_params_ptau(dir)
    };
    let pp = match pp {
        Ok(pp) => pp,
        Err(e) => return fail(&format!("building public params failed: {e}")),
    };

    let vk_bytes = match compressed_verifier_key(&pp) {
        Ok(b) => b,
        Err(e) => return fail(&format!("verifier-key setup/serialize failed: {e}")),
    };

    if let Err(e) = std::fs::write(&out, &vk_bytes) {
        return fail(&format!("writing {} failed: {e}", out.display()));
    }

    let digest = blake3::hash(&vk_bytes);
    eprintln!(
        "bake_vk: wrote {} bytes to {} (blake3 {})",
        vk_bytes.len(),
        out.display(),
        digest.to_hex()
    );
    eprintln!("bake_vk: pin this digest in the ADR + the 0x0130 precompile comment.");
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("bake_vk: {msg}");
    ExitCode::FAILURE
}
