# 0x0130 fold-verifier baked key (`commd_fold_vk.bin`)

The `commd-fold-verify` feature embeds a SINGLE Nova `CompressedSNARK` verifier key here via
`include_bytes!`. One key verifies proofs for **every** file size (the circuit is fixed-arity —
`FixedCommDFoldStep`, `MAX_DEPTH = 40`).

## STATUS: production key baked + committed (citrate-chain#170, 2026-08-27)

`commd_fold_vk.bin` (27,152,352 bytes) is the **production** verifier key and **is committed** (shipped
with the source so validators build with it embedded).

**Provenance — audit by re-baking and comparing the BLAKE3:**
- **SRS:** PSE **Perpetual Powers of Tau**, `ppot_0080_17.ptau`
  (`sha256 f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c`), from
  <https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/>. The community ceremony
  (80+ contributors) — **not** the insecure `--dev` SRS.
- **BLAKE3(commd_fold_vk.bin):** `1e20b9244a63f4323fc7b5b6e3770c586a3122e7c43e520d601edbebd6c6e2d4`.
- The circuit's augmented primary is 42,832 constraints → needs 2^16 generators; `ppot_0080_17` (2^17)
  covers it with margin and yields the identical key a 2^16 file would (the ceremony is one sequence).

## Re-baking (to audit or regenerate)

```
# 1. download the trusted PPOT (once):
curl -o ppot/ppot_0080_17.ptau \
  https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_17.ptau
# 2. bake + compare the digest:
cargo run --release --manifest-path ../../crates/citrate-commd-fold/Cargo.toml \
  --bin bake_vk -- --ptau-dir ./ptau --out /tmp/vk.bin
b3sum /tmp/vk.bin   # must equal 1e20b924…c6e2d4
```

## ⚠️ Prover must match the SRS

A challenger's proof only verifies against this key if it was produced with the **same** ptau. The
challenge-proving tooling must build its `PublicParams` via
`citrate_commd_fold::commd_fixed_fold::fixed_public_params_ptau(<same ppot dir>)` — **not** the
`fixed_public_params()` (`--dev`) path.

## Activation (owner-gated — a consensus change)

Build validators with `--features commd-fold-verify` (the `node` package passthrough) — **all nodes
must agree** (a genesis/reroll or coordinated activation). Then `IPFSIncentivesV3.challengeWrongCommD`
(already deployed at `0xa1a37f79…` with `foldVerifier = 0x0130`) becomes enforceable.
