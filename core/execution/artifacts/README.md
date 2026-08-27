# 0x0130 fold-verifier baked key (`commd_fold_vk.bin`)

The `commd-fold-verify` feature embeds a SINGLE Nova `CompressedSNARK` verifier key here via
`include_bytes!`. One key verifies proofs for **every** file size (the circuit is fixed-arity —
`FixedCommDFoldStep`, `MAX_DEPTH = 40`). The key is a large (~27 MB) generated artifact and is **not
committed**; a feature-ON build requires it to exist first.

## Producing the key (citrate-chain#170, M3)

```
# PRODUCTION — from a trusted-setup ceremony .ptau directory:
cargo run --release --manifest-path ../../crates/citrate-commd-fold/Cargo.toml \
  --bin bake_vk -- --ptau-dir /path/to/ptau --out artifacts/commd_fold_vk.bin

# DEV / CI only — INSECURE deterministic test-utils SRS (reproducible toxic waste; never ship):
cargo run --release --manifest-path ../../crates/citrate-commd-fold/Cargo.toml \
  --bin bake_vk -- --dev --out artifacts/commd_fold_vk.dev.bin   # then rename to commd_fold_vk.bin
```

The tool prints the key's size and a BLAKE3 digest. **Pin the production digest** in
`ADR-2026-08-27-pin-commd-bond-zk-challenge` and in the `0x0130` precompile comment so the baked key is
auditable.

## Activation (owner-gated — a consensus change)

1. Run a real trusted-setup ceremony → `.ptau`; bake the key here (drop the insecure `--dev` SRS).
2. Build validators with `--features commd-fold-verify`; **all nodes must agree** — coordinate a fleet
   upgrade / activation height. Until every node runs it, do NOT route real traffic to `0x0130`.
3. Redeploy `IPFSIncentivesV3` on 40204 with `foldVerifier = 0x0130`; update the address JSONs.
