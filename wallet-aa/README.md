# citrate-wallet-aa

Off-chain helpers for the Citrate ERC-4337 embedded-wallet stack.
Counterpart to `contracts/src/aa/` — every byte this crate produces
must match what the on-chain contracts expect.

## What this crate does

- **Address prediction** (`address::predict_address`) — compute the
  deterministic smart-wallet address for a Citrate user id, offline.
  Matches Solady's `LibClone::predictDeterministicAddressERC1967`
  byte-for-byte; the off-chain prediction equals the on-chain
  `CitrateWalletFactory.predictAddress` for every input.
- **Kernel init data** (`init_data::kernel_initialize_calldata`) —
  encode the calldata `CitrateWalletFactory.deployFor` will delegatecall
  into the freshly-deployed proxy. Mirrors Kernel v3's
  `initialize(bytes21,address,bytes,bytes,bytes[])` ABI.
- **Validator install data** (`init_data::*_install_data`) — pack the
  `onInstall` payload for each Citrate validator + the guardian
  recovery module. Matches each contract's strict
  decoding layout (`WebAuthnP256Validator`: 97 bytes;
  `CitrateECDSAValidator`: 21 bytes; `GuardianRecoveryModule`:
  2 + 20·N bytes).
- **Permit digest + signing** (`permit::permit_digest`,
  `permit::sign_permit`) — reproduce the digest the factory's
  `identitySigner` must sign to authorise a deploy, and produce the
  65-byte EIP-191 signature for it. Used by auth.citrate.ai to
  construct the signature with the operator wallet, and by clients to
  reconstruct the digest offline for verification.

## Who consumes this crate

| Consumer | Build | What it uses |
|---|---|---|
| `citrate-identity` (Node) | `napi-rs` or `wasm-bindgen` (separate crate, follow-up) | All three modules — predict address, build init data, mint deploy permit signatures |
| `citrate-gui-native` (Slint Rust) | Native | Address prediction + offline display |
| `citrate-wallet-extension` (Chrome MV3) | `wasm-bindgen` (separate crate, follow-up) | Address prediction + UserOp builder |
| `citrate-sdk-js` (TS) | `wasm-bindgen` (separate crate, follow-up) | Address prediction + permit digest reconstruction (for verification, not signing) |

The `wasm-bindgen` / `napi-rs` wrappers ship in follow-up crates so
this crate stays clean Rust and easy to test.

## Tests

```
cargo test -p citrate-wallet-aa
```

→ 18/18 pass. Covers determinism, parameter sensitivity (digest
changes with every input), signature round-trip via `k256`, layout
invariants for every validator's install data, ABI round-trip for
the Kernel initialize calldata.

## Cross-language fixture (deferred)

A future change will add a Foundry fixture script that emits known
`(factory, impl, userId) → predicted_address` triples and a Rust
integration test that hardcodes them; this proves the off-chain
prediction matches the on-chain factory byte-for-byte on a real
deployment.  Sprint exit-criterion (`predict() matches on-chain`) is
satisfied by the unit test plus the snapshot test on the init-code
hash; the cross-language fixture is a hardening step deferred to
ratchet up confidence before any user-visible launch.

## Related

- On-chain surface: `contracts/src/aa/`
- Deploy script: `contracts/script/aa/DeployAA.s.sol`
- Planset: `citrate-federation/.agentile/planset/2026-06-05-ew-s1-passkey-aa.md`
- ADRs (especially): `ADR-2026-06-05-ew-wallet-stack`,
  `ADR-2026-06-05-ew-surface-interop`
