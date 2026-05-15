# Building the echo-chain capsule

Standalone source crate — NOT a workspace member. Compiles to a
WASM component that imports `citrate:chain/eth-call@0.1.0`.

```bash
cd citrate_v0.01.1/tools/cps-build/echo-chain-capsule
cargo component build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/echo_chain_capsule.wasm \
   ../../capsules/echo-chain/capsule.wasm
```

The WIT depends on the `citrate:chain` package, declared inline
at `wit/deps/chain/eth-call.wit` and wired via the Cargo.toml
metadata:

```toml
[package.metadata.component.target.dependencies]
"citrate:chain" = { path = "wit/deps/chain" }
```

The cit-agent harness registers `citrate:chain/eth-call@0.1.0`
as a host function when the capsule's manifest declares
`chain_calls = ["eth_call:0x..."]`. The host fn enforces the
per-address allow-list at call time.
