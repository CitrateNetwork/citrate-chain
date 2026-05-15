# Building the hello capsule

This crate is NOT a workspace member. It compiles to a WASM
component via `cargo-component`. To rebuild and stage the
artifact:

```bash
cd citrate_v0.01.1/tools/cps-build/hello-capsule
cargo component build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/hello_capsule.wasm \
   ../../capsules/hello/capsule.wasm
```

The `wasm32-unknown-unknown` target avoids the WASI preview1→2
adapter, so the compiled component imports nothing — matching
the manifest's `network = "none", filesystem = [], chain_calls = []`
declaration.

If you build for `wasm32-wasip1` (or `wasm32-wasip2`), the
component will import the full WASI surface and the cit-agent
manifest-built linker will reject it at instantiate time
(correctly, per the CIT-AGENT-9a fail-closed witness).

## Toolchain versions used in CIT-AGENT-9b

- `cargo-component 0.21.1`
- `wasm-tools 1.248.0`
- `wit-bindgen-rt 0.36`
- `rustup target wasm32-wasip2` + `wasm32-unknown-unknown`
- `wasmtime 26` (consumer side)
