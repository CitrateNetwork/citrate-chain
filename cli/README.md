# CLI

Command-line interface for interacting with a running Citrate node. Provides subcommands for account management, contract deployment, model operations, governance, and network diagnostics.

## Contents

- `src/main.rs` -- Entry point and argument parsing
- `src/commands/account.rs` -- Account creation, balance queries, transfers
- `src/commands/contract.rs` -- Contract deployment and interaction
- `src/commands/verify.rs` -- Source verification client for CitrateScan's Etherscan-compatible API
- `src/commands/model.rs` -- AI model registration, listing, and inference
- `src/commands/governance.rs` -- On-chain governance proposals and voting
- `src/commands/network.rs` -- Peer info and network diagnostics
- `src/commands/wizard.rs` -- Interactive setup wizard
- `src/config.rs` -- CLI configuration (RPC URL, keyfile paths)

## Build / Usage

```bash
cargo build --release -p citrate-cli
cargo run --bin citrate-cli -- --help
cargo run --bin citrate-cli -- account balance --address 0x1111...1111 --rpc-url http://localhost:8545
```

## Verifying contracts (`citrate contract verify`)

`citrate contract verify` submits source to CitrateScan, the explorer for chain 40204, through
its Etherscan-compatible API (`https://explorer.citrate.ai/api`, actions `verifysourcecode` and
`checkverifystatus`). It does not call the node. The explorer recompiles with the exact solc
release and compares the result with the code on chain. The CLI only submits and reports the
verdict.

Forge: build with full build-info, then point at the file.

```bash
forge build --build-info            # or build_info = true in foundry.toml
citrate contract verify 0xYourContractAddress \
  --build-info out/build-info/<id>.json \
  --contract src/MyContract.sol:MyContract \
  --constructor-args $(cast abi-encode "constructor(uint256,string)" 7 "hello") \
  --watch
```

A plain `forge build` writes a build-info without the compiler input. The CLI refuses that
file and tells you to rebuild with `--build-info`.

Hardhat: pass the contract artifact. The CLI follows the `.dbg.json` next to it to the
build-info, and takes the contract name from the artifact.

```bash
npx hardhat compile
citrate contract verify 0xYourContractAddress \
  --build-info artifacts/contracts/MyContract.sol/MyContract.json --watch
```

Other inputs:

```bash
# A standard JSON input, e.g. from `forge verify-contract --show-standard-json-input`
citrate contract verify 0xYourContractAddress --standard-json input.json \
  --contract src/MyContract.sol:MyContract --compiler v0.8.26+commit.8a97fa7a --watch

# One flattened source file
citrate contract verify 0xYourContractAddress MyContract.sol \
  --compiler v0.8.26+commit.8a97fa7a --optimized --runs 200 --evm-version cancun \
  --library MyLib:0xYourLibraryAddress --watch

# Without --watch the CLI prints the guid. Check it later:
citrate contract verify-status <guid> --watch

# The explorer's verified record for an address (getsourcecode)
citrate contract verify-get 0xYourContractAddress
```

| Flag | Default | Notes |
|---|---|---|
| `--explorer-url` | `https://explorer.citrate.ai/api` | also `CITRATE_EXPLORER_URL` |
| `--api-key` | none | sent as `apikey`; also `CITRATE_EXPLORER_API_KEY`. Verification needs no key |
| `--constructor-args` | none | ABI-encoded hex. Optional: the explorer reads the arguments from the creation transaction |
| `--creation-tx` | none | creation transaction hash, sent as `creationtxhash` |
| `--watch` | off | poll `checkverifystatus` until `Pass - Verified` or `Fail - Unable to verify` |
| `--poll-interval-ms`, `--watch-timeout-secs` | 3000, 300 | polling cadence and deadline |

The CLI sends only the sources the contract's metadata lists, as forge and hardhat-verify do. The
explorer accepts at most 64 files and 2 MiB, with inline content only. A submission the
explorer refuses (`Contract source code already verified`,
`Unable to locate ContractCode at 0x…`) is reported with the explorer's own message. After
`Max rate limit reached` the CLI waits 5 s and retries, up to 3 times.

The node's `citrate_verifyContract` RPC method is an operator tool that needs the operator
token. The CLI no longer uses it. `citrate contract verify-list` still lists the records stored
on the node.

### forge and hardhat directly

Standard tools work against the same API. Two details matter on chain 40204:

- **forge:** use `--verifier custom`. With forge 1.5.1, `--verifier etherscan` stops before
  sending anything ("No known Etherscan API URL for chain `40204`"). `custom` speaks the same
  protocol. `--verifier-api-key` must be present, and any value works.

  ```bash
  forge verify-contract --chain 40204 --rpc-url https://rpc.citrate.ai \
    --verifier custom --verifier-url https://explorer.citrate.ai/api --verifier-api-key citrate \
    --watch 0xYourContractAddress src/MyContract.sol:MyContract
  ```

- **hardhat-verify:** give `apiKey` as a per-network object (`apiKey: { citrate: "citrate" }`)
  with a `customChains` entry for chainId 40204 and `apiURL: "https://explorer.citrate.ai/api"`.
  With hardhat-verify 2.1.3 a single string `apiKey` switches it to Etherscan's v2 mode, which
  ignores `customChains` and sends the request to api.etherscan.io. The deprecation warning it
  prints about per-network keys applies to etherscan.io, not to this API.
