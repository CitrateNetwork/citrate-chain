---
created: 2026-11-12T19:30:00Z
branch: docs/cli-qa-r1007
author: CLI QA lane (Claude Opus 5.5), directed by Larry Klosowski (@SaulBuilds)
status: active
purpose: Command-by-command QA of citrate-cli and citrate-wallet against live r1007 (chain 40204), plus install instructions
---

# CLI QA against live r1007

Run on 2026-11-12, 17:40Z to 19:20Z, against `https://rpc.citrate.ai`. That endpoint serves chain 40204, genesis
`0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631`, blocks 6,867 to about 8,000 during the run.

- **Build:** `cargo build --release -p citrate-cli` and `-p citrate-wallet` at main `02aa3f89`, on citrate-core-linux-build
  (x86_64 Linux). The `cli/` and `wallet/` trees on main are identical to tag `r1007-genesis` (a53bac64) and PR #465.
- **Write-path key:** one throwaway ed25519 key, created on the build host with `citrate-cli account create`
  (address `0xbc6a39c7d861a8f3d791f8a025051e7eac7043bb`). It was funded by one faucet drip of 10 SALT
  (tx `0x2e40aea4…5a6f`, block 6956). No real or role key was used, and no private key was printed.

## How users get the CLI today

| Path | State on 2026-11-12 |
|---|---|
| Build from source | **Works.** This is the only path that gives an r1007-ready CLI (see below). |
| GitHub release tarball (`release.yml`) | The newest release is `v0.5.0-beta1` (2026-05-24), which predates r1007. The tarball ships `citrate-node`, `citrate-cli`, `citrate-wallet` and `citrate-faucet`. No release has been cut for r1007. |
| Homebrew (`homebrew/citrate.rb`) | **Not usable.** The tap is not published. The formula pins `v0.4.0`, which has no release, and its sha256 values are `PENDING_RELEASE_DIGEST`. It installs `citrate` and `faucet`, but the tarball names them `citrate-node` and `citrate-faucet`. `homebrew/README.md` still says `brew install citrate-ai/tap/lattice`. |
| Citrate Core app 0.5.x | **Not bundled.** Core's `externalBin` ships `binaries/citrate`, which is the node, not `citrate-cli`. |

### Install (source build)

```bash
git clone https://github.com/CitrateNetwork/citrate-chain.git
cd citrate-chain
cargo build --release -p citrate-cli -p citrate-wallet
# Binaries: target/release/citrate-cli and target/release/wallet (shipped as citrate-wallet)
export CITRATE_RPC=https://rpc.citrate.ai      # or pass --rpc on each command
target/release/citrate-cli network status       # expect Chain ID 40204, Genesis 0xcf686345…6631
```

`citrate-cli` reads chain data and manages a local ed25519 keystore. It does **not** sign transactions. Its write
commands send `eth_sendTransaction`, which public nodes refuse. To move SALT, use `citrate-wallet send`, which signs
locally. Both tools use the same keystore format, so a key exported from one (`account export --out`) imports into
the other with the same address.

## Matrix

PASS means the command ran against live r1007 and printed correct data. FIXED means it failed, and the PR named fixes
it (red test first, then a live re-run of the fixed build). Errors are quoted as the CLI printed them.

### citrate-cli 0.4.0 (prints `citrate 0.4.0` for `--version`)

| Command | Result | Notes |
|---|---|---|
| `init` | PASS | A second run refuses without `--force`. |
| `network status` | PASS, FIXED #468 | It printed the config's chain id. It now prints the node's `eth_chainId` and block-0 hash, and warns that the vendored book is r1006 (see below). |
| `network block <n>` / `latest` / `0` | FAIL, FIXED #467 | It panicked on every block: `network.rs:370: no entry found for key`. The node sends `mergeParentHashes`, and `blueScore` comes as hex. |
| `network transaction <hash>` | PASS | It decodes the faucet tx and the self-transfers, with receipt status and gas used. A missing hash prints `Transaction not found`. |
| `network gas-price` | PASS | 1 gwei. The unit is now SALT, not ETH (#468). |
| `network peers` | PASS | 10 peers. |
| `network sync` | PASS | SYNCED. |
| `network dag-stats` | PASS | It shows height, total blocks and tips. Blue and red block counts print `not tracked`, which is the node's answer. |
| `network bootnodes` | NOT RUN | It needs `--bootnodes` or `CITRATE_BOOTNODES`, and it says so. |
| `account create` / `list` | PASS | `list` with no keystore dir fails: `Failed to read keystore directory`. |
| `account balance <addr>` | PASS | The unit is now SALT (#468). |
| `account export --out` | PASS | It writes the file with mode 0600, and refuses stdout without `--confirm-stdout`. |
| `account import --key-file` | PASS | Same address in a second keystore. A duplicate import refuses: `Account already exists in keystore`. |
| nonce | NO COMMAND | The CLI has no nonce command. `citrate-wallet list` shows the nonce. |
| `contract code <addr>` | PASS | WrappedSALT `0xaa91…c906`, 5101 bytes. |
| `contract read <addr> <sig>` | PASS | `totalSupply()`, `balanceOf(address)` and `symbol()` return. Strings print raw ABI hex, not decoded. |
| `contract call` / `deploy` | FAIL (by design), message FIXED #468 | `eth_sendTransaction is disabled`. There is no local signer. The error now names the next step. |
| `contract verify-get` | PASS | `No verified source on the explorer for 0xaa91…`. |
| `contract verify-status <guid>` | PASS | A bogus guid gets `Unknown UID`. |
| `contract verify-list` | PASS | 0 records. `verify` itself was not run (no contract to submit). |
| `governance get-param` | FAIL, partly FIXED #468 | It failed with `Missing default account` for a read. It now sends no `from`, and the precompile at `0x…1003` answers `execution reverted: Access denied` (node side, open). |
| `governance set-admin` / `queue-param` / `execute-param` | FAIL (by design) | Same `eth_sendTransaction` path as `contract call`. Not attempted. |
| `model list` | PASS | `No models found`. |
| `model info <id>` | PASS | It needs a 32-byte id. `0x01` gets `Invalid model ID format`. |
| `model search <q>` | PASS | It queries HuggingFace. The hints say `citrate model download`, but the binary is `citrate-cli`. |
| `model deploy` / `inference` / `update` / `verify` / `download` | NOT RUN | `deploy` and `update` are writes. `inference` needs a deployed model. |
| `advanced monitor --count 1 [--dag --mempool]` | PASS | It prints hex quantities (`0x1afd`), and DAG and mempool fields print `N/A`. |
| `advanced topology` | PASS | It prints a header only. The node exposes no topology. |
| `advanced tx-debug <hash> [--trace]` | PASS | It prints hex quantities. |
| `advanced model-stats` | PASS | `No statistics available`. |
| `advanced benchmark` / `stress-test` | NOT RUN | These are load generators over `eth_sendTransaction`, so they do not belong on the public RPC. |
| `wizard *` | NOT RUN | Interactive. |
| `devx contract --section chain` | FAIL (stale data) | It prints genesis `0xa3651a27…cdd4` (r1006). `cli/federation-contract.json` is being re-synced by the address lane (`chore/cli-contract-r1007`). This QA pass leaves the file alone. |
| `devx contract --section aa` | PASS | The AA stack and membership addresses match the r1007 book (`contracts/addresses/40204.json`). |
| `devx predict-address` | PASS | It returns an address from the vendored factory, which is unchanged in r1007. |
| no `--rpc`, no local node | FIXED #468 | It printed a bare `Connection refused`. It now names the endpoint and `--rpc https://rpc.citrate.ai`. |

The vendored `cli/federation-contract.json` also lists 28 contracts that are not in the r1007 root book. These
include AppRegistry, Sortition, TenantHierarchy and the DefensePrime registries. That is input for the address lane.

### citrate-wallet (`wallet` bin)

| Command | Result | Notes |
|---|---|---|
| `import` (prompted key) | PASS | Same address as `citrate-cli`. |
| `list` | PASS | 10 SALT, nonce 0. |
| `info` | PASS | Chain 40204, current block. |
| `send` (defaults) | PASS | 0.001 SALT to self, tx `0x4f26db08…3c55`, block 7059, 1 gwei. |
| `send --gas-price 2 --gas-limit 21000` | FAIL, FIXED #469 | `-g` was on both flags, a debug build panicked, and `send` ignored both values. Fixed: tx `0x5d3f243f…4e5b`, block 8002, 2 gwei. |
| `new`, `export`, `interactive` | NOT RUN | |

Prompts are interactive only: the wallet has no password-file or stdin flag. Scripted use needs a pty.

## Open findings (not fixed here)

1. **Node RPC (`core/api/src/eth_rpc.rs`, `pubkey_hex_to_evm_address`):** for a native ed25519 transaction,
   `eth_getTransactionByHash` and full `eth_getBlockByNumber` report `from` as the first 20 bytes of the public key
   (`0x10ebe0d8…4c94`). The account that pays and holds the balance is `keccak(pubkey)[12..]` (`0xbc6a39c7…43bb`).
   Explorers and SDKs that read `from` show the wrong sender. This needs a chain lane decision and a node release.
2. **There is no local signer in citrate-cli.** Contract, governance and model writes cannot reach a public node.
   Fixing that means signing in the CLI (EIP-155 secp256k1, or the native ed25519 format the wallet uses). That
   is a feature, outside this QA pass.
3. **The governance precompile** answers `Access denied` to an unauthenticated `get-param` read.
4. **Distribution:** cut an r1007 release from `release.yml`, then fix the Homebrew formula's binary names, version
   and digests before the tap is published.
5. **Naming:** clap's `name = "citrate"` makes `--version` print `citrate 0.4.0`, and the `model search` hints say
   `citrate …`, but the binary is `citrate-cli`, and `citrate` is the node. The `/chain/cli` page in citrate-docs
   says `cargo build -p citrate-cli` "produces the `citrate` binary".

## PRs from this pass (citrate-chain)

| PR | Branch | What |
|---|---|---|
| #467 | `fix/cli-block-render-r1007` | `network block` panic; `[]` on a Map replaced at 16 RPC-result sites |
| #468 | `fix/cli-r1007-guidance` | status chain and genesis, get-param without an account, next steps for refused sends and unreachable nodes, SALT units |
| #469 | `fix/wallet-gas-flag-clash` | wallet `-g` clash; gas flags reach the transaction |

#467 and #468 both edit `cli/src/commands/network.rs`. The second to merge needs a rebase, and the conflict is one
hunk in `get_gas_price`.
