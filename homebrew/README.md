# homebrew/

Homebrew formula for installing Citrate CLI tools on macOS and Linux.

## Files

### citrate.rb

Homebrew formula that installs the four binaries in the release tarball
(`.github/workflows/release.yml`, asset `citrate-chain-<target>.tar.gz`):
- `citrate-node` -- node binary
- `citrate-cli` -- CLI tools
- `citrate-wallet` -- wallet management
- `citrate-faucet` -- testnet faucet server

Supports macOS (Intel + Apple Silicon) and Linux (x86_64 + arm64).
Downloads pre-built binaries from GitHub Releases.

Includes a `launchd`/`systemd` service definition that runs `citrate-node
--network testnet` as a background service with automatic restart.

## Status

The tap is not published, and no release this formula can point at has
been cut yet. Until then, build from source (`cargo build --release -p
citrate-cli -p citrate-wallet`).

Each `sha256` is the marker `PENDING_RELEASE_DIGEST`, which is not a valid
digest, so `brew` refuses to install (fail closed). At release time, set
`version` to the release tag without the `v`, and replace each marker with
the digest from that tag's `<asset>.sha256` file.

`scripts/tests/test_homebrew_formula.sh` (run in merge-gate) checks that the
formula's binary and asset names match what `release.yml` ships.

## Usage (once a release and the tap exist)

```bash
brew install citrate   # from the CitrateNetwork tap
citrate-cli --rpc https://rpc.citrate.ai network status
brew services start citrate
```
