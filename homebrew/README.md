# homebrew/

Homebrew formula for installing Citrate CLI tools on macOS and Linux.

## Files

### citrate.rb

Homebrew formula that installs:
- `citrate` -- node binary
- `citrate-cli` -- CLI tools
- `citrate-wallet` -- wallet management
- `faucet` -- testnet faucet

Supports macOS (Intel + Apple Silicon) and Linux (x86_64 + arm64).
Downloads pre-built binaries from GitHub Releases.

Includes a `launchd`/`systemd` service definition to run the node as a
background service with automatic restart.

## Usage

```bash
# Install (once the tap is published)
brew install citrate-ai/tap/lattice

# Start as background service
brew services start lattice

# Verify
citrate --version
```

Note: SHA256 checksums are placeholder values (`TBD`) and must be updated
during each release build.
