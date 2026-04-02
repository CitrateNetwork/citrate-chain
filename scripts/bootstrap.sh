#!/usr/bin/env bash
# bootstrap.sh — one-step bootstrap for developers and agent operators
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile developer
#   curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile agent

set -euo pipefail

PROFILE="developer"
INSTALL_ROOT="${CITRATE_INSTALL_ROOT:-$HOME/src}"
REPO_URL="${CITRATE_REPO_URL:-https://github.com/SaulBuilds/citrate.git}"
WORKTREE_DIR="${CITRATE_WORKTREE_DIR:-$INSTALL_ROOT/citrate}"
SKIP_SYSTEM_PACKAGES=0
SKIP_BUILD=0
WITH_GUI=0

usage() {
    cat <<'EOF'
Usage: bootstrap.sh [options]

Options:
  --profile <runtime|developer|agent|full>   Bootstrap profile (default: developer)
  --install-root <dir>                       Where the repo will be cloned (default: ~/src)
  --repo-url <url>                           Git repository URL
  --skip-system-packages                     Do not install apt/brew packages
  --skip-build                               Clone and prepare only; do not build Rust binaries
  --with-gui                                 Also build the native Slint GUI
  -h, --help                                 Show this help

Profiles:
  runtime     Base CLI/operator dependencies
  developer   runtime + Rust + Foundry
  agent       developer + Ollama best-effort install
  full        agent + GUI build
EOF
}

log() {
    printf '[citrate-bootstrap] %s\n' "$*"
}

warn() {
    printf '[citrate-bootstrap] WARNING: %s\n' "$*" >&2
}

have() {
    command -v "$1" >/dev/null 2>&1
}

run() {
    log "+ $*"
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --install-root)
            INSTALL_ROOT="$2"
            WORKTREE_DIR="$INSTALL_ROOT/citrate"
            shift 2
            ;;
        --repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        --skip-system-packages)
            SKIP_SYSTEM_PACKAGES=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --with-gui)
            WITH_GUI=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

case "$PROFILE" in
    runtime|developer|agent|full) ;;
    *)
        echo "Invalid profile: $PROFILE" >&2
        usage
        exit 1
        ;;
esac

if [[ "$PROFILE" == "full" ]]; then
    WITH_GUI=1
fi

detect_pkg_manager() {
    if have apt-get; then
        echo "apt"
    elif have brew; then
        echo "brew"
    else
        echo "none"
    fi
}

install_base_packages() {
    local pm="$1"
    case "$pm" in
        apt)
            run sudo apt-get update
            run sudo apt-get install -y \
                ca-certificates curl git jq unzip tar ripgrep \
                build-essential pkg-config libssl-dev clang cmake
            ;;
        brew)
            run brew update
            run brew install git jq ripgrep pkg-config openssl cmake
            ;;
        none)
            warn "No supported package manager detected. Install curl, git, jq, ripgrep, pkg-config, clang, cmake, and OpenSSL manually."
            ;;
    esac
}

install_rust() {
    if have cargo; then
        return
    fi
    log "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
}

install_foundry() {
    if have forge; then
        return
    fi
    log "Installing Foundry..."
    curl -L https://foundry.paradigm.xyz | bash
    export PATH="$HOME/.foundry/bin:$PATH"
    "$HOME/.foundry/bin/foundryup"
}

install_ollama_best_effort() {
    if have ollama; then
        return
    fi
    case "$(uname -s)" in
        Linux|Darwin)
            log "Attempting best-effort Ollama install..."
            if ! curl -fsSL https://ollama.com/install.sh | sh; then
                warn "Ollama install failed. Install manually from https://ollama.com/download"
            fi
            ;;
        *)
            warn "Ollama bootstrap is only automated for Linux/macOS. Install manually for this platform."
            ;;
    esac
}

clone_or_update_repo() {
    mkdir -p "$INSTALL_ROOT"
    if [[ -d "$WORKTREE_DIR/.git" ]]; then
        log "Repo already exists at $WORKTREE_DIR"
        run git -C "$WORKTREE_DIR" fetch --all --tags
    else
        run git clone --depth 1 "$REPO_URL" "$WORKTREE_DIR"
    fi
}

build_targets() {
    export PATH="$HOME/.cargo/bin:$HOME/.foundry/bin:$PATH"
    cd "$WORKTREE_DIR/citrate_v0.01.1"

    local targets=(-p citrate-node -p citrate-cli -p citrate-faucet)
    if [[ "$WITH_GUI" -eq 1 ]]; then
        targets+=(-p citrate-gui-native)
    fi

    run cargo build --release "${targets[@]}"
}

run_first_launch() {
    cd "$WORKTREE_DIR/citrate_v0.01.1"
    export PATH="$PWD/target/release:$HOME/.cargo/bin:$PATH"
    run bash scripts/installers/first_launch.sh
}

main() {
    log "Profile: $PROFILE"
    log "Worktree: $WORKTREE_DIR"

    if [[ "$SKIP_SYSTEM_PACKAGES" -eq 0 ]]; then
        install_base_packages "$(detect_pkg_manager)"
    fi

    if [[ "$PROFILE" == "developer" || "$PROFILE" == "agent" || "$PROFILE" == "full" ]]; then
        install_rust
        install_foundry
    fi

    if [[ "$PROFILE" == "agent" || "$PROFILE" == "full" ]]; then
        install_ollama_best_effort
    fi

    clone_or_update_repo

    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        build_targets
    fi

    run_first_launch

    cat <<EOF

Bootstrap complete.

Next steps:
  1. cd "$WORKTREE_DIR/citrate_v0.01.1"
  2. Start a local devnet:
       ./target/release/citrate --config "$HOME/.citrate/configs/devnet.toml"
  3. Or inspect the public testnet profile:
       cat "$HOME/.citrate/configs/testnet-beta.toml"
  4. Run the full test master script:
       ./scripts/run_all_tests.sh

Docs:
  - docs/guides/open-source-bootstrap.md
  - docs/guides/installation.md
EOF
}

main "$@"
