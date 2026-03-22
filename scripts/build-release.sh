#!/bin/bash
# Citrate Release Build Script
# Builds release binaries for multiple platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$PROJECT_ROOT/releases"
VERSION="${VERSION:-$(date +%Y%m%d-%H%M%S)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Platform configurations
declare -A TARGETS=(
    ["linux-x86_64"]="x86_64-unknown-linux-gnu"
    ["linux-aarch64"]="aarch64-unknown-linux-gnu"
    ["windows-x86_64"]="x86_64-pc-windows-gnu"
    ["macos-x86_64"]="x86_64-apple-darwin"
    ["macos-aarch64"]="aarch64-apple-darwin"
)

declare -A LINKERS=(
    ["x86_64-unknown-linux-gnu"]="x86_64-linux-gnu-gcc"
    ["aarch64-unknown-linux-gnu"]="aarch64-linux-gnu-gcc"
    ["x86_64-pc-windows-gnu"]="x86_64-w64-mingw32-gcc"
    ["x86_64-apple-darwin"]="x86_64-apple-darwin-clang"
    ["aarch64-apple-darwin"]="aarch64-apple-darwin-clang"
)

declare -A EXTENSIONS=(
    ["windows-x86_64"]=".exe"
)

# Parse arguments
BUILD_PLATFORMS=()
UPLOAD=false
UPLOAD_TARGET=""

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Platform Options:"
    echo "  --linux-x86_64       Build for Linux x86_64 (servers, DGX)"
    echo "  --linux-aarch64      Build for Linux ARM64 (Raspberry Pi, ARM servers)"
    echo "  --windows            Build for Windows x86_64"
    echo "  --macos-x86_64       Build for macOS Intel (requires macOS or osxcross)"
    echo "  --macos-aarch64      Build for macOS Apple Silicon (requires macOS or osxcross)"
    echo "  --linux              Build all Linux variants"
    echo "  --macos              Build all macOS variants"
    echo "  --all                Build for all supported platforms"
    echo ""
    echo "Other Options:"
    echo "  --upload <target>    Upload to target (github, scp:user@host:/path)"
    echo "  --version <ver>      Set version string (default: timestamp)"
    echo "  --skip-unavailable   Skip platforms without required toolchains"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --all --version v0.1.0-beta --upload github"
    echo "  $0 --linux --windows --version v0.1.0"
    echo "  $0 --linux-x86_64 --upload scp:user@server:/opt/citrate"
}

SKIP_UNAVAILABLE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --linux-x86_64)
            BUILD_PLATFORMS+=("linux-x86_64")
            shift
            ;;
        --linux-aarch64)
            BUILD_PLATFORMS+=("linux-aarch64")
            shift
            ;;
        --windows)
            BUILD_PLATFORMS+=("windows-x86_64")
            shift
            ;;
        --macos-x86_64)
            BUILD_PLATFORMS+=("macos-x86_64")
            shift
            ;;
        --macos-aarch64)
            BUILD_PLATFORMS+=("macos-aarch64")
            shift
            ;;
        --linux)
            BUILD_PLATFORMS+=("linux-x86_64" "linux-aarch64")
            shift
            ;;
        --macos)
            BUILD_PLATFORMS+=("macos-x86_64" "macos-aarch64")
            shift
            ;;
        --all)
            BUILD_PLATFORMS+=("linux-x86_64" "linux-aarch64" "windows-x86_64" "macos-x86_64" "macos-aarch64")
            shift
            ;;
        --upload)
            UPLOAD=true
            UPLOAD_TARGET="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --skip-unavailable)
            SKIP_UNAVAILABLE=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Default to Linux platforms if nothing specified
if [ ${#BUILD_PLATFORMS[@]} -eq 0 ]; then
    BUILD_PLATFORMS=("linux-x86_64" "linux-aarch64")
fi

# Remove duplicates
BUILD_PLATFORMS=($(echo "${BUILD_PLATFORMS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

cd "$PROJECT_ROOT"

# Create release directory
mkdir -p "$RELEASE_DIR/$VERSION"

log_info "Building Citrate release $VERSION"
log_info "Release directory: $RELEASE_DIR/$VERSION"
log_info "Platforms: ${BUILD_PLATFORMS[*]}"
echo ""

# Check toolchain availability
check_toolchain() {
    local platform=$1
    local target=${TARGETS[$platform]}
    local linker=${LINKERS[$target]}

    # Check if target is installed
    if ! rustup target list --installed | grep -q "$target"; then
        log_warn "Rust target $target not installed. Installing..."
        rustup target add "$target" 2>/dev/null || {
            log_error "Failed to install target $target"
            return 1
        }
    fi

    # Check if linker exists (skip for native builds)
    if [[ "$linker" != *"apple-darwin"* ]]; then
        if ! command -v "$linker" &> /dev/null; then
            log_warn "Linker $linker not found for $platform"
            return 1
        fi
    else
        # macOS cross-compilation requires osxcross or macOS host
        if [[ "$(uname)" != "Darwin" ]]; then
            if ! command -v "$linker" &> /dev/null; then
                log_warn "macOS cross-compilation requires osxcross or macOS host"
                return 1
            fi
        fi
    fi

    return 0
}

# Build function
build_target() {
    local platform=$1
    local target=${TARGETS[$platform]}
    local ext=${EXTENSIONS[$platform]:-""}

    log_info "Building for $platform ($target)..."

    # Set up environment for cross-compilation
    local linker=${LINKERS[$target]}
    export CARGO_TARGET_${target^^}_LINKER="$linker" 2>/dev/null || true

    # For Windows, ensure we use static linking for CRT
    if [[ "$platform" == "windows"* ]]; then
        export RUSTFLAGS="-C target-feature=+crt-static"
    fi

    if cargo build --release --target "$target" -p citrate-node 2>&1; then
        local binary="target/$target/release/citrate$ext"
        local output="$RELEASE_DIR/$VERSION/citrate-$platform$ext"

        if [ -f "$binary" ]; then
            cp "$binary" "$output"
            chmod +x "$output"

            # Create checksum
            sha256sum "$output" | sed "s|$RELEASE_DIR/$VERSION/||" > "$output.sha256"

            local size=$(du -h "$output" | cut -f1)
            log_success "Built $platform ($size)"
            return 0
        else
            log_error "Binary not found: $binary"
            return 1
        fi
    else
        log_error "Build failed for $platform"
        return 1
    fi
}

# Build each platform
SUCCESSFUL_BUILDS=()
FAILED_BUILDS=()

for platform in "${BUILD_PLATFORMS[@]}"; do
    echo ""
    if check_toolchain "$platform"; then
        if build_target "$platform"; then
            SUCCESSFUL_BUILDS+=("$platform")
        else
            FAILED_BUILDS+=("$platform")
        fi
    else
        if $SKIP_UNAVAILABLE; then
            log_warn "Skipping $platform (toolchain unavailable)"
        else
            FAILED_BUILDS+=("$platform")
        fi
    fi
done

echo ""

# Create release info
cat > "$RELEASE_DIR/$VERSION/RELEASE.md" << EOF
# Citrate Release $VERSION

**Built:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Git Commit:** \`$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")\`
**Full Commit:** \`$(git rev-parse HEAD 2>/dev/null || echo "unknown")\`

## Downloads

| Platform | Architecture | File | Size |
|----------|--------------|------|------|
EOF

for binary in "$RELEASE_DIR/$VERSION"/citrate-*; do
    if [[ -f "$binary" && ! "$binary" =~ \.sha256$ ]]; then
        name=$(basename "$binary")
        size=$(du -h "$binary" | cut -f1)

        # Parse platform info
        platform_info="${name#citrate-}"
        platform_info="${platform_info%.exe}"

        case "$platform_info" in
            linux-x86_64) os="Linux"; arch="x86_64 (64-bit)" ;;
            linux-aarch64) os="Linux"; arch="ARM64" ;;
            windows-x86_64) os="Windows"; arch="x86_64 (64-bit)" ;;
            macos-x86_64) os="macOS"; arch="Intel" ;;
            macos-aarch64) os="macOS"; arch="Apple Silicon (M1/M2/M3/M4)" ;;
            *) os="Unknown"; arch="Unknown" ;;
        esac

        echo "| $os | $arch | \`$name\` | $size |" >> "$RELEASE_DIR/$VERSION/RELEASE.md"
    fi
done

cat >> "$RELEASE_DIR/$VERSION/RELEASE.md" << 'EOF'

## Checksums (SHA256)

```
EOF

for checksum in "$RELEASE_DIR/$VERSION"/*.sha256; do
    if [ -f "$checksum" ]; then
        cat "$checksum" >> "$RELEASE_DIR/$VERSION/RELEASE.md"
    fi
done

cat >> "$RELEASE_DIR/$VERSION/RELEASE.md" << 'EOF'
```

## Installation

### Linux / macOS

```bash
# Download the appropriate binary for your platform
# Make it executable
chmod +x citrate-linux-x86_64  # or your platform

# Optionally move to PATH
sudo mv citrate-linux-x86_64 /usr/local/bin/citrate

# Verify installation
citrate --version
```

### Windows

1. Download `citrate-windows-x86_64.exe`
2. Rename to `citrate.exe` (optional)
3. Add to your PATH or run directly

```powershell
.\citrate-windows-x86_64.exe --version
```

## Quick Start

```bash
# Start a local development network
citrate devnet

# Start with custom data directory
citrate --data-dir /path/to/data devnet

# Start with configuration file
citrate --config config.toml

# Show all options
citrate --help
```

## System Requirements

| Platform | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8+ GB |
| Disk | 50 GB SSD | 200+ GB NVMe |
| CPU | 2 cores | 4+ cores |
| Network | 10 Mbps | 100+ Mbps |

### Supported Operating Systems

- **Linux:** Ubuntu 20.04+, Debian 11+, Fedora 35+, CentOS 8+
- **macOS:** macOS 11 (Big Sur) or later
- **Windows:** Windows 10/11 (64-bit)

## Configuration

Create a `config.toml` file:

```toml
[node]
data_dir = "/var/lib/citrate"
network = "mainnet"  # or "testnet", "devnet"

[rpc]
enabled = true
listen_addr = "0.0.0.0:8545"

[p2p]
listen_addr = "/ip4/0.0.0.0/tcp/4001"
bootstrap_peers = []

[storage]
encryption_enabled = true
```

## Support

- **Documentation:** https://docs.citrate.ai
- **GitHub Issues:** https://github.com/SaulBuilds/citrate/issues
- **Discord:** https://discord.gg/A3Uwe4BvdN
EOF

# Summary
echo ""
log_info "Build Summary"
echo "============================================"

if [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
    log_success "Successful builds (${#SUCCESSFUL_BUILDS[@]}):"
    for p in "${SUCCESSFUL_BUILDS[@]}"; do
        echo "  ✓ $p"
    done
fi

if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
    echo ""
    log_error "Failed builds (${#FAILED_BUILDS[@]}):"
    for p in "${FAILED_BUILDS[@]}"; do
        echo "  ✗ $p"
    done
fi

echo ""
log_info "Release files:"
ls -lh "$RELEASE_DIR/$VERSION/"

# Upload if requested
if $UPLOAD && [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
    echo ""
    log_info "Uploading to $UPLOAD_TARGET..."

    if [[ "$UPLOAD_TARGET" == "github" ]]; then
        log_info "Creating GitHub release..."
        if command -v gh &> /dev/null; then
            # Check if authenticated
            if ! gh auth status &>/dev/null; then
                log_error "GitHub CLI not authenticated. Run: gh auth login"
                exit 1
            fi

            cd "$RELEASE_DIR/$VERSION"

            # Get list of binaries to upload
            UPLOAD_FILES=()
            for f in citrate-*; do
                if [[ -f "$f" ]]; then
                    UPLOAD_FILES+=("$f")
                fi
            done

            log_info "Uploading ${#UPLOAD_FILES[@]} files..."

            # Create release
            gh release create "$VERSION" \
                --repo "SaulBuilds/citrate" \
                --title "Citrate $VERSION" \
                --notes-file RELEASE.md \
                "${UPLOAD_FILES[@]}" \
                && log_success "GitHub release created: https://github.com/SaulBuilds/citrate/releases/tag/$VERSION" \
                || log_error "GitHub release failed"
        else
            log_error "GitHub CLI (gh) not installed. Install with: sudo apt install gh"
            exit 1
        fi

    elif [[ "$UPLOAD_TARGET" == scp:* ]]; then
        SCP_DEST="${UPLOAD_TARGET#scp:}"
        log_info "Uploading via SCP to $SCP_DEST..."
        scp -r "$RELEASE_DIR/$VERSION"/* "$SCP_DEST/" \
            && log_success "Upload complete" \
            || log_error "SCP upload failed"
    else
        log_error "Unknown upload target: $UPLOAD_TARGET"
        log_info "Supported: github, scp:user@host:/path"
    fi
fi

echo ""
if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
    log_warn "Some builds failed. Check logs above for details."
    exit 1
else
    log_success "Release build complete!"
fi
