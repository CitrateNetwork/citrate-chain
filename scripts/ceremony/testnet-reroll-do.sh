#!/usr/bin/env bash
# ============================================================================
# testnet-reroll-do.sh — one-shot reroll + re-launch on the DO bootnode
# ============================================================================
#
# Purpose:
#   Pull latest main, rebuild, stop the systemd node, reroll the data dir +
#   forge state, bring the node back up, run the real ceremony, verify the
#   endpoint is live. All in one script so it's auditable.
#
# Requires on the DO host:
#   - Repo checkout at $REPO_ON_DO (pass via env or first arg)
#   - `.env.testnet` at the repo root with:
#       CAST_PASSWORD=...
#       CEREMONY_DEPLOYER_ACCOUNT=citrate-devops
#       CEREMONY_DEPLOYER_ADDRESS=0x...
#       SIGNER_1, SIGNER_2, SIGNER_3, RELAYER, GOVERNANCE
#   - Foundry installed (forge, cast)
#   - Rust toolchain
#   - sudo access for systemctl
#
# Usage:
#   # On DO, from anywhere:
#   REPO_ON_DO=/var/lib/citrate/citrate ./testnet-reroll-do.sh
#
#   # Or pass as arg:
#   ./testnet-reroll-do.sh /var/lib/citrate/citrate
#
# Safety:
#   - Confirms two-key gate before destructive reroll
#   - Archives (mv, not rm) the old data dir
#   - Aborts on any error (set -euo pipefail)
#
# ============================================================================
set -euo pipefail

# ---- Config ----
REPO_ON_DO="${REPO_ON_DO:-${1:-}}"
if [ -z "$REPO_ON_DO" ] || [ ! -d "$REPO_ON_DO" ]; then
    echo "ERROR: repo path required. Set REPO_ON_DO or pass as arg." >&2
    echo "usage: REPO_ON_DO=/path/to/citrate $0" >&2
    exit 1
fi
NODE_UNIT="${NODE_UNIT:-citrate-node.service}"
NODE_BINARY="$REPO_ON_DO/citrate_v0.01.1/target/release/citrate-node"
ENV_FILE="$REPO_ON_DO/.env.testnet"

# ---- Colors ----
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; CYAN=''; BOLD=''; NC=''
fi
say()  { echo -e "${CYAN}[$(date -u +%H:%M:%S)]${NC} ${BOLD}$1${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1" >&2; exit 1; }

# ---- Preflight ----
say "Preflight"
[ -f "$ENV_FILE" ] || fail ".env.testnet missing at $ENV_FILE"
command -v forge  >/dev/null || fail "forge not in PATH"
command -v cast   >/dev/null || fail "cast not in PATH"
command -v cargo  >/dev/null || fail "cargo not in PATH"
command -v sudo   >/dev/null || fail "sudo not in PATH"
ok "tools present"

# ---- 1. Pull latest main ----
say "Step 1 — pull latest main"
cd "$REPO_ON_DO"
git fetch origin main --quiet
git checkout main --quiet
git pull --ff-only origin main
head_sha=$(git rev-parse --short HEAD)
ok "on main at $head_sha"
# Expect ceremony password bridge (#65) + MVCC deflake (#63) + fontconfig (#61)
echo "  latest 3 commits:"
git log --oneline -3 | sed 's/^/    /'

# ---- 2. Build release binaries + benchmark-suite ----
say "Step 2 — build release binaries"
cd "$REPO_ON_DO/citrate_v0.01.1"
cargo build --release --bin citrate-node --bin citrate-cli --quiet
ok "citrate-node + citrate-cli built"
cd tests/load && cargo build --release --bin benchmark-suite --quiet && cd - >/dev/null
ok "benchmark-suite built"

# ---- 3. Load ceremony env ----
say "Step 3 — load .env.testnet"
set -a; . "$ENV_FILE"; set +a
[ -n "${CAST_PASSWORD:-}" ]              || fail "CAST_PASSWORD not in .env.testnet"
[ -n "${CEREMONY_DEPLOYER_ACCOUNT:-}" ]  || fail "CEREMONY_DEPLOYER_ACCOUNT not in .env.testnet"
[ -n "${CEREMONY_DEPLOYER_ADDRESS:-}" ]  || fail "CEREMONY_DEPLOYER_ADDRESS not in .env.testnet"
ok "env loaded (deployer=$CEREMONY_DEPLOYER_ADDRESS account=$CEREMONY_DEPLOYER_ACCOUNT)"

# ---- 4. Two-key confirmation ----
say "Step 4 — destructive reroll gate"
echo "  This will:"
echo "    - stop $NODE_UNIT"
echo "    - archive .citrate-testnet-beta/ (via mv, recoverable)"
echo "    - clear contracts/broadcast + contracts/cache"
echo "    - redeploy all 36 contracts on chain 40204"
echo "    - restart the node on a FRESH genesis"
echo
read -r -p "  Type 'REROLL' to proceed, anything else aborts: " confirm
[ "$confirm" = "REROLL" ] || fail "aborted by operator"
ok "proceeding with reroll"

# ---- 5. Stop the node ----
say "Step 5 — stop node service ($NODE_UNIT)"
if systemctl list-units --type=service --all --no-pager | grep -q "$NODE_UNIT"; then
    sudo systemctl stop "$NODE_UNIT" || warn "systemctl stop returned non-zero (may already be stopped)"
    sleep 2
    if ss -tln 2>/dev/null | grep -qE ":8545\b"; then
        warn "port 8545 still in use after stop; reroll script will try to kill"
    else
        ok "$NODE_UNIT stopped, port 8545 free"
    fi
else
    warn "unit $NODE_UNIT not found; set NODE_UNIT env var if different"
fi

# ---- 6. Reroll data dir + forge state ----
say "Step 6 — ceremony-reroll.sh"
CEREMONY_MODE=real CEREMONY_REROLL_REAL=1 \
    "$REPO_ON_DO/citrate_v0.01.1/scripts/ceremony/ceremony-reroll.sh" --reroll
ok "reroll complete"

# ---- 7. Start fresh node, wait for RPC ----
say "Step 7 — start fresh node"
sudo systemctl start "$NODE_UNIT"
ok "$NODE_UNIT started, waiting for RPC..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -fsS -X POST http://127.0.0.1:8545 \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            >/dev/null 2>&1; then
        ok "RPC responding after ${i}s"
        break
    fi
    [ "$i" = "15" ] && fail "RPC not responding after 15s"
    sleep 1
done

# ---- 8. Run the ceremony ----
say "Step 8 — run real ceremony (CEREMONY_MODE=real)"
export CEREMONY_MODE=real
export CEREMONY_RPC_URL=http://127.0.0.1:8545
# Patched ceremony.sh will bridge CAST_PASSWORD → ETH_PASSWORD automatically.
cd "$REPO_ON_DO"
./citrate_v0.01.1/scripts/ceremony/ceremony.sh

# ---- 9. Post-ceremony health ----
say "Step 9 — post-ceremony health"
chain_id_hex=$(curl -fsS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq -r .result)
block_hex=$(curl -fsS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r .result)
ok "chain_id=$chain_id_hex (expect 0x9d0c=40204), blockNumber=$block_hex"

# ---- 10. External endpoint check ----
say "Step 10 — external endpoint (via Cloudflare)"
if chain_ext=$(curl -fsS -m 10 -X POST https://rpc.citrate.ai -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null | jq -r .result 2>/dev/null); then
    ok "rpc.citrate.ai → chain_id=$chain_ext"
else
    warn "rpc.citrate.ai did not respond — check cloudflared tunnel"
fi

echo
say "DONE — testnet reroll complete"
echo "  Proof bundle: $(ls -1t $REPO_ON_DO/ceremony-output/*/60_proof_bundle.tar.gz | head -1)"
echo "  Address table: $(ls -1t $REPO_ON_DO/ceremony-output/*/30_address_table.md | head -1)"
echo
echo "Next:"
echo "  1. Review $(ls -1t $REPO_ON_DO/ceremony-output/*/30_address_table.md | head -1)"
echo "  2. From Spark: update DEPLOYED_ADDRESSES.md and citrate_edu_app/src/config.rs"
echo "  3. Commit the proof bundle under .agentile/ceremonies/<timestamp>/"
