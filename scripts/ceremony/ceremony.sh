#!/usr/bin/env bash
# ============================================================================
# Citrate Genesis Ceremony Script
# ============================================================================
#
# One script to run the full freeze ceremony end-to-end. This is designed to
# be:
#   - idempotent (safe to re-run if a step fails)
#   - rehearsable (can run against disposable infrastructure)
#   - auditable (produces a proof bundle at every step)
#   - reviewable (every destructive action is gated by confirmation)
#
# USAGE:
#   # Rehearsal run on disposable infra:
#   CEREMONY_MODE=rehearsal ./ceremony.sh
#
#   # Real freeze (only after 2+ clean rehearsals):
#   CEREMONY_MODE=real sudo ./ceremony.sh
#
# PREREQUISITES:
#   - All hosts provisioned via provision-host.sh
#   - Foundry installed (forge, cast, anvil)
#   - Rust toolchain (for node build)
#   - jq, curl, sha256sum
#   - Git repo checked out at a signed commit
#   - Keystore keys imported per keystore_protocol.md
#
# OUTPUTS (written to ceremony-output/<timestamp>/):
#   - 00_preflight.log          — environment fingerprint
#   - 10_genesis.json           — genesis config used
#   - 20_deployment_txs.jsonl   — deployment transactions in order
#   - 30_address_table.md       — canonical address table (Markdown)
#   - 30_address_table.json     — canonical address table (machine-readable)
#   - 40_code_verification.log  — eth_getCode output for every address
#   - 50_benchmark.md           — post-deploy benchmark report
#   - 60_proof_bundle.tar.gz    — signed archive of everything above
#   - 99_signatures.txt         — ceremony operator + auditor signatures
#
# ============================================================================
set -euo pipefail

# ---- Constants ----
readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
readonly CONTRACTS_DIR="$REPO_ROOT/contracts"
readonly CHAIN_ID="${CEREMONY_CHAIN_ID:-40204}"
readonly CEREMONY_MODE="${CEREMONY_MODE:-rehearsal}"
readonly GAS_ESTIMATE_MULTIPLIER="${CEREMONY_GAS_ESTIMATE_MULTIPLIER:-200}"

# Output directory (timestamped)
readonly OUTPUT_BASE="${CEREMONY_OUTPUT_DIR:-$REPO_ROOT/ceremony-output}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly OUTPUT_DIR="$OUTPUT_BASE/$TIMESTAMP"

# ---- Colors ----
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

FORGE_WALLET_ARGS=()
CEREMONY_PASSFILE=""

# Bridge CAST_PASSWORD (how operators set the keystore password for cast,
# e.g. in .env.testnet) to ETH_PASSWORD (the file-path env var forge
# consults for --account). Without this bridge, forge falls back to an
# interactive stdin prompt and dies with ENXIO in scripted runs.
#
# We only create a temp file if neither ETH_PASSWORD nor --password is
# already in play. The temp file is chmod 600 and shredded on exit via
# the trap below. Callers that prefer to manage their own password file
# can pre-set ETH_PASSWORD and this branch is skipped.
setup_forge_password() {
    if [ -n "${ETH_PASSWORD:-}" ]; then
        return 0
    fi
    if [ -z "${CAST_PASSWORD:-}" ]; then
        return 0
    fi
    CEREMONY_PASSFILE="$(mktemp -t citrate-ceremony-pass.XXXXXXXX)"
    chmod 600 "$CEREMONY_PASSFILE"
    printf '%s' "$CAST_PASSWORD" > "$CEREMONY_PASSFILE"
    export ETH_PASSWORD="$CEREMONY_PASSFILE"
}

cleanup_forge_password() {
    if [ -n "$CEREMONY_PASSFILE" ] && [ -f "$CEREMONY_PASSFILE" ]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u "$CEREMONY_PASSFILE" 2>/dev/null || rm -f "$CEREMONY_PASSFILE"
        else
            rm -f "$CEREMONY_PASSFILE"
        fi
        CEREMONY_PASSFILE=""
    fi
}
trap cleanup_forge_password EXIT INT TERM

# ---- Logging ----
log_step() { echo -e "\n${CYAN}[$(date -u +%H:%M:%S)]${NC} ${BOLD}$1${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
log_err()  { echo -e "  ${RED}✗${NC} $1" >&2; }
log_gate() { echo -e "\n${YELLOW}[GATE]${NC} $1"; }

# ---- Safety gates ----
require_env() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        log_err "Required environment variable not set: $name"
        log_err "See keystore_protocol.md for the expected setup."
        exit 1
    fi
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        log_err "Required command not found: $cmd"
        log_err "Install it before running the ceremony."
        exit 1
    fi
}

require_confirm() {
    local prompt="$1"
    if [ "$CEREMONY_MODE" = "real" ]; then
        log_gate "$prompt"
        read -r -p "Type 'PROCEED' to continue, anything else to abort: " confirm
        if [ "$confirm" != "PROCEED" ]; then
            log_err "Aborted by operator"
            exit 1
        fi
    else
        log_warn "Rehearsal mode — auto-confirming: $prompt"
    fi
}

require_deployer_auth() {
    if [ -n "${CEREMONY_DEPLOYER_ACCOUNT:-}" ]; then
        return 0
    fi

    if [ -n "${CEREMONY_DEPLOYER_KEYSTORE:-}" ]; then
        return 0
    fi

    log_err "Set CEREMONY_DEPLOYER_ACCOUNT (preferred) or legacy CEREMONY_DEPLOYER_KEYSTORE"
    exit 1
}

build_forge_wallet_args() {
    FORGE_WALLET_ARGS=(--sender "$CEREMONY_DEPLOYER_ADDRESS")

    if [ -n "${CEREMONY_DEPLOYER_ACCOUNT:-}" ]; then
        FORGE_WALLET_ARGS+=(--account "$CEREMONY_DEPLOYER_ACCOUNT")
        return 0
    fi

    local legacy_path legacy_dir legacy_name default_dir
    legacy_path="${CEREMONY_DEPLOYER_KEYSTORE:-}"
    legacy_dir="$(dirname "$legacy_path")"
    legacy_name="$(basename "$legacy_path")"
    default_dir="$HOME/.foundry/keystores"

    if [ "$legacy_dir" != "$default_dir" ]; then
        log_err "Legacy CEREMONY_DEPLOYER_KEYSTORE must live under $default_dir"
        log_err "Set CEREMONY_DEPLOYER_ACCOUNT instead for ceremony runs."
        exit 1
    fi

    log_warn "CEREMONY_DEPLOYER_KEYSTORE is legacy. Deriving account name '$legacy_name'."
    FORGE_WALLET_ARGS+=(--account "$legacy_name")
}

# ---- Step 00: Preflight ----
step_preflight() {
    log_step "Step 00: Preflight"
    mkdir -p "$OUTPUT_DIR"
    local log="$OUTPUT_DIR/00_preflight.log"

    {
        echo "Ceremony preflight report"
        echo "========================="
        echo "Timestamp (UTC): $(date -u)"
        echo "Ceremony mode: $CEREMONY_MODE"
        echo "Chain ID: $CHAIN_ID"
        echo "Forge gas estimate multiplier: $GAS_ESTIMATE_MULTIPLIER"
        echo "Output dir: $OUTPUT_DIR"
        echo
        echo "--- Host fingerprint ---"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Kernel: $(uname -a)"
        echo
        echo "--- Tool versions ---"
        (forge --version 2>/dev/null || echo "forge: NOT FOUND") | head -1
        (cast --version 2>/dev/null || echo "cast: NOT FOUND") | head -1
        (anvil --version 2>/dev/null || echo "anvil: NOT FOUND") | head -1
        (cargo --version 2>/dev/null || echo "cargo: NOT FOUND") | head -1
        (jq --version 2>/dev/null || echo "jq: NOT FOUND") | head -1
        echo
        echo "--- Git state ---"
        git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "git: not a repo"
        git -C "$REPO_ROOT" status --short 2>/dev/null || true
        echo
        echo "--- Environment variables (names only, values redacted) ---"
        env | grep -E '^CEREMONY_|^CITRATE_|^FOUNDRY_|^RPC_' | cut -d= -f1 | sort
    } | tee "$log"

    for cmd in forge cast jq curl sha256sum git; do
        require_cmd "$cmd"
    done

    require_env CEREMONY_RPC_URL
    require_env CEREMONY_DEPLOYER_ADDRESS
    require_deployer_auth
    build_forge_wallet_args
    setup_forge_password
    if [ -n "${ETH_PASSWORD:-}" ]; then
        log_ok "Forge keystore password: ETH_PASSWORD is set (file-path)"
    else
        log_warn "Forge keystore password not set — ceremony will prompt on stdin (interactive only)"
    fi

    log_ok "Preflight complete — log at $log"
}

# ---- Step 10: Genesis config ----
step_genesis_config() {
    log_step "Step 10: Genesis config"
    local config_out="$OUTPUT_DIR/10_genesis.json"

    # In real mode, the node operator generates fresh genesis on the bootnodes
    # before running this script. This step captures the genesis config that
    # was used so it ends up in the proof bundle.

    if [ -n "${CEREMONY_GENESIS_FILE:-}" ] && [ -f "$CEREMONY_GENESIS_FILE" ]; then
        cp "$CEREMONY_GENESIS_FILE" "$config_out"
        log_ok "Captured genesis config from $CEREMONY_GENESIS_FILE"
    else
        log_warn "CEREMONY_GENESIS_FILE not set — fetching genesis from RPC"
        cast block 0 --rpc-url "$CEREMONY_RPC_URL" --json > "$config_out"
        log_ok "Captured genesis block from RPC"
    fi

    local genesis_hash
    genesis_hash=$(jq -r '.hash' "$config_out")
    echo "Genesis block hash: $genesis_hash" | tee -a "$OUTPUT_DIR/00_preflight.log"
}

# ---- Step 20: Deploy contracts ----
step_deploy_contracts() {
    log_step "Step 20: Deploy contract suite"
    local tx_log="$OUTPUT_DIR/20_deployment_txs.jsonl"
    : > "$tx_log"

    require_confirm "About to deploy the full contract suite to chain $CHAIN_ID via $CEREMONY_RPC_URL"

    cd "$CONTRACTS_DIR"

    # Use --slow to avoid nonce-tracking issues during cold deployments.
    # The forge CLI selects the signer; Solidity scripts must never do so.
    local forge_common=(
        --rpc-url "$CEREMONY_RPC_URL"
        "${FORGE_WALLET_ARGS[@]}"
        --gas-estimate-multiplier "$GAS_ESTIMATE_MULTIPLIER"
        --slow
        --broadcast
    )

    log_step "  20a: Deploy core contracts (DeployAll)"
    forge script script/DeployAll.s.sol:DeployAll "${forge_common[@]}" \
        2>&1 | tee "$OUTPUT_DIR/20a_deploy_all.log"

    log_step "  20b: Deploy AI Gateway portable contracts"
    forge script script/DeployAIGateway.s.sol:DeployAIGateway "${forge_common[@]}" \
        2>&1 | tee "$OUTPUT_DIR/20b_deploy_gateway.log"

    log_step "  20c: Deploy education stack"
    forge script script/DeployEduStack.s.sol:DeployEduStack "${forge_common[@]}" \
        2>&1 | tee "$OUTPUT_DIR/20c_deploy_edu.log"

    if [ "${CEREMONY_INCLUDE_MODEL_ACCESS_CONTROL:-1}" = "1" ]; then
        log_step "  20d: Deploy ModelAccessControl"
        forge script script/DeployModelAccessControl.s.sol:DeployModelAccessControl "${forge_common[@]}" \
            2>&1 | tee "$OUTPUT_DIR/20d_deploy_model_access_control.log"
    else
        log_warn "Skipping ModelAccessControl because CEREMONY_INCLUDE_MODEL_ACCESS_CONTROL=0"
    fi

    # Extract deployment transactions from broadcast output
    if [ -d "$CONTRACTS_DIR/broadcast" ]; then
        find "$CONTRACTS_DIR/broadcast" -name "run-latest.json" -newer "$OUTPUT_DIR/00_preflight.log" \
            -exec jq -c '.transactions[]' {} \; > "$tx_log" 2>/dev/null || true
    fi

    log_ok "Contract deployment complete — transactions in $tx_log"
}

# ---- Step 30: Build address table ----
step_address_table() {
    log_step "Step 30: Build canonical address table"
    local md_out="$OUTPUT_DIR/30_address_table.md"
    local json_out="$OUTPUT_DIR/30_address_table.json"
    local entries_jsonl="$OUTPUT_DIR/30_contract_entries.jsonl"
    : > "$entries_jsonl"

    # Parse all run-latest.json files from broadcast directory and extract contractName → address
    local broadcast_dir="$CONTRACTS_DIR/broadcast"
    if [ ! -d "$broadcast_dir" ]; then
        log_err "Broadcast directory not found — did deployment succeed?"
        return 1
    fi

    while IFS= read -r run_file; do
        local script_name
        script_name="$(basename "$(dirname "$(dirname "$run_file")")")"

        jq -c --arg script "$script_name" '
            . as $run
            | .transactions
            | to_entries[]
            | select(.value.transactionType == "CREATE")
            | {
                name: .value.contractName,
                address: .value.contractAddress,
                deployment_tx_hash: .value.hash,
                source_script: $script,
                constructor_args: (.value.arguments // []),
                deployer: .value.transaction.from,
                chain_id_hex: (.value.transaction.chainId // null),
                receipt_status_hex: ($run.receipts[.key].status // null),
                gas_used_hex: ($run.receipts[.key].gasUsed // null)
            }' "$run_file" >> "$entries_jsonl"
    done < <(find "$broadcast_dir" -name "run-latest.json" -newer "$OUTPUT_DIR/00_preflight.log" | sort)

    jq -s --arg deployer "$CEREMONY_DEPLOYER_ADDRESS" --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson chainId "$CHAIN_ID" '
        {
            chainId: $chainId,
            deployedAt: $deployedAt,
            deployer: $deployer,
            contractCount: length,
            contracts: (sort_by(.name))
        }' "$entries_jsonl" > "$json_out"

    # Markdown version
    {
        echo "# Ceremony Address Table"
        echo
        echo "- Chain ID: $CHAIN_ID"
        echo "- Deployed: $(date -u)"
        echo "- Deployer: \`$CEREMONY_DEPLOYER_ADDRESS\`"
        echo "- Ceremony mode: $CEREMONY_MODE"
        echo "- Contract count: \`$(jq -r '.contractCount' "$json_out")\`"
        echo
        echo "## Contracts"
        echo
        echo "| Contract | Address | Deploy Tx | Script |"
        echo "|----------|---------|-----------|--------|"
        jq -r '.contracts[] | "| \(.name) | `\(.address)` | `\(.deployment_tx_hash)` | `\(.source_script)` |"' "$json_out"
    } > "$md_out"

    log_ok "Address table written to $md_out"
    log_ok "Machine-readable table at $json_out"

    local count
    count=$(jq -r '.contractCount' "$json_out")
    log_ok "Total contracts deployed: $count"
}

# ---- Step 40: Verify contract bytecode ----
step_verify_code() {
    log_step "Step 40: Verify every contract has non-zero bytecode"
    local json_out="$OUTPUT_DIR/30_address_table.json"
    local verify_log="$OUTPUT_DIR/40_code_verification.log"
    : > "$verify_log"

    if [ ! -f "$json_out" ]; then
        log_err "Address table not found — cannot verify"
        return 1
    fi

    local failed=0
    local total=0

    while IFS= read -r line; do
        local name address code
        name="$(echo "$line" | jq -r '.name')"
        address="$(echo "$line" | jq -r '.address')"
        code=$(cast code "$address" --rpc-url "$CEREMONY_RPC_URL" 2>/dev/null || echo "ERROR")
        total=$((total + 1))

        if [ "$code" = "0x" ] || [ "$code" = "ERROR" ] || [ -z "$code" ]; then
            log_err "  $name at $address: NO BYTECODE"
            echo "FAIL $name $address 0x" >> "$verify_log"
            failed=$((failed + 1))
        else
            local code_size=$(( (${#code} - 2) / 2 ))
            log_ok "  $name at $address: $code_size bytes"
            echo "OK $name $address $code_size" >> "$verify_log"
        fi
    done < <(jq -c '.contracts[]' "$json_out")

    echo >> "$verify_log"
    echo "TOTAL: $total contracts, $failed failures" >> "$verify_log"

    if [ "$failed" -gt 0 ]; then
        log_err "$failed of $total contracts have no bytecode — ceremony FAILED"
        return 1
    fi

    log_ok "All $total contracts verified with non-zero bytecode"
}

# ---- Step 50: Benchmark ----
# Benchmark evidence is a Phase 3 gate per CEREMONY_CHECKLIST.md section 3.3.
# In REAL mode, a missing or failing benchmark is a ceremony abort condition,
# not a silent skip. In REHEARSAL mode, a missing benchmark is a hard warning
# (not an abort) so operators can iterate quickly on ceremony logistics before
# the full benchmark suite is built.
step_benchmark() {
    log_step "Step 50: Post-deploy benchmark"
    local bench_out="$OUTPUT_DIR/50_benchmark.md"
    local bench_bin="$REPO_ROOT/tests/load/target/release/benchmark-suite"

    if [ ! -f "$bench_bin" ]; then
        local msg="Benchmark suite binary not found at $bench_bin"
        if [ "$CEREMONY_MODE" = "real" ]; then
            log_err "$msg"
            log_err "Real ceremony REQUIRES benchmark evidence. Build the suite first:"
            log_err "  cd $REPO_ROOT/tests/load && cargo build --release"
            log_err "Aborting ceremony — benchmark gate cannot be bypassed in real mode."
            echo "# Benchmark MISSING — ceremony aborted" > "$bench_out"
            echo "Binary not found: $bench_bin" >> "$bench_out"
            return 1
        else
            log_warn "$msg (rehearsal mode — continuing, but you MUST build this before real run)"
            echo "# Benchmark SKIPPED (rehearsal only)" > "$bench_out"
            echo "The benchmark suite binary was not found. Build it with:" >> "$bench_out"
            echo "  cd $REPO_ROOT/tests/load && cargo build --release" >> "$bench_out"
            echo "" >> "$bench_out"
            echo "**This skip is ONLY acceptable in rehearsal mode.**" >> "$bench_out"
            return 0
        fi
    fi

    log_ok "Running benchmark suite against $CEREMONY_RPC_URL"
    if ! "$bench_bin" "$CEREMONY_RPC_URL" 1000 30 "$OUTPUT_DIR"; then
        local msg="Benchmark suite exited with non-zero status"
        if [ "$CEREMONY_MODE" = "real" ]; then
            log_err "$msg"
            log_err "Aborting ceremony — benchmark failure is a hard gate in real mode."
            return 1
        else
            log_warn "$msg (rehearsal mode — continuing, but investigate before real run)"
            return 0
        fi
    fi

    # Verify the benchmark actually wrote a report file
    # (the benchmark-suite binary writes benchmark_<timestamp>.md into OUTPUT_DIR)
    local report_count
    report_count=$(find "$OUTPUT_DIR" -maxdepth 1 -name "benchmark_*.md" 2>/dev/null | wc -l)
    if [ "$report_count" -eq 0 ]; then
        local msg="Benchmark suite ran but produced no report file"
        if [ "$CEREMONY_MODE" = "real" ]; then
            log_err "$msg"
            log_err "Aborting ceremony — benchmark evidence is required."
            return 1
        else
            log_warn "$msg (rehearsal mode — continuing)"
        fi
    else
        log_ok "Benchmark produced $report_count report file(s)"
    fi
}

# ---- Step 60: Proof bundle ----
step_proof_bundle() {
    log_step "Step 60: Create signed proof bundle"
    local bundle="$OUTPUT_DIR/60_proof_bundle.tar.gz"
    local manifest="$OUTPUT_DIR/60_manifest.json"

    # Manifest: hash every output file
    {
        echo "{"
        echo "  \"ceremonyMode\": \"$CEREMONY_MODE\","
        echo "  \"chainId\": $CHAIN_ID,"
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"gitCommit\": \"$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)\","
        echo "  \"operator\": \"$CEREMONY_DEPLOYER_ADDRESS\","
        echo "  \"files\": {"
        find "$OUTPUT_DIR" -maxdepth 1 -type f ! -name "60_*" ! -name "99_*" -printf '%f\n' \
            | sort \
            | while read -r f; do
                if [ -f "$OUTPUT_DIR/$f" ]; then
                    local hash
                    hash=$(sha256sum "$OUTPUT_DIR/$f" | cut -d' ' -f1)
                    echo "    \"$f\": \"sha256:$hash\","
                fi
            done \
            | sed '$ s/,$//'
        echo "  }"
        echo "}"
    } > "$manifest"

    # Create archive
    (cd "$OUTPUT_DIR" && tar -czf "$(basename "$bundle")" -- *.log *.json *.md *.jsonl 2>/dev/null || true)

    local bundle_hash
    bundle_hash=$(sha256sum "$bundle" | cut -d' ' -f1)

    log_ok "Proof bundle: $bundle"
    log_ok "Bundle SHA256: $bundle_hash"
    echo "$bundle_hash  $(basename "$bundle")" > "$OUTPUT_DIR/60_bundle.sha256"
}

# ---- Step 99: Signatures ----
step_signatures() {
    log_step "Step 99: Capture signatures"
    local sigs="$OUTPUT_DIR/99_signatures.txt"

    cat > "$sigs" <<EOF
Citrate Ceremony Signatures
===========================
Ceremony: $TIMESTAMP
Mode: $CEREMONY_MODE
Chain ID: $CHAIN_ID
Bundle hash: $(cat "$OUTPUT_DIR/60_bundle.sha256" 2>/dev/null || echo "NOT COMPUTED")

Operator signature: __________________________________________
  Name:
  Date:
  Address: $CEREMONY_DEPLOYER_ADDRESS

Auditor signature:  __________________________________________
  Name:
  Date:

Stakeholder signature: _______________________________________
  Name:
  Date:

---
This file is filled in manually post-ceremony and committed to the repo
alongside the proof bundle. In rehearsal mode, signatures are blank — they
are only captured for the real freeze run.
EOF

    log_ok "Signature template: $sigs"
}

# ---- Main ----
main() {
    echo -e "${BOLD}=================================================${NC}"
    echo -e "${BOLD}       Citrate Genesis Ceremony${NC}"
    echo -e "${BOLD}       Mode: $CEREMONY_MODE${NC}"
    echo -e "${BOLD}       Chain: $CHAIN_ID${NC}"
    echo -e "${BOLD}=================================================${NC}"

    if [ "$CEREMONY_MODE" != "real" ] && [ "$CEREMONY_MODE" != "rehearsal" ]; then
        log_err "CEREMONY_MODE must be 'rehearsal' or 'real' (got: $CEREMONY_MODE)"
        exit 1
    fi

    if [ "$CEREMONY_MODE" = "real" ]; then
        require_confirm "This is a REAL ceremony. Have you run 2+ clean rehearsals?"
        require_confirm "Have all 3 parties (operator, auditor, stakeholder) approved the pre-signoff document?"
    fi

    step_preflight
    step_genesis_config
    step_deploy_contracts
    step_address_table
    step_verify_code
    step_benchmark
    step_proof_bundle
    step_signatures

    echo
    echo -e "${GREEN}${BOLD}=================================================${NC}"
    echo -e "${GREEN}${BOLD}       Ceremony complete${NC}"
    echo -e "${GREEN}${BOLD}       Output: $OUTPUT_DIR${NC}"
    echo -e "${GREEN}${BOLD}=================================================${NC}"
    echo
    echo "Next steps:"
    echo "  1. Review 30_address_table.md"
    echo "  2. Review 40_code_verification.log"
    echo "  3. Review 50_benchmark.md for regressions"
    echo "  4. Update canonical constant files (CONFIG.md, etc.)"
    echo "  5. Commit proof bundle to repo at .agentile/ceremonies/$TIMESTAMP/"
    echo "  6. Fill in 99_signatures.txt (real mode only)"
}

main "$@"
