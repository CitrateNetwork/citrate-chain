#!/bin/bash
# seed_models.sh — Download GGUF models from HuggingFace, upload to IPFS, register on-chain
#
# Usage:
#   ./scripts/seed_models.sh                  # Seed all models
#   ./scripts/seed_models.sh --dry-run        # Show what would happen
#   ./scripts/seed_models.sh --start 3        # Skip first 3 models (resume)
#   ./scripts/seed_models.sh --only 0         # Process only model at index 0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/model_manifest.json"
DOWNLOAD_DIR="/tmp/citrate-seed"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
REGISTRY_ADDR="${REGISTRY_ADDR:-0x313F922BE1649cEc058EC0f076664500c78bdc0b}"
IPFS_ADDR="${IPFS_ADDR:-0x5322471a7E37Ac2B8902cFcba84d266b37D811A0}"

DRY_RUN=false
START_INDEX=0
ONLY_INDEX=-1

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --start) START_INDEX="$2"; shift 2 ;;
        --only) ONLY_INDEX="$2"; shift 2 ;;
        --rpc) RPC_URL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Results tracking
declare -a RESULTS_NAME=()
declare -a RESULTS_SIZE=()
declare -a RESULTS_CID=()
declare -a RESULTS_STATUS=()

# Helper: read manifest field
mf() {
    python3 -c "import json; m=json.load(open('$MANIFEST'))[$1]; v=m['$2']; print(','.join(['\"'+x+'\"' for x in v]) if isinstance(v, list) else v)"
}

echo "=========================================="
echo "  Citrate Model Registry Seeder"
echo "=========================================="
echo "RPC:       $RPC_URL"
echo "Registry:  $REGISTRY_ADDR"
echo "IPFS:      $IPFS_ADDR"
echo "Manifest:  $MANIFEST"
echo "Dry run:   $DRY_RUN"
echo ""

# ── Pre-flight checks ──────────────────────────
echo "[PRE-FLIGHT] Checking infrastructure..."

# IPFS daemon
if ! ipfs id > /dev/null 2>&1; then
    echo "  ERROR: IPFS daemon not running. Start with: ipfs daemon"
    exit 1
fi
echo "  IPFS daemon:  OK"

# RPC
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || echo "FAIL")
if [ "$CHAIN_ID" = "FAIL" ]; then
    echo "  ERROR: RPC not reachable at $RPC_URL"
    exit 1
fi
echo "  RPC (chain $CHAIN_ID): OK"

# Deployer balance
BALANCE_WEI=$(cast balance 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url "$RPC_URL" 2>/dev/null)
BALANCE_ETH=$(cast from-wei "$BALANCE_WEI" 2>/dev/null || echo "?")
echo "  Deployer balance: $BALANCE_ETH SALT"

# Model count
MODEL_COUNT=$(python3 -c "import json; print(len(json.load(open('$MANIFEST'))))")
echo "  Models in manifest: $MODEL_COUNT"

# Disk space
AVAIL_GB=$(df -g /tmp 2>/dev/null | tail -1 | awk '{print $4}' || echo "?")
echo "  Disk available (/tmp): ${AVAIL_GB} GB"

# Existing on-chain models
EXISTING=$(cast call --rpc-url "$RPC_URL" "$REGISTRY_ADDR" "totalModels()(uint256)" 2>/dev/null || echo "?")
echo "  Models already on-chain: $EXISTING"

echo ""
mkdir -p "$DOWNLOAD_DIR"

# ── Process each model ──────────────────────────
for i in $(seq 0 $((MODEL_COUNT - 1))); do
    # Skip/filter logic
    if [ "$ONLY_INDEX" -ge 0 ] && [ "$i" -ne "$ONLY_INDEX" ]; then
        continue
    fi
    if [ "$i" -lt "$START_INDEX" ]; then
        continue
    fi

    NAME=$(mf "$i" "name")
    URL=$(mf "$i" "url")
    FILENAME=$(mf "$i" "filename")
    VERSION=$(mf "$i" "version")
    DESC=$(mf "$i" "description")
    INPUT_SHAPE=$(mf "$i" "inputShape")
    OUTPUT_SHAPE=$(mf "$i" "outputShape")
    PARAMS=$(mf "$i" "parameters")
    LICENSE=$(mf "$i" "license")
    TAGS=$(mf "$i" "tags")
    MODEL_TYPE=$(mf "$i" "modelType")
    INF_PRICE=$(mf "$i" "inferencePrice")

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  [$((i+1))/$MODEL_COUNT] $NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  URL:     $URL"
    echo "  Tags:    $TAGS"
    echo "  License: $LICENSE"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would download, upload to IPFS, register on-chain"
        echo ""
        RESULTS_NAME+=("$NAME")
        RESULTS_SIZE+=("(dry run)")
        RESULTS_CID+=("(dry run)")
        RESULTS_STATUS+=("SKIPPED")
        continue
    fi

    FILEPATH="$DOWNLOAD_DIR/$FILENAME"

    # ── Step 1: Download ──
    echo ""
    echo "  [1/6] Downloading from HuggingFace..."
    if [ -f "$FILEPATH" ]; then
        echo "    File already exists, skipping download"
    else
        if ! curl -L --progress-bar --fail -o "$FILEPATH" "$URL"; then
            echo "    ERROR: Download failed"
            RESULTS_NAME+=("$NAME")
            RESULTS_SIZE+=("—")
            RESULTS_CID+=("—")
            RESULTS_STATUS+=("DOWNLOAD FAILED")
            continue
        fi
    fi

    # ── Step 2: Measure ──
    SIZE_BYTES=$(stat -f%z "$FILEPATH" 2>/dev/null || stat -c%s "$FILEPATH" 2>/dev/null)
    SIZE_MB=$((SIZE_BYTES / 1048576))
    echo "  [2/6] Size: ${SIZE_MB} MB (${SIZE_BYTES} bytes)"

    # ── Step 3: Upload to IPFS ──
    echo "  [3/6] Adding to IPFS (this may take a few minutes for large models)..."
    CID=$(ipfs add --pin --quieter "$FILEPATH" 2>&1)
    if [ $? -ne 0 ] || [ -z "$CID" ]; then
        echo "    ERROR: IPFS add failed"
        rm -f "$FILEPATH"
        RESULTS_NAME+=("$NAME")
        RESULTS_SIZE+=("${SIZE_MB} MB")
        RESULTS_CID+=("—")
        RESULTS_STATUS+=("IPFS FAILED")
        continue
    fi
    echo "    CID: $CID"

    # ── Step 4: Register on ModelRegistry ──
    echo "  [4/6] Registering on-chain..."
    METADATA_TUPLE="(\"${DESC}\",[${INPUT_SHAPE}],[${OUTPUT_SHAPE}],${PARAMS},\"${LICENSE}\",[${TAGS}])"

    REG_OUTPUT=$(cast send --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
        "$REGISTRY_ADDR" \
        "registerModel(string,string,string,string,uint256,uint256,(string,string[],string[],uint256,string,string[]))" \
        "$NAME" \
        "GGUF" \
        "$VERSION" \
        "$CID" \
        "$SIZE_BYTES" \
        "$INF_PRICE" \
        "$METADATA_TUPLE" \
        --value 0.1ether \
        2>&1)

    REG_STATUS=$(echo "$REG_OUTPUT" | grep "^status" | awk '{print $2}')
    REG_TX=$(echo "$REG_OUTPUT" | grep "transactionHash" | awk '{print $2}')

    if [ "$REG_STATUS" != "1" ]; then
        echo "    ERROR: Registration tx reverted"
        echo "    $REG_OUTPUT" | head -5
        rm -f "$FILEPATH"
        RESULTS_NAME+=("$NAME")
        RESULTS_SIZE+=("${SIZE_MB} MB")
        RESULTS_CID+=("$CID")
        RESULTS_STATUS+=("REG FAILED")
        continue
    fi
    echo "    TX: $REG_TX (status: $REG_STATUS)"

    # ── Step 5: Report pinning on IPFSIncentives ──
    echo "  [5/6] Reporting pinning to IPFSIncentives..."
    PIN_OUTPUT=$(cast send --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
        "$IPFS_ADDR" \
        "reportPinning(string,uint256,uint8)" \
        "$CID" \
        "$SIZE_BYTES" \
        "$MODEL_TYPE" \
        2>&1)

    PIN_STATUS=$(echo "$PIN_OUTPUT" | grep "^status" | awk '{print $2}')
    if [ "$PIN_STATUS" = "1" ]; then
        echo "    Pinning reported (status: $PIN_STATUS)"
    else
        echo "    WARNING: reportPinning may have failed (status: $PIN_STATUS)"
    fi

    # ── Step 6: Cleanup ──
    echo "  [6/6] Cleaning up local file..."
    rm -f "$FILEPATH"
    echo "    Deleted: $FILEPATH"

    RESULTS_NAME+=("$NAME")
    RESULTS_SIZE+=("${SIZE_MB} MB")
    RESULTS_CID+=("$CID")
    RESULTS_STATUS+=("SUCCESS")

    echo ""
done

# ── Summary ──────────────────────────────────────
echo ""
echo "=========================================="
echo "  Results Summary"
echo "=========================================="
printf "%-35s %-10s %-50s %-15s\n" "MODEL" "SIZE" "IPFS CID" "STATUS"
printf "%-35s %-10s %-50s %-15s\n" "-----" "----" "--------" "------"
for j in "${!RESULTS_NAME[@]}"; do
    printf "%-35s %-10s %-50s %-15s\n" "${RESULTS_NAME[$j]}" "${RESULTS_SIZE[$j]}" "${RESULTS_CID[$j]}" "${RESULTS_STATUS[$j]}"
done

# ── Verification ─────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "=========================================="
    echo "  Post-Run Verification"
    echo "=========================================="
    FINAL_COUNT=$(cast call --rpc-url "$RPC_URL" "$REGISTRY_ADDR" "totalModels()(uint256)" 2>/dev/null || echo "?")
    echo "  Models on-chain: $FINAL_COUNT"

    REWARDS=$(cast call --rpc-url "$RPC_URL" "$IPFS_ADDR" \
        "pendingRewards(address)(uint256)" \
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" 2>/dev/null || echo "?")
    REWARDS_ETH=$(cast from-wei "$REWARDS" 2>/dev/null || echo "?")
    echo "  Pending IPFS rewards: $REWARDS_ETH SALT"

    PINNED=$(cast call --rpc-url "$RPC_URL" "$IPFS_ADDR" \
        "pinnedStorage(address)(uint256)" \
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" 2>/dev/null || echo "?")
    PINNED_GB=$(python3 -c "print(f'{int(\"$PINNED\") / 1e9:.3f}')" 2>/dev/null || echo "?")
    echo "  Total pinned storage: ${PINNED_GB} GB"
fi

echo ""
echo "Done."
