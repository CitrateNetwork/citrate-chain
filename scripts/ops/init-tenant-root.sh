#!/usr/bin/env bash
# init-tenant-root.sh — seed the root node of TenantHierarchy on chain 40204.
#
# WHY THIS IS A CEREMONY AND NOT A DEPLOY STEP
#
# `TenantHierarchy` has been deployed since the BFR run, but `root()` is the zero
# word: `initRoot` has never been called. Everything that reads the tenant tree —
# citrate-quorum's Settings surface, and the operator half of its MR-4 clearance
# check — correctly reports an empty tree, because there is one.
#
# Seeding it fixes three things that CANNOT be changed afterwards:
#
#   * the root tenant id (`keccak256(name)`), because `initRoot` is one-shot;
#   * the ADMIN SET, because the contract has no `setAdmins`;
#   * and therefore who may ever create a business unit, site or team under it.
#
# `classification_max` is the one parameter that IS changeable later
# (`setClassificationMax`, unbounded upward for the root), which is why it is set
# conservatively below.
#
# Only the contract's `deployer` may call `initRoot` (FWA-C3-02 closed the
# front-run window where any EOA could seize the RBAC root).
#
# SAFETY: dry-run by default — it reads the chain, prints exactly what it would
# send, and stops. Nothing is broadcast without `--broadcast`.
#
# Usage:
#   scripts/ops/init-tenant-root.sh                      # dry run
#   DEPLOY_KEY=0x... scripts/ops/init-tenant-root.sh --broadcast
#
# Env:
#   RPC_URL     RPC endpoint     (default: https://rpc.citrate.ai)
#   DEPLOY_KEY  deployer key     (required only with --broadcast)
#   BOOK        address book     (default: contracts/addresses/bfr-40204.json)
set -euo pipefail

RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
BROADCAST=0
[[ "${1:-}" == "--broadcast" ]] && BROADCAST=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BOOK="${BOOK:-$ROOT_DIR/contracts/addresses/bfr-40204.json}"

# ── The governance parameters. Owner decision, 2026-07-26 (@SaulBuilds). ──────
#
# Root name — the id is keccak256 of this EXACT string and is permanent. Chain
# 40204 is our own federation chain; the F200 customer gets a dedicated,
# firewalled instance on their own infra (locked decision D-3), so this tree is
# ours: dogfooding, the demo, and our own agent governance.
ROOT_NAME="${ROOT_NAME:-Citrate}"
#
# Admins — IMMUTABLE. The same three keys that own the 2-of-3
# MultisigTimelock2of3 (0x3d4abcbe…68fc) for the cit_agent set.
#
# Read `THRESHOLD` honestly: on THIS contract `admin_threshold` is DATA, not
# enforcement. `createNode` checks `_isAdmin` only, so any ONE of these keys can
# create a node today. The 2-of-3 is recorded intent, to be enforced by the
# off-chain orchestrator that batches admin signatures through a
# `MultiSigEnvelope` (the contract's own doc comment says exactly this). Anyone
# quoting "2-of-3 tenant governance" must quote that sentence with it.
ADMINS=(
  0xF4FE9B2c6441Ff7c081B60716a78193127919783
  0x269deEe81cb8Eb5899b2D17945b951608E41774B
  0x671F3F4f9cBb0509a28eE4fa0b416daBBc9375C5
)
THRESHOLD="${THRESHOLD:-2}"
#
# classification_max — 0 Public / 1 Proprietary / 2 CUI / 3 ITAR.
# CUI, deliberately. This is our own tenant on a PUBLIC chain, and an ITAR
# ceiling would assert a posture we do not claim (CLAUDE.md forbids
# export-control compliance claims federation-wide). Every child node is bounded
# by its parent, so CUI caps the whole tree — and unlike the admin set, the root's
# ceiling can be raised later with `setClassificationMax`.
CLASSIFICATION_MAX="${CLASSIFICATION_MAX:-2}"

# ── Resolve ──────────────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 2; }; }
need cast; need jq

TH=$(jq -r '.TenantHierarchy // empty' "$BOOK")
[ -n "$TH" ] || { echo "TenantHierarchy not in $BOOK" >&2; exit 2; }

ROOT_ID=$(cast keccak "$ROOT_NAME")
# The HKDF salt is public on chain (it is a salt, not a secret) but must be
# unpredictable, so it is drawn fresh rather than being a memorable constant.
HKDF_SALT="${HKDF_SALT:-$(cast keccak "$(head -c 32 /dev/urandom | xxd -p -c 64)")}"

echo "TenantHierarchy   $TH"
echo "rpc               $RPC_URL"
echo "deployer (chain)  $(cast call "$TH" 'deployer()(address)' --rpc-url "$RPC_URL")"
CURRENT_ROOT=$(cast call "$TH" 'root()(bytes32)' --rpc-url "$RPC_URL")
echo "root() now        $CURRENT_ROOT"
echo
echo "would call initRoot("
echo "  self               $ROOT_ID   // keccak256(\"$ROOT_NAME\")"
echo "  display            \"$ROOT_NAME\""
echo "  hkdf_salt          $HKDF_SALT"
echo "  admins             ${ADMINS[*]}"
echo "  threshold          $THRESHOLD   // DATA on this contract, not enforcement"
echo "  classification_max $CLASSIFICATION_MAX   // 2 = CUI; raisable later"
echo ")"
echo

ZERO=0x0000000000000000000000000000000000000000000000000000000000000000
if [ "$CURRENT_ROOT" != "$ZERO" ]; then
  echo "REFUSING: root is already set to $CURRENT_ROOT."
  echo "initRoot is one-shot (AlreadyInitialized). Nothing to do."
  exit 1
fi

if [ "$BROADCAST" -ne 1 ]; then
  echo "dry run — nothing sent. Re-run with DEPLOY_KEY=0x... --broadcast"
  exit 0
fi
[ -n "${DEPLOY_KEY:-}" ] || { echo "DEPLOY_KEY is required to broadcast" >&2; exit 2; }

# Chain 40204 REJECTS EIP-1559 transactions — always --legacy, or the send comes
# back as a bare "contract was not deployed" / silent failure.
ADMIN_CSV=$(IFS=,; echo "[${ADMINS[*]}]")
set -x
cast send "$TH" \
  'initRoot(bytes32,string,bytes32,address[],uint8,uint8)' \
  "$ROOT_ID" "$ROOT_NAME" "$HKDF_SALT" "$ADMIN_CSV" "$THRESHOLD" "$CLASSIFICATION_MAX" \
  --private-key "$DEPLOY_KEY" --rpc-url "$RPC_URL" --legacy
set +x

echo
echo "── verify (read back from chain, not from this script's own inputs) ──"
NEW_ROOT=$(cast call "$TH" 'root()(bytes32)' --rpc-url "$RPC_URL")
echo "root()   $NEW_ROOT"
[ "$NEW_ROOT" = "$ROOT_ID" ] || { echo "MISMATCH: expected $ROOT_ID" >&2; exit 1; }
cast call "$TH" 'getNode(bytes32)((bytes32,bytes32,string,uint8,bytes32,address[],uint8,uint8,bool))' \
  "$ROOT_ID" --rpc-url "$RPC_URL"
echo
echo "Root seeded. Next: quorum's Settings → Tenancy now renders a tree, and"
echo "scripts/sync-addresses.sh in citrate-quorum needs no change (same address)."
