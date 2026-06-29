#!/usr/bin/env bash
# Regenerate `contracts/addresses/40204.json` — the federation's canonical
# contract-address table — from the deploy-broadcast outputs and the
# `.env.testnet` AA stack pins.
#
# Run AFTER a successful redeploy ceremony (e.g., post-re-roll). The output
# is what every consumer repo's `sync-addresses` script reads from. Diff
# the output against the committed copy; if it changed, commit + push, then
# fan out to the consumers.
#
# Inputs:
#   - contracts/broadcast/Deploy*.s.sol/40204/run-latest.json — every
#     CREATE transaction's deployed contract name + address.
#   - /home/saul/Projects/Citrate-Labs/.env.testnet — CITRATE_AA_* pins
#     for the EW-S1 ERC-4337 stack.
#
# Output:
#   - contracts/addresses/40204.json — the canonical table.
#
# Dependencies: jq (for JSON parsing).
#
# Exit codes:
#   0  success
#   1  precondition failed (jq missing, broadcast files missing, etc.)
#   2  unexpected schema in a broadcast file
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BROADCAST_ROOT="${REPO_ROOT}/contracts/broadcast"
OUTPUT="${REPO_ROOT}/contracts/addresses/40204.json"
ENV_TESTNET="${ENV_TESTNET:-/home/saul/Projects/Citrate-Labs/.env.testnet}"

CHAIN_ID=40204

err() { echo "[emit-address-table] ERROR: $*" >&2; }
log() { echo "[emit-address-table] $*"; }

command -v jq >/dev/null || { err "jq is required"; exit 1; }

# The 7 ceremonies that produce chain-40204 broadcasts. Adding a new
# ceremony? List it here so its CREATEs are included.
CEREMONIES=(
  "DeployAll.s.sol"
  "DeployEduStack.s.sol"
  "DeployAIGateway.s.sol"
  "DeployModelAccessControl.s.sol"
  "DeployTEEAttestationRegistry.s.sol"
  "DeployComputePoolTraining.s.sol"
  "DeployAA.s.sol"
  # WP-D ceremony: same six AA contracts as DeployAA.s.sol but emitted via
  # the pin-table wrapper. Listed AFTER DeployAA so its CREATEs override
  # the older addresses (the merge step is last-write-wins).
  "DeployAndPinAA.s.sol"
  # I64-S1 WP-B1: the five federated-learning contracts (KYCRegistry,
  # IPFSIncentivesV2/V3, AggregationChallenge, ComputePoolPipeline) that
  # joined the surface after the last re-roll. Picked up post-ceremony from
  # this broadcast; pre-ceremony their deterministic projection lives in
  # contracts/addresses/I64S1_PROJECTION.md.
  "DeployFederatedLearning.s.sol"
)

# Collect every CREATE transaction's (contractName, contractAddress) pair
# from each broadcast file, then dedupe (later ceremonies wouldn't normally
# re-emit the same name, but the prior _address_table had MentorMatcher and
# StablecoinTreasury duped — dedupe defensively).
contracts_jq=$(mktemp)
aa_jq=$(mktemp)
trap 'rm -f "$contracts_jq" "$aa_jq"' EXIT

echo "{}" > "$contracts_jq"
echo "{}" > "$aa_jq"

for ceremony in "${CEREMONIES[@]}"; do
  bc="${BROADCAST_ROOT}/${ceremony}/${CHAIN_ID}/run-latest.json"
  if [[ ! -f "$bc" ]]; then
    log "skip ${ceremony} (no broadcast at ${bc})"
    continue
  fi
  log "merging ${ceremony}"
  # forge writes transactions with .transactionType = "CREATE" for new
  # deployments and a .contractName that names the Solidity contract.
  pairs=$(jq -c '
    .transactions
    | map(select((.transactionType == "CREATE" or .transactionType == "CREATE2") and .contractName != null and .contractAddress != null))
    | map({ key: .contractName, value: (.contractAddress | ascii_downcase) })
    | from_entries
  ' "$bc")
  if [[ "$ceremony" == "DeployAA.s.sol" || "$ceremony" == "DeployAndPinAA.s.sol" ]]; then
    jq --argjson new "$pairs" '. + $new' "$aa_jq" > "${aa_jq}.tmp" && mv "${aa_jq}.tmp" "$aa_jq"
  else
    jq --argjson new "$pairs" '. + $new' "$contracts_jq" > "${contracts_jq}.tmp" && mv "${contracts_jq}.tmp" "$contracts_jq"
  fi
done

# Rename the EduStack `Forwarder` to `EduForwarder` — the canonical name
# distinguishes it from any future Citrate-wide EIP-2771 forwarder.
mv "$contracts_jq" "${contracts_jq}.orig"
jq 'if has("Forwarder") then (.EduForwarder = .Forwarder | del(.Forwarder)) else . end' \
  "${contracts_jq}.orig" > "$contracts_jq"
rm -f "${contracts_jq}.orig"

# AA stack: merge broadcast output with .env.testnet pins. EntryPoint v0.7
# is vendored (from eth-infinitism) so it's not in DeployAA's broadcast as
# a CREATE; pull it from .env.testnet.
get_env() { grep -E "^${1}=" "$ENV_TESTNET" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' '; }

# I64-S1 WP-B2: the co-op `CitrateCooperativeFactory` is deployed from the
# SEPARATE citrate-coop repo (its own foundry project + "citrate.coop.v1."
# salt namespace), so there is no broadcast for it under this repo's
# contracts/broadcast — it can't be auto-merged like the ceremonies above.
# Inject it as a pinned entry: prefer a CITRATE_COOP_FACTORY override in
# .env.testnet, else the deterministic CREATE2 address the coop DeployCoop.s.sol
# lands at (no-arg constructor → sender-independent).
coop_factory=$(get_env "CITRATE_COOP_FACTORY" || true)
coop_factory=${coop_factory:-0xa9ded8dbfca510cca8f5896c3f6144b30ad98c6d}
jq --arg cf "$coop_factory" '.CitrateCooperativeFactory = ($cf | ascii_downcase)' \
  "$contracts_jq" > "${contracts_jq}.tmp" && mv "${contracts_jq}.tmp" "$contracts_jq"

aa_entrypoint=$(get_env "CITRATE_AA_ENTRY_POINT" || true)
aa_webauthn=$(get_env "CITRATE_AA_WEBAUTHN_VALIDATOR" || true)
aa_ecdsa=$(get_env "CITRATE_AA_ECDSA_VALIDATOR" || true)
aa_guardian=$(get_env "CITRATE_AA_GUARDIAN_RECOVERY" || true)
aa_wallet=$(get_env "CITRATE_AA_WALLET_IMPL" || true)
aa_factory=$(get_env "CITRATE_AA_FACTORY" || true)
aa_paymaster=$(get_env "CITRATE_AA_PAYMASTER" || true)

# Honor either the broadcast-recovered value (if present) or the env pin.
aa_final=$(jq -n \
  --arg ep "$aa_entrypoint" --arg wv "$aa_webauthn" --arg ev "$aa_ecdsa" \
  --arg gr "$aa_guardian" --arg wi "$aa_wallet" --arg fa "$aa_factory" --arg pm "$aa_paymaster" \
  --argjson bc "$(cat "$aa_jq")" \
  '{
    EntryPoint:             ($bc.EntryPoint            // $ep),
    CitrateWallet:          ($bc.CitrateWallet         // $wi),
    CitrateWalletFactory:   ($bc.CitrateWalletFactory  // $fa),
    CitratePaymaster:       ($bc.CitratePaymaster      // $pm),
    WebAuthnP256Validator:  ($bc.WebAuthnP256Validator // $wv),
    CitrateECDSAValidator:  ($bc.CitrateECDSAValidator // $ev),
    GuardianRecoveryModule: ($bc.GuardianRecoveryModule // $gr)
   }
   | with_entries(select(.value != "" and .value != null))')

# Deployer: pulled from .env.testnet (the canonical EOA). The broadcast
# files' `.transactions[].from` is unreliable (DeployAll's first row is
# `from: null` because forge fills it post-broadcast). We don't trust those.
DEPLOYER=$(get_env "DEPLOYER_ADDRESS")
DEPLOYER=${DEPLOYER:-0x4250675F9015E65fC866F3a373F82bb9DFc000c6}

# Deployed-at: MAX timestamp across every broadcast (i.e. the most recent
# ceremony) — that's the answer to "when was this table's youngest row?".
# forge writes `.timestamp` as milliseconds since epoch.
DEPLOYED_AT_MS=0
for ceremony in "${CEREMONIES[@]}"; do
  bc="${BROADCAST_ROOT}/${ceremony}/${CHAIN_ID}/run-latest.json"
  [[ -f "$bc" ]] || continue
  ts=$(jq -r '.timestamp // 0' "$bc" 2>/dev/null)
  if [[ -n "$ts" && "$ts" != "null" && "$ts" -gt "$DEPLOYED_AT_MS" ]]; then
    DEPLOYED_AT_MS=$ts
  fi
done
DEPLOYED_AT=""
if [[ "$DEPLOYED_AT_MS" -gt 0 ]]; then
  DEPLOYED_AT_S=$((DEPLOYED_AT_MS / 1000))
  DEPLOYED_AT=$(date -u -d "@${DEPLOYED_AT_S}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
fi

# Final canonical assembly. Keep contract names exactly as Solidity defined
# them; the precompile + genesis blocks are static (not from broadcasts).
jq -n \
  --argjson contracts "$(cat "$contracts_jq")" \
  --argjson aa "$aa_final" \
  --arg deployer "${DEPLOYER:-0x4250675F9015E65fC866F3a373F82bb9DFc000c6}" \
  --arg deployed_at "${DEPLOYED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
  '{
    "$schema": "./schema.json",
    chainId: 40204,
    chainName: "Citrate Network",
    rpcUrl: "https://rpc.citrate.ai",
    explorerUrl: "https://explorer.citrate.ai",
    deployer: $deployer,
    deployedAt: $deployed_at,
    regenerator: "scripts/ops/emit-address-table.sh",
    comment: "Canonical contract-address table for chain 40204 — the single source of truth the federation reads from. Regenerated from broadcast/*.s.sol/40204/run-latest.json + .env.testnet AA pins. See contracts/addresses/README.md.",
    contracts: $contracts,
    aaStack: $aa,
    genesis: { ArachnidDeterministicDeployer: "0x4e59b44847b379578588920cA78FbF26c0B4956C" },
    precompiles: {
      StateModel:        "0x0000000000000000000000000000000000001000",
      StateArtifact:     "0x0000000000000000000000000000000000001001",
      StateGovernance:   "0x0000000000000000000000000000000000001003",
      InferenceDeploy:   "0x0000000000000000000000000000000000000100",
      InferenceRun:      "0x0000000000000000000000000000000000000101",
      InferenceVerify:   "0x0000000000000000000000000000000000000108"
    }
   }' > "$OUTPUT"

log "wrote ${OUTPUT}"
contract_count=$(jq '.contracts | length' "$OUTPUT")
aa_count=$(jq '.aaStack | length' "$OUTPUT")
log "  contracts: ${contract_count}"
log "  aaStack:   ${aa_count}"
log ""
log "Diff against committed copy:"
log "  git diff contracts/addresses/40204.json"
log ""
log "If the diff is non-empty, run each consumer's sync-addresses script:"
log "  cd ../citrate-explorer            && pnpm sync-addresses"
log "  cd ../citrate-inference-gateway   && bash scripts/sync-addresses.sh"
log "  cd ../citrate-node-agent          && bash scripts/sync-addresses.sh"
log "  cd ../citrate-sdk-marketplace     && pnpm sync-addresses"
log "  cd ../citrate-gui-native          && bash scripts/sync-addresses.sh"
log "  cd ../citrate-boeing-shell        && bash scripts/sync-addresses.sh"
log "  cd ../citrate-buyer-webapp        && pnpm sync-addresses"
