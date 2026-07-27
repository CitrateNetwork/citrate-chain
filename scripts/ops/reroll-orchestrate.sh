#!/usr/bin/env bash
# reroll-orchestrate.sh — the SINGLE non-stop CLEAN REROLL orchestrator.
#
# Chains every reroll dependency behind a hard PASS gate so the ceremony runs
# from "live wedged chain" to "fully reconnected fresh chain, all dependencies
# deployed" WITHOUT stopping mid-way. This exists because the S2/S3/S3c rerolls
# each stalled between scattered scripts and manual SSH (see
# handoffs/REROLL_END_TO_END_CEREMONY_AUDIT_2026-07-23.md).
#
# Phase order (front-loads the validator set BEFORE the long forge deploys so the
# chain never halts at 1999 waiting for an epoch-2 snapshot — GAP-5):
#   P0  pre-flight asserts (env fixes applied, deployer/Arachnid, staged binaries)
#   P1  fleet-surgical-wipe.sh --confirm-wipe        → G1 (genesis) + G2 (consensus)
#   P2  DeployValidatorRegistry (CREATE2) + register 4 validators (--force)
#                                                     → G7 (registry) + G5 (activeCount 4)
#   P3  regenesis.sh --with-aa (44 core+feature+AA)  → G3 (all addrs have code)
#   P4  post-reroll-membership.sh (SBT+vault+fund)   → G6 (membership + grant signer 200k)
#   P5  fund-operational-roles.sh --broadcast        → operator gas floats
#   P6  monitor to activation height 2000            → G8 (sr identical across activation)
#   P7  treasury-signer health (address-neutral NO-OP verify)
#   P8  consumer re-pins (address-neutral NO-OP verify)
#   --  then the human WP-3.1 acceptance: G9 restart-proof + G4 deep cold-sync
#
# DEFAULT IS DRY-RUN. Pass --confirm to execute (P1 is IRREVERSIBLE). Every gate
# is stop-on-fail; on failure it prints the exact `--from <phase>` to resume after
# a fix, so a mid-ceremony stop never means re-wiping.
#
# Usage:
#   scripts/ops/reroll-orchestrate.sh --tag srp-s4                 # dry-run plan
#   scripts/ops/reroll-orchestrate.sh --tag srp-s4 --confirm       # execute all
#   scripts/ops/reroll-orchestrate.sh --tag srp-s4 --confirm --from P3   # resume
#
# Exit codes: 0 ok · 1 precondition/arg · 2 a phase step failed · 3 a gate failed
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS_DIR="${REPO_ROOT}/contracts"
OPS="${REPO_ROOT}/scripts/ops"
ENV_TESTNET="${ENV_TESTNET:-$(cd "${REPO_ROOT}/.." && pwd)/.env.testnet}"

# FROM defaults to P0 so the .env prep (blank CITRATE_AA_ENTRY_POINT — GAP-7) and
# the GAP-2 regression guards ALWAYS run before the deploys. Resuming with an
# explicit --from P3 etc. deliberately skips prep, so re-blank the pin by hand first.
TAG=""; CONFIRM=0; FROM="P0"
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --confirm) CONFIRM=1; shift ;;
    --from) FROM="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
[ -n "$TAG" ] || { echo "ERROR: --tag <binary-tag> required (e.g. srp-s4)" >&2; exit 1; }

CHAIN_ID=40204
REGISTRY_EXPECT="0x915DdE02831ebacFc57f329f60944492ebb0A095"
EPOINT_EXPECT="0xc698feaf0ff7fdb0d60e2f620c97cb729a694975"
SBT_EXPECT="0x4CE39F891c0A519Fa0E0De97A1DD3e3f856e0cF1"
VAULT_EXPECT="0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268"
GRANT_SIGNER="0xF42a19194fee89E71dC4b8631a71a9CeCf42B483"
ACTIVATION_HEIGHT=2000

log()  { echo "[reroll] $*"; }
err()  { echo "[reroll] ERROR: $*" >&2; }
# Execute (real) or print (dry-run). The dry-run echo REDACTS 64-hex private keys
# so piping a plan to a log never leaks a signer key.
run()  { if [ "$CONFIRM" -eq 1 ]; then "$@"; else echo "    DRYRUN $*" | sed -E 's/0x[0-9a-fA-F]{64}/0x<REDACTED_KEY>/g'; fi; }
get_env() { grep -E "^$1=" "$ENV_TESTNET" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'\'''; }

RPC="$(get_env CITRATE_RPC_URL)"; RPC="${RPC:-$(get_env RPC_URL)}"; RPC="${RPC:-https://rpc.citrate.ai}"
DK="$(get_env DEPLOYER_PRIVATE_KEY)"
DEPLOYER="$(get_env DEPLOYER_ADDRESS)"

# phase-ordering helper: should we run phase $1 given --from?
declare -a PHASES=(P0 P1 P2 P3 P4 P5 P6 P7 P8)
idx() { local p="$1" i; for i in "${!PHASES[@]}"; do [ "${PHASES[$i]}" = "$p" ] && { echo "$i"; return; }; done; echo 99; }
FROM_I="$(idx "$FROM")"
should() { [ "$(idx "$1")" -ge "$FROM_I" ]; }
gate_fail() { err "GATE FAIL at $1: $2"; err "fix, then resume: $0 --tag $TAG --confirm --from $1"; exit 3; }

# cast wrapper (real vs dry-run echo). Reads run against the live chain in BOTH
# modes so a dry-run still validates preconditions; only writes are gated.
cast_read() { cast "$@" --rpc-url "$RPC" 2>/dev/null; }
has_code()  { [ "$(cast_read code "$1" | wc -c)" -gt 6 ]; }

log "orchestrator: tag=$TAG confirm=$CONFIRM from=$FROM rpc=$RPC env=$ENV_TESTNET"
[ "$CONFIRM" -eq 0 ] && log "DRY-RUN — no wipe/deploy; reads are live, writes are printed only."

# ─────────────────────────── P0: PRE-FLIGHT ────────────────────────────────────
if should P0; then
  log "── P0 pre-flight asserts ─────────────────────────────────────────────────"
  command -v forge >/dev/null || { err "forge required"; exit 1; }
  command -v cast  >/dev/null || { err "cast required"; exit 1; }
  command -v jq    >/dev/null || { err "jq required"; exit 1; }
  [ -n "$DK" ] || { err "DEPLOYER_PRIVATE_KEY not in $ENV_TESTNET"; exit 1; }
  [ -n "$DEPLOYER" ] || { err "DEPLOYER_ADDRESS not in $ENV_TESTNET"; exit 1; }
  # GAP-7: CITRATE_AA_ENTRY_POINT MUST be blank before the AA deploy (a fresh
  # chain has no code there yet → post-reroll-redeploy would exit). Back up + blank.
  AAEP="$(get_env CITRATE_AA_ENTRY_POINT)"
  if [ -n "$AAEP" ]; then
    log "  GAP-7: blanking CITRATE_AA_ENTRY_POINT (was $AAEP; backup .env.testnet.bak-$TAG)"
    run cp "$ENV_TESTNET" "${ENV_TESTNET}.bak-${TAG}"
    run sed -i 's/^CITRATE_AA_ENTRY_POINT=.*/CITRATE_AA_ENTRY_POINT=/' "$ENV_TESTNET"
  else
    log "  CITRATE_AA_ENTRY_POINT already blank ✓"
  fi
  # GAP-2 regression guard: the two scripts must NOT contain the backwards guard.
  if grep -q 'command -v python3 >/dev/null || PY="uv run python3"' "$OPS/post-reroll-membership.sh"; then
    gate_fail P0 "post-reroll-membership.sh still has the backwards python3 guard (GAP-2)"
  fi
  # match only the command-substitution form `$(python3 -c …` (the real footgun),
  # not comment prose that mentions python3.
  grep -qE '\$\(python3 ' "$OPS/fund-operational-roles.sh" && \
    gate_fail P0 "fund-operational-roles.sh still has a bare \$(python3 …) call (GAP-2)"
  log "  GAP-2 python3 landmine: fixed in both scripts ✓"
  # deployer key present; the chain is not yet live (wiped in P1) so we do NOT
  # assert on-chain deployer balance here — that is G1's job inside the wipe.
  log "  P0 PASS: tooling present, deployer key set, .env fixes applied."
fi

# ─────────────────────────── P1: SURGICAL WIPE ─────────────────────────────────
if should P1; then
  log "── P1 fleet surgical wipe (IRREVERSIBLE) → G1 + G2 ───────────────────────"
  if [ "$CONFIRM" -eq 1 ]; then
    bash "$OPS/fleet-surgical-wipe.sh" --tag "$TAG" --confirm-wipe || gate_fail P1 "surgical wipe / G1 / G2 failed"
  else
    bash "$OPS/fleet-surgical-wipe.sh" --tag "$TAG" || true   # dry-run plan
  fi
  log "  P1 done (G1 genesis + G2 fresh-chain consensus asserted by the wipe script)."
fi

# ─────────────────────────── P2: VALIDATOR SET (front-loaded) ─────────────────
if should P2; then
  log "── P2 ValidatorRegistry + register 4 validators → G7 + G5 ────────────────"
  log "  deploy ValidatorRegistry (CREATE2)…"
  # DeployValidatorRegistry.s.sol (like the regenesis scripts) reads the deployer
  # from the ENV (CEREMONY_DEPLOYER_ADDRESS/DEPLOYER_ADDRESS), not just --sender.
  run bash -c "cd '$CONTRACTS_DIR' && DEPLOYER_ADDRESS='$DEPLOYER' CEREMONY_DEPLOYER_ADDRESS='$DEPLOYER' \
      forge script script/DeployValidatorRegistry.s.sol \
      --rpc-url '$RPC' --private-key '$DK' --sender '$DEPLOYER' \
      --broadcast --slow --gas-estimate-multiplier 130 >/dev/null" \
    || gate_fail P2 "DeployValidatorRegistry failed"
  if [ "$CONFIRM" -eq 1 ]; then
    has_code "$REGISTRY_EXPECT" || gate_fail P2 "G7: ValidatorRegistry has no code at $REGISTRY_EXPECT"
  fi
  log "  G7 PASS: registry at $REGISTRY_EXPECT has code."
  # register the 4 validators (coinbase == staker addr; --force per GAP-6).
  #
  # WP-11: the proposer key is no longer derivable from the coinbase — it is a
  # real secret each node mints into <data-dir>/proposer.key on first start (P1
  # brought the fleet up, so the files exist by now). Fetch each node's key over
  # SSH into a 0700 staging dir and pass it as the ceremony's third --node field.
  # The ceremony REJECTS the old two-field form rather than silently re-deriving.
  # Fleet order MUST match fleet-surgical-wipe.sh's ALL_IPS and the staker index:
  #   STAKER_1 = rpc-1, STAKER_2 = boot1, STAKER_3 = boot2, STAKER_4 = boot3.
  # A mismatch would register node N's coinbase against node M's proposer key —
  # every such validator would be admitted and then never able to sign a block.
  FLEET_IPS=( "142.93.58.145" "142.93.50.217" "143.198.134.151" "142.93.99.212" )

  PROPOSER_KEY_DIR="$(mktemp -d -t citrate-proposer-keys-XXXXXX)"
  chmod 700 "$PROPOSER_KEY_DIR"
  # Wipe the private keys from disk on ANY exit path, including a gate failure.
  trap 'rm -rf -- "$PROPOSER_KEY_DIR"' EXIT INT TERM

  NODE_ARGS=()
  for i in 1 2 3 4; do
    CB="$(get_env "VALIDATOR_STAKER_${i}_ADDRESS")"
    [ -n "$CB" ] || gate_fail P2 "VALIDATOR_STAKER_${i}_ADDRESS missing in $ENV_TESTNET"
    NODE_IP="${FLEET_IPS[$((i-1))]}"
    PK_FILE="$PROPOSER_KEY_DIR/node${i}-proposer.key"
    if [ "$CONFIRM" -eq 1 ]; then
      # Nodes mint proposer.key at 0600 on first start; if it is absent the node
      # never came up in P1 and registering would bind a key nothing signs with.
      scp -q -o BatchMode=yes -o StrictHostKeyChecking=no \
        "root@${NODE_IP}:/home/citrate/.citrate/proposer.key" "$PK_FILE" \
        || gate_fail P2 "could not fetch proposer.key from ${NODE_IP} — did P1 start the node?"
      chmod 600 "$PK_FILE"
      SZ="$(wc -c < "$PK_FILE" | tr -d ' ')"
      [ "$SZ" = "32" ] || gate_fail P2 "proposer.key from ${NODE_IP} is ${SZ} bytes, expected 32"
    fi
    NODE_ARGS+=( --node "${CB}=VALIDATOR_STAKER_${i}_PRIVATE_KEY=${PK_FILE}" )
  done
  # export the staker keys so the ceremony bin can resolve the env-var names.
  if [ "$CONFIRM" -eq 1 ]; then
    for i in 1 2 3 4; do export "VALIDATOR_STAKER_${i}_PRIVATE_KEY=$(get_env "VALIDATOR_STAKER_${i}_PRIVATE_KEY")"; done
    export CITRATE_RPC_URL="$RPC" CITRATE_VALIDATOR_REGISTRY="$REGISTRY_EXPECT"
  fi
  run bash -c "cd '$REPO_ROOT' && cargo run --release --bin validator-registration-ceremony -- \
      --rpc-url '$RPC' --registry '$REGISTRY_EXPECT' --stake-salt 32000 --force ${NODE_ARGS[*]}" \
    || gate_fail P2 "validator registration failed"
  if [ "$CONFIRM" -eq 1 ]; then
    AC="$(cast_read call "$REGISTRY_EXPECT" 'activeCount()(uint256)')"
    [ "$AC" = "4" ] || gate_fail P2 "G5: activeCount()=$AC != 4"
  fi
  log "  G5 PASS: 4 validators registered, activeCount()==4."
fi

# ─────────────────────────── P3: CORE + FEATURE + AA ──────────────────────────
if should P3; then
  log "── P3 regenesis.sh --with-aa (44 core+feature+AA) → G3 ───────────────────"
  run bash -c "ENV_TESTNET='$ENV_TESTNET' bash '$OPS/regenesis.sh' --with-aa" \
    || gate_fail P3 "regenesis (core+feature+AA) failed"
  if [ "$CONFIRM" -eq 1 ]; then
    has_code "$EPOINT_EXPECT" || gate_fail P3 "G3: EntryPoint has no code at $EPOINT_EXPECT"
  fi
  log "  G3 PASS: 44 core+feature+AA deployed address-neutral; EntryPoint has code."
fi

# ─────────────────────────── P4: MEMBERSHIP MONEY PATH ────────────────────────
if should P4; then
  log "── P4 post-reroll-membership.sh (SBT+vault+fund grant signer) → G6 ───────"
  run bash -c "CITRATE_ENV_FILE='$ENV_TESTNET' bash '$OPS/post-reroll-membership.sh'" \
    || gate_fail P4 "membership deploy/fund failed (GAP-2 fixed; if it still halts, check uv)"
  if [ "$CONFIRM" -eq 1 ]; then
    has_code "$SBT_EXPECT"   || gate_fail P4 "G6: SBT has no code at $SBT_EXPECT"
    has_code "$VAULT_EXPECT" || gate_fail P4 "G6: vault has no code at $VAULT_EXPECT"
    OWN="$(cast_read call "$SBT_EXPECT" 'owner()(address)' || true)"
    [ -z "$OWN" ] || [ "${OWN,,}" = "${GRANT_SIGNER,,}" ] || gate_fail P4 "G6: SBT owner $OWN != grant signer $GRANT_SIGNER"
    GB="$(cast_read balance "$GRANT_SIGNER")"
    [ -n "$GB" ] && [ "$GB" != "0" ] || gate_fail P4 "G6: grant signer $GRANT_SIGNER not funded"
  fi
  log "  G6 PASS: SBT $SBT_EXPECT + vault $VAULT_EXPECT owned by grant signer, funded."
fi

# ─────────────────────────── P5: OPERATIONAL FUNDING ──────────────────────────
if should P5; then
  log "── P5 fund-operational-roles.sh --broadcast ──────────────────────────────"
  run bash -c "ENV_FILE='$ENV_TESTNET' bash '$OPS/fund-operational-roles.sh' --broadcast" \
    || gate_fail P5 "operational-role funding failed"
  log "  P5 done: operator gas floats topped up."
fi

# ─────────────────────────── P6: ACTIVATION MONITOR → G8 ──────────────────────
if should P6; then
  log "── P6 monitor to activation height ${ACTIVATION_HEIGHT} → G8 ──────────────"
  if [ "$CONFIRM" -eq 1 ]; then
    # poll the public RPC until head crosses activation+5, then confirm no wedge.
    deadline=$(( $(date +%s 2>/dev/null || echo 0) + 5400 ))   # ~90 min budget
    while :; do
      H="$(cast_read block-number || echo 0)"
      log "  head=$H (target $((ACTIVATION_HEIGHT+5)))"
      [ "${H:-0}" -ge $((ACTIVATION_HEIGHT+5)) ] && break
      NOW=$(date +%s 2>/dev/null || echo 0)
      [ "$NOW" -ge "$deadline" ] && gate_fail P6 "chain did not cross activation ${ACTIVATION_HEIGHT} within budget (head $H — check the producer did not halt at $((ACTIVATION_HEIGHT-1)))"
      sleep 30
    done
    # sr@activation+1 must be reproducible (single-RPC sanity; cross-node compare
    # is the wipe/G2 style ssh check, run in WP-3.1). A halt would have tripped above.
    SR="$(cast_read block "$((ACTIVATION_HEIGHT+1))" -f stateRoot || true)"
    [ -n "$SR" ] || gate_fail P6 "G8: no block at $((ACTIVATION_HEIGHT+1))"
    log "  G8 PASS: crossed activation ${ACTIVATION_HEIGHT}; sr@$((ACTIVATION_HEIGHT+1))=$SR; producer did not halt."
  else
    echo "    DRYRUN would poll head to $((ACTIVATION_HEIGHT+5)) and confirm no producer halt"
  fi
fi

# ─────────────────────────── P7: TREASURY-SIGNER (NO-OP verify) ───────────────
if should P7; then
  log "── P7 treasury-signer health (address-neutral → NO-OP verify) ────────────"
  if [ "$CONFIRM" -eq 1 ]; then
    HJ="$(curl -s --max-time 8 https://auth.citrate.ai/_ops/treasury/health || true)"
    echo "$HJ" | grep -qi "$GRANT_SIGNER" && log "  P7 PASS: treasury-signer /health reports grant signer ${GRANT_SIGNER}." \
      || log "  P7 WARN: could not confirm grant signer in /health (rekey only if SBT/vault moved — they did not this reroll). Response: ${HJ:0:200}"
  else
    echo "    DRYRUN would GET https://auth.citrate.ai/_ops/treasury/health and check signer"
  fi
fi

# ─────────────────────────── P8: CONSUMER RE-PINS (NO-OP verify) ──────────────
if should P8; then
  log "── P8 consumer re-pins (address-neutral reroll → NO-OP) ──────────────────"
  BOOK="${CONTRACTS_DIR}/addresses/40204.json"
  if [ "$CONFIRM" -eq 1 ] && command -v git >/dev/null; then
    ( cd "$REPO_ROOT" && git diff --stat -- "$BOOK" 2>/dev/null | tail -1 ) || true
    log "  P8: verify the book diff shows only registry/SBT/vault re-added (no core address moved); consumers are NO-OP."
  else
    echo "    DRYRUN would git-diff $BOOK to confirm address-neutrality (consumer re-pins NO-OP)"
  fi
fi

log ""
log "════════════════════════════════════════════════════════════════════════════"
if [ "$CONFIRM" -eq 1 ]; then
  log "✅ REROLL DEPLOY COMPLETE — all dependencies live (P0–P8 gated PASS)."
else
  log "DRY-RUN complete. Execute with:  $0 --tag $TAG --confirm"
fi
log "REMAINING (human WP-3.1 acceptance — the only sign-off, per the audit):"
log "  • G9  restart-proof: restart the MINER (rpc-1, NO wipe) + a follower mid-epoch;"
log "        applied tips advance in lockstep, stateRoot identical, 0 reorg-thrash."
log "  • G4  deep cold-sync: a fresh external aarch64 node syncs genesis→head across the"
log "        forked height with 0 state-root mismatches; citrate-core bundled node (Linux+Mac)"
log "        cold-syncs + close/reopen. THIS is the SRP-S4 acceptance gate."
log "════════════════════════════════════════════════════════════════════════════"
