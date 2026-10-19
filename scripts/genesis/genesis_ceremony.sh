#!/usr/bin/env bash
# genesis_ceremony.sh: the genesis contract ceremony, phase by phase, each behind a gate.
#
# Runs after the new chain is producing (runbook §6). Order:
#   P0  preflight      inputs present, governance values at the genesis floors, tools,
#                      required contract scripts present; with an RPC: chain id, block-0
#                      hash, deployer nonce 0
#   P1  governance     DeployGenesisGovernance: GOVERNANCE + GUARDIAN timelocks, each
#                      fronted by an m-of-n MultisigProposer; deployer renounces in-run
#   P2  stack          scripts/ops/regenesis.sh --reroll --with-aa (registries, VR, AA,
#                      membership), with GOVERNANCE/GUARDIAN taken from P1's output
#   P3  vesting        DeployTeamVesting from the owner's TEAM_VESTING_FILE
#   P4  dormant        DeployDormantLedgers (FederatedRoundLedger, PatronageLedger)
#   P5  admins         CheckDeployedAdmins over the book + P1/P3/P4 outputs:
#                      FACTORY-ADMIN 0 and DEPLOYER-ADMIN 0 (the handover gate)
#   P6  keep           keep_check.sh verify against the frozen KEEP list
#   P7  fleet          fleet_agree.sh: every endpoint on the same genesis and tip
#
# Modes
#   (default) dry run  offline: validates inputs and prints every command. No RPC.
#   --simulate         runs the phases against RPC_URL without broadcasting (forge
#                      simulation; use an anvil fork or a rehearsal node). P5-P7 run for real
#                      since they only read.
#   --confirm          broadcasts. A non-loopback RPC_URL also needs CITRATE_ALLOW_REMOTE=1.
#   --from Pn          resume at phase n after a fix (no phase is re-run blindly).
#   --only Pn          run a single phase.
#   The P0 safety preflight (inputs, governance floors, chain id, block-0 hash, remote-RPC
#   authorization, deployer seat) runs on EVERY --simulate/--confirm invocation, including
#   --from and --only. Only the fresh-deployer nonce-0 check is limited to a new ceremony
#   (no --from/--only).
#
# Signing: --account NAME (Foundry keystore) and optionally --password-file PATH. A raw key
# (--private-key, or PRIVATE_KEY/DEPLOYER_PRIVATE_KEY in the environment) is refused.
#
# Inputs (env). Values marked OPEN are owner decisions recorded in the runbook §2:
#   RPC_URL, DEPLOYER_ADDRESS, EXPECTED_CHAIN_ID (40204), EXPECTED_GENESIS_HASH (from the cut)
#   GOV_OWNERS, GOV_THRESHOLD, GOV_MIN_DELAY, GOV_PROPOSAL_TTL      (holders OPEN)
#   GRD_OWNERS, GRD_THRESHOLD, GRD_MIN_DELAY, GRD_PROPOSAL_TTL      (holders OPEN)
#   TEAM_VESTING_FILE (OPEN amounts/schedule; must sit under contracts/genesis/)
#   PATRONAGE_KYC_REGISTRY, PATRONAGE_MEMBERSHIP, MEMBERSHIP_OWNER, plus regenesis.sh's env
#   KEEP_LIST (the rehearsal-1 freeze) · FLEET_RPCS (comma-separated)
#   GENESIS_OUT_DIR (contracts/genesis) · ADDRESS_BOOK (contracts/addresses/40204.json)
#
# Output books: P1/P3/P4 write governance.json, team-vesting.json and dormant-ledgers.json
# into GENESIS_OUT_DIR, and P2/P4/P5 read them from the same place; every producer and
# consumer path is derived from that one directory. Forge may only write under
# contracts/genesis (foundry.toml fs_permissions), so GENESIS_OUT_DIR must be that directory
# or one below it; anything else is refused before any phase runs. A phase that writes a
# book refuses to start, in --simulate or --confirm, while that book already exists: an
# older file in the directory would otherwise be read as this ceremony's output.
#
# Exit: 0 ok · 1 precondition/usage · 2 a phase step failed · 3 a gate failed
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/genesis/lib.sh
. "$HERE/lib.sh"
GENESIS_LOG_TAG=ceremony
# A command that fails outside an explicit check stops the run non-zero (set -e); say where.
trap 'err "unexpected failure (exit $?) at line $LINENO; inspect before resuming with --from"' ERR

REPO_ROOT="${REPO_ROOT:-$(cd "$HERE/../.." && pwd)}"
CONTRACTS="$REPO_ROOT/contracts"
FORGE="${FORGE:-${FOUNDRY_BIN:+$FOUNDRY_BIN/}forge}"
CAST="${CAST:-${FOUNDRY_BIN:+$FOUNDRY_BIN/}cast}"
PY="${PYTHON:-python3}"
REGENESIS="${REGENESIS:-$REPO_ROOT/scripts/ops/regenesis.sh}"
EXPECTED_CHAIN_ID="${EXPECTED_CHAIN_ID:-40204}"
OUT="${GENESIS_OUT_DIR:-$CONTRACTS/genesis}"
ADDRESS_BOOK="${ADDRESS_BOOK:-$CONTRACTS/addresses/40204.json}"

# Genesis floors (owner decisions 2026-10-19, C2 D5). #324 enforces these on-chain in the
# deploy script; this preflight refuses earlier, before anything is sent.
GOV_MIN_THRESHOLD=3
GOV_MIN_OWNERS=5
GOV_MIN_DELAY_SECS=172800 # 48 h
GRD_MIN_THRESHOLD=2
GRD_MIN_OWNERS=3
GRD_MIN_DELAY_SECS=3600 # the contract floor
GENESIS_TTL_SECS=1209600 # 14 days, fixed on 40204

PHASES=(P0 P1 P2 P3 P4 P5 P6 P7)
MODE=dry
FROM=P0
ONLY=""
ACCOUNT=""
PASSWORD_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --simulate) MODE=simulate; shift ;;
    --confirm) MODE=confirm; shift ;;
    --dry-run) MODE=dry; shift ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    --account) ACCOUNT="${2:-}"; shift 2 ;;
    --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
    --private-key | --private-key=*) die "raw private keys are refused; sign with --account (Foundry keystore)" 1 ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
      exit 1
      ;;
    *) die "unknown argument $1" 1 ;;
  esac
done
refuse_raw_keys

# The one output directory, as forge sees it (relative to contracts/) and as this script
# sees it (absolute). Lexical normalisation only, so it works before the directory exists.
norm_path() { "$PY" -c 'import os,sys; print(os.path.normpath(os.path.abspath(sys.argv[1])))' "$1"; }
contracts_abs=$(norm_path "$CONTRACTS") || die "cannot resolve $CONTRACTS" 1
out_abs=$(norm_path "$OUT") || die "cannot resolve GENESIS_OUT_DIR $OUT" 1
case "$out_abs" in
  "$contracts_abs/genesis" | "$contracts_abs/genesis/"*) OUT_REL="${out_abs#"$contracts_abs/"}" ;;
  *) die "GENESIS_OUT_DIR must be contracts/genesis or a directory below it (forge writes only there); got $OUT" 1 ;;
esac
OUT="$out_abs"
GOV_REL="$OUT_REL/governance.json"
VEST_REL="$OUT_REL/team-vesting.json"
DORMANT_REL="$OUT_REL/dormant-ledgers.json"
GOV_BOOK="$CONTRACTS/$GOV_REL"
VEST_BOOK="$CONTRACTS/$VEST_REL"
DORMANT_BOOK="$CONTRACTS/$DORMANT_REL"

idx() {
  local i
  for i in "${!PHASES[@]}"; do [[ "${PHASES[$i]}" == "$1" ]] && {
    echo "$i"
    return
  }; done
  echo -1
}
[[ $(idx "$FROM") -ge 0 ]] || die "--from must be one of ${PHASES[*]}" 1
[[ -z "$ONLY" || $(idx "$ONLY") -ge 0 ]] || die "--only must be one of ${PHASES[*]}" 1
should() {
  if [[ -n "$ONLY" ]]; then [[ "$1" == "$ONLY" ]]; else [[ $(idx "$1") -ge $(idx "$FROM") ]]; fi
}
gate_fail() {
  err "GATE FAIL at $1: $2"
  err "fix it, then resume: $0 --$MODE --from $1 ${ACCOUNT:+--account $ACCOUNT}"
  exit 3
}
step_fail() {
  err "STEP FAIL at $1: $2"
  err "inspect contracts/broadcast/ and the chain before resuming with --from $1 (never re-run a partly broadcast phase blindly)"
  exit 2
}

SIGN=()
if [[ -n "$ACCOUNT" ]]; then
  SIGN=(--account "$ACCOUNT")
  if [[ -n "$PASSWORD_FILE" ]]; then SIGN+=(--password-file "$PASSWORD_FILE"); fi
fi

# forge_phase <phase> <script> : forge script in the mode's shape.
forge_phase() {
  local phase="$1" script="$2" args
  args=(script "script/$script" --rpc-url "${RPC_URL:-\$RPC_URL}" --sender "${DEPLOYER_ADDRESS:-\$DEPLOYER_ADDRESS}" --slow)
  if [[ "$MODE" == confirm ]]; then args+=(--broadcast "${SIGN[@]}"); fi
  if [[ "$MODE" == dry ]]; then
    describe_cmd "(cd contracts &&" "$FORGE" "${args[@]}" ")"
    return 0
  fi
  (cd "$CONTRACTS" && "$FORGE" "${args[@]}") || step_fail "$phase" "$script"
}

# book_addr <book> <name>: contracts.<name> from a book-shaped JSON.
book_addr() {
  "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["contracts"][sys.argv[2]])' "$1" "$2" 2>/dev/null
}

count_owners() { # comma-separated list -> number of distinct non-empty entries
  count_owners_list "$1" | wc -l | tr -d ' '
}

need_env() { # name...
  local v missing=()
  for v in "$@"; do [[ -n "${!v:-}" ]] || missing+=("$v"); done
  [[ ${#missing[@]} -eq 0 ]] || gate_fail P0 "missing inputs: ${missing[*]}"
}

check_council() { # prefix min_threshold min_owners min_delay
  local p="$1" ov tv dv ttlv owners o t d ttl a
  ov="${p}_OWNERS" tv="${p}_THRESHOLD" dv="${p}_MIN_DELAY" ttlv="${p}_PROPOSAL_TTL"
  owners="${!ov}" t="${!tv}" d="${!dv}" ttl="${!ttlv:-$GENESIS_TTL_SECS}"
  o=$(count_owners "$owners")
  [[ "$t" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ && "$ttl" =~ ^[0-9]+$ ]] || gate_fail P0 "${p}_THRESHOLD/_MIN_DELAY/_PROPOSAL_TTL must be whole numbers"
  for a in ${owners//,/ }; do
    is_addr "$a" || gate_fail P0 "${p}_OWNERS has a malformed address"
  done
  if [[ "$EXPECTED_CHAIN_ID" == 40204 ]]; then
    ((o >= $3)) || gate_fail P0 "$p has $o distinct owners; the genesis needs at least $3"
    ((t >= $2)) || gate_fail P0 "$p threshold $t is below the genesis floor $2"
    ((d >= $4)) || gate_fail P0 "$p delay ${d}s is below the genesis floor ${4}s"
    ((ttl == GENESIS_TTL_SECS)) || gate_fail P0 "${p}_PROPOSAL_TTL must be $GENESIS_TTL_SECS (14 days) on 40204"
  fi
  ((d >= GRD_MIN_DELAY_SECS)) || gate_fail P0 "$p delay ${d}s is below the 1 h contract floor"
  ((ttl >= 86400 && ttl <= 2592000)) || gate_fail P0 "${p}_PROPOSAL_TTL must be 1 to 30 days"
  ((t <= o)) || gate_fail P0 "$p threshold $t exceeds $o owners"
  ((t * 2 > o)) || gate_fail P0 "$p threshold $t is not a majority of $o owners"
  log "P0 $p: $t-of-$o, delay ${d}s, proposal ttl ${ttl}s"
}

overlap_check() {
  # No process substitution: bash drops its exit status, so both lists are captured and
  # checked first.
  local gov grd a shared=""
  gov=$(count_owners_list "$GOV_OWNERS") || gate_fail P0 "cannot read GOV_OWNERS"
  grd=$(count_owners_list "$GRD_OWNERS") || gate_fail P0 "cannot read GRD_OWNERS"
  for a in $gov; do
    if grep -qxF -- "$a" <<<"$grd"; then shared+="$a "; fi
  done
  if [[ -n "$shared" && "${ALLOW_SHARED_HOLDERS:-0}" != 1 ]]; then
    gate_fail P0 "an address sits on both GOVERNANCE and GUARDIAN (needs the owner's written approval and ALLOW_SHARED_HOLDERS=1)"
  fi
}
count_owners_list() { # comma-separated list -> distinct non-empty lowercased entries, one per line
  printf '%s' "$1" | tr ',' '\n' | sed 's/[[:space:]]//g' | { grep -v '^$' || true; } | tr 'A-F' 'a-f' | sort -u
}

log "mode=$MODE from=$FROM${ONLY:+ only=$ONLY} chain=$EXPECTED_CHAIN_ID"

# ---------------------------------------------------------------- P0
# The preflight is mandatory whenever the run talks to a chain (simulate or confirm), whatever
# --from/--only selects: a resume must re-prove the chain, the genesis and the inputs before it
# sends anything. A dry run only runs it when P0 is selected.
if should P0 || [[ "$MODE" != dry ]]; then
  should P0 || log "P0 preflight (mandatory before a $MODE run that resumes at ${ONLY:-$FROM})"
  need_env DEPLOYER_ADDRESS GOV_OWNERS GOV_THRESHOLD GOV_MIN_DELAY GRD_OWNERS GRD_THRESHOLD GRD_MIN_DELAY
  is_addr "$DEPLOYER_ADDRESS" || gate_fail P0 "DEPLOYER_ADDRESS is malformed"
  check_council GOV $GOV_MIN_THRESHOLD $GOV_MIN_OWNERS $GOV_MIN_DELAY_SECS
  check_council GRD $GRD_MIN_THRESHOLD $GRD_MIN_OWNERS $GRD_MIN_DELAY_SECS
  ((GRD_MIN_DELAY < GOV_MIN_DELAY)) || gate_fail P0 "the GUARDIAN delay must be shorter than the GOVERNANCE delay, or a veto lands too late"
  overlap_check
  if count_owners_list "$GOV_OWNERS,$GRD_OWNERS" | grep -qx "$(lower "$DEPLOYER_ADDRESS")"; then
    gate_fail P0 "the deployer must not hold a governance or guardian seat"
  fi
  for s in DeployGenesisGovernance.s.sol DeployTeamVesting.s.sol DeployDormantLedgers.s.sol CheckDeployedAdmins.s.sol; do
    [[ -f "$CONTRACTS/script/$s" ]] || gate_fail P0 "contracts/script/$s is missing (the genesis contract set, chain#320, must be merged)"
  done
  [[ -x "$REGENESIS" || -f "$REGENESIS" ]] || gate_fail P0 "$REGENESIS is missing"
  if [[ -n "${TEAM_VESTING_FILE:-}" ]]; then
    [[ -f "$TEAM_VESTING_FILE" || -f "$CONTRACTS/$TEAM_VESTING_FILE" ]] || gate_fail P0 "TEAM_VESTING_FILE not found (a path relative to contracts/, under genesis/)"
  fi
  [[ -z "${KEEP_LIST:-}" || -f "$KEEP_LIST" ]] || gate_fail P0 "KEEP_LIST not found"
  if [[ "$MODE" == confirm ]]; then
    [[ -n "$ACCOUNT" ]] || gate_fail P0 "--confirm needs --account (Foundry keystore)"
    need_env RPC_URL EXPECTED_GENESIS_HASH TEAM_VESTING_FILE KEEP_LIST FLEET_RPCS
    if ! is_local_rpc "$RPC_URL" && [[ "${CITRATE_ALLOW_REMOTE:-0}" != 1 ]]; then
      gate_fail P0 "RPC_URL is not loopback; a live broadcast needs CITRATE_ALLOW_REMOTE=1 as well"
    fi
  fi
  if [[ "$MODE" != dry ]]; then
    need_env RPC_URL
    cid=$("$CAST" chain-id --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "RPC $RPC_URL unreachable"
    [[ "$cid" == "$EXPECTED_CHAIN_ID" ]] || gate_fail P0 "RPC chain id $cid, want $EXPECTED_CHAIN_ID"
    if [[ -n "${EXPECTED_GENESIS_HASH:-}" ]]; then
      g0=$("$CAST" block 0 --field hash --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "cannot read block 0 from $RPC_URL"
      [[ "$(lower "$g0")" == "$(lower "$EXPECTED_GENESIS_HASH")" ]] || gate_fail P0 "block 0 is $g0, want $EXPECTED_GENESIS_HASH"
    fi
    if [[ "$FROM" == P0 && -z "$ONLY" ]]; then
      nonce=$("$CAST" nonce "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "cannot read the deployer nonce from $RPC_URL"
      [[ "$nonce" == 0 ]] || gate_fail P0 "deployer nonce is $nonce; a fresh ceremony starts at 0 (resume with --from instead)"
    fi
  fi
  if [[ "$MODE" != dry ]]; then
    # A phase about to write a book must not find one already there: it would be an earlier
    # run's (or a simulation's) output, and later phases would read it as this run's.
    for pb in "P1:$GOV_BOOK" "P3:$VEST_BOOK" "P4:$DORMANT_BOOK"; do
      if should "${pb%%:*}" && [[ -e "${pb#*:}" ]]; then
        gate_fail P0 "${pb#*:} already exists and ${pb%%:*} would write it; move it aside (it is not this ceremony's output) or resume after ${pb%%:*}"
      fi
    done
  fi
  log "P0 preflight PASS (books in $OUT_REL/)"
fi

# ---------------------------------------------------------------- P1
if should P1; then
  export GENESIS_GOVERNANCE_OUT="$GOV_REL"
  export GENESIS_PROFILE=1
  export GOV_PROPOSAL_TTL="${GOV_PROPOSAL_TTL:-$GENESIS_TTL_SECS}" GRD_PROPOSAL_TTL="${GRD_PROPOSAL_TTL:-$GENESIS_TTL_SECS}"
  log "P1 governance → $GOV_BOOK"
  forge_phase P1 DeployGenesisGovernance.s.sol
fi

# The governance addresses every later phase uses come from P1's output, never from a constant.
load_governance() {
  if [[ "$MODE" == dry ]]; then
    export GOVERNANCE='<GovernanceTimelock from governance.json>' GUARDIAN='<GuardianTimelock from governance.json>'
    export GOVERNANCE_TIMELOCK="$GOVERNANCE" GOVERNANCE_MULTISIG='<GovernanceMultisig from governance.json>'
    return
  fi
  [[ -f "$GOV_BOOK" ]] || gate_fail "$1" "$GOV_BOOK missing (run P1 first)"
  GOVERNANCE=$(book_addr "$GOV_BOOK" GovernanceTimelock)
  GUARDIAN=$(book_addr "$GOV_BOOK" GuardianTimelock)
  GOVERNANCE_MULTISIG=$(book_addr "$GOV_BOOK" GovernanceMultisig)
  for a in "$GOVERNANCE" "$GUARDIAN" "$GOVERNANCE_MULTISIG"; do is_addr "$a" || gate_fail "$1" "governance.json is incomplete"; done
  export GOVERNANCE GUARDIAN GOVERNANCE_MULTISIG GOVERNANCE_TIMELOCK="$GOVERNANCE"
  export VALIDATOR_GOVERNANCE="${VALIDATOR_GOVERNANCE:-$GOVERNANCE}"
  log "    GOVERNANCE=$GOVERNANCE GUARDIAN=$GUARDIAN"
}

# ---------------------------------------------------------------- P2
if should P2; then
  load_governance P2
  rargs=(--reroll --with-aa)
  # regenesis.sh takes --account only; the keystore password comes from forge's own prompt.
  if [[ "$MODE" == confirm ]]; then rargs+=(--broadcast --account "$ACCOUNT"); fi
  log "P2 contract stack via regenesis.sh"
  if [[ "$MODE" == dry ]]; then
    describe_cmd RPC_URL='$RPC_URL' DEPLOYER_ADDRESS='$DEPLOYER_ADDRESS' bash "$REGENESIS" "${rargs[@]}"
  else
    RPC_URL="$RPC_URL" bash "$REGENESIS" "${rargs[@]}" || step_fail P2 regenesis.sh
  fi
fi

# ---------------------------------------------------------------- P3
if should P3; then
  if [[ -z "${TEAM_VESTING_FILE:-}" ]]; then
    [[ "$MODE" == confirm ]] && gate_fail P3 "TEAM_VESTING_FILE is required"
    log "P3 vesting: TEAM_VESTING_FILE unset (OPEN: owner amounts); planned only"
  fi
  export TEAM_VESTING_FILE="${TEAM_VESTING_FILE:-genesis/team-vesting.input.json}" TEAM_VESTING_OUT="$VEST_REL"
  log "P3 team vesting → $VEST_BOOK"
  forge_phase P3 DeployTeamVesting.s.sol
fi

# ---------------------------------------------------------------- P4
if should P4; then
  load_governance P4
  export DORMANT_LEDGERS_OUT="$DORMANT_REL" GENESIS_GOVERNANCE_BOOK="$GOV_REL"
  [[ "$MODE" == dry ]] || need_env PATRONAGE_KYC_REGISTRY PATRONAGE_MEMBERSHIP
  log "P4 dormant ledgers → $DORMANT_BOOK"
  forge_phase P4 DeployDormantLedgers.s.sol
fi

# ---------------------------------------------------------------- P5
if should P5; then
  extras="$GOV_REL"
  if [[ -f "$VEST_BOOK" || "$MODE" == dry ]]; then extras+=",$VEST_REL"; fi
  if [[ -f "$DORMANT_BOOK" || "$MODE" == dry ]]; then extras+=",$DORMANT_REL"; fi
  log "P5 admin handover gate (FACTORY-ADMIN 0, DEPLOYER-ADMIN 0)"
  cmd=("$FORGE" script script/CheckDeployedAdmins.s.sol --rpc-url "${RPC_URL:-\$RPC_URL}")
  if [[ "$MODE" == dry ]]; then
    describe_cmd "(cd contracts && ADDRESS_BOOK=$ADDRESS_BOOK EXTRA_ADDRESS_BOOKS=$extras REQUIRE_ALL_CODE=true" "${cmd[@]}" ")"
  else
    report=$(cd "$CONTRACTS" && ADDRESS_BOOK="$ADDRESS_BOOK" EXTRA_ADDRESS_BOOKS="$extras" REQUIRE_ALL_CODE=true "${cmd[@]}" 2>&1) || {
      printf '%s\n' "$report" | tail -40
      gate_fail P5 "CheckDeployedAdmins failed to run"
    }
    printf '%s\n' "$report" | { grep -E 'ADMIN' || true; } | tail -20
    printf '%s\n' "$report" | grep -qE 'FACTORY-ADMIN failures:[[:space:]]*0$' || gate_fail P5 "FACTORY-ADMIN is not 0"
    printf '%s\n' "$report" | grep -qE 'DEPLOYER-ADMIN failures:[[:space:]]*0$' || gate_fail P5 "DEPLOYER-ADMIN is not 0: the deployer still holds a role"
    log "P5 PASS: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0"
  fi
fi

# ---------------------------------------------------------------- P6
if should P6; then
  if [[ -z "${KEEP_LIST:-}" ]]; then
    [[ "$MODE" == confirm ]] && gate_fail P6 "KEEP_LIST is required (the rehearsal-1 freeze)"
    log "P6 keep: KEEP_LIST unset; skipped (it exists from rehearsal 1 on)"
  elif [[ "$MODE" == dry ]]; then
    ADDRESS_BOOK="$ADDRESS_BOOK" bash "$HERE/keep_check.sh" verify --dry-run "$KEEP_LIST" || gate_fail P6 "KEEP list malformed"
  else
    # Only broadcasts recorded on this chain since its block 0 are evidence for P6.
    g0ts=$("$CAST" block 0 --field timestamp --rpc-url "$RPC_URL" 2>/dev/null) || g0ts=""
    g0ts=$("$PY" -c 'import sys; print(int(sys.argv[1], 0))' "$g0ts" 2>/dev/null) ||
      gate_fail P6 "cannot read the block-0 timestamp to scope the broadcast evidence"
    RPC="$RPC_URL" ADDRESS_BOOK="$ADDRESS_BOOK" BROADCAST_DIR="$CONTRACTS/broadcast" BROADCAST_SINCE="$g0ts" \
      bash "$HERE/keep_check.sh" verify "$KEEP_LIST" || gate_fail P6 "keep_check failed"
  fi
fi

# ---------------------------------------------------------------- P7
if should P7; then
  if [[ -z "${FLEET_RPCS:-}" ]]; then
    [[ "$MODE" == confirm ]] && gate_fail P7 "FLEET_RPCS is required"
    log "P7 fleet: FLEET_RPCS unset; skipped"
  else
    dryflag=()
    if [[ "$MODE" == dry ]]; then dryflag=(--dry-run); fi
    FLEET_RPCS="$FLEET_RPCS" EXPECTED_CHAIN_ID="$EXPECTED_CHAIN_ID" bash "$HERE/fleet_agree.sh" "${dryflag[@]}" ||
      gate_fail P7 "the fleet does not agree on genesis and tip"
  fi
fi

log "done (mode=$MODE)"
