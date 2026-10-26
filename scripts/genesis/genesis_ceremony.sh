#!/usr/bin/env bash
# genesis_ceremony.sh: the genesis contract ceremony, phase by phase, each behind a gate.
#
# Runs after the new chain is producing (runbook §6). Order:
#   P0  preflight      inputs present, governance values at the genesis floors, tools,
#                      required contract scripts present; with an RPC: chain id, block-0
#                      hash and timestamp, deployer nonce 0; then the run manifest
#                      (written on a fresh run, re-verified on every resume)
#   P1  governance     DeployGenesisGovernance: GOVERNANCE + GUARDIAN timelocks, each
#                      fronted by an m-of-n MultisigProposer; deployer renounces in-run
#   P2  stack          scripts/ops/regenesis.sh --reroll --with-aa --genesis-membership
#                      (registries, VR, AA, then membership through chain#331's
#                      DeployGenesisMembership, never the r1005 DeployCoreMembership), with
#                      GOVERNANCE/GUARDIAN taken from P1's output; its
#                      address book comes from emit-address-table.sh in fresh-genesis mode
#                      (this run's deployer and broadcasts only) and, on --confirm, is
#                      re-derived, checked against the broadcasts and recorded (C8)
#   P3  vesting        DeployTeamVesting from the owner's TEAM_VESTING_FILE
#   P4  dormant        DeployDormantLedgers (FederatedRoundLedger, PatronageLedger)
#   P5  admins         CheckDeployedAdmins over ONE merged book (the book + the P1/P3/P4
#                      outputs' contracts), every book bound to the run manifest's deployer:
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
# Signing: --account NAME (Foundry keystore) and optionally --password-file PATH, which every
# broadcasting phase gets, P2's regenesis.sh included (as the path; neither script reads or
# prints the file). A raw key (--private-key, or PRIVATE_KEY/DEPLOYER_PRIVATE_KEY in the
# environment) and a password on the command line (--password) are refused.
#
# Inputs (env). Values marked OPEN are owner decisions recorded in the runbook §2:
#   RPC_URL, DEPLOYER_ADDRESS, EXPECTED_CHAIN_ID (40204), EXPECTED_GENESIS_HASH (from the cut)
#   GOV_OWNERS, GOV_THRESHOLD, GOV_MIN_DELAY, GOV_PROPOSAL_TTL      (holders OPEN)
#   GRD_OWNERS, GRD_THRESHOLD, GRD_MIN_DELAY, GRD_PROPOSAL_TTL      (holders OPEN)
#   TEAM_VESTING_FILE (OPEN amounts/schedule; must sit under contracts/genesis/)
#   PATRONAGE_KYC_REGISTRY, PATRONAGE_MEMBERSHIP, plus regenesis.sh's env
#   MEMBERSHIP_GRANTOR (the treasury-signer address that places membership grants; P2)
#   KEEP_LIST (the rehearsal-1 freeze) · FLEET_RPCS (comma-separated)
#   GENESIS_OUT_DIR (contracts/genesis) · ADDRESS_BOOK (contracts/addresses/40204.json)
#
# Run manifest: GENESIS_OUT_DIR/ceremony-run.json. A fresh --simulate/--confirm run (no
# --from/--only) writes it at the end of P0: run id, mode, chain id, block-0 hash and
# timestamp, the deployer address (--sender; on --confirm forge only signs for it with the
# --account keystore, so the two are the same account) and the keystore account name. Every
# resume re-reads it and refuses to go on unless the chain, block 0, deployer, account and
# mode all match this invocation; a missing or malformed manifest is a gate failure, and a
# fresh run refuses to start over an existing one. P5 checks the manifest's deployer and P6
# scopes the broadcast evidence to the manifest's block-0 timestamp, so neither trusts a
# value that only a (possibly stale) book or the environment supplies.
#
# Invariants (every gate's pass implies them; runbook §4.1 maps each to its code and test):
#   C1 run binding: every --simulate/--confirm invocation re-proves chain id, block-0 hash and
#      timestamp, deployer, account and mode against the run manifest (P0).
#   C2 governance identity: the four governance contracts every later phase uses are the ones
#      recorded in the manifest the first time they were verified on chain; a governance.json
#      that names others fails (load_governance + manifest_bind).
#   C3 governance floors on chain: at P0 (once recorded), after P1 (--confirm), before P2/P4
#      use it (--confirm) and at every gate P5/P6/P7, each council is read from the chain:
#      the multisig fronts its timelock and is its proposer, its owners and threshold are the
#      P0-validated inputs (on 40204 also >= the genesis floors, a strict majority), the
#      timelock delay is the input (>= floor), the deployer holds no seat or timelock role,
#      and the GUARDIAN delay is shorter than the GOVERNANCE delay (check_governance_onchain).
#   C4 no authority override: VALIDATOR_GOVERNANCE and VALIDATOR_SLASHER are always P1's
#      GOVERNANCE; a different preset value (or a conflicting GOVERNANCE, GUARDIAN,
#      GOVERNANCE_TIMELOCK or GOVERNANCE_MULTISIG) fails the phase before anything is sent,
#      and P5 reads ValidatorRegistry.governance()/slasher() (= GOVERNANCE) and
#      pendingGovernance() (= 0) from the chain.
#   C5 handover over the exact outputs: P5 merges only books bound to the manifest (deployer,
#      governance contracts, and the vesting/dormant contract maps). P3 and P4 record their
#      book's contract map (teamVesting, dormantLedgers) when they write it, after checking it
#      names the run's deployer (C9) and, on --confirm, that every contract in it is a
#      deployment in this run's broadcasts of that step (P4's governance entries must be the
#      run's recorded governance). A --confirm step that writes no book, or a book that fails
#      these checks, fails the step; --confirm P5 refuses a book its step did not record.
#   C6 no redeploy over the exact KEEP list: the KEEP list's sha256 is recorded at P0 (or at
#      first use) and P6 refuses another; keep_check matches each row's contract_name to the
#      broadcast deployments at its pinned address.
#   C7 fleet on this run's block 0 (P7).
#   C8 stack book = generator output: P2 runs the generator (scripts/ops/emit-address-table.sh,
#      via regenesis.sh) with EMIT_FRESH_GENESIS=1, EMIT_DEPLOYER = the manifest's deployer,
#      EMIT_BROADCAST_SINCE = its block-0 timestamp and EMIT_OUTPUT = ADDRESS_BOOK; a different
#      preset of any of them (or of DEPLOYER) fails P2 before anything is sent. After a
#      --confirm P2 the ceremony re-runs the generator into a scratch file and requires the
#      same book byte for byte, requires the book's deployer, ValidatorRegistry and membership
#      entries (SBT, MemberBond, vault implementation, vault proxy, root aliases) to be this
#      run's broadcasts (membership: DeployGenesisMembership's), and records the book in the
#      manifest (stackBook). P5 and P6 read only
#      that book on --confirm (and check it whenever it is recorded).
#   C9 one deployer: CEREMONY_DEPLOYER_ADDRESS (which the deploy scripts prefer), DEPLOYER and
#      EMIT_DEPLOYER, when preset, must be DEPLOYER_ADDRESS byte for byte (an empty value, another
#      address, case or spelling fails P0 before anything is sent); every phase then runs with
#      CEREMONY_DEPLOYER_ADDRESS = DEPLOYER_ADDRESS. After a --confirm P2, the deployer-derived
#      fee recipients (X402Facilitator.treasury, ModelMarketplace.treasuryAddress,
#      ComputeMarketplace.treasury) of the contracts in the verified book are read from the
#      chain and must be the book's deployer.
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
    # Never echo the value: it is the password.
    --password | --password=*) die "a keystore password on the command line is refused; pass --password-file PATH" 1 ;;
    --private-key | --private-key=*) die "raw private keys are refused; sign with --account (Foundry keystore)" 1 ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
      exit 1
      ;;
    *) die "unknown argument $1" 1 ;;
  esac
done
refuse_raw_keys
# The keystore password reaches forge (P1/P3/P4) and regenesis.sh (P2) only as this path. The
# value is not echoed on refusal: a caller that passed the password itself in its place must
# not see it in the log.
if [[ -n "$PASSWORD_FILE" ]]; then
  [[ -n "$ACCOUNT" ]] || die "--password-file needs --account (it unlocks that keystore)" 1
  [[ -f "$PASSWORD_FILE" && -r "$PASSWORD_FILE" ]] || die "--password-file must name a readable file (the path to the keystore password, not the password)" 1
fi

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
MEMB_REL="$OUT_REL/membership.json"
GOV_BOOK="$CONTRACTS/$GOV_REL"
VEST_BOOK="$CONTRACTS/$VEST_REL"
DORMANT_BOOK="$CONTRACTS/$DORMANT_REL"
MEMB_BOOK="$CONTRACTS/$MEMB_REL"
# G9: the genesis membership deploy (chain#331). P2 runs it through regenesis.sh
# --genesis-membership, and the generator reads the membership from its broadcast.
GENESIS_MEMBERSHIP_SCRIPT=DeployGenesisMembership.s.sol
RUN_MANIFEST="$OUT/ceremony-run.json"
EMITTER="${EMITTER:-$REPO_ROOT/scripts/ops/emit-address-table.sh}"
book_abs=$(norm_path "$ADDRESS_BOOK") || die "cannot resolve ADDRESS_BOOK $ADDRESS_BOOK" 1

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
  err "fix it, then resume: $0 --$MODE --from $1 ${ACCOUNT:+--account $ACCOUNT}${PASSWORD_FILE:+ --password-file $PASSWORD_FILE}"
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

# manifest_write <path> <run_id> <mode> <chain_id> <genesis_hash> <g0_ts> <deployer> <account>
# Atomic (temp file + rename), refusing to replace an existing manifest.
manifest_write() {
  "$PY" - "$@" <<'PY'
import json, os, sys
path, run_id, mode, cid, g0, ts, dep, acct = sys.argv[1:9]
if os.path.exists(path):
    sys.exit(f"{path} already exists")
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump({"version": 1, "runId": run_id, "mode": mode, "chainId": int(cid),
               "genesisHash": g0.lower(), "block0Timestamp": int(ts),
               "deployer": dep.lower(), "account": acct}, f, indent=2, sort_keys=True)
    f.write("\n")
os.link(tmp, path)  # fails if the path appeared meanwhile; never overwrites
os.unlink(tmp)
PY
}

# manifest_check <path> <mode> <chain_id> <genesis_hash> <g0_ts> <deployer> <account>
# Prints "runId<TAB>deployer<TAB>block0Timestamp" when the manifest is well formed and names
# this run; exits non-zero with the reason otherwise.
manifest_check() {
  "$PY" - "$@" <<'PY'
import json, re, sys
path, mode, cid, g0, ts, dep, acct = sys.argv[1:8]
try:
    with open(path) as f:
        m = json.load(f)
except FileNotFoundError:
    sys.exit(f"{path} is missing: a resume needs the manifest its fresh run wrote at P0")
except (OSError, ValueError) as e:
    sys.exit(f"cannot read {path}: {e}")
if not isinstance(m, dict):
    sys.exit(f"{path} is not a JSON object")
def field(k, typ):
    v = m.get(k)
    if not isinstance(v, typ) or isinstance(v, bool):
        sys.exit(f"{path} .{k} is missing or malformed")
    return v
rid = field("runId", str)
want = {
    "mode": (field("mode", str), mode),
    "chainId": (field("chainId", int), int(cid)),
    "genesisHash": (field("genesisHash", str).lower(), g0.lower()),
    "block0Timestamp": (field("block0Timestamp", int), int(ts)),
    "deployer": (field("deployer", str).lower(), dep.lower()),
    "account": (field("account", str), acct),
}
if not re.fullmatch(r"0x[0-9a-f]{40}", want["deployer"][0]) or not rid:
    sys.exit(f"{path} is malformed")
bad = [f"{k} {have!r} (this run: {cur!r})" for k, (have, cur) in want.items() if have != cur]
if bad:
    sys.exit(f"{path} (run {rid}) is not this run's: " + "; ".join(bad))
print(f"{rid}\t{want['deployer'][0]}\t{want['block0Timestamp'][0]}")
PY
}

# manifest_bind <check|bind> <path> <key> <json value>: the run manifest's record of a value
# this run depends on (governance contracts, an output book's contracts, the KEEP list hash).
# check: if the manifest already records <key>, it must equal <value>. bind: the same, and if
# it does not record it yet, record it now (atomic rewrite).
manifest_bind() {
  "$PY" - "$@" <<'PY'
import json, os, sys
mode, path, key, raw = sys.argv[1:5]
val = json.loads(raw)
try:
    with open(path) as f:
        m = json.load(f)
except (OSError, ValueError) as e:
    sys.exit(f"cannot read the run manifest {path}: {e}")
if not isinstance(m, dict):
    sys.exit(f"{path} is not a JSON object")
if key in m:
    if m[key] != val:
        sys.exit(f"{path} records {key} = {json.dumps(m[key], sort_keys=True)}; this run now has {json.dumps(val, sort_keys=True)}")
    sys.exit(0)
if mode != "bind":
    sys.exit(0)
m[key] = val
tmp = path + ".bind.tmp"
with open(tmp, "w") as f:
    json.dump(m, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
PY
}
manifest_has() { # path key
  "$PY" -c 'import json,sys; sys.exit(0 if sys.argv[2] in json.load(open(sys.argv[1])) else 1)' "$1" "$2" 2>/dev/null
}
# book_contracts_json <book>: its .contracts as compact JSON with lowercased addresses.
book_contracts_json() {
  "$PY" -c '
import json, re, sys
c = json.load(open(sys.argv[1])).get("contracts")
if not isinstance(c, dict) or not c or not all(isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", v) for v in c.values()):
    sys.exit(1)
print(json.dumps({k: v.lower() for k, v in c.items()}, sort_keys=True, separators=(",", ":")))' "$1" 2>/dev/null
}

# cast_read <addr> <sig> [args...]: the first token of `cast call` (cast may append a
# "[1.728e5]" style annotation), or failure.
cast_read() {
  local out
  out=$("$CAST" call "$@" --rpc-url "$RPC_URL" 2>/dev/null) || return 1
  out="${out%% *}"
  [[ -n "$out" ]] || return 1
  printf '%s\n' "$out"
}
PROPOSER_ROLE=0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1 # keccak256("PROPOSER_ROLE")
DEFAULT_ADMIN_ROLE=0x0000000000000000000000000000000000000000000000000000000000000000

# council_onchain <phase> <P> <timelock> <multisig> <min_threshold> <min_owners> <min_delay>
# C3 for one council: what the chain says, against the P0-validated inputs and the floors.
# Prints the timelock delay.
council_onchain() {
  local ph="$1" p="$2" tl="$3" ms="$4" ov tv dv d t mtl raw got want n a dep
  ov="${p}_OWNERS" tv="${p}_THRESHOLD" dv="${p}_MIN_DELAY"
  dep=$(lower "${RUN_DEPLOYER:-$DEPLOYER_ADDRESS}")
  d=$(cast_read "$tl" "getMinDelay()(uint256)") && [[ "$d" =~ ^[0-9]+$ ]] || gate_fail "$ph" "$p: cannot read getMinDelay() at $tl"
  mtl=$(cast_read "$ms" "timelock()(address)") && is_addr "$mtl" || gate_fail "$ph" "$p: cannot read timelock() at $ms"
  [[ "$(lower "$mtl")" == "$(lower "$tl")" ]] || gate_fail "$ph" "$p: multisig $ms fronts $mtl, not its timelock $tl"
  t=$(cast_read "$ms" "threshold()(uint256)") && [[ "$t" =~ ^[0-9]+$ ]] || gate_fail "$ph" "$p: cannot read threshold() at $ms"
  raw=$("$CAST" call "$ms" "owners()(address[])" --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail "$ph" "$p: cannot read owners() at $ms"
  got=$(printf '%s' "$raw" | tr -d '[] ' | tr ',' '\n' | { grep -v '^$' || true; } | tr 'A-F' 'a-f' | sort -u)
  for a in $got; do is_addr "$a" || gate_fail "$ph" "$p: owners() at $ms returned a malformed address"; done
  n=$(printf '%s' "$got" | grep -c . || true)
  want=$(count_owners_list "${!ov}")
  [[ "$got" == "$want" ]] || gate_fail "$ph" "$p: the multisig's owners on chain are not the ${p}_OWNERS this run validated"
  [[ "$t" == "${!tv}" ]] || gate_fail "$ph" "$p: threshold on chain is $t, the validated input is ${!tv}"
  [[ "$d" == "${!dv}" ]] || gate_fail "$ph" "$p: timelock delay on chain is ${d}s, the validated input is ${!dv}s"
  if [[ "$EXPECTED_CHAIN_ID" == 40204 ]]; then
    ((n >= $6)) || gate_fail "$ph" "$p: $n owners on chain; the genesis floor is $6"
    ((t >= $5)) || gate_fail "$ph" "$p: threshold $t on chain is below the genesis floor $5"
    ((d >= $7)) || gate_fail "$ph" "$p: delay ${d}s on chain is below the genesis floor ${7}s"
  fi
  ((t <= n && t * 2 > n)) || gate_fail "$ph" "$p: threshold $t of $n owners on chain is not a majority"
  ! grep -qxF -- "$dep" <<<"$got" || gate_fail "$ph" "$p: the deployer holds an owner seat on chain"
  [[ "$(cast_read "$tl" "hasRole(bytes32,address)(bool)" "$PROPOSER_ROLE" "$ms")" == true ]] ||
    gate_fail "$ph" "$p: the multisig $ms is not the proposer of $tl on chain"
  for r in "$PROPOSER_ROLE" "$DEFAULT_ADMIN_ROLE"; do
    [[ "$(cast_read "$tl" "hasRole(bytes32,address)(bool)" "$r" "$dep")" == false ]] ||
      gate_fail "$ph" "$p: the deployer still holds (or cannot be shown not to hold) role $r on $tl"
  done
  log "    $p on chain: $t-of-$n, delay ${d}s, multisig fronts and proposes for $tl" >&2
  printf '%s\n' "$d"
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

# stack_book_json <book>: the part of the address book the gates depend on (deployer,
# contracts, aaStack and the membership root aliases), compact, lowercased, sorted.
stack_book_json() {
  "$PY" - "$1" <<'PY' 2>/dev/null
import json, re, sys
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
b = json.load(open(sys.argv[1]))
dep = b.get("deployer")
assert isinstance(dep, str) and ADDR.fullmatch(dep)
out = {"deployer": dep.lower()}
for sec in ("contracts", "aaStack"):
    d = b.get(sec, {})
    assert isinstance(d, dict) and all(isinstance(v, str) and ADDR.fullmatch(v) for v in d.values())
    out[sec] = {k: v.lower() for k, v in d.items()}
for k in ("CitrateMemberSBT", "MembershipStakeVault"):
    if k in b:
        assert isinstance(b[k], str) and ADDR.fullmatch(b[k])
        out["root." + k] = b[k].lower()
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
PY
}

# stack_book_bound <phase> <require 0|1>: C8 for a reader of ADDRESS_BOOK. The book must be the
# one P2 recorded in the run manifest; with require=1 a manifest without one fails.
stack_book_bound() {
  local ph="$1" sb why
  if ! manifest_has "$RUN_MANIFEST" stackBook; then
    [[ "$2" == 1 ]] && gate_fail "$ph" "the run manifest records no stack book: run P2 with --confirm in this run first"
    log "$ph note: no stack book recorded in this run's manifest; $ADDRESS_BOOK is not bound to a P2 run"
    return 0
  fi
  sb=$(stack_book_json "$ADDRESS_BOOK") || gate_fail "$ph" "$ADDRESS_BOOK is not a well-formed address book"
  why=$(manifest_bind check "$RUN_MANIFEST" stackBook "$sb" 2>&1) ||
    gate_fail "$ph" "$ADDRESS_BOOK is not the stack book this run's P2 generated: $why"
  log "$ph address book is the stack book P2 generated and recorded"
}

# verify_stack_book: C8 after a --confirm P2 (see the header).
verify_stack_book() {
  local check why sb
  [[ -f "$book_abs" ]] || gate_fail P2 "$ADDRESS_BOOK missing after regenesis.sh: the generator did not write it"
  check="$OUT/stack-book.check.json"
  rm -f "$check"
  EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$RUN_DEPLOYER" EMIT_BROADCAST_SINCE="$RUN_G0TS" EMIT_OUTPUT="$check" \
    EMIT_MEMBERSHIP_SCRIPT="$GENESIS_MEMBERSHIP_SCRIPT" bash "$EMITTER" >"$OUT/stack-book.check.log" 2>&1 ||
    gate_fail P2 "re-running the generator failed (see $OUT/stack-book.check.log)"
  why=$("$PY" - "$book_abs" "$check" "$RUN_DEPLOYER" "$CONTRACTS/broadcast" "$EXPECTED_CHAIN_ID" "$RUN_G0TS" "$GENESIS_MEMBERSHIP_SCRIPT" <<'PY' 2>&1
import json, sys
book_p, check_p, dep, bdir, cid, since, mscript = sys.argv[1:8]
since = int(since)
book, check = json.load(open(book_p)), json.load(open(check_p))
if book != check:
    diff = sorted(k for k in set(book) | set(check) if book.get(k) != check.get(k))
    sys.exit(f"the book differs from what the generator emits for this run (keys: {', '.join(diff)})")
if str(book.get("deployer", "")).lower() != dep:
    sys.exit(f"the book names deployer {book.get('deployer')!r}, not this run's {dep}")
def deployed(script, with_names):
    p = f"{bdir}/{script}/{cid}/run-latest.json"
    try:
        run = json.load(open(p))
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read this run's {script} broadcast: {e}")
    ts = run.get("timestamp")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        sys.exit(f"{p} has no timestamp")
    if (ts / 1000 if ts > 10**12 else ts) < since:
        sys.exit(f"{p} was recorded before this chain's block 0")
    got = {}
    for tx in run.get("transactions") or []:
        if tx.get("transactionType") in ("CREATE", "CREATE2") and tx.get("contractName") in with_names and tx.get("contractAddress"):
            got[tx["contractName"]] = tx["contractAddress"].lower()
    return got
c = {k: v.lower() for k, v in book.get("contracts", {}).items()}
vr = deployed("DeployValidatorRegistry.s.sol", {"ValidatorRegistry"})
m = deployed(mscript, {"CitrateMemberSBT", "MemberBond", "MembershipStakeVault", "ERC1967Proxy"})
want = {
    "ValidatorRegistry": vr.get("ValidatorRegistry"),
    "CitrateMemberSBT": m.get("CitrateMemberSBT"),
    "MemberBond": m.get("MemberBond"),
    "MembershipStakeVaultImpl": m.get("MembershipStakeVault"),
    "MembershipStakeVault": m.get("ERC1967Proxy"),
}
for k, v in want.items():
    if not v:
        sys.exit(f"this run's broadcasts deployed no {k}")
    if c.get(k) != v:
        sys.exit(f"the book's {k} is {c.get(k)}, this run deployed {v}")
for k in ("CitrateMemberSBT", "MembershipStakeVault"):
    if str(book.get(k, "")).lower() != want[k]:
        sys.exit(f"the book's root alias {k} is {book.get(k)!r}, this run deployed {want[k]}")
print(f"ValidatorRegistry {want['ValidatorRegistry']}, CitrateMemberSBT {want['CitrateMemberSBT']}, MembershipStakeVault {want['MembershipStakeVault']} (impl {want['MembershipStakeVaultImpl']})")
PY
  ) || gate_fail P2 "stack book: $why"
  log "P2 stack book = generator output for this run: $why"
  sb=$(stack_book_json "$book_abs") || gate_fail P2 "$ADDRESS_BOOK is not a well-formed address book"
  check_fee_recipients
  why=$(manifest_bind bind "$RUN_MANIFEST" stackBook "$sb" 2>&1) || gate_fail P2 "cannot record the stack book: $why"
  rm -f "$check"
}

# C9: the fee recipients DeployAll derives from the deployer (treasury constructor arguments)
# are read from the chain for every such contract the verified book lists, and must be the
# book's deployer (= the run's, checked above), never a value only the environment supplied.
FEE_RECIPIENT_GETTERS=("X402Facilitator:treasury" "ModelMarketplace:treasuryAddress" "ComputeMarketplace:treasury")
check_fee_recipients() {
  local e name fn a got seen=""
  for e in "${FEE_RECIPIENT_GETTERS[@]}"; do
    name="${e%%:*}" fn="${e#*:}"
    a=$(book_addr "$book_abs" "$name") || continue
    is_addr "$a" || gate_fail P2 "the book's $name ($a) is not an address"
    got=$(cast_read "$a" "$fn()(address)") && is_addr "$got" || gate_fail P2 "cannot read $name.$fn() at $a"
    [[ "$(lower "$got")" == "$RUN_DEPLOYER" ]] ||
      gate_fail P2 "$name.$fn() is $(lower "$got"), not the book's deployer $RUN_DEPLOYER"
    seen+="${seen:+, }$name"
  done
  if [[ -n "$seen" ]]; then
    log "P2 fee recipients are the run's deployer: $seen"
  else
    log "P2 note: the book lists no contract with a deployer-derived fee recipient"
  fi
}

# record_output_book <phase> <key> <book> <script> [governance json]: C5 + C9 for the book a
# P3/P4 step writes, at the step that writes it. The book must name the run manifest's
# deployer and list well-formed contracts; on --confirm it must exist, and every contract in
# it must be a CREATE/CREATE2 in this run's <script> broadcasts (run-*.json recorded since
# this chain's block 0), except the governance contracts P4 records by reference, which must
# be this run's recorded governance (as must the book's "governance" field). The contract map
# is then recorded in the run manifest under <key>; --confirm P5 sweeps only what was
# recorded there. A --simulate step broadcasts nothing, so there the broadcast check is
# skipped and a missing book is only noted.
record_output_book() {
  local ph="$1" key="$2" book="$3" script="$4" gov="${5:-}" why rec cj
  if [[ ! -f "$book" ]]; then
    [[ "$MODE" == confirm ]] && gate_fail "$ph" "$book missing after ${script%.s.sol}: the step wrote no book, so nothing it deployed can be swept"
    log "$ph note: $book absent after a simulation; nothing recorded"
    return 0
  fi
  is_addr "${RUN_DEPLOYER:-}" && [[ "${RUN_G0TS:-}" =~ ^[0-9]+$ ]] || gate_fail "$ph" "no run deployer or block-0 timestamp (the P0 run manifest did not load)"
  rec=$("$PY" - "$book" "$RUN_DEPLOYER" "$CONTRACTS/broadcast/$script/$EXPECTED_CHAIN_ID" "$RUN_G0TS" "$MODE" "$gov" "$script" <<'PY' 2>&1
import glob, json, re, sys
book_p, dep, bdir, since, mode, gov, script = sys.argv[1:8]
since = int(since)
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
try:
    with open(book_p) as f:
        book = json.load(f)
except (OSError, ValueError) as e:
    sys.exit(f"cannot read {book_p}: {e}")
if not isinstance(book, dict):
    sys.exit(f"{book_p} is not a JSON object")
bdep = book.get("deployer")
if not isinstance(bdep, str) or not ADDR.fullmatch(bdep) or bdep.lower() != dep:
    sys.exit(f"{book_p} names deployer {str(bdep).lower()}, not this run's {dep}")
c = book.get("contracts")
if not isinstance(c, dict) or not c:
    sys.exit(f"{book_p} has no contracts")
for name, a in c.items():
    if not isinstance(a, str) or not ADDR.fullmatch(a) or int(a, 16) == 0:
        sys.exit(f"{book_p} .contracts.{name} is not an address")
refs = json.loads(gov) if gov else {}
for name, want in refs.items():
    if name in c and c[name].lower() != want:
        sys.exit(f"{book_p}: {name} is {c[name].lower()}, this run's is {want}")
if refs and "governance" in book and str(book["governance"]).lower() != refs.get("GovernanceTimelock"):
    sys.exit(f"{book_p}: governance is {str(book['governance']).lower()}, this run's is {refs.get('GovernanceTimelock')}")
if mode != "confirm":
    print(f"{len(c)} contract(s), deployer {dep}; a simulation has no broadcast to check")
    sys.exit(0)
created, runs = set(), 0
for p in sorted(glob.glob(f"{bdir}/run-*.json")):
    try:
        with open(p) as f:
            run = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read {p}: {e}")
    ts = run.get("timestamp") if isinstance(run, dict) else None
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        sys.exit(f"{p} has no timestamp")
    if (ts / 1000 if ts > 10**12 else ts) < since:
        continue
    runs += 1
    for tx in run.get("transactions") or []:
        if tx.get("transactionType") in ("CREATE", "CREATE2") and isinstance(tx.get("contractAddress"), str):
            created.add(tx["contractAddress"].lower())
if not runs:
    sys.exit(f"no {script} broadcast since this chain's block 0 in {bdir}")
for name, a in sorted(c.items()):
    if name not in refs and a.lower() not in created:
        sys.exit(f"{book_p}: {name} {a.lower()} is not a deployment in this run's {script} broadcasts")
print(f"{len(c)} contract(s), deployer {dep}, each deployed by this run's {script} broadcasts" + (" or this run's governance" if refs else ""))
PY
  ) || gate_fail "$ph" "$rec"
  cj=$(book_contracts_json "$book") || gate_fail "$ph" "$book has no well-formed contracts"
  why=$(manifest_bind bind "$RUN_MANIFEST" "$key" "$cj" 2>&1) || gate_fail "$ph" "cannot record $book: $why"
  log "$ph $(basename "$book") recorded in the run manifest ($key): $rec"
}

log "mode=$MODE from=$FROM${ONLY:+ only=$ONLY} chain=$EXPECTED_CHAIN_ID"

# The governance addresses every later phase uses come from P1's output, never from a constant.
# load_governance <phase> <onchain 0|1>: read governance.json; require it to be the governance
# the manifest recorded (C2); with onchain=1 run check_governance_onchain (C3) and record it
# if this is the first verified load; export the addresses, and set every authority input the
# stack scripts read to GOVERNANCE, refusing a different preset value (C4).
load_governance() {
  if [[ "$MODE" == dry ]]; then
    export GOVERNANCE='<GovernanceTimelock from governance.json>' GUARDIAN='<GuardianTimelock from governance.json>'
    export GOVERNANCE_TIMELOCK="$GOVERNANCE" GOVERNANCE_MULTISIG='<GovernanceMultisig from governance.json>'
    export VALIDATOR_GOVERNANCE="$GOVERNANCE" VALIDATOR_SLASHER="$GOVERNANCE"
    return
  fi
  local ph="$1" a v want gov_json why pre=()
  # Preset values, read before this function assigns any of them.
  for v in VALIDATOR_GOVERNANCE VALIDATOR_SLASHER GOVERNANCE GUARDIAN GOVERNANCE_TIMELOCK GOVERNANCE_MULTISIG GUARDIAN_MULTISIG; do
    pre+=("$v=${!v:-}")
  done
  [[ -f "$GOV_BOOK" ]] || gate_fail "$ph" "$GOV_BOOK missing (run P1 first)"
  GOVERNANCE=$(book_addr "$GOV_BOOK" GovernanceTimelock) || gate_fail "$ph" "governance.json has no GovernanceTimelock"
  GUARDIAN=$(book_addr "$GOV_BOOK" GuardianTimelock) || gate_fail "$ph" "governance.json has no GuardianTimelock"
  GOVERNANCE_MULTISIG=$(book_addr "$GOV_BOOK" GovernanceMultisig) || gate_fail "$ph" "governance.json has no GovernanceMultisig"
  GUARDIAN_MULTISIG=$(book_addr "$GOV_BOOK" GuardianMultisig) || gate_fail "$ph" "governance.json has no GuardianMultisig"
  for a in "$GOVERNANCE" "$GUARDIAN" "$GOVERNANCE_MULTISIG" "$GUARDIAN_MULTISIG"; do is_addr "$a" || gate_fail "$ph" "governance.json is incomplete"; done
  # C4: an authority input left in the environment (a stale EOA from an earlier reroll) must
  # never override the council this run deployed.
  for v in "${pre[@]}"; do
    a="${v#*=}"
    case "${v%%=*}" in
      GUARDIAN) want="$GUARDIAN" ;;
      GOVERNANCE_MULTISIG) want="$GOVERNANCE_MULTISIG" ;;
      GUARDIAN_MULTISIG) want="$GUARDIAN_MULTISIG" ;;
      *) want="$GOVERNANCE" ;;
    esac
    if [[ -n "$a" && "$(lower "$a")" != "$(lower "$want")" ]]; then
      gate_fail "$ph" "${v%%=*} is set to $a, but this run's governance is $want (governance.json); unset it: the ceremony sets it from P1's output"
    fi
  done
  gov_json=$(printf '{"GovernanceTimelock":"%s","GovernanceMultisig":"%s","GuardianTimelock":"%s","GuardianMultisig":"%s"}' \
    "$(lower "$GOVERNANCE")" "$(lower "$GOVERNANCE_MULTISIG")" "$(lower "$GUARDIAN")" "$(lower "$GUARDIAN_MULTISIG")")
  why=$(manifest_bind check "$RUN_MANIFEST" governance "$gov_json" 2>&1) ||
    gate_fail "$ph" "governance.json is not the governance this run recorded: $why"
  if [[ "$2" == 1 ]]; then
    check_governance_onchain "$ph"
    why=$(manifest_bind bind "$RUN_MANIFEST" governance "$gov_json" 2>&1) || gate_fail "$ph" "cannot record the governance in the run manifest: $why"
  fi
  export GOVERNANCE GUARDIAN GOVERNANCE_MULTISIG GUARDIAN_MULTISIG GOVERNANCE_TIMELOCK="$GOVERNANCE"
  export VALIDATOR_GOVERNANCE="$GOVERNANCE" VALIDATOR_SLASHER="$GOVERNANCE"
  log "    GOVERNANCE=$GOVERNANCE GUARDIAN=$GUARDIAN"
}
# check_governance_onchain <phase>: C3 for both councils (see council_onchain) and the delay
# order between them.
check_governance_onchain() {
  local gd rd
  gd=$(council_onchain "$1" GOV "$GOVERNANCE" "$GOVERNANCE_MULTISIG" $GOV_MIN_THRESHOLD $GOV_MIN_OWNERS $GOV_MIN_DELAY_SECS) || exit 3
  rd=$(council_onchain "$1" GRD "$GUARDIAN" "$GUARDIAN_MULTISIG" $GRD_MIN_THRESHOLD $GRD_MIN_OWNERS $GRD_MIN_DELAY_SECS) || exit 3
  ((rd < gd)) || gate_fail "$1" "the GUARDIAN delay on chain (${rd}s) is not shorter than the GOVERNANCE delay (${gd}s)"
  log "$1 governance floors hold on chain for the recorded councils"
}

# ---------------------------------------------------------------- P0
# The preflight is mandatory whenever the run talks to a chain (simulate or confirm), whatever
# --from/--only selects: a resume must re-prove the chain, the genesis and the inputs before it
# sends anything. A dry run only runs it when P0 is selected.
if should P0 || [[ "$MODE" != dry ]]; then
  should P0 || log "P0 preflight (mandatory before a $MODE run that resumes at ${ONLY:-$FROM})"
  need_env DEPLOYER_ADDRESS GOV_OWNERS GOV_THRESHOLD GOV_MIN_DELAY GRD_OWNERS GRD_THRESHOLD GRD_MIN_DELAY
  is_addr "$DEPLOYER_ADDRESS" || gate_fail P0 "DEPLOYER_ADDRESS is malformed"
  # C9: the deploy scripts read the deployer from CEREMONY_DEPLOYER_ADDRESS before
  # DEPLOYER_ADDRESS (ScriptEnv), and the generator from EMIT_DEPLOYER/DEPLOYER. A preset alias
  # must be DEPLOYER_ADDRESS byte for byte (not empty, not another case or spelling); then
  # every phase gets DEPLOYER_ADDRESS, which the run manifest binds.
  for v in CEREMONY_DEPLOYER_ADDRESS DEPLOYER EMIT_DEPLOYER; do
    [[ -n "${!v+x}" ]] || continue
    [[ -n "${!v}" ]] || gate_fail P0 "$v is set but empty; unset it: the ceremony sets every deployer input from DEPLOYER_ADDRESS"
    [[ "${!v}" == "$DEPLOYER_ADDRESS" ]] ||
      gate_fail P0 "$v is set to '${!v}', not exactly DEPLOYER_ADDRESS ($DEPLOYER_ADDRESS); unset it: the ceremony sets every deployer input from DEPLOYER_ADDRESS"
  done
  export CEREMONY_DEPLOYER_ADDRESS="$DEPLOYER_ADDRESS"
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
  [[ -f "$CONTRACTS/script/$GENESIS_MEMBERSHIP_SCRIPT" ]] ||
    gate_fail P0 "contracts/script/$GENESIS_MEMBERSHIP_SCRIPT is missing (the genesis membership path, chain#331, must be merged)"
  [[ -x "$REGENESIS" || -f "$REGENESIS" ]] || gate_fail P0 "$REGENESIS is missing"
  if [[ -n "${TEAM_VESTING_FILE:-}" ]]; then
    [[ -f "$TEAM_VESTING_FILE" || -f "$CONTRACTS/$TEAM_VESTING_FILE" ]] || gate_fail P0 "TEAM_VESTING_FILE not found (a path relative to contracts/, under genesis/)"
  fi
  [[ -z "${KEEP_LIST:-}" || -f "$KEEP_LIST" ]] || gate_fail P0 "KEEP_LIST not found"
  if [[ "$MODE" == confirm ]]; then
    [[ -n "$ACCOUNT" ]] || gate_fail P0 "--confirm needs --account (Foundry keystore)"
    need_env RPC_URL EXPECTED_GENESIS_HASH TEAM_VESTING_FILE KEEP_LIST FLEET_RPCS MEMBERSHIP_GRANTOR
    if ! is_local_rpc "$RPC_URL" && [[ "${CITRATE_ALLOW_REMOTE:-0}" != 1 ]]; then
      gate_fail P0 "RPC_URL is not loopback; a live broadcast needs CITRATE_ALLOW_REMOTE=1 as well"
    fi
  fi
  if [[ "$MODE" != dry ]]; then
    need_env RPC_URL
    cid=$("$CAST" chain-id --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "RPC $RPC_URL unreachable"
    [[ "$cid" == "$EXPECTED_CHAIN_ID" ]] || gate_fail P0 "RPC chain id $cid, want $EXPECTED_CHAIN_ID"
    g0=$("$CAST" block 0 --field hash --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "cannot read block 0 from $RPC_URL"
    [[ "$g0" =~ ^0x[0-9a-fA-F]{64}$ ]] || gate_fail P0 "block 0 hash from $RPC_URL is malformed"
    if [[ -n "${EXPECTED_GENESIS_HASH:-}" ]]; then
      [[ "$(lower "$g0")" == "$(lower "$EXPECTED_GENESIS_HASH")" ]] || gate_fail P0 "block 0 is $g0, want $EXPECTED_GENESIS_HASH"
    fi
    g0ts=$("$CAST" block 0 --field timestamp --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "cannot read the block-0 timestamp from $RPC_URL"
    g0ts=$("$PY" -c 'import sys; v=int(sys.argv[1], 0); assert v > 0; print(v)' "$g0ts" 2>/dev/null) ||
      gate_fail P0 "the block-0 timestamp from $RPC_URL is malformed"
    if [[ "$FROM" == P0 && -z "$ONLY" ]]; then
      nonce=$("$CAST" nonce "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null) || gate_fail P0 "cannot read the deployer nonce from $RPC_URL"
      [[ "$nonce" == 0 ]] || gate_fail P0 "deployer nonce is $nonce; a fresh ceremony starts at 0 (resume with --from instead)"
    fi
  fi
  if [[ "$MODE" != dry ]]; then
    # A phase about to write a book must not find one already there: it would be an earlier
    # run's (or a simulation's) output, and later phases would read it as this run's.
    for pb in "P1:$GOV_BOOK" "P2:$MEMB_BOOK" "P3:$VEST_BOOK" "P4:$DORMANT_BOOK"; do
      if should "${pb%%:*}" && [[ -e "${pb#*:}" ]]; then
        gate_fail P0 "${pb#*:} already exists and ${pb%%:*} would write it; move it aside (it is not this ceremony's output) or resume after ${pb%%:*}"
      fi
    done
  fi
  if [[ "$MODE" != dry ]]; then
    # Bind this invocation to its ceremony run (see "Run manifest" above).
    if [[ "$FROM" == P0 && -z "$ONLY" ]]; then
      [[ ! -e "$RUN_MANIFEST" ]] ||
        gate_fail P0 "$RUN_MANIFEST already exists: it belongs to an earlier run; move it aside with that run's books, or resume that run with --from"
      mkdir -p "$OUT" || gate_fail P0 "cannot create $OUT"
      run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
      manifest_write "$RUN_MANIFEST" "$run_id" "$MODE" "$cid" "$g0" "$g0ts" "$DEPLOYER_ADDRESS" "$ACCOUNT" ||
        gate_fail P0 "cannot write the run manifest $RUN_MANIFEST"
      log "P0 run manifest written: run $run_id, deployer $(lower "$DEPLOYER_ADDRESS")${ACCOUNT:+ (account $ACCOUNT)}"
    fi
    run_rec=$(manifest_check "$RUN_MANIFEST" "$MODE" "$cid" "$g0" "$g0ts" "$DEPLOYER_ADDRESS" "$ACCOUNT" 2>&1) ||
      gate_fail P0 "run manifest: $run_rec"
    IFS=$'\t' read -r RUN_ID RUN_DEPLOYER RUN_G0TS <<<"$run_rec"
    is_addr "$RUN_DEPLOYER" && [[ "$RUN_G0TS" =~ ^[0-9]+$ && -n "$RUN_ID" ]] || gate_fail P0 "run manifest: unexpected record $run_rec"
    RUN_G0=$(lower "$g0")
    log "P0 bound to run $RUN_ID (deployer $RUN_DEPLOYER)"
    # C6: the KEEP list this run checks is fixed by its hash, recorded on the fresh run.
    if [[ -n "${KEEP_LIST:-}" ]]; then
      keep_sha=$(sha256sum "$KEEP_LIST" | cut -c1-64) || gate_fail P0 "cannot hash KEEP_LIST"
      bind_mode=check
      if [[ "$FROM" == P0 && -z "$ONLY" ]]; then bind_mode=bind; fi
      why=$(manifest_bind "$bind_mode" "$RUN_MANIFEST" keepListSha256 "\"$keep_sha\"" 2>&1) || gate_fail P0 "KEEP list: $why"
    fi
    # C2/C3: once the run has recorded its governance, every invocation re-proves it on chain.
    if manifest_has "$RUN_MANIFEST" governance; then
      load_governance P0 1
    fi
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
  # A broadcast P1 is checked on chain and recorded in the manifest at once (C2, C3).
  if [[ "$MODE" == confirm ]]; then load_governance P1 1; fi
fi

# ---------------------------------------------------------------- P2
if should P2; then
  # --confirm: the council the registry will be governed by is proven on chain first (C3).
  load_governance P2 "$([[ "$MODE" == confirm ]] && echo 1 || echo 0)"
  rargs=(--reroll --with-aa --genesis-membership)
  # G9: the membership deploy is chain#331's DeployGenesisMembership. It reads P1's governance
  # (GOVERNANCE_TIMELOCK / GOVERNANCE_MULTISIG, from load_governance) and its book, the grantor,
  # and writes its own book into this run's output directory.
  export GENESIS_MEMBERSHIP_OUT="$MEMB_REL" GENESIS_GOVERNANCE_BOOK="$GOV_REL"
  # The keystore account and, when given, the password file (a path, never the password) go
  # through to every forge step regenesis.sh runs, as P1/P3/P4 get them (SIGN).
  if [[ "$MODE" == confirm ]]; then rargs+=(--broadcast "${SIGN[@]}"); fi
  log "P2 contract stack via regenesis.sh; address book → $ADDRESS_BOOK (fresh genesis)"
  if [[ "$MODE" == dry ]]; then
    describe_cmd RPC_URL='$RPC_URL' DEPLOYER_ADDRESS='$DEPLOYER_ADDRESS' MEMBERSHIP_GRANTOR='$MEMBERSHIP_GRANTOR' \
      GENESIS_MEMBERSHIP_OUT="$MEMB_REL" GENESIS_GOVERNANCE_BOOK="$GOV_REL" EMIT_FRESH_GENESIS=1 EMIT_MEMBERSHIP_SCRIPT="$GENESIS_MEMBERSHIP_SCRIPT" \
      EMIT_DEPLOYER='<manifest deployer>' EMIT_BROADCAST_SINCE='<manifest block-0 timestamp>' EMIT_OUTPUT="$book_abs" bash "$REGENESIS" "${rargs[@]}"
  else
    # C8: the generator gets this run's deployer, block 0 and book path; a preset that says
    # otherwise is refused before anything is sent.
    is_addr "${RUN_DEPLOYER:-}" && [[ "${RUN_G0TS:-}" =~ ^[0-9]+$ ]] || gate_fail P2 "no run deployer or block-0 timestamp (the P0 run manifest did not load)"
    for v in DEPLOYER EMIT_DEPLOYER; do
      if [[ -n "${!v:-}" && "$(lower "${!v}")" != "$RUN_DEPLOYER" ]]; then
        gate_fail P2 "$v is set to ${!v}, but this run's deployer is $RUN_DEPLOYER; unset it: the ceremony sets the generator's deployer from the run manifest"
      fi
    done
    [[ -z "${EMIT_OUTPUT:-}" || "$(norm_path "$EMIT_OUTPUT")" == "$book_abs" ]] ||
      gate_fail P2 "EMIT_OUTPUT is set to $EMIT_OUTPUT, but the ceremony's book is $ADDRESS_BOOK"
    [[ -z "${EMIT_BROADCAST_SINCE:-}" || "$EMIT_BROADCAST_SINCE" == "$RUN_G0TS" ]] ||
      gate_fail P2 "EMIT_BROADCAST_SINCE is set to $EMIT_BROADCAST_SINCE, but this run's block 0 is at $RUN_G0TS"
    [[ -z "${EMIT_FRESH_GENESIS:-}" || "$EMIT_FRESH_GENESIS" == 1 ]] ||
      gate_fail P2 "EMIT_FRESH_GENESIS is set to $EMIT_FRESH_GENESIS; a genesis ceremony always regenerates a fresh book"
    [[ -z "${EMIT_MEMBERSHIP_SCRIPT:-}" || "$EMIT_MEMBERSHIP_SCRIPT" == "$GENESIS_MEMBERSHIP_SCRIPT" ]] ||
      gate_fail P2 "EMIT_MEMBERSHIP_SCRIPT is set to $EMIT_MEMBERSHIP_SCRIPT; the genesis membership is $GENESIS_MEMBERSHIP_SCRIPT, unset it"
    # G9: the grantor (the treasury signer that places grants) is a real, separate account.
    [[ -n "${MEMBERSHIP_GRANTOR:-}" ]] || gate_fail P2 "MEMBERSHIP_GRANTOR is not set (the treasury-signer address that places membership grants)"
    is_addr "$MEMBERSHIP_GRANTOR" || gate_fail P2 "MEMBERSHIP_GRANTOR ($MEMBERSHIP_GRANTOR) is not an address"
    g=$(lower "$MEMBERSHIP_GRANTOR")
    [[ "$g" != "$RUN_DEPLOYER" ]] || gate_fail P2 "MEMBERSHIP_GRANTOR ($MEMBERSHIP_GRANTOR) is the deployer; the grant signer is a separate account"
    for a in "$GOVERNANCE" "$GOVERNANCE_MULTISIG" "$GUARDIAN" "$GUARDIAN_MULTISIG" 0x0000000000000000000000000000000000000000; do
      [[ "$g" != "$(lower "$a")" ]] || gate_fail P2 "MEMBERSHIP_GRANTOR ($MEMBERSHIP_GRANTOR) is a governance contract or the zero address"
    done
    export EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$RUN_DEPLOYER" EMIT_BROADCAST_SINCE="$RUN_G0TS" EMIT_OUTPUT="$book_abs"
    export EMIT_MEMBERSHIP_SCRIPT="$GENESIS_MEMBERSHIP_SCRIPT" MEMBERSHIP_GRANTOR
    RPC_URL="$RPC_URL" bash "$REGENESIS" "${rargs[@]}" || step_fail P2 regenesis.sh
    if [[ "$MODE" == confirm ]]; then
      verify_stack_book
    else
      log "P2 note: a simulation broadcasts nothing, so regenesis.sh writes no book; $ADDRESS_BOOK is unchanged"
    fi
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
  if [[ "$MODE" != dry ]]; then record_output_book P3 teamVesting "$VEST_BOOK" DeployTeamVesting.s.sol; fi
fi

# ---------------------------------------------------------------- P4
if should P4; then
  load_governance P4 "$([[ "$MODE" == confirm ]] && echo 1 || echo 0)"
  export DORMANT_LEDGERS_OUT="$DORMANT_REL" GENESIS_GOVERNANCE_BOOK="$GOV_REL"
  [[ "$MODE" == dry ]] || need_env PATRONAGE_KYC_REGISTRY PATRONAGE_MEMBERSHIP
  log "P4 dormant ledgers → $DORMANT_BOOK"
  forge_phase P4 DeployDormantLedgers.s.sol
  if [[ "$MODE" != dry ]]; then
    # The book also names the governance it was deployed under: it must be this run's.
    record_output_book P4 dormantLedgers "$DORMANT_BOOK" DeployDormantLedgers.s.sol \
      "$(printf '{"GovernanceTimelock":"%s","GovernanceMultisig":"%s"}' "$(lower "$GOVERNANCE")" "$(lower "$GOVERNANCE_MULTISIG")")"
  fi
fi

# ---------------------------------------------------------------- P5
# The checker reads ONE book (ADDRESS_BOOK) and sweeps its .contracts and .aaStack. P5 hands
# it a single merged book: the canonical book plus the .contracts of every ceremony output,
# so every contract the ceremony deployed is swept by whatever checker revision is installed
# (nothing depends on the checker honouring a side channel such as EXTRA_ADDRESS_BOOKS).
# The checker derives the identity it checks from the book's .deployer, so every book (the
# canonical one and each output) must name the deployer this run recorded in its manifest
# at P0: stale books that agree with each other on another deployer are refused, not
# checked. The merge also refuses an extra book that has no contracts. A name repeated
# across books (the dormant-ledger book lists GovernanceTimelock and GovernanceMultisig,
# which governance.json also lists) is one contract only if every book gives it the same
# address, compared case-insensitively; it is swept once. A repeat with another address
# fails, naming both books, and so does a name that appears twice in one book (JSON would
# keep only the last), so no entry is dropped or shadowed. --confirm needs all three
# outputs; --simulate takes those present, governance always.
if should P5; then
  P5_BOOK_REL="$OUT_REL/p5-admin-book.json"
  P5_BOOK="$CONTRACTS/$P5_BOOK_REL"
  log "P5 admin handover gate (FACTORY-ADMIN 0, DEPLOYER-ADMIN 0) over the book + the ceremony outputs"
  cmd=("$FORGE" script script/CheckDeployedAdmins.s.sol --rpc-url "${RPC_URL:-\$RPC_URL}")
  if [[ "$MODE" == dry ]]; then
    log "P5 would merge $ADDRESS_BOOK + $GOV_REL, $VEST_REL, $DORMANT_REL → $P5_BOOK_REL"
    describe_cmd "(cd contracts && ADDRESS_BOOK=$P5_BOOK_REL REQUIRE_ALL_CODE=true" "${cmd[@]}" ")"
  else
    extras=("$GOV_BOOK")
    [[ -f "$GOV_BOOK" ]] || gate_fail P5 "$GOV_BOOK missing (run P1 first)"
    for b in "$VEST_BOOK" "$DORMANT_BOOK"; do
      if [[ -f "$b" ]]; then
        extras+=("$b")
      elif [[ "$MODE" == confirm ]]; then
        gate_fail P5 "$b missing: the handover gate must cover every ceremony output (run P3/P4 first)"
      else
        log "P5 note: $b absent in a simulation; not swept"
      fi
    done
    is_addr "${RUN_DEPLOYER:-}" || gate_fail P5 "no run deployer (the P0 run manifest did not load)"
    log "P5 deployer bound to run $RUN_ID: $RUN_DEPLOYER"
    load_governance P5 1
    # C5: the vesting and dormant-ledger outputs are the ones this run recorded. P3/P4 record
    # them when they write them; on --confirm a book its step did not record is refused (a
    # simulation still records one at first use here).
    for kb in "teamVesting:P3:$VEST_BOOK" "dormantLedgers:P4:$DORMANT_BOOK"; do
      IFS=: read -r k st b <<<"$kb"
      [[ -f "$b" ]] || continue
      cj=$(book_contracts_json "$b") || gate_fail P5 "$b has no well-formed contracts"
      if [[ "$MODE" == confirm ]] && ! manifest_has "$RUN_MANIFEST" "$k"; then
        gate_fail P5 "$b was not recorded by $st in this run (the run manifest has no $k): it is not this ceremony's output"
      fi
      why=$(manifest_bind bind "$RUN_MANIFEST" "$k" "$cj" 2>&1) || gate_fail P5 "$b is not the output this run recorded: $why"
    done
    # C4: the ValidatorRegistry is governed by this run's GOVERNANCE, whatever the env said.
    vr=$(book_addr "$ADDRESS_BOOK" ValidatorRegistry) || vr=""
    if is_addr "$vr"; then
      for f in governance slasher; do
        got=$(cast_read "$vr" "$f()(address)") && is_addr "$got" || gate_fail P5 "cannot read ValidatorRegistry.$f() at $vr"
        [[ "$(lower "$got")" == "$(lower "$GOVERNANCE")" ]] ||
          gate_fail P5 "ValidatorRegistry.$f() is $got, not this run's GOVERNANCE $GOVERNANCE"
      done
      got=$(cast_read "$vr" "pendingGovernance()(address)") && is_addr "$got" || gate_fail P5 "cannot read ValidatorRegistry.pendingGovernance() at $vr"
      [[ "$(lower "$got")" == 0x0000000000000000000000000000000000000000 ]] ||
        gate_fail P5 "ValidatorRegistry.pendingGovernance() is $got: a governance transfer is pending"
      log "P5 ValidatorRegistry $vr: governance and slasher are GOVERNANCE, nothing pending"
    elif [[ "$MODE" == confirm ]]; then
      gate_fail P5 "$ADDRESS_BOOK has no ValidatorRegistry; the handover gate must check its governance"
    else
      log "P5 note: no ValidatorRegistry in $ADDRESS_BOOK in a simulation; its governance is not checked"
    fi
    # C8: the book swept here is the one P2 generated for this run.
    stack_book_bound P5 "$([[ "$MODE" == confirm ]] && echo 1 || echo 0)"
    merged=$("$PY" - "$RUN_DEPLOYER" "$ADDRESS_BOOK" "$P5_BOOK" "${extras[@]}" <<'PY'
import json, re, sys
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
run_dep, main_path, out_path, extras = sys.argv[1].lower(), sys.argv[2], sys.argv[3], sys.argv[4:]
def load(p):
    def once(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                sys.exit(f"{p}: the key {k!r} appears more than once in one object")
            d[k] = v
        return d
    try:
        with open(p) as f:
            d = json.load(f, object_pairs_hook=once)
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read {p}: {e}")
    if not isinstance(d, dict):
        sys.exit(f"{p} is not a JSON object")
    return d
book = load(main_path)
dep = book.get("deployer")
if not isinstance(dep, str) or not ADDR.fullmatch(dep):
    sys.exit(f"{main_path} has no deployer address")
if dep.lower() != run_dep:
    sys.exit(f"{main_path} names deployer {dep}, not this run's deployer {run_dep}")
book.setdefault("contracts", {})
book.setdefault("aaStack", {})
for sec in ("contracts", "aaStack"):
    if not isinstance(book[sec], dict):
        sys.exit(f"{main_path} .{sec} is not an object")
# name -> (address, the book that first gave it)
seen = {}
for sec in ("aaStack", "contracts"):
    for name, a in book[sec].items():
        seen[name] = (a, main_path)
for p in extras:
    d = load(p)
    xdep = d.get("deployer")
    if not isinstance(xdep, str) or not ADDR.fullmatch(xdep) or xdep.lower() != run_dep:
        sys.exit(f"{p} names deployer {xdep!r}, not this run's deployer {run_dep}")
    c = d.get("contracts")
    if not isinstance(c, dict) or not c:
        sys.exit(f"{p} has no contracts")
    same = 0
    for name, a in c.items():
        if not isinstance(a, str) or not ADDR.fullmatch(a) or int(a, 16) == 0:
            sys.exit(f"{p} .contracts.{name} is not an address")
        if name in seen:
            prev, src = seen[name]
            if not isinstance(prev, str) or prev.lower() != a.lower():
                sys.exit(f"{p} .contracts.{name} is {a}, but {src} already has {prev}: a repeated name must give the same address")
            same += 1
            continue
        seen[name] = (a, p)
        book["contracts"][name] = a
    print(f"{p}: {len(c)} contract(s)" + (f", {same} already in the merged book at the same address" if same else ""))
book["deployer"] = run_dep
with open(out_path, "w") as f:
    json.dump(book, f, indent=2, sort_keys=True)
PY
    ) || gate_fail P5 "cannot build the merged admin book"
    printf '%s\n' "$merged" | sed 's/^/    P5 swept /'
    report=$(cd "$CONTRACTS" && ADDRESS_BOOK="$P5_BOOK_REL" REQUIRE_ALL_CODE=true "${cmd[@]}" 2>&1) || {
      printf '%s\n' "$report" | tail -40
      gate_fail P5 "CheckDeployedAdmins failed (see the report above)"
    }
    printf '%s\n' "$report" | { grep -E 'ADMIN' || true; } | tail -20
    # Exactly one summary line per class, and it must read 0: a missing, repeated or
    # unparsable summary is not a pass.
    admin_count() { # class -> the single "<class> failures: N" value, or nothing
      local lines
      lines=$(printf '%s\n' "$report" | sed -nE "s/.*$1 failures:[[:space:]]*([0-9]+)[[:space:]]*\$/\1/p")
      [[ $(printf '%s' "$lines" | grep -c .) -eq 1 ]] && printf '%s' "$lines"
    }
    fa=$(admin_count FACTORY-ADMIN) || gate_fail P5 "the checker report has no single FACTORY-ADMIN summary"
    da=$(admin_count DEPLOYER-ADMIN) || gate_fail P5 "the checker report has no single DEPLOYER-ADMIN summary"
    [[ "$fa" == 0 ]] || gate_fail P5 "FACTORY-ADMIN is not 0"
    [[ "$da" == 0 ]] || gate_fail P5 "DEPLOYER-ADMIN is not 0: the deployer still holds a role"
    log "P5 PASS: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0 over $P5_BOOK_REL"
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
    # Only broadcasts recorded on this chain since its block 0 are evidence for P6. The
    # timestamp is the run manifest's, which P0 re-checked against the chain.
    [[ "${RUN_G0TS:-}" =~ ^[0-9]+$ ]] || gate_fail P6 "no block-0 timestamp from the run manifest to scope the broadcast evidence"
    load_governance P6 1
    stack_book_bound P6 "$([[ "$MODE" == confirm ]] && echo 1 || echo 0)"
    keep_sha=$(sha256sum "$KEEP_LIST" | cut -c1-64) || gate_fail P6 "cannot hash KEEP_LIST"
    why=$(manifest_bind bind "$RUN_MANIFEST" keepListSha256 "\"$keep_sha\"" 2>&1) || gate_fail P6 "KEEP list is not the one this run recorded: $why"
    RPC="$RPC_URL" ADDRESS_BOOK="$ADDRESS_BOOK" BROADCAST_DIR="$CONTRACTS/broadcast" BROADCAST_SINCE="$RUN_G0TS" \
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
    # Every endpoint must be on THIS run's block 0 (P0 read it and matched the manifest), not
    # merely agree with each other or with the first endpoint that answers.
    fleet_g0=()
    if [[ "$MODE" != dry ]]; then
      is_hash() { [[ "$1" =~ ^0x[0-9a-f]{64}$ ]]; }
      is_hash "${RUN_G0:-}" || gate_fail P7 "no block-0 hash from the run manifest to check the fleet against"
      load_governance P7 1
      fleet_g0=(EXPECTED_GENESIS_HASH="$RUN_G0")
    fi
    env "${fleet_g0[@]}" FLEET_RPCS="$FLEET_RPCS" EXPECTED_CHAIN_ID="$EXPECTED_CHAIN_ID" bash "$HERE/fleet_agree.sh" "${dryflag[@]}" ||
      gate_fail P7 "the fleet does not agree on genesis and tip"
  fi
fi

log "done (mode=$MODE)"
