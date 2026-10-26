#!/usr/bin/env bash
# test_genesis_scripts.sh: offline tests for scripts/genesis/*.sh.
#
# Every external tool (cast, forge, systemctl) is a fake written into a temp dir, so the tests
# need no network, no chain, no root and no key. Nothing outside the temp dir is touched.
#
# Run: bash scripts/genesis/tests/test_genesis_scripts.sh
# Exit: 0 all passed · 1 at least one failed
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
G="$(cd "$HERE/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

PASS=0
FAIL=0
ok() {
  PASS=$((PASS + 1))
  printf 'ok   %s\n' "$1"
}
bad() {
  FAIL=$((FAIL + 1))
  printf 'FAIL %s\n' "$1"
  [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/     | /' | tail -15
}
# expect <name> <want_exit> <grep_pattern|""> -- cmd...
expect() {
  local name="$1" want="$2" pat="$3"
  shift 4
  local out rc
  out=$("$@" 2>&1)
  rc=$?
  if [[ $rc -ne $want ]]; then
    bad "$name (exit $rc, want $want)" "$out"
  elif [[ -n "$pat" ]] && ! grep -qE -- "$pat" <<<"$out"; then
    bad "$name (output lacks /$pat/)" "$out"
  else
    ok "$name"
  fi
}

# ------------------------------------------------------------------ fakes
FAKE="$T/fake"
BIN="$T/bin"
mkdir -p "$FAKE/code" "$FAKE/impl" "$FAKE/rpc" "$BIN"
rpcdir() { printf '%s/rpc/%s' "$FAKE" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"; }

cat >"$BIN/cast" <<'EOF'
#!/usr/bin/env bash
# Fake cast. Reads canned answers from $FAKE; logs every call.
echo "cast $*" >>"$FAKE/calls.log"
# FAKE_PW_SWAP=<path>: at the first call, change that password file the way FAKE_PW_SWAP_HOW
# says (a new file at the path, a looser mode, a symlink, or another file renamed over it).
if [[ -n "${FAKE_PW_SWAP:-}" && ! -e "$FAKE/pw-swapped" ]]; then
  : >"$FAKE/pw-swapped"
  d=$(dirname "$FAKE_PW_SWAP")
  case "${FAKE_PW_SWAP_HOW:-}" in
    replace) rm -f "$FAKE_PW_SWAP"; (umask 077 && printf 'other\n' >"$FAKE_PW_SWAP") ;;
    chmod) chmod 644 "$FAKE_PW_SWAP" ;;
    symlink) rm -f "$FAKE_PW_SWAP"; ln -s "$d/target" "$FAKE_PW_SWAP" ;;
    rename) (umask 077 && printf 'other\n' >"$d/pw.new") && mv -f "$d/pw.new" "$FAKE_PW_SWAP" ;;
  esac
fi
rpc=""; field=""; args=()
while [[ $# -gt 0 ]]; do
  case "$1" in --rpc-url) rpc="$2"; shift 2 ;; --field) field="$2"; shift 2 ;; *) args+=("$1"); shift ;; esac
done
d="$FAKE/rpc/$(printf '%s' "$rpc" | tr -c 'A-Za-z0-9' '_')"
case "${args[0]}" in
  code) a=$(printf '%s' "${args[1]}" | tr 'A-F' 'a-f'); cat "$FAKE/code/$a" 2>/dev/null || echo 0x ;;
  keccak) [[ -z "${FAKE_KECCAK_FAIL:-}" ]] || exit 1; printf '0x%s\n' "$(printf '%s' "${args[1]}" | sha256sum | cut -c1-64)" ;;
  storage) a=$(printf '%s' "${args[1]}" | tr 'A-F' 'a-f'); cat "$FAKE/impl/$a" 2>/dev/null || printf '0x%064d\n' 0 ;;
  chain-id) [[ -f "$d/chain-id" ]] || exit 1; cat "$d/chain-id" ;;
  block-number) [[ -f "$d/head" ]] || exit 1; cat "$d/head" ;;
  block)
    if [[ "${field:-}" == timestamp ]]; then
      [[ -f "$d/block-${args[1]}-timestamp" ]] || exit 1; cat "$d/block-${args[1]}-timestamp"
    else
      [[ -f "$d/block-${args[1]}" ]] || exit 1; cat "$d/block-${args[1]}"
    fi ;;
  nonce) cat "$d/nonce" 2>/dev/null || echo 0 ;;
  call)
    # $FAKE/call/<addr>/<function>[_<arg>...] holds the decoded answer; a missing file is a
    # revert, except hasRole, which answers false.
    a=$(printf '%s' "${args[1]}" | tr 'A-F' 'a-f'); fn="${args[2]%%(*}"
    key="$fn"; for x in "${args[@]:3}"; do key+="_$(printf '%s' "$x" | tr 'A-F' 'a-f')"; done
    if [[ -f "$FAKE/call/$a/$key" ]]; then cat "$FAKE/call/$a/$key"
    elif [[ "$fn" == hasRole ]]; then echo false
    else exit 1; fi ;;
  *) echo "fake cast: unsupported ${args[*]}" >&2; exit 9 ;;
esac
EOF
cat >"$BIN/forge" <<'EOF'
#!/usr/bin/env bash
echo "forge $*" >>"$FAKE/calls.log"
echo "forge-env gov=${GENESIS_GOVERNANCE_OUT:-} vest=${TEAM_VESTING_OUT:-} dormant=${DORMANT_LEDGERS_OUT:-} govbook=${GENESIS_GOVERNANCE_BOOK:-} extras=${EXTRA_ADDRESS_BOOKS:-}" >>"$FAKE/calls.log"
echo "forge-deployer dep=${DEPLOYER_ADDRESS-<unset>} ceremony=${CEREMONY_DEPLOYER_ADDRESS-<unset>}" >>"$FAKE/calls.log"
# FAKE_FORGE_BCAST=1: a --broadcast run records its broadcast as forge does
# (broadcast/<script>/40204/run-<n>.json and run-latest.json, relative to contracts/, the cwd),
# at FAKE_FORGE_TS (default 6000, after the fake block 0). FAKE_P1_BOOK=<file>: P1 "writes" that
# file as its governance output (GENESIS_GOVERNANCE_OUT). FAKE_FORGE_FAIL=1: a --broadcast run
# fails after it has recorded its broadcast (sent, then stopped).
if [[ "$*" == *--broadcast* && -n "${FAKE_FORGE_BCAST:-}" ]]; then
  fs=""
  for a in "$@"; do [[ "$a" == script/* ]] && fs="${a#script/}"; done
  fd="broadcast/$fs/40204"
  mkdir -p "$fd"
  fn=$(find "$fd" -name 'run-[0-9]*.json' | wc -l)
  printf '{"timestamp":%s,"transactions":[{"transactionType":"CREATE","contractName":"Fake","contractAddress":"0x%040x"}]}\n' "${FAKE_FORGE_TS:-6000}" "$((fn + 4096))" >"$fd/run-$((${FAKE_FORGE_TS:-6000} + fn)).json"
  cp "$fd/run-$((${FAKE_FORGE_TS:-6000} + fn)).json" "$fd/run-latest.json"
fi
if [[ "$*" == *DeployGenesisGovernance* && "$*" == *--broadcast* && -n "${FAKE_P1_BOOK:-}" ]]; then cp "$FAKE_P1_BOOK" "$GENESIS_GOVERNANCE_OUT"; fi
[[ "$*" != *--broadcast* || -z "${FAKE_FORGE_FAIL:-}" ]] || exit 2
if [[ "$*" == *CheckDeployedAdmins* ]]; then
  # Like the real checker: read ONE book, ADDRESS_BOOK (relative to contracts/, the cwd).
  # FAKE_DEPLOYER_HELD=<name>: the contract of that name in the book still has the deployer
  # in a role, so it counts as a DEPLOYER-ADMIN failure only if the book the checker reads
  # actually contains it.
  echo "forge-book ${ADDRESS_BOOK:-}" >>"$FAKE/calls.log"
  [[ -f "${ADDRESS_BOOK:-}" ]] || { echo "fake forge: cannot read ADDRESS_BOOK ${ADDRESS_BOOK:-}" >&2; exit 1; }
  da=${FAKE_DEPLOYER_ADMIN:-0}
  if [[ -n "${FAKE_DEPLOYER_HELD:-}" ]] && grep -q "\"${FAKE_DEPLOYER_HELD}\"" "$ADDRESS_BOOK"; then
    echo "DEPLOYER-ADMIN ${FAKE_DEPLOYER_HELD}: governance() is the deployer EOA"
    da=$((da + 1))
  fi
  echo "FACTORY-ADMIN failures: ${FAKE_FACTORY_ADMIN:-0}"
  [[ "${FAKE_REPORT_DUP:-}" == FACTORY ]] && echo "FACTORY-ADMIN failures: 0"
  [[ "${FAKE_REPORT_DROP:-}" == DEPLOYER ]] || echo "DEPLOYER-ADMIN failures: $da"
fi
EOF
cat >"$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
# Fake systemctl. FAKE_STOP_FAILS / FAKE_STILL_ACTIVE: space-separated unit names whose stop
# returns non-zero / which still report active afterwards.
echo "systemctl $*" >>"$FAKE/calls.log"
case "$1" in
  stop) [[ " ${FAKE_STOP_FAILS:-} " == *" $2 "* ]] && exit 1 ;;
  is-active)
    if [[ " ${FAKE_STILL_ACTIVE:-} " == *" $2 "* ]]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
esac
exit 0
EOF
# Fake python that crashes the keep_check broadcast scanner (recognised by its script text
# on stdin) and runs every other script with the real interpreter. FAKE_SCANNER=crash prints a
# partial result and exits 1; FAKE_SCANNER=truncate prints nothing and exits 0.
cat >"$BIN/python-scanfault" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == - ]]; then
  src=$(cat)
  if [[ "$src" == *"keep_check broadcast scanner"* ]]; then
    case "${FAKE_SCANNER:-}" in
      crash) printf 'PIN\tEarly.s.sol\tAlpha at 0xabc\n'; echo "Traceback: boom" >&2; exit 1 ;;
      truncate) exit 0 ;;
    esac
  fi
  exec python3 - "${@:2}" <<<"$src"
fi
exec python3 "$@"
EOF
chmod +x "$BIN"/*
export FAKE CAST="$BIN/cast" FORGE="$BIN/forge" SYSTEMCTL="$BIN/systemctl"
unset RPC RPC_URL ADDRESS_BOOK BROADCAST_DIR KEEP_LIST FLEET_RPCS EXPECTED_GENESIS_HASH PRIVATE_KEY DEPLOYER_PRIVATE_KEY \
  DEPLOYER_ADDRESS CEREMONY_DEPLOYER_ADDRESS DEPLOYER EMIT_DEPLOYER EMIT_OUTPUT EMIT_BROADCAST_SINCE EMIT_FRESH_GENESIS EMITTER \
  TREASURY ETH_PASSWORD ETH_KEYSTORE ETH_KEYSTORE_ACCOUNT
calls() { cat "$FAKE/calls.log" 2>/dev/null; }
reset_calls() { : >"$FAKE/calls.log"; }

addr() { printf '0x%040x' "$1"; }
lower_t() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
A1=$(addr 161)
A2=$(addr 162)
A3=$(addr 163)
IMPL=$(addr 164)
printf '0x6001' >"$FAKE/code/$A1"
printf '0x6002' >"$FAKE/code/$A2"
printf '0x6003' >"$FAKE/code/$A3"
printf '0x%024d%s\n' 0 "${IMPL#0x}" >"$FAKE/impl/$A3"
hash_of() { printf '0x%s' "$(printf '%s' "$1" | sha256sum | cut -c1-64)"; }

BOOK="$T/book.json"
cat >"$BOOK" <<EOF
{"chainId":40204,"contracts":{"Alpha":"$A1","Beta":"$A2","Vault":"$A3","Zero":"0x0000000000000000000000000000000000000000"},
 "aaStack":{},"Vault":"$A3"}
EOF

# ------------------------------------------------------------------ keep_check
KC="$G/keep_check.sh"
LIST="$T/keep.tsv"
{
  printf '# test list\n'
  printf 'Alpha\tcontracts\t%s\tAlpha\t%s\t-\n' "$A1" "$(hash_of 0x6001)"
  printf 'Beta\tcontracts\t%s\t-\t%s\t-\n' "$A2" "$(hash_of 0x6002)"
  printf 'Vault\tcontracts\t%s\t-\t%s\t%s\n' "$A3" "$(hash_of 0x6003)" "$IMPL"
} >"$LIST"

expect "keep: verify passes on an unchanged chain" 0 'KEEP gate PASS \(3 entries\)' -- env RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" verify "$LIST"

printf '0x60ff' >"$FAKE/code/$A2"
expect "keep: changed code fails" 1 'KEEP-FAIL +Beta .*code changed' -- env RPC=http://r1 bash "$KC" verify "$LIST"
printf '0x6002' >"$FAKE/code/$A2"

printf '0x%064d\n' 7 >"$FAKE/impl/$A3"
expect "keep: changed proxy implementation fails" 1 'implementation slot changed' -- env RPC=http://r1 bash "$KC" verify "$LIST"
printf '0x%024d%s\n' 0 "${IMPL#0x}" >"$FAKE/impl/$A3"

rm "$FAKE/code/$A1"
expect "keep: missing code fails" 1 'Alpha .*got EMPTY' -- env RPC=http://r1 bash "$KC" verify "$LIST"
printf '0x6001' >"$FAKE/code/$A1"

MOVED="$T/moved.json"
sed "s/\"Beta\":\"$A2\"/\"Beta\":\"$(addr 999)\"/" "$BOOK" >"$MOVED"
expect "keep: a book that moved an address fails" 1 'Beta book.contracts moved' -- env RPC=http://r1 ADDRESS_BOOK="$MOVED" bash "$KC" verify "$LIST"

ROOTMOVED="$T/rootmoved.json"
sed "s/\"Vault\":\"$A3\"}/\"Vault\":\"$(addr 998)\"}/" "$BOOK" >"$ROOTMOVED"
expect "keep: a root-level pin that disagrees fails" 1 'Vault book.<root> moved' -- env RPC=http://r1 ADDRESS_BOOK="$ROOTMOVED" bash "$KC" verify "$LIST"

mkdir -p "$(rpcdir http://r1)"
echo 40204 >"$(rpcdir http://r1)/chain-id"
BC="$T/broadcast/DeployX.s.sol/40204"
mkdir -p "$BC"
run_json() { # timestamp name address
  printf '{"timestamp":%s,"transactions":[{"transactionType":"CREATE2","contractName":"%s","contractAddress":"%s"}]}' "$1" "$2" "$3"
}
# anchored_json <timestamp> <address>: an unrelated deployment plus the genesis deployment of
# the named KEEP row (Alpha) at its pin, which every passing broadcast set must contain.
anchored_json() {
  printf '{"timestamp":%s,"transactions":[{"transactionType":"CREATE2","contractName":"Other","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$1" "$2" "$A1"
}
run_json 2000 Alpha "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a broadcast that redeploys a kept contract elsewhere fails" 1 'DeployX.s.sol redeploys Alpha at 0x0+309 \(not the pinned' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
anchored_json 2000 "$(addr 777)" >"$BC/run-latest.json"
expect "keep: an unrelated broadcast passes" 0 'no chain-40204 broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# The deterministic genesis replay deploys the kept contract AT its pinned address: that passes.
run_json 2000 Alpha "$(printf '%s' "$A1" | tr 'a-f' 'A-F' | sed 's/^0X/0x/')" >"$BC/run-latest.json"
expect "keep: a genesis deployment at the pinned address passes" 0 'deploys Alpha at 0x0+a1 \(the pinned address\)' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# Another chain's broadcasts are not evidence for this one.
# Another chain's broadcasts are not evidence for this one (an unrelated chain-40204 run is
# the in-scope evidence).
anchored_json 2000 "$(addr 777)" >"$BC/run-latest.json"
mkdir -p "$T/broadcast/DeployX.s.sol/31337"
run_json 2000 Alpha "$(addr 777)" >"$T/broadcast/DeployX.s.sol/31337/run-latest.json"
expect "keep: another chain's broadcast is ignored" 0 'no chain-40204 broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
rm "$BC/run-latest.json"
expect "keep: only another chain's broadcasts is no evidence" 1 'no chain-40204 broadcast run in scope' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
rm -r "$T/broadcast/DeployX.s.sol/31337"
expect "keep: a BROADCAST_DIR that does not exist fails" 1 'is not a directory; no broadcast evidence' -- env RPC=http://r1 BROADCAST_DIR="$T/no-such-broadcast" bash "$KC" verify "$LIST"
# A run from an earlier chain on the same chain id (before block 0) is ignored with BROADCAST_SINCE.
run_json 1000 Alpha "$(addr 777)" >"$BC/run-1000.json"
anchored_json 2000 "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a run before BROADCAST_SINCE is ignored" 0 'KEEP-SKIP +DeployX.s.sol: run-1000.json' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1500 bash "$KC" verify "$LIST"
expect "keep: the same run after BROADCAST_SINCE counts" 1 'redeploys Alpha' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=500 bash "$KC" verify "$LIST"
rm "$BC/run-1000.json"
run_json 1600000000000 Alpha "$(addr 777)" >"$BC/run-1600000000000.json"
anchored_json 1800000000000 "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a millisecond timestamp is compared in seconds" 0 'KEEP-SKIP' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1700000000 bash "$KC" verify "$LIST"
expect "keep: only runs before BROADCAST_SINCE is no evidence" 1 'no chain-40204 broadcast run in scope' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1900000000 bash "$KC" verify "$LIST"
rm "$BC/run-1600000000000.json"
# Foundry keeps every run as run-<ts>.json and overwrites run-latest.json with the newest. An
# earlier in-scope run that moved a kept contract must still fail the gate when the latest
# run only holds unrelated transactions.
run_json 3000 Alpha "$(addr 777)" >"$BC/run-3000.json"
anchored_json 4000 "$(addr 778)" >"$BC/run-4000.json"
cp "$BC/run-4000.json" "$BC/run-latest.json"
expect "keep: an earlier timestamped run that moved a kept contract fails" 1 'DeployX.s.sol redeploys Alpha at 0x0+309 \(not the pinned' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=2500 bash "$KC" verify "$LIST"
expect "keep: an earlier timestamped run before BROADCAST_SINCE is ignored" 0 'KEEP-SKIP +DeployX.s.sol: run-3000.json' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=3500 bash "$KC" verify "$LIST"
printf '{not json' >"$BC/run-3500.json"
expect "keep: a malformed timestamped run fails" 1 'unreadable broadcast .*run-3500.json' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=2500 bash "$KC" verify "$LIST"
rm "$BC/run-3000.json" "$BC/run-3500.json" "$BC/run-4000.json"
# The latest copy and its timestamped original hold the same transactions: reported once.
printf '{"timestamp":5000,"transactions":[{"hash":"0xab","transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$BC/run-5000.json"
cp "$BC/run-5000.json" "$BC/run-latest.json"
out=$(env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST" 2>&1)
if [[ $? -eq 1 && $(grep -c 'redeploys Alpha' <<<"$out") -eq 1 ]]; then ok "keep: a transaction in run-latest and run-<ts> is reported once"; else bad "keep: a transaction in run-latest and run-<ts> is reported once" "$out"; fi
printf '{"timestamp":5000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$A1" >"$BC/run-5000.json"
cp "$BC/run-5000.json" "$BC/run-latest.json"
out=$(env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST" 2>&1)
if [[ $? -eq 0 && $(grep -c 'deploys Alpha at' <<<"$out") -eq 1 ]]; then ok "keep: a hashless duplicate deployment is reported once"; else bad "keep: a hashless duplicate deployment is reported once" "$out"; fi
rm "$BC/run-5000.json"
mkdir -p "$T/broadcast/multi/DeployX.s.sol-latest"
printf '{}' >"$T/broadcast/multi/DeployX.s.sol-latest/run.json"
run_json 2000 Other "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a multi-chain broadcast is not accepted as evidence" 1 'multi-chain broadcasts' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
rm -r "$T/broadcast/multi"
printf '{not json' >"$BC/run-latest.json"
expect "keep: an unreadable broadcast fails" 1 'unreadable broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
printf '{"transactions":[{"transactionType":"CREATE","contractName":"Alpha"}]}' >"$BC/run-latest.json"
expect "keep: a kept deployment with no address fails" 1 'has no contractAddress' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
expect "keep: broadcasts need a readable chain id" 1 'cannot read the chain id' -- env RPC=http://nochain BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# A scanner that crashes, or stops without finishing, fails the gate whatever it printed.
anchored_json 2000 "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a crashing broadcast scanner fails the gate" 1 'broadcast scanner exited 1' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" PYTHON="$BIN/python-scanfault" FAKE_SCANNER=crash bash "$KC" verify "$LIST"
expect "keep: a crashing scanner is never reported as a pass" 1 'KEEP gate FAIL' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" PYTHON="$BIN/python-scanfault" FAKE_SCANNER=crash bash "$KC" verify "$LIST"
expect "keep: a scanner that stops early fails the gate" 1 'broadcast scan did not complete' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" PYTHON="$BIN/python-scanfault" FAKE_SCANNER=truncate bash "$KC" verify "$LIST"
expect "keep: the fault-injecting python passes a clean scan through" 0 'no chain-40204 broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" PYTHON="$BIN/python-scanfault" bash "$KC" verify "$LIST"
# Schema errors in an earlier broadcast are reported AND the later broadcasts are still read.
mkdir -p "$T/broadcast/AAA.s.sol/40204" "$T/broadcast/ZZZ.s.sol/40204"
run_json 2000 Alpha "$(addr 777)" >"$T/broadcast/ZZZ.s.sol/40204/run-latest.json"
schema_case() { # name json
  printf '%s' "$2" >"$T/broadcast/AAA.s.sol/40204/run-latest.json"
  local out rc
  out=$(env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST" 2>&1)
  rc=$?
  if [[ $rc -eq 1 ]] && grep -q 'KEEP-FAIL    AAA.s.sol' <<<"$out" && grep -q 'ZZZ.s.sol redeploys Alpha' <<<"$out"; then
    ok "keep: $1 fails and the later redeploy is still found"
  else
    bad "keep: $1 fails and the later redeploy is still found (exit $rc)" "$out"
  fi
}
schema_case "a null transaction" '{"timestamp":2000,"transactions":[null]}'
schema_case "transactions that is not a list" '{"timestamp":2000,"transactions":{"a":1}}'
schema_case "a run that is not an object" '[1,2]'
schema_case "a non-numeric timestamp" '{"timestamp":"soon","transactions":[]}'
schema_case "a non-string contract name" '{"timestamp":2000,"transactions":[{"transactionType":"CREATE","contractName":["Alpha"]}]}'
schema_case "a non-string contract address" '{"timestamp":2000,"transactions":[{"transactionType":"CREATE","contractName":"Alpha","contractAddress":7}]}'
printf '{"transactions":[]}' >"$T/broadcast/AAA.s.sol/40204/run-latest.json"
run_json 2000 Other "$(addr 777)" >"$T/broadcast/ZZZ.s.sol/40204/run-latest.json"
expect "keep: a run with no timestamp fails when BROADCAST_SINCE scopes the evidence" 1 'no timestamp to compare' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1500 bash "$KC" verify "$LIST"
rm -r "$T/broadcast/AAA.s.sol" "$T/broadcast/ZZZ.s.sol"
# Other helper failures fail the gate too.
printf '{not json' >"$T/badbook.json"
expect "keep: an unreadable address book fails" 1 'book.contracts moved: want 0x[0-9a-f]+ got BOOK-ERROR' -- env RPC=http://r1 ADDRESS_BOOK="$T/badbook.json" bash "$KC" verify "$LIST"
expect "keep: a failing keccak fails" 1 'code changed: .* got KECCAK-ERROR' -- env RPC=http://r1 FAKE_KECCAK_FAIL=1 bash "$KC" verify "$LIST"
expect "keep: keys on an unreadable book is an input error" 2 'cannot read sections' -- env ADDRESS_BOOK="$T/badbook.json" BROADCAST_DIR="$T/broadcast" bash "$KC" keys contracts
rm -r "$T/broadcast"

# Contract names come from the broadcasts, never from the book key (Codex r6 on chain#329).
# emit-address-table.sh renames the EduStack Forwarder to EduForwarder in the book, so a KEEP
# row named after the book key never matches a broadcast, and a Forwarder redeployed
# elsewhere would pass. Rehearsal-chain broadcasts (RBC): Alpha, the Forwarder behind the
# book's EduForwarder, and the Vault proxy; Beta has no broadcast deployment.
A4=$(addr 165)
printf '0x6004' >"$FAKE/code/$A4"
ABOOK="$T/alias-book.json"
printf '{"chainId":40204,"contracts":{"Alpha":"%s","Beta":"%s","Vault":"%s","EduForwarder":"%s"},"aaStack":{}}' "$A1" "$A2" "$A3" "$A4" >"$ABOOK"
RBC="$T/rbc"
mkdir -p "$RBC/DeployAll.s.sol/40204"
printf '{"timestamp":1000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"Forwarder","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"ERC1967Proxy","contractAddress":"%s"}]}' "$A1" "$A4" "$A3" >"$RBC/DeployAll.s.sol/40204/run-latest.json"
expect "keep: keys needs the broadcasts" 2 'keys needs BROADCAST_DIR' -- env ADDRESS_BOOK="$ABOOK" bash "$KC" keys contracts
AKEYS="$T/alias-keys.tsv"
if ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$RBC" bash "$KC" keys contracts >"$AKEYS" 2>"$T/keys.err" &&
  grep -q "^EduForwarder	contracts	Forwarder	no$" "$AKEYS" && grep -q "^Alpha	contracts	Alpha	no$" "$AKEYS"; then
  ok "keep: keys names EduForwarder by its broadcast name, Forwarder"
else
  bad "keep: keys names EduForwarder by its broadcast name, Forwarder" "$(cat "$AKEYS" "$T/keys.err")"
fi
grep -q "^Beta	contracts	-	no$" "$AKEYS" && grep -q 'WARNING: .*contracts.Beta .*redeploy detection is OFF' "$T/keys.err" &&
  ok "keep: keys marks a row with no broadcast deployment - and warns" || bad "keep: keys marks a row with no broadcast deployment - and warns" "$(cat "$AKEYS" "$T/keys.err")"
sed -i 's/^Vault\tcontracts\tERC1967Proxy\tno$/Vault\tcontracts\tERC1967Proxy\tyes/' "$AKEYS"
echo 1234 >"$(rpcdir http://r1)/head"
printf 'EduForwarder\tcontracts\tEduForwarder\tno\n' >"$T/alias-wrong.tsv"
expect "keep: pin refuses a book-key name the broadcasts never deployed" 2 'EduForwarder is not what the broadcasts deploy at 0x0+a5 \(Forwarder\)' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$RBC" bash "$KC" pin "$T/alias-wrong.tsv"
printf 'EduForwarder\tcontracts\t-\tno\n' >"$T/alias-dash.tsv"
expect "keep: pin refuses - where the broadcasts show a deployment" 2 'contract_name is - but the broadcasts deploy Forwarder' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$RBC" bash "$KC" pin "$T/alias-dash.tsv"
expect "keep: pin needs the broadcasts" 2 'pin needs BROADCAST_DIR' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" bash "$KC" pin "$AKEYS"
echo 1234 >"$(rpcdir http://r1)/head"
APIN="$T/alias-pinned.tsv"
if RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$RBC" bash "$KC" pin "$AKEYS" >"$APIN" 2>"$T/pin.err"; then ok "keep: pin accepts broadcast-derived names"; else bad "keep: pin accepts broadcast-derived names" "$(cat "$T/pin.err")"; fi
# Genesis-chain broadcasts (GBC): the deterministic replay of all three at their pins.
GBC="$T/gbc"
mkdir -p "$GBC/DeployAll.s.sol/40204" "$GBC/Later.s.sol/40204"
cp "$RBC/DeployAll.s.sol/40204/run-latest.json" "$GBC/DeployAll.s.sol/40204/run-latest.json"
printf '{"timestamp":1500,"transactions":[]}' >"$GBC/Later.s.sol/40204/run-latest.json"
expect "keep: the alias list verifies against an untouched genesis replay" 0 'KEEP gate PASS \(4 entries\)' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$GBC" bash "$KC" verify "$APIN"
# Codex scenario: the pinned Forwarder stays intact and another Forwarder is deployed elsewhere.
printf '{"timestamp":1500,"transactions":[{"transactionType":"CREATE2","contractName":"Forwarder","contractAddress":"%s"}]}' "$(addr 888)" >"$GBC/Later.s.sol/40204/run-latest.json"
expect "keep: a Forwarder redeployed elsewhere fails under the EduForwarder alias" 1 'Later.s.sol redeploys Forwarder at 0x0+378 \(not the pinned' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$GBC" bash "$KC" verify "$APIN"
# The same scenario with a KEEP row still named after the book key (the pre-fix list) is no
# longer a pass: the pinned address is deployed under another name, and the name never anchors.
sed 's/^\(EduForwarder\tcontracts\t[^\t]*\t\)Forwarder\t/\1EduForwarder\t/' "$APIN" >"$T/alias-stale.tsv"
expect "keep: a KEEP row named by the book key fails (pinned address deployed as Forwarder)" 1 'deploys Forwarder at 0x0+a5, the pinned address of EduForwarder whose KEEP row names EduForwarder' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$GBC" bash "$KC" verify "$T/alias-stale.tsv"
expect "keep: a KEEP row name with no deployment at its pin fails" 1 'no in-scope broadcast deploys EduForwarder at 0x0+a5' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$GBC" bash "$KC" verify "$T/alias-stale.tsv"
# A - row (Beta, no deployment at pin time) that the genesis broadcasts DO deploy: fail.
printf '{"timestamp":1500,"transactions":[{"transactionType":"CREATE2","contractName":"Beta","contractAddress":"%s"}]}' "$A2" >"$GBC/Later.s.sol/40204/run-latest.json"
expect "keep: a deployment at a - row's pinned address fails" 1 'deploys Beta at 0x0+a2, the pinned address of Beta whose KEEP row names -' -- env RPC=http://r1 ADDRESS_BOOK="$ABOOK" BROADCAST_DIR="$GBC" bash "$KC" verify "$APIN"
rm -r "$RBC" "$GBC"

# A deployment forge records without a contract name: the P-256 verifier, which
# aa/DeployP256Verifier.s.sol deploys from vendored init code through the CREATE2 factory
# (contractName null). The fixture is that step's real broadcast record (chain 40204). The
# gate identifies such a deployment by its init code, once the record proves its address
# (CREATE2 of its factory, salt and init code); before, keys, pin and verify all refused it.
P256=0xc2b78104907f722dabac4c69f826a522b2754de4
P256_ID=initcode:0x3257821cc41f91063996667ce8ccb18b2ef28210b0e35376a36d6d47f3aea33a
P256_FIX="$HERE/fixtures/p256-verifier-run.json"
if [[ "$(jq -r '.transactions[0] | [.transactionType, (.contractName // "null"), .contractAddress, .transaction.to] | join(" ")' "$P256_FIX")" == "CREATE2 null $P256 0x4e59b44847b379578588920ca78fbf26c0b4956c" ]]; then
  ok "keep nameless: the fixture is a nameless CREATE2 through the factory at the verifier's address"
else
  bad "keep nameless: the fixture is a nameless CREATE2 through the factory at the verifier's address" "$(jq -c '.transactions[0] | del(.transaction.input)' "$P256_FIX")"
fi
# keccak256 (not FIPS SHA3) is what the identity hashes with: known vectors.
if [[ "$(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import broadcast_ident as b; print(b.keccak256(b"").hex(), b.keccak256(b"abc").hex())' "$G" 2>&1)" == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" ]]; then
  ok "keep nameless: keccak256 matches the known vectors"
else
  bad "keep nameless: keccak256 matches the known vectors"
fi
printf '0x6005' >"$FAKE/code/$P256"
PBOOK="$T/p256-book.json"
printf '{"chainId":40204,"contracts":{"Alpha":"%s"},"aaStack":{"P256Verifier":"%s"}}' "$A1" "$P256" >"$PBOOK"
PBC="$T/pbc"
mkdir -p "$PBC/DeployAll.s.sol/40204" "$PBC/DeployP256Verifier.s.sol/40204"
run_json 1000 Alpha "$A1" >"$PBC/DeployAll.s.sol/40204/run-latest.json"
cp "$P256_FIX" "$PBC/DeployP256Verifier.s.sol/40204/run-latest.json"
PKEYS="$T/p256-keys.tsv"
if ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" keys contracts,aaStack >"$PKEYS" 2>"$T/pkeys.err" &&
  grep -qxF "P256Verifier	aaStack	$P256_ID	no" "$PKEYS" && grep -qxF "Alpha	contracts	Alpha	no" "$PKEYS"; then
  ok "keep nameless: keys names the verifier by its init code, next to the named rows"
else
  bad "keep nameless: keys names the verifier by its init code, next to the named rows" "$(cat "$PKEYS" "$T/pkeys.err")"
fi
echo 1234 >"$(rpcdir http://r1)/head"
PPIN="$T/p256-pinned.tsv"
if RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" pin "$PKEYS" >"$PPIN" 2>"$T/ppin.err" &&
  grep -qP "^P256Verifier\taaStack\t$P256\t$P256_ID\t0x[0-9a-f]{64}\t-$" "$PPIN"; then
  ok "keep nameless: pin records the verifier row under its init-code identity"
else
  bad "keep nameless: pin records the verifier row under its init-code identity" "$(cat "$PPIN" "$T/ppin.err")"
fi
printf 'P256Verifier\taaStack\t-\tno\n' >"$T/p256-dash.tsv"
expect "keep nameless: pin refuses - for the verifier (the broadcasts identify it)" 2 "contract_name is - but the broadcasts deploy $P256_ID" -- env RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" pin "$T/p256-dash.tsv"
expect "keep nameless: verify passes the real P2 broadcast set" 0 "deploys $P256_ID at $P256 \(the pinned address\)" -- env RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" verify "$PPIN"
# The same init code through the factory with another salt is the same contract elsewhere.
P256_MOVED=$(python3 -I - "$G" "$P256_FIX" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
import broadcast_ident as b
r = json.load(open(sys.argv[2]))
t = r["transactions"][0]
init = bytes.fromhex(t["transaction"]["input"][2:])[32:]
salt = (1).to_bytes(32, "big")
t["transaction"]["input"] = "0x" + (salt + init).hex()
t["contractAddress"] = b.create2_address(t["transaction"]["to"], salt, init)
t["hash"] = "0x" + "11" * 32
r["timestamp"] = 1791264990000
print(json.dumps(r))
PY
)
mkdir -p "$PBC/Later.s.sol/40204"
printf '%s' "$P256_MOVED" >"$PBC/Later.s.sol/40204/run-latest.json"
expect "keep nameless: the verifier's init code deployed elsewhere fails as a redeploy" 1 "Later.s.sol redeploys $P256_ID at 0x[0-9a-f]{40} \(not the pinned" -- env RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" verify "$PPIN"
# A nameless record whose address its own fields do not prove has no identity: refused.
jq '.transactions[0].contractAddress = "0x00000000000000000000000000000000000000c7" | .transactions[0].hash = "0x" + ("22" * 32)' "$P256_FIX" >"$PBC/Later.s.sol/40204/run-latest.json"
expect "keep nameless: keys refuses a nameless record that does not prove its address" 2 'cannot read the chain-40204 broadcasts' -- env ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" keys contracts,aaStack
expect "keep nameless: verify fails a nameless record that does not prove its address" 1 'does not prove that address' -- env RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" verify "$PPIN"
# A nameless plain CREATE (no factory) cannot prove its address from the record either.
printf '{"timestamp":1791264990000,"transactions":[{"hash":"0x33","transactionType":"CREATE","contractName":null,"contractAddress":"%s","transaction":{"to":null,"input":"0x6001"}}]}' "$(addr 4321)" >"$PBC/Later.s.sol/40204/run-latest.json"
expect "keep nameless: verify fails a nameless plain CREATE" 1 'not a CREATE2 factory call' -- env RPC=http://r1 ADDRESS_BOOK="$PBOOK" BROADCAST_DIR="$PBC" bash "$KC" verify "$PPIN"
rm -r "$PBC" "$FAKE/code/$P256"

reset_calls
expect "keep: --dry-run needs no RPC" 0 'KEEP dry run OK \(3 entries' -- bash "$KC" verify --dry-run "$LIST"
if calls | grep -q .; then bad "keep: --dry-run made no tool call" "$(calls)"; else ok "keep: --dry-run made no tool call"; fi

BADLIST="$T/bad.tsv"
printf 'Alpha\tcontracts\tnot-an-address\tAlpha\t0x00\t-\n' >"$BADLIST"
expect "keep: a malformed row fails" 1 'line 1 is malformed' -- env RPC=http://r1 bash "$KC" verify "$BADLIST"
: >"$T/empty.tsv"
expect "keep: an empty list fails" 1 'empty KEEP list' -- env RPC=http://r1 bash "$KC" verify "$T/empty.tsv"
expect "keep: verify without RPC is a usage error" 2 'verify needs RPC' -- bash "$KC" verify "$LIST"

KEYS="$T/keys.tsv"
KBC="$T/kbc"
mkdir -p "$KBC/DeployAll.s.sol/40204"
run_json 1000 Alpha "$A1" >"$KBC/DeployAll.s.sol/40204/run-latest.json"
ADDRESS_BOOK="$BOOK" BROADCAST_DIR="$KBC" bash "$KC" keys contracts >"$KEYS" 2>/dev/null
if [[ $(grep -vc '^#' "$KEYS") -eq 3 ]] && ! grep -q Zero "$KEYS"; then ok "keep: keys lists the book's nonzero addresses"; else bad "keep: keys lists the book's nonzero addresses" "$(cat "$KEYS")"; fi
sed -i 's/^Vault\tcontracts\t-\tno$/Vault\tcontracts\t-\tyes/' "$KEYS"
echo 1234 >"$(rpcdir http://r1)/head"
PINNED="$T/pinned.tsv"
if RPC=http://r1 ADDRESS_BOOK="$BOOK" BROADCAST_DIR="$KBC" bash "$KC" pin "$KEYS" >"$PINNED" 2>"$T/pin.err"; then ok "keep: pin records the chain"; else bad "keep: pin records the chain" "$(cat "$T/pin.err")"; fi
expect "keep: a freshly pinned list verifies" 0 'KEEP gate PASS \(3 entries\)' -- env RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" verify "$PINNED"
grep -q "^Vault.*$IMPL\$" "$PINNED" && ok "keep: pin records the proxy implementation" || bad "keep: pin records the proxy implementation" "$(cat "$PINNED")"

# A final row without a trailing newline is still a row: `read` returns non-zero at EOF but
# fills the fields. Before the fix the loops dropped it, so a changed last contract passed.
NONL="$T/keep-nonl.tsv"
printf 'Alpha\tcontracts\t%s\tAlpha\t%s\t-\nBeta\tcontracts\t%s\t-\t%s\t-' "$A1" "$(hash_of 0x6001)" "$A2" "$(hash_of 0x6002)" >"$NONL"
expect "keep: an unterminated last row is counted" 0 'KEEP gate PASS \(2 entries\)' -- env RPC=http://r1 bash "$KC" verify "$NONL"
printf '0x60ff' >"$FAKE/code/$A2"
expect "keep: an unterminated last row that changed fails" 1 'KEEP-FAIL +Beta .*code changed' -- env RPC=http://r1 bash "$KC" verify "$NONL"
printf '0x6002' >"$FAKE/code/$A2"
expect "keep: --dry-run counts an unterminated last row" 0 'KEEP dry run OK \(2 entries' -- bash "$KC" verify --dry-run "$NONL"
printf 'Alpha\tcontracts\tAlpha\tno\nBeta\tcontracts\t-\tno' >"$T/keys-nonl.tsv"
if RPC=http://r1 ADDRESS_BOOK="$BOOK" BROADCAST_DIR="$KBC" bash "$KC" pin "$T/keys-nonl.tsv" >"$T/pinned-nonl.tsv" 2>"$T/pin.err" &&
  grep -q "^Beta	contracts	$A2	" "$T/pinned-nonl.tsv"; then
  ok "keep: pin records an unterminated last key"
else
  bad "keep: pin records an unterminated last key" "$(cat "$T/pinned-nonl.tsv" "$T/pin.err")"
fi
expect "keep: pin --dry-run reads an unterminated last key" 0 "cast code $A2" -- env ADDRESS_BOOK="$BOOK" bash "$KC" pin --dry-run "$T/keys-nonl.tsv"

# ------------------------------------------------------------------ fleet_agree
FA="$G/fleet_agree.sh"
h64() { printf '%064d' 0 | tr 0 "$1"; }
GEN=0x$(h64 a)
TIP=0x$(h64 b)
mk_node() { # url chain head genesis tiphash(at head-6)
  local d
  d=$(rpcdir "$1")
  mkdir -p "$d"
  echo "$2" >"$d/chain-id"
  echo "$3" >"$d/head"
  echo "$4" >"$d/block-0"
  rm -f "$d"/block-[1-9]*
  echo "$5" >"$d/block-$(($3 - 6))"
}
mk_node http://n1 40204 100 "$GEN" "$TIP"
mk_node http://n2 40204 100 "$GEN" "$TIP"
mk_node http://n3 40204 100 "$GEN" "$TIP"
expect "fleet: three agreeing nodes pass" 0 'FLEET AGREE \(3 endpoints' -- bash "$FA" http://n1 http://n2 http://n3
expect "fleet: FLEET_RPCS works like args" 0 'FLEET AGREE' -- env FLEET_RPCS=http://n1,http://n2 bash "$FA"
expect "fleet: the expected genesis hash is checked" 1 'differs from' -- env EXPECTED_GENESIS_HASH="0x$(h64 c)" bash "$FA" http://n1 http://n2
mk_node http://n3 40204 100 "0x$(h64 d)" "$TIP"
expect "fleet: a different genesis fails" 1 'n3 genesis .* differs' -- bash "$FA" http://n1 http://n2 http://n3
mk_node http://n3 40204 100 "$GEN" "0x$(h64 e)"
expect "fleet: a fork at the common height fails" 1 '\(fork\)' -- bash "$FA" http://n1 http://n2 http://n3
mk_node http://n3 1 100 "$GEN" "$TIP"
expect "fleet: a wrong chain id fails" 1 'chain id 1, want 40204' -- bash "$FA" http://n1 http://n3
expect "fleet: an unreachable node fails" 1 'unreachable' -- bash "$FA" http://n1 http://nowhere
mk_node http://n3 40204 400 "$GEN" "$TIP"
expect "fleet: heads far apart fail" 1 'blocks apart' -- bash "$FA" http://n1 http://n3
reset_calls
expect "fleet: --dry-run plans only" 0 'DRYRUN .* chain-id' -- bash "$FA" --dry-run http://n1 http://n2
if calls | grep -q .; then bad "fleet: --dry-run made no tool call" "$(calls)"; else ok "fleet: --dry-run made no tool call"; fi
expect "fleet: no endpoints is a usage error" 2 'at least one RPC' -- bash "$FA"

# ------------------------------------------------------------------ reset_node
RN="$G/reset_node.sh"
setup_node() {
  rm -rf "$T/node"
  mkdir -p "$T/node/home/.citrate/models" "$T/node/home/bin" "$T/node/dropin" "$T/node/home/.citrate/chaindata"
  local d="$T/node/home/.citrate"
  printf 'n' >"$d/noise.key"
  printf 'p' >"$d/proposer.key"
  printf 'id' >"$d/peer.id"
  printf 'chaindata' >"$d/chaindata/000001.sst"
  printf 'IDENTITY' >"$d/IDENTITY"
  printf 'm' >"$d/models/x.gguf"
  printf '[mining]\ncoinbase = "%s"\n' "${A1#0x}" >"$d/node.toml"
  printf '#!/bin/sh\necho old\n' >"$T/node/home/bin/citrate-node"
  printf '#!/bin/sh\necho new\n' >"$T/node/home/bin/citrate-node.new"
  chmod +x "$T/node/home/bin/"*
  printf '[Service]\nEnvironment=CITRATE_VALIDATOR_REGISTRY=%s\n' "$A2" >"$T/node/dropin/reroll.conf"
}
# Fake chown: logs, changes nothing (the tests do not run as root).
printf '#!/usr/bin/env bash\necho "chown $*" >>"$FAKE/calls.log"\n' >"$BIN/chown"
chmod +x "$BIN/chown"
RNENV=(env CITRATE_HOME="$T/node/home" DROPIN="$T/node/dropin/reroll.conf" NODE_OWNER= SYSTEMCTL="$BIN/systemctl" CHOWN="$BIN/chown")
NEWCB=$(addr 4660)
NEWVR=$(addr 4661)

setup_node
reset_calls
expect "reset: dry run prints the plan" 0 'dry run: nothing changed' -- "${RNENV[@]}" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0
if [[ -f "$T/node/home/.citrate/chaindata/000001.sst" ]] && ! calls | grep -q .; then ok "reset: dry run changed nothing"; else bad "reset: dry run changed nothing" "$(calls)"; fi

setup_node
reset_calls
expect "reset: --confirm resets the node" 0 'NOT started' -- "${RNENV[@]}" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
D="$T/node/home/.citrate"
arch=$(ls -d "$T"/node/home/.citrate.pregenesis-* 2>/dev/null | head -1)
[[ -n "$arch" && -f "$arch/chaindata/000001.sst" && -f "$arch/proposer.key" ]] && ok "reset: old state archived, not deleted" || bad "reset: old state archived, not deleted"
[[ -f "$D/noise.key" && -f "$D/peer.id" && -f "$D/models/x.gguf" ]] && ok "reset: identity and models carried" || bad "reset: identity and models carried" "$(ls -A "$D")"
[[ ! -e "$D/proposer.key" && ! -e "$D/chaindata" && ! -e "$D/IDENTITY" ]] && ok "reset: proposer.key and RocksDB not carried" || bad "reset: proposer.key and RocksDB not carried" "$(ls -A "$D")"
grep -qx "coinbase = \"${NEWCB#0x}\"" "$D/node.toml" && ok "reset: coinbase remapped (bare hex)" || bad "reset: coinbase remapped" "$(cat "$D/node.toml")"
grep -qx "Environment=CITRATE_VALIDATOR_REGISTRY=$NEWVR" "$T/node/dropin/reroll.conf" && grep -qx 'Environment=CITRATE_VALIDATOR_ACTIVATION_HEIGHT=0' "$T/node/dropin/reroll.conf" &&
  ok "reset: drop-in points at the new registry and activation" || bad "reset: drop-in" "$(cat "$T/node/dropin/reroll.conf")"
grep -q 'echo new' "$T/node/home/bin/citrate-node" && ok "reset: staged binary installed" || bad "reset: staged binary installed"
if calls | grep -q 'stop citrate-height-watchdog.timer' && calls | grep -q 'stop citrate-node' && ! calls | grep -qE 'systemctl (start|restart|enable)'; then
  ok "reset: watchdog and node stopped, nothing started"
else
  bad "reset: watchdog and node stopped, nothing started" "$(calls)"
fi

# The installed binary is root's (mode 0755), never the node user's: the service account runs
# it but cannot rewrite it. The new data dir is created 0700 and handed to the node user.
setup_node
reset_calls
expect "reset: --confirm with a node user" 0 'NOT started' -- "${RNENV[@]}" NODE_OWNER=citrate:citrate bash -c 'umask 022; exec "$@"' _ bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
RNB="$T/node/home/bin/citrate-node"
if calls | grep -qx "chown root:root $RNB" && ! calls | grep -qx "chown citrate:citrate $RNB" && [[ "$(stat -c %a "$RNB")" == 755 ]]; then
  ok "reset: the installed binary is root-owned 0755, not the node user's"
else
  bad "reset: the installed binary is root-owned 0755, not the node user's" "$(calls; stat -c '%a %n' "$RNB")"
fi
calls | grep -qx "chown -R citrate:citrate $T/node/home/.citrate" && ok "reset: the new data dir is handed to the node user" || bad "reset: the new data dir is handed to the node user" "$(calls)"
[[ "$(stat -c %a "$T/node/home/.citrate")" == 700 ]] && ok "reset: the new data dir is mode 0700 under umask 022" || bad "reset: the new data dir is mode 0700 under umask 022" "$(stat -c '%a' "$T/node/home/.citrate")"
setup_node
expect "reset: --keep-proposer-key carries it" 0 'NOT started' -- "${RNENV[@]}" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --keep-proposer-key --confirm
[[ -f "$T/node/home/.citrate/proposer.key" ]] && ok "reset: proposer.key present with the flag" || bad "reset: proposer.key present with the flag"

setup_node
rm "$T/node/home/.citrate/noise.key"
expect "reset: refuses a node without noise.key" 1 'noise.key is missing' -- "${RNENV[@]}" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
setup_node
expect "reset: refuses a binary with the wrong sha256" 1 'sha256 .* != EXPECTED_BIN_SHA256' -- "${RNENV[@]}" EXPECTED_BIN_SHA256="$(h64 0)" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
[[ -f "$T/node/home/.citrate/chaindata/000001.sst" ]] && ok "reset: a refused run changed nothing" || bad "reset: a refused run changed nothing"
untouched() { # name: binary still old, data dir not archived, nothing replaced
  if grep -q 'echo old' "$T/node/home/bin/citrate-node" && [[ -f "$T/node/home/.citrate/chaindata/000001.sst" ]] &&
    ! ls -d "$T"/node/home/.citrate.pregenesis-* >/dev/null 2>&1; then
    ok "$1"
  else
    bad "$1" "$(ls -A "$T/node/home" "$T/node/home/.citrate")"
  fi
}
setup_node
expect "reset: a node whose stop fails aborts" 1 'stop citrate-node failed' -- "${RNENV[@]}" FAKE_STOP_FAILS=citrate-node bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
untouched "reset: failed node stop leaves binary and data untouched"
setup_node
expect "reset: a node still active after stop aborts" 1 "node service citrate-node is 'active'" -- "${RNENV[@]}" FAKE_STILL_ACTIVE=citrate-node bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
untouched "reset: active node leaves binary and data untouched"
setup_node
reset_calls
expect "reset: a watchdog timer still active aborts" 1 "watchdog timer citrate-height-watchdog.timer is 'active'" -- "${RNENV[@]}" FAKE_STOP_FAILS=citrate-height-watchdog.timer FAKE_STILL_ACTIVE=citrate-height-watchdog.timer bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
untouched "reset: active watchdog timer leaves binary and data untouched"
if ! calls | grep -q 'stop citrate-node$'; then ok "reset: node not stopped while the watchdog is up"; else bad "reset: node not stopped while the watchdog is up" "$(calls)"; fi
setup_node
expect "reset: a running watchdog service aborts" 1 "watchdog service citrate-height-watchdog.service is 'active'" -- "${RNENV[@]}" FAKE_STILL_ACTIVE=citrate-height-watchdog.service bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
untouched "reset: running watchdog service leaves binary and data untouched"
setup_node
expect "reset: a missing watchdog timer (stop fails, inactive) still resets" 0 'NOT started' -- "${RNENV[@]}" FAKE_STOP_FAILS=citrate-height-watchdog.timer bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
setup_node
chmod 000 "$T/node/home/bin/citrate-node"
expect "reset: a binary that cannot be backed up aborts" 1 'cannot back up' -- "${RNENV[@]}" bash "$RN" --coinbase "$NEWCB" --validator-registry "$NEWVR" --activation-height 0 --confirm
chmod 755 "$T/node/home/bin/citrate-node"
untouched "reset: a failed binary backup leaves binary and data untouched"
expect "reset: a malformed coinbase is a usage error" 2 'coinbase must be' -- "${RNENV[@]}" bash "$RN" --coinbase 0x12 --validator-registry "$NEWVR" --activation-height 0

# ------------------------------------------------------------------ ceremony
CE="$G/genesis_ceremony.sh"
REPO="$T/repo"
mkdir -p "$REPO/contracts/script" "$REPO/contracts/genesis" "$REPO/contracts/addresses" "$REPO/scripts/ops"
for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers CheckDeployedAdmins; do : >"$REPO/contracts/script/$s.s.sol"; done
# Fake regenesis.sh: logs what it was given. FAKE_REGEN_BOOK=<file>: also "deploy" by writing
# that file as the generated book (EMIT_OUTPUT), as the real generator does after a broadcast.
# FAKE_REGEN_BCAST=<dir>: and record that dir's forge broadcasts under contracts/broadcast/.
cat >"$REPO/scripts/ops/regenesis.sh" <<'EOF'
#!/usr/bin/env bash
echo "regenesis $*" >>"$FAKE/calls.log"
echo "regenesis-env vg=${VALIDATOR_GOVERNANCE:-} vs=${VALIDATOR_SLASHER:-} gov=${GOVERNANCE:-}" >>"$FAKE/calls.log"
echo "regenesis-treasury ${TREASURY-<unset>}" >>"$FAKE/calls.log"
echo "regenesis-emit fresh=${EMIT_FRESH_GENESIS:-} dep=${EMIT_DEPLOYER:-} since=${EMIT_BROADCAST_SINCE:-} out=${EMIT_OUTPUT:-}" >>"$FAKE/calls.log"
echo "regenesis-deployer dep=${DEPLOYER_ADDRESS-<unset>} ceremony=${CEREMONY_DEPLOYER_ADDRESS-<unset>}" >>"$FAKE/calls.log"
if [[ -n "${FAKE_REGEN_BCAST:-}" ]]; then
  mkdir -p "$(dirname "$0")/../../contracts/broadcast"
  cp -R "$FAKE_REGEN_BCAST"/. "$(dirname "$0")/../../contracts/broadcast/"
fi
[[ "${FAKE_REGEN_FAIL:-}" != 1 ]] || exit 2
if [[ -n "${FAKE_REGEN_BOOK:-}" ]]; then cp "$FAKE_REGEN_BOOK" "$EMIT_OUTPUT"; fi
EOF
DEP=$(addr 1)
printf '{"chainId":40204,"deployer":"%s","contracts":{"Alpha":"%s","Beta":"%s","Vault":"%s"},"aaStack":{},"Vault":"%s"}' "$DEP" "$A1" "$A2" "$A3" "$A3" >"$REPO/contracts/addresses/40204.json"
# gov_book <dir> <deployer> [extra "Name":"0x..." pairs]: a P1-shaped governance output.
# The four addresses come from GTL/RTL/GMS/RMS (defaults 31, 32, 33, 35).
gov_book() {
  printf '{"deployer":"%s","contracts":{"GovernanceTimelock":"%s","GuardianTimelock":"%s","GovernanceMultisig":"%s","GuardianMultisig":"%s"%s}}' \
    "$2" "${GTL:-$(addr 31)}" "${RTL:-$(addr 32)}" "${GMS:-$(addr 33)}" "${RMS:-$(addr 35)}" "${3:+,$3}" >"$1/governance.json"
}
PROPOSER=0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1
# fake_call <addr> <key> <answer>: what `cast call` returns for that address and call.
fake_call() {
  local a; a=$(printf '%s' "$1" | tr 'A-F' 'a-f')
  mkdir -p "$FAKE/call/$a"
  printf '%s\n' "$3" >"$FAKE/call/$a/$2"
}
# council_chain <timelock> <multisig> <delay> <threshold> <owner ids...>: a council as P1
# deploys it (the multisig fronts the timelock and is its proposer).
council_chain() {
  local tl="$1" ms="$2" d="$3" t="$4" i list=""
  shift 4
  for i in "$@"; do list+="${list:+, }$(addr "$i")"; done
  rm -rf "$FAKE/call/$(printf '%s' "$tl" | tr 'A-F' 'a-f')" "$FAKE/call/$(printf '%s' "$ms" | tr 'A-F' 'a-f')"
  fake_call "$tl" getMinDelay "$d [1e5]"
  fake_call "$tl" "hasRole_${PROPOSER}_$(printf '%s' "$ms" | tr 'A-F' 'a-f')" true
  fake_call "$ms" timelock "$tl"
  fake_call "$ms" threshold "$t"
  fake_call "$ms" owners "[$list]"
}
# gov_chain [gtl gms rtl rms]: both councils on chain exactly as CEENV declares them.
gov_chain() {
  council_chain "${1:-$(addr 31)}" "${2:-$(addr 33)}" 172800 3 11 12 13 14 15
  council_chain "${3:-$(addr 32)}" "${4:-$(addr 35)}" 3600 2 21 22 23
}
gov_chain
owners() { local i out=""; for i in "$@"; do out+="${out:+,}$(addr "$i")"; done; printf '%s' "$out"; }
CEENV=(env REPO_ROOT="$REPO" DEPLOYER_ADDRESS="$DEP"
  GOV_OWNERS="$(owners 11 12 13 14 15)" GOV_THRESHOLD=3 GOV_MIN_DELAY=172800
  GRD_OWNERS="$(owners 21 22 23)" GRD_THRESHOLD=2 GRD_MIN_DELAY=3600
  SIGNER_1="$(addr 61)" SIGNER_2="$(addr 62)" SIGNER_3="$(addr 63)" RELAYER="$(addr 64)"
  CITRATE_AA_OWNER="$(addr 65)" CITRATE_AA_IDENTITY_SIGNER="$(addr 66)" CITRATE_AA_SPONSOR_SIGNER="$(addr 67)"
  MEMBERSHIP_OWNER="$(addr 68)" TREASURY="$(addr 90)")

reset_calls
expect "ceremony: dry run with genesis values passes" 0 'done \(mode=dry\)' -- "${CEENV[@]}" bash "$CE"
expect "ceremony: dry run plans the governance deploy" 0 'DRYRUN .*DeployGenesisGovernance' -- "${CEENV[@]}" bash "$CE"
expect "ceremony: dry run plans the admin gate" 0 'DRYRUN .*CheckDeployedAdmins' -- "${CEENV[@]}" bash "$CE"
if calls | grep -q .; then bad "ceremony: dry run made no tool call" "$(calls)"; else ok "ceremony: dry run made no tool call"; fi
expect "ceremony: governance 2-of-5 is below the floor" 3 'GOV threshold 2 is below' -- "${CEENV[@]}" GOV_THRESHOLD=2 bash "$CE"
expect "ceremony: governance with 4 holders is refused" 3 'GOV has 4 distinct owners' -- "${CEENV[@]}" GOV_OWNERS="$(owners 11 12 13 14)" bash "$CE"
expect "ceremony: a duplicated holder does not count twice" 3 'GOV has 4 distinct owners' -- "${CEENV[@]}" GOV_OWNERS="$(owners 11 12 13 14 14)" bash "$CE"
expect "ceremony: a 24 h governance delay is refused" 3 'GOV delay 86400s is below' -- "${CEENV[@]}" GOV_MIN_DELAY=86400 bash "$CE"
expect "ceremony: guardian 1-of-3 is refused" 3 'GRD threshold 1 is below' -- "${CEENV[@]}" GRD_THRESHOLD=1 bash "$CE"
expect "ceremony: proposal TTL other than 14 days is refused on 40204" 3 'must be 1209600' -- "${CEENV[@]}" GOV_PROPOSAL_TTL=604800 bash "$CE"
expect "ceremony: a rehearsal chain may use other floors" 0 'done \(mode=dry\)' -- "${CEENV[@]}" EXPECTED_CHAIN_ID=31337 GOV_OWNERS="$(owners 11 12 13)" GOV_THRESHOLD=2 GOV_MIN_DELAY=7200 GOV_PROPOSAL_TTL=86400 bash "$CE"
expect "ceremony: guardian delay must be shorter than governance" 3 'GUARDIAN delay must be shorter' -- "${CEENV[@]}" GRD_MIN_DELAY=172800 bash "$CE"
expect "ceremony: a holder on both councils is refused" 3 'sits on both' -- "${CEENV[@]}" GRD_OWNERS="$(owners 11 22 23)" bash "$CE"
expect "ceremony: the deployer on a council is refused" 3 'deployer must not hold' -- "${CEENV[@]}" GRD_OWNERS="$(owners 1 22 23)" bash "$CE"
expect "ceremony: --private-key is refused" 1 'raw private keys are refused' -- "${CEENV[@]}" bash "$CE" --private-key 0xabc
expect "ceremony: a raw key in the environment is refused" 1 'PRIVATE_KEY is set' -- "${CEENV[@]}" PRIVATE_KEY=x bash "$CE"
# The keystore password file: a regular file of the user running the ceremony, private to that
# user (no group or world bits), in a directory no other user can write. Checked on lstat, so
# a symlink is refused rather than followed. The path is never echoed and the file never read.
PWD_DIR="$T/pw"
mkdir -p "$PWD_DIR"
chmod 700 "$PWD_DIR"
pwfile() { # <name> <mode>: a password file with that mode
  (umask 077 && printf 'not-a-real-password\n' >"$PWD_DIR/$1")
  chmod "$2" "$PWD_DIR/$1"
  printf '%s' "$PWD_DIR/$1"
}
PW_OK=$(pwfile ok 600)
expect "ceremony: a private password file (0600) is accepted" 0 'done \(mode=dry\)' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PW_OK"
expect "ceremony: a read-only private password file (0400) is accepted" 0 'done \(mode=dry\)' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$(pwfile ro 400)"
for m in 640 604 620 602 660 644 666; do
  expect "ceremony: a password file with mode 0$m is refused" 1 '--password-file must not be readable or writable by group or others' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$(pwfile "m$m" "$m")"
done
ln -s "$PW_OK" "$PWD_DIR/link"
expect "ceremony: a password file given as a symlink is refused" 1 '--password-file must not be a symlink' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/link"
ln -s "$PWD_DIR/missing" "$PWD_DIR/dangling"
expect "ceremony: a dangling symlink as the password file is refused" 1 '--password-file must not be a symlink' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/dangling"
expect "ceremony: a missing password file is refused" 1 '--password-file must name an existing regular file' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/missing"
expect "ceremony: a directory as the password file is refused" 1 '--password-file must name an existing regular file' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR"
mkfifo "$PWD_DIR/fifo" && chmod 600 "$PWD_DIR/fifo"
expect "ceremony: a FIFO as the password file is refused" 1 '--password-file must name an existing regular file' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/fifo"
# Another user's file: stat only, never read or written. A root-owned file stands in for it
# (the shell binary); when the suite itself runs as root there is no other owner to try.
OTHER=$(python3 -c 'import os,shutil,sys; p=os.path.realpath(shutil.which("sh")); print(p if os.lstat(p).st_uid != os.geteuid() else "")')
if [[ -n "$OTHER" ]]; then
  expect "ceremony: a password file owned by another user is refused" 1 '--password-file must be owned by the user running the ceremony' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$OTHER"
else
  printf 'SKIP ceremony: a password file owned by another user (the suite runs as root)\n'
fi
# The directory: another user who can write it could swap the file between the check and its
# use. A sticky world-writable directory (like /tmp) stops that; a plain one does not.
mkdir -p "$PWD_DIR/open" "$PWD_DIR/sticky" "$PWD_DIR/grp"
chmod 777 "$PWD_DIR/open"; chmod 1777 "$PWD_DIR/sticky"; chmod 770 "$PWD_DIR/grp"
(umask 077 && printf 'x\n' >"$PWD_DIR/open/pw" && printf 'x\n' >"$PWD_DIR/sticky/pw" && printf 'x\n' >"$PWD_DIR/grp/pw")
expect "ceremony: a password file in a world-writable directory is refused" 1 '--password-file must sit in a directory only its owner can change' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/open/pw"
expect "ceremony: a password file in a group-writable directory is refused" 1 '--password-file must sit in a directory only its owner can change' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/grp/pw"
expect "ceremony: a password file in a sticky world-writable directory is accepted" 0 'done \(mode=dry\)' -- "${CEENV[@]}" bash "$CE" --account deployer --password-file "$PWD_DIR/sticky/pw"
chmod 700 "$PWD_DIR/open" "$PWD_DIR/sticky" "$PWD_DIR/grp"
# Tripwire: every script under scripts/genesis/ and scripts/ops/ that takes --password-file runs
# it through the shared check (password_file_check or secret_file_check.py). Negative control: a
# script that takes the flag and only tests -f is flagged.
pwfile_unchecked() { # <file...>: prints each file that parses --password-file without the check
  local f
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    if grep -qE -- '--password-file\)' "$f" && ! grep -qE 'password_file_check|secret_file_check\.py' "$f"; then
      printf '%s\n' "$f"
    fi
  done
}
mkdir -p "$T/tw"
printf '#!/usr/bin/env bash\ncase "$1" in\n  --password-file) PF="$2"; shift 2 ;;\nesac\n[[ -f "$PF" ]] || exit 1\n' >"$T/tw/unchecked.sh"
printf '#!/usr/bin/env bash\ncase "$1" in\n  --password-file) PF="$2"; shift 2 ;;\nesac\nPF_ID=$(password_file_check "$PF") || exit 1\n' >"$T/tw/checked.sh"
if [[ "$(pwfile_unchecked "$T/tw/unchecked.sh" "$T/tw/checked.sh")" == "$T/tw/unchecked.sh" ]]; then
  ok "tripwire: a script that takes --password-file without the shared check is flagged (negative control)"
else
  bad "tripwire: a script that takes --password-file without the shared check is flagged (negative control)" "$(pwfile_unchecked "$T/tw/unchecked.sh" "$T/tw/checked.sh")"
fi
tw=$(pwfile_unchecked "$G"/*.sh "$G/../ops"/*.sh)
if [[ -z "$tw" ]]; then
  ok "tripwire: every genesis/ops script that takes --password-file runs the shared check"
else
  bad "tripwire: every genesis/ops script that takes --password-file runs the shared check" "$tw"
fi
# A refusal names neither the path nor the content.
out=$("${CEENV[@]}" bash "$CE" --account deployer --password-file "$(pwfile leak 644)" 2>&1)
if grep -qF "$PWD_DIR" <<<"$out" || grep -qF 'not-a-real-password' <<<"$out"; then
  bad "ceremony: a refused password file is not echoed (path or content)" "$out"
else
  ok "ceremony: a refused password file is not echoed (path or content)"
fi
expect "ceremony: --confirm needs a keystore account" 3 'needs --account' -- "${CEENV[@]}" bash "$CE" --confirm
expect "ceremony: --confirm to a remote RPC needs CITRATE_ALLOW_REMOTE" 3 'not loopback' -- "${CEENV[@]}" RPC_URL=https://rpc.example EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --account deployer
expect "ceremony: missing genesis contract scripts are named" 3 'chain#320' -- "${CEENV[@]}" REPO_ROOT="$T/empty-repo" bash "$CE"
expect "ceremony: an unknown phase is refused" 1 'must be one of' -- "${CEENV[@]}" bash "$CE" --from P9
# Tripwire: every environment key a ceremony phase reads (derived from the ceremony,
# regenesis.sh and the forge scripts each phase runs) is classified in phase_inputs.json, which
# P0 checks. Negative controls on a copy of the tree: each kind of drift is caught.
PI="$G/phase_inputs.py"
expect "phase inputs tripwire: the tree's phase reads are all classified" 0 'phase_inputs: OK' -- python3 -I "$PI" check-spec
TW="$T/pi-tree"
mkdir -p "$TW/scripts/genesis" "$TW/scripts/ops" "$TW/contracts"
cp "$G/genesis_ceremony.sh" "$TW/scripts/genesis/"
cp "$G/../ops/regenesis.sh" "$TW/scripts/ops/"
cp -R "$G/../../contracts/script" "$TW/contracts/script"
cp "$G/phase_inputs.json" "$T/pi-spec.json"
# shellcheck disable=SC2120 # the spec argument is passed through expect's "$@"
pi_tw() { python3 -I "$PI" check-spec --repo "$TW" --spec "${1:-$T/pi-spec.json}"; }
expect "phase inputs tripwire: the copied tree passes (control)" 0 'phase_inputs: OK' -- pi_tw
cp "$TW/contracts/script/DeployEduStack.s.sol" "$T/edu.orig"
sed -i 's|^\(\s*\)address relayer = |\1address extra = vm.envAddress("NEW_EDU_INPUT");\n\1address relayer = |' "$TW/contracts/script/DeployEduStack.s.sol"
expect "phase inputs tripwire: a new literal read in a P2 script is flagged" 1 'NEW_EDU_INPUT is read \(P2: contracts/script/DeployEduStack.s.sol\) but phase_inputs.json does not classify it' -- pi_tw
cp "$T/edu.orig" "$TW/contracts/script/DeployEduStack.s.sol"
cat >>"$TW/contracts/script/DeployEduStack.s.sol" <<'SOL'
contract EnvHelpers is ScriptEnv {
    function _need(string memory k) internal view returns (address) { return vm.envAddress(k); }
    function _pair(string memory prefix) internal view returns (uint256) { return vm.envUint(string.concat(prefix, "_LIMIT")); }
    function use() external view returns (address a, uint256 n) { a = _need("WRAPPED_INPUT"); n = _pair("PFX"); }
}
SOL
out=$(pi_tw 2>&1)
if [[ $? -eq 1 ]] && grep -q 'WRAPPED_INPUT is read' <<<"$out" && grep -q 'PFX_LIMIT is read' <<<"$out"; then
  ok "phase inputs tripwire: a read through a helper, and a prefixed key, are flagged"
else
  bad "phase inputs tripwire: a read through a helper, and a prefixed key, are flagged" "$out"
fi
cp "$T/edu.orig" "$TW/contracts/script/DeployEduStack.s.sol"
cat >>"$TW/contracts/script/DeployEduStack.s.sol" <<'SOL'
contract EnvDynamic is ScriptEnv {
    function pick(uint256 i) external view returns (address) { string[2] memory ks = ["A", "B"]; return vm.envAddress(ks[i]); }
}
SOL
expect "phase inputs tripwire: a dynamic key is flagged" 1 'reads an environment key P0 cannot check: ks\[i\]' -- pi_tw
cp "$T/edu.orig" "$TW/contracts/script/DeployEduStack.s.sol"
jq '.inputs.OLD_INPUT = {"class": "default", "phases": ["P2"], "why": "x"}' "$G/phase_inputs.json" >"$T/pi-stale.json"
expect "phase inputs tripwire: a spec entry no phase reads is flagged" 1 'OLD_INPUT is in phase_inputs.json but no phase reads it' -- pi_tw "$T/pi-stale.json"
# TREASURY is read by DeployAll once chain#396 is in the tree; until then its entry names that
# reader (pending_reader). Without the field the unread entry is stale; once the reader reads
# it, the field itself is flagged so it is dropped.
python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); del s["inputs"]["TREASURY"]["pending_reader"]; json.dump(s, open(sys.argv[2], "w"))' "$T/pi-spec.json" "$T/pi-nopending.json"
if ! grep -q 'vm.env[A-Za-z]*("TREASURY"\|requiredTreasury("TREASURY"' "$TW/contracts/script/DeployAll.s.sol"; then
  expect "phase inputs tripwire: an unread entry without pending_reader is stale (control)" 1 'TREASURY is in phase_inputs.json but no phase reads it' -- pi_tw "$T/pi-nopending.json"
  cp "$TW/contracts/script/DeployAll.s.sol" "$T/deployall.orig"
  sed -i '0,/^\(\s*\)address deployer = deployerAddress();/s//&\n\1address t0 = vm.envAddress("TREASURY");/' "$TW/contracts/script/DeployAll.s.sol"
  grep -q 'vm.envAddress("TREASURY")' "$TW/contracts/script/DeployAll.s.sol" || bad "phase inputs tripwire: the TREASURY read was planted in the copied DeployAll (setup)"
  expect "phase inputs tripwire: a pending_reader whose script now reads the key is flagged" 1 'TREASURY: pending_reader .* but the scripts now read it' -- pi_tw
  expect "phase inputs tripwire: with the reader in place the entry needs no pending_reader (control)" 0 'phase_inputs: OK' -- pi_tw "$T/pi-nopending.json"
  cp "$T/deployall.orig" "$TW/contracts/script/DeployAll.s.sol"
else
  ok "phase inputs tripwire: DeployAll reads TREASURY in this tree; pending_reader cases not applicable"
fi
jq '.inputs.SIGNER_1.phases = ["P3"]' "$G/phase_inputs.json" >"$T/pi-phase.json"
expect "phase inputs tripwire: a wrong phase list is flagged" 1 "SIGNER_1: phase_inputs.json says phases \['P3'\], the scripts read it in \['P2'\]" -- pi_tw "$T/pi-phase.json"
jq '.inputs.SIGNER_1.class = "p0-bash"' "$G/phase_inputs.json" >"$T/pi-bash.json"
expect "phase inputs tripwire: a p0-bash key P0 never names is flagged" 1 'SIGNER_1 is classed p0-bash but the P0 section' -- pi_tw "$T/pi-bash.json"
jq '.inputs.SIGNER_1.class = "set"' "$G/phase_inputs.json" >"$T/pi-set.json"
expect "phase inputs tripwire: a set key nothing assigns is flagged" 1 'SIGNER_1 is classed set but neither' -- pi_tw "$T/pi-set.json"
mv "$TW/contracts/script/DeployAIGateway.s.sol" "$T/aig.aside"
expect "phase inputs tripwire: a P2 step whose script is missing is flagged" 1 'P2 runs contracts/script/DeployAIGateway.s.sol, which is missing' -- pi_tw
mv "$T/aig.aside" "$TW/contracts/script/DeployAIGateway.s.sol"
rm -r "$TW"

# simulate: P5 reads the admin report
mkdir -p "$(rpcdir http://127.0.0.1:8545)"
LRPC="$(rpcdir http://127.0.0.1:8545)"
echo 40204 >"$LRPC/chain-id"
echo "$GEN" >"$LRPC/block-0"
echo 5000 >"$LRPC/block-0-timestamp"
GB="$REPO/contracts/genesis"
# mk_manifest <outdir> [deployer] [mode] [account] [genesis] [g0ts]: the record a fresh run
# writes at P0, for the local fake RPC.
mk_manifest() {
  printf '{"version":1,"runId":"test-run","mode":"%s","chainId":40204,"genesisHash":"%s","block0Timestamp":%s,"deployer":"%s","account":"%s"}\n' \
    "${3:-simulate}" "${5:-$GEN}" "${6:-5000}" "${2:-$DEP}" "${4:-}" >"$1/ceremony-run.json"
}
expect "ceremony: a resume needs the run manifest" 3 'run manifest: .*ceremony-run.json is missing' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
printf '{"runId":"x"' >"$GB/ceremony-run.json"
expect "ceremony: a malformed run manifest fails" 3 'run manifest: cannot read' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
printf '{"runId":"x","mode":"simulate","chainId":40204,"genesisHash":"%s","block0Timestamp":5000,"account":""}' "$GEN" >"$GB/ceremony-run.json"
expect "ceremony: a run manifest without a deployer fails" 3 'deployer is missing or malformed' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
mk_manifest "$GB"
expect "ceremony: P5 needs P1's governance output" 3 'governance.json missing' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
gov_book "$GB" "$DEP"
expect "ceremony: P5 passes at DEPLOYER-ADMIN 0" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony: P5 fails while the deployer holds a role" 3 'DEPLOYER-ADMIN is not 0' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_DEPLOYER_ADMIN=2 bash "$CE" --simulate --only P5
# The checker reads one book: every ceremony output's contracts must be in it. Before the
# merge, P5 passed the outputs through EXTRA_ADDRESS_BOOKS, which the checker never read, so
# a role still held on a contract that only a ceremony output lists passed the gate.
reset_calls
expect "ceremony: P5 sweeps the governance output" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
calls | grep -q '^forge-book genesis/p5-admin-book.json$' && ok "ceremony: P5 hands the checker the merged book" || bad "ceremony: P5 hands the checker the merged book" "$(calls)"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["contracts"]; sys.exit(0 if {"Alpha","Beta","GovernanceTimelock","GuardianTimelock","GovernanceMultisig"} <= set(c) else 1)' "$GB/p5-admin-book.json" &&
  ok "ceremony: the merged book holds the book and governance contracts" || bad "ceremony: the merged book holds the book and governance contracts" "$(cat "$GB/p5-admin-book.json")"
expect "ceremony: P5 fails a deployer role held in the governance output" 3 'DEPLOYER-ADMIN GovernanceMultisig' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_DEPLOYER_HELD=GovernanceMultisig bash "$CE" --simulate --only P5
printf '{"deployer":"%s","contracts":{"VestingAlice":"%s"}}' "$DEP" "$(addr 71)" >"$GB/team-vesting.json"
printf '{"deployer":"%s","contracts":{"FederatedRoundLedger":"%s","PatronageLedger":"%s"}}' "$DEP" "$(addr 81)" "$(addr 82)" >"$GB/dormant-ledgers.json"
expect "ceremony: P5 fails a deployer role held in the vesting output" 3 'DEPLOYER-ADMIN VestingAlice' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_DEPLOYER_HELD=VestingAlice bash "$CE" --simulate --only P5
expect "ceremony: P5 fails a deployer role held in the dormant-ledger output" 3 'DEPLOYER-ADMIN PatronageLedger' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_DEPLOYER_HELD=PatronageLedger bash "$CE" --simulate --only P5
expect "ceremony: P5 refuses an output from another deployer" 3 "names deployer '0x0+9', not this run's deployer" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash -c "printf '{\"deployer\":\"%s\",\"contracts\":{\"VestingAlice\":\"%s\"}}' '$(addr 9)' '$(addr 71)' > '$GB/team-vesting.json'; bash '$CE' --simulate --only P5"
printf '{"deployer":"%s","contracts":{"Alpha":"%s"}}' "$DEP" "$(addr 71)" >"$GB/team-vesting.json"
mk_manifest "$GB"
expect "ceremony: P5 refuses an output that shadows a book name" 3 'cannot build the merged admin book' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
printf '{"deployer":"%s","contracts":{}}' "$DEP" >"$GB/team-vesting.json"
mk_manifest "$GB"
expect "ceremony: P5 refuses an output with no contracts" 3 'team-vesting.json has no well-formed contracts' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
rm "$GB/team-vesting.json" "$GB/dormant-ledgers.json"
expect "ceremony: a simulation's manifest does not serve a --confirm resume" 3 "run manifest: .*mode 'simulate' \(this run: 'confirm'\)" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P5 --account deployer
mk_manifest "$GB" "$DEP" confirm deployer
expect "ceremony: --confirm P5 needs every ceremony output" 3 'team-vesting.json missing' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P5 --account deployer
expect "ceremony: a resume with another keystore account is refused" 3 "account 'deployer' \(this run: 'other'\)" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P5 --account other
mk_manifest "$GB"
# The deployer P5 checks is the run's, from the manifest. Stale books that agree with each
# other on deployer A while this run (manifest and DEPLOYER_ADDRESS) used B are refused, so
# the checker never sweeps for A while B may still hold a role.
DEPB=$(addr 2)
mk_manifest "$GB" "$DEPB"
reset_calls
expect "ceremony: consistent books naming another deployer than the run's fail P5" 3 "names deployer 0x0+1, not this run's deployer 0x0+2" -- "${CEENV[@]}" DEPLOYER_ADDRESS="$DEPB" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
if calls | grep -q CheckDeployedAdmins; then bad "ceremony: a deployer mismatch runs no checker" "$(calls)"; else ok "ceremony: a deployer mismatch runs no checker"; fi
expect "ceremony: a resume with another DEPLOYER_ADDRESS than the manifest is refused" 3 "run manifest: .*deployer '0x0+2' \(this run: '0x0+1'\)" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
gov_book "$GB" "$DEPB"
expect "ceremony: an extra book matching the run but not the canonical book still fails" 3 "addresses/40204.json names deployer 0x0+1, not this run's deployer 0x0+2" -- "${CEENV[@]}" DEPLOYER_ADDRESS="$DEPB" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
gov_book "$GB" "$DEP"
mk_manifest "$GB"
expect "ceremony: a manifest from another genesis is refused" 3 'genesisHash' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash -c "echo 0x$(h64 9) > '$LRPC/block-0'; bash '$CE' --simulate --only P5; rc=\$?; echo '$GEN' > '$LRPC/block-0'; exit \$rc"
# P5 reads one summary per class: a repeated or missing summary is not a pass.
expect "ceremony: a checker report with no DEPLOYER-ADMIN summary fails" 3 'no single DEPLOYER-ADMIN summary' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_REPORT_DROP=DEPLOYER bash "$CE" --simulate --only P5
expect "ceremony: a checker report with two FACTORY-ADMIN summaries fails" 3 'no single FACTORY-ADMIN summary' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_REPORT_DUP=FACTORY bash "$CE" --simulate --only P5
expect "ceremony: P0 checks the RPC chain id" 3 'chain id 1, want 40204' -- "${CEENV[@]}" RPC_URL=http://n3x bash -c "mkdir -p '$(rpcdir http://n3x)'; echo 1 > '$(rpcdir http://n3x)/chain-id'; bash '$CE' --simulate --only P0"
reset_calls
expect "ceremony: P2 takes governance from P1's output" 0 'GOVERNANCE=0x0+1f GUARDIAN=0x0+20' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
calls | grep -q 'regenesis --reroll --with-aa$' && ok "ceremony: simulate does not broadcast" || bad "ceremony: simulate does not broadcast" "$(calls)"

# Resume paths: the safety preflight runs before any phase that talks to a chain.
expect "ceremony: --confirm --from P1 to a remote RPC is refused" 3 'not loopback' -- "${CEENV[@]}" RPC_URL=https://rpc.example EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --from P1 --account deployer
expect "ceremony: --confirm --only P2 without --account is refused" 3 'needs --account' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --confirm --only P2
expect "ceremony: --simulate --from P1 checks the chain id" 3 'chain id 1, want 40204' -- "${CEENV[@]}" RPC_URL=http://n3x bash "$CE" --simulate --from P1
echo "0x$(h64 f)" >"$LRPC/block-0"
expect "ceremony: --simulate --only P3 checks the genesis hash" 3 'block 0 is 0x[f]+, want' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" bash "$CE" --simulate --only P3
echo "$GEN" >"$LRPC/block-0"
expect "ceremony: --simulate --from P4 checks the council floors" 3 'GOV threshold 2 is below' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GOV_THRESHOLD=2 bash "$CE" --simulate --from P4
expect "ceremony: --simulate --only P2 checks the deployer seat" 3 'deployer must not hold' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GRD_OWNERS="$(owners 1 22 23)" bash "$CE" --simulate --only P2
echo 5 >"$LRPC/nonce"
expect "ceremony: a resume does not require deployer nonce 0" 0 'P0 preflight PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony: a fresh ceremony requires deployer nonce 0" 3 'deployer nonce is 5' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate
# A deployer that has sent is not a fresh ceremony: the hint never says --from P0 (that is the
# fresh run that just refused).
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate 2>&1)
if grep -q 'never start a fresh ceremony over them' <<<"$out" && ! grep -qF -- '--from P0' <<<"$out"; then
  ok "ceremony: a non-zero deployer nonce names a resume, never --from P0"
else
  bad "ceremony: a non-zero deployer nonce names a resume, never --from P0" "$out"
fi
rm "$LRPC/nonce"
# P0 checks every input a later phase of this run reads (phase_inputs.json), before anything is
# sent. Before, P2's inputs (vault signers, relayer, AA owner and signers, membership owner)
# were read only by the forge steps inside regenesis.sh: a missing one stopped P2 after its
# earlier steps had broadcast, and P2 cannot be re-run (C10).
P0FRESH="$REPO/contracts/genesis/p0fresh"
mkdir -p "$P0FRESH"
reset_calls
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$P0FRESH" SIGNER_1= bash "$CE" --simulate 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P0: phase inputs: .*SIGNER_1 is not set' <<<"$out" && ! calls | grep -q '^forge\|^regenesis' && [[ ! -e "$P0FRESH/ceremony-run.json" ]]; then
  ok "ceremony P0 inputs: a missing P2 input stops a fresh run at P0, before P1 (no forge, no manifest)"
else
  bad "ceremony P0 inputs: a missing P2 input stops a fresh run at P0, before P1 (no forge, no manifest) (exit $rc)" "$out
$(calls)"
fi
rm -rf "$P0FRESH"
for v in SIGNER_1 SIGNER_2 SIGNER_3 RELAYER CITRATE_AA_OWNER CITRATE_AA_IDENTITY_SIGNER CITRATE_AA_SPONSOR_SIGNER "${P2_MEMBERSHIP_INPUT:-MEMBERSHIP_OWNER}"; do
  expect "ceremony P0 inputs: P2 without $v is refused at P0" 3 "GATE FAIL at P0: phase inputs: .*$v is not set" -- "${CEENV[@]}" "$v=" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
done
# --confirm: refused at P0 before anything is sent, with the resume of this invocation.
reset_calls
out=$("${CEENV[@]}" RELAYER= RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P2 --account deployer 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P0: phase inputs: .*RELAYER is not set' <<<"$out" && grep -qF -- '--confirm --only P2 --account deployer' <<<"$out" &&
  ! grep -qF -- '--from P0' <<<"$out" && ! calls | grep -q '^forge\|^regenesis'; then
  ok "ceremony P0 inputs: --confirm P2 without RELAYER sends nothing and names this invocation's resume (--only P2)"
else
  bad "ceremony P0 inputs: --confirm P2 without RELAYER sends nothing and names this invocation's resume (--only P2) (exit $rc)" "$out
$(calls)"
fi
expect "ceremony P0 inputs: the three vault signers must be distinct" 3 'SIGNER_1, SIGNER_2, SIGNER_3 must be distinct' -- "${CEENV[@]}" SIGNER_2="$(addr 61)" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: a vault signer that is the deployer is refused" 3 'SIGNER_3 .* is the deployer' -- "${CEENV[@]}" SIGNER_3="$DEP" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: the sponsor signer is not the identity signer" 3 'CITRATE_AA_IDENTITY_SIGNER, CITRATE_AA_SPONSOR_SIGNER must be distinct' -- "${CEENV[@]}" CITRATE_AA_SPONSOR_SIGNER="$(addr 66)" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: a malformed relayer is refused" 3 'RELAYER \(0x12\) is not an address' -- "${CEENV[@]}" RELAYER=0x12 RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: a zero AA owner is refused" 3 'CITRATE_AA_OWNER is the zero address' -- "${CEENV[@]}" CITRATE_AA_OWNER=0x0000000000000000000000000000000000000000 RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: an EntryPoint pin is refused (deployed at its projected address)" 3 'CITRATE_AA_ENTRY_POINT is set; a genesis ceremony runs without it' -- "${CEENV[@]}" CITRATE_AA_ENTRY_POINT="$(addr 70)" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: a P-256 init-code override is refused" 3 'P256_VERIFIER_INITCODE is set' -- "${CEENV[@]}" P256_VERIFIER_INITCODE=0x00 RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
expect "ceremony P0 inputs: a malformed optional cap is refused" 3 'CITRATE_AA_DAILY_CAP \(lots\) is not an unsigned integer' -- "${CEENV[@]}" CITRATE_AA_DAILY_CAP=lots RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
# Negative controls: a run that does not reach P2 does not need P2's inputs, and a dry run
# plans without them, naming what a real run will refuse.
expect "ceremony P0 inputs: --only P5 does not need P2's inputs" 0 'P0 preflight PASS' -- "${CEENV[@]}" SIGNER_1= RELAYER= RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony P0 inputs: a dry run plans without them and names them" 0 'P0 plan: .*SIGNER_1 is not set' -- "${CEENV[@]}" SIGNER_1= bash "$CE"
# P4's PATRONAGE_* inputs exist only after P1 (deployed under GOVERNANCE): a run that starts
# at P4 needs them at P0; a fresh run is checked at P4, before P4 sends.
expect "ceremony P0 inputs: --from P4 needs P4's inputs at P0, and the resume is --from P4" 3 'GATE FAIL at P0: phase inputs: .*PATRONAGE_KYC_REGISTRY is not set' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --from P4
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --from P4 2>&1)
if grep -qF -- 'resume: '"$CE"' --simulate --from P4' <<<"$out" && ! grep -qF -- '--from P0' <<<"$out"; then
  ok "ceremony P0 inputs: a P0 refusal on a resume names that resume, not --from P0"
else
  bad "ceremony P0 inputs: a P0 refusal on a resume names that resume, not --from P0" "$out"
fi
P0FRESH="$REPO/contracts/genesis/p0fresh"
mkdir -p "$P0FRESH"
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$P0FRESH" bash "$CE" --simulate 2>&1)
if grep -q 'P0 preflight PASS' <<<"$out" && ! grep -q 'GATE FAIL at P0' <<<"$out"; then
  ok "ceremony P0 inputs: a fresh run does not need P4's late inputs at P0"
else
  bad "ceremony P0 inputs: a fresh run does not need P4's late inputs at P0" "$out"
fi
rm -rf "$P0FRESH"
# A fresh run refuses to start over an earlier run's manifest, and writes its own at P0.
expect "ceremony: a fresh run refuses an existing run manifest" 3 'ceremony-run.json already exists' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$GB" bash -c "mv '$GB/governance.json' '$T/gov.aside'; bash '$CE' --simulate; rc=\$?; mv '$T/gov.aside' '$GB/governance.json'; exit \$rc"
FRESH="$REPO/contracts/genesis/fresh"
mkdir -p "$FRESH"
expect "ceremony: a fresh run writes the manifest at P0" 3 'P0 bound to run [0-9TZ]+-[0-9]+ \(deployer 0x0+1\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$FRESH" bash "$CE" --simulate
if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if (m["deployer"],m["mode"],m["chainId"],m["block0Timestamp"],m["genesisHash"])==(sys.argv[2],"simulate",40204,5000,sys.argv[3]) else 1)' "$FRESH/ceremony-run.json" "$DEP" "$GEN"; then
  ok "ceremony: the manifest records the run's deployer, chain and block 0"
else
  bad "ceremony: the manifest records the run's deployer, chain and block 0" "$(cat "$FRESH/ceremony-run.json" 2>&1)"
fi
rm -r "$FRESH"

# P6 integration: the genesis replay's own broadcasts (deployments at the pinned addresses,
# recorded after block 0) pass; a stale run from an earlier chain on the same id is ignored.
mkdir -p "$REPO/contracts/broadcast/Regenesis.s.sol/40204" "$REPO/contracts/broadcast/Old.s.sol/40204"
printf '{"timestamp":6000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$A1" >"$REPO/contracts/broadcast/Regenesis.s.sol/40204/run-latest.json"
printf '{"timestamp":100,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$REPO/contracts/broadcast/Old.s.sol/40204/run-latest.json"
expect "ceremony: P6 passes the genesis deployments at their pins" 0 'KEEP gate PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
printf '{"timestamp":7000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$REPO/contracts/broadcast/Old.s.sol/40204/run-latest.json"
expect "ceremony: P6 fails a post-genesis redeploy away from the pin" 3 'keep_check failed' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
# P6 scopes its evidence with the manifest's block-0 timestamp: an earlier run's redeploy
# kept only in a timestamped record is still found.
printf '{"timestamp":6500,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$REPO/contracts/broadcast/Regenesis.s.sol/40204/run-6500.json"
printf '{"timestamp":100,"transactions":[]}' >"$REPO/contracts/broadcast/Old.s.sol/40204/run-latest.json"
expect "ceremony: P6 fails a redeploy kept only in a timestamped record" 3 'keep_check failed' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
rm "$REPO/contracts/broadcast/Regenesis.s.sol/40204/run-6500.json"
mv "$LRPC/block-0-timestamp" "$T/g0ts.aside"
expect "ceremony: P0 needs the block-0 timestamp" 3 'block-0 timestamp' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
mv "$T/g0ts.aside" "$LRPC/block-0-timestamp"

# P7 checks the fleet against THIS run's block 0, not just against the first endpoint.
mk_node http://n4 40204 100 "0x$(h64 d)" "$TIP"
mk_node http://n5 40204 100 "0x$(h64 d)" "$TIP"
expect "ceremony: P7 fails a fleet that agrees on another genesis than the run's" 3 'n4 genesis 0x[d]+ differs from 0x[a]+' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FLEET_RPCS=http://n4,http://n5 bash "$CE" --simulate --only P7
expect "ceremony: P7 passes a fleet on the run's genesis" 0 'FLEET AGREE' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FLEET_RPCS=http://n1,http://n2 bash "$CE" --simulate --only P7

# ---------------------------------------------------------------- round-6 invariants (C2-C6)
# C4 (Codex r6 on chain#329): a stale VALIDATOR_GOVERNANCE in the ceremony environment used to
# override P1's GOVERNANCE, so DeployValidatorRegistry made that EOA the registry's governance,
# and P5 (factory + deployer only) still passed.
mk_manifest "$GB"
gov_book "$GB" "$DEP"
gov_chain
STALE=$(addr 99)
reset_calls
expect "ceremony C4: a conflicting VALIDATOR_GOVERNANCE is refused before P2 runs" 3 "VALIDATOR_GOVERNANCE is set to 0x0+63, but this run's governance is 0x0+1f" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 VALIDATOR_GOVERNANCE="$STALE" bash "$CE" --simulate --only P2
if calls | grep -q '^regenesis'; then bad "ceremony C4: a refused P2 runs no regenesis" "$(calls)"; else ok "ceremony C4: a refused P2 runs no regenesis"; fi
expect "ceremony C4: a conflicting VALIDATOR_SLASHER is refused" 3 'VALIDATOR_SLASHER is set to' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 VALIDATOR_SLASHER="$STALE" bash "$CE" --simulate --only P2
expect "ceremony C4: a conflicting GOVERNANCE preset is refused" 3 'GOVERNANCE is set to 0x0+63, but this run' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GOVERNANCE="$STALE" bash "$CE" --simulate --only P2
reset_calls
expect "ceremony C4: a matching preset is accepted" 0 'done \(mode=simulate\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 VALIDATOR_GOVERNANCE="$(addr 31 | tr 'a-f' 'A-F' | sed 's/^0X/0x/')" bash "$CE" --simulate --only P2
calls | grep -q "^regenesis-env vg=$(addr 31) vs=$(addr 31) gov=$(addr 31)$" && ok "ceremony C4: regenesis gets VALIDATOR_GOVERNANCE and VALIDATOR_SLASHER = GOVERNANCE" ||
  bad "ceremony C4: regenesis gets VALIDATOR_GOVERNANCE and VALIDATOR_SLASHER = GOVERNANCE" "$(calls)"
# C8 (Codex 527c80b): the generator regenesis.sh runs gets this run's deployer, block 0 and book
# path in fresh-genesis mode; a preset that says otherwise stops P2 before anything is sent.
calls | grep -q "^regenesis-emit fresh=1 dep=$DEP since=5000 out=$REPO/contracts/addresses/40204.json$" &&
  ok "ceremony C8: regenesis gets the fresh-genesis generator inputs from the run manifest" ||
  bad "ceremony C8: regenesis gets the fresh-genesis generator inputs from the run manifest" "$(calls)"
for preset in "EMIT_DEPLOYER=$STALE:EMIT_DEPLOYER is set to '0x0+63', not exactly DEPLOYER_ADDRESS" \
  "DEPLOYER=$STALE:DEPLOYER is set to '0x0+63', not exactly DEPLOYER_ADDRESS" \
  "EMIT_OUTPUT=$T/elsewhere.json:EMIT_OUTPUT is set to .*elsewhere.json, but the ceremony's book is" \
  "EMIT_BROADCAST_SINCE=4000:EMIT_BROADCAST_SINCE is set to 4000, but this run's block 0 is at 5000" \
  "EMIT_FRESH_GENESIS=0:EMIT_FRESH_GENESIS is set to 0"; do
  reset_calls
  expect "ceremony C8: a conflicting ${preset%%=*} is refused before P2 runs" 3 "${preset#*:}" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 "${preset%%:*}" bash "$CE" --simulate --only P2
  if calls | grep -q '^regenesis'; then bad "ceremony C8: a refused ${preset%%=*} runs no regenesis" "$(calls)"; else ok "ceremony C8: a refused ${preset%%=*} runs no regenesis"; fi
done
reset_calls
expect "ceremony C8: a matching EMIT_DEPLOYER preset is accepted" 0 'done \(mode=simulate\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EMIT_DEPLOYER="$DEP" bash "$CE" --simulate --only P2
expect "ceremony C8: the dry run plans the fresh-genesis book" 0 'DRYRUN .*EMIT_FRESH_GENESIS=1 .*EMIT_OUTPUT=.*/contracts/addresses/40204.json bash .*regenesis.sh --reroll --with-aa' -- "${CEENV[@]}" bash "$CE" --only P2
GBK="$REPO/contracts/addresses/40204.json"
# C9 (Codex 3cc160c on chain#329): every deployer input the deploy scripts read names the
# run's deployer exactly. ScriptEnv.deployerAddress() prefers CEREMONY_DEPLOYER_ADDRESS over
# DEPLOYER_ADDRESS, and regenesis.sh kept a preset one, so a stale value redirected the
# deployer-derived constructor arguments (fee recipients) while the book named DEPLOYER_ADDRESS.
# P0 refuses any alias that is not byte-for-byte DEPLOYER_ADDRESS (other value, empty, other
# case, other spelling) before anything is sent, and every phase gets the run's deployer.
mk_manifest "$GB"
gov_book "$GB" "$DEP"
gov_chain
for preset in "CEREMONY_DEPLOYER_ADDRESS=$STALE:CEREMONY_DEPLOYER_ADDRESS is set to '0x0+63', not exactly DEPLOYER_ADDRESS" \
  "CEREMONY_DEPLOYER_ADDRESS=:CEREMONY_DEPLOYER_ADDRESS is set but empty" \
  "CEREMONY_DEPLOYER_ADDRESS=0X${DEP#0x}:CEREMONY_DEPLOYER_ADDRESS is set to '0X0+1', not exactly" \
  "CEREMONY_DEPLOYER_ADDRESS=${DEP#0x}:CEREMONY_DEPLOYER_ADDRESS is set to '0+1', not exactly" \
  "CEREMONY_DEPLOYER_ADDRESS= $DEP:CEREMONY_DEPLOYER_ADDRESS is set to ' 0x0+1', not exactly" \
  "DEPLOYER=:DEPLOYER is set but empty" \
  "EMIT_DEPLOYER=:EMIT_DEPLOYER is set but empty"; do
  reset_calls
  expect "ceremony C9: P0 refuses ${preset%%:*} before P2 runs" 3 "GATE FAIL at P0: ${preset#*:}" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 "${preset%%:*}" bash "$CE" --simulate --only P2
  if calls | grep -q '^regenesis'; then bad "ceremony C9: a refused ${preset%%:*} runs no regenesis" "$(calls)"; else ok "ceremony C9: a refused ${preset%%:*} runs no regenesis"; fi
done
C9D="$REPO/contracts/genesis/c9"
mkdir -p "$C9D"
mk_manifest "$C9D"
reset_calls
expect "ceremony C9: P0 refuses a stale CEREMONY_DEPLOYER_ADDRESS before P1's forge" 3 'GATE FAIL at P0: CEREMONY_DEPLOYER_ADDRESS is set to' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 CEREMONY_DEPLOYER_ADDRESS="$STALE" GENESIS_OUT_DIR="$C9D" bash "$CE" --simulate --only P1
if calls | grep -q '^forge'; then bad "ceremony C9: a refused P1 runs no forge" "$(calls)"; else ok "ceremony C9: a refused P1 runs no forge"; fi
# A checksum-case difference is refused even in a dry run; the exact spelling passes.
MIXED=0xAbCdEf0123456789aBcDeF0123456789AbCdEf01
expect "ceremony C9: a dry run refuses a CEREMONY_DEPLOYER_ADDRESS in another case" 3 "CEREMONY_DEPLOYER_ADDRESS is set to '0xabcdef0123456789abcdef0123456789abcdef01', not exactly DEPLOYER_ADDRESS" -- "${CEENV[@]}" DEPLOYER_ADDRESS="$MIXED" CEREMONY_DEPLOYER_ADDRESS="$(printf '%s' "$MIXED" | tr 'A-F' 'a-f')" bash "$CE"
expect "ceremony C9: a dry run accepts CEREMONY_DEPLOYER_ADDRESS spelled exactly as DEPLOYER_ADDRESS" 0 'done \(mode=dry\)' -- "${CEENV[@]}" DEPLOYER_ADDRESS="$MIXED" CEREMONY_DEPLOYER_ADDRESS="$MIXED" bash "$CE"
# Negative controls: no preset, or the exact value, runs; regenesis and forge see the run's deployer.
reset_calls
expect "ceremony C9: an exact CEREMONY_DEPLOYER_ADDRESS is accepted" 0 'done \(mode=simulate\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 CEREMONY_DEPLOYER_ADDRESS="$DEP" bash "$CE" --simulate --only P2
reset_calls
expect "ceremony C9: P2 runs with no deployer alias preset" 0 'done \(mode=simulate\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
calls | grep -q "^regenesis-deployer dep=$DEP ceremony=$DEP$" && ok "ceremony C9: regenesis gets CEREMONY_DEPLOYER_ADDRESS = the run's deployer" ||
  bad "ceremony C9: regenesis gets CEREMONY_DEPLOYER_ADDRESS = the run's deployer" "$(calls)"
reset_calls
expect "ceremony C9: P1 runs with no deployer alias preset" 0 'done \(mode=simulate\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$C9D" bash "$CE" --simulate --only P1
calls | grep -q "^forge-deployer dep=$DEP ceremony=$DEP$" && ok "ceremony C9: forge phases get CEREMONY_DEPLOYER_ADDRESS = the run's deployer" ||
  bad "ceremony C9: forge phases get CEREMONY_DEPLOYER_ADDRESS = the run's deployer" "$(calls)"
rm -rf "$C9D"
# regenesis.sh on its own (the reroll runbooks call it directly): a CEREMONY_DEPLOYER_ADDRESS
# that is not exactly DEPLOYER_ADDRESS stops it before the build.
RG="$T/rg"
mkdir -p "$RG/scripts/ops" "$RG/contracts"
cp "$G/../ops/regenesis.sh" "$RG/scripts/ops/"
for preset in "$STALE" "" "$(printf '%s' "$MIXED" | tr 'a-f' 'A-F' | sed 's/^0X/0x/')"; do
  reset_calls
  expect "regenesis: CEREMONY_DEPLOYER_ADDRESS='$preset' with DEPLOYER_ADDRESS=$MIXED is refused" 1 'CEREMONY_DEPLOYER_ADDRESS .*is not exactly DEPLOYER_ADDRESS' -- env PATH="$BIN:$PATH" RPC_URL=http://127.0.0.1:8545 DEPLOYER_ADDRESS="$MIXED" CEREMONY_DEPLOYER_ADDRESS="$preset" bash "$RG/scripts/ops/regenesis.sh"
  if calls | grep -q '^forge'; then bad "regenesis: a refused deployer alias runs no forge" "$(calls)"; else ok "regenesis: a refused deployer alias runs no forge"; fi
done
reset_calls
env PATH="$BIN:$PATH" RPC_URL=http://127.0.0.1:8545 DEPLOYER_ADDRESS="$MIXED" CEREMONY_DEPLOYER_ADDRESS="$MIXED" bash "$RG/scripts/ops/regenesis.sh" >"$T/rg.log" 2>&1
calls | grep -q '^forge clean' && ! grep -q 'not exactly DEPLOYER_ADDRESS' "$T/rg.log" && ok "regenesis: an exact CEREMONY_DEPLOYER_ADDRESS goes on to the build" ||
  bad "regenesis: an exact CEREMONY_DEPLOYER_ADDRESS goes on to the build" "$(cat "$T/rg.log")"
rm -rf "$RG"
# C10 tripwire: the ceremony refuses a second P2 by finding this run's broadcasts of the scripts
# in P2_BROADCAST_SCRIPTS, so that list must be every script regenesis.sh broadcasts. A
# run_step added to regenesis.sh without the list fails here (negative control below).
p2_list_sync() { # <regenesis.sh> -> 0 when its run_step scripts are the ceremony's list
  local want have
  want=$(sed -n 's/^[[:space:]]*run_step "\([^"]*\)".*/\1/p' "$1" | sed 's|.*/||' | sort -u)
  have=$(sed -n '/^P2_BROADCAST_SCRIPTS=(/,/)/p' "$CE" | tr ' ()' '\n\n\n' | grep '\.s\.sol$' | sort -u)
  [[ -n "$want" && "$want" == "$have" ]]
}
p2_list_sync "$G/../ops/regenesis.sh" && ok "ceremony C10: P2_BROADCAST_SCRIPTS is every script regenesis.sh broadcasts" ||
  bad "ceremony C10: P2_BROADCAST_SCRIPTS is every script regenesis.sh broadcasts" "$(sed -n 's/^[[:space:]]*run_step "\([^"]*\)".*/\1/p' "$G/../ops/regenesis.sh")"
{ cat "$G/../ops/regenesis.sh"; echo 'run_step "DeployNewThing.s.sol"'; } >"$T/regenesis-extra.sh"
p2_list_sync "$T/regenesis-extra.sh" && bad "ceremony C10: the list check catches a script added to regenesis.sh (negative control)" ||
  ok "ceremony C10: the list check catches a script added to regenesis.sh (negative control)"
# After a --confirm P2, the fee recipients of the contracts in the book are read from the chain
# and must be the TREASURY P2 handed DeployAll (0x..5a here), never the deployer:
# block 0 routes no revenue to the ceremony EOA.
C9B="$T/c9-book.json"
C9VR=$(addr 401) C9SBT=$(addr 402) C9BOND=$(addr 403) C9VI=$(addr 404) C9VP=$(addr 405)
C9X=$(addr 411) C9MM=$(addr 412) C9CM=$(addr 413)
printf '{"chainId":40204,"deployer":"%s","contracts":{"ValidatorRegistry":"%s","CitrateMemberSBT":"%s","MemberBond":"%s","MembershipStakeVaultImpl":"%s","MembershipStakeVault":"%s","X402Facilitator":"%s","ModelMarketplace":"%s","ComputeMarketplace":"%s"},"aaStack":{},"CitrateMemberSBT":"%s","MembershipStakeVault":"%s"}\n' \
  "$DEP" "$C9VR" "$C9SBT" "$C9BOND" "$C9VI" "$C9VP" "$C9X" "$C9MM" "$C9CM" "$C9SBT" "$C9VP" >"$C9B"
# The generator the gate re-runs: FAKE_EMIT_BOOK (default FAKE_REGEN_BOOK) is what it emits.
cat >"$T/fake-emit.sh" <<'EOF'
#!/usr/bin/env bash
echo "emitter dep=${EMIT_DEPLOYER:-} out=${EMIT_OUTPUT:-}" >>"$FAKE/calls.log"
[[ "${FAKE_EMIT_FAIL:-}" != 1 ]] || exit 1
cp "${FAKE_EMIT_BOOK:-$FAKE_REGEN_BOOK}" "$EMIT_OUTPUT"
EOF
# This run's P2 broadcasts, recorded (by the fake regenesis) after block 0 (5000).
C9BC="$T/c9-bcast"
mkdir -p "$C9BC/DeployValidatorRegistry.s.sol/40204" "$C9BC/DeployCoreMembership.s.sol/40204"
printf '{"timestamp":6000,"transactions":[{"transactionType":"CREATE2","contractName":"ValidatorRegistry","contractAddress":"%s"}]}' "$C9VR" \
  >"$C9BC/DeployValidatorRegistry.s.sol/40204/run-latest.json"
printf '{"timestamp":6001,"transactions":[{"transactionType":"CREATE2","contractName":"CitrateMemberSBT","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"MemberBond","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"MembershipStakeVault","contractAddress":"%s"},{"transactionType":"CREATE2","contractName":"ERC1967Proxy","contractAddress":"%s"}]}' \
  "$C9SBT" "$C9BOND" "$C9VI" "$C9VP" >"$C9BC/DeployCoreMembership.s.sol/40204/run-latest.json"
cp "$GBK" "$T/book.c9.orig"
C9ENV=("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1
  FAKE_REGEN_BOOK="$C9B" FAKE_REGEN_BCAST="$C9BC" EMITTER="$T/fake-emit.sh")
# c9_setup: a --confirm run after P1 (manifest, governance on chain, fee recipients = the
# TREASURY), before P2 has sent anything (no broadcast recorded yet).
c9_setup() {
  rm -rf "$REPO/contracts/broadcast"
  cp "$T/book.c9.orig" "$GBK"
  mk_manifest "$GB" "$DEP" confirm deployer
  gov_book "$GB" "$DEP"
  gov_chain
  rm -rf "$FAKE/call/$C9X" "$FAKE/call/$C9MM" "$FAKE/call/$C9CM"
  fake_call "$C9X" treasury "$(addr 90)"
  fake_call "$C9MM" treasuryAddress "$(addr 90)"
  fake_call "$C9CM" treasury "$(addr 90)"
}
c9_fee() { # name want-exit pattern [fake_call setup...]
  local name="$1" want="$2" pat="$3"
  shift 3
  c9_setup
  "$@"
  expect "ceremony C9: $name" "$want" "$pat" -- "${C9ENV[@]}" bash "$CE" --confirm --only P2 --account deployer
  cp "$T/book.c9.orig" "$GBK"
}
c9_fee "fee recipients equal to TREASURY pass P2" 0 'P2 fee recipients are TREASURY: X402Facilitator, ModelMarketplace, ComputeMarketplace' true
c9_fee "an X402Facilitator fee recipient other than TREASURY fails P2" 3 'X402Facilitator.treasury\(\) is 0x0+63, not TREASURY 0x0+5a' fake_call "$C9X" treasury "$STALE"
c9_fee "a GOVERNANCE fee recipient is not TREASURY and fails P2" 3 'X402Facilitator.treasury\(\) is 0x0+1f, not TREASURY' fake_call "$C9X" treasury "$(addr 31)"
c9_fee "a ModelMarketplace fee recipient other than TREASURY fails P2" 3 'ModelMarketplace.treasuryAddress\(\) is 0x0+63' fake_call "$C9MM" treasuryAddress "$STALE"
for g in "X402Facilitator:$C9X:treasury" "ModelMarketplace:$C9MM:treasuryAddress" "ComputeMarketplace:$C9CM:treasury"; do
  IFS=: read -r gn ga gf <<<"$g"
  c9_fee "a $gn fee recipient that is the deployer fails P2" 3 "$gn.$gf\\(\\) is the deployer 0x0+1: the fee recipient must be TREASURY" fake_call "$ga" "$gf" "$DEP"
done
c9_fee "an unreadable ComputeMarketplace fee recipient fails P2" 3 'cannot read ComputeMarketplace.treasury\(\)' rm -f "$FAKE/call/$C9CM/treasury"
# One canonical spelling on the compare side: the gate compares canonical (lowercase) books, so
# a book that spells an address in another case is the same book as the generator's.
C9B_MIXED="$T/c9-book-mixed.json"
python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); b["contracts"]["X402Facilitator"]="0x"+b["contracts"]["X402Facilitator"][2:].upper(); json.dump(b,open(sys.argv[2],"w"))' "$C9B" "$C9B_MIXED"
c9_setup
expect "ceremony C8: P2 compares the books in one canonical spelling" 0 'P2 stack book = generator output for this run' -- "${C9ENV[@]}" FAKE_REGEN_BOOK="$C9B_MIXED" FAKE_EMIT_BOOK="$C9B" bash "$CE" --confirm --only P2 --account deployer
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if m["stackBook"]["contracts"]["X402Facilitator"]==sys.argv[2] else 1)' "$GB/ceremony-run.json" "$C9X" &&
  ok "ceremony C8: the recorded stack book is lowercase" || bad "ceremony C8: the recorded stack book is lowercase" "$(cat "$GB/ceremony-run.json")"
cp "$T/book.c9.orig" "$GBK"

# Recovery after a broadcast: P2 has sent its transactions when the gate after it runs, so a
# failed gate must never send the operator back into P2. It names the step that records the
# book from this run's broadcasts and the chain (and sends nothing); P2 itself refuses to run
# again once this run's broadcasts exist or the book is recorded.
# reruns_p2 <output>: the lines that would re-enter P2 (a --from P2 / --only P2 resume that is
# not the record step).
reruns_p2() { grep -E -- '--(from|only) P2([^0-9]|$)' <<<"$1" | grep -v -- '--record-stack-book' || true; }
c9_setup
fake_call "$C9X" treasury "$STALE"
out=$("${C9ENV[@]}" bash "$CE" --confirm --only P2 --account deployer 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P2' <<<"$out" && grep -q 'P2 has already broadcast' <<<"$out" &&
  grep -qF -- "--confirm --only P2 --record-stack-book --account deployer" <<<"$out" && [[ -z "$(reruns_p2 "$out")" ]]; then
  ok "ceremony recovery: a gate failure after P2 broadcast names the record step, never a P2 re-run"
else
  bad "ceremony recovery: a gate failure after P2 broadcast names the record step, never a P2 re-run (exit $rc)" "$out"
fi
manifest_has_t() { python3 -c 'import json,sys; sys.exit(0 if sys.argv[2] in json.load(open(sys.argv[1])) else 1)' "$GB/ceremony-run.json" "$1"; }
manifest_has_t stackBook && bad "ceremony recovery: the failed gate recorded no stack book" "$(cat "$GB/ceremony-run.json")" || ok "ceremony recovery: the failed gate recorded no stack book"
for how in "--only P2" "--from P2"; do
  reset_calls
  # shellcheck disable=SC2086 # $how is two words on purpose
  expect "ceremony recovery: $how is refused once this run's P2 broadcasts exist" 3 'GATE FAIL at P2: this run.s P2 broadcasts are already recorded' -- "${C9ENV[@]}" bash "$CE" --confirm $how --account deployer
  if calls | grep -q '^regenesis'; then bad "ceremony recovery: $how after a broadcast runs no regenesis" "$(calls)"; else ok "ceremony recovery: $how after a broadcast runs no regenesis"; fi
done
fake_call "$C9X" treasury "$(addr 90)"
reset_calls
expect "ceremony recovery: the record step verifies and records the book from this run's broadcasts" 0 'P2 stack book recorded' -- "${C9ENV[@]}" bash "$CE" --confirm --only P2 --record-stack-book --account deployer
if calls | grep -q '^regenesis'; then bad "ceremony recovery: the record step sends nothing (no regenesis)" "$(calls)"; else ok "ceremony recovery: the record step sends nothing (no regenesis)"; fi
calls | grep -q "^emitter dep=$DEP out=$GBK$" && ok "ceremony recovery: the record step regenerates the book with the run's deployer" ||
  bad "ceremony recovery: the record step regenerates the book with the run's deployer" "$(calls)"
manifest_has_t stackBook && ok "ceremony recovery: the record step records the stack book" || bad "ceremony recovery: the record step records the stack book" "$(cat "$GB/ceremony-run.json")"
# Once the book is recorded, P2 is done: an explicit refusal, before anything is sent, whether
# or not the broadcasts are still on disk.
for keep in yes no; do
  [[ "$keep" == yes ]] || rm -rf "$REPO/contracts/broadcast"
  reset_calls
  expect "ceremony recovery: P2 is refused once the stack book is recorded (broadcasts on disk: $keep)" 3 'GATE FAIL at P2: the run manifest already records the stack book: P2 is done' -- "${C9ENV[@]}" bash "$CE" --confirm --only P2 --account deployer
  if calls | grep -q '^regenesis'; then bad "ceremony recovery: a refused P2 re-run runs no regenesis ($keep)" "$(calls)"; else ok "ceremony recovery: a refused P2 re-run runs no regenesis ($keep)"; fi
done
expect "ceremony recovery: the record step is refused once the book is recorded" 3 'already records the stack book: P2 is done' -- "${C9ENV[@]}" bash "$CE" --confirm --only P2 --record-stack-book --account deployer
expect "ceremony recovery: --record-stack-book needs --only P2" 1 '--record-stack-book needs --confirm --only P2' -- "${C9ENV[@]}" bash "$CE" --confirm --from P2 --record-stack-book --account deployer
expect "ceremony recovery: --record-stack-book needs --confirm" 1 '--record-stack-book needs --confirm --only P2' -- "${C9ENV[@]}" bash "$CE" --simulate --only P2 --record-stack-book
# Negative control: a broadcast from an earlier chain (recorded before this block 0) is not
# this run's and does not block P2.
c9_setup
mkdir -p "$REPO/contracts/broadcast/DeployAll.s.sol/40204"
printf '{"timestamp":100,"transactions":[]}' >"$REPO/contracts/broadcast/DeployAll.s.sol/40204/run-latest.json"
expect "ceremony recovery: an earlier chain's broadcast does not block P2" 0 'P2 stack book = generator output for this run' -- "${C9ENV[@]}" bash "$CE" --confirm --only P2 --account deployer
cp "$T/book.c9.orig" "$GBK"
# A P2 that fails part way (regenesis stops after sending some transactions): no advice to
# re-run P2; inspect first, and the record step if everything reached the chain.
c9_setup
out=$("${C9ENV[@]}" FAKE_REGEN_FAIL=1 bash "$CE" --confirm --only P2 --account deployer 2>&1)
rc=$?
if [[ $rc -eq 2 ]] && grep -q 'STEP FAIL at P2' <<<"$out" && grep -q 'do NOT re-run P2' <<<"$out" && grep -qF -- '--record-stack-book' <<<"$out" && [[ -z "$(reruns_p2 "$out")" ]]; then
  ok "ceremony recovery: a P2 step failure under --confirm never advises a P2 re-run"
else
  bad "ceremony recovery: a P2 step failure under --confirm never advises a P2 re-run (exit $rc)" "$out"
fi
# The same for P1: once it has broadcast, a failed gate points past it (every later phase
# re-verifies P1's governance on chain), never back into it.
P1D="$REPO/contracts/genesis/p1rec"
mkdir -p "$P1D"
mk_manifest "$P1D" "$DEP" confirm deployer
out=$("${C9ENV[@]}" GENESIS_OUT_DIR="$P1D" bash "$CE" --confirm --only P1 --account deployer 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P1' <<<"$out" && grep -q 'P1 has already broadcast' <<<"$out" && grep -qF -- '--confirm --from P2 --account deployer' <<<"$out" &&
  ! grep -qE -- '--(from|only) P1([^0-9]|$)' <<<"$out"; then
  ok "ceremony recovery: a gate failure after P1 broadcast resumes after P1, never P1 again"
else
  bad "ceremony recovery: a gate failure after P1 broadcast resumes after P1, never P1 again (exit $rc)" "$out"
fi
rm -rf "$P1D"
# A gate that fails before its phase sent anything still names that phase's resume (control).
c9_setup
expect "ceremony recovery: a gate failure before any broadcast resumes at that phase" 3 "fix it, then resume: .* --confirm --from P2 --account deployer" -- "${C9ENV[@]}" VALIDATOR_GOVERNANCE="$STALE" bash "$CE" --confirm --only P2 --account deployer
# ---------------------------------------------------------------- C10: every broadcasting phase sends once
# Before, only P2 refused a second send. An identical retry of P1, P3 or P4 after a failure that
# came after its broadcast sent the phase again, and P0 called a book this run had written "not
# this ceremony's output; move it aside", which also led to a second send. The fake forge
# records its broadcasts here (FAKE_FORGE_BCAST=1) and bcount counts the broadcasting calls.
bcount() { calls | grep -cE '^(forge script .*--broadcast|regenesis .*--broadcast)' || true; }
C10D="$REPO/contracts/genesis/c10"
C10ENV=("${C9ENV[@]}" GENESIS_OUT_DIR="$C10D" PATRONAGE_KYC_REGISTRY="$(addr 51)" PATRONAGE_MEMBERSHIP="$(addr 52)" FAKE_FORGE_BCAST=1)
c10_reset() { # a --confirm run bound to its manifest, nothing sent yet
  rm -rf "$REPO/contracts/broadcast" "$C10D"
  mkdir -p "$C10D"
  mk_manifest "$C10D" "$DEP" confirm deployer
  gov_chain
  reset_calls
}
c10_record() { # <key> <json>: the run manifest records the phase output <key>
  python3 -c 'import json,sys; p=sys.argv[1]; m=json.load(open(p)); m[sys.argv[2]]=json.loads(sys.argv[3]); json.dump(m, open(p, "w"))' "$C10D/ceremony-run.json" "$1" "$2"
}
C10GOV=$(printf '{"GovernanceTimelock":"%s","GovernanceMultisig":"%s","GuardianTimelock":"%s","GuardianMultisig":"%s"}' "$(addr 31)" "$(addr 33)" "$(addr 32)" "$(addr 35)")
gov_book "$T" "$DEP"
mv "$T/governance.json" "$T/c10-gov.json"
# not_moved_aside <output>: the output never calls this run's book another run's output.
not_moved_aside() { ! grep -qE 'move it aside|not this ceremony.s output' <<<"$1"; }

# A failure after the phase broadcast, then the identical command again: the retry is refused
# and sends nothing. P1: its gate fails (no governance.json). P3, P4: the step fails after it
# has recorded its broadcast.
for c in "P1:" "P3:FAKE_FORGE_FAIL=1" "P4:FAKE_FORGE_FAIL=1"; do
  ph="${c%%:*}" fault="${c#*:}"
  c10_reset
  if [[ "$ph" == P4 ]]; then gov_book "$C10D" "$DEP"; c10_record governance "$C10GOV"; fi
  # shellcheck disable=SC2086 # $fault is one VAR=value word or empty
  out=$("${C10ENV[@]}" $fault bash "$CE" --confirm --only "$ph" --account deployer 2>&1)
  rc=$?
  if [[ $rc -ne 0 && "$(bcount)" == 1 ]] && grep -q "$ph has already broadcast\|$ph may have sent" <<<"$out"; then
    ok "ceremony C10: a $ph that fails after its broadcast sent once (setup)"
  else
    bad "ceremony C10: a $ph that fails after its broadcast sent once (setup) (exit $rc, sent $(bcount))" "$out"
  fi
  reset_calls
  # shellcheck disable=SC2086
  out=$("${C10ENV[@]}" $fault bash "$CE" --confirm --only "$ph" --account deployer 2>&1)
  rc=$?
  if [[ $rc -eq 3 ]] && grep -q "GATE FAIL at $ph: this run.s $ph broadcasts are already recorded" <<<"$out" && grep -q "do NOT re-run $ph" <<<"$out"; then
    ok "ceremony C10: an identical $ph retry after a failure past its broadcast is refused"
  else
    bad "ceremony C10: an identical $ph retry after a failure past its broadcast is refused (exit $rc)" "$out"
  fi
  [[ "$(bcount)" == 0 ]] && ok "ceremony C10: the refused $ph retry calls no broadcasting forge" ||
    bad "ceremony C10: the refused $ph retry calls no broadcasting forge ($(bcount) sent)" "$(calls)"
done

# A phase whose output the run manifest records is done: --only Pn is refused as done, at P0
# while its book is in place (never "move it aside"), and by the guard once the book is gone.
for c in "P1:governance:governance.json" "P3:teamVesting:team-vesting.json" "P4:dormantLedgers:dormant-ledgers.json"; do
  IFS=: read -r ph key file <<<"$c"
  c10_reset
  gov_book "$C10D" "$DEP"
  c10_record governance "$C10GOV"
  [[ "$ph" == P1 ]] || {
    printf '{"deployer":"%s","contracts":{"Out%s":"%s"}}' "$DEP" "$ph" "$(addr 700)" >"$C10D/$file"
    c10_record "$key" "$(printf '{"Out%s":"%s"}' "$ph" "$(addr 700)")"
  }
  out=$("${C10ENV[@]}" bash "$CE" --confirm --only "$ph" --account deployer 2>&1)
  rc=$?
  if [[ $rc -eq 3 ]] && grep -q "GATE FAIL at P0: .*$file is this run.s $ph output: the run manifest records .*($key). $ph is done" <<<"$out" &&
    grep -q "do NOT re-run $ph" <<<"$out" && not_moved_aside "$out" && ! grep -qE -- "--(only|from) $ph([^0-9]|$)" <<<"$out"; then
    ok "ceremony C10: --only $ph after a recorded $ph is refused at P0 as done, never 'move it aside'"
  else
    bad "ceremony C10: --only $ph after a recorded $ph is refused at P0 as done, never 'move it aside' (exit $rc)" "$out"
  fi
  [[ "$(bcount)" == 0 ]] && ok "ceremony C10: the refused --only $ph sends nothing" || bad "ceremony C10: the refused --only $ph sends nothing" "$(calls)"
  # Following the old advice (move the book aside) no longer sends the phase again.
  mv "$C10D/$file" "$T/c10-aside.json"
  reset_calls
  out=$("${C10ENV[@]}" bash "$CE" --confirm --only "$ph" --account deployer 2>&1)
  rc=$?
  if [[ $rc -eq 3 ]] && grep -q "$ph is done" <<<"$out" && grep -q "do NOT re-run $ph" <<<"$out" && [[ "$(bcount)" == 0 ]]; then
    ok "ceremony C10: with its book moved aside, a recorded $ph is still refused as done and sends nothing"
  else
    bad "ceremony C10: with its book moved aside, a recorded $ph is still refused as done and sends nothing (exit $rc, sent $(bcount))" "$out"
  fi
done
# The broadcasts alone also make a book this run's: P0 says done, not "move it aside".
c10_reset
gov_book "$C10D" "$DEP"
c10_record governance "$C10GOV"
printf '{"deployer":"%s","contracts":{"OutP4":"%s"}}' "$DEP" "$(addr 700)" >"$C10D/dormant-ledgers.json"
mkdir -p "$REPO/contracts/broadcast/DeployDormantLedgers.s.sol/40204"
printf '{"timestamp":6000,"transactions":[]}' >"$REPO/contracts/broadcast/DeployDormantLedgers.s.sol/40204/run-latest.json"
out=$("${C10ENV[@]}" bash "$CE" --confirm --only P4 --account deployer 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q "is this run.s P4 output: this run.s P4 broadcasts are recorded (DeployDormantLedgers.s.sol). P4 is done" <<<"$out" && not_moved_aside "$out" && [[ "$(bcount)" == 0 ]]; then
  ok "ceremony C10: a book this run's P4 broadcasts account for is done at P0, never 'move it aside'"
else
  bad "ceremony C10: a book this run's P4 broadcasts account for is done at P0, never 'move it aside' (exit $rc)" "$out"
fi
# Control: a book this run has no record of is still another run's output to move aside.
c10_reset
gov_book "$C10D" "$DEP"
c10_record governance "$C10GOV"
printf '{"deployer":"%s","contracts":{"OutP4":"%s"}}' "$DEP" "$(addr 700)" >"$C10D/dormant-ledgers.json"
expect "ceremony C10: a book with no record in this run is still refused as another run's (control)" 3 'dormant-ledgers.json already exists and P4 would write it; move it aside' -- "${C10ENV[@]}" bash "$CE" --confirm --only P4 --account deployer
# A recorded P1 whose governance.json is missing: P1 is done, put the book back; never "run P1".
c10_reset
c10_record governance "$C10GOV"
out=$("${C10ENV[@]}" bash "$CE" --confirm --only P2 --account deployer 2>&1)
if grep -q 'records P1.s governance: P1 is done' <<<"$out" && ! grep -q 'run P1 first' <<<"$out"; then
  ok "ceremony C10: a missing governance.json after a recorded P1 says P1 is done, never 'run P1 first'"
else
  bad "ceremony C10: a missing governance.json after a recorded P1 says P1 is done, never 'run P1 first'" "$out"
fi
# The normal path still sends each phase once (control): P1 broadcasts, writes and records its
# governance; the same --only P1 again is then done.
c10_reset
expect "ceremony C10: a first P1 sends and records its governance (control)" 0 'done \(mode=confirm\)' -- "${C10ENV[@]}" FAKE_P1_BOOK="$T/c10-gov.json" bash "$CE" --confirm --only P1 --account deployer
[[ "$(bcount)" == 1 ]] && ok "ceremony C10: the first P1 broadcast once (control)" || bad "ceremony C10: the first P1 broadcast once (control)" "$(calls)"
reset_calls
expect "ceremony C10: --only P1 after a good P1 is refused as done" 3 'governance.json is this run.s P1 output: the run manifest records P1.s governance' -- "${C10ENV[@]}" FAKE_P1_BOOK="$T/c10-gov.json" bash "$CE" --confirm --only P1 --account deployer
[[ "$(bcount)" == 0 ]] && ok "ceremony C10: the refused second P1 sends nothing" || bad "ceremony C10: the refused second P1 sends nothing" "$(calls)"

# C10 tripwire, behaviour: with this run's broadcasts recorded for every script any phase
# broadcasts, no phase of the ceremony (the PHASES list, read from the script) may call a
# broadcasting forge or regenesis.sh. A new broadcasting phase that skips the guard, or a
# guard that stops refusing, fails here.
c10_sends() { # <ceremony script> -> "phase:count" for each phase that broadcast
  local ce="$1" phases p s
  phases=$(sed -n 's/^PHASES=(\(.*\))$/\1/p' "$ce")
  for p in $phases; do
    c10_reset
    gov_book "$C10D" "$DEP"
    c10_record governance "$C10GOV"
    rm -f "$C10D/governance.json"
    [[ "$p" == P1 ]] || gov_book "$C10D" "$DEP"
    for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers DeployAll DeployValidatorRegistry DeployModelAccessControl \
      DeployTEEAttestationRegistry DeployComputePoolTraining DeployEduStack DeployAIGateway DeployP256Verifier DeployAA DeployCoreMembership; do
      mkdir -p "$REPO/contracts/broadcast/$s.s.sol/40204"
      printf '{"timestamp":6000,"transactions":[]}' >"$REPO/contracts/broadcast/$s.s.sol/40204/run-latest.json"
    done
    # P1 itself must be guarded by its broadcasts, not by the recorded governance.
    if [[ "$p" == P1 ]]; then python3 -c 'import json,sys; p=sys.argv[1]; m=json.load(open(p)); m.pop("governance"); json.dump(m, open(p, "w"))' "$C10D/ceremony-run.json"; fi
    "${C10ENV[@]}" bash "$ce" --confirm --only "$p" --account deployer >/dev/null 2>&1
    s=$(bcount)
    [[ "$s" == 0 ]] || printf '%s:%s\n' "$p" "$s"
  done
}
tw=$(c10_sends "$CE")
[[ -z "$tw" ]] && ok "tripwire C10: no phase sends again over this run's broadcasts" || bad "tripwire C10: no phase sends again over this run's broadcasts" "$tw"
# Negative control: the same ceremony with the guard disabled is caught, phase by phase.
# (a copy of scripts/genesis in the temp dir; the source tree is not touched)
rm -rf "$T/c10gen"
cp -R "$G" "$T/c10gen"
python3 - "$T/c10gen/genesis_ceremony.sh" <<'PY2'
import sys
p = sys.argv[1]; s = open(p).read()
a = 'sends_once() {\n  local ph="$1" key\n'
assert a in s
s = s.replace(a, a + '  SENDS_ONCE_OK="$ph"; return 0\n', 1)
open(p, "w").write(s)
PY2
tw=$(c10_sends "$T/c10gen/genesis_ceremony.sh")
rm -rf "$T/c10gen"
cp "$T/book.c9.orig" "$GBK" # the unguarded P2 above "wrote" the fake regenesis book over it
if grep -q '^P1:' <<<"$tw" && grep -q '^P2:' <<<"$tw" && grep -q '^P3:' <<<"$tw" && grep -q '^P4:' <<<"$tw"; then
  ok "tripwire C10: a ceremony without the guard is caught for P1, P2, P3 and P4 (negative control)"
else
  bad "tripwire C10: a ceremony without the guard is caught for P1, P2, P3 and P4 (negative control)" "$tw"
fi
# C10 tripwire, source: forge and regenesis.sh run only through run_broadcast (which needs the
# guard), except the P5 checker, which reads. A new direct call is flagged.
c10_direct() { # <ceremony script> -> the executable lines that run forge or regenesis.sh directly
  # (continuation lines are joined first, so a call is judged with the command it belongs to)
  sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$1" | grep -nE '"\$(FORGE|REGENESIS)"' | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE 'describe_cmd|run_broadcast P2 bash "\$REGENESIS"|^[0-9]+:forge_in_contracts\(\) \{ \(cd "\$CONTRACTS" && "\$FORGE" "\$@"\); \}$|-[xf] "\$REGENESIS"|CheckDeployedAdmins|FORGE="\$\{FORGE' || true
}
tw=$(c10_direct "$CE")
[[ -z "$tw" ]] && ok "tripwire C10: the ceremony runs forge and regenesis.sh only through run_broadcast" || bad "tripwire C10: the ceremony runs forge and regenesis.sh only through run_broadcast" "$tw"
{ cat "$CE"; echo '(cd "$CONTRACTS" && "$FORGE" script script/DeployNew.s.sol --broadcast)'; echo '  RPC_URL="$RPC_URL" bash "$REGENESIS" --broadcast'; } >"$T/c10-direct.sh"
[[ $(c10_direct "$T/c10-direct.sh" | wc -l) -eq 2 ]] && ok "tripwire C10: a direct forge or regenesis.sh call is flagged (negative control)" ||
  bad "tripwire C10: a direct forge or regenesis.sh call is flagged (negative control)" "$(c10_direct "$T/c10-direct.sh")"

# A fresh --confirm run refuses a broadcast directory that already holds records for this chain
# id (a rehearsal's would count as this run's); other chains' records and dry runs do not.
c10_fresh() { rm -rf "$REPO/contracts/broadcast" "$C10D"; mkdir -p "$C10D"; reset_calls; }
c10_fresh
mkdir -p "$REPO/contracts/broadcast/DeployAll.s.sol/40204"
printf '{"timestamp":9000,"transactions":[]}' >"$REPO/contracts/broadcast/DeployAll.s.sol/40204/run-latest.json"
out=$("${C10ENV[@]}" bash "$CE" --confirm --account deployer 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P0: contracts/broadcast/ already holds chain 40204 broadcast records (DeployAll.s.sol) from before this run' <<<"$out" &&
  [[ ! -e "$C10D/ceremony-run.json" && "$(bcount)" == 0 ]]; then
  ok "ceremony C10: a fresh --confirm run refuses earlier 40204 broadcast records, before the manifest and any send"
else
  bad "ceremony C10: a fresh --confirm run refuses earlier 40204 broadcast records, before the manifest and any send (exit $rc)" "$out"
fi
c10_fresh
mkdir -p "$REPO/contracts/broadcast/DeployAll.s.sol/31337" "$REPO/contracts/broadcast/DeployAll.s.sol/40204/dry-run"
printf '{"timestamp":9000,"transactions":[]}' >"$REPO/contracts/broadcast/DeployAll.s.sol/31337/run-latest.json"
printf '{"timestamp":9000,"transactions":[]}' >"$REPO/contracts/broadcast/DeployAll.s.sol/40204/dry-run/run-latest.json"
out=$("${C10ENV[@]}" bash "$CE" --confirm --account deployer 2>&1)
if grep -q 'P0 preflight PASS' <<<"$out" && ! grep -q 'already holds chain' <<<"$out"; then
  ok "ceremony C10: another chain's records and a dry run do not block a fresh run (control)"
else
  bad "ceremony C10: another chain's records and a dry run do not block a fresh run (control)" "$out"
fi
rm -rf "$REPO/contracts/broadcast" "$C10D"

# forge's own keystore variables: ETH_PASSWORD (its password-file variable) is refused by name;
# ETH_KEYSTORE_ACCOUNT / ETH_KEYSTORE must be unset or name the --account keystore. The value
# is never printed.
expect "ceremony: ETH_PASSWORD in the environment is refused" 1 'ETH_PASSWORD is set in the environment' -- "${CEENV[@]}" ETH_PASSWORD="$T/c10-secret-value" bash "$CE" --account deployer
out=$("${CEENV[@]}" ETH_PASSWORD="$T/c10-secret-value" bash "$CE" --account deployer 2>&1)
grep -qF "c10-secret-value" <<<"$out" && bad "ceremony: the ETH_PASSWORD refusal does not print its value" "$out" || ok "ceremony: the ETH_PASSWORD refusal does not print its value"
expect "ceremony: an ETH_KEYSTORE_ACCOUNT other than --account is refused" 1 'ETH_KEYSTORE_ACCOUNT is set in the environment and does not name the --account keystore' -- "${CEENV[@]}" ETH_KEYSTORE_ACCOUNT=other bash "$CE" --account deployer
expect "ceremony: an ETH_KEYSTORE other than the --account keystore is refused" 1 'ETH_KEYSTORE is set in the environment and is not the --account keystore' -- "${CEENV[@]}" HOME="$T/kshome" ETH_KEYSTORE="$T/elsewhere/deployer" bash "$CE" --account deployer
expect "ceremony: ETH_KEYSTORE without --account is refused" 1 'ETH_KEYSTORE is set in the environment without --account' -- "${CEENV[@]}" ETH_KEYSTORE="$T/elsewhere/deployer" bash "$CE"
expect "ceremony: keystore variables that agree with --account pass (control)" 0 'done \(mode=dry\)' -- "${CEENV[@]}" HOME="$T/kshome" ETH_KEYSTORE_ACCOUNT=deployer ETH_KEYSTORE="$T/kshome/.foundry/keystores/deployer" bash "$CE" --account deployer

# C9: P2 hands DeployAll TREASURY as the fee recipient. P0 checks it whenever P2 runs,
# before anything is sent; a run that does not reach P2 does not need it.
for c in "unset:TREASURY=:TREASURY is not set" "the deployer:TREASURY=$(addr 1):TREASURY \\(0x0+1\\) is the deployer" \
  "zero:TREASURY=0x0000000000000000000000000000000000000000:TREASURY is the zero address" "malformed:TREASURY=0x12:TREASURY \\(0x12\\) is not an address"; do
  IFS=: read -r tn tv tp <<<"$c"
  reset_calls
  expect "ceremony C9: a TREASURY that is $tn stops P2 at P0" 3 "GATE FAIL at P0: phase inputs: .*$tp" -- "${CEENV[@]}" "$tv" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
  calls | grep -q '^regenesis' && bad "ceremony C9: a refused TREASURY ($tn) runs no regenesis" "$(calls)" || ok "ceremony C9: a refused TREASURY ($tn) runs no regenesis"
done
mk_manifest "$GB" # a simulation run (the C9 cases above left a --confirm one)
gov_book "$GB" "$DEP"
expect "ceremony C9: --only P5 does not need TREASURY (control)" 0 'P0 preflight PASS' -- "${CEENV[@]}" TREASURY= RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony C9: a dry run plans without TREASURY and names it" 0 'P0 plan: .*TREASURY is not set' -- "${CEENV[@]}" TREASURY= bash "$CE"
reset_calls
"${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2 >/dev/null 2>&1
calls | grep -qx "regenesis-treasury $(addr 90)" && ok "ceremony C9: P2 hands regenesis.sh (DeployAll) TREASURY" || bad "ceremony C9: P2 hands regenesis.sh (DeployAll) TREASURY" "$(calls)"

# The run manifest's temp file is created with O_EXCL: a symlink (or stale file) there is
# refused, and what it points at is not written.
MWD="$REPO/contracts/genesis/mw"
rm -rf "$MWD"
mkdir -p "$MWD"
printf 'victim\n' >"$T/c10-victim"
ln -s "$T/c10-victim" "$MWD/ceremony-run.json.tmp"
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$MWD" bash "$CE" --simulate 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'cannot write the run manifest' <<<"$out" && [[ "$(cat "$T/c10-victim")" == victim && ! -e "$MWD/ceremony-run.json" ]]; then
  ok "ceremony: a symlinked manifest temp file is refused and its target is not written"
else
  bad "ceremony: a symlinked manifest temp file is refused and its target is not written (exit $rc)" "$out"$'\n'"victim: $(cat "$T/c10-victim")"
fi
rm -rf "$MWD"

# P5's DEPLOYER-ADMIN gate also counts a fee recipient that is the deployer.
C9P5B="$T/c9-p5-book.json"
printf '{"chainId":40204,"deployer":"%s","contracts":{"Alpha":"%s","X402Facilitator":"%s","ModelMarketplace":"%s","ComputeMarketplace":"%s"},"aaStack":{}}' "$DEP" "$A1" "$C9X" "$C9MM" "$C9CM" >"$C9P5B"
mk_manifest "$GB"
gov_book "$GB" "$DEP"
p5_fees() { # x402 mm cm
  rm -rf "$FAKE/call/$C9X" "$FAKE/call/$C9MM" "$FAKE/call/$C9CM"
  fake_call "$C9X" treasury "$1"
  fake_call "$C9MM" treasuryAddress "$2"
  fake_call "$C9CM" treasury "$3"
}
p5_fees "$(addr 31)" "$(addr 31)" "$(addr 31)"
expect "ceremony C9: P5 passes when no fee recipient is the deployer (control)" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$C9P5B" bash "$CE" --simulate --only P5
p5_fees "$(addr 31)" "$DEP" "$(addr 31)"
expect "ceremony C9: P5 fails DEPLOYER-ADMIN when a fee recipient is the deployer" 3 'DEPLOYER-ADMIN is not 0' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$C9P5B" bash "$CE" --simulate --only P5
expect "ceremony C9: P5 names the fee recipient held by the deployer" 3 'DEPLOYER-ADMIN ModelMarketplace: treasuryAddress\(\) is the deployer EOA' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$C9P5B" bash "$CE" --simulate --only P5
rm -f "$FAKE/call/$C9CM/treasury"
expect "ceremony C9: P5 fails a fee recipient it cannot read" 3 'GATE FAIL at P5: fee recipients: cannot read ComputeMarketplace.treasury' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$C9P5B" bash "$CE" --simulate --only P5
rm -rf "$FAKE/call/$C9X" "$FAKE/call/$C9MM" "$FAKE/call/$C9CM"

# The password file is re-checked right before each signing step and must still be the same
# file the preflight accepted (device and inode), with the same private mode. A change between
# the preflight and the first forge broadcast stops the run before anything is sent. The fake
# cast makes the change at its first call, which is during the P0 preflight.
PWD_RUN="$T/pw-run"
mkdir -p "$PWD_RUN"
chmod 700 "$PWD_RUN"
P1D="$REPO/contracts/genesis/p1pw"
pw_run() { # <how|""> -> runs --confirm --only P1 with a fresh private password file
  rm -rf "$P1D" "$PWD_RUN/pw" "$PWD_RUN/pw.new" "$PWD_RUN/target" "$FAKE/pw-swapped"
  mkdir -p "$P1D"
  mk_manifest "$P1D" "$DEP" confirm deployer
  (umask 077 && printf 'x\n' >"$PWD_RUN/pw" && printf 'y\n' >"$PWD_RUN/target")
  reset_calls
  out=$("${C9ENV[@]}" GENESIS_OUT_DIR="$P1D" FAKE_PW_SWAP="${1:+$PWD_RUN/pw}" FAKE_PW_SWAP_HOW="$1" bash "$CE" --confirm --only P1 --account deployer --password-file "$PWD_RUN/pw" 2>&1)
  rc=$?
}
pw_run ""
if calls | grep -E '^forge script script/DeployGenesisGovernance.s.sol .*--broadcast --account deployer --password-file ' | grep -qF "$PWD_RUN/pw"; then
  ok "ceremony: an unchanged password file reaches the P1 broadcast as a path (control)"
else
  bad "ceremony: an unchanged password file reaches the P1 broadcast as a path (control)" "$(calls)"$'\n'"$out"
fi
for how in replace chmod symlink rename; do
  pw_run "$how"
  if [[ -f "$FAKE/pw-swapped" ]] && [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P1: --password-file' <<<"$out" && ! calls | grep -q '^forge '; then
    ok "ceremony: a password file changed after the preflight ($how) stops P1 before forge runs"
  else
    bad "ceremony: a password file changed after the preflight ($how) stops P1 before forge runs (exit $rc)" "$(calls)"$'\n'"$out"
  fi
done
rm -rf "$P1D" "$PWD_RUN"
rm -rf "$REPO/contracts/broadcast" "$FAKE/call/$C9X" "$FAKE/call/$C9MM" "$FAKE/call/$C9CM"
mk_manifest "$GB"
# C8 on P5/P6: once P2 recorded its book, a different book is refused; --confirm needs one.
cp "$GBK" "$T/book.orig"
mk_manifest "$GB"
gov_book "$GB" "$DEP"
python3 - "$GB/ceremony-run.json" "$GBK" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
m["stackBook"] = {"deployer": b["deployer"].lower(), "contracts": {k: v.lower() for k, v in b["contracts"].items()},
                  "aaStack": {}}
json.dump(m, open(sys.argv[1], "w"))
PY
expect "ceremony C8: P5 passes over the recorded stack book" 0 'P5 address book is the stack book P2 generated' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); b["contracts"]["Alpha"]=sys.argv[2]; json.dump(b,open(sys.argv[1],"w"))' "$GBK" "$A2"
expect "ceremony C8: P5 refuses a book other than the recorded stack book" 3 "is not the stack book this run's P2 generated" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
cp "$T/book.orig" "$GBK"
mk_manifest "$GB"
# P5 reads the registry's authority from the chain: a stale EOA there fails the handover gate.
VR=$(addr 123)
printf '{"chainId":40204,"deployer":"%s","contracts":{"Alpha":"%s","Beta":"%s","Vault":"%s","ValidatorRegistry":"%s"},"aaStack":{},"Vault":"%s"}' "$DEP" "$A1" "$A2" "$A3" "$VR" "$A3" >"$T/book-vr.json"
vr_chain() { # governance slasher pending
  fake_call "$VR" governance "$1"
  fake_call "$VR" slasher "$2"
  fake_call "$VR" pendingGovernance "$3"
}
Z40=0x0000000000000000000000000000000000000000
vr_chain "$(addr 31)" "$(addr 31)" "$Z40"
expect "ceremony C4: P5 passes a registry governed by GOVERNANCE" 0 'ValidatorRegistry 0x0+7b: governance and slasher are GOVERNANCE' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --simulate --only P5
vr_chain "$STALE" "$(addr 31)" "$Z40"
expect "ceremony C4: P5 fails a registry governed by a stale EOA" 3 'ValidatorRegistry.governance\(\) is 0x0+63, not this run' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --simulate --only P5
vr_chain "$(addr 31)" "$STALE" "$Z40"
expect "ceremony C4: P5 fails a registry with another slasher" 3 'ValidatorRegistry.slasher\(\) is 0x0+63' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --simulate --only P5
vr_chain "$(addr 31)" "$(addr 31)" "$STALE"
expect "ceremony C4: P5 fails a registry with a pending governance transfer" 3 'pendingGovernance\(\) is 0x0+63' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --simulate --only P5
rm -rf "$FAKE/call/$VR"
expect "ceremony C4: P5 fails when the registry cannot be read" 3 'cannot read ValidatorRegistry.governance' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --simulate --only P5
mk_manifest "$GB" "$DEP" confirm deployer
printf '{"deployer":"%s","contracts":{"VestingAlice":"%s"}}' "$DEP" "$(addr 71)" >"$GB/team-vesting.json"
printf '{"deployer":"%s","contracts":{"FederatedRoundLedger":"%s","PatronageLedger":"%s"}}' "$DEP" "$(addr 81)" "$(addr 82)" >"$GB/dormant-ledgers.json"
expect "ceremony C4: --confirm P5 needs a ValidatorRegistry in the book" 3 'has no ValidatorRegistry' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P5 --account deployer
vr_chain "$(addr 31)" "$(addr 31)" "$Z40"
expect "ceremony C8: --confirm P5 needs a stack book recorded by P2" 3 'records no stack book' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 ADDRESS_BOOK="$T/book-vr.json" bash "$CE" --confirm --only P5 --account deployer
rm -rf "$FAKE/call/$VR"
rm "$GB/team-vesting.json" "$GB/dormant-ledgers.json"

# C3: every gate reads both councils from the chain and holds them to the validated inputs
# and the genesis floors.
mk_manifest "$GB"
gov_chain
expect "ceremony C3: P5 checks the councils on chain" 0 'P5 governance floors hold on chain' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
c3_case() { # name pattern setup...
  local name="$1" pat="$2"
  shift 2
  mk_manifest "$GB"
  gov_chain
  "$@"
  expect "ceremony C3: $name" 3 "$pat" -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
}
c3_case "a 2-of-5 governance on chain fails" 'GOV: threshold on chain is 2, the validated input is 3' fake_call "$(addr 33)" threshold 2
c3_case "a governance multisig with other owners fails" 'GOV: the multisig.s owners on chain are not' fake_call "$(addr 33)" owners "[$(addr 11), $(addr 12), $(addr 13), $(addr 14), $(addr 16)]"
c3_case "a 24 h governance delay on chain fails" 'GOV: timelock delay on chain is 86400s' fake_call "$(addr 31)" getMinDelay 86400
c3_case "a multisig fronting another timelock fails" 'GOV: multisig 0x0+21 fronts 0x0+63' fake_call "$(addr 33)" timelock "$STALE"
c3_case "a multisig that is not the timelock's proposer fails" 'is not the proposer of' rm -f "$FAKE/call/$(addr 31)/hasRole_${PROPOSER}_$(addr 33)"
c3_case "a deployer still proposer on the timelock fails" 'the deployer still holds' fake_call "$(addr 31)" "hasRole_${PROPOSER}_$DEP" true
c3_case "a deployer still admin of the timelock fails" 'the deployer still holds' fake_call "$(addr 32)" "hasRole_0x0000000000000000000000000000000000000000000000000000000000000000_$DEP" true
c3_case "an unreadable timelock fails" 'GRD: cannot read getMinDelay' rm -f "$FAKE/call/$(addr 32)/getMinDelay"
c3_case "a guardian delay not shorter than governance fails" 'GRD: timelock delay on chain is 172800s' fake_call "$(addr 32)" getMinDelay 172800
# On a rehearsal chain (not 40204) the genesis floors do not apply, but the councils on chain
# must still be exactly the inputs P0 validated there.
RRPC=http://127.0.0.1:8546
mkdir -p "$(rpcdir "$RRPC")"
echo 31337 >"$(rpcdir "$RRPC")/chain-id"
echo "$GEN" >"$(rpcdir "$RRPC")/block-0"
echo 5000 >"$(rpcdir "$RRPC")/block-0-timestamp"
REH="$REPO/contracts/genesis/reh"
mkdir -p "$REH"
mk_manifest "$REH"
sed -i 's/"chainId":40204/"chainId":31337/' "$REH/ceremony-run.json"
gov_book "$REH" "$DEP"
REHENV=("${CEENV[@]}" RPC_URL="$RRPC" EXPECTED_CHAIN_ID=31337 GENESIS_OUT_DIR="$REH" GOV_OWNERS="$(owners 11 12 13)" GOV_THRESHOLD=2 GOV_MIN_DELAY=7200 GOV_PROPOSAL_TTL=86400)
gov_chain
expect "ceremony C3: a rehearsal chain holds the councils to its own inputs" 3 "GOV: the multisig.s owners on chain are not the GOV_OWNERS" -- "${REHENV[@]}" bash "$CE" --simulate --only P5
council_chain "$(addr 31)" "$(addr 33)" 7200 2 11 12 13
expect "ceremony C3: a rehearsal council matching its inputs passes" 0 'P5 PASS' -- "${REHENV[@]}" bash "$CE" --simulate --only P5
rm -r "$REH"
gov_chain
# P6 and P7 are gates too: a council that fails on chain fails them.
mk_manifest "$GB"
fake_call "$(addr 33)" threshold 2
mkdir -p "$REPO/contracts/broadcast/Regenesis.s.sol/40204"
printf '{"timestamp":6000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$A1" >"$REPO/contracts/broadcast/Regenesis.s.sol/40204/run-latest.json"
expect "ceremony C3: P6 fails a council below its inputs" 3 'GOV: threshold on chain is 2' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
expect "ceremony C3: P7 fails a council below its inputs" 3 'GOV: threshold on chain is 2' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FLEET_RPCS=http://n1,http://n2 bash "$CE" --simulate --only P7
gov_chain

# C2: once a gate has verified and recorded the governance, a different governance.json fails
# every later invocation, P0 included, even if it is internally consistent on chain.
mk_manifest "$GB"
gov_book "$GB" "$DEP"
expect "ceremony C2: P5 records the verified governance" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
python3 -c 'import json,sys; g=json.load(open(sys.argv[1]))["governance"]; sys.exit(0 if g["GovernanceTimelock"]==sys.argv[2] and g["GuardianMultisig"]==sys.argv[3] else 1)' "$GB/ceremony-run.json" "$(addr 31)" "$(addr 35)" &&
  ok "ceremony C2: the manifest holds the four governance addresses" || bad "ceremony C2: the manifest holds the four governance addresses" "$(cat "$GB/ceremony-run.json")"
GTL=$(addr 51) GMS=$(addr 53) RTL=$(addr 52) RMS=$(addr 55) gov_book "$GB" "$DEP"
gov_chain "$(addr 51)" "$(addr 53)" "$(addr 52)" "$(addr 55)"
expect "ceremony C2: a swapped governance.json fails the P0 preflight of a resume" 3 'GATE FAIL at P0: governance.json is not the governance this run recorded' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P7
reset_calls
expect "ceremony C2: a swapped governance.json stops P2 before regenesis" 3 'not the governance this run recorded' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
if calls | grep -q '^regenesis'; then bad "ceremony C2: no regenesis with a swapped governance" "$(calls)"; else ok "ceremony C2: no regenesis with a swapped governance"; fi
gov_book "$GB" "$DEP"
expect "ceremony C2: P0 re-proves the recorded governance on chain" 3 'GATE FAIL at P0: GOV: threshold on chain is 2' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash -c "$(declare -f fake_call); FAKE='$FAKE'; fake_call '$(addr 33)' threshold 2; bash '$CE' --simulate --only P5"
gov_chain

# C5: the vesting / dormant outputs P5 sweeps are the ones this run first recorded.
mk_manifest "$GB"
printf '{"deployer":"%s","contracts":{"VestingAlice":"%s"}}' "$DEP" "$(addr 71)" >"$GB/team-vesting.json"
expect "ceremony C5: P5 records the vesting output" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
printf '{"deployer":"%s","contracts":{"VestingAlice":"%s"}}' "$DEP" "$(addr 72)" >"$GB/team-vesting.json"
expect "ceremony C5: P5 refuses a vesting output other than the recorded one" 3 'team-vesting.json is not the output this run recorded' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
rm "$GB/team-vesting.json"

# C6: the KEEP list is fixed by hash for the run.
mk_manifest "$GB"
expect "ceremony C6: P6 records the KEEP list" 0 'KEEP gate PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
cp "$LIST" "$T/keep-other.tsv"
printf '# edited after the run started\n' >>"$T/keep-other.tsv"
expect "ceremony C6: P6 refuses another KEEP list than the recorded one (P0 stops it first)" 3 'GATE FAIL at P0: KEEP list: .* records keepListSha256' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$T/keep-other.tsv" bash "$CE" --simulate --only P6
expect "ceremony C6: a resume's P0 refuses another KEEP list" 3 'GATE FAIL at P0: KEEP list: ' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$T/keep-other.tsv" bash "$CE" --simulate --only P7
rm -r "$REPO/contracts/broadcast"
mk_manifest "$GB"

# GENESIS_OUT_DIR: one directory for every producer and consumer path.
expect "ceremony: an output dir outside contracts/genesis is refused" 1 'GENESIS_OUT_DIR must be contracts/genesis' -- "${CEENV[@]}" GENESIS_OUT_DIR="$T/elsewhere" bash "$CE"
expect "ceremony: an output dir that escapes contracts/genesis is refused" 1 'GENESIS_OUT_DIR must be' -- "${CEENV[@]}" GENESIS_OUT_DIR="$REPO/contracts/genesis/../addresses" bash "$CE"
expect "ceremony: dry run reads the books from a nondefault dir" 0 'merge .* \+ genesis/run2/governance.json, genesis/run2/team-vesting.json, genesis/run2/dormant-ledgers.json → genesis/run2/p5-admin-book.json' -- "${CEENV[@]}" GENESIS_OUT_DIR="$REPO/contracts/genesis/run2" bash "$CE"
RUN2="$REPO/contracts/genesis/run2"
mkdir -p "$RUN2"
mk_manifest "$RUN2"
reset_calls
expect "ceremony: P1 writes governance into the nondefault dir" 0 'P0 preflight PASS \(books in genesis/run2/\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P1
calls | grep -q 'forge-env gov=genesis/run2/governance.json ' && ok "ceremony: P1 output path follows GENESIS_OUT_DIR" || bad "ceremony: P1 output path follows GENESIS_OUT_DIR" "$(calls)"
# A stale book in the nondefault dir: P1 refuses to run over it (nothing sent).
printf '{"deployer":"%s","contracts":{"GovernanceTimelock":"%s","GuardianTimelock":"%s","GovernanceMultisig":"%s","GuardianMultisig":"%s"}}' "$DEP" "$(addr 41)" "$(addr 42)" "$(addr 43)" "$(addr 44)" >"$RUN2/governance.json"
gov_chain "$(addr 41)" "$(addr 43)" "$(addr 42)" "$(addr 44)"
reset_calls
expect "ceremony: P1 refuses a stale governance book" 3 'run2/governance.json already exists and P1 would write it' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P1
if calls | grep -q '^forge'; then bad "ceremony: a refused P1 runs no forge" "$(calls)"; else ok "ceremony: a refused P1 runs no forge"; fi
expect "ceremony: a stale book stops a resumed run before P1" 3 'already exists and P1' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --from P1
# Consumers read the same directory: P2 takes the run2 book, not contracts/genesis/governance.json.
expect "ceremony: P2 reads governance from the nondefault dir" 0 'GOVERNANCE=0x0+29 GUARDIAN=0x0+2a' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P2
reset_calls
expect "ceremony: P4 runs with the nondefault dir" 0 'P4 dormant ledgers' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" PATRONAGE_KYC_REGISTRY="$(addr 51)" PATRONAGE_MEMBERSHIP="$(addr 52)" bash "$CE" --simulate --only P4
# A fresh-run-shaped invocation that reaches P4 without P4's inputs: the gate is P4's, and so
# is the resume (before, it said "GATE FAIL at P0 ... --from P0", which starts a fresh run).
out=$("${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --from P3 2>&1)
rc=$?
if [[ $rc -eq 3 ]] && grep -q 'GATE FAIL at P4: .*PATRONAGE_KYC_REGISTRY' <<<"$out" && grep -qF -- "resume: $CE --simulate --from P4" <<<"$out" && ! grep -qF -- '--from P0' <<<"$out"; then
  ok "ceremony P4: a missing P4 input is P4's gate, resumed with --from P4"
else
  bad "ceremony P4: a missing P4 input is P4's gate, resumed with --from P4 (exit $rc)" "$out"
fi
calls | grep -q 'forge-env gov=[^ ]* vest=[^ ]* dormant=genesis/run2/dormant-ledgers.json govbook=genesis/run2/governance.json ' && ok "ceremony: P4 reads and writes the nondefault dir" || bad "ceremony: P4 reads and writes the nondefault dir" "$(calls)"
reset_calls
expect "ceremony: P5 checks the nondefault dir's books" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P5
calls | grep -q '^forge-book genesis/run2/p5-admin-book.json$' && grep -q "$(addr 41)" "$RUN2/p5-admin-book.json" && ok "ceremony: P5 merges the nondefault dir's books" || bad "ceremony: P5 merges the nondefault dir's books" "$(calls)"
rm -r "$RUN2"

# ------------------------------------------------------------------ address-book generator
# scripts/ops/emit-address-table.sh (what regenesis.sh runs and P2 verifies, C8) over synthetic
# broadcasts in a temp repo. ENV_TESTNET points at a file inside the temp dir; the real one is
# never read.
GR="$T/genrepo"
EMIT="$GR/scripts/ops/emit-address-table.sh"
mkdir -p "$GR/scripts/ops" "$GR/contracts/addresses"
cp "$G/../ops/emit-address-table.sh" "$EMIT"
printf 'DEPLOYER_ADDRESS=%s\nCITRATE_AA_ENTRY_POINT=%s\n' "$(addr 4242)" "$(addr 4243)" >"$T/env.testnet"
# bcast <script> <timestamp> <name:addr>...: a forge run-latest.json with CREATE2 rows.
bcast() {
  local f="$GR/contracts/broadcast/$1/40204/run-latest.json" ts="$2" rows="" r
  shift 2
  for r in "$@"; do rows+="${rows:+,}{\"transactionType\":\"CREATE2\",\"contractName\":\"${r%%:*}\",\"contractAddress\":\"${r#*:}\"}"; done
  mkdir -p "$(dirname "$f")"
  printf '{"timestamp":%s,"transactions":[%s]}\n' "$ts" "$rows" >"$f"
}
GBOOK="$GR/contracts/addresses/40204.json"
stale_book() {
  printf '{"chainId":40204,"deployer":"0x4250675F9015E65fC866F3a373F82bb9DFc000c6","contracts":{"ValidatorRegistry":"%s","CitrateMemberSBT":"%s","MemberBond":"%s","MembershipStakeVaultImpl":"%s","MembershipStakeVault":"%s","AnchorRegistry":"%s"},"aaStack":{},"CitrateMemberSBT":"%s","MembershipStakeVault":"%s","governance":{"GOVERNANCE":"%s","GUARDIAN":"%s"}}\n' \
    "$(addr 3001)" "$(addr 3002)" "$(addr 3003)" "$(addr 3004)" "$(addr 3005)" "$(addr 3006)" "$(addr 3002)" "$(addr 3005)" "$(addr 3007)" "$(addr 3008)" >"$GBOOK"
}
jqv() { jq -r "$1" "$GBOOK"; }
FD=$(addr 2001)
bcast DeployValidatorRegistry.s.sol 9000 "ValidatorRegistry:$(addr 2101)"
bcast DeployCoreMembership.s.sol 9001 "CitrateMemberSBT:$(addr 2102)" "MemberBond:$(addr 2103)" "MembershipStakeVault:$(addr 2104)" "ERC1967Proxy:$(addr 2105)"
bcast DeployEduStack.s.sol 1000 "StaleEdu:$(addr 2999)" # an earlier chain's broadcast
stale_book
GEMIT=(env ENV_TESTNET="$T/env.testnet" RPC_URL= GOVERNANCE="$(addr 31)" GUARDIAN="$(addr 32)")
expect "generator: a fresh genesis needs EMIT_DEPLOYER" 1 'needs EMIT_DEPLOYER' -- "${GEMIT[@]}" EMIT_FRESH_GENESIS=1 EMIT_BROADCAST_SINCE=5000 bash "$EMIT"
expect "generator: a fresh genesis needs EMIT_BROADCAST_SINCE" 1 'needs EMIT_BROADCAST_SINCE' -- "${GEMIT[@]}" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD" bash "$EMIT"
expect "generator: a malformed EMIT_DEPLOYER is refused" 1 'EMIT_DEPLOYER is not an address' -- "${GEMIT[@]}" EMIT_DEPLOYER=0x12 bash "$EMIT"
expect "generator: a fresh genesis builds the book from this run's broadcasts" 0 'not carried from the previous book: AnchorRegistry' -- "${GEMIT[@]}" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD" EMIT_BROADCAST_SINCE=5000 bash "$EMIT"
[[ "$(jqv .deployer)" == "$FD" ]] && ok "generator: the fresh book names EMIT_DEPLOYER, not the .env.testnet or historical deployer" ||
  bad "generator: the fresh book names EMIT_DEPLOYER, not the .env.testnet or historical deployer" "$(jqv .deployer)"
[[ "$(jqv '[.contracts.ValidatorRegistry, .contracts.CitrateMemberSBT, .contracts.MemberBond, .contracts.MembershipStakeVaultImpl, .contracts.MembershipStakeVault, .CitrateMemberSBT, .MembershipStakeVault] | join(" ")')" == \
  "$(addr 2101) $(addr 2102) $(addr 2103) $(addr 2104) $(addr 2105) $(addr 2102) $(addr 2105)" ]] &&
  ok "generator: membership entries and root aliases come from this run's DeployCoreMembership (impl vs proxy kept)" ||
  bad "generator: membership entries and root aliases come from this run's DeployCoreMembership (impl vs proxy kept)" "$(cat "$GBOOK")"
[[ "$(jqv '[(.contracts | has("AnchorRegistry")), (.contracts | has("StaleEdu")), (.aaStack | length)] | join(" ")')" == "false false 0" ]] &&
  ok "generator: a fresh book carries no previous-book entry, no pre-genesis broadcast and no .env.testnet pin" ||
  bad "generator: a fresh book carries no previous-book entry, no pre-genesis broadcast and no .env.testnet pin" "$(cat "$GBOOK")"
[[ "$(jqv '[.governance.GOVERNANCE, .governance.GUARDIAN] | join(" ")')" == "$(addr 31) $(addr 32)" ]] &&
  ok "generator: the fresh book's governance block is this run's GOVERNANCE/GUARDIAN" ||
  bad "generator: the fresh book's governance block is this run's GOVERNANCE/GUARDIAN" "$(jqv .governance)"
cp "$GBOOK" "$T/fresh1.json"
expect "generator: a fresh regeneration is reproducible" 0 'wrote' -- "${GEMIT[@]}" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD" EMIT_BROADCAST_SINCE=5000 EMIT_OUTPUT="$T/fresh2.json" bash "$EMIT"
cmp -s "$T/fresh1.json" "$T/fresh2.json" && ok "generator: the same broadcasts give the same fresh book byte for byte" || bad "generator: the same broadcasts give the same fresh book byte for byte" "$(diff "$T/fresh1.json" "$T/fresh2.json")"
# Not fresh: EMIT_DEPLOYER (what regenesis.sh passes) wins over .env.testnet, the regenerated
# membership entries replace the old ones and their root aliases follow; other keys carry over.
stale_book
expect "generator: an incremental regeneration still runs" 0 'wrote' -- "${GEMIT[@]}" EMIT_DEPLOYER="$FD" bash "$EMIT"
[[ "$(jqv '[.deployer, .contracts.MembershipStakeVault, .MembershipStakeVault, .CitrateMemberSBT, .contracts.AnchorRegistry] | join(" ")')" == "$FD $(addr 2105) $(addr 2105) $(addr 2102) $(addr 3006)" ]] &&
  ok "generator: an incremental book takes EMIT_DEPLOYER and the new membership, and keeps the rest" ||
  bad "generator: an incremental book takes EMIT_DEPLOYER and the new membership, and keeps the rest" "$(cat "$GBOOK")"
# One canonical spelling: every address the generator writes is lowercase, whatever case its
# input had. `cast wallet address` prints the EIP-55 checksummed form, so a checksummed
# EMIT_DEPLOYER (what regenesis.sh passes as typed) is the likely input on the day; the
# ceremony's P2 gate re-runs the generator with the manifest's lowercase deployer and needs
# the same book.
FD_CS=0x00000000000000000000000000000000000007D1 # addr 2001, checksummed
GOV_MIXED=0xAbCdEf0123456789aBcDeF0123456789AbCdEf31
GRD_MIXED=0xaBcDeF0123456789AbCdEf0123456789aBcDeF32
bcast DeployCoreMembership.s.sol 9001 "CitrateMemberSBT:$(addr 2102)" "MemberBond:$(addr 2103)" "MembershipStakeVault:$(addr 2104)" "ERC1967Proxy:$(addr 2105)"
expect "generator: a fresh genesis with mixed-case inputs still runs" 0 'wrote' -- "${GEMIT[@]}" GOVERNANCE="$GOV_MIXED" GUARDIAN="$GRD_MIXED" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD_CS" EMIT_BROADCAST_SINCE=5000 EMIT_OUTPUT="$T/fresh-cs.json" bash "$EMIT"
[[ "$(jq -r .deployer "$T/fresh-cs.json")" == "$FD" ]] && ok "generator: a checksummed EMIT_DEPLOYER is written lowercase" ||
  bad "generator: a checksummed EMIT_DEPLOYER is written lowercase" "$(jq -r .deployer "$T/fresh-cs.json")"
[[ "$(jq -r '[.governance.GOVERNANCE, .governance.GUARDIAN] | join(" ")' "$T/fresh-cs.json")" == "$(lower_t "$GOV_MIXED") $(lower_t "$GRD_MIXED")" ]] &&
  ok "generator: a mixed-case GOVERNANCE/GUARDIAN is written lowercase" ||
  bad "generator: a mixed-case GOVERNANCE/GUARDIAN is written lowercase" "$(jq -c .governance "$T/fresh-cs.json")"
expect "generator: the same run with a lowercase deployer still runs" 0 'wrote' -- "${GEMIT[@]}" GOVERNANCE="$(lower_t "$GOV_MIXED")" GUARDIAN="$(lower_t "$GRD_MIXED")" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD" EMIT_BROADCAST_SINCE=5000 EMIT_OUTPUT="$T/fresh-lc.json" bash "$EMIT"
cmp -s "$T/fresh-cs.json" "$T/fresh-lc.json" && ok "generator: the book is the same byte for byte whatever case the inputs had" ||
  bad "generator: the book is the same byte for byte whatever case the inputs had" "$(diff "$T/fresh-cs.json" "$T/fresh-lc.json")"
# canonical_addrs <book>: every 0x-prefixed 20-byte string anywhere in the book is lowercase.
canonical_addrs() {
  jq -e '[.. | strings | select(test("^0x[0-9a-fA-F]{40}$")) | select(. != ascii_downcase)] | length == 0' "$1" >/dev/null
}
canonical_addrs "$T/fresh-cs.json" && ok "generator: every address in a fresh book is lowercase (static blocks included)" ||
  bad "generator: every address in a fresh book is lowercase (static blocks included)" "$(jq -c '[.. | strings | select(test("^0x[0-9a-fA-F]{40}$")) | select(. != ascii_downcase)]' "$T/fresh-cs.json")"
# Incremental mode: the .env.testnet pins (AA stack, deployer fallback) are canonicalised too.
printf 'DEPLOYER_ADDRESS=%s\nCITRATE_AA_ENTRY_POINT=%s\n' "$FD_CS" 0x0000000071727De22E5E9d8BAf0edAc6f37da032 >"$T/env.mixed"
stale_book
expect "generator: an incremental regeneration with mixed-case pins runs" 0 'wrote' -- "${GEMIT[@]}" ENV_TESTNET="$T/env.mixed" bash "$EMIT"
[[ "$(jqv '[.deployer, .aaStack.EntryPoint] | join(" ")')" == "$FD 0x0000000071727de22e5e9d8baf0edac6f37da032" ]] && canonical_addrs "$GBOOK" &&
  ok "generator: mixed-case .env.testnet pins are written lowercase" ||
  bad "generator: mixed-case .env.testnet pins are written lowercase" "$(cat "$GBOOK")"
stale_book
expect "generator: the historical default deployer is written lowercase" 0 'wrote' -- "${GEMIT[@]}" ENV_TESTNET=/dev/null bash "$EMIT"
[[ "$(jqv .deployer)" == 0x4250675f9015e65fc866f3a373f82bb9dfc000c6 ]] && canonical_addrs "$GBOOK" &&
  ok "generator: the default deployer and every other address are lowercase" ||
  bad "generator: the default deployer and every other address are lowercase" "$(jqv .deployer)"
bcast DeployCoreMembership.s.sol 9001 "CitrateMemberSBT:$(addr 2102)" "MemberBond:$(addr 2103)" "MembershipStakeVault:$(addr 2104)"
expect "generator: a membership broadcast without the vault proxy is refused" 2 'expected CitrateMemberSBT, MemberBond, MembershipStakeVault and its ERC1967Proxy' -- "${GEMIT[@]}" EMIT_FRESH_GENESIS=1 EMIT_DEPLOYER="$FD" EMIT_BROADCAST_SINCE=5000 bash "$EMIT"

# ------------------------------------------------------------------ P5 with the real checker
# Integration: the real CheckDeployedAdmins (this tree's script and AdminChecks) under real
# forge, against a local anvil, driven through genesis_ceremony.sh --simulate --only P5. A
# contract that only the governance output lists, and whose governance() is still the
# deployer, must fail the gate. Needs forge, cast and anvil (Foundry) and solc 0.8.36 in the
# Foundry cache; without the tools it is skipped and says so (it is not counted as passed).
# The temp project is the checker's own sources plus forge-std; its foundry.toml adds read
# access to ./genesis, which the genesis contract set (chain#320) adds to contracts/.
REAL_FORGE=$(command -v forge || true)
REAL_CAST=$(command -v cast || true)
REAL_ANVIL=$(command -v anvil || true)
SRC="$(cd "$G/../.." && pwd)/contracts"
if [[ -z "$REAL_FORGE" || -z "$REAL_CAST" || -z "$REAL_ANVIL" || "${GENESIS_TESTS_NO_FOUNDRY:-0}" == 1 ]]; then
  if [[ "${GENESIS_E2E_REQUIRED:-0}" == 1 ]]; then
    bad "integration: required (GENESIS_E2E_REQUIRED=1) but forge/cast/anvil are not on PATH"
  else
    printf 'SKIP P5 real-checker integration (forge/cast/anvil not on PATH)\n'
  fi
else
  IR="$T/irepo"
  IC="$IR/contracts"
  mkdir -p "$IC/script/lib" "$IC/src/aa/lib/webauthn" "$IC/lib" "$IC/genesis" "$IC/addresses" "$IR/scripts/ops"
  sed 's|{ access = "read", path = "./addresses" }\]|{ access = "read", path = "./addresses" }, { access = "read", path = "./genesis" }]|' \
    "$SRC/foundry.toml" >"$IC/foundry.toml"
  cp "$SRC/remappings.txt" "$IC/"
  ln -s "$SRC/lib/forge-std" "$IC/lib/forge-std"
  # On-chain councils for the C3 checks (and a registry for C4): minimal contracts with the
  # getters P5 reads. They exist only in this temp project.
  mkdir -p "$IC/src/fixtures"
  cat >"$IC/src/fixtures/GenesisFixtures.sol" <<'SOL'
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

contract FixtureTimelock {
    uint256 internal immutable _delay;
    address internal _proposer;

    constructor(uint256 d) {
        _delay = d;
    }

    function setProposer(address p) external {
        require(_proposer == address(0), "set");
        _proposer = p;
    }

    function getMinDelay() external view returns (uint256) {
        return _delay;
    }

    function hasRole(bytes32 role, address a) external view returns (bool) {
        return role == keccak256("PROPOSER_ROLE") && a == _proposer;
    }
}

contract FixtureMultisig {
    address public immutable timelock;
    uint256 public immutable threshold;
    address[] internal _owners;

    constructor(address t, address[] memory o, uint256 th) {
        timelock = t;
        _owners = o;
        threshold = th;
    }

    function owners() external view returns (address[] memory) {
        return _owners;
    }
}

contract FixtureRegistry {
    address public governance;
    address public slasher;
    address public pendingGovernance;

    constructor(address g, address s) {
        governance = g;
        slasher = s;
    }
}
SOL
  cp "$SRC/script/CheckDeployedAdmins.s.sol" "$IC/script/"
  cp "$SRC/script/lib/AdminChecks.sol" "$IC/script/lib/"
  cp "$SRC/src/aa/lib/webauthn/P256.sol" "$IC/src/aa/lib/webauthn/"
  # P0 only checks that the other ceremony scripts exist.
  for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers; do
    printf '// SPDX-License-Identifier: Apache-2.0\npragma solidity ^0.8.26;\n' >"$IC/script/$s.s.sol"
  done
  printf '#!/usr/bin/env bash\nexit 0\n' >"$IR/scripts/ops/regenesis.sh"
  if ! out=$(cd "$IC" && "$REAL_FORGE" build 2>&1); then
    bad "P5 integration: the checker builds" "$out"
  else
    port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    IRPC="http://127.0.0.1:$port"
    "$REAL_ANVIL" --port "$port" --silent >"$T/anvil.log" 2>&1 &
    ANVIL_PID=$!
    trap 'kill "$ANVIL_PID" 2>/dev/null; rm -rf "$T"' EXIT
    for _ in $(seq 100); do
      "$REAL_CAST" chain-id --rpc-url "$IRPC" >/dev/null 2>&1 && break
      sleep 0.1
    done
    # Runtime code answering governance() with the given address; any other call reverts.
    gov_code() { printf '0x60003560e01c635aa6e67514601357600080fd5b73%s60005260206000f3' "${1#0x}"; }
    set_code() { "$REAL_CAST" rpc anvil_setCode "$1" "$2" --rpc-url "$IRPC" >/dev/null; }
    MSIG=$(addr 209)
    set_code 0xc2b78104907F722DABAc4C69f826a522B2754De4 0x600160005260206000f3 # the P-256 verifier
    for i in 161 31 32 33; do set_code "$(addr "$i")" "$(gov_code "$MSIG")"; done
    set_code "$(addr 34)" "$(gov_code "$DEP")"
    ANVIL0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 # anvil's first unlocked account
    fcreate() { # contract [constructor args...] -> deployed address
      (cd "$IC" && "$REAL_FORGE" create --rpc-url "$IRPC" --unlocked --from "$ANVIL0" --broadcast "src/fixtures/GenesisFixtures.sol:$1" ${2:+--constructor-args} "${@:2}" 2>&1) |
        sed -n 's/^Deployed to: //p'
    }
    council_fixture() { # delay threshold owner ids... -> "timelock multisig"
      local d="$1" t="$2" tl ms ids=""
      shift 2
      for i in "$@"; do ids+="${ids:+,}$(addr "$i")"; done
      tl=$(fcreate FixtureTimelock "$d")
      ms=$(fcreate FixtureMultisig "$tl" "[$ids]" "$t")
      "$REAL_CAST" send "$tl" "setProposer(address)" "$ms" --unlocked --from "$ANVIL0" --rpc-url "$IRPC" >/dev/null 2>&1
      printf '%s %s\n' "$tl" "$ms"
    }
    read -r GTL GMS < <(council_fixture 172800 3 11 12 13 14 15)
    read -r RTL RMS < <(council_fixture 3600 2 21 22 23)
    export GTL GMS RTL RMS
    if is_addr_t() { [[ "$1" =~ ^0x[0-9a-fA-F]{40}$ ]]; }; is_addr_t "$GTL" && is_addr_t "$GMS" && is_addr_t "$RTL" && is_addr_t "$RMS"; then
      ok "P5 integration: council fixtures deployed on anvil"
    else
      bad "P5 integration: council fixtures deployed on anvil" "$GTL $GMS $RTL $RMS"
    fi
    printf '{"chainId":31337,"deployer":"%s","contracts":{"Alpha":"%s"},"aaStack":{}}' "$DEP" "$A1" >"$IC/addresses/40204.json"
    IENV=("${CEENV[@]}" REPO_ROOT="$IR" RPC_URL="$IRPC" EXPECTED_CHAIN_ID=31337 FORGE="$REAL_FORGE" CAST="$REAL_CAST")
    ig0=$("$REAL_CAST" block 0 --field hash --rpc-url "$IRPC")
    ig0ts=$("$REAL_CAST" block 0 --field timestamp --rpc-url "$IRPC")
    mk_manifest "$IC/genesis" "$DEP" simulate "" "$ig0" "$((ig0ts))"
    sed -i 's/"chainId":40204/"chainId":31337/' "$IC/genesis/ceremony-run.json"
    gov_book "$IC/genesis" "$DEP"
    expect "P5 integration: a handed-over governance output passes the real checker" 0 'P5 PASS' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    gov_book "$IC/genesis" "$DEP" "\"GenesisHeld\":\"$(addr 34)\""
    expect "P5 integration: a deployer role held only in the governance output fails the real checker" 3 'DEPLOYER-ADMIN GenesisHeld: governance\(\) is the deployer EOA' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    # Binding: stale books that agree on the deployer while this run used another one never
    # reach the checker.
    mk_manifest "$IC/genesis" "$(addr 2)" simulate "" "$ig0" "$((ig0ts))"
    sed -i 's/"chainId":40204/"chainId":31337/' "$IC/genesis/ceremony-run.json"
    expect "P5 integration: books naming another deployer than the run's are refused before the real checker" 3 "not this run's deployer 0x0+2" -- "${IENV[@]}" DEPLOYER_ADDRESS="$(addr 2)" bash "$CE" --simulate --only P5
    # C3 on a real chain: a council whose threshold differs from the validated input fails.
    mk_manifest "$IC/genesis" "$DEP" simulate "" "$ig0" "$((ig0ts))"
    sed -i 's/"chainId":40204/"chainId":31337/' "$IC/genesis/ceremony-run.json"
    gov_book "$IC/genesis" "$DEP"
    expect "P5 integration: the real councils pass the on-chain floor check" 0 'P5 governance floors hold on chain' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    mk_manifest "$IC/genesis" "$DEP" simulate "" "$ig0" "$((ig0ts))"
    sed -i 's/"chainId":40204/"chainId":31337/' "$IC/genesis/ceremony-run.json"
    read -r WTL WMS < <(council_fixture 172800 2 11 12 13 14 15)
    GTL="$WTL" GMS="$WMS" gov_book "$IC/genesis" "$DEP"
    expect "P5 integration: a 2-of-5 governance council on chain fails" 3 'GOV: threshold on chain is 2, the validated input is 3' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    # C4 on a real chain (Codex r6): the registry's governance is a stale EOA. The real checker
    # alone does not see it (the EOA is neither the factory nor the deployer); P5 does.
    mk_manifest "$IC/genesis" "$DEP" simulate "" "$ig0" "$((ig0ts))"
    sed -i 's/"chainId":40204/"chainId":31337/' "$IC/genesis/ceremony-run.json"
    gov_book "$IC/genesis" "$DEP"
    SVR=$(fcreate FixtureRegistry "$(addr 99)" "$GTL")
    printf '{"chainId":31337,"deployer":"%s","contracts":{"Alpha":"%s","ValidatorRegistry":"%s"},"aaStack":{}}' "$DEP" "$A1" "$SVR" >"$IC/addresses/40204.json"
    if (cd "$IC" && ADDRESS_BOOK=addresses/40204.json "$REAL_FORGE" script script/CheckDeployedAdmins.s.sol --rpc-url "$IRPC" 2>&1) | grep -q 'DEPLOYER-ADMIN failures: 0'; then
      ok "P5 integration: the real checker alone passes a registry governed by a stale EOA"
    else
      bad "P5 integration: the real checker alone passes a registry governed by a stale EOA"
    fi
    expect "P5 integration: P5 fails a registry governed by a stale EOA" 3 'ValidatorRegistry.governance\(\) is 0x0+63' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    GVR=$(fcreate FixtureRegistry "$GTL" "$GTL")
    printf '{"chainId":31337,"deployer":"%s","contracts":{"Alpha":"%s","ValidatorRegistry":"%s"},"aaStack":{}}' "$DEP" "$A1" "$GVR" >"$IC/addresses/40204.json"
    expect "P5 integration: P5 passes a registry governed by this run's GOVERNANCE" 0 'governance and slasher are GOVERNANCE' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    kill "$ANVIL_PID" 2>/dev/null

    # ---------------------------------------------------------- fresh genesis end to end (C8)
    # P2 --confirm on a fresh anvil chain (id 40204) through the REAL regenesis.sh, the REAL
    # emit-address-table.sh and the real DeployValidatorRegistry / DeployCoreMembership scripts,
    # then P5 --confirm with the real checker over the book the generator wrote. The other
    # ceremonies regenesis.sh runs (DeployAll, AA, ...) are not in this temp project: a forge shim
    # on PATH says so and skips them, and stands in for the keystore (--account becomes anvil's
    # --unlocked for the impersonated deployer). Two runs on two fresh chains with a different
    # MEMBERSHIP_OWNER and a different governance council (so a different ValidatorRegistry):
    # the book follows each run, and nothing from the stale committed book survives.
    if [[ ! -f "$SRC/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol" ]]; then
      if [[ "${GENESIS_E2E_REQUIRED:-0}" == 1 ]]; then
        bad "fresh genesis e2e: required (GENESIS_E2E_REQUIRED=1) but contracts/lib/openzeppelin-contracts is not checked out"
      else
        printf 'SKIP fresh-genesis end to end (contracts/lib/openzeppelin-contracts is not checked out)\n'
      fi
    else
      FR="$T/frepo"
      FC="$FR/contracts"
      ROOT_SRC="$(cd "$G/../.." && pwd)"
      mkdir -p "$FC/script/lib" "$FC/src/core_membership" "$FC/src/lib" "$FC/src/aa/lib/webauthn" "$FC/src/fixtures" "$FC/lib" \
        "$FC/genesis" "$FC/addresses" "$FR/scripts/ops" "$FR/scripts/ci" "$T/fbin"
      cp "$IC/foundry.toml" "$IC/remappings.txt" "$FC/"
      ln -s "$SRC/lib/forge-std" "$FC/lib/forge-std"
      ln -s "$SRC/lib/openzeppelin-contracts" "$FC/lib/openzeppelin-contracts"
      for f in script/CheckDeployedAdmins.s.sol script/lib/AdminChecks.sol script/DeployValidatorRegistry.s.sol \
        script/DeployCoreMembership.s.sol script/ScriptEnv.sol script/Salts.sol src/ValidatorRegistry.sol \
        src/lib/ReentrancyGuard.sol src/lib/Governable.sol src/lib/InitialAdmin.sol src/aa/lib/webauthn/P256.sol \
        src/core_membership/CitrateMemberSBT.sol src/core_membership/MemberBond.sol \
        src/core_membership/MembershipStakeVault.sol src/core_membership/MemberEmblem.sol; do
        cp "$SRC/$f" "$FC/$f"
      done
      cp "$IC/src/fixtures/GenesisFixtures.sol" "$FC/src/fixtures/"
      for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers; do cp "$IC/script/$s.s.sol" "$FC/script/"; done
      cp "$ROOT_SRC/scripts/ops/regenesis.sh" "$ROOT_SRC/scripts/ops/emit-address-table.sh" "$FR/scripts/ops/"
      cp "$ROOT_SRC/scripts/ci/check-create2-determinism.sh" "$FR/scripts/ci/"
      cat >"$T/fbin/forge" <<'EOF'
#!/usr/bin/env bash
# Test shim for regenesis.sh: --account NAME becomes --unlocked (anvil signs for the
# impersonated deployer); `forge script script/X` for a ceremony this temp project does not
# hold is reported and skipped. Everything else is the real forge.
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --account) args+=(--unlocked); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ "${args[0]:-}" == script && ! -f "${args[1]:-}" ]]; then
  echo "forge shim: ${args[1]} is not in this test's stack; skipped"
  exit 0
fi
exec "$REAL_FORGE" "${args[@]}"
EOF
      chmod +x "$T/fbin/forge"
      export REAL_FORGE
      # C9 at the source: ScriptEnv.deployerAddress(), which every deploy script uses, run under
      # the real forge (local, no RPC) with each combination of the two deployer inputs.
      cat >"$FC/script/DeployerProbe.s.sol" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import "./ScriptEnv.sol";
contract DeployerProbe is ScriptEnv {
    function run() external {
        console.log("PROBE-DEPLOYER", deployerAddress());
    }
}
EOF
      PD=0xabcdef0123456789abcdef0123456789abcdef01
      probe() { (cd "$FC" && env -u DEPLOYER_ADDRESS -u CEREMONY_DEPLOYER_ADDRESS "$@" "$REAL_FORGE" script script/DeployerProbe.s.sol 2>&1); }
      for c in "agree:0:PROBE-DEPLOYER $PD:DEPLOYER_ADDRESS=$PD CEREMONY_DEPLOYER_ADDRESS=$PD" \
        "only DEPLOYER_ADDRESS:0:PROBE-DEPLOYER $PD:DEPLOYER_ADDRESS=$PD" \
        "only CEREMONY_DEPLOYER_ADDRESS:0:PROBE-DEPLOYER $PD:CEREMONY_DEPLOYER_ADDRESS=$PD" \
        "disagree:1:CEREMONY_DEPLOYER_ADDRESS and DEPLOYER_ADDRESS name different deployers:DEPLOYER_ADDRESS=$PD CEREMONY_DEPLOYER_ADDRESS=$(addr 99)" \
        "CEREMONY_DEPLOYER_ADDRESS empty:1:CEREMONY_DEPLOYER_ADDRESS is set but is not an address:DEPLOYER_ADDRESS=$PD CEREMONY_DEPLOYER_ADDRESS=" \
        "CEREMONY_DEPLOYER_ADDRESS malformed:1:CEREMONY_DEPLOYER_ADDRESS is set but is not an address:DEPLOYER_ADDRESS=$PD CEREMONY_DEPLOYER_ADDRESS=0x12" \
        "CEREMONY_DEPLOYER_ADDRESS zero:1:CEREMONY_DEPLOYER_ADDRESS is the zero address:DEPLOYER_ADDRESS=$PD CEREMONY_DEPLOYER_ADDRESS=0x0000000000000000000000000000000000000000" \
        "neither:1:set CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS:"; do
        IFS=: read -r cname cwant cpat cenv <<<"$c"
        read -ra cvars <<<"$cenv"
        out=$(probe "${cvars[@]}")
        rc=$?
        if { [[ "$cwant" == 0 && $rc -eq 0 ]] || [[ "$cwant" == 1 && $rc -ne 0 ]]; } && grep -qiF -- "$cpat" <<<"$out"; then
          ok "ScriptEnv C9: deployer inputs $cname"
        else
          bad "ScriptEnv C9: deployer inputs $cname (exit $rc)" "$out"
        fi
      done
      fport=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
      FRPC="http://127.0.0.1:$fport"
      FANVIL_PID=""
      trap 'kill "$ANVIL_PID" ${FANVIL_PID:+"$FANVIL_PID"} 2>/dev/null; rm -rf "$T"' EXIT
      FDEP=0xd1e0000000000000000000000000000000000001 # the fresh deployer (impersonated)
      FDEP_CS=0xd1E0000000000000000000000000000000000001 # the same, EIP-55 (as `cast wallet address` prints it)
      printf '#!/usr/bin/env bash\necho "generator re-run failed (test fault)" >&2\nexit 1\n' >"$T/fail-emit.sh"
      fcast() { "$REAL_CAST" "$@" --rpc-url "$FRPC"; }
      ffcreate() { # contract [constructor args...] -> deployed address (deployed by anvil's first account)
        (cd "$FC" && "$REAL_FORGE" create --rpc-url "$FRPC" --unlocked --from "$ANVIL0" --broadcast "src/fixtures/GenesisFixtures.sol:$1" ${2:+--constructor-args} "${@:2}" 2>&1) |
          sed -n 's/^Deployed to: //p'
      }
      fcouncil() { # delay threshold owner ids... -> "timelock multisig"
        local d="$1" t="$2" tl ms ids=""
        shift 2
        for i in "$@"; do ids+="${ids:+,}$(addr "$i")"; done
        tl=$(ffcreate FixtureTimelock "$d")
        ms=$(ffcreate FixtureMultisig "$tl" "[$ids]" "$t")
        fcast send "$tl" "setProposer(address)" "$ms" --unlocked --from "$ANVIL0" >/dev/null 2>&1
        printf '%s %s\n' "$tl" "$ms"
      }
      FCODE_MSIG=$(addr 209)
      # e2e_run <label> <membership owner> <extra txs before the councils> <deployer spelling>
      # [gate-fault]: a fresh chain, P2 and P5 --confirm. Sets RUN_VR RUN_SBT RUN_VAULT
      # RUN_VAULT_IMPL from the generated book. The deployer spelling is what the operator types
      # as DEPLOYER_ADDRESS (and in the councils' and outputs' inputs): the book is canonical
      # (lowercase) either way. gate-fault: the gate after P2's broadcast fails once, and the
      # run recovers through the record step without sending again.
      e2e_run() {
        local label="$1" owner="$2" i g0 g0ts book="$FC/addresses/40204.json" dspell="$4" fault="${5:-}" n_sent out rc spelled=()
        [[ -z "$FANVIL_PID" ]] || { kill "$FANVIL_PID" 2>/dev/null; wait "$FANVIL_PID" 2>/dev/null; }
        "$REAL_ANVIL" --port "$fport" --chain-id 40204 --silent >"$T/fanvil.log" 2>&1 &
        FANVIL_PID=$!
        for _ in $(seq 100); do fcast chain-id >/dev/null 2>&1 && break; sleep 0.1; done
        for ((i = 0; i < $3; i++)); do fcast send "$(addr 77)" --value 1 --unlocked --from "$ANVIL0" >/dev/null 2>&1; done
        read -r GTL GMS < <(fcouncil 172800 3 11 12 13 14 15)
        read -r RTL RMS < <(fcouncil 3600 2 21 22 23)
        fcast rpc anvil_impersonateAccount "$FDEP" >/dev/null
        fcast rpc anvil_setBalance "$FDEP" 0x56bc75e2d63100000 >/dev/null
        for a in 71 81 82; do fcast rpc anvil_setCode "$(addr "$a")" "$(gov_code "$FCODE_MSIG")" >/dev/null; done
        # The checker needs the P-256 verifier, which regenesis.sh's aa/DeployP256Verifier step (not
        # in this temp project) provisions on a real chain.
        fcast rpc anvil_setCode 0xc2b78104907F722DABAc4C69f826a522B2754De4 0x600160005260206000f3 >/dev/null
        g0=$(fcast block 0 --field hash)
        g0ts=$(fcast block 0 --field timestamp)
        rm -f "$FC"/genesis/*.json
        mk_manifest "$FC/genesis" "$FDEP" confirm fixture "$g0" "$((g0ts))"
        gov_book "$FC/genesis" "$dspell"
        printf '{"deployer":"%s","contracts":{"VestingAlice":"%s"}}' "$dspell" "$(addr 71)" >"$FC/genesis/team-vesting.json"
        printf '{"deployer":"%s","contracts":{"FederatedRoundLedger":"%s","PatronageLedger":"%s"}}' "$dspell" "$(addr 81)" "$(addr 82)" >"$FC/genesis/dormant-ledgers.json"
        if [[ "$dspell" != "$FDEP" ]]; then
          # Mixed-case variants of the other address inputs: the council owners (upper-case
          # hex) and a deployer alias spelled exactly as typed.
          spelled=(GOV_OWNERS="$(owners 11 12 13 14 15 | tr 'a-f' 'A-F' | sed 's/0X/0x/g')" GRD_OWNERS="$(owners 21 22 23 | tr 'a-f' 'A-F' | sed 's/0X/0x/g')"
            EMIT_DEPLOYER="$dspell")
        fi
        FENV=("${CEENV[@]}" REPO_ROOT="$FR" DEPLOYER_ADDRESS="$dspell" RPC_URL="$FRPC" EXPECTED_CHAIN_ID=40204
          EXPECTED_GENESIS_HASH="$g0" FORGE="$REAL_FORGE" CAST="$REAL_CAST" PATH="$T/fbin:$PATH" MEMBERSHIP_OWNER="$owner"
          TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS="$FRPC" "${spelled[@]}")
        if [[ "$label" == run1 ]]; then
          # A stale generator preset is refused before anything is broadcast.
          expect "fresh genesis e2e: a stale EMIT_DEPLOYER stops P2 before any broadcast" 3 "EMIT_DEPLOYER is set to '0x0+63'" -- "${FENV[@]}" EMIT_DEPLOYER="$STALE" bash "$CE" --confirm --only P2 --account fixture
          [[ "$(fcast nonce "$FDEP")" == 0 ]] && ok "fresh genesis e2e: the refused P2 sent nothing" || bad "fresh genesis e2e: the refused P2 sent nothing" "nonce $(fcast nonce "$FDEP")"
          # C9: the alias the deploy scripts prefer, stale, is refused the same way.
          expect "fresh genesis e2e: a stale CEREMONY_DEPLOYER_ADDRESS stops P2 before any broadcast" 3 "GATE FAIL at P0: CEREMONY_DEPLOYER_ADDRESS is set to '0x0+63'" -- "${FENV[@]}" CEREMONY_DEPLOYER_ADDRESS="$STALE" bash "$CE" --confirm --only P2 --account fixture
          [[ "$(fcast nonce "$FDEP")" == 0 ]] && ok "fresh genesis e2e: the refused CEREMONY_DEPLOYER_ADDRESS sent nothing" || bad "fresh genesis e2e: the refused CEREMONY_DEPLOYER_ADDRESS sent nothing" "nonce $(fcast nonce "$FDEP")"
        fi
        if [[ "$fault" == gate-fault ]]; then
          out=$("${FENV[@]}" EMITTER="$T/fail-emit.sh" bash "$CE" --confirm --only P2 --account fixture 2>&1)
          rc=$?
          n_sent=$(fcast nonce "$FDEP")
          if [[ $rc -eq 3 && "$n_sent" -gt 0 ]] && grep -q 'P2 has already broadcast' <<<"$out" &&
            grep -qF -- '--confirm --only P2 --record-stack-book --account fixture' <<<"$out" && [[ -z "$(reruns_p2 "$out")" ]]; then
            ok "fresh genesis e2e ($label): a gate failure after P2 broadcast names the record step, never a P2 re-run"
          else
            bad "fresh genesis e2e ($label): a gate failure after P2 broadcast names the record step, never a P2 re-run (exit $rc, nonce $n_sent)" "$out"
          fi
          expect "fresh genesis e2e ($label): P2 is refused once its broadcasts are recorded" 3 'this run.s P2 broadcasts are already recorded' -- "${FENV[@]}" bash "$CE" --confirm --only P2 --account fixture
          [[ "$(fcast nonce "$FDEP")" == "$n_sent" ]] && ok "fresh genesis e2e ($label): the refused P2 re-run sent nothing" ||
            bad "fresh genesis e2e ($label): the refused P2 re-run sent nothing" "nonce $n_sent -> $(fcast nonce "$FDEP")"
          expect "fresh genesis e2e ($label): the record step verifies and records the book from the broadcasts and the chain" 0 'P2 stack book recorded' -- "${FENV[@]}" bash "$CE" --confirm --only P2 --record-stack-book --account fixture
          [[ "$(fcast nonce "$FDEP")" == "$n_sent" ]] && ok "fresh genesis e2e ($label): the record step sent nothing" ||
            bad "fresh genesis e2e ($label): the record step sent nothing" "nonce $n_sent -> $(fcast nonce "$FDEP")"
        else
          expect "fresh genesis e2e ($label): P2 deploys through regenesis.sh and the generator, and the book is verified" 0 'P2 stack book = generator output for this run' -- "${FENV[@]}" bash "$CE" --confirm --only P2 --account fixture
        fi
        jq -e '[.. | strings | select(test("^0x[0-9a-fA-F]{40}$")) | select(. != ascii_downcase)] | length == 0' "$book" >/dev/null &&
          ok "fresh genesis e2e ($label): every address in the book is lowercase" ||
          bad "fresh genesis e2e ($label): every address in the book is lowercase" "$(cat "$book")"
        RUN_VR=$(jq -r '.contracts.ValidatorRegistry' "$book")
        RUN_SBT=$(jq -r '.contracts.CitrateMemberSBT' "$book")
        RUN_VAULT=$(jq -r '.contracts.MembershipStakeVault' "$book")
        RUN_VAULT_IMPL=$(jq -r '.contracts.MembershipStakeVaultImpl' "$book")
        if [[ "$(jq -r '.deployer' "$book")" == "$FDEP" && "$(jq -r '[.CitrateMemberSBT, .MembershipStakeVault] | join(" ")' "$book")" == "$RUN_SBT $RUN_VAULT" &&
          "$(jq -r '(.contracts | has("AnchorRegistry")) or (.contracts | has("StaleEdu"))' "$book")" == false &&
          "$(jq -r '.governance.GOVERNANCE' "$book")" == "$(lower "$GTL")" && "$RUN_VAULT" != "$RUN_VAULT_IMPL" ]]; then
          ok "fresh genesis e2e ($label): the book names the run's deployer, membership (impl and proxy), root aliases and governance, nothing stale"
        else
          bad "fresh genesis e2e ($label): the book names the run's deployer, membership (impl and proxy), root aliases and governance, nothing stale" "$(cat "$book")"
        fi
        local sbt_owner vr_gov
        sbt_owner=$(fcast call "$RUN_SBT" "owner()(address)" 2>/dev/null)
        vr_gov=$(fcast call "$RUN_VR" "governance()(address)" 2>/dev/null)
        [[ "$(lower "$sbt_owner")" == "$(lower "$owner")" && "$(lower "$vr_gov")" == "$(lower "$GTL")" ]] &&
          ok "fresh genesis e2e ($label): the booked SBT and registry are live with this run's owner and governance" ||
          bad "fresh genesis e2e ($label): the booked SBT and registry are live with this run's owner and governance" "sbt owner $sbt_owner, vr governance $vr_gov"
        expect "fresh genesis e2e ($label): P5 --confirm passes the real checker over the generated book" 0 'P5 PASS: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0' -- "${FENV[@]}" bash "$CE" --confirm --only P5 --account fixture
        # P2 is done once its book is recorded: a second P2 is refused before anything is sent.
        n_sent=$(fcast nonce "$FDEP")
        expect "fresh genesis e2e ($label): P2 is refused once the stack book is recorded" 3 'already records the stack book: P2 is done' -- "${FENV[@]}" bash "$CE" --confirm --only P2 --account fixture
        [[ "$(fcast nonce "$FDEP")" == "$n_sent" ]] && ok "fresh genesis e2e ($label): the refused second P2 sent nothing" ||
          bad "fresh genesis e2e ($label): the refused second P2 sent nothing" "nonce $n_sent -> $(fcast nonce "$FDEP")"
      }
      lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
      # The committed book before the genesis: an earlier chain's deployer, membership and extras.
      printf '{"chainId":40204,"deployer":"0x4250675F9015E65fC866F3a373F82bb9DFc000c6","contracts":{"ValidatorRegistry":"%s","CitrateMemberSBT":"%s","MemberBond":"%s","MembershipStakeVaultImpl":"%s","MembershipStakeVault":"%s","AnchorRegistry":"%s"},"aaStack":{},"CitrateMemberSBT":"%s","MembershipStakeVault":"%s"}\n' \
        "$(addr 3001)" "$(addr 3002)" "$(addr 3003)" "$(addr 3004)" "$(addr 3005)" "$(addr 3006)" "$(addr 3002)" "$(addr 3005)" >"$FC/addresses/40204.json"
      OWNER1=0xAbCDEF0123456789AbCDeF0123456789aBcD0E11 # EIP-55 mixed case on purpose
      OWNER2=0x0e1a000000000000000000000000000000000002
      e2e_run run1 "$OWNER1" 0 "$FDEP_CS"
      VR1=$RUN_VR SBT1=$RUN_SBT VAULT1=$RUN_VAULT
      # C8 on the consumer side: a book edited after P2 is not the one P5 sweeps.
      cp "$FC/addresses/40204.json" "$T/fbook.orig"
      jq --arg a "$(addr 3005)" '.MembershipStakeVault = $a' "$T/fbook.orig" >"$FC/addresses/40204.json"
      expect "fresh genesis e2e: P5 refuses a book edited after P2 (stale vault alias)" 3 "is not the stack book this run's P2 generated" -- "${FENV[@]}" bash "$CE" --confirm --only P5 --account fixture
      cp "$T/fbook.orig" "$FC/addresses/40204.json"
      # Second genesis: another owner, another council (one extra tx moves the fixture
      # addresses), and an earlier chain's broadcast left for a ceremony this run does not run.
      mkdir -p "$FC/broadcast/DeployEduStack.s.sol/40204"
      printf '{"timestamp":1000,"transactions":[{"transactionType":"CREATE2","contractName":"StaleEdu","contractAddress":"%s"}]}\n' "$(addr 2999)" \
        >"$FC/broadcast/DeployEduStack.s.sol/40204/run-latest.json"
      e2e_run run2 "$OWNER2" 1 "$FDEP" gate-fault
      if [[ "$RUN_VR" != "$VR1" && "$RUN_SBT" != "$SBT1" && "$RUN_VAULT" != "$VAULT1" ]]; then
        ok "fresh genesis e2e: a new owner and registry move the SBT, the vault and the registry, and the book follows"
      else
        bad "fresh genesis e2e: a new owner and registry move the SBT, the vault and the registry, and the book follows" "VR $VR1→$RUN_VR SBT $SBT1→$RUN_SBT vault $VAULT1→$RUN_VAULT"
      fi
      kill "$FANVIL_PID" 2>/dev/null
    fi
  fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
