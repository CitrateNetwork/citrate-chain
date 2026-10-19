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
  *) echo "fake cast: unsupported ${args[*]}" >&2; exit 9 ;;
esac
EOF
cat >"$BIN/forge" <<'EOF'
#!/usr/bin/env bash
echo "forge $*" >>"$FAKE/calls.log"
echo "forge-env gov=${GENESIS_GOVERNANCE_OUT:-} vest=${TEAM_VESTING_OUT:-} dormant=${DORMANT_LEDGERS_OUT:-} govbook=${GENESIS_GOVERNANCE_BOOK:-} extras=${EXTRA_ADDRESS_BOOKS:-}" >>"$FAKE/calls.log"
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
  echo "DEPLOYER-ADMIN failures: $da"
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
  if [[ "$src" == *run-latest.json* ]]; then
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
unset RPC RPC_URL ADDRESS_BOOK BROADCAST_DIR KEEP_LIST FLEET_RPCS EXPECTED_GENESIS_HASH PRIVATE_KEY DEPLOYER_PRIVATE_KEY
calls() { cat "$FAKE/calls.log" 2>/dev/null; }
reset_calls() { : >"$FAKE/calls.log"; }

addr() { printf '0x%040x' "$1"; }
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
run_json 2000 Alpha "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a broadcast that redeploys a kept contract elsewhere fails" 1 'DeployX.s.sol redeploys Alpha at 0x0+309 \(not the pinned' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
run_json 2000 Other "$(addr 777)" >"$BC/run-latest.json"
expect "keep: an unrelated broadcast passes" 0 'no chain-40204 broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# The deterministic genesis replay deploys the kept contract AT its pinned address: that passes.
run_json 2000 Alpha "$(printf '%s' "$A1" | tr 'a-f' 'A-F' | sed 's/^0X/0x/')" >"$BC/run-latest.json"
expect "keep: a genesis deployment at the pinned address passes" 0 'deploys Alpha at 0x0+a1 \(the pinned address\)' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# Another chain's broadcasts are not evidence for this one.
rm "$BC/run-latest.json"
mkdir -p "$T/broadcast/DeployX.s.sol/31337"
run_json 2000 Alpha "$(addr 777)" >"$T/broadcast/DeployX.s.sol/31337/run-latest.json"
expect "keep: another chain's broadcast is ignored" 0 'no chain-40204 broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
rm -r "$T/broadcast/DeployX.s.sol/31337"
# A run from an earlier chain on the same chain id (before block 0) is ignored with BROADCAST_SINCE.
run_json 1000 Alpha "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a run before BROADCAST_SINCE is ignored" 0 'KEEP-SKIP +DeployX.s.sol' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1500 bash "$KC" verify "$LIST"
expect "keep: the same run after BROADCAST_SINCE counts" 1 'redeploys Alpha' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=500 bash "$KC" verify "$LIST"
run_json 1600000000000 Alpha "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a millisecond timestamp is compared in seconds" 0 'KEEP-SKIP' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" BROADCAST_SINCE=1700000000 bash "$KC" verify "$LIST"
printf '{not json' >"$BC/run-latest.json"
expect "keep: an unreadable broadcast fails" 1 'unreadable broadcast' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
printf '{"transactions":[{"transactionType":"CREATE","contractName":"Alpha"}]}' >"$BC/run-latest.json"
expect "keep: a kept deployment with no address fails" 1 'has no contractAddress' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
expect "keep: broadcasts need a readable chain id" 1 'cannot read the chain id' -- env RPC=http://nochain BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
# A scanner that crashes, or stops without finishing, fails the gate whatever it printed.
run_json 2000 Other "$(addr 777)" >"$BC/run-latest.json"
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
expect "keep: keys on an unreadable book is an input error" 2 'cannot read sections' -- env ADDRESS_BOOK="$T/badbook.json" bash "$KC" keys contracts
rm -r "$T/broadcast"

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
ADDRESS_BOOK="$BOOK" bash "$KC" keys contracts >"$KEYS"
if [[ $(grep -vc '^#' "$KEYS") -eq 3 ]] && ! grep -q Zero "$KEYS"; then ok "keep: keys lists the book's nonzero addresses"; else bad "keep: keys lists the book's nonzero addresses" "$(cat "$KEYS")"; fi
sed -i 's/^Vault\tcontracts\tVault\tno$/Vault\tcontracts\t-\tyes/' "$KEYS"
echo 1234 >"$(rpcdir http://r1)/head"
PINNED="$T/pinned.tsv"
if RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" pin "$KEYS" >"$PINNED" 2>"$T/pin.err"; then ok "keep: pin records the chain"; else bad "keep: pin records the chain" "$(cat "$T/pin.err")"; fi
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
if RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" pin "$T/keys-nonl.tsv" >"$T/pinned-nonl.tsv" 2>"$T/pin.err" &&
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
RNENV=(env CITRATE_HOME="$T/node/home" DROPIN="$T/node/dropin/reroll.conf" NODE_OWNER= SYSTEMCTL="$BIN/systemctl")
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
expect "reset: a malformed coinbase is a usage error" 2 'coinbase must be' -- "${RNENV[@]}" bash "$RN" --coinbase 0x12 --validator-registry "$NEWVR" --activation-height 0

# ------------------------------------------------------------------ ceremony
CE="$G/genesis_ceremony.sh"
REPO="$T/repo"
mkdir -p "$REPO/contracts/script" "$REPO/contracts/genesis" "$REPO/contracts/addresses" "$REPO/scripts/ops"
for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers CheckDeployedAdmins; do : >"$REPO/contracts/script/$s.s.sol"; done
printf '#!/usr/bin/env bash\necho "regenesis $*" >>"$FAKE/calls.log"\n' >"$REPO/scripts/ops/regenesis.sh"
DEP=$(addr 1)
printf '{"chainId":40204,"deployer":"%s","contracts":{"Alpha":"%s","Beta":"%s","Vault":"%s"},"aaStack":{},"Vault":"%s"}' "$DEP" "$A1" "$A2" "$A3" "$A3" >"$REPO/contracts/addresses/40204.json"
# gov_book <dir> <deployer> [extra "Name":"0x..." pairs]: a P1-shaped governance output.
gov_book() {
  printf '{"deployer":"%s","contracts":{"GovernanceTimelock":"%s","GuardianTimelock":"%s","GovernanceMultisig":"%s"%s}}' \
    "$2" "$(addr 31)" "$(addr 32)" "$(addr 33)" "${3:+,$3}" >"$1/governance.json"
}
owners() { local i out=""; for i in "$@"; do out+="${out:+,}$(addr "$i")"; done; printf '%s' "$out"; }
CEENV=(env REPO_ROOT="$REPO" DEPLOYER_ADDRESS="$DEP"
  GOV_OWNERS="$(owners 11 12 13 14 15)" GOV_THRESHOLD=3 GOV_MIN_DELAY=172800
  GRD_OWNERS="$(owners 21 22 23)" GRD_THRESHOLD=2 GRD_MIN_DELAY=3600)

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
expect "ceremony: --confirm needs a keystore account" 3 'needs --account' -- "${CEENV[@]}" bash "$CE" --confirm
expect "ceremony: --confirm to a remote RPC needs CITRATE_ALLOW_REMOTE" 3 'not loopback' -- "${CEENV[@]}" RPC_URL=https://rpc.example EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --account deployer
expect "ceremony: missing genesis contract scripts are named" 3 'chain#320' -- "${CEENV[@]}" REPO_ROOT="$T/empty-repo" bash "$CE"
expect "ceremony: an unknown phase is refused" 1 'must be one of' -- "${CEENV[@]}" bash "$CE" --from P9

# simulate: P5 reads the admin report
mkdir -p "$(rpcdir http://127.0.0.1:8545)"
echo 40204 >"$(rpcdir http://127.0.0.1:8545)/chain-id"
expect "ceremony: P5 needs P1's governance output" 3 'governance.json missing' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
GB="$REPO/contracts/genesis"
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
expect "ceremony: P5 refuses an output from another deployer" 3 'cannot build the merged admin book' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash -c "printf '{\"deployer\":\"%s\",\"contracts\":{\"VestingAlice\":\"%s\"}}' '$(addr 9)' '$(addr 71)' > '$GB/team-vesting.json'; bash '$CE' --simulate --only P5"
printf '{"deployer":"%s","contracts":{"Alpha":"%s"}}' "$DEP" "$(addr 71)" >"$GB/team-vesting.json"
expect "ceremony: P5 refuses an output that shadows a book name" 3 'cannot build the merged admin book' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
printf '{"deployer":"%s","contracts":{}}' "$DEP" >"$GB/team-vesting.json"
expect "ceremony: P5 refuses an output with no contracts" 3 'cannot build the merged admin book' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
rm "$GB/team-vesting.json" "$GB/dormant-ledgers.json"
echo "$GEN" >"$(rpcdir http://127.0.0.1:8545)/block-0"
expect "ceremony: --confirm P5 needs every ceremony output" 3 'team-vesting.json missing' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --only P5 --account deployer
rm "$(rpcdir http://127.0.0.1:8545)/block-0"
expect "ceremony: P0 checks the RPC chain id" 3 'chain id 1, want 40204' -- "${CEENV[@]}" RPC_URL=http://n3x bash -c "mkdir -p '$(rpcdir http://n3x)'; echo 1 > '$(rpcdir http://n3x)/chain-id'; bash '$CE' --simulate --only P0"
reset_calls
expect "ceremony: P2 takes governance from P1's output" 0 'GOVERNANCE=0x0+1f GUARDIAN=0x0+20' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
calls | grep -q 'regenesis --reroll --with-aa$' && ok "ceremony: simulate does not broadcast" || bad "ceremony: simulate does not broadcast" "$(calls)"

# Resume paths: the safety preflight runs before any phase that talks to a chain.
expect "ceremony: --confirm --from P1 to a remote RPC is refused" 3 'not loopback' -- "${CEENV[@]}" RPC_URL=https://rpc.example EXPECTED_GENESIS_HASH="$GEN" TEAM_VESTING_FILE="$BOOK" KEEP_LIST="$LIST" FLEET_RPCS=http://n1 bash "$CE" --confirm --from P1 --account deployer
expect "ceremony: --confirm --only P2 without --account is refused" 3 'needs --account' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --confirm --only P2
expect "ceremony: --simulate --from P1 checks the chain id" 3 'chain id 1, want 40204' -- "${CEENV[@]}" RPC_URL=http://n3x bash "$CE" --simulate --from P1
echo "0x$(h64 f)" >"$(rpcdir http://127.0.0.1:8545)/block-0"
expect "ceremony: --simulate --only P3 checks the genesis hash" 3 'block 0 is 0x[f]+, want' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 EXPECTED_GENESIS_HASH="$GEN" bash "$CE" --simulate --only P3
expect "ceremony: --simulate --from P4 checks the council floors" 3 'GOV threshold 2 is below' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GOV_THRESHOLD=2 bash "$CE" --simulate --from P4
expect "ceremony: --simulate --only P2 checks the deployer seat" 3 'deployer must not hold' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GRD_OWNERS="$(owners 1 22 23)" bash "$CE" --simulate --only P2
echo 5 >"$(rpcdir http://127.0.0.1:8545)/nonce"
expect "ceremony: a resume does not require deployer nonce 0" 0 'P0 preflight PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony: a fresh ceremony requires deployer nonce 0" 3 'deployer nonce is 5' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate
rm "$(rpcdir http://127.0.0.1:8545)/nonce" "$(rpcdir http://127.0.0.1:8545)/block-0"

# P6 integration: the genesis replay's own broadcasts (deployments at the pinned addresses,
# recorded after block 0) pass; a stale run from an earlier chain on the same id is ignored.
echo 5000 >"$(rpcdir http://127.0.0.1:8545)/block-0-timestamp"
mkdir -p "$REPO/contracts/broadcast/Regenesis.s.sol/40204" "$REPO/contracts/broadcast/Old.s.sol/40204"
printf '{"timestamp":6000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$A1" >"$REPO/contracts/broadcast/Regenesis.s.sol/40204/run-latest.json"
printf '{"timestamp":100,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$REPO/contracts/broadcast/Old.s.sol/40204/run-latest.json"
expect "ceremony: P6 passes the genesis deployments at their pins" 0 'KEEP gate PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
printf '{"timestamp":7000,"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$REPO/contracts/broadcast/Old.s.sol/40204/run-latest.json"
expect "ceremony: P6 fails a post-genesis redeploy away from the pin" 3 'keep_check failed' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6
rm "$(rpcdir http://127.0.0.1:8545)/block-0-timestamp"
expect "ceremony: P6 needs the block-0 timestamp" 3 'block-0 timestamp' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 KEEP_LIST="$LIST" bash "$CE" --simulate --only P6

# GENESIS_OUT_DIR: one directory for every producer and consumer path.
expect "ceremony: an output dir outside contracts/genesis is refused" 1 'GENESIS_OUT_DIR must be contracts/genesis' -- "${CEENV[@]}" GENESIS_OUT_DIR="$T/elsewhere" bash "$CE"
expect "ceremony: an output dir that escapes contracts/genesis is refused" 1 'GENESIS_OUT_DIR must be' -- "${CEENV[@]}" GENESIS_OUT_DIR="$REPO/contracts/genesis/../addresses" bash "$CE"
expect "ceremony: dry run reads the books from a nondefault dir" 0 'merge .* \+ genesis/run2/governance.json, genesis/run2/team-vesting.json, genesis/run2/dormant-ledgers.json → genesis/run2/p5-admin-book.json' -- "${CEENV[@]}" GENESIS_OUT_DIR="$REPO/contracts/genesis/run2" bash "$CE"
RUN2="$REPO/contracts/genesis/run2"
mkdir -p "$RUN2"
reset_calls
expect "ceremony: P1 writes governance into the nondefault dir" 0 'P0 preflight PASS \(books in genesis/run2/\)' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P1
calls | grep -q 'forge-env gov=genesis/run2/governance.json ' && ok "ceremony: P1 output path follows GENESIS_OUT_DIR" || bad "ceremony: P1 output path follows GENESIS_OUT_DIR" "$(calls)"
# A stale book in the nondefault dir: P1 refuses to run over it (nothing sent).
printf '{"deployer":"%s","contracts":{"GovernanceTimelock":"%s","GuardianTimelock":"%s","GovernanceMultisig":"%s"}}' "$DEP" "$(addr 41)" "$(addr 42)" "$(addr 43)" >"$RUN2/governance.json"
reset_calls
expect "ceremony: P1 refuses a stale governance book" 3 'run2/governance.json already exists and P1 would write it' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P1
if calls | grep -q '^forge'; then bad "ceremony: a refused P1 runs no forge" "$(calls)"; else ok "ceremony: a refused P1 runs no forge"; fi
expect "ceremony: a stale book stops a resumed run before P1" 3 'already exists and P1' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --from P1
# Consumers read the same directory: P2 takes the run2 book, not contracts/genesis/governance.json.
expect "ceremony: P2 reads governance from the nondefault dir" 0 'GOVERNANCE=0x0+29 GUARDIAN=0x0+2a' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P2
reset_calls
expect "ceremony: P4 runs with the nondefault dir" 0 'P4 dormant ledgers' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" PATRONAGE_KYC_REGISTRY="$(addr 51)" PATRONAGE_MEMBERSHIP="$(addr 52)" bash "$CE" --simulate --only P4
calls | grep -q 'forge-env gov=[^ ]* vest=[^ ]* dormant=genesis/run2/dormant-ledgers.json govbook=genesis/run2/governance.json ' && ok "ceremony: P4 reads and writes the nondefault dir" || bad "ceremony: P4 reads and writes the nondefault dir" "$(calls)"
reset_calls
expect "ceremony: P5 checks the nondefault dir's books" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 GENESIS_OUT_DIR="$RUN2" bash "$CE" --simulate --only P5
calls | grep -q '^forge-book genesis/run2/p5-admin-book.json$' && grep -q "$(addr 41)" "$RUN2/p5-admin-book.json" && ok "ceremony: P5 merges the nondefault dir's books" || bad "ceremony: P5 merges the nondefault dir's books" "$(calls)"
rm -r "$RUN2"

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
  printf 'SKIP P5 real-checker integration (forge/cast/anvil not on PATH)\n'
else
  IR="$T/irepo"
  IC="$IR/contracts"
  mkdir -p "$IC/script/lib" "$IC/src/aa/lib/webauthn" "$IC/lib" "$IC/genesis" "$IC/addresses" "$IR/scripts/ops"
  sed 's|{ access = "read", path = "./addresses" }\]|{ access = "read", path = "./addresses" }, { access = "read", path = "./genesis" }]|' \
    "$SRC/foundry.toml" >"$IC/foundry.toml"
  cp "$SRC/remappings.txt" "$IC/"
  ln -s "$SRC/lib/forge-std" "$IC/lib/forge-std"
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
    printf '{"chainId":31337,"deployer":"%s","contracts":{"Alpha":"%s"},"aaStack":{}}' "$DEP" "$A1" >"$IC/addresses/40204.json"
    IENV=("${CEENV[@]}" REPO_ROOT="$IR" RPC_URL="$IRPC" EXPECTED_CHAIN_ID=31337 FORGE="$REAL_FORGE" CAST="$REAL_CAST")
    gov_book "$IC/genesis" "$DEP"
    expect "P5 integration: a handed-over governance output passes the real checker" 0 'P5 PASS' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    gov_book "$IC/genesis" "$DEP" "\"GenesisHeld\":\"$(addr 34)\""
    expect "P5 integration: a deployer role held only in the governance output fails the real checker" 3 'DEPLOYER-ADMIN GenesisHeld: governance\(\) is the deployer EOA' -- "${IENV[@]}" bash "$CE" --simulate --only P5
    kill "$ANVIL_PID" 2>/dev/null
  fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
