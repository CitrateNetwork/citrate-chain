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
rpc=""; args=()
while [[ $# -gt 0 ]]; do
  case "$1" in --rpc-url) rpc="$2"; shift 2 ;; --field) field="$2"; shift 2 ;; *) args+=("$1"); shift ;; esac
done
d="$FAKE/rpc/$(printf '%s' "$rpc" | tr -c 'A-Za-z0-9' '_')"
case "${args[0]}" in
  code) a=$(printf '%s' "${args[1]}" | tr 'A-F' 'a-f'); cat "$FAKE/code/$a" 2>/dev/null || echo 0x ;;
  keccak) printf '0x%s\n' "$(printf '%s' "${args[1]}" | sha256sum | cut -c1-64)" ;;
  storage) a=$(printf '%s' "${args[1]}" | tr 'A-F' 'a-f'); cat "$FAKE/impl/$a" 2>/dev/null || printf '0x%064d\n' 0 ;;
  chain-id) [[ -f "$d/chain-id" ]] || exit 1; cat "$d/chain-id" ;;
  block-number) [[ -f "$d/head" ]] || exit 1; cat "$d/head" ;;
  block) [[ -f "$d/block-${args[1]}" ]] || exit 1; cat "$d/block-${args[1]}" ;;
  nonce) cat "$d/nonce" 2>/dev/null || echo 0 ;;
  *) echo "fake cast: unsupported ${args[*]}" >&2; exit 9 ;;
esac
EOF
cat >"$BIN/forge" <<'EOF'
#!/usr/bin/env bash
echo "forge $*" >>"$FAKE/calls.log"
if [[ "$*" == *CheckDeployedAdmins* ]]; then
  echo "FACTORY-ADMIN failures: ${FAKE_FACTORY_ADMIN:-0}"
  echo "DEPLOYER-ADMIN failures: ${FAKE_DEPLOYER_ADMIN:-0}"
fi
EOF
cat >"$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$FAKE/calls.log"
[[ "$1" == is-active ]] && echo inactive
exit 0
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

BC="$T/broadcast/DeployX.s.sol/40204"
mkdir -p "$BC"
printf '{"transactions":[{"transactionType":"CREATE2","contractName":"Alpha","contractAddress":"%s"}]}' "$(addr 777)" >"$BC/run-latest.json"
expect "keep: a broadcast that redeploys a kept contract fails" 1 'Alpha redeployed by DeployX.s.sol' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"
printf '{"transactions":[{"transactionType":"CREATE2","contractName":"Other","contractAddress":"%s"}]}' "$(addr 777)" >"$BC/run-latest.json"
expect "keep: an unrelated broadcast passes" 0 'no broadcast under' -- env RPC=http://r1 BROADCAST_DIR="$T/broadcast" bash "$KC" verify "$LIST"

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
mkdir -p "$(rpcdir http://r1)"
echo 40204 >"$(rpcdir http://r1)/chain-id"
echo 1234 >"$(rpcdir http://r1)/head"
PINNED="$T/pinned.tsv"
if RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" pin "$KEYS" >"$PINNED" 2>"$T/pin.err"; then ok "keep: pin records the chain"; else bad "keep: pin records the chain" "$(cat "$T/pin.err")"; fi
expect "keep: a freshly pinned list verifies" 0 'KEEP gate PASS \(3 entries\)' -- env RPC=http://r1 ADDRESS_BOOK="$BOOK" bash "$KC" verify "$PINNED"
grep -q "^Vault.*$IMPL\$" "$PINNED" && ok "keep: pin records the proxy implementation" || bad "keep: pin records the proxy implementation" "$(cat "$PINNED")"

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
expect "reset: a malformed coinbase is a usage error" 2 'coinbase must be' -- "${RNENV[@]}" bash "$RN" --coinbase 0x12 --validator-registry "$NEWVR" --activation-height 0

# ------------------------------------------------------------------ ceremony
CE="$G/genesis_ceremony.sh"
REPO="$T/repo"
mkdir -p "$REPO/contracts/script" "$REPO/contracts/genesis" "$REPO/contracts/addresses" "$REPO/scripts/ops"
for s in DeployGenesisGovernance DeployTeamVesting DeployDormantLedgers CheckDeployedAdmins; do : >"$REPO/contracts/script/$s.s.sol"; done
printf '#!/usr/bin/env bash\necho "regenesis $*" >>"$FAKE/calls.log"\n' >"$REPO/scripts/ops/regenesis.sh"
cp "$BOOK" "$REPO/contracts/addresses/40204.json"
owners() { local i out=""; for i in "$@"; do out+="${out:+,}$(addr "$i")"; done; printf '%s' "$out"; }
CEENV=(env REPO_ROOT="$REPO" DEPLOYER_ADDRESS="$(addr 1)"
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
expect "ceremony: P5 passes at DEPLOYER-ADMIN 0" 0 'P5 PASS' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P5
expect "ceremony: P5 fails while the deployer holds a role" 3 'DEPLOYER-ADMIN is not 0' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 FAKE_DEPLOYER_ADMIN=2 bash "$CE" --simulate --only P5
expect "ceremony: P0 checks the RPC chain id" 3 'chain id 1, want 40204' -- "${CEENV[@]}" RPC_URL=http://n3x bash -c "mkdir -p '$(rpcdir http://n3x)'; echo 1 > '$(rpcdir http://n3x)/chain-id'; bash '$CE' --simulate --only P0"
printf '{"contracts":{"GovernanceTimelock":"%s","GuardianTimelock":"%s","GovernanceMultisig":"%s"}}' "$(addr 31)" "$(addr 32)" "$(addr 33)" >"$REPO/contracts/genesis/governance.json"
reset_calls
expect "ceremony: P2 takes governance from P1's output" 0 'GOVERNANCE=0x0+1f GUARDIAN=0x0+20' -- "${CEENV[@]}" RPC_URL=http://127.0.0.1:8545 bash "$CE" --simulate --only P2
calls | grep -q 'regenesis --reroll --with-aa$' && ok "ceremony: simulate does not broadcast" || bad "ceremony: simulate does not broadcast" "$(calls)"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
