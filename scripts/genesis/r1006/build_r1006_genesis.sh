#!/usr/bin/env bash
# build_r1006_genesis.sh: the r1006 genesis from ceremony state ("genesis from ceremony state").
#
# r1006's block 0 already holds every genesis contract, deployed and configured. It is built
# by running the real contract ceremony (scripts/genesis/genesis_ceremony.sh P0-P5) against a
# PRIVATE local Citrate node, then dumping that node's post-ceremony state into a genesis
# allocation that the node's `r1006` genesis profile loads.
#
#   ceremony   run the ceremony on a private devnet and dump its state:
#                build_r1006_genesis.sh ceremony --node BIN --state-dump BIN --work DIR
#                  [--inputs FILE] [--ref REF]
#              Writes DIR/dump.json (the post-ceremony state), DIR/book (the ceremony books),
#              DIR/KEEP_LIST.r1006.tsv, DIR/devnet-data (the stopped node's data dir) and logs.
#   alloc      turn a dump into the committed allocation (see emit_alloc.py):
#                build_r1006_genesis.sh alloc --work DIR [--out FILE]
#
# Isolation. The devnet, forge and cast run inside `unshare --user --map-root-user --net`
# (a private network namespace with only loopback), so nothing here can reach any other
# host, the fleet included. HOME is a directory under --work. No key material is read: the
# ceremony deployer is a THROWAWAY key derived from a public label (below; anyone can derive
# it, and after P5 it holds no role: DEPLOYER-ADMIN 0), funded on the devnet from the public
# Hardhat/Anvil dev account that the devnet's `default` genesis funds.
#
# Reproducibility. Every input is fixed: the inputs file, the deployer key, the phase order
# (P0-P3, the two P4 stand-ins, P4, P5), the funding amounts and the devnet config. Two runs
# give a byte-identical allocation (scripts/genesis/r1006/test_reproducible.sh).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${PYTHON:-python3}"

# Public by construction (not a secret): keccak256 of this label. Throwaway, devnet only.
DEPLOYER_LABEL="citrate-r1006-genesis-ceremony-deployer-v1 (throwaway, public)"
# The Hardhat/Anvil account #0 dev key: public, funded by the devnet `default` genesis.
DEV_FUNDER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEPLOYER_FUNDING=5000ether
RPC_PORT=18545
# Block rewards on the devnet go here (public, no code; not carried into the alloc).
DEVNET_COINBASE=c17a7e0000000000000000000000000000de7e01
P2P_PORT=30399

die() { echo "build_r1006_genesis: $*" >&2; exit 1; }
log() { echo "[r1006 $(date -u +%H:%M:%S)] $*" >&2; }

cmd="${1:-}"; shift || true
NODE="" DUMP="" WORK="" INPUTS="$HERE/inputs.placeholder.env" REF=HEAD OUT=""
VALIDATORS="$CHAIN_ROOT/core/economics/assets/r1006/validators.json"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    --state-dump) DUMP="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --inputs) INPUTS="$2"; shift 2 ;;
    --validators) VALIDATORS="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --solc) SOLC_BIN="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done

case "$cmd" in
  ceremony)
    # The contracts bind the chain id, and several deploy scripts fail closed ONLY on 40204
    # (elsewhere they fall back to the deployer or a placeholder governance, which would be
    # baked into block 0). The build devnet is 40204, always; anything else is refused here,
    # before a worktree or a node exists, and the live chain id is re-checked once it runs.
    [[ "${R1006_DEVNET_CHAIN_ID:-40204}" == 40204 ]] ||
      die "the build devnet must run chain id 40204 (R1006_DEVNET_CHAIN_ID=${R1006_DEVNET_CHAIN_ID}); the deploy scripts fail closed only there"
    [[ -x "$NODE" && -x "$DUMP" ]] || die "--node and --state-dump must be executables"
    [[ -n "$WORK" && -d "$WORK" && -z "$(ls -A "$WORK")" ]] || die "--work must be an existing EMPTY directory (mktemp -d)"
    [[ -f "$INPUTS" ]] || die "inputs file $INPUTS not found"
    WORK="$(cd "$WORK" && pwd)"
    command -v unshare >/dev/null || die "unshare is required"
    for t in forge cast jq ip; do command -v "$t" >/dev/null || die "$t is required"; done
    # The ceremony writes books and broadcasts into its repo: give it a checkout of its own.
    git -C "$CHAIN_ROOT" worktree add --detach "$WORK/repo" "$REF" >"$WORK/worktree.log" 2>&1 ||
      die "cannot create the ceremony worktree (see $WORK/worktree.log)"
    # The OpenZeppelin submodules are not checked out in a new worktree, and the namespace
    # has no network: copy them from this clone, at exactly the commits the ref pins.
    SM_SRC="$(dirname "$(git -C "$CHAIN_ROOT" rev-parse --path-format=absolute --git-common-dir)")"
    for sm in openzeppelin-contracts openzeppelin-contracts-upgradeable; do
      want=$(git -C "$CHAIN_ROOT" ls-tree "$REF" "contracts/lib/$sm" | awk '{print $3}')
      have=$(git -C "$SM_SRC/contracts/lib/$sm" rev-parse HEAD 2>/dev/null || true)
      [[ -n "$want" && "$want" == "$have" ]] || die "contracts/lib/$sm is at ${have:-nothing}, the ref pins $want"
      [[ -z "$(git -C "$SM_SRC/contracts/lib/$sm" status --porcelain --ignore-submodules)" ]] || die "contracts/lib/$sm has local changes"
      rm -rf "${WORK:?}/repo/contracts/lib/$sm"
      git -C "$SM_SRC/contracts/lib/$sm" archive --format=tar --prefix="$sm/" HEAD | tar -x -C "$WORK/repo/contracts/lib"
    done
    SOLC_BIN="${SOLC_BIN:-$HOME/.svm/0.8.36/solc-0.8.36}"
    [[ -x "$SOLC_BIN" ]] || die "solc 0.8.36 not found at $SOLC_BIN (set SOLC_BIN)"
    cp "$INPUTS" "$WORK/inputs.env"
    cp "$VALIDATORS" "$WORK/validators.json"
    rc=0
    unshare --user --map-root-user --net bash "$HERE/build_r1006_genesis.sh" _inner \
      --node "$(readlink -f "$NODE")" --state-dump "$(readlink -f "$DUMP")" --work "$WORK" --solc "$SOLC_BIN" || rc=$?
    git -C "$CHAIN_ROOT" worktree remove --force "$WORK/repo" >>"$WORK/worktree.log" 2>&1 || true
    exit "$rc"
    ;;
  alloc)
    [[ -f "$WORK/dump.json" ]] || die "--work has no dump.json (run ceremony first)"
    exec "$PY" "$HERE/emit_alloc.py" --dump "$WORK/dump.json" --inputs "$WORK/inputs.env" \
      --manifest "$WORK/book/ceremony-run.json" --validators "$WORK/validators.json" --out "${OUT:-$WORK/alloc.json}"
    ;;
  _inner) ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2; exit 1 ;;
esac

# ------------------------------------------------------------------ inside the namespace
ip link set lo up
REAL_FORGE="$(command -v forge)"
REAL_CAST="$(command -v cast)"
export HOME="$WORK/home" FOUNDRY_DISABLE_NIGHTLY_WARNING=1 FOUNDRY_OFFLINE=true FOUNDRY_SOLC="$SOLC_BIN"
mkdir -p "$HOME" "$WORK/bin" "$WORK/devnet-data"
chmod 700 "$HOME"
ln -sf "$HERE/forge_resume.sh" "$WORK/bin/forge"
export R1006_REAL_FORGE="$REAL_FORGE" PATH="$WORK/bin:$PATH"
RPC="http://127.0.0.1:$RPC_PORT"
c() { "$REAL_CAST" "$@" --rpc-url "$RPC"; }

cat >"$WORK/devnet.toml" <<EOF
# r1006 ceremony devnet: chain 40204 (the contracts bind the chain id), the devnet
# 'default' genesis (funds the public dev account), loopback only, one miner.
[chain]
chain_id = 40204
block_time = 2
genesis_profile = "default"
ghostdag_k = 18
exact_create_code_height = 0

[network]
listen_addr = "127.0.0.1:$P2P_PORT"
bootstrap_nodes = []
max_peers = 4

[rpc]
enabled = true
listen_addr = "127.0.0.1:$RPC_PORT"
ws_addr = "127.0.0.1:$((RPC_PORT + 1))"
# PV sends each staker's registration with eth_sendTransaction (loopback only).
allow_eth_send_transaction = true

[storage]
data_dir = "$WORK/devnet-data"
pruning = false
keep_blocks = 1000000

[mining]
enabled = true
coinbase = "$DEVNET_COINBASE"
target_block_time = 2
min_gas_price = 1000000000

[vrf]
strict_vrf = false
migration_mode = false

[checkpoint]
interval = 50
committee_size = 100
quorum_threshold = 67
EOF

NODE_PID=""
stop_node() {
  if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill -TERM "$NODE_PID"
    for _ in $(seq 120); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
  NODE_PID=""
}
trap stop_node EXIT
start_node() {
  (cd "$WORK" && exec "$NODE" --config "$WORK/devnet.toml") >>"$WORK/devnet.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 240); do c chain-id >/dev/null 2>&1 && return 0; sleep 0.5; done
  die "devnet RPC did not come up (see $WORK/devnet.log)"
}
log "starting the ceremony devnet"
start_node
LIVE_CHAIN_ID=$(c chain-id)
[[ "$LIVE_CHAIN_ID" == 40204 ]] || die "the build devnet reports chain id $LIVE_CHAIN_ID, not 40204; refusing to run the ceremony"
G0=$(c block 0 --field hash)
G0TS=$(c block 0 --field timestamp)
log "devnet block 0 $G0 (timestamp $G0TS)"

# Deployer: a throwaway key from a public label, in a keystore under this run's HOME.
DEPLOYER_KEY=$("$REAL_CAST" keccak "$DEPLOYER_LABEL")
DEPLOYER=$("$REAL_CAST" wallet address --private-key "$DEPLOYER_KEY")
DEPLOYER=$(printf '%s' "$DEPLOYER" | tr 'A-F' 'a-f')
PWF="$HOME/keystore.pw"
(umask 077 && printf 'r1006-throwaway\n' >"$PWF")
"$REAL_CAST" wallet import r1006-ceremony --private-key "$DEPLOYER_KEY" --unsafe-password "r1006-throwaway" >/dev/null
unset DEPLOYER_KEY
log "deployer $DEPLOYER (throwaway); funding $DEPLOYER_FUNDING"
c send --private-key "$DEV_FUNDER_KEY" --legacy --gas-limit 21000 --value "$DEPLOYER_FUNDING" "$DEPLOYER" >"$WORK/fund.log" 2>&1 ||
  die "funding the deployer failed (see $WORK/fund.log)"
[[ "$(c nonce "$DEPLOYER")" == 0 ]] || die "deployer nonce is not 0 after funding"

# Inputs (public addresses) and the files the ceremony reads.
set -a
# shellcheck disable=SC1091
. "$WORK/inputs.env"
set +a
REPO="$WORK/repo"
mkdir -p "$REPO/contracts/genesis"
printf '{"wallets":[{"label":"team_1","beneficiary":"%s","start":%s,"duration":%s,"cliff":%s,"amount":"%s"}]}\n' \
  "$TEAM_VESTING_BENEFICIARY" "$TEAM_VESTING_START" "$TEAM_VESTING_DURATION" "$TEAM_VESTING_CLIFF" "$TEAM_VESTING_AMOUNT" \
  >"$REPO/contracts/genesis/team-vesting.input.json"
printf '# r1006 ceremony devnet: placeholder KEEP list (P6 is not part of the genesis build)\n' >"$WORK/keep.placeholder.tsv"
CE=(env DEPLOYER_ADDRESS="$DEPLOYER" RPC_URL="$RPC" EXPECTED_CHAIN_ID=40204 EXPECTED_GENESIS_HASH="$G0"
  TEAM_VESTING_FILE=genesis/team-vesting.input.json KEEP_LIST="$WORK/keep.placeholder.tsv" FLEET_RPCS="$RPC"
  bash "$REPO/scripts/genesis/genesis_ceremony.sh" --confirm --account r1006-ceremony --password-file "$PWF")

log "ceremony P0-P3 (P4 stops for its inputs, by design)"
rc=0
"${CE[@]}" >"$WORK/ceremony-1.log" 2>&1 || rc=$?
grep -q 'P3 ' "$WORK/ceremony-1.log" && grep -q 'missing inputs: PATRONAGE_KYC_REGISTRY' "$WORK/ceremony-1.log" ||
  die "ceremony P0-P3 did not reach P4's input check (exit $rc; see $WORK/ceremony-1.log)"

# P4 stand-ins (A-5 open): KYCRegistry and the coop MembershipSBT, both administered by
# GOVERNANCE, deployed by the ceremony deployer in this fixed order.
GOVERNANCE=$(jq -r '.contracts.GovernanceTimelock' "$REPO/contracts/genesis/governance.json")
[[ "$GOVERNANCE" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "no GOVERNANCE in P1's book"
create() {
  (cd "$REPO/contracts" && "$REAL_FORGE" create "$@" --rpc-url "$RPC" --account r1006-ceremony --password-file "$PWF" \
    --legacy --gas-limit 8000000 --broadcast --json) | tee -a "$WORK/standins.log" | jq -r '.deployedTo'
}
log "P4 stand-ins under GOVERNANCE $GOVERNANCE"
KYC=$(create src/KYCRegistry.sol:KYCRegistry --constructor-args "$PATRONAGE_KYC_UPDATER" "$GOVERNANCE")
[[ "$KYC" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "KYCRegistry stand-in failed (see $WORK/standins.log)"
MSBT=$(create src/coop/MembershipSBT.sol:MembershipSBT --constructor-args "$KYC" "[]" "$GOVERNANCE" "$PATRONAGE_REGISTRAR")
[[ "$MSBT" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "MembershipSBT stand-in failed (see $WORK/standins.log)"
printf '{"KYCRegistry":"%s","MembershipSBT":"%s"}\n' "$KYC" "$MSBT" >"$WORK/standins.json"

log "ceremony P4-P5 (P6 refuses the placeholder KEEP list, by design)"
rc=0
env PATRONAGE_KYC_REGISTRY="$KYC" PATRONAGE_MEMBERSHIP="$MSBT" "${CE[@]}" --from P4 >"$WORK/ceremony-2.log" 2>&1 || rc=$?
grep -q 'P5 PASS: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0' "$WORK/ceremony-2.log" ||
  die "P5 did not pass (exit $rc; see $WORK/ceremony-2.log)"
log "P5 PASS: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0"

# PV: the producer set, registered in the ValidatorRegistry so block 0 has it (only once
# fill_producers.py has filled validators.json; a placeholder set registers nothing and
# leaves the genesis not release-ready). The staker sends its own registration through the
# devnet's loopback eth_sendTransaction; the bond is funded from the dev account.
if [[ "$(jq -r .status "$WORK/validators.json")" == final ]]; then
  VR=$(jq -r '.contracts.ValidatorRegistry' "$REPO/contracts/addresses/40204.json" | tr 'A-F' 'a-f')
  [[ "$VR" == "$(jq -r .validatorRegistry "$WORK/validators.json")" ]] ||
    die "validators.json was signed for registry $(jq -r .validatorRegistry "$WORK/validators.json"), the ceremony deployed $VR"
  python3 "$HERE/fill_producers.py" check --path "$WORK/validators.json" >&2 || die "validators.json does not verify"
  n=$(jq '.producers | length' "$WORK/validators.json")
  for i in $(seq 0 $((n - 1))); do
    read -r name staker pk sig stake < <(jq -r ".producers[$i] | [.name,.staker,.proposerPubkey,.registrationSig,.stake] | @tsv" "$WORK/validators.json")
    c send --private-key "$DEV_FUNDER_KEY" --legacy --gas-limit 21000 --value "$(python3 -c "print($stake + 10**18)")" "$staker" >>"$WORK/pv.log" 2>&1 ||
      die "PV: funding $name's staker failed (see $WORK/pv.log)"
    c send --unlocked --from "$staker" --legacy --gas-limit 2000000 --value "$stake" "$VR" "registerValidator(bytes32,bytes)" "$pk" "$sig" >>"$WORK/pv.log" 2>&1 ||
      die "PV: registering $name failed (see $WORK/pv.log)"
    [[ "$(c call "$VR" "isActive(bytes32)(bool)" "$pk")" == true ]] || die "PV: $name is not active after registering"
    log "PV: $name registered ($pk)"
  done
  [[ "$(c call "$VR" "activeCount()(uint256)")" == "$n" ]] || die "PV: the active set is not the $n producers"
else
  log "PV: producer set is a placeholder; none registered (the genesis is not release-ready)"
fi

# Books, broadcasts and the KEEP pin from this devnet (the r1006 node is verified against it).
mkdir -p "$WORK/book"
cp "$REPO"/contracts/genesis/*.json "$REPO/contracts/addresses/40204.json" "$WORK/book/"
cp -r "$REPO/contracts/broadcast" "$WORK/broadcast"
(cd "$REPO" && RPC="$RPC" ADDRESS_BOOK="$REPO/contracts/addresses/40204.json" BROADCAST_DIR="$REPO/contracts/broadcast" \
  CHAIN_ID=40204 bash scripts/genesis/keep_check.sh keys contracts,aaStack >"$WORK/KEEP_KEYS.tsv" 2>"$WORK/keep.log" &&
  RPC="$RPC" ADDRESS_BOOK="$REPO/contracts/addresses/40204.json" BROADCAST_DIR="$REPO/contracts/broadcast" bash scripts/genesis/keep_check.sh pin "$WORK/KEEP_KEYS.tsv" >"$WORK/KEEP_LIST.r1006.tsv" 2>>"$WORK/keep.log") ||
  log "WARN: KEEP pin failed (see $WORK/keep.log); verify will skip keep_check"
TIP=$(c block-number)
log "devnet tip $TIP; stopping the node and dumping its state"
stop_node
"$DUMP" "$WORK/devnet-data" >"$WORK/dump.json" 2>"$WORK/dump.log" || die "state-dump failed (see $WORK/dump.log)"
printf '{"devnetGenesis":"%s","devnetGenesisTimestamp":%s,"deployer":"%s","tip":%s}\n' "$G0" "$((G0TS))" "$DEPLOYER" "$TIP" >"$WORK/devnet.json"
log "dump: $(jq '.accounts | length' "$WORK/dump.json") accounts, state root $(jq -r .stateRoot "$WORK/dump.json")"
