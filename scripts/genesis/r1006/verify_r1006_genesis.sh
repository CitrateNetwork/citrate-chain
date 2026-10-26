#!/usr/bin/env bash
# verify_r1006_genesis.sh: boot a node from the r1006 genesis and prove it serves the
# ceremony's state. Local only: both nodes run inside a private network namespace.
#
#   verify_r1006_genesis.sh --node BIN --devnet-node BIN --work DIR --repo DIR --alloc FILE
#     --node         a citrate binary built with the alloc embedded (profile r1006)
#     --devnet-node  the binary the ceremony devnet ran
#     --work         the ceremony's work dir (devnet-data, dump.json, book/, KEEP_LIST.r1006.tsv)
#     --repo         a chain checkout with contracts compiled (for CheckDeployedAdmins)
#     --alloc        the alloc the --node binary embeds
#
# Checks, in order (exit 1 at the first failure):
#   1. the r1006 node's block 0 is the hash `citrate consensus`-pinned R1006_GENESIS, and not
#      the devnet's or r1005's;
#   2. compare_rpc.py: eth_getCode / eth_getStorageAt identical to the devnet for every alloc
#      account and every slot, balances and nonces equal the alloc;
#   3. keep_check.sh verify with the KEEP list pinned on the devnet, against the r1006 node;
#   4. CheckDeployedAdmins over the ceremony's P5 book against the r1006 node:
#      FACTORY-ADMIN 0, DEPLOYER-ADMIN 0;
#   5. the genesis note reads back from block 0's state.
# The r1006 node runs with CITRATE_R1006_REHEARSAL=1 (a placeholder genesis refuses to
# boot otherwise) and with mining off. No key is used.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
die() { echo "verify_r1006: $*" >&2; exit 1; }
log() { echo "[verify $(date -u +%H:%M:%S)] $*" >&2; }
cmd="${1:-}"
NODE="" DEVNODE="" WORK="" REPO="" ALLOC="" V=""
[[ "$cmd" == _inner ]] && shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    --devnet-node) DEVNODE="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --alloc) ALLOC="$2"; shift 2 ;;
    --v) V="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
if [[ "$cmd" != _inner ]]; then
  for f in "$NODE" "$DEVNODE"; do [[ -x "$f" ]] || die "not executable: $f"; done
  [[ -f "$WORK/dump.json" && -d "$WORK/devnet-data" && -f "$ALLOC" && -d "$REPO/contracts" ]] || die "missing inputs"
  export FOUNDRY_SOLC="${FOUNDRY_SOLC:-$HOME/.svm/0.8.36/solc-0.8.36}" # HOME is replaced inside
  V=$(mktemp -d "${TMPDIR:-/tmp}/r1006-verify.XXXXXX")
  cp -a "$WORK/devnet-data" "$V/devnet-data"
  rc=0
  unshare --user --map-root-user --net bash "$0" _inner --node "$(readlink -f "$NODE")" --devnet-node "$(readlink -f "$DEVNODE")" \
    --work "$WORK" --repo "$REPO" --alloc "$(readlink -f "$ALLOC")" --v "$V" || rc=$?
  echo "verify_r1006: logs in $V" >&2
  exit "$rc"
fi

ip link set lo up
export HOME="$V/home"
mkdir -p "$HOME" "$V/r1006-data"
cfg() { # cfg NAME PORT DATA PROFILE
  cat >"$V/$1.toml" <<EOF
[chain]
chain_id = 40204
block_time = 2
genesis_profile = "$4"
ghostdag_k = 18
[network]
listen_addr = "127.0.0.1:$(($2 + 1000))"
bootstrap_nodes = []
max_peers = 4
[rpc]
enabled = true
listen_addr = "127.0.0.1:$2"
ws_addr = "127.0.0.1:$(($2 + 1))"
[storage]
data_dir = "$3"
pruning = false
keep_blocks = 1000000
[mining]
enabled = false
coinbase = ""
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
}
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done; wait 2>/dev/null || true' EXIT
up() { # up BIN NAME PORT [env...]
  local bin="$1" name="$2" port="$3"
  shift 3
  (cd "$V" && exec env "$@" "$bin" --config "$V/$name.toml") >"$V/$name.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 240); do cast chain-id --rpc-url "http://127.0.0.1:$port" >/dev/null 2>&1 && return 0; sleep 0.5; done
  die "$name did not come up (see $V/$name.log)"
}
DEV=http://127.0.0.1:18545 R06=http://127.0.0.1:28545
# The devnet's own data dir carries its exact-created-code height in its config, so
# replaying is not needed: the node only serves the stored state (mining off).
cfg devnet 18545 "$V/devnet-data" default
sed -i 's/^ghostdag_k = 18$/ghostdag_k = 18\nexact_create_code_height = 0/' "$V/devnet.toml"
cfg r1006 28545 "$V/r1006-data" r1006
up "$DEVNODE" devnet 18545
up "$NODE" r1006 28545 CITRATE_R1006_REHEARSAL=1

G=$(cast block 0 --field hash --rpc-url "$R06")
GD=$(cast block 0 --field hash --rpc-url "$DEV")
PIN=$("$NODE" consensus --json 2>/dev/null | grep -oE '"r1006_genesis": "0x[0-9a-f]{64}"' | grep -oE '0x[0-9a-f]{64}' || true)
[[ -n "$PIN" ]] || die "cannot read the binary's R1006_GENESIS from 'citrate consensus --json'"
log "r1006 block 0 $G (devnet block 0 $GD)"
[[ "$G" != "$GD" ]] || die "the r1006 node serves the devnet's block 0"
[[ "$G" != 0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1 ]] || die "the r1006 node serves r1005's block 0"
[[ "$PIN" == "$G" ]] || die "block 0 $G is not the binary's pinned R1006_GENESIS $PIN"
echo "R1006_BLOCK0=$G" >"$V/result.env"

python3 "$HERE/compare_rpc.py" --alloc "$ALLOC" --dump "$WORK/dump.json" --devnet "$DEV" --r1006 "$R06" | tee "$V/compare.log"

if [[ -s "$WORK/KEEP_LIST.r1006.tsv" ]]; then
  RPC="$R06" bash "$HERE/../keep_check.sh" verify "$WORK/KEEP_LIST.r1006.tsv" 2>&1 | tee "$V/keep.log" | tail -3
  grep -q 'KEEP gate PASS' "$V/keep.log" || die "keep_check verify failed against the r1006 node (see $V/keep.log)"
else
  die "no KEEP list from the ceremony devnet"
fi

mkdir -p "$REPO/contracts/genesis"
cp "$WORK/book/p5-admin-book.json" "$REPO/contracts/genesis/p5-admin-book.json"
# The admin sweep reads role STATE (hasRole, owner, admin slots) and role HISTORY (events).
# A genesis chain has no events: its contracts were never deployed by a transaction, so the
# history-based lines (TIMELOCK-HOLDERS, GENESIS-FLOOR's veto lookup) have nothing to read
# here. They passed at P5 on the devnet, and compare_rpc above proved every storage slot of
# every contract identical to that devnet, so the role state they protect is the same. The
# gate here is the state-based handover: FACTORY-ADMIN 0 and DEPLOYER-ADMIN 0 on the r1006 node.
(cd "$REPO/contracts" && FOUNDRY_OFFLINE=true ADDRESS_BOOK=genesis/p5-admin-book.json REQUIRE_ALL_CODE=true \
  forge script script/CheckDeployedAdmins.s.sol --rpc-url "$R06") >"$V/admins.log" 2>&1 || true
grep -E 'FACTORY-ADMIN failures|DEPLOYER-ADMIN failures|NO-CODE entries|TIMELOCK-HOLDERS failures|GENESIS-FLOOR failures' "$V/admins.log" | sed 's/^ */  /'
grep -q 'FACTORY-ADMIN failures: 0' "$V/admins.log" || die "FACTORY-ADMIN is not 0 on the r1006 node (see $V/admins.log)"
grep -q 'DEPLOYER-ADMIN failures: 0' "$V/admins.log" || die "DEPLOYER-ADMIN is not 0 on the r1006 node (see $V/admins.log)"
grep -q 'NO-CODE entries (reported): 0' "$V/admins.log" || die "a book entry has no code on the r1006 node (see $V/admins.log)"
log "admins: FACTORY-ADMIN 0, DEPLOYER-ADMIN 0, NO-CODE 0 on the r1006 node (history-based lines: no events at genesis, see the comment)"

NOTE_LEN=$(cast storage 0x000000000000000000000000000000c17a7e1006 0 --rpc-url "$R06")
log "genesis note slot 0 = $NOTE_LEN"
[[ "$NOTE_LEN" != 0x0000000000000000000000000000000000000000000000000000000000000000 ]] || die "no genesis note in block 0's state"
log "VERIFIED: r1006 block 0 $G serves the ceremony state"
