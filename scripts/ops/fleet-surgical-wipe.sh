#!/usr/bin/env bash
# fleet-surgical-wipe.sh — the 4-node ATOMIC SURGICAL WIPE for a CLEAN REROLL.
#
# This is the single most destructive step of the reroll and, until now, was
# 100% manual SSH (which is why the S2/S3/S3c rerolls stalled here). It performs
# the exact hand-run procedure from SRP_S2_REROLL_EXECUTION_STATUS.md, scripted
# and idempotent:
#
#   1. `systemctl stop citrate-node` on ALL 4 nodes.
#   2. On each node, ARCHIVE + WIPE the RocksDB chaindata while PRESERVING the
#      three per-node artifacts that must survive a reroll:
#        - noise.key   (stable libp2p identity / peer id)
#        - node.toml   (per-node coinbase == that node's staker)
#        - models/     (pinned model blobs)
#
#      WP-11 — `proposer.key` is DELIBERATELY NOT PRESERVED HERE.
#
#      Since WP-11 the ed25519 block-signing key is a real secret persisted at
#      `<data-dir>/proposer.key`, not a value derived from the public coinbase.
#      A reroll re-registers every validator from genesis, so each node SHOULD
#      mint a fresh consensus identity — carrying the old one over would re-use
#      a key across two chains for no benefit.
#
#      THIS CHANGES THE REROLL SEQUENCE. The old flow could register validators
#      before the nodes had even started, because the pubkey was computable from
#      the coinbase. It no longer is. The order is now:
#
#        wipe → start nodes (each mints proposer.key) → COPY each node's
#        proposer.key to the operator box (0600 both ends) → run
#        validator-registration-ceremony with
#        `--node <coinbase>=<STAKER_KEY_ENV>=<proposer_key_file>`
#
#      Registering before the nodes have started is now impossible, and the
#      ceremony rejects the old two-field `--node` form rather than silently
#      falling back to a derivation.
#
#      For a NON-reroll resync (a single node rebuilding its chaindata while the
#      network keeps running) the opposite is true: `proposer.key` MUST be
#      preserved, or that node comes back with an unregistered identity and
#      silently stops proposing. Use a targeted copy, not this script.
#      i.e. mv /home/citrate/.citrate → .citrate.preroll-<tag>-<ts>, recreate
#      /home/citrate/.citrate, copy the 3 artifacts back.
#   3. Swap the binary: back up the live one, install the pre-staged
#      /home/citrate/bin/citrate-node.<tag> (must md5-match across all 4 nodes).
#   4. Bring rpc-1 up ISOLATED (boots still down) and assert G1 (fresh genesis).
#   5. Join boot1/2/3 and assert G2 (early state-root consensus, 0 mismatches).
#
# It is NON-INTERACTIVE by default so the orchestrator can chain it, but the
# irreversible wipe is gated by an explicit `--confirm-wipe` flag (the orchestrator
# passes it only after the single human go/no-go). Without that flag it runs a
# full DRY-RUN plan (prints every remote command, changes nothing).
#
# Usage:
#   scripts/ops/fleet-surgical-wipe.sh --tag srp-s4 [--confirm-wipe]
#   scripts/ops/fleet-surgical-wipe.sh --tag srp-s4                 # dry-run plan
#
# Exit codes: 0 ok · 1 precondition/arg · 2 remote step failed · 3 G1 fail · 4 G2 fail
set -euo pipefail

TAG=""
CONFIRM=0
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o BatchMode=yes}"
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --confirm-wipe) CONFIRM=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
[ -n "$TAG" ] || { echo "ERROR: --tag <binary-tag> required (e.g. srp-s4)" >&2; exit 1; }

# --- fleet (user citrate; bin/data under /home/citrate; SSH as root) ----------
# host  ip               coinbase==staker   role
# rpc-1 142.93.58.145    STAKER_1           MINER + serves RPC
# boot1 142.93.50.217    STAKER_2           boot
# boot2 143.198.134.151  STAKER_3           boot
# boot3 142.93.99.212    STAKER_4           boot
RPC1_IP="142.93.58.145"
BOOT_IPS=( "142.93.50.217" "143.198.134.151" "142.93.99.212" )
ALL_IPS=( "$RPC1_IP" "${BOOT_IPS[@]}" )

DATA_DIR="/home/citrate/.citrate"
BIN_LIVE="/home/citrate/bin/citrate-node"
BIN_STAGED="/home/citrate/bin/citrate-node.${TAG}"
UNIT="citrate-node"
PRESERVE=( "noise.key" "node.toml" "models" )
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo manual)"
ARCHIVE="${DATA_DIR}.preroll-${TAG}-${TS}"

# --- G1/G2 ground-truth (must reproduce; from SRP_S2 execution log) -----------
CHAIN_ID_HEX="0x9d0c"                                     # 40204
GENESIS_HASH_PREFIX="0xd1a1941e"
GENESIS_STATEROOT_PREFIX="0xd703e8c6"
ARACHNID="0x4e59b44847b379578588920cA78FbF26c0B4956C"
DEPLOYER="0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732"
DEPLOYER_BAL_HEX="0x84595161401484a000000"               # 10,000,000 SALT

log()  { echo "[wipe] $*"; }
err()  { echo "[wipe] ERROR: $*" >&2; }
# Run a remote command (or, in dry-run, print it).
rsh() {
  local ip="$1"; shift
  if [ "$CONFIRM" -eq 1 ]; then
    ssh $SSH_OPTS "${SSH_USER}@${ip}" "$@"
  else
    echo "    DRYRUN ssh ${SSH_USER}@${ip} $*"
  fi
}
# Remote RPC call against a node's LOCAL 127.0.0.1:8545 (truly isolated, no LB).
rrpc() {
  local ip="$1" method="$2" params="$3"
  ssh $SSH_OPTS "${SSH_USER}@${ip}" \
    "curl -s --max-time 8 -X POST -H 'content-type: application/json' \
     --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}' \
     http://127.0.0.1:8545"
}

# --- PRECONDITIONS ------------------------------------------------------------
log "preflight: reachability + staged binary md5-match across 4 nodes (tag=${TAG})"
FIRST_MD5=""
for ip in "${ALL_IPS[@]}"; do
  ssh $SSH_OPTS "${SSH_USER}@${ip}" true 2>/dev/null || { err "cannot SSH ${SSH_USER}@${ip}"; exit 1; }
  M="$(ssh $SSH_OPTS "${SSH_USER}@${ip}" "md5sum '${BIN_STAGED}' 2>/dev/null | cut -d' ' -f1")"
  [ -n "$M" ] || { err "${ip}: staged binary ${BIN_STAGED} missing (Phase 0.2 build+stage first)"; exit 1; }
  if [ -z "$FIRST_MD5" ]; then FIRST_MD5="$M"; fi
  [ "$M" = "$FIRST_MD5" ] || { err "${ip}: staged binary md5 $M != $FIRST_MD5 — REBUILD; a mixed binary forks the chain"; exit 1; }
  log "  ${ip}: staged md5 $M ✓"
done
log "  all 4 staged binaries md5-match ($FIRST_MD5) ✓"

if [ "$CONFIRM" -eq 0 ]; then
  log ""
  log "DRY-RUN ONLY (no --confirm-wipe). The plan below changes NOTHING."
fi

# --- STEP 1: stop all 4 -------------------------------------------------------
log "step 1: stop ${UNIT} on all 4 nodes"
for ip in "${ALL_IPS[@]}"; do rsh "$ip" "systemctl stop ${UNIT}"; done

# --- STEP 2+3: surgical wipe + binary swap per node ---------------------------
# One remote heredoc per node keeps the preserve→wipe→restore→swap atomic and
# avoids a half-wiped node if the connection drops between substeps.
wipe_one() {
  local ip="$1"
  log "step 2/3: surgical wipe + binary swap on ${ip}"
  local script
  script=$(cat <<REMOTE
set -euo pipefail
DATA_DIR='${DATA_DIR}'; ARCHIVE='${ARCHIVE}'; BIN_LIVE='${BIN_LIVE}'; BIN_STAGED='${BIN_STAGED}'
# 2a: archive current chaindata (idempotent: skip if already archived this run)
if [ -d "\$DATA_DIR" ] && [ ! -d "\$ARCHIVE" ]; then mv "\$DATA_DIR" "\$ARCHIVE"; fi
mkdir -p "\$DATA_DIR"
# 2b: restore the three preserved artifacts from the archive
for f in ${PRESERVE[*]}; do
  if [ -e "\$ARCHIVE/\$f" ]; then cp -a "\$ARCHIVE/\$f" "\$DATA_DIR/\$f"; fi
done
chown -R citrate:citrate "\$DATA_DIR"
# 2c: assert the preserved artifacts landed (noise.key + node.toml are load-bearing)
[ -f "\$DATA_DIR/noise.key" ] || { echo "PRESERVE FAIL: noise.key missing after wipe" >&2; exit 7; }
[ -f "\$DATA_DIR/node.toml" ] || { echo "PRESERVE FAIL: node.toml missing after wipe" >&2; exit 7; }
# 3: swap binary (back up the live one once), install staged, verify md5
if [ -f "\$BIN_LIVE" ] && [ ! -f "\${BIN_LIVE}.pre-${TAG}" ]; then cp -a "\$BIN_LIVE" "\${BIN_LIVE}.pre-${TAG}"; fi
install -o citrate -g citrate -m 0755 "\$BIN_STAGED" "\$BIN_LIVE"
LM=\$(md5sum "\$BIN_LIVE" | cut -d' ' -f1); SM=\$(md5sum "\$BIN_STAGED" | cut -d' ' -f1)
[ "\$LM" = "\$SM" ] || { echo "SWAP FAIL: live md5 \$LM != staged \$SM" >&2; exit 8; }
echo "OK ${ip}: wiped (archive \$ARCHIVE), preserved noise.key+node.toml+models, binary=\$LM"
REMOTE
)
  if [ "$CONFIRM" -eq 1 ]; then
    ssh $SSH_OPTS "${SSH_USER}@${ip}" "bash -s" <<<"$script" || { err "${ip}: wipe/swap failed"; exit 2; }
  else
    echo "    DRYRUN would run surgical-wipe+swap heredoc on ${ip} (archive ${ARCHIVE})"
  fi
}
for ip in "${ALL_IPS[@]}"; do wipe_one "$ip"; done

# --- STEP 4: rpc-1 ISOLATED + G1 ----------------------------------------------
log "step 4: start rpc-1 ISOLATED (boots down) + assert G1 fresh genesis"
rsh "$RPC1_IP" "systemctl start ${UNIT}"
if [ "$CONFIRM" -eq 1 ]; then
  # give the node a moment to open genesis + RPC (poll up to ~40s)
  ok=0
  for _ in $(seq 1 20); do
    CID="$(rrpc "$RPC1_IP" eth_chainId '[]' | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
    [ "$CID" = "$CHAIN_ID_HEX" ] && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = "1" ] || { err "G1: rpc-1 chainId != ${CHAIN_ID_HEX} (got '${CID:-none}')"; exit 3; }
  B0="$(rrpc "$RPC1_IP" eth_getBlockByNumber '["0x0",false]')"
  echo "$B0" | grep -q "\"hash\":\"${GENESIS_HASH_PREFIX}" || { err "G1: genesis hash != ${GENESIS_HASH_PREFIX}…"; echo "$B0" | head -c 400 >&2; exit 3; }
  echo "$B0" | grep -q "\"stateRoot\":\"${GENESIS_STATEROOT_PREFIX}" || { err "G1: genesis stateRoot != ${GENESIS_STATEROOT_PREFIX}…"; exit 3; }
  AC="$(rrpc "$RPC1_IP" eth_getCode "[\"$ARACHNID\",\"latest\"]" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
  [ "${#AC}" -gt 6 ] || { err "G1: Arachnid CREATE2 deployer has no code at $ARACHNID"; exit 3; }
  DB="$(rrpc "$RPC1_IP" eth_getBalance "[\"$DEPLOYER\",\"latest\"]" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
  [ "$DB" = "$DEPLOYER_BAL_HEX" ] || { err "G1: deployer balance $DB != $DEPLOYER_BAL_HEX (10M)"; exit 3; }
  log "  G1 PASS: chainId ${CHAIN_ID_HEX}, genesis ${GENESIS_HASH_PREFIX}…/${GENESIS_STATEROOT_PREFIX}…, Arachnid code ✓, deployer 10M ✓"
else
  echo "    DRYRUN would poll rpc-1 for G1 (chainId ${CHAIN_ID_HEX}, genesis ${GENESIS_HASH_PREFIX}, stateRoot ${GENESIS_STATEROOT_PREFIX}, Arachnid code, deployer 10M)"
fi

# --- STEP 5: join boots + G2 --------------------------------------------------
log "step 5: start boot1/2/3 + assert G2 early state-root consensus"
for ip in "${BOOT_IPS[@]}"; do rsh "$ip" "systemctl start ${UNIT}"; done
if [ "$CONFIRM" -eq 1 ]; then
  # wait until rpc-1 has advanced past a small checkpoint height, then compare
  # every node's stateRoot at that height (byte-identical == consensus).
  CHECK_HEIGHT_HEX="0x0a"   # height 10 (G2 checkpoint from the S2 log)
  ok=0
  for _ in $(seq 1 40); do
    H="$(rrpc "$RPC1_IP" eth_blockNumber '[]' | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
    # numeric compare: head >= 10
    if [ -n "$H" ] && [ "$((16#${H#0x}))" -ge 10 ]; then ok=1; break; fi
    sleep 3
  done
  [ "$ok" = "1" ] || { err "G2: rpc-1 did not reach height 10 (head '${H:-none}')"; exit 4; }
  REF=""
  for ip in "${ALL_IPS[@]}"; do
    SR="$(rrpc "$ip" eth_getBlockByNumber "[\"$CHECK_HEIGHT_HEX\",false]" | sed -n 's/.*"stateRoot":"\([^"]*\)".*/\1/p')"
    [ -n "$SR" ] || { err "G2: ${ip} has no block at height 10 yet"; exit 4; }
    if [ -z "$REF" ]; then REF="$SR"; fi
    [ "$SR" = "$REF" ] || { err "G2: ${ip} stateRoot@10 $SR != $REF — FRESH-CHAIN FORK"; exit 4; }
    log "  ${ip}: stateRoot@10 $SR"
  done
  log "  G2 PASS: stateRoot@10 byte-identical on all 4 ($REF); 0 fresh mismatches"
else
  echo "    DRYRUN would start boots + compare stateRoot@10 across all 4 nodes"
fi

log ""
if [ "$CONFIRM" -eq 1 ]; then
  log "✅ SURGICAL WIPE COMPLETE — fresh chain live on all 4 nodes, G1+G2 PASS."
  log "   next (orchestrator): front-load ValidatorRegistry + registration (Phase 2)."
else
  log "DRY-RUN complete. Re-run with --confirm-wipe to execute (IRREVERSIBLE)."
fi
