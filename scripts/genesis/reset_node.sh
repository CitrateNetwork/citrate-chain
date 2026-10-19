#!/usr/bin/env bash
# reset_node.sh: per-node state reset for a new genesis. Run on a fleet node, as root.
#
# Generalized from the r1005 reroll's reset-node script (2026-10-05). For one node it:
#   1. pauses the height watchdog timer (re-enabled by hand once the chain is past genesis;
#      a watchdog that restarts a node mid-replay caused the 2026-09-27 replay loop);
#   2. stops the node service;
#   3. installs the staged binary, after checking its sha256 when EXPECTED_BIN_SHA256 is set
#      (every node must run the same build);
#   4. ARCHIVES the data dir (a move, never a delete: the old chain stays recoverable) and
#      copies back only the node's identity and config: noise.key, node.toml, peer.id,
#      encryption.meta, models/. proposer.key is NOT carried by default: a new genesis
#      registers every validator from scratch, so each node mints a fresh consensus key on
#      first start (WP-11). --keep-proposer-key carries it for a same-chain resync.
#      RocksDB files (IDENTITY included) never carry over.
#   5. sets the [mining] coinbase in node.toml to this node's staker address;
#   6. points CITRATE_VALIDATOR_REGISTRY and CITRATE_VALIDATOR_ACTIVATION_HEIGHT in the
#      systemd drop-in at the new genesis values, before the first start;
#   7. does NOT start the node. The ceremony starts nodes in order (runbook §6).
#
# Key files are copied as files (cp -a); their contents are never read or printed.
#
# Usage
#   reset_node.sh --coinbase 0x… --validator-registry 0x… --activation-height N
#                 [--keep-proposer-key] [--confirm]
# Without --confirm it checks every precondition and prints the plan, changing nothing.
#
# Env (defaults are the fleet layout): CITRATE_HOME=/home/citrate  DATA_DIR=$CITRATE_HOME/.citrate
#   BIN=$CITRATE_HOME/bin/citrate-node  NEW_BIN=$BIN.new  SERVICE=citrate-node
#   DROPIN=/etc/systemd/system/$SERVICE.service.d/reroll.conf  WATCHDOG_TIMER=citrate-height-watchdog.timer
#   NODE_OWNER=citrate:citrate (empty = no chown)  SYSTEMCTL=systemctl  EXPECTED_BIN_SHA256 (optional)
#
# Exit: 0 ok · 1 precondition failed · 2 usage
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/genesis/lib.sh
. "$HERE/lib.sh"
GENESIS_LOG_TAG="reset_node $(hostname 2>/dev/null || echo node)"

COINBASE=""
VR=""
ACT=""
KEEP_PROPOSER=0
CONFIRM=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --coinbase) COINBASE="${2:-}"; shift 2 ;;
    --validator-registry) VR="${2:-}"; shift 2 ;;
    --activation-height) ACT="${2:-}"; shift 2 ;;
    --keep-proposer-key) KEEP_PROPOSER=1; shift ;;
    --confirm) CONFIRM=1; shift ;;
    --dry-run) CONFIRM=0; shift ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
      exit 2
      ;;
    *) die "unknown argument $1" 2 ;;
  esac
done
is_addr "$COINBASE" || die "--coinbase must be a 0x 20-byte address" 2
is_addr "$VR" || die "--validator-registry must be a 0x 20-byte address" 2
[[ "$ACT" =~ ^[0-9]+$ ]] || die "--activation-height must be a whole number" 2

CITRATE_HOME="${CITRATE_HOME:-/home/citrate}"
DATA="${DATA_DIR:-$CITRATE_HOME/.citrate}"
BIN="${BIN:-$CITRATE_HOME/bin/citrate-node}"
NEW="${NEW_BIN:-$BIN.new}"
SERVICE="${SERVICE:-citrate-node}"
DROPIN="${DROPIN:-/etc/systemd/system/$SERVICE.service.d/reroll.conf}"
WATCHDOG_TIMER="${WATCHDOG_TIMER:-citrate-height-watchdog.timer}"
NODE_OWNER="${NODE_OWNER-citrate:citrate}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE="${DATA}.pregenesis-${TS}"

CARRY=(noise.key node.toml peer.id encryption.meta)
[[ $KEEP_PROPOSER -eq 1 ]] && CARRY+=(proposer.key)

# ---- preconditions (read-only) ----
[[ -x "$NEW" ]] || die "staged binary $NEW is missing or not executable"
[[ -f "$DATA/noise.key" ]] || die "$DATA/noise.key is missing: refusing to touch a node without its identity"
[[ -f "$DATA/node.toml" ]] || die "$DATA/node.toml is missing"
[[ -f "$DROPIN" ]] || die "systemd drop-in $DROPIN is missing"
grep -qE '^\s*coinbase\s*=' "$DATA/node.toml" || die "$DATA/node.toml has no coinbase line to remap"
if [[ -n "${EXPECTED_BIN_SHA256:-}" ]]; then
  got=$(sha256sum "$NEW" | cut -d' ' -f1)
  [[ "$got" == "$(lower "$EXPECTED_BIN_SHA256")" ]] || die "staged binary sha256 $got != EXPECTED_BIN_SHA256"
  log "staged binary sha256 matches"
else
  log "WARN: EXPECTED_BIN_SHA256 unset; the binary is not checked against the release"
fi

CB_HEX=$(lower "${COINBASE#0x}")
log "plan: watchdog off · stop $SERVICE · install $NEW → $BIN · archive $DATA → $ARCHIVE"
log "      carry: ${CARRY[*]} models/ · coinbase → $CB_HEX · VR → $VR · activation → $ACT"
[[ $KEEP_PROPOSER -eq 1 ]] || log "      proposer.key NOT carried (fresh consensus key on first start)"
if [[ $CONFIRM -ne 1 ]]; then
  log "dry run: nothing changed. Re-run with --confirm to execute."
  exit 0
fi

# ---- execute ----
"$SYSTEMCTL" stop "$WATCHDOG_TIMER" 2>/dev/null || true
log "watchdog timer: $("$SYSTEMCTL" is-active "$WATCHDOG_TIMER" 2>/dev/null || echo inactive)"
"$SYSTEMCTL" stop "$SERVICE" || true

cp -a "$BIN" "${BIN}.pregenesis-${TS}" 2>/dev/null || true
install -m 0755 "$NEW" "$BIN"
[[ -n "$NODE_OWNER" ]] && chown "$NODE_OWNER" "$BIN"
log "binary sha256=$(sha256sum "$BIN" | cut -c1-16)…"

mv "$DATA" "$ARCHIVE"
mkdir -p "$DATA"
for f in "${CARRY[@]}"; do
  [[ -e "$ARCHIVE/$f" ]] && cp -a "$ARCHIVE/$f" "$DATA/$f"
done
[[ -d "$ARCHIVE/models" ]] && cp -a "$ARCHIVE/models" "$DATA/models"

# node.toml stores the coinbase as bare lowercase hex (no 0x); keep that format.
sed -i -E "s/^(\s*coinbase\s*=\s*\")(0x)?[0-9a-fA-F]{40}(\")/\1${CB_HEX}\3/" "$DATA/node.toml"
grep -qE "^\s*coinbase\s*=\s*\"${CB_HEX}\"" "$DATA/node.toml" || die "coinbase remap failed"
[[ -n "$NODE_OWNER" ]] && chown -R "$NODE_OWNER" "$DATA"

cp -a "$DROPIN" "${DROPIN}.bak-${TS}"
set_env() { # NAME VALUE in the drop-in
  if grep -q "^Environment=$1=" "$DROPIN"; then
    sed -i -E "s|^Environment=$1=.*|Environment=$1=$2|" "$DROPIN"
  else
    printf 'Environment=%s=%s\n' "$1" "$2" >>"$DROPIN"
  fi
}
set_env CITRATE_VALIDATOR_REGISTRY "$VR"
set_env CITRATE_VALIDATOR_ACTIVATION_HEIGHT "$ACT"
"$SYSTEMCTL" daemon-reload

log "reset done; $SERVICE NOT started. Archive: $ARCHIVE"
ls -A "$DATA"
