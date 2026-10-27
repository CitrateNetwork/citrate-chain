#!/usr/bin/env bash
# r1006_bringup.sh: bring up the r1006 testnet on the 7 producer hosts, step by step.
#
# Every step is idempotent and has --dry-run (prints what it would do; touches no host
# and writes nothing but the plan). Run from a citrate-chain checkout on the DGX. The
# per-host work is scripts/ops/r1006/host_agent.sh, streamed over ssh as root.
#
#   r1006_bringup.sh build        --sha SHA        build citrate-node from origin/main at SHA on the
#                                                  x86_64 build host (own temp dir); record sha256 and
#                                                  the r1006 genesis the binary compiles
#   r1006_bringup.sh keys                          mint each host's keys ON the host (as citrate);
#                                                  collect ONLY the public parts -> r1006-producers.json,
#                                                  each host's registration proof for the committed
#                                                  r1006 ValidatorRegistry -> r1006-registration-proofs.json,
#                                                  and r1006-public-bootnodes.json for the cutover profile
#   r1006_bringup.sh genesis-fill --fill-cmd CMD   producers + stake allocations -> genesis fill
#                                                  (genesis hash, profile, registry) -> fill-result.json,
#                                                  kept only if it is the build's compiled r1006 genesis
#   r1006_bringup.sh distribute                    binary to every host, hash checked; node.toml per
#                                                  host (genesis_profile r1006, mining OFF, bootnodes =
#                                                  the other producers, RPC on loopback); block 0
#                                                  probed on every host
#   r1006_bringup.sh start                         pre-join: every host's installed binary must be a
#                                                  clean build at or after MIN_CHAIN_REV (refused
#                                                  before any host starts); then start in inventory
#                                                  order, mining off, with health gates; then
#                                                  (--mining on) switch mining on, host by host, only
#                                                  once EVERY host shows the r1006 block 0
#   r1006_bringup.sh smoke                         FLEET AGREE, chain id, code vs genesis alloc,
#                                                  OrangeSeed story(), CheckDeployedAdmins in
#                                                  genesis-chain mode (GENESIS_CHAIN=1, GENESIS_ALLOC
#                                                  = the fill's block-0 alloc): FACTORY-ADMIN,
#                                                  DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS and
#                                                  GENESIS-FLOOR all 0, no CONFLICT/
#                                                  fork in logs, finality status, no contribution
#                                                  recorder configured, memory per host
#   r1006_bringup.sh stop                          stop every node (reverse order)
#   r1006_bringup.sh wipe [--wipe-keys]            delete r1006 chain data only; keys kept unless
#                                                  --wipe-keys (asks for the typed confirmation)
#   r1006_bringup.sh status                        one line per host
#   r1006_bringup.sh tunnels up|down               loopback tunnels to every host's RPC
#
# Hosts: only citrate-prod-1..7 at their pinned IPs (scripts/ops/r1006/guard.py), cross-
# checked live with `doctl compute droplet list --tag-name citrate-producer` (read-only)
# before any ssh. `build` may ssh only to the build-only host citrate-core-linux-build,
# which never runs a node or key action. Anything else is refused before connecting.
#
# Genesis: genesis-fill, distribute and start refuse a release network's block 0 (r1005
# testnet, team testnet, mainnet) and any block 0 but the R1006_GENESIS pin committed in
# this checkout's core/consensus/src/hardening.rs, read at run time (it is re-pinned after
# the fill and after the final rebuild); the recorded build must compile that same genesis.
#
# Host output: every agent call's stdout and stderr are checked on the host and again
# here, in memory, before anything is printed or written; a key or password pattern fails
# the step (rc 3) without echoing it. Only checked public identities reach the state dir.
#
# Common options
#   --inventory FILE   hosts (default scripts/ops/r1006/inventory.r1006.json)
#   --state DIR        local state (default ~/r1006-state, 0700; a dir inside a git checkout
#                      must be gitignored): build record, binary, public identities,
#                      r1006-producers.json, genesis fill, rendered profiles, timings
#   --only NAMES       comma-separated subset of hosts (re-run a step on some hosts)
#   --dry-run          plan only
#
# Step options
#   build:        --sha SHA (required) · --local-repo PATH (build on this machine from PATH,
#                 rehearsal) · --allow-non-main (rehearsal only; distribute refuses such a
#                 binary for an ssh inventory)
#   genesis-fill: --fill-cmd 'CMD {producers} {stakes} {out}' (the genesis builder's
#                 validator-set fill, scripts/genesis/r1006/fill_producers.py; it reads
#                 r1006-registration-proofs.json next to {producers}; must write {out}/fill-result.json, see
#                 scripts/ops/r1006/render_profile.py) · --stake-salt N (32000) · --liquid-salt N (100)
#   start:        --mining on|off (on; on: the validator set is in the genesis) · --gate-minutes N (10)
#                 · --min-peers N (hosts-1) · --skip-producing-gate
#                 · --min-chain-rev SHA: the oldest chain commit a producer binary may be built
#                   from (40 hex). Also read from the reviewed one-line file
#                   scripts/ops/r1006/min_chain_rev (comment lines start with #); when both are
#                   set they must be equal; when neither is set, start refuses. A binary built
#                   before the r1006 genesis rules (chain#398) runs the r1006 data dir with those
#                   rules off, so each host's `citrate-node consensus --json` git_sha must be
#                   clean, resolve in this checkout, and have MIN_CHAIN_REV as an ancestor
#                   (git merge-base --is-ancestor). Fetch origin first.
#   smoke:        --skip CHECK[,CHECK] (orangeseed, admins, code, logs) printed as SKIP, never PASS
#                 · --min-height N (60): wait (up to --gate-minutes) until every head is past N, so
#                   FLEET AGREE compares a real common block, not block 0
#   wipe:         --wipe-keys (destroys noise.key, proposer.key and the staker keystore)
#
# Env: R1006_SSH_KEY (inventory ssh_key) · CAST, FORGE (cast, forge) · R1006_TUNNEL_BASE (18545)
#      DOCTL (doctl)
#
# Exit: 0 ok · 1 a gate failed · 2 usage or refused
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
AGENT="$HERE/r1006/host_agent.sh"
PY="$HERE/r1006"
GUARD="$HERE/r1006/guard.py"
CAST="${CAST:-cast}"
FORGE="${FORGE:-forge}"
TUNNEL_BASE="${R1006_TUNNEL_BASE:-18545}"

INVENTORY="$HERE/r1006/inventory.r1006.json"
STATE="$HOME/r1006-state"
DRY=0
ONLY=""
SHA=""
LOCAL_REPO=""
ALLOW_NON_MAIN=0
FILL_CMD=""
STAKE_SALT=32000
LIQUID_SALT=100
MINING=on
MINING_SET=0
GATE_MIN=10
MIN_PEERS=""
SKIP_PRODUCING=0
SKIPS=""
MIN_HEIGHT=60
WIPE_KEYS=0
MIN_CHAIN_REV_OPT=""

die() { echo "r1006_bringup: $*" >&2; exit 2; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
gate_fail() { log "GATE FAIL: $*"; exit 1; }

STEP="${1:-}"
[[ -n "$STEP" ]] || { sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 2; }
shift
SUB=""
if [[ "$STEP" == tunnels ]]; then SUB="${1:-}"; shift || true; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) INVENTORY="$2"; shift 2 ;;
    --state) STATE="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --sha) SHA="$2"; shift 2 ;;
    --local-repo) LOCAL_REPO="$2"; shift 2 ;;
    --allow-non-main) ALLOW_NON_MAIN=1; shift ;;
    --fill-cmd) FILL_CMD="$2"; shift 2 ;;
    --stake-salt) STAKE_SALT="$2"; shift 2 ;;
    --liquid-salt) LIQUID_SALT="$2"; shift 2 ;;
    --mining) MINING="$2"; MINING_SET=1; shift 2 ;;
    --gate-minutes) GATE_MIN="$2"; shift 2 ;;
    --min-peers) MIN_PEERS="$2"; shift 2 ;;
    --skip-producing-gate) SKIP_PRODUCING=1; shift ;;
    --skip) SKIPS="$2"; shift 2 ;;
    --min-height) MIN_HEIGHT="$2"; shift 2 ;;
    --wipe-keys) WIPE_KEYS=1; shift ;;
    --min-chain-rev) MIN_CHAIN_REV_OPT="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[[ -f "$INVENTORY" ]] || die "no inventory at $INVENTORY"
# Names, IPs and the host allowlist, before anything reads a host name.
python3 "$GUARD" check-inventory --inventory "$INVENTORY" || die "inventory refused (see REFUSED above)"

# The state dir holds public data only, and never inside a checkout unless gitignored.
STATE="$(realpath -m -- "$STATE")"
state_anc="$STATE"
while [[ ! -d "$state_anc" ]]; do state_anc="$(dirname -- "$state_anc")"; done
if state_top=$(git -C "$state_anc" rev-parse --show-toplevel 2>/dev/null) &&
  ! git -C "$state_top" check-ignore -q --no-index -- "$STATE/"; then
  die "--state $STATE is inside the checkout $state_top and not gitignored; use ~/r1006-state or an ignored path"
fi
(umask 077; mkdir -p -- "$STATE")
chmod 0700 -- "$STATE"
TIMINGS="$STATE/timings.log"

# ---- inventory --------------------------------------------------------------

inv() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$INVENTORY" "$1"; }
TRANSPORT=$(inv 'd.get("transport","ssh")')
[[ "$TRANSPORT" == ssh || "$TRANSPORT" == local ]] || die "inventory transport must be ssh or local"
SSH_USER=$(inv 'd.get("ssh_user","root")')
SSH_KEY="${R1006_SSH_KEY:-$(inv 'd.get("ssh_key","")')}"
SSH_KEY="${SSH_KEY/#\~/$HOME}"
mapfile -t ALL_HOSTS < <(inv '"\n".join(h["name"] for h in d["hosts"])')
HOSTS=()
if [[ -n "$ONLY" ]]; then
  IFS=',' read -r -a want <<<"$ONLY"
  for w in "${want[@]}"; do
    printf '%s\n' "${ALL_HOSTS[@]}" | grep -qx -- "$w" || die "--only: $w is not in the inventory"
    HOSTS+=("$w")
  done
else
  HOSTS=("${ALL_HOSTS[@]}")
fi
host_field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([h for h in d["hosts"] if h["name"]==sys.argv[2]][0].get(sys.argv[3],""))' "$INVENTORY" "$1" "$2"; }
host_index() { local i=0; for h in "${ALL_HOSTS[@]}"; do [[ "$h" == "$1" ]] && { echo "$i"; return; }; i=$((i + 1)); done; die "unknown host $1"; }

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new)
[[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")

# ---- host allowlist (compiled into guard.py, not the inventory) ----------------
declare -A PROD_IP=()
BUILD_NAME="" BUILD_IP=""
while read -r n ip role; do
  case "$role" in
    producer) PROD_IP[$n]=$ip ;;
    build) BUILD_NAME=$n; BUILD_IP=$ip ;;
  esac
done < <(python3 "$GUARD" hosts)
[[ ${#PROD_IP[@]} -eq 7 && -n "$BUILD_IP" ]] || die "the pinned host table did not load"

# target_ip HOST: the address a node/key action on HOST may connect to. Only a pinned
# producer at its pinned IP; the build host and everything else are refused.
target_ip() {
  local h="$1" ip
  ip=$(host_field "$h" ip)
  if [[ "$TRANSPORT" == ssh ]]; then
    [[ -n "${PROD_IP[$h]:-}" && "${PROD_IP[$h]}" == "$ip" ]] ||
      die "REFUSED $h ($ip) is not an approved r1006 producer; not connecting"
  fi
  printf '%s' "$ip"
}

# Live cross-check (read-only doctl) before the first connection of a real ssh run.
if [[ "$TRANSPORT" == ssh && $DRY -eq 0 ]]; then
  case "$STEP" in
    build) [[ -n "$LOCAL_REPO" ]] || python3 "$GUARD" live-check --build || die "build host refused" ;;
    genesis-fill) ;;
    *) python3 "$GUARD" live-check --names "$(IFS=,; echo "${HOSTS[*]}")" || die "hosts refused" ;;
  esac
fi

# ---- transport ---------------------------------------------------------------
# agent_cmd HOST CMD ARGS...: the transport command line for host_agent.sh CMD on HOST.
agent_cmd() {
  local h="$1"
  shift
  AGENT_CMD=()
  if [[ "$TRANSPORT" == ssh ]]; then
    local q ip
    ip=$(target_ip "$h") || exit 2
    q=$(printf '%q ' "$@")
    AGENT_CMD=(ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "bash -s -- $q")
  else
    local pid root
    pid=$(host_field "$h" netns_pid)
    root=$(host_field "$h" root)
    [[ -n "$pid" ]] && AGENT_CMD=(nsenter --net="/proc/$pid/ns/net")
    AGENT_CMD+=(env R1006_ROOT="$root" R1006_SERVICE=proc R1006_RUN_AS=
      R1006_NODE_ENV_PASSTHRU="${R1006_NODE_ENV_PASSTHRU:-}" bash -s -- "$@")
  fi
}

# agent HOST CMD ARGS...: run host_agent.sh CMD on HOST (as root). Its stdout and stderr
# pass guard.py's in-memory check before either is shown (rc 3 on a key pattern).
agent() {
  local h="$1"
  shift
  if [[ $DRY -eq 1 ]]; then
    [[ "$TRANSPORT" == ssh ]] && target_ip "$h" >/dev/null
    echo "  [dry-run] $h: host_agent.sh $*"
    return 0
  fi
  agent_cmd "$h" "$@"
  python3 "$GUARD" relay --host "$h" -- "${AGENT_CMD[@]}" <"$AGENT"
}

# agent_identity HOST OUT CMD ARGS...: like agent, but stdout must be exactly one public
# host identity; only the checked, re-serialised object is written to OUT.
agent_identity() {
  local h="$1" out="$2"
  shift 2
  agent_cmd "$h" "$@"
  python3 "$GUARD" relay --host "$h" --identity-out "$out" -- "${AGENT_CMD[@]}" <"$AGENT"
}

# put HOST LOCAL_FILE NAME: stage a file as usr/local/lib/citrate-r1006/<NAME> on HOST.
put() {
  local h="$1" src="$2" name="$3"
  local dest="/usr/local/lib/citrate-r1006/$name"
  if [[ $DRY -eq 1 ]]; then
    [[ "$TRANSPORT" == ssh ]] && target_ip "$h" >/dev/null
    echo "  [dry-run] $h: copy $src -> $dest"
    return 0
  fi
  if [[ "$TRANSPORT" == ssh ]]; then
    local ip
    ip=$(target_ip "$h") || exit 2
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "mkdir -p '$(dirname "$dest")'"
    scp -q "${SSH_OPTS[@]}" -- "$src" "$SSH_USER@$ip:$dest.part"
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$ip" "mv -f '$dest.part' '$dest'"
  else
    local root
    root=$(host_field "$h" root)
    mkdir -p "$root$(dirname "$dest")"
    cp -f -- "$src" "$root$dest.part"
    mv -f -- "$root$dest.part" "$root$dest"
  fi
}

rpc_url() { echo "http://127.0.0.1:$((TUNNEL_BASE + $(host_index "$1")))"; }

tunnel_up() {
  local h="$1" port
  port=$((TUNNEL_BASE + $(host_index "$h")))
  if [[ $DRY -eq 1 ]]; then
    [[ "$TRANSPORT" == ssh ]] && target_ip "$h" >/dev/null
    echo "  [dry-run] tunnel 127.0.0.1:$port -> $h 127.0.0.1:8545"
    return 0
  fi
  mkdir -p "$STATE/tunnels"
  if [[ "$TRANSPORT" == ssh ]]; then
    local sock="$STATE/tunnels/$h.sock" ip
    ip=$(target_ip "$h") || exit 2
    if [[ -S "$sock" ]] && ssh -S "$sock" -O check x 2>/dev/null; then return 0; fi
    ssh "${SSH_OPTS[@]}" -M -S "$sock" -f -N -o ExitOnForwardFailure=yes \
      -L "127.0.0.1:$port:127.0.0.1:8545" "$SSH_USER@$ip"
  else
    local pidf="$STATE/tunnels/$h.pid"
    if [[ -f "$pidf" ]] && kill -0 "$(cat "$pidf")" 2>/dev/null; then return 0; fi
    python3 "$PY/nsfwd.py" "$port" "$(host_field "$h" netns_pid)" 8545 >/dev/null 2>&1 &
    echo $! >"$pidf"
    sleep 0.3
  fi
}

tunnel_down() {
  local h="$1"
  if [[ $DRY -eq 1 ]]; then echo "  [dry-run] close tunnel to $h"; return 0; fi
  if [[ "$TRANSPORT" == ssh ]]; then
    local sock="$STATE/tunnels/$h.sock"
    [[ -S "$sock" ]] && ssh -S "$sock" -O exit x 2>/dev/null || true
  else
    local pidf="$STATE/tunnels/$h.pid"
    if [[ -f "$pidf" ]]; then kill "$(cat "$pidf")" 2>/dev/null || true; rm -f -- "$pidf"; fi
  fi
}

rpc() { # HOST METHOD PARAMS_JSON -> result JSON (or empty)
  curl -s -m 5 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$(rpc_url "$1")" |
    python3 -c 'import json,sys
try:
    r=json.load(sys.stdin)["result"]
except Exception:
    sys.exit(1)
print(json.dumps(r) if not isinstance(r,str) else r)' 2>/dev/null || true
}
hexnum() { python3 -c 'import sys; v=sys.argv[1]; print(int(v,16) if v.startswith("0x") else int(v))' "$1" 2>/dev/null || echo ""; }

# ---- timing ------------------------------------------------------------------
T0=$(date +%s)
finish() {
  local rc=$?
  local dt=$(( $(date +%s) - T0 ))
  if [[ $DRY -eq 0 ]]; then
    printf '%s %-14s rc=%s %ss hosts=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STEP${SUB:+ $SUB}" "$rc" "$dt" "${#HOSTS[@]}" >>"$TIMINGS"
  fi
  log "step $STEP${SUB:+ $SUB} finished rc=$rc in ${dt}s"
}
trap finish EXIT

# ---- build -------------------------------------------------------------------
BUILD_JSON="$STATE/build.json"
build_field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$BUILD_JSON" "$1"; }

step_build() {
  [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || die "build needs --sha <40-hex commit>"
  if [[ -f "$BUILD_JSON" && "$(build_field sha)" == "$SHA" && -f "$STATE/bin/citrate-node" ]] &&
    [[ "$(sha256sum "$STATE/bin/citrate-node" | cut -d' ' -f1)" == "$(build_field sha256)" ]]; then
    log "build $SHA already recorded (sha256 $(build_field sha256)); nothing to do"
    return 0
  fi
  local script
  script=$(cat <<'BUILD'
set -euo pipefail
SHA="$1"; SRC="$2"; ALLOW="$3"; BASE="$4"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null || { echo "no cargo on the build host" >&2; exit 3; }
T=$(mktemp -d "$BASE/r1006-build.XXXXXX")
echo "BUILD_DIR=$T"
git clone -q --no-checkout "$SRC" "$T/src"
cd "$T/src"
git fetch -q origin main
git checkout -q --detach "$SHA"
if ! git merge-base --is-ancestor "$SHA" origin/main; then
  if [ "$ALLOW" = 1 ]; then echo "WARNING: $SHA is NOT on origin/main (rehearsal build)" >&2
  else echo "REFUSED: $SHA is not on origin/main" >&2; exit 3; fi
fi
CARGO_TARGET_DIR="$T/target" CARGO_PROFILE_RELEASE_DEBUG=0 cargo build --release --locked -p citrate-node --bin citrate >&2
B="$T/target/release/citrate"
echo "SHA256=$(sha256sum "$B" | cut -d' ' -f1)"
CONS=$(RUST_LOG=error "$B" consensus --json)
echo "FINGERPRINT=$(python3 -c 'import json,sys; l=sys.argv[1].splitlines(); print(json.loads("\n".join(l[l.index("{"):]))["fingerprint"])' "$CONS")"
echo "R1006_GENESIS=$(python3 -c 'import json,sys; l=sys.argv[1].splitlines(); print(json.loads("\n".join(l[l.index("{"):])).get("r1006_genesis",""))' "$CONS")"
echo "ARCH=$(uname -m)"
BUILD
)
  local where out
  if [[ -n "$LOCAL_REPO" ]]; then
    where="local:$LOCAL_REPO"
    if [[ $DRY -eq 1 ]]; then
      echo "  [dry-run] build $SHA from $LOCAL_REPO in a fresh mktemp dir on this machine"
      return 0
    fi
    out=$(bash -c "$script" build "$SHA" "$LOCAL_REPO" "$ALLOW_NON_MAIN" "${TMPDIR:-/tmp}")
  else
    # Only the pinned build-only host (guard.py); check-inventory already refused an
    # inventory whose build_host is anything else.
    local bip="$BUILD_IP"
    where="$BUILD_NAME ($bip)"
    if [[ $DRY -eq 1 ]]; then
      echo "  [dry-run] ssh $SSH_USER@$bip: clone https://github.com/CitrateNetwork/citrate-chain into mktemp /root/r1006-build.*,"
      echo "            checkout $SHA (must be on origin/main), cargo build --release --locked -p citrate-node --bin citrate,"
      echo "            sha256 + consensus fingerprint, copy back to $STATE/bin/citrate-node, delete the temp dir"
      return 0
    fi
    out=$(ssh "${SSH_OPTS[@]}" "$SSH_USER@$bip" "bash -s -- $SHA https://github.com/CitrateNetwork/citrate-chain $ALLOW_NON_MAIN /root" <<<"$script")
  fi
  local dir sha fp arch g6
  g6=$(sed -n 's/^R1006_GENESIS=//p' <<<"$out")
  dir=$(sed -n 's/^BUILD_DIR=//p' <<<"$out")
  sha=$(sed -n 's/^SHA256=//p' <<<"$out")
  fp=$(sed -n 's/^FINGERPRINT=//p' <<<"$out")
  arch=$(sed -n 's/^ARCH=//p' <<<"$out")
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || gate_fail "build produced no sha256"
  mkdir -p "$STATE/bin"
  if [[ -n "$LOCAL_REPO" ]]; then
    cp -f -- "$dir/target/release/citrate" "$STATE/bin/citrate-node.part"
    [[ "$dir" == "${TMPDIR:-/tmp}"/r1006-build.* ]] && rm -rf -- "${dir:?}"
  else
    scp -q "${SSH_OPTS[@]}" "$SSH_USER@$bip:$dir/target/release/citrate" "$STATE/bin/citrate-node.part"
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$bip" "case '$dir' in /root/r1006-build.*) rm -rf -- '$dir' ;; esac"
  fi
  [[ "$(sha256sum "$STATE/bin/citrate-node.part" | cut -d' ' -f1)" == "$sha" ]] || gate_fail "copied binary differs from the build's sha256"
  mv -f -- "$STATE/bin/citrate-node.part" "$STATE/bin/citrate-node"
  chmod 0755 "$STATE/bin/citrate-node"
  python3 - "$BUILD_JSON" "$SHA" "$sha" "$fp" "$arch" "$where" "$ALLOW_NON_MAIN" "$g6" <<'PY'
import json, sys, datetime
p, sha, s256, fp, arch, where, nm, g6 = sys.argv[1:]
json.dump({"sha": sha, "sha256": s256, "fingerprint": fp, "arch": arch, "built_on": where,
           "from_main": nm != "1", "r1006_genesis": g6.lower(),
           "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
          open(p, "w"), indent=2)
PY
  log "built $SHA on $where: sha256 $sha fingerprint $fp arch $arch r1006 genesis ${g6:-NONE (genesis steps will refuse this build)}"
}

need_build() {
  if [[ $DRY -eq 1 && ! -f "$BUILD_JSON" ]]; then
    echo "  [dry-run] no build recorded yet; the real run needs: $0 build --sha <sha>"
    build_field() { echo "<build $1>"; }
    return 0
  fi
  [[ -f "$BUILD_JSON" && -f "$STATE/bin/citrate-node" ]] || die "no build recorded; run: $0 build --sha <sha>"
  [[ "$(sha256sum "$STATE/bin/citrate-node" | cut -d' ' -f1)" == "$(build_field sha256)" ]] || die "$STATE/bin/citrate-node differs from build.json"
  if [[ "$TRANSPORT" == ssh && "$(build_field from_main)" != True ]]; then
    die "the recorded build is not from origin/main; producers run main builds only"
  fi
  return 0
}

# ---- keys --------------------------------------------------------------------
step_keys() {
  need_build
  local REGISTRY
  REGISTRY=$(python3 "$GUARD" committed --repo "$REPO" | cut -d' ' -f2) || die "no committed r1006 genesis/registry (see REFUSED above)"
  [[ -n "$REGISTRY" ]] || die "no committed r1006 ValidatorRegistry"
  local s256
  s256=$(build_field sha256)
  mkdir -p "$STATE/pub"
  for h in "${HOSTS[@]}"; do
    log "keys: $h"
    put "$h" "$STATE/bin/citrate-node" citrate-keytool
    if [[ $DRY -eq 1 ]]; then
      agent "$h" keys "$s256"
      continue
    fi
    # The host re-serialises its checked public file; guard.py checks it again in memory
    # and writes only that object. On any refusal nothing is written and the step stops.
    local rc=0
    agent_identity "$h" "$STATE/pub/$h.pub.json" keys "$s256" || rc=$?
    [[ $rc -eq 0 ]] || { log "keys: $h refused (rc=$rc); nothing written for it; stopping"; exit "$rc"; }
    # The proof of key control for the committed registry, checked the same way and
    # against this host's own checked identity.
    local st pk
    st=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["staker_address"])' "$STATE/pub/$h.pub.json")
    pk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["proposer_pubkey"])' "$STATE/pub/$h.pub.json")
    agent_cmd "$h" registration-proof "$REGISTRY"
    python3 "$GUARD" relay --host "$h" --proof-out "$STATE/pub/$h.proof.json" --expect-staker "$st" \
      --expect-proposer "$pk" --expect-registry "$REGISTRY" -- "${AGENT_CMD[@]}" <"$AGENT" || rc=$?
    [[ $rc -eq 0 ]] || { log "keys: $h registration proof refused (rc=$rc); nothing written for it; stopping"; exit "$rc"; }
  done
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] registration-proof --registry $REGISTRY on each host (checked on the host and here)"
    echo "  [dry-run] collect.py -> $STATE/r1006-producers.json + r1006-registration-proofs.json + r1006-public-bootnodes.json"
    return 0
  fi
  python3 "$PY/collect.py" --inventory "$INVENTORY" --pub-dir "$STATE/pub" --out "$STATE/r1006-producers.json" \
    --bootnodes-out "$STATE/r1006-public-bootnodes.json" \
    --proofs-out "$STATE/r1006-registration-proofs.json" --registry "$REGISTRY"
}

# ---- genesis checks ---------------------------------------------------------------
# check_genesis FILL: refuse a release network's block 0, any profile but the compiled
# r1006 one, a genesis file, and any block 0 but the recorded build's r1006 genesis.
check_genesis() {
  python3 "$GUARD" check-genesis --fill "$1" --build "$BUILD_JSON" --repo "$REPO" || die "genesis refused (see REFUSED above)"
}

# ---- genesis-fill --------------------------------------------------------------
step_genesis_fill() {
  local prod="$STATE/r1006-producers.json" stakes="$STATE/r1006-stakes.json"
  local final="$STATE/genesis" out="$STATE/genesis.incoming"
  [[ -f "$prod" || $DRY -eq 1 ]] || die "no $prod; run keys first"
  [[ -n "$FILL_CMD" ]] || die "genesis-fill needs --fill-cmd (the genesis builder's validator-set fill)"
  need_build
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] render_profile.py stakes ($STAKE_SALT SALT bonded + $LIQUID_SALT SALT liquid per staker) -> $stakes"
    echo "  [dry-run] $FILL_CMD   with {producers}=$prod {stakes}=$stakes {out}=$out"
    echo "  [dry-run] render_profile.py check-fill: the fill lists exactly these validators and stakes"
    echo "  [dry-run] guard.py check-genesis: profile r1006, no genesis file, block 0 == the committed R1006_GENESIS (and the build's),"
    echo "            never a release network's; only then $out -> $final"
    return 0
  fi
  python3 "$PY/render_profile.py" stakes --producers "$prod" --stake-salt "$STAKE_SALT" --liquid-salt "$LIQUID_SALT" --out "$stakes"
  rm -rf -- "${out:?}"
  mkdir -p "$out"
  local cmd="$FILL_CMD"
  cmd=${cmd//\{producers\}/$(printf '%q' "$prod")}
  cmd=${cmd//\{stakes\}/$(printf '%q' "$stakes")}
  cmd=${cmd//\{out\}/$(printf '%q' "$out")}
  log "genesis-fill: $cmd"
  (cd "$REPO" && bash -c "$cmd")
  [[ -f "$out/fill-result.json" ]] || { rm -rf -- "${out:?}"; gate_fail "the fill command wrote no $out/fill-result.json"; }
  if ! python3 "$PY/render_profile.py" check-fill --producers "$prod" --stakes "$stakes" --fill "$out/fill-result.json"; then
    rm -rf -- "${out:?}"
    gate_fail "the genesis fill does not match the producer set"
  fi
  if ! python3 "$GUARD" check-genesis --fill "$out/fill-result.json" --build "$BUILD_JSON" --repo "$REPO"; then
    rm -rf -- "${out:?}"
    die "genesis refused (see REFUSED above); the fill was discarded"
  fi
  rm -rf -- "${final:?}"
  mv -- "$out" "$final"
  log "genesis: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["genesis_hash"], "profile", d.get("genesis_profile"), "registry", d["validator_registry"])' "$final/fill-result.json")"
}

fill_field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$STATE/genesis/fill-result.json" "$1"; }

# ---- distribute ---------------------------------------------------------------
step_distribute() {
  need_build
  local fill="$STATE/genesis/fill-result.json"
  [[ -f "$fill" || $DRY -eq 1 ]] || die "no $fill; run genesis-fill first"
  [[ $MINING_SET -eq 0 ]] || die "--mining is a start option: distribute always configures mining OFF"
  local s256 gh
  s256=$(build_field sha256)
  log "distribute: binary $(build_field sha) sha256 $s256"
  if [[ $DRY -eq 0 ]]; then
    check_genesis "$fill"
    gh=$(fill_field genesis_hash)
  else
    echo "  [dry-run] guard.py check-genesis on the fill (r1006 profile, committed R1006_GENESIS = the build's, committed registry, no release genesis)"
    gh="<genesis hash from fill-result.json>"
  fi
  mkdir -p "$STATE/profiles"
  for h in "${HOSTS[@]}"; do
    log "distribute: $h"
    if [[ $DRY -eq 0 ]]; then
      python3 "$PY/render_profile.py" profile --template "$REPO/scripts/producers/profiles/r1006.json" \
        --producers "$STATE/r1006-producers.json" --fill "$fill" --host "$h" --out "$STATE/profiles/$h.json" >/dev/null
    else
      echo "  [dry-run] render_profile.py profile --host $h -> $STATE/profiles/$h.json"
    fi
    put "$h" "$STATE/bin/citrate-node" incoming/citrate-node
    if [[ $DRY -eq 0 ]]; then
      local got
      got=$(agent "$h" sha citrate-node)
      [[ "$got" == "$s256" ]] || gate_fail "$h: staged binary sha256 $got, want $s256"
    fi
    agent "$h" install-bin "$s256"
    put "$h" "$REPO/scripts/producers/gen_node_config.py" tools/gen_node_config.py
    put "$h" "$REPO/scripts/producers/producerlib.py" tools/producerlib.py
    put "$h" "$STATE/profiles/$h.json" profile.json
    local staker="<staker of $h>"
    [[ $DRY -eq 0 ]] && staker=$(python3 -c 'import json,sys; print([p for p in json.load(open(sys.argv[1]))["producers"] if p["name"]==sys.argv[2]][0]["staker_address"])' "$STATE/r1006-producers.json" "$h")
    agent "$h" write-config "$staker" off
    agent "$h" probe-genesis "$gh" || gate_fail "$h: the installed binary + config do not give block 0 $gh"
  done
}

# ---- start -------------------------------------------------------------------
wait_until() { # SECONDS DESCRIPTION CMD...: poll CMD every 2 s
  local limit=$1 what=$2
  shift 2
  local t=0
  until "$@"; do
    t=$((t + 2))
    ((t >= limit)) && return 1
    sleep 2
  done
  log "  ok: $what (${t}s)"
}

node_answers() { [[ "$(rpc "$1" eth_getBlockByNumber '["0x0",false]')" == *'"hash"'* ]]; }
block0_is() { [[ "$(rpc "$1" eth_getBlockByNumber '["0x0",false]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"].lower())' 2>/dev/null)" == "${2,,}" ]]; }
peers_at_least() { local n; n=$(hexnum "$(rpc "$1" net_peerCount '[]')"); [[ -n "$n" && "$n" -ge "$2" ]]; }

producers_seen() { # prints the number of distinct producer coinbases seen in blocks 1..head on HOST
  local h="$1" head
  head=$(hexnum "$(rpc "$h" eth_blockNumber '[]')")
  [[ -n "$head" ]] || { echo 0; return; }
  python3 - "$(rpc_url "$h")" "$head" "$STATE/r1006-producers.json" "$STATE/miners.seen" <<'PY'
import json, sys, urllib.request
url, head, prod, seen_f = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
want = {p["staker_address"].lower(): p["name"] for p in json.load(open(prod))["producers"]}
try:
    seen = json.load(open(seen_f))
except Exception:
    seen = {"upto": 0, "miners": {}}
def call(m, p):
    r = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=5))["result"]
for n in range(seen["upto"] + 1, head + 1):
    b = call("eth_getBlockByNumber", [hex(n), False])
    if b:
        m = (b.get("miner") or "").lower()
        seen["miners"][m] = seen["miners"].get(m, 0) + 1
seen["upto"] = head
json.dump(seen, open(seen_f, "w"))
print(sum(1 for m in seen["miners"] if m in want))
PY
}

stop_started() { # stop every host in HOSTS up to and including $1
  local s
  for s in "${HOSTS[@]}"; do agent "$s" stop || true; [[ "$s" == "$1" ]] && break; done
}

# ---- pre-join: build rev at or after MIN_CHAIN_REV ----------------------------
MIN_REV_FILE="$HERE/r1006/min_chain_rev"

# min_chain_rev: the floor from --min-chain-rev and/or the reviewed file; refuses when
# neither is set, when they differ, or when it is not a full commit in this checkout.
min_chain_rev() {
  local v="" f=""
  if [[ -f "$MIN_REV_FILE" ]]; then
    f=$(grep -vE '^[[:space:]]*(#|$)' "$MIN_REV_FILE" | tr -d '[:space:]' || true)
    [[ -n "$f" ]] || die "MIN_CHAIN_REV: $MIN_REV_FILE names no commit"
  fi
  if [[ -n "$MIN_CHAIN_REV_OPT" && -n "$f" && "$MIN_CHAIN_REV_OPT" != "$f" ]]; then
    die "MIN_CHAIN_REV: --min-chain-rev $MIN_CHAIN_REV_OPT differs from the reviewed $MIN_REV_FILE ($f); refusing"
  fi
  v="${MIN_CHAIN_REV_OPT:-$f}"
  [[ -n "$v" ]] || die "MIN_CHAIN_REV is not set (--min-chain-rev SHA or $MIN_REV_FILE); refusing to start nodes without a binary floor"
  [[ "$v" =~ ^[0-9a-f]{40}$ ]] || die "MIN_CHAIN_REV must be a full 40-hex commit, got '$v'"
  git -C "$REPO" cat-file -e "$v^{commit}" 2>/dev/null ||
    die "MIN_CHAIN_REV $v is not a commit in this checkout ($REPO); fetch origin and retry"
  printf '%s' "$v"
}

# check_build_revs: every host in HOSTS runs a clean binary built from MIN_CHAIN_REV or a
# descendant of it. Runs before any host is started; any doubt refuses.
check_build_revs() {
  local min h out sha dirty full
  min=$(min_chain_rev) || exit 2
  for h in "${HOSTS[@]}"; do
    out=$(agent "$h" build-rev) || die "MIN_CHAIN_REV: $h did not report its binary's build rev; refusing"
    read -r sha dirty <<<"$out"
    [[ "$sha" =~ ^[0-9a-f]{7,40}$ ]] || die "MIN_CHAIN_REV: $h's binary reports build rev '${sha:-}' (no commit); refusing"
    [[ "$dirty" == false ]] || die "MIN_CHAIN_REV: $h's binary was built from a dirty tree ($sha); refusing"
    full=$(git -C "$REPO" rev-parse --verify -q "$sha^{commit}" 2>/dev/null) ||
      die "MIN_CHAIN_REV: $h's build rev $sha does not resolve to one commit in this checkout (fetch origin); refusing"
    git -C "$REPO" merge-base --is-ancestor "$min" "$full" ||
      die "MIN_CHAIN_REV: $h's binary is built from $sha, which does not contain $min; refusing"
    log "  ok: $h binary $sha contains MIN_CHAIN_REV ${min:0:12}"
  done
}

step_start() {
  local n=${#HOSTS[@]} gh
  [[ -z "$MIN_PEERS" ]] && MIN_PEERS=$((${#ALL_HOSTS[@]} - 1))
  [[ "$MINING" == on || "$MINING" == off ]] || die "--mining on|off"
  if [[ $DRY -eq 1 ]]; then
    gh="<fill genesis_hash>"
  else
    need_build
    [[ -f "$STATE/genesis/fill-result.json" ]] || die "no fill; run genesis-fill first"
    check_genesis "$STATE/genesis/fill-result.json"
    gh=$(fill_field genesis_hash)
  fi
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] pre-join: each host's citrate-node consensus --json git_sha is clean and contains MIN_CHAIN_REV"
    echo "            (--min-chain-rev / $MIN_REV_FILE; unset refuses) per git merge-base --is-ancestor; else no host starts"
  else
    log "start: pre-join build-rev check (MIN_CHAIN_REV)"
    check_build_revs
  fi
  [[ $DRY -eq 0 && ! -f "$STATE/started_at" ]] && date +%s >"$STATE/started_at"
  local first=1
  for h in "${HOSTS[@]}"; do
    log "start: $h (mining off)"
    if ! agent "$h" start "$gh"; then stop_started "$h"; gate_fail "$h did not start"; fi
    tunnel_up "$h"
    if [[ $DRY -eq 1 ]]; then
      echo "  [dry-run] gate: $h RPC answers within 120 s and block 0 == $gh${first:+ (the first node starts ALONE)}"
      first=""
      continue
    fi
    wait_until 120 "$h RPC answers" node_answers "$h" || { stop_started "$h"; gate_fail "$h RPC did not answer in 120 s (stopped)"; }
    if ! block0_is "$h" "$gh"; then
      log "  $h block 0 differs from $gh: stopping every started node"
      stop_started "$h"
      gate_fail "$h block 0 is not the r1006 genesis $gh"
    fi
    log "  ok: $h block 0 = $gh"
  done
  # Mining: only now that EVERY host shows the r1006 block 0. Each host checks its own
  # node's block 0 again before switching, and the result is checked from here after.
  local last="${HOSTS[-1]}"
  if [[ "$MINING" == on ]]; then
    for h in "${HOSTS[@]}"; do
      if [[ $DRY -eq 1 ]]; then
        echo "  [dry-run] $h: enable-mining $gh (host re-checks its node's block 0 first), then block 0 == $gh again"
        continue
      fi
      log "start: $h enable mining"
      if ! agent "$h" enable-mining "$gh"; then stop_started "$last"; gate_fail "$h refused to enable mining"; fi
      if ! wait_until 120 "$h RPC answers (mining on)" node_answers "$h" || ! block0_is "$h" "$gh"; then
        stop_started "$last"
        gate_fail "$h block 0 is not $gh after enabling mining (every node stopped)"
      fi
    done
  else
    log "mining stays off (--mining off)"
  fi
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] gate: every node net_peerCount >= $MIN_PEERS within $GATE_MIN min (tcp-check 30303 between producers on failure)"
    echo "  [dry-run] gate: blocks with each of the ${#ALL_HOSTS[@]} producers' coinbases within $GATE_MIN min"
    return 0
  fi
  local limit=$((GATE_MIN * 60))
  for h in "${HOSTS[@]}"; do
    if ! wait_until "$limit" "$h has >= $MIN_PEERS peers" peers_at_least "$h" "$MIN_PEERS"; then
      log "  $h has $(hexnum "$(rpc "$h" net_peerCount '[]')") peers; checking 30303 from $h to the others:"
      for o in "${ALL_HOSTS[@]}"; do [[ "$o" == "$h" ]] || agent "$h" tcp-check "$(host_field "$o" ip)" 30303 || true; done
      gate_fail "$h peers below $MIN_PEERS"
    fi
  done
  if [[ $SKIP_PRODUCING -eq 1 ]]; then
    log "SKIP producing gate (--skip-producing-gate)"
    return 0
  fi
  rm -f -- "$STATE/miners.seen"
  local want=${#ALL_HOSTS[@]} got=0 t=0
  while ((t < limit)); do
    got=$(producers_seen "${HOSTS[0]}")
    ((got >= want)) && break
    sleep 10
    t=$((t + 10))
  done
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [print(f"  coinbase {m}: {c} block(s)") for m,c in sorted(d["miners"].items())]' "$STATE/miners.seen" || true
  ((got >= want)) || gate_fail "only $got of $want producers have blocks after $GATE_MIN min"
  log "  ok: all $want producers have produced blocks (${t}s)"
}

# ---- smoke -------------------------------------------------------------------
SMOKE_FAIL=0
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; SMOKE_FAIL=1; }
skipped() { [[ ",$SKIPS," == *",$1,"* ]]; }

step_smoke() {
  if [[ $DRY -eq 1 ]]; then
    for h in "${HOSTS[@]}"; do tunnel_up "$h"; done
    echo "  [dry-run] wait until every head is past block $MIN_HEIGHT (up to $GATE_MIN min)"
    echo "  [dry-run] fleet_agree.sh over the ${#HOSTS[@]} tunnels, EXPECTED_GENESIS_HASH = fill genesis_hash"
    echo "  [dry-run] eth_chainId == 40204 on every host"
    echo "  [dry-run] eth_getCode(addr) == alloc[addr].code for every coded alloc entry (fill alloc_file), on every host"
    echo "  [dry-run] OrangeSeed (fill orangeseed): story() returns a non-empty string"
    echo "  [dry-run] CheckDeployedAdmins.s.sol, GENESIS_CHAIN=1, over the fill address_book with GENESIS_ALLOC = the fill alloc_file"
    echo "            (both staged under contracts/addresses, removed after): forge rc 0 and FACTORY-ADMIN, DEPLOYER-ADMIN,"
    echo "            NO-CODE, TIMELOCK-HOLDERS, GENESIS-FLOOR each reported once as 0"
    echo "  [dry-run] host_agent logs-scan: no CONFLICT / fork line since start, every host"
    echo "  [dry-run] finality: eth_getBlockByNumber(finalized) answers (switch OFF: expect block 0)"
    echo "  [dry-run] config: no contribution recorder in node.toml / env / unit drop-ins, every host"
    echo "  [dry-run] memory: node RSS < 3 GiB on every host (runbook alert line)"
    return 0
  fi
  local gh urls=()
  gh=$(fill_field genesis_hash)
  for h in "${HOSTS[@]}"; do tunnel_up "$h"; urls+=("$(rpc_url "$h")"); done

  # 0. every head past --min-height, so the agreement is about a real common block
  heads_past() {
    local h n
    for h in "${HOSTS[@]}"; do
      n=$(hexnum "$(rpc "$h" eth_blockNumber '[]')")
      [[ -n "$n" && "$n" -ge "$MIN_HEIGHT" ]] || return 1
    done
  }
  wait_until $((GATE_MIN * 60)) "every head past block $MIN_HEIGHT" heads_past ||
    fail "a head is not past block $MIN_HEIGHT after $GATE_MIN min"

  # 1. FLEET AGREE
  local fa="$REPO/scripts/genesis/fleet_agree.sh"
  if [[ ! -f "$fa" ]]; then
    fail "fleet_agree.sh not in this checkout (needs the genesis ceremony stack)"
  elif EXPECTED_GENESIS_HASH="$gh" CAST="$CAST" bash "$fa" "${urls[@]}" | tee "$STATE/fleet_agree.log" | grep -q '=> FLEET AGREE'; then
    pass "$(grep '=> FLEET AGREE' "$STATE/fleet_agree.log" | sed 's/.*=> //')"
  else
    sed 's/^/  | /' "$STATE/fleet_agree.log"
    fail "fleet_agree.sh did not agree"
  fi

  # 2. chain id
  local bad=0
  for h in "${HOSTS[@]}"; do
    [[ "$(hexnum "$(rpc "$h" eth_chainId '[]')")" == 40204 ]] || { bad=1; log "  $h chain id $(rpc "$h" eth_chainId '[]')"; }
  done
  [[ $bad -eq 0 ]] && pass "eth_chainId 40204 on ${#HOSTS[@]} hosts" || fail "chain id differs"

  # 3. code vs the genesis alloc
  local alloc
  alloc=$(fill_field alloc_file)
  if skipped code; then
    log "SKIP  code check (--skip code)"
  elif [[ -z "$alloc" || ! -f "$STATE/genesis/$alloc" ]]; then
    fail "no genesis alloc file in the fill result: cannot check eth_getCode"
  else
    local urls_csv
    urls_csv=$(IFS=,; echo "${urls[*]}")
    if python3 - "$STATE/genesis/$alloc" "$urls_csv" <<'PY'
import json, sys, urllib.request
alloc = json.load(open(sys.argv[1]))["alloc"]
urls = sys.argv[2].split(",")
coded = {a: v["code"].lower() for a, v in alloc.items() if v.get("code") not in (None, "", "0x")}
bad = 0
for url in urls:
    for a, code in coded.items():
        a = a if a.startswith("0x") else "0x" + a
        r = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [a, "latest"]}).encode(),
                                   {"content-type": "application/json"})
        got = json.load(urllib.request.urlopen(r, timeout=10)).get("result", "").lower()
        want = code if code.startswith("0x") else "0x" + code
        if got != want:
            bad += 1
            print(f"  {url} {a}: code {len(got)//2-1} bytes, genesis alloc {len(want)//2-1} bytes")
print(f"  {len(coded)} coded alloc entries x {len(urls)} hosts, {bad} mismatches")
sys.exit(1 if bad or not coded else 0)
PY
    then pass "eth_getCode equals the genesis alloc on every host"; else fail "eth_getCode differs from the genesis alloc"; fi
  fi

  # 4. OrangeSeed story()
  local seed
  seed=$(fill_field orangeseed)
  if skipped orangeseed; then
    log "SKIP  OrangeSeed (--skip orangeseed)"
  elif [[ -z "$seed" ]]; then
    fail "the fill result names no OrangeSeed address"
  else
    local story
    story=$("$CAST" call "$seed" 'story()(string)' --rpc-url "${urls[0]}" 2>/dev/null || true)
    [[ -n "$story" && "$story" != '""' ]] && pass "OrangeSeed $seed story(): ${story:0:80}" || fail "OrangeSeed $seed story() returned nothing"
  fi

  # 5. admins: the ceremony's P5 checker over the genesis book, in chain#398's genesis-chain
  #    mode. r1006's contracts are in block 0, so the timelock has no role history: the
  #    holder sets are proved from state against the block-0 alloc (GENESIS_ALLOC), forced
  #    with GENESIS_CHAIN=1. Without the alloc that mode fails closed, so a fill with no
  #    alloc fails here without running forge.
  local book admins_alloc
  book=$(fill_field address_book)
  admins_alloc=$(fill_field alloc_file)
  if skipped admins; then
    log "SKIP  admins (--skip admins)"
  elif [[ -z "$book" || ! -f "$STATE/genesis/$book" || ! -f "$REPO/contracts/script/CheckDeployedAdmins.s.sol" ]]; then
    fail "admins (genesis-chain mode): no address book in the fill result, or no CheckDeployedAdmins.s.sol in this checkout"
  elif [[ -z "$admins_alloc" || ! -f "$STATE/genesis/$admins_alloc" ]]; then
    fail "admins (genesis-chain mode): no block-0 alloc in the fill result (GENESIS_ALLOC is required)"
  else
    # forge may read only under contracts/ (fs_permissions: ./addresses), and the state dir
    # is outside the checkout: stage the fill's (public) book and alloc there for this run only.
    local report frc=0 c n bad_classes="" staged="addresses/.r1006-smoke-$$.json" staged_alloc="addresses/.r1006-smoke-$$-alloc.json"
    cp -f -- "$STATE/genesis/$book" "$REPO/contracts/$staged"
    cp -f -- "$STATE/genesis/$admins_alloc" "$REPO/contracts/$staged_alloc"
    report=$(cd "$REPO/contracts" && ADDRESS_BOOK="$staged" REQUIRE_ALL_CODE=true GENESIS_CHAIN=1 \
      GENESIS_ALLOC="$staged_alloc" "$FORGE" script script/CheckDeployedAdmins.s.sol --rpc-url "${urls[0]}" 2>&1) || frc=$?
    rm -f -- "$REPO/contracts/$staged" "$REPO/contracts/$staged_alloc"
    # The whole checker must pass (rc 0), and report each class exactly once, as 0.
    for c in "FACTORY-ADMIN failures" "DEPLOYER-ADMIN failures" "NO-CODE entries (reported)" \
      "TIMELOCK-HOLDERS failures" "GENESIS-FLOOR failures"; do
      n=$(printf '%s\n' "$report" | grep -F -- "$c:" | sed -nE 's/.*:[[:space:]]*([0-9]+)[[:space:]]*$/\1/p' || true)
      [[ $(printf '%s' "$n" | grep -c .) -eq 1 && "$n" == 0 ]] || bad_classes+=" ${c%% *}=${n:-missing}"
    done
    if [[ $frc -eq 0 && -z "$bad_classes" ]]; then
      pass "admins (genesis-chain mode): FACTORY-ADMIN, DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS, GENESIS-FLOOR all 0"
    else
      printf '%s\n' "$report" | tail -15 | sed 's/^/  | /'
      fail "admins (genesis-chain mode): forge rc=$frc;${bad_classes:- every class 0}"
    fi
  fi

  # 6. logs: no CONFLICT / fork
  local since
  since=$(cat "$STATE/started_at" 2>/dev/null || echo 0)
  if skipped logs; then
    log "SKIP  log scan (--skip logs)"
  else
    bad=0
    for h in "${HOSTS[@]}"; do
      local scan
      scan=$(agent "$h" logs-scan "$since")
      if [[ "$(sed -n 's/^matches //p' <<<"$scan")" != 0 ]]; then bad=1; log "  $h:"; sed -n '/^  |/p' <<<"$scan"; fi
      local sr dr
      sr=$(sed -n 's/^shallow_reorgs //p' <<<"$scan")
      dr=$(sed -n 's/^deepest_reorg //p' <<<"$scan")
      [[ "${sr:-0}" != 0 ]] && log "  NOTE $h: $sr shallow fork-choice reorg(s), deepest $dr block(s)"
    done
    [[ $bad -eq 0 ]] && pass "no CONFLICT / fork lines in any node log" || fail "CONFLICT / fork lines in node logs"
  fi

  # 7. finality status
  local fin
  fin=$(rpc "${HOSTS[0]}" eth_getBlockByNumber '["finalized",false]' | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["number"],16))' 2>/dev/null || true)
  if [[ -n "$fin" ]]; then pass "finality: finalized block $fin (checkpoint finality switch OFF on 40204: 0 expected)"
  else fail "finality: eth_getBlockByNumber(finalized) did not answer"; fi

  # 8. no contribution recorder configured
  bad=0
  for h in "${HOSTS[@]}"; do agent "$h" config-check >/dev/null || { bad=1; agent "$h" config-check || true; }; done
  [[ $bad -eq 0 ]] && pass "no contribution recorder configured on any host" || fail "a host configures a contribution recorder"

  # 9. memory
  bad=0
  for h in "${HOSTS[@]}"; do
    local st rss
    st=$(agent "$h" status)
    rss=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["rss_kb"])' "$st")
    log "  $h node RSS $((rss / 1024)) MiB  $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print("disk", d["data_disk_used"])' "$st")"
    ((rss < 3 * 1024 * 1024)) || bad=1
  done
  [[ $bad -eq 0 ]] && pass "node RSS under 3 GiB on every host" || fail "a node is over 3 GiB RSS"

  [[ $SMOKE_FAIL -eq 0 ]] || gate_fail "smoke"
  log "SMOKE PASS"
}

# ---- stop / wipe / status / tunnels ------------------------------------------
step_stop() {
  local i
  for ((i = ${#HOSTS[@]} - 1; i >= 0; i--)); do
    log "stop: ${HOSTS[$i]}"
    agent "${HOSTS[$i]}" stop
    tunnel_down "${HOSTS[$i]}"
  done
}

step_wipe() {
  if [[ $WIPE_KEYS -eq 1 ]]; then
    local token="WIPE-KEYS-${#HOSTS[@]}-HOSTS"
    log "--wipe-keys destroys noise.key, proposer.key and the staker keystore on: ${HOSTS[*]}"
    log "Every peer id, proposer key and staker address in r1006-producers.json becomes invalid."
    if [[ $DRY -eq 0 ]]; then
      [[ -t 0 ]] || die "--wipe-keys needs an interactive confirmation (stdin is not a terminal)"
      local ans
      read -r -p "Type $token to continue: " ans
      [[ "$ans" == "$token" ]] || die "not confirmed; nothing wiped"
    fi
  fi
  step_stop
  [[ $DRY -eq 0 ]] && rm -f -- "$STATE/started_at" "$STATE/miners.seen"
  for h in "${HOSTS[@]}"; do
    log "wipe: $h"
    if [[ $WIPE_KEYS -eq 1 ]]; then agent "$h" wipe --wipe-keys; else agent "$h" wipe; fi
  done
}

step_status() {
  for h in "${HOSTS[@]}"; do
    if [[ $DRY -eq 1 ]]; then agent "$h" status; continue; fi
    printf '%-16s %s\n' "$h" "$(agent "$h" status 2>&1 || true)"
  done
}

step_tunnels() {
  case "$SUB" in
    up) for h in "${HOSTS[@]}"; do tunnel_up "$h"; echo "$h $(rpc_url "$h")"; done ;;
    down) for h in "${HOSTS[@]}"; do tunnel_down "$h"; done ;;
    *) die "tunnels up|down" ;;
  esac
}

[[ $DRY -eq 1 ]] && log "DRY RUN: $STEP on ${#HOSTS[@]} host(s) [$TRANSPORT]; nothing is changed"
case "$STEP" in
  build) step_build ;;
  keys) step_keys ;;
  genesis-fill) step_genesis_fill ;;
  distribute) step_distribute ;;
  start) step_start ;;
  smoke) step_smoke ;;
  stop) step_stop ;;
  wipe) step_wipe ;;
  status) step_status ;;
  tunnels) step_tunnels ;;
  *) die "unknown step $STEP" ;;
esac
