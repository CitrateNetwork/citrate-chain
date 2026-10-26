#!/usr/bin/env bash
# r1006_bringup.sh: bring up the r1006 testnet on the 7 producer hosts, step by step.
#
# Every step is idempotent and has --dry-run (prints what it would do; touches no host
# and writes nothing but the plan). Run from a citrate-chain checkout on the DGX. The
# per-host work is scripts/ops/r1006/host_agent.sh, streamed over ssh as root.
#
#   r1006_bringup.sh build        --sha SHA        build citrate-node from origin/main at SHA on the
#                                                  x86_64 build host (own temp dir); record sha256
#   r1006_bringup.sh keys                          mint each host's keys ON the host (as citrate);
#                                                  collect ONLY the public parts -> r1006-producers.json
#   r1006_bringup.sh genesis-fill --fill-cmd CMD   producers + stake allocations -> genesis fill
#                                                  (genesis hash, profile, registry) -> fill-result.json
#   r1006_bringup.sh distribute                    binary + genesis to every host, hashes checked;
#                                                  node.toml per host (bootnodes = the other producers,
#                                                  RPC on loopback); block 0 probed on every host
#   r1006_bringup.sh start                         start in inventory order with health gates
#   r1006_bringup.sh smoke                         FLEET AGREE, chain id, code vs genesis alloc,
#                                                  OrangeSeed story(), DEPLOYER-ADMIN 0, no CONFLICT/
#                                                  fork in logs, finality status, memory per host
#   r1006_bringup.sh stop                          stop every node (reverse order)
#   r1006_bringup.sh wipe [--wipe-keys]            delete r1006 chain data only; keys kept unless
#                                                  --wipe-keys (asks for the typed confirmation)
#   r1006_bringup.sh status                        one line per host
#   r1006_bringup.sh tunnels up|down               loopback tunnels to every host's RPC
#
# Common options
#   --inventory FILE   hosts (default scripts/ops/r1006/inventory.r1006.json)
#   --state DIR        local state (default ./r1006-state): build record, binary, public
#                      identities, r1006-producers.json, genesis, rendered profiles, timings
#   --only NAMES       comma-separated subset of hosts (re-run a step on some hosts)
#   --dry-run          plan only
#
# Step options
#   build:        --sha SHA (required) · --local-repo PATH (build on this machine from PATH,
#                 rehearsal) · --allow-non-main (rehearsal only; distribute refuses such a
#                 binary for an ssh inventory)
#   genesis-fill: --fill-cmd 'CMD {producers} {stakes} {out}' (the genesis builder's
#                 validator-set fill; must write {out}/fill-result.json, see
#                 scripts/ops/r1006/render_profile.py) · --stake-salt N (32000) · --liquid-salt N (100)
#   distribute:   --mining on|off (on: the validator set is in the genesis)
#   start:        --gate-minutes N (10) · --min-peers N (hosts-1) · --skip-producing-gate
#   smoke:        --skip CHECK[,CHECK] (orangeseed, admins, code, logs) printed as SKIP, never PASS
#   wipe:         --wipe-keys (destroys noise.key, proposer.key and the staker keystore)
#
# Env: R1006_SSH_KEY (inventory ssh_key) · CAST, FORGE (cast, forge) · R1006_TUNNEL_BASE (18545)
#
# Exit: 0 ok · 1 a gate failed · 2 usage or refused
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
AGENT="$HERE/r1006/host_agent.sh"
PY="$HERE/r1006"
CAST="${CAST:-cast}"
FORGE="${FORGE:-forge}"
TUNNEL_BASE="${R1006_TUNNEL_BASE:-18545}"

INVENTORY="$HERE/r1006/inventory.r1006.json"
STATE="./r1006-state"
DRY=0
ONLY=""
SHA=""
LOCAL_REPO=""
ALLOW_NON_MAIN=0
FILL_CMD=""
STAKE_SALT=32000
LIQUID_SALT=100
MINING=on
GATE_MIN=10
MIN_PEERS=""
SKIP_PRODUCING=0
SKIPS=""
WIPE_KEYS=0

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
    --mining) MINING="$2"; shift 2 ;;
    --gate-minutes) GATE_MIN="$2"; shift 2 ;;
    --min-peers) MIN_PEERS="$2"; shift 2 ;;
    --skip-producing-gate) SKIP_PRODUCING=1; shift ;;
    --skip) SKIPS="$2"; shift 2 ;;
    --wipe-keys) WIPE_KEYS=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[[ -f "$INVENTORY" ]] || die "no inventory at $INVENTORY"
mkdir -p "$STATE"
STATE="$(cd "$STATE" && pwd)"
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
host_field() { inv "[h for h in d[\"hosts\"] if h[\"name\"]==\"$1\"][0].get(\"$2\",\"\")"; }
host_index() { local i=0; for h in "${ALL_HOSTS[@]}"; do [[ "$h" == "$1" ]] && { echo "$i"; return; }; i=$((i + 1)); done; die "unknown host $1"; }

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new)
[[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")

# ---- transport ---------------------------------------------------------------
# agent HOST CMD ARGS...: run host_agent.sh CMD on HOST (as root).
agent() {
  local h="$1"
  shift
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] $h: host_agent.sh $*"
    return 0
  fi
  if [[ "$TRANSPORT" == ssh ]]; then
    local q
    q=$(printf '%q ' "$@")
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$(host_field "$h" ip)" "bash -s -- $q" <"$AGENT"
  else
    local pid root
    pid=$(host_field "$h" netns_pid)
    root=$(host_field "$h" root)
    local ns=()
    [[ -n "$pid" ]] && ns=(nsenter --net="/proc/$pid/ns/net")
    "${ns[@]}" env R1006_ROOT="$root" R1006_SERVICE=proc R1006_RUN_AS= \
      R1006_NODE_ENV_PASSTHRU="${R1006_NODE_ENV_PASSTHRU:-}" bash -s -- "$@" <"$AGENT"
  fi
}

# put HOST LOCAL_FILE NAME: stage a file as usr/local/lib/citrate-r1006/<NAME> on HOST.
put() {
  local h="$1" src="$2" name="$3"
  local dest="/usr/local/lib/citrate-r1006/$name"
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] $h: copy $src -> $dest"
    return 0
  fi
  if [[ "$TRANSPORT" == ssh ]]; then
    local ip
    ip=$(host_field "$h" ip)
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
    echo "  [dry-run] tunnel 127.0.0.1:$port -> $h 127.0.0.1:8545"
    return 0
  fi
  mkdir -p "$STATE/tunnels"
  if [[ "$TRANSPORT" == ssh ]]; then
    local sock="$STATE/tunnels/$h.sock"
    if [[ -S "$sock" ]] && ssh -S "$sock" -O check x 2>/dev/null; then return 0; fi
    ssh "${SSH_OPTS[@]}" -M -S "$sock" -f -N -o ExitOnForwardFailure=yes \
      -L "127.0.0.1:$port:127.0.0.1:8545" "$SSH_USER@$(host_field "$h" ip)"
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
echo "FINGERPRINT=$(RUST_LOG=error "$B" consensus --json | python3 -c 'import json,sys; l=sys.stdin.read().splitlines(); print(json.loads("\n".join(l[l.index("{"):]))["fingerprint"])')"
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
    local bip
    bip=$(inv 'd["build_host"]["ip"]')
    where="$(inv 'd["build_host"]["name"]') ($bip)"
    if [[ $DRY -eq 1 ]]; then
      echo "  [dry-run] ssh $SSH_USER@$bip: clone https://github.com/CitrateNetwork/citrate-chain into mktemp /root/r1006-build.*,"
      echo "            checkout $SHA (must be on origin/main), cargo build --release --locked -p citrate-node --bin citrate,"
      echo "            sha256 + consensus fingerprint, copy back to $STATE/bin/citrate-node, delete the temp dir"
      return 0
    fi
    out=$(ssh "${SSH_OPTS[@]}" "$SSH_USER@$bip" "bash -s -- $SHA https://github.com/CitrateNetwork/citrate-chain $ALLOW_NON_MAIN /root" <<<"$script")
  fi
  local dir sha fp arch
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
  python3 - "$BUILD_JSON" "$SHA" "$sha" "$fp" "$arch" "$where" "$ALLOW_NON_MAIN" <<'PY'
import json, sys, datetime
p, sha, s256, fp, arch, where, nm = sys.argv[1:]
json.dump({"sha": sha, "sha256": s256, "fingerprint": fp, "arch": arch, "built_on": where,
           "from_main": nm != "1",
           "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
          open(p, "w"), indent=2)
PY
  log "built $SHA on $where: sha256 $sha fingerprint $fp arch $arch"
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
}

# ---- keys --------------------------------------------------------------------
step_keys() {
  need_build
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
    # The agent prints exactly the public file. It is validated before it is kept.
    agent "$h" keys "$s256" >"$STATE/pub/$h.pub.json.part"
    mv -f -- "$STATE/pub/$h.pub.json.part" "$STATE/pub/$h.pub.json"
  done
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] collect.py -> $STATE/r1006-producers.json"
    return 0
  fi
  python3 "$PY/collect.py" --inventory "$INVENTORY" --pub-dir "$STATE/pub" --out "$STATE/r1006-producers.json"
}

# ---- genesis-fill --------------------------------------------------------------
step_genesis_fill() {
  local prod="$STATE/r1006-producers.json" stakes="$STATE/r1006-stakes.json" out="$STATE/genesis"
  [[ -f "$prod" || $DRY -eq 1 ]] || die "no $prod; run keys first"
  [[ -n "$FILL_CMD" ]] || die "genesis-fill needs --fill-cmd (the genesis builder's validator-set fill)"
  if [[ $DRY -eq 1 ]]; then
    echo "  [dry-run] render_profile.py stakes ($STAKE_SALT SALT bonded + $LIQUID_SALT SALT liquid per staker) -> $stakes"
    echo "  [dry-run] $FILL_CMD   with {producers}=$prod {stakes}=$stakes {out}=$out"
    echo "  [dry-run] render_profile.py check-fill: the fill lists exactly these validators and stakes"
    return 0
  fi
  python3 "$PY/render_profile.py" stakes --producers "$prod" --stake-salt "$STAKE_SALT" --liquid-salt "$LIQUID_SALT" --out "$stakes"
  mkdir -p "$out"
  local cmd="$FILL_CMD"
  cmd=${cmd//\{producers\}/$(printf '%q' "$prod")}
  cmd=${cmd//\{stakes\}/$(printf '%q' "$stakes")}
  cmd=${cmd//\{out\}/$(printf '%q' "$out")}
  log "genesis-fill: $cmd"
  (cd "$REPO" && bash -c "$cmd")
  [[ -f "$out/fill-result.json" ]] || gate_fail "the fill command wrote no $out/fill-result.json"
  python3 "$PY/render_profile.py" check-fill --producers "$prod" --stakes "$stakes" --fill "$out/fill-result.json" ||
    gate_fail "the genesis fill does not match the producer set"
  log "genesis: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["genesis_hash"], "profile", d.get("genesis_profile"), "registry", d["validator_registry"])' "$out/fill-result.json")"
}

fill_field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$STATE/genesis/fill-result.json" "$1"; }

# ---- distribute ---------------------------------------------------------------
step_distribute() {
  need_build
  local fill="$STATE/genesis/fill-result.json"
  [[ -f "$fill" || $DRY -eq 1 ]] || die "no $fill; run genesis-fill first"
  [[ "$MINING" == on || "$MINING" == off ]] || die "--mining on|off"
  local s256 gh gfile gsha=""
  s256=$(build_field sha256)
  log "distribute: binary $(build_field sha) sha256 $s256"
  if [[ $DRY -eq 0 ]]; then
    gh=$(fill_field genesis_hash)
    gfile=$(fill_field genesis_file)
    if [[ -n "$gfile" ]]; then gsha=$(sha256sum "$STATE/genesis/$gfile" | cut -d' ' -f1); fi
  else
    gh="<genesis hash from fill-result.json>"
    gfile=""
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
    if [[ -n "$gfile" ]]; then
      put "$h" "$STATE/genesis/$gfile" incoming/genesis.json
      agent "$h" install-genesis "$gsha"
    fi
    put "$h" "$REPO/scripts/producers/gen_node_config.py" tools/gen_node_config.py
    put "$h" "$REPO/scripts/producers/producerlib.py" tools/producerlib.py
    put "$h" "$STATE/profiles/$h.json" profile.json
    local staker="<staker of $h>"
    [[ $DRY -eq 0 ]] && staker=$(python3 -c 'import json,sys; print([p for p in json.load(open(sys.argv[1]))["producers"] if p["name"]==sys.argv[2]][0]["staker_address"])' "$STATE/r1006-producers.json" "$h")
    agent "$h" write-config "$staker" "$MINING"
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

step_start() {
  local n=${#HOSTS[@]} gh
  [[ -z "$MIN_PEERS" ]] && MIN_PEERS=$((${#ALL_HOSTS[@]} - 1))
  if [[ $DRY -eq 1 ]]; then
    gh="<fill genesis_hash>"
  else
    gh=$(fill_field genesis_hash)
  fi
  local first=1
  for h in "${HOSTS[@]}"; do
    log "start: $h"
    agent "$h" start
    tunnel_up "$h"
    if [[ $DRY -eq 1 ]]; then
      echo "  [dry-run] gate: $h RPC answers within 120 s and block 0 == $gh${first:+ (the first node starts ALONE)}"
      first=""
      continue
    fi
    wait_until 120 "$h RPC answers" node_answers "$h" || { agent "$h" stop; gate_fail "$h RPC did not answer in 120 s (stopped it)"; }
    if ! block0_is "$h" "$gh"; then
      log "  $h block 0 differs from $gh: stopping every started node"
      for s in "${HOSTS[@]}"; do agent "$s" stop || true; [[ "$s" == "$h" ]] && break; done
      gate_fail "$h block 0 is not the r1006 genesis $gh"
    fi
    log "  ok: $h block 0 = $gh"
  done
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
    echo "  [dry-run] fleet_agree.sh over the ${#HOSTS[@]} tunnels, EXPECTED_GENESIS_HASH = fill genesis_hash"
    echo "  [dry-run] eth_chainId == 40204 on every host"
    echo "  [dry-run] eth_getCode(addr) == alloc[addr].code for every coded alloc entry (fill alloc_file), on every host"
    echo "  [dry-run] OrangeSeed (fill orangeseed): story() returns a non-empty string"
    echo "  [dry-run] CheckDeployedAdmins.s.sol over the fill address_book: DEPLOYER-ADMIN failures: 0"
    echo "  [dry-run] host_agent logs-scan: no CONFLICT / fork line since start, every host"
    echo "  [dry-run] finality: eth_getBlockByNumber(finalized) answers (switch OFF: expect block 0)"
    echo "  [dry-run] memory: node RSS < 3 GiB on every host (runbook alert line)"
    return 0
  fi
  local gh urls=()
  gh=$(fill_field genesis_hash)
  for h in "${HOSTS[@]}"; do tunnel_up "$h"; urls+=("$(rpc_url "$h")"); done

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

  # 5. DEPLOYER-ADMIN 0 (the ceremony's P5 checker over the genesis book)
  local book
  book=$(fill_field address_book)
  if skipped admins; then
    log "SKIP  DEPLOYER-ADMIN (--skip admins)"
  elif [[ -z "$book" || ! -f "$REPO/contracts/script/CheckDeployedAdmins.s.sol" ]]; then
    fail "no address book in the fill result, or no CheckDeployedAdmins.s.sol in this checkout"
  else
    local report da
    report=$(cd "$REPO/contracts" && ADDRESS_BOOK="$STATE/genesis/$book" REQUIRE_ALL_CODE=true \
      "$FORGE" script script/CheckDeployedAdmins.s.sol --rpc-url "${urls[0]}" 2>&1 || true)
    da=$(printf '%s\n' "$report" | sed -nE 's/.*DEPLOYER-ADMIN failures:[[:space:]]*([0-9]+)[[:space:]]*$/\1/p')
    if [[ $(printf '%s' "$da" | grep -c .) -eq 1 && "$da" == 0 ]]; then pass "DEPLOYER-ADMIN 0"
    else printf '%s\n' "$report" | tail -15 | sed 's/^/  | /'; fail "DEPLOYER-ADMIN is not a single 0"; fi
  fi

  # 6. logs: no CONFLICT / fork
  local since
  since=$(python3 -c 'import os,sys; print(int(os.path.getmtime(sys.argv[1])))' "$STATE/r1006-producers.json")
  if skipped logs; then
    log "SKIP  log scan (--skip logs)"
  else
    bad=0
    for h in "${HOSTS[@]}"; do
      local scan
      scan=$(agent "$h" logs-scan "$since")
      if [[ "$(sed -n 's/^matches //p' <<<"$scan")" != 0 ]]; then bad=1; log "  $h:"; sed -n '/^  |/p' <<<"$scan"; fi
    done
    [[ $bad -eq 0 ]] && pass "no CONFLICT / fork lines in any node log" || fail "CONFLICT / fork lines in node logs"
  fi

  # 7. finality status
  local fin
  fin=$(rpc "${HOSTS[0]}" eth_getBlockByNumber '["finalized",false]' | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["number"],16))' 2>/dev/null || true)
  if [[ -n "$fin" ]]; then pass "finality: finalized block $fin (checkpoint finality switch OFF on 40204: 0 expected)"
  else fail "finality: eth_getBlockByNumber(finalized) did not answer"; fi

  # 8. memory
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
