#!/usr/bin/env bash
# host_agent.sh: the per-host half of scripts/ops/r1006_bringup.sh. Runs as root ON a
# producer host, streamed over ssh (`ssh root@HOST 'bash -s -- CMD ARGS' < host_agent.sh`),
# the same way scripts/ops/producer_baseline.sh is run. Every command is idempotent.
#
# Layout (docs/ops/PRODUCER_OPERATOR_RUNBOOK.md §2, producer_baseline.sh):
#   $R1006_ROOT/etc/citrate                 node.toml, citrate-node.env, citrate-node.service
#   $R1006_ROOT/etc/citrate/r1006           (0700, citrate) staker keystore + password,
#                                           identity.pub.json (the ONLY file read back),
#                                           genesis.json when the genesis is a file, DEPLOYED
#   $R1006_ROOT/var/lib/citrate/data        (0700, citrate) noise.key, proposer.key, chain db
#   $R1006_ROOT/usr/local/bin/citrate-node  the release binary
#   $R1006_ROOT/usr/local/lib/citrate-r1006 keytool, incoming/, tools/ (gen_node_config.py), profile.json
# R1006_ROOT is empty on a real host. The local devnet rehearsal sets it to a per-host dir.
#
# Commands
#   keys SHA256                mint the host identity (if missing) with the staged keytool
#                              as the citrate user; prints nothing secret; then `pub`
#   pub                        cat identity.pub.json, and nothing else
#   install-bin SHA256         incoming/citrate-node -> /usr/local/bin/citrate-node (hash-checked)
#   install-genesis SHA256     incoming/genesis.json -> etc/citrate/r1006/genesis.json (hash-checked)
#   write-config STAKER MINING gen_node_config.py with the staged per-host profile
#   start | stop | status      the node service (systemd, or a plain process when R1006_SERVICE=proc)
#   logs-scan SINCE_EPOCH      count CONFLICT / fork lines in the node log since a unix time
#   wipe [--wipe-keys]         stopped node only: delete the r1006 chain data, keep the keys
#                              (with --wipe-keys, the keys and keystore too)
#   sha FILE                   sha256 of a staged file (for the orchestrator's checks)
#   probe-genesis HASH         start the installed binary + config in an ISOLATED network
#                              namespace (loopback only), with a throwaway data dir and
#                              mining off; read block 0; compare; delete the throwaway dir
#   tcp-check IP PORT          can this host open a TCP connection to IP:PORT
#
# Env: R1006_ROOT ("") · R1006_SERVICE (systemd|proc) · R1006_RUN_AS (citrate; "" = no switch)
#      R1006_NODE_ENV_PASSTHRU (proc mode only)
set -euo pipefail

ROOT="${R1006_ROOT:-}"
SERVICE="${R1006_SERVICE:-systemd}"
RUN_AS="${R1006_RUN_AS-citrate}"
ETC="$ROOT/etc/citrate"
RDIR="$ETC/r1006"
DATA="$ROOT/var/lib/citrate/data"
BIN="$ROOT/usr/local/bin/citrate-node"
LIB="$ROOT/usr/local/lib/citrate-r1006"
PUB="$RDIR/identity.pub.json"
KEYSTORE="$RDIR/staker.keystore.json"
PASSWORD="$RDIR/staker.password"
MARKER="$RDIR/DEPLOYED"
LOGFILE="$ROOT/var/log/citrate-node.log"
PIDFILE="$ROOT/run/citrate-node.pid"
# The only files `wipe` (without --wipe-keys) keeps in the data dir.
KEEP_IN_DATA=(noise.key proposer.key)

die() { echo "host_agent: $*" >&2; exit 2; }
say() { echo "$*"; }

as_node_user() {
  if [[ -n "$RUN_AS" ]]; then runuser -u "$RUN_AS" -- "$@"; else "$@"; fi
}

own() { # path mode: owned by the node user (when there is one) with this mode
  if [[ -n "$RUN_AS" ]]; then chown "$RUN_AS:$RUN_AS" "$1"; fi
  chmod "$2" "$1"
}

sha_of() { sha256sum -- "$1" | cut -d' ' -f1; }

need_sha() {
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]] || die "expected a sha256 (64 lowercase hex), got '${1:-}'"
}

ensure_layout() {
  if [[ -n "$RUN_AS" ]] && ! id -u "$RUN_AS" >/dev/null 2>&1; then
    die "user $RUN_AS does not exist (run scripts/ops/producer_baseline.sh apply first)"
  fi
  mkdir -p "$ETC" "$LIB/incoming" "$LIB/tools" "$(dirname "$BIN")" "$(dirname "$LOGFILE")" "$(dirname "$PIDFILE")"
  [[ -d "$DATA" ]] || mkdir -p "$DATA"
  own "$DATA" 0700
  [[ -d "$RDIR" ]] || mkdir -p "$RDIR"
  own "$RDIR" 0700
}

node_pid() { # pid of the running node (proc mode), or nothing
  [[ -f "$PIDFILE" ]] || return 0
  local p
  p=$(cat "$PIDFILE")
  if [[ "$p" =~ ^[0-9]+$ ]] && kill -0 "$p" 2>/dev/null; then printf '%s' "$p"; fi
}

is_running() {
  if [[ "$SERVICE" == systemd ]]; then
    systemctl is-active --quiet citrate-node
  else
    [[ -n "$(node_pid)" ]]
  fi
}

cmd_keys() {
  need_sha "${1:-}"
  ensure_layout
  local tool="$LIB/citrate-keytool"
  [[ -f "$tool" ]] || die "keytool not staged at $tool"
  [[ "$(sha_of "$tool")" == "$1" ]] || die "keytool sha256 differs from the build record"
  chmod 0755 "$tool"
  # stdout is the public identity, which `pub` prints next; drop it here so this
  # command's output is exactly one copy of the public file.
  as_node_user "$tool" host-identity \
    --identity-dir "$DATA" --staker-keystore "$KEYSTORE" --staker-password-file "$PASSWORD" \
    --mint --out "$PUB" >/dev/null
  chmod 0644 "$PUB"
  cmd_pub
}

cmd_pub() {
  [[ -f "$PUB" ]] || die "no public identity at $PUB (run keys first)"
  cat -- "$PUB"
}

install_staged() { # incoming-name dest sha mode
  local src="$LIB/incoming/$1" dest="$2" want="$3" mode="$4"
  if [[ -f "$dest" && "$(sha_of "$dest")" == "$want" ]]; then
    say "unchanged $dest ($want)"
    return 0
  fi
  [[ -f "$src" ]] || die "$src not staged"
  [[ "$(sha_of "$src")" == "$want" ]] || die "staged $1 sha256 $(sha_of "$src") is not $want"
  local tmp
  tmp=$(mktemp "$(dirname "$dest")/.r1006.new.XXXXXX")
  install -m "$mode" -- "$src" "$tmp"
  [[ "$(sha_of "$tmp")" == "$want" ]] || { rm -f -- "$tmp"; die "copy of $1 changed in transit"; }
  if [[ -f "$dest" ]]; then ln -f -- "$dest" "$dest.prev"; fi
  mv -f -- "$tmp" "$dest"
  say "installed $dest ($want)"
}

cmd_install_bin() {
  need_sha "${1:-}"
  ensure_layout
  if is_running; then die "the node is running; stop it before replacing the binary"; fi
  install_staged citrate-node "$BIN" "$1" 0755
}

cmd_install_genesis() {
  need_sha "${1:-}"
  ensure_layout
  install_staged genesis.json "$RDIR/genesis.json" "$1" 0644
  own "$RDIR/genesis.json" 0644
}

cmd_write_config() {
  local staker="${1:-}" mining="${2:-}"
  [[ "$staker" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "write-config needs the staker address"
  [[ "$mining" == on || "$mining" == off ]] || die "write-config needs mining on|off"
  ensure_layout
  [[ -f "$LIB/profile.json" && -f "$LIB/tools/gen_node_config.py" ]] || die "profile/tools not staged"
  # The staker in the config must be this host's own minted staker.
  local mine
  mine=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["staker_address"])' "$PUB")
  [[ "${mine,,}" == "${staker,,}" ]] || die "staker $staker is not this host's ($mine)"
  python3 "$LIB/tools/gen_node_config.py" --profile "$LIB/profile.json" --staker "$staker" \
    --out-dir "$ETC" --data-dir "$DATA" --binary "$BIN" --mining "$mining" --force
  if [[ "$SERVICE" == systemd ]]; then
    if ! cmp -s "$ETC/citrate-node.service" /etc/systemd/system/citrate-node.service; then
      install -m 0644 "$ETC/citrate-node.service" /etc/systemd/system/citrate-node.service
      systemctl daemon-reload
    fi
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ >"$MARKER"
}

cmd_start() {
  [[ -f "$MARKER" && -x "$BIN" && -f "$ETC/node.toml" ]] || die "not distributed (no marker, binary or node.toml)"
  if is_running; then
    say "already running"
    return 0
  fi
  if [[ "$SERVICE" == systemd ]]; then
    systemctl enable --now citrate-node
  else
    local envs=()
    while IFS='=' read -r k v; do
      [[ "$k" =~ ^CITRATE_[A-Z0-9_]+$ ]] && envs+=("$k=$v")
    done <"$ETC/citrate-node.env"
    # shellcheck disable=SC2206
    local extra=(${R1006_NODE_ENV_PASSTHRU:-})
    (
      cd "$DATA"
      env "${envs[@]}" "${extra[@]}" setsid "$BIN" --config "$ETC/node.toml" >>"$LOGFILE" 2>&1 &
      echo $! >"$PIDFILE"
    )
  fi
  say "started"
}

cmd_stop() {
  if [[ "$SERVICE" == systemd ]]; then
    # A watchdog would restart a stopped node; pause it first where one is installed.
    if command -v citrate-watchdog-ctl.sh >/dev/null && systemctl is-enabled --quiet citrate-height-watchdog.timer 2>/dev/null; then
      citrate-watchdog-ctl.sh pause 12 "r1006 bring-up stop"
    fi
    if systemctl is-active --quiet citrate-node; then systemctl stop citrate-node; fi
    systemctl is-active --quiet citrate-node && die "citrate-node still active"
  else
    local p
    p=$(node_pid)
    if [[ -n "$p" ]]; then
      kill "$p"
      for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 0.5; done
      if kill -0 "$p" 2>/dev/null; then kill -9 "$p"; fi
    fi
    rm -f -- "$PIDFILE"
  fi
  say "stopped"
}

cmd_status() {
  local active=false pid="" rss_kb=0
  if [[ "$SERVICE" == systemd ]]; then
    systemctl is-active --quiet citrate-node && active=true
    pid=$(systemctl show -p MainPID --value citrate-node 2>/dev/null || true)
    [[ "$pid" == 0 ]] && pid=""
  else
    pid=$(node_pid)
    [[ -n "$pid" ]] && active=true
  fi
  if [[ -n "$pid" && -r "/proc/$pid/status" ]]; then
    rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
  fi
  local mem_total_kb
  mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  local disk
  disk=$(df -P -- "$DATA" | awk 'NR==2 {print $5}')
  printf '{"active": %s, "pid": "%s", "rss_kb": %s, "mem_total_kb": %s, "data_disk_used": "%s", "distributed": %s}\n' \
    "$active" "$pid" "${rss_kb:-0}" "$mem_total_kb" "$disk" "$([[ -f "$MARKER" ]] && echo true || echo false)"
}

cmd_logs_scan() {
  local since="${1:-}"
  [[ "$since" =~ ^[0-9]+$ ]] || die "logs-scan needs a unix time"
  local text
  if [[ "$SERVICE" == systemd ]]; then
    text=$(journalctl -u citrate-node --since "@$since" --no-pager -o cat 2>/dev/null || true)
  else
    text=$(cat -- "$LOGFILE" 2>/dev/null || true)
  fi
  local hits
  hits=$(printf '%s\n' "$text" | grep -E -i '(^|[^a-z])(conflict|fork)([^a-z]|$)' || true)
  printf 'lines %s\nmatches %s\n' "$(printf '%s\n' "$text" | grep -c . || true)" "$(printf '%s' "$hits" | grep -c . || true)"
  printf '%s\n' "$hits" | head -5 | sed 's/^/  | /'
}

cmd_wipe() {
  local wipe_keys=0
  [[ "${1:-}" == --wipe-keys ]] && wipe_keys=1
  if is_running; then die "the node is running; stop it first"; fi
  [[ -f "$MARKER" ]] || die "no r1006 marker at $MARKER: this host was not set up by the r1006 bring-up; refusing"
  [[ -d "$DATA" ]] || { say "no data dir"; return 0; }
  [[ "$DATA" == */var/lib/citrate/data ]] || die "refusing to wipe unexpected path $DATA"
  local n=0 e base keep
  shopt -s dotglob nullglob
  for e in "$DATA"/*; do
    base=${e##*/}
    keep=0
    if [[ $wipe_keys -eq 0 ]]; then
      for k in "${KEEP_IN_DATA[@]}"; do [[ "$base" == "$k" ]] && keep=1; done
    fi
    [[ $keep -eq 1 ]] && continue
    rm -rf -- "${e:?}"
    n=$((n + 1))
  done
  shopt -u dotglob nullglob
  if [[ $wipe_keys -eq 1 ]]; then
    rm -f -- "$KEYSTORE" "$PASSWORD" "$PUB"
    say "wiped $n entries in $DATA INCLUDING noise.key/proposer.key, and the staker keystore"
  else
    say "wiped $n entries in $DATA; kept ${KEEP_IN_DATA[*]} and the staker keystore"
  fi
  rm -f -- "$RDIR/genesis.json" "$LOGFILE"
}

cmd_sha() {
  local f="$LIB/incoming/${1:-}"
  [[ "${1:-}" =~ ^[A-Za-z0-9._-]+$ && -f "$f" ]] || die "no staged file ${1:-}"
  sha_of "$f"
}

cmd_probe_genesis() {
  local want="${1:-}"
  [[ "$want" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "probe-genesis needs the expected block-0 hash"
  [[ -x "$BIN" && -f "$ETC/node.toml" ]] || die "not distributed"
  mkdir -p "$ROOT/var/tmp"
  local t
  t=$(mktemp -d "$ROOT/var/tmp/r1006-probe.XXXXXX")
  [[ -n "$RUN_AS" ]] && chown "$RUN_AS:$RUN_AS" "$t"
  python3 - "$ETC/node.toml" "$t" <<'PY'
import re, sys
src, t = sys.argv[1], sys.argv[2]
out, sec = [], ""
for line in open(src):
    m = re.match(r"^\[(\w+)\]", line)
    if m:
        sec = m.group(1)
    if sec == "storage" and line.startswith("data_dir ="):
        line = f'data_dir = "{t}/data"\n'
    if sec == "mining" and line.startswith("enabled ="):
        line = "enabled = false\n"
    out.append(line)
open(f"{t}/node.toml", "w").write("".join(out))
PY
  local envs=()
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^CITRATE_[A-Z0-9_]+$ && "$k" != CITRATE_METRICS ]] && envs+=("$k=$v")
  done <"$ETC/citrate-node.env"
  local runas=""
  [[ -n "$RUN_AS" ]] && runas="runuser -u $RUN_AS --"
  local got
  got=$(unshare --net sh -c '
    ip link set lo up 2>/dev/null || true
    t="$1"; bin="$2"; shift 2
    env "$@" '"$runas"' "$bin" --config "$t/node.toml" >"$t/probe.log" 2>&1 &
    pid=$!
    h=""
    i=0
    while [ $i -lt 180 ]; do
      h=$(curl -s -m 2 -H "content-type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x0\",false]}" \
        http://127.0.0.1:8545 | python3 -c "import json,sys; print(json.load(sys.stdin)[\"result\"][\"hash\"])" 2>/dev/null) && [ -n "$h" ] && break
      i=$((i+1)); sleep 0.5
    done
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    printf "%s" "$h"
  ' probe "$t" "$BIN" "${envs[@]}") || true
  if [[ -z "$got" ]]; then
    tail -5 "$t/probe.log" | sed 's/^/  probe| /' >&2
  fi
  [[ "$t" == "$ROOT"/var/tmp/r1006-probe.* ]] && rm -rf -- "${t:?}"
  if [[ -z "$got" ]]; then die "probe node never answered"; fi
  if [[ "${got,,}" != "${want,,}" ]]; then
    echo "PROBE FAIL block 0 $got, want $want"
    exit 1
  fi
  echo "PROBE OK block 0 $got"
}

cmd_tcp_check() {
  local ip="${1:-}" port="${2:-}"
  [[ "$ip" =~ ^[0-9.]+$ && "$port" =~ ^[0-9]+$ ]] || die "tcp-check IP PORT"
  if timeout 3 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then echo "open $ip:$port"; else echo "closed $ip:$port"; return 1; fi
}

c="${1:-}"
shift || true
case "$c" in
  keys) cmd_keys "$@" ;;
  pub) cmd_pub ;;
  install-bin) cmd_install_bin "$@" ;;
  install-genesis) cmd_install_genesis "$@" ;;
  write-config) cmd_write_config "$@" ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  logs-scan) cmd_logs_scan "$@" ;;
  wipe) cmd_wipe "$@" ;;
  sha) cmd_sha "$@" ;;
  probe-genesis) cmd_probe_genesis "$@" ;;
  tcp-check) cmd_tcp_check "$@" ;;
  *) die "unknown command '$c'" ;;
esac
