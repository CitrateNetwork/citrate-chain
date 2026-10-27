#!/usr/bin/env bash
# host_agent.sh: the per-host half of scripts/ops/r1006_bringup.sh. Runs as root ON a
# producer host, streamed over ssh (`ssh root@HOST 'bash -s -- CMD ARGS' < host_agent.sh`),
# the same way scripts/ops/producer_baseline.sh is run. Every command is idempotent.
#
# Layout (docs/ops/PRODUCER_OPERATOR_RUNBOOK.md §2, producer_baseline.sh):
#   $R1006_ROOT/etc/citrate                 node.toml, citrate-node.env, citrate-node.service
#   $R1006_ROOT/etc/citrate/r1006           (0700, citrate) staker keystore + password,
#                                           identity.pub.json (the ONLY file read back),
#                                           keytool.log (0600), DEPLOYED, PROBED
#   $R1006_ROOT/var/lib/citrate/data        (0700, citrate) noise.key, proposer.key, chain db
#   $R1006_ROOT/usr/local/bin/citrate-node  the release binary
#   $R1006_ROOT/usr/local/lib/citrate-r1006 keytool, incoming/, tools/ (gen_node_config.py), profile.json
# R1006_ROOT is empty on a real host. The local devnet rehearsal sets it to a per-host dir.
#
# Output containment: every command runs with stdout and stderr held on the host. They
# are released only if neither contains this host's own key material (the bytes of
# noise.key, proposer.key, the staker keystore or its password, raw, hex or base64);
# otherwise both are dropped and the command exits 3. Hashes are shortened on stderr.
#
# Genesis: a release network's block 0 (r1005 testnet, team testnet, mainnet; mirror of
# core/consensus/src/hardening.rs RELEASE_GENESIS) is refused by write-config,
# probe-genesis, start and enable-mining, and the profile must select the compiled
# `r1006` genesis.
#
# Commands
#   keys SHA256                mint the host identity (if missing) with the staged keytool
#                              as the citrate user (its stderr goes to a 0600 log on the
#                              host, never over ssh); then `pub`
#   pub                        the public identity, re-serialised from the checked fields
#                              of identity.pub.json (anything else in the file is refused)
#   registration-proof REGISTRY  the staged keytool's `registration-proof --registry REGISTRY`
#                              (chain 40204, this host's staker, nonce 0), run as the citrate
#                              user against a throwaway config naming only the data dir and
#                              coinbase; its stderr goes to the 0600 keytool log; the proof is
#                              checked and re-serialised here (public fields only)
#   install-bin SHA256         incoming/citrate-node -> /usr/local/bin/citrate-node (hash-checked)
#   write-config STAKER MINING gen_node_config.py with the staged per-host profile
#   start HASH                 start the node with mining OFF; HASH must be the block 0
#                              probe-genesis recorded for the installed binary + config
#   enable-mining HASH         the running node's own block 0 (local RPC) must be HASH;
#                              then the config is regenerated with mining on and the node
#                              restarted
#   stop | status              the node service (systemd, or a plain process when R1006_SERVICE=proc)
#   logs-scan SINCE_EPOCH      count CONFLICT / fork lines in the node log since a unix time
#   wipe [--wipe-keys]         stopped node only: delete the r1006 chain data, keep the keys
#                              (with --wipe-keys, the keys and keystore too)
#   sha FILE                   sha256 of a staged file (for the orchestrator's checks)
#   build-rev                  the installed binary's build stamp (`consensus --json`):
#                              "<git_sha> <git_dirty>", for the MIN_CHAIN_REV pre-join check
#   probe-genesis HASH         start the installed binary + config in an ISOLATED network
#                              namespace (loopback only), with a throwaway data dir and
#                              mining off; read block 0; compare; delete the throwaway dir;
#                              on a match record HASH in etc/citrate/r1006/PROBED
#   tcp-check IP PORT          can this host open a TCP connection to IP:PORT
#   config-check               the node's config must configure no contribution recorder
#                              (a configured one sends a heartbeat transaction to the zero
#                              address every 100 blocks); prints the offending lines
#
# Env: R1006_ROOT ("") · R1006_SERVICE (systemd|proc) · R1006_RUN_AS (citrate; "" = no switch)
#      R1006_NODE_ENV_PASSTHRU (proc mode only) · R1006_NODE_RPC (http://127.0.0.1:8545)
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
PROBED="$RDIR/PROBED"
KEYTOOL_LOG="$RDIR/keytool.log"
NODE_RPC="${R1006_NODE_RPC:-http://127.0.0.1:8545}"
R1006_PROFILE=r1006
# Mirror of core/consensus/src/hardening.rs RELEASE_GENESIS (a test keeps them equal).
RELEASE_GENESIS_HASHES=(0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1 0x90044175c36a6491309d769bd0fa684afbf7b90b64136446db8e2e6ff0927553 0xba93d716ab8b005f1d7e61d369a65fc1d6a358d6a479e11b640815c74388ab01)
LOGFILE="$ROOT/var/log/citrate-node.log"
PIDFILE="$ROOT/run/citrate-node.pid"
# The only files `wipe` (without --wipe-keys) keeps in the data dir.
KEEP_IN_DATA=(noise.key proposer.key)

die() { echo "host_agent: $*" >&2; exit 2; }
say() { echo "$*"; }
short() { local v="${1:-}"; if ((${#v} > 18)); then printf '%s…' "${v:0:14}"; else printf '%s' "$v"; fi; }

# need_r1006_hash HASH: a 32-byte block hash that is not a release network's genesis.
need_r1006_hash() {
  local h="${1,,}"
  [[ "$h" =~ ^0x[0-9a-f]{64}$ ]] || die "expected a block-0 hash (0x + 64 hex), got '$(short "${1:-}")'"
  local r
  for r in "${RELEASE_GENESIS_HASHES[@]}"; do
    [[ "$h" == "$r" ]] && die "block 0 $(short "$h") is a release network's genesis (r1005 testnet, team testnet or mainnet); refusing"
  done
  return 0
}

# The strict public-identity check, run on the host: exactly the public fields, each in
# its public form, re-serialised. Nothing else in the file is ever printed.
PUB_CHECK='
import json, re, sys
F = {"schema": r"^citrate-host-identity/1$", "peer_id": r"^noise_[0-9a-f]{64}$",
     "noise_pubkey": r"^[0-9a-f]{64}$", "proposer_pubkey": r"^0x[0-9a-f]{64}$",
     "vrf_pubkey": r"^0x0[23][0-9a-f]{64}$", "staker_address": r"^0x[0-9a-f]{40}$",
     "coinbase_address": r"^0x[0-9a-f]{40}$"}
try:
    d = json.load(open(sys.argv[1]))
    ok = isinstance(d, dict) and set(d) == set(F) and all(
        isinstance(d[k], str) and re.match(rx, d[k]) for k, rx in F.items())
except Exception:
    ok = False
if not ok:
    sys.exit("host_agent: identity.pub.json is not exactly a public host identity; nothing sent")
print(json.dumps({k: d[k] for k in F}, indent=2))
'

# withhold_secrets OUT_FILE ERR_FILE: fail when either holds this host key material.
withhold_secrets() {
  python3 - "$1" "$2" "$DATA/noise.key" "$DATA/proposer.key" "$KEYSTORE" "$PASSWORD" <<'PY'
import base64, json, sys
out, err, *secrets = sys.argv[1:]
needles = set()
def add(b):
    if len(b) >= 8:
        needles.update({b, b.hex().encode(), b.hex().upper().encode(), base64.b64encode(b)})
for p in secrets:
    try:
        raw = open(p, "rb").read()
    except OSError:
        continue
    add(raw)
    add(raw.strip())
    try:
        ks = json.loads(raw)
        c = ks.get("crypto") or ks.get("Crypto") or {}
        for v in (c.get("ciphertext"), c.get("mac"), (c.get("kdfparams") or {}).get("salt"),
                  (c.get("cipherparams") or {}).get("iv")):
            if isinstance(v, str) and len(v) >= 16:
                needles.add(v.encode())
                needles.add(v.lower().encode())
    except (ValueError, AttributeError):
        pass
data = open(out, "rb").read() + b"\n" + open(err, "rb").read()
sys.exit(1 if any(n in data for n in needles) else 0)
PY
}

as_node_user() {
  if [[ -n "$RUN_AS" ]]; then runuser -u "$RUN_AS" -- "$@"; else "$@"; fi
}

own() { # path mode: owned by the node user (when there is one) with this mode
  if [[ -n "$RUN_AS" ]]; then chown "$RUN_AS:$RUN_AS" "$1"; fi
  chmod "$2" "$1"
}

sha_of() { sha256sum -- "$1" | cut -d' ' -f1; }

need_sha() {
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]] || die "expected a sha256 (64 lowercase hex), got '$(short "${1:-}")'"
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
  local rc=0
  (umask 077; : >>"$KEYTOOL_LOG")
  as_node_user "$tool" host-identity \
    --identity-dir "$DATA" --staker-keystore "$KEYSTORE" --staker-password-file "$PASSWORD" \
    --mint --out "$PUB" >/dev/null 2>>"$KEYTOOL_LOG" || rc=$?
  [[ $rc -eq 0 ]] || die "keytool failed (rc=$rc); its stderr stays on this host in $KEYTOOL_LOG"
  chmod 0644 "$PUB"
  cmd_pub
}

# The strict registration-proof check, run on the host: exactly the public fields, for
# this host's staker and proposer key, re-serialised.
PROOF_CHECK='
import json, re, sys
raw, pub, registry = sys.argv[1], json.load(open(sys.argv[2])), sys.argv[3]
F = ["schema", "chain_id", "registry", "staker", "proposer_pubkey", "registration_sig"]
try:
    d = json.loads(raw)
    ok = (isinstance(d, dict) and sorted(d) == sorted(F) and d["schema"] == "citrate-registration-proof/1"
          and d["chain_id"] == 40204 and d["registry"] == registry and d["staker"] == pub["staker_address"]
          and d["proposer_pubkey"] == pub["proposer_pubkey"]
          and isinstance(d["registration_sig"], str) and re.match(r"^0x[0-9a-f]{128}$", d["registration_sig"]))
except Exception:
    ok = False
if not ok:
    sys.exit("host_agent: the registration proof is not exactly the public proof for this host; nothing sent")
print(json.dumps({k: d[k] for k in F}, indent=2))
'

cmd_registration_proof() {
  local reg="${1:-}"
  [[ "$reg" =~ ^0x[0-9a-f]{40}$ ]] || die "registration-proof needs the ValidatorRegistry (0x + 40 lowercase hex)"
  ensure_layout
  local tool="$LIB/citrate-keytool"
  [[ -f "$tool" && -f "$PUB" ]] || die "no keytool or public identity (run keys first)"
  local staker t
  staker=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["staker_address"])' "$PUB")
  t=$(mktemp -d "${TMPDIR:-/tmp}/r1006-proof.XXXXXX")
  chmod 0700 "$t"
  [[ -n "$RUN_AS" ]] && chown "$RUN_AS:$RUN_AS" "$t"
  # A throwaway config: the proof reads only the chain id, the coinbase and the data dir.
  cat >"$t/node.toml" <<EOF
[chain]
chain_id = 40204
genesis_hash = ""
block_time = 2
ghostdag_k = 18

[network]
listen_addr = "127.0.0.1:30399"
bootstrap_nodes = []
max_peers = 4
allowed_peers = []

[rpc]
enabled = false
listen_addr = "127.0.0.1:8545"
ws_addr = "127.0.0.1:8546"
allow_eth_send_transaction = false

[storage]
data_dir = "$DATA"
pruning = false
keep_blocks = 100000

[mining]
enabled = false
coinbase = "${staker#0x}"
target_block_time = 2
min_gas_price = 1000000000
EOF
  [[ -n "$RUN_AS" ]] && chown "$RUN_AS:$RUN_AS" "$t/node.toml"
  local out proof_tool_rc=0
  (umask 077; : >>"$KEYTOOL_LOG")
  out=$(as_node_user "$tool" --config "$t/node.toml" registration-proof --registry "$reg" 2>>"$KEYTOOL_LOG") || proof_tool_rc=$?
  [[ "$t" == "${TMPDIR:-/tmp}"/r1006-proof.* ]] && rm -rf -- "${t:?}"
  [[ $proof_tool_rc -eq 0 ]] || die "registration-proof failed (rc=$proof_tool_rc); its stderr stays on this host in $KEYTOOL_LOG"
  python3 -c "$PROOF_CHECK" "$out" "$PUB" "$reg"
}

cmd_pub() {
  [[ -f "$PUB" ]] || die "no public identity at $PUB (run keys first)"
  python3 -c "$PUB_CHECK" "$PUB"
}

install_staged() { # incoming-name dest sha mode
  local src="$LIB/incoming/$1" dest="$2" want="$3" mode="$4"
  if [[ -f "$dest" && "$(sha_of "$dest")" == "$want" ]]; then
    say "unchanged $dest ($want)"
    return 0
  fi
  [[ -f "$src" ]] || die "$src not staged"
  [[ "$(sha_of "$src")" == "$want" ]] || die "staged $1 sha256 $(short "$(sha_of "$src")") is not $(short "$want")"
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

# The staged profile must select the compiled r1006 genesis, and not a release network's.
check_profile() {
  [[ -f "$LIB/profile.json" && -f "$LIB/tools/gen_node_config.py" ]] || die "profile/tools not staged"
  local gp gh
  gp=$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get("genesis_profile"); print("" if v is None else v)' "$LIB/profile.json")
  gh=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("genesis_hash",""))' "$LIB/profile.json")
  [[ "$gp" == "$R1006_PROFILE" ]] || die "the profile selects genesis_profile '$gp', not the compiled '$R1006_PROFILE'; refusing"
  need_r1006_hash "$gh"
}

gen_config() { # MINING: regenerate node.toml / env / unit for this host's own staker
  local mine
  mine=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["staker_address"])' "$PUB")
  python3 "$LIB/tools/gen_node_config.py" --profile "$LIB/profile.json" --staker "$mine" \
    --out-dir "$ETC" --data-dir "$DATA" --binary "$BIN" --mining "$1" --force
}

mining_configured() { python3 - "$ETC/node.toml" <<'PY'
import re, sys
sec = ""
for line in open(sys.argv[1]):
    m = re.match(r"^\[(\w+)\]", line)
    if m:
        sec = m.group(1)
    if sec == "mining" and line.startswith("enabled ="):
        sys.exit(0 if line.split("=", 1)[1].strip() == "true" else 1)
sys.exit(1)
PY
}

cmd_write_config() {
  local staker="${1:-}" mining="${2:-}"
  [[ "$staker" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "write-config needs the staker address"
  [[ "$mining" == on || "$mining" == off ]] || die "write-config needs mining on|off"
  ensure_layout
  check_profile
  # The staker in the config must be this host's own minted staker.
  local mine
  mine=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["staker_address"])' "$PUB")
  [[ "${mine,,}" == "${staker,,}" ]] || die "staker $staker is not this host's ($mine)"
  gen_config "$mining"
  rm -f -- "$PROBED"
  if [[ "$SERVICE" == systemd ]]; then
    if ! cmp -s "$ETC/citrate-node.service" /etc/systemd/system/citrate-node.service; then
      install -m 0644 "$ETC/citrate-node.service" /etc/systemd/system/citrate-node.service
      systemctl daemon-reload
    fi
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ >"$MARKER"
}

launch() {
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
      env "${envs[@]}" "${extra[@]}" setsid "$BIN" --config "$ETC/node.toml" </dev/null >>"$LOGFILE" 2>&1 &
      echo $! >"$PIDFILE"
    )
  fi
}

cmd_start() {
  local want="${1:-}"
  need_r1006_hash "$want"
  [[ -f "$MARKER" && -x "$BIN" && -f "$ETC/node.toml" ]] || die "not distributed (no marker, binary or node.toml)"
  [[ -f "$PROBED" && "$(cat -- "$PROBED")" == "${want,,}" ]] ||
    die "block 0 of the installed binary + config was not probed as $(short "$want") (run distribute)"
  if is_running; then
    say "already running"
    return 0
  fi
  # Every start begins with mining off; enable-mining turns it on after the block-0 check.
  if mining_configured; then
    check_profile
    gen_config off >/dev/null
  fi
  launch
  say "started (mining off)"
}

node_block0() {
  curl -s -m 5 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' "$NODE_RPC" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["hash"].lower())' 2>/dev/null || true
}

cmd_enable_mining() {
  local want="${1:-}"
  need_r1006_hash "$want"
  check_profile
  is_running || die "the node is not running; start it first"
  local got
  got=$(node_block0)
  [[ -n "$got" ]] || die "the running node did not answer eth_getBlockByNumber(0) on $NODE_RPC"
  [[ "$got" == "${want,,}" ]] || die "the running node's block 0 is $(short "$got"), not $(short "$want"); mining stays off"
  gen_config on >/dev/null
  cmd_stop >/dev/null
  launch
  say "mining enabled (block 0 $(short "$got") verified on this host)"
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
  # Colour codes off; then every CONFLICT / fork line counts except the known notices that
  # only use the word: a fork ACTIVATION ("… fork ACTIVE from height …") and a converged
  # fork choice ("… to the fork-choice head"). A real fork logs "deep-fork self-heal",
  # "runtime reorg" or a state-root BOOT HALT, none of which is exempt.
  text=$(printf '%s\n' "$text" | sed 's/\x1b\[[0-9;]*m//g')
  local all hits benign
  all=$(printf '%s\n' "$text" | grep -E -i '(^|[^a-z])(conflict|fork)([^a-z]|$)' || true)
  benign='fork ACTIVE from height|converged to the fork-choice head|rebuilt applied state to the fork-choice head'
  hits=$(printf '%s\n' "$all" | grep -v -E "$benign" | grep . || true)
  # Fork-choice reorgs: competing tips while several producers mine. One no deeper than
  # R1006_MAX_REORG blocks (default 6, fleet_agree's LAG) is counted and shown, not
  # failed; a deeper one is a hit like any other fork line.
  local max="${R1006_MAX_REORG:-6}" shallow=0 deepest=0 line n keep=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ fork-choice\ reorged\ to\ .*\(reverted\ ([0-9]+), ]]; then
      n=${BASH_REMATCH[1]}
      ((n > deepest)) && deepest=$n
      if ((n <= max)); then shallow=$((shallow + 1)); continue; fi
    fi
    keep+="$line"$'\n'
  done <<<"$hits"
  hits="$keep"
  printf 'lines %s\nmatches %s\nexempt %s\nshallow_reorgs %s\ndeepest_reorg %s\n' "$(printf '%s\n' "$text" | grep -c . || true)" \
    "$(printf '%s' "$hits" | grep -c . || true)" "$(printf '%s\n' "$all" | grep -c -E "$benign" || true)" "$shallow" "$deepest"
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

# build-rev: the installed binary's build stamp from `citrate consensus --json`, printed as
# "<git_sha> <true|false>" (git_sha is the short commit or "unknown"; the second field is
# git_dirty). The orchestrator compares it with MIN_CHAIN_REV before any node starts.
cmd_build_rev() {
  [[ -x "$BIN" ]] || die "no installed binary at $BIN"
  local out
  out=$(RUST_LOG=error "$BIN" consensus --json </dev/null 2>/dev/null) || die "the installed binary did not answer consensus --json"
  python3 -c 'import json, re, sys
l = sys.argv[1].splitlines()
try:
    d = json.loads("\n".join(l[l.index(next(x for x in l if x.startswith("{"))):]))
except Exception:
    sys.exit("host_agent: no build stamp in consensus --json")
sha, dirty = d.get("git_sha"), d.get("git_dirty")
if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{7,40}|unknown", sha) or not isinstance(dirty, bool):
    sys.exit("host_agent: malformed build stamp in consensus --json")
print(sha, "true" if dirty else "false")' "$out"
}

cmd_probe_genesis() {
  local want="${1:-}"
  need_r1006_hash "$want"
  [[ -x "$BIN" && -f "$ETC/node.toml" ]] || die "not distributed"
  rm -f -- "$PROBED"
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
  if [[ "$SERVICE" == proc ]]; then
    # shellcheck disable=SC2206
    envs+=(${R1006_NODE_ENV_PASSTHRU:-})
  fi
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
    # Diagnostic tail, with every long hex run shortened (stderr carries no full hash).
    tail -5 "$t/probe.log" | sed -E 's/[0-9a-fA-F]{24,}/<hex>/g; s/^/  probe| /' >&2
  fi
  [[ "$t" == "$ROOT"/var/tmp/r1006-probe.* ]] && rm -rf -- "${t:?}"
  if [[ -z "$got" ]]; then die "probe node never answered"; fi
  if [[ "${got,,}" != "${want,,}" ]]; then
    echo "PROBE FAIL block 0 $got, want $want"
    exit 1
  fi
  printf '%s' "${got,,}" >"$PROBED"
  echo "PROBE OK block 0 $got"
}

cmd_tcp_check() {
  local ip="${1:-}" port="${2:-}"
  [[ "$ip" =~ ^[0-9.]+$ && "$port" =~ ^[0-9]+$ ]] || die "tcp-check IP PORT"
  if timeout 3 bash -c "</dev/tcp/$ip/$port" 2>/dev/null; then echo "open $ip:$port"; else echo "closed $ip:$port"; return 1; fi
}

cmd_config_check() {
  local f hits=0
  for f in "$ETC/node.toml" "$ETC/citrate-node.env" /etc/systemd/system/citrate-node.service.d/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -n -i 'contribution' -- "$f" | sed "s|^|  $f:|"; then hits=1; fi
  done
  if [[ $hits -eq 1 ]]; then echo "CONFIG FAIL: a contribution recorder is configured"; return 1; fi
  echo "config ok: no contribution recorder"
}

dispatch() {
c="${1:-}"
shift || true
case "$c" in
  keys) cmd_keys "$@" ;;
  pub) cmd_pub ;;
  registration-proof) cmd_registration_proof "$@" ;;
  install-bin) cmd_install_bin "$@" ;;
  write-config) cmd_write_config "$@" ;;
  start) cmd_start "$@" ;;
  enable-mining) cmd_enable_mining "$@" ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  logs-scan) cmd_logs_scan "$@" ;;
  wipe) cmd_wipe "$@" ;;
  sha) cmd_sha "$@" ;;
  build-rev) cmd_build_rev ;;
  probe-genesis) cmd_probe_genesis "$@" ;;
  tcp-check) cmd_tcp_check "$@" ;;
  config-check) cmd_config_check ;;
  *) die "unknown command '$c'" ;;
esac
}

# Run the command with both streams held on the host; release them only when they hold
# none of this host's key material. Otherwise drop both and exit 3.
held=$(mktemp -d "${TMPDIR:-/tmp}/r1006-agent.XXXXXX")
chmod 0700 "$held"
out="$held/out"
err="$held/err"
set +e
(set -e; dispatch "$@") >"$out" 2>"$err"
rc=$?
set -e
if ! withhold_secrets "$out" "$err"; then
  rm -rf -- "${held:?}"
  echo "host_agent: output withheld: it contained this host's key material" >&2
  exit 3
fi
cat -- "$out"
cat -- "$err" >&2
rm -rf -- "${held:?}"
exit "$rc"
