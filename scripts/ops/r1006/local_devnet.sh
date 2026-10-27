#!/usr/bin/env bash
# local_devnet.sh: rehearse r1006_bringup.sh end to end on N local "producer hosts".
#
# Each host is a directory (its R1006_ROOT) plus its own network namespace with an
# address on a private bridge (10.206.0.<i>/24, P2P on <ip>:30303 as on the fleet; RPC
# on each namespace's own loopback). Everything runs inside ONE unprivileged user +
# network + mount + pid namespace, so nothing here can reach the fleet, the internet
# or the host's services, and every process dies with the rehearsal.
#
#   local_devnet.sh --nodes 7 --work DIR [--steps "keys genesis-fill distribute start smoke"]
#                   [--gate-minutes N] [--skip CHECKS] [--fill-cmd CMD] [--min-chain-rev SHA]
#
# --min-chain-rev: passed to `start` (its pre-join build-rev floor; see r1006_bringup.sh).
#
# --fill-cmd: the genesis-fill command ({producers} {stakes} {out} as in r1006_bringup.sh);
# default: the rehearsal stand-in (tests/fixtures/rehearsal_fill.py). For the real fill:
#   --fill-cmd 'python3 scripts/genesis/r1006/fill_producers.py {producers} {stakes} {out}' 
#
# DIR/state must already hold a build (r1006_bringup.sh build --local-repo … --state DIR/state).
# Timings go to DIR/rehearsal-timings.txt; the orchestrator's own log to DIR/rehearsal.log.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRINGUP="$HERE/../r1006_bringup.sh"
FILL="$HERE/../tests/fixtures/rehearsal_fill.py"

NODES=4
WORK=""
STEPS="keys genesis-fill distribute start smoke status"
GATE=10
SKIP="orangeseed,admins"
FILL_CMD=""
MIN_REV=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nodes) NODES="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --steps) STEPS="$2"; shift 2 ;;
    --gate-minutes) GATE="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    --fill-cmd) FILL_CMD="$2"; shift 2 ;;
    --min-chain-rev) MIN_REV=(--min-chain-rev "$2"); shift 2 ;;
    *) echo "local_devnet: unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$WORK" && -d "$WORK/state" ]] || { echo "local_devnet: --work DIR with DIR/state (a recorded build)" >&2; exit 2; }
[[ "$NODES" =~ ^[0-9]+$ && "$NODES" -ge 2 && "$NODES" -le 7 ]] || { echo "local_devnet: --nodes 2..7" >&2; exit 2; }
WORK="$(cd "$WORK" && pwd)"

if [[ "${R1006_IN_NS:-}" != 1 ]]; then
  exec unshare --user --map-root-user --net --mount --pid --fork --mount-proc \
    env R1006_IN_NS=1 bash "$0" --nodes "$NODES" --work "$WORK" --steps "$STEPS" --gate-minutes "$GATE" --skip "$SKIP" \
    --fill-cmd "$FILL_CMD"
fi

# ---- inside the namespaces ---------------------------------------------------
ip link set lo up
ip link add br-r1006 type bridge
ip addr add 10.206.0.254/24 dev br-r1006
ip link set br-r1006 up
HOLDERS=()
hosts_json="["
for i in $(seq 1 "$NODES"); do
  name="citrate-prod-$i"
  root="$WORK/hosts/$name"
  mkdir -p "$root"
  unshare --net sleep infinity &
  pid=$!
  HOLDERS+=("$pid")
  sleep 0.2
  ip link add "vh$i" type veth peer name "vn$i"
  ip link set "vn$i" netns "$pid"
  ip link set "vh$i" master br-r1006 up
  nsenter --net="/proc/$pid/ns/net" sh -c "ip link set lo up; ip link set vn$i name eth0; ip addr add 10.206.0.$i/24 dev eth0; ip link set eth0 up"
  [[ $i -gt 1 ]] && hosts_json+=","
  hosts_json+="{\"name\":\"$name\",\"region\":\"local-ns\",\"ip\":\"10.206.0.$i\",\"root\":\"$root\",\"netns_pid\":\"$pid\"}"
done
hosts_json+="]"
INV="$WORK/inventory.local.json"
printf '{"schema":"r1006-inventory/1","transport":"local","build_host":{"name":"local","ip":"127.0.0.1"},"hosts":%s}\n' "$hosts_json" >"$INV"
echo "devnet: $NODES hosts in network namespaces on br-r1006 (10.206.0.0/24); inventory $INV"

# P2P reachability between namespaces (the 30303 path the fleet firewall opens)
nsenter --net="/proc/${HOLDERS[0]}/ns/net" ping -c1 -W1 "10.206.0.$NODES" >/dev/null && echo "devnet: 10.206.0.1 -> 10.206.0.$NODES reachable"

TIMES="$WORK/rehearsal-timings.txt"
LOG="$WORK/rehearsal.log"
: >"$TIMES"
run_step() {
  local step="$1"
  shift
  local t0 rc
  t0=$(date +%s%N)
  echo "===== $step $* =====" | tee -a "$LOG"
  set +e
  # The rehearsal r1006 genesis is not release-ready; the nodes need the explicit opt-in.
  R1006_NODE_ENV_PASSTHRU="CITRATE_R1006_REHEARSAL=1" \
    bash "$BRINGUP" "$step" --inventory "$INV" --state "$WORK/state" "$@" 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  set -e
  local ms=$((($(date +%s%N) - t0) / 1000000))
  printf '%-14s rc=%s %4d.%01ds\n' "$step" "$rc" $((ms / 1000)) $((ms % 1000 / 100)) | tee -a "$TIMES"
  return 0
}

for s in $STEPS; do
  case "$s" in
    genesis-fill)
      fc="$FILL_CMD"
      [[ -n "$fc" ]] || fc="python3 $FILL --producers {producers} --stakes {stakes} --out {out} --bin $WORK/state/bin/citrate-node"
      run_step genesis-fill --fill-cmd "$fc" ;;
    distribute) run_step distribute ;;
    start) run_step start --mining on --gate-minutes "$GATE" "${MIN_REV[@]}" ;;
    smoke) run_step smoke --skip "$SKIP" ;;
    wipe-keys-refused) run_step wipe --wipe-keys ;;
    stop) run_step stop ;;
    wipe) run_step wipe ;;
    *) run_step "$s" ;;
  esac
done
echo "devnet: done; timings:"
cat "$TIMES"
