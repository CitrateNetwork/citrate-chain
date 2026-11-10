#!/usr/bin/env bash
# devnet.sh: rehearse the whole r1007 ceremony on local "hosts" in network namespaces:
# a stand-in r1006 comes up first, then the cut-over to r1007, the health gates, and the
# rollback to r1006 with its data kept.
#
#   devnet.sh --binary PATH --work DIR [--producers N] [--gate-minutes N] [--stagger-seconds N]
#             [--steps "…"] [--keep]
#
# Each host is a directory (its root) plus its own network namespace with an address on a
# private bridge (10.207.0.<i>/24, P2P on <ip>:30303 as on the fleet; RPC on each
# namespace's own loopback). Everything runs inside ONE unprivileged user + network +
# mount + pid namespace (the r1006 devnet's userns harness, scripts/ops/r1006/local_devnet.sh),
# so nothing here can reach the fleet, the internet or the host's services, and every
# node dies with the rehearsal. Linux only (unshare, nsenter, ip).
#
# Topology: 3 boots, N producers (default 4, at most 7), 1 rpc. Keys are minted per host
# by the binary's own host-identity (throwaway, never leave DIR). These producers are not
# the registered r1006 set, so each chain halts at the validator activation height (1000);
# the rehearsal needs far fewer blocks.
#
# Default steps: collect render-r1006 render-r1007 check devnet-r1006 health-r1006 prepare cut
#                boots producers rpc indexer health-r1007 rollback health-kept
# Timings: DIR/timings.txt. Log: DIR/rehearsal.log. Exit: the first failed step's rc.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CER="$HERE/ceremony.py"
BIN=""
WORK=""
NPROD=4
GATE=10
STAGGER=5
STEPS="collect render-r1006 render-r1007 check devnet-r1006 health-r1006 prepare cut boots producers rpc indexer health-r1007 rollback health-kept"
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BIN="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --producers) NPROD="$2"; shift 2 ;;
    --gate-minutes) GATE="$2"; shift 2 ;;
    --stagger-seconds) STAGGER="$2"; shift 2 ;;
    --steps) STEPS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "devnet: unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -x "$BIN" && -n "$WORK" ]] || { echo "devnet: --binary (executable) and --work DIR are required" >&2; exit 2; }
[[ "$NPROD" =~ ^[0-9]+$ && "$NPROD" -ge 2 && "$NPROD" -le 7 ]] || { echo "devnet: --producers 2..7" >&2; exit 2; }
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

if [[ "${R1007_IN_NS:-}" != 1 ]]; then
  keep=()
  [[ $KEEP -eq 1 ]] && keep=(--keep)
  exec unshare --user --map-root-user --net --mount --pid --fork --kill-child --mount-proc \
    env R1007_IN_NS=1 bash "$0" --binary "$BIN" --work "$WORK" --producers "$NPROD" --gate-minutes "$GATE" \
    --stagger-seconds "$STAGGER" --steps "$STEPS" "${keep[@]}"
fi

# ---- inside the namespaces ---------------------------------------------------
ip link set lo up
ip link add br-r1007 type bridge
ip addr add 10.207.0.254/24 dev br-r1007
ip link set br-r1007 up
names=(citrate-boot-1 citrate-boot-2 citrate-boot-3)
roles=(boot boot boot)
for i in $(seq 1 "$NPROD"); do names+=("citrate-prod-$i"); roles+=(producer); done
names+=(citrate-rpc-1)
roles+=(rpc)
hosts_json="["
for idx in "${!names[@]}"; do
  i=$((idx + 1))
  name="${names[$idx]}"
  root="$WORK/hosts/$name"
  mkdir -p "$root"
  unshare --net sleep infinity &
  pid=$!
  sleep 0.2
  ip link add "vh$i" type veth peer name "vn$i"
  ip link set "vn$i" netns "$pid"
  ip link set "vh$i" master br-r1007 up
  nsenter --net="/proc/$pid/ns/net" sh -c "ip link set lo up; ip link set vn$i name eth0; ip addr add 10.207.0.$i/24 dev eth0; ip link set eth0 up"
  extra=""
  [[ "${roles[$idx]}" == rpc ]] && extra=',"indexer":true'
  [[ $idx -gt 0 ]] && hosts_json+=","
  hosts_json+="{\"name\":\"$name\",\"role\":\"${roles[$idx]}\",\"p2p_host\":\"10.207.0.$i\",\"peer_id\":null,\"root\":\"$root\",\"netns_pid\":\"$pid\"$extra}"
done
hosts_json+="]"
FLEET="$WORK/fleet.local.json"
printf '{"schema":"r1007-fleet/1","chain_id":40204,"transport":"local","p2p_port":30303,"hosts":%s}\n' "$hosts_json" >"$FLEET"
echo "devnet: ${#names[@]} hosts (3 boots, $NPROD producers, 1 rpc) on br-r1007 (10.207.0.0/24); fleet $FLEET"

STATE="$WORK/state"
mkdir -p "$STATE"
LOG="$WORK/rehearsal.log"
TIMES="$WORK/timings.txt"
: >"$TIMES"
# The stand-in r1006 and the r1007 profile are rehearsal geneses on these hosts.
export R1007_NODE_ENV_PASSTHRU="CITRATE_R1006_REHEARSAL=1"
C=(python3 "$CER")
COMMON=(--fleet "$FLEET" --state "$STATE" --binary "$BIN" --gate-minutes "$GATE" --stagger-seconds "$STAGGER" --min-peers 2 --last 40)

one() {
  case "$1" in
    collect) "${C[@]}" collect "${COMMON[@]}" --mint ;;
    render-r1006) "${C[@]}" render "${COMMON[@]}" --network r1006 ;;
    render-r1007) "${C[@]}" render "${COMMON[@]}" --network r1007 ;;
    check) "${C[@]}" check "${COMMON[@]}" --network r1007 ;;
    devnet-r1006) "${C[@]}" run devnet-r1006 "${COMMON[@]}" ;;
    health-r1006) sleep 20; "${C[@]}" health "${COMMON[@]}" --network r1006 --require-sealing ;;
    health-r1007) "${C[@]}" health "${COMMON[@]}" --network r1007 ;;
    health-kept) "${C[@]}" health "${COMMON[@]}" --network r1006 --expect-kept ;;
    *) "${C[@]}" run "$1" "${COMMON[@]}" ;;
  esac
}

for s in $STEPS; do
  t0=$(date +%s%N)
  echo "===== $s =====" | tee -a "$LOG"
  set +e
  one "$s" 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  set -e
  ms=$((($(date +%s%N) - t0) / 1000000))
  printf '%-14s rc=%s %5d.%01ds\n' "$s" "$rc" $((ms / 1000)) $((ms % 1000 / 100)) | tee -a "$TIMES"
  if [[ $rc -ne 0 ]]; then
    echo "devnet: step $s failed (rc=$rc); later steps not run" | tee -a "$LOG"
    for n in "${names[@]}"; do
      f="$WORK/hosts/$n/var/lib/citrate/ceremony"
      for l in "$f"/node-*.log; do [[ -f "$l" ]] && { echo "--- $n $(basename "$l") (tail)"; tail -n 15 "$l"; }; done
    done | tee -a "$LOG"
    exit "$rc"
  fi
done
echo "devnet: done"
cat "$TIMES"

if [[ $KEEP -eq 1 ]]; then
  trap 'exit 0' TERM INT HUP
  echo "devnet: kept running (--keep); Ctrl-C ends it"
  while :; do sleep 3600 & wait $! || true; done
fi
