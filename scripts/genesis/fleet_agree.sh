#!/usr/bin/env bash
# fleet_agree.sh: do all producers and RPC nodes report the same chain? Read-only.
#
# For every RPC endpoint given, reads eth_chainId, the hash of block 0 and the head height.
# Then it picks a common height H = (lowest head) - LAG and compares, on every endpoint, the
# block at H on that endpoint's CANONICAL chain: found by walking parentHash down from its
# `latest` block, not from `eth_getBlockByNumber(H)`. The node's height index keeps the last
# block written at a height, which after a shallow fork-choice reorg can be the replaced
# sibling (scripts/ci/rpc_height_index_tripwire.sh); a by-number answer that differs from the
# walked block is reported as a NOTE (an RPC height-index lag), not as a fork. It FAILS if:
#   * an endpoint is unreachable;
#   * a chain id differs from EXPECTED_CHAIN_ID (default 40204);
#   * the block-0 hashes differ from each other, or from EXPECTED_GENESIS_HASH when set;
#   * the block hashes at H differ (a fork), or the heads are further apart than MAX_SPREAD.
#
# This is the "all producers report the SAME genesis hash and tip hash" check from the
# 2026-09-28 runbook, as a script. Ported from the R2 sample_height.sh probe, generalized.
#
# Usage
#   fleet_agree.sh [--dry-run] RPC_URL [RPC_URL...]
#   FLEET_RPCS=url1,url2 fleet_agree.sh
# Env: EXPECTED_CHAIN_ID (40204) · EXPECTED_GENESIS_HASH (optional) · LAG (6 blocks)
#      MAX_SPREAD (blocks; 120) · CAST (cast)
#
# Exit: 0 agree · 1 disagree or unreachable · 2 usage
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/genesis/lib.sh
. "$HERE/lib.sh"
GENESIS_LOG_TAG=fleet_agree

CAST="${CAST:-${FOUNDRY_BIN:+$FOUNDRY_BIN/}cast}"
EXPECTED_CHAIN_ID="${EXPECTED_CHAIN_ID:-40204}"
LAG="${LAG:-6}"
MAX_SPREAD="${MAX_SPREAD:-120}"

DRY=0
RPCS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h | --help)
      sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
      exit 2
      ;;
    -*) die "unknown flag $a" 2 ;;
    *) RPCS+=("$a") ;;
  esac
done
if [[ ${#RPCS[@]} -eq 0 && -n "${FLEET_RPCS:-}" ]]; then
  IFS=',' read -r -a RPCS <<<"$FLEET_RPCS"
fi
[[ ${#RPCS[@]} -ge 1 ]] || die "give at least one RPC URL (args or FLEET_RPCS)" 2
[[ "$LAG" =~ ^[0-9]+$ && "$MAX_SPREAD" =~ ^[0-9]+$ ]] || die "LAG and MAX_SPREAD are whole numbers" 2
if [[ -n "${EXPECTED_GENESIS_HASH:-}" && ! "$EXPECTED_GENESIS_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
  die "EXPECTED_GENESIS_HASH must be a 0x 32-byte hash" 2
fi

if [[ $DRY -eq 1 ]]; then
  log "plan: ${#RPCS[@]} endpoint(s), chain id $EXPECTED_CHAIN_ID, lag $LAG, max spread $MAX_SPREAD"
  for r in "${RPCS[@]}"; do
    describe_cmd "$CAST" chain-id --rpc-url "$r"
    describe_cmd "$CAST" block 0 --field hash --rpc-url "$r"
    describe_cmd "$CAST" block latest --field hash --rpc-url "$r"
  done
  log "then: walk parentHash from $CAST block latest to <min head - $LAG> on every endpoint, compared"
  exit 0
fi

fail=0
declare -A HEAD G0 TIPH
for r in "${RPCS[@]}"; do
  cid=$("$CAST" chain-id --rpc-url "$r" 2>/dev/null) || cid=""
  g0=$("$CAST" block 0 --field hash --rpc-url "$r" 2>/dev/null) || g0=""
  # The head is pinned here, as a block (hash, and the number read for that hash): the walk
  # below starts from it, so its length is bounded by the spread + LAG however long the run
  # takes. A walk from a later `latest` grows with every endpoint checked before it.
  tip=$("$CAST" block latest --field hash --rpc-url "$r" 2>/dev/null) || tip=""
  h=""
  [[ -n "$tip" ]] && { h=$("$CAST" block "$tip" --field number --rpc-url "$r" 2>/dev/null) || h=""; }
  if [[ -z "$cid" || -z "$g0" || ! "$h" =~ ^[0-9]+$ ]]; then
    log "FAIL  $r unreachable or incomplete answer"
    fail=1
    continue
  fi
  g0=$(lower "$g0")
  HEAD[$r]=$h
  TIPH[$r]=$tip
  G0[$r]=$g0
  log "      $r chain=$cid head=$h genesis=$g0"
  if [[ "$cid" != "$EXPECTED_CHAIN_ID" ]]; then
    log "FAIL  $r chain id $cid, want $EXPECTED_CHAIN_ID"
    fail=1
  fi
done
[[ ${#HEAD[@]} -gt 0 ]] || {
  log "=> FLEET FAIL (no endpoint answered)"
  exit 1
}

# Reference genesis: the expected one when given, else the first endpoint that answered.
ref="$(lower "${EXPECTED_GENESIS_HASH:-}")"
if [[ -z "$ref" ]]; then
  for r in "${RPCS[@]}"; do
    if [[ -n "${G0[$r]:-}" ]]; then
      ref="${G0[$r]}"
      break
    fi
  done
fi
for r in "${!G0[@]}"; do
  if [[ "${G0[$r]}" != "$ref" ]]; then
    log "FAIL  $r genesis ${G0[$r]} differs from $ref"
    fail=1
  fi
done

min=""
max=0
for r in "${!HEAD[@]}"; do
  h=${HEAD[$r]}
  [[ -z "$min" || $h -lt $min ]] && min=$h
  [[ $h -gt $max ]] && max=$h
done
if ((max - min > MAX_SPREAD)); then
  log "FAIL  heads are $((max - min)) blocks apart (> $MAX_SPREAD): a node is stalled or on a fork"
  fail=1
fi
H=$((min > LAG ? min - LAG : 0))
# canonical_at URL H: the hash at height H on URL's chain, by walking parentHash down from
# the head pinned for URL above (at most MAX_SPREAD + LAG steps). Empty on any failed read.
canonical_at() {
  local r="$1" want="$2" b="${TIPH[$1]}" n="${HEAD[$1]}" steps=0
  [[ -n "$b" && "$n" =~ ^[0-9]+$ ]] || return 0
  while ((n > want)); do
    ((steps++ > MAX_SPREAD + LAG + 64)) && return 0
    b=$("$CAST" block "$b" --field parentHash --rpc-url "$r" 2>/dev/null) || return 0
    n=$((n - 1))
  done
  ((n == want)) && lower "$b"
}
first=""
for r in "${!HEAD[@]}"; do
  bh=$(canonical_at "$r" "$H")
  if [[ -z "$bh" ]]; then
    log "FAIL  $r has no block $H on its canonical chain"
    fail=1
    continue
  fi
  idx=$("$CAST" block "$H" --field hash --rpc-url "$r" 2>/dev/null) || idx=""
  idx=$(lower "$idx")
  if [[ -n "$idx" && "$idx" != "$bh" ]]; then
    log "NOTE  $r eth_getBlockByNumber($H) = $idx, its canonical chain has $bh (RPC height-index lag)"
  fi
  [[ -z "$first" ]] && first="$bh"
  if [[ "$bh" != "$first" ]]; then
    log "FAIL  $r block $H = $bh, others $first (fork)"
    fail=1
  fi
done
log "      common height $H hash ${first:-none}"

if [[ $fail -eq 0 ]]; then
  log "=> FLEET AGREE (${#HEAD[@]} endpoints, genesis $ref, block $H)"
else
  log "=> FLEET FAIL"
fi
exit $fail
