#!/usr/bin/env bash
#
# check_paymaster_balance.sh — read the CitratePaymaster's EntryPoint
# deposit and exit non-zero (with a stderr alert line) if it falls
# below the configured threshold.
#
# WP-3 of EW-S1 (the "low-balance alerting hook"). Designed to be
# cron'd every ~5 minutes on the auth.citrate.ai droplet; pipe stderr
# into whatever the operator's incident channel is.
#
# Env:
#   RPC_URL                            (default https://rpc.citrate.ai)
#   CITRATE_AA_PAYMASTER               (required — paymaster address)
#   CITRATE_AA_LOW_BALANCE_THRESHOLD   (default 1000000000000000000 i.e. 1 native unit)
#
# Exit codes:
#   0  — balance >= threshold
#   1  — balance <  threshold (alert)
#   2  — invocation / RPC error

set -euo pipefail

RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
PAYMASTER="${CITRATE_AA_PAYMASTER:-}"
THRESHOLD="${CITRATE_AA_LOW_BALANCE_THRESHOLD:-1000000000000000000}"

if [[ -z "$PAYMASTER" ]]; then
  echo "FATAL: CITRATE_AA_PAYMASTER not set" >&2
  exit 2
fi

# Resolve the EntryPoint from the paymaster's `entryPoint()` view.
# entryPoint() selector: keccak256("entryPoint()")[0..4] = 0xb0d691fe
EP_DATA="0xb0d691fe"
EP_RAW=$(curl -s -X POST "$RPC_URL" \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"$PAYMASTER\",\"data\":\"$EP_DATA\"},\"latest\"],\"id\":1}" \
  | sed -E 's/.*"result":"([^"]+)".*/\1/')
if [[ "$EP_RAW" == "null" || -z "$EP_RAW" ]]; then
  echo "FATAL: could not resolve paymaster.entryPoint() at $PAYMASTER on $RPC_URL" >&2
  exit 2
fi
# `address` is the last 20 bytes (40 hex chars) of the 32-byte return.
EP_ADDR="0x${EP_RAW: -40}"

# Read EntryPoint.balanceOf(paymaster). balanceOf(address) selector =
# keccak256("balanceOf(address)")[0..4] = 0x70a08231.
# Address is left-pad-zero to 32 bytes.
PM_NO_PREFIX="${PAYMASTER#0x}"
BAL_DATA="0x70a08231000000000000000000000000${PM_NO_PREFIX}"
BAL_RAW=$(curl -s -X POST "$RPC_URL" \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"$EP_ADDR\",\"data\":\"$BAL_DATA\"},\"latest\"],\"id\":1}" \
  | sed -E 's/.*"result":"([^"]+)".*/\1/')
if [[ "$BAL_RAW" == "null" || -z "$BAL_RAW" ]]; then
  echo "FATAL: could not read EntryPoint.balanceOf($PAYMASTER) on $RPC_URL" >&2
  exit 2
fi

BAL_HEX="${BAL_RAW#0x}"
# python3 handles arbitrary-precision int → str cleanly. bc/awk would too.
BAL_DEC=$(python3 -c "print(int('$BAL_HEX', 16))")
THR_DEC=$(python3 -c "print(int('$THRESHOLD'))")

if (( BAL_DEC < THR_DEC )); then
  echo "ALERT: CitratePaymaster deposit below threshold." >&2
  echo "  paymaster     = $PAYMASTER" >&2
  echo "  entry_point   = $EP_ADDR" >&2
  echo "  balance       = $BAL_DEC" >&2
  echo "  threshold     = $THR_DEC" >&2
  echo "  shortfall     = $((THR_DEC - BAL_DEC))" >&2
  echo "  next_action   = run \`forge script script/aa/FundPaymaster.s.sol\` from the treasury wallet" >&2
  exit 1
fi

echo "ok paymaster=$PAYMASTER balance=$BAL_DEC threshold=$THR_DEC"
exit 0
