#!/usr/bin/env bash
# created: 2026-10-04 | branch: hup/n7-chain-precompile-followups | author: Larry Klosowski + Claude Opus 5.5 | status: active
#
# Refusal tests for scripts/devnet-precompile-check.sh that need no node: it must stop
# before touching any RPC when the fork height is missing or malformed, when chain 40204
# is named, when an existing devnet is given without a deployer key file, and when its
# pinned inputs are missing. The full check runs against a devnet (see the script header).
# Usage: test_devnet_precompile_check.sh [repo-root]   (default: this repo)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRIPT="$ROOT/scripts/devnet-precompile-check.sh"
[ -f "$SCRIPT" ] || { echo "FAIL - missing $SCRIPT"; exit 2; }
fails=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

expect_refusal() { # name expected-message env...
  local name="$1" want="$2"; shift 2
  local out code
  out="$(env -i PATH="$PATH" HOME="$HOME" WORK="$TMP/w" RPC_PORT=1 P2P_PORT=1 "$@" bash "$SCRIPT" 2>&1)"
  code=$?
  if [ "$code" -eq 0 ] || ! grep -q -- "$want" <<<"$out"; then
    echo "FAIL - $name: exit $code, output: $out"
    fails=$((fails + 1))
  else
    echo "ok   - $name"
  fi
}

expect_refusal "no fork height" "set CITRATE_AGENT_PRECOMPILES_HEIGHT"
expect_refusal "non-numeric fork height" "set CITRATE_AGENT_PRECOMPILES_HEIGHT" \
  CITRATE_AGENT_PRECOMPILES_HEIGHT=soon
expect_refusal "chain 40204 named" "never on 40204" \
  CITRATE_AGENT_PRECOMPILES_HEIGHT=40 EXPECT_CHAIN_ID=1337,40204
expect_refusal "existing devnet without a key file" "DEPLOYER_KEY_FILE" \
  CITRATE_AGENT_PRECOMPILES_HEIGHT=40 RPC_URLS=http://127.0.0.1:1
expect_refusal "missing node binary" "no node binary" \
  CITRATE_AGENT_PRECOMPILES_HEIGHT=40 CITRATE_NODE_BIN="$TMP/none"

# A copy of the script whose pinned vectors are gone must refuse, not pass vacuously.
mkdir -p "$TMP/repo/scripts" "$TMP/repo/core/execution/tests/fixtures"
cp "$SCRIPT" "$TMP/repo/scripts/"
cp "$ROOT/core/execution/tests/fixtures/agent_precompile_caller_runtime.hex" \
  "$TMP/repo/core/execution/tests/fixtures/"
SCRIPT="$TMP/repo/scripts/devnet-precompile-check.sh"
expect_refusal "missing vectors" "agent_precompile_vectors.json" CITRATE_AGENT_PRECOMPILES_HEIGHT=40

[ "$fails" -eq 0 ] || exit 1
echo "ok   - devnet-precompile-check refusals"
