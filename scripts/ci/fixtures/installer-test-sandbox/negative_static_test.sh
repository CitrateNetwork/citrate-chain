#!/usr/bin/env bash
# Fixture (installer-test-sandbox, negative): a test that only READS installer scripts (grep, a
# git pathspec, an echo). Nothing here runs them, so nothing may be flagged.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/deploy_testnet.sh"
grep -q 'cosign verify-blob' "$SCRIPT" && echo "ok - cosign present"
git -C "$ROOT" grep -n 'releases/latest' -- ':!scripts/tests/test_deploy_testnet_supply_chain.sh' || true
echo "checked $ROOT/scripts/ops/regenesis.sh"
[ -x "$SCRIPT" ] && echo "executable"
