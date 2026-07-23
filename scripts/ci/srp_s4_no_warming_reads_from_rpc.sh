#!/usr/bin/env bash
# SRP-S4 WP-2.2 tripwire — the RPC/API layer must NEVER call the WARMING executor reads
# (get_balance / get_nonce / get_code_hash), which do `state_db.accounts.load_account`
# and mutate the SHARED consensus resident map the block producer's lock-free state-root
# fold iterates. A concurrent RPC warm can tear the committed root (the block-5,406
# non-injective wedge). RPC handlers must use the non-warming `get_canonical_account`
# (committed store-first read). Execution paths (revm_adapter, settle_block_rewards,
# calculate_state_root) legitimately warm — but they run under `advance_lock` or on the
# isolated simulation db, and live OUTSIDE core/api.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HITS=$(grep -rnE '\b(exec|executor)\.(get_balance|get_nonce|get_code_hash)\(' "$ROOT/core/api/src" 2>/dev/null | grep -vE 'get_canonical_account|//' || true)
if [ -n "$HITS" ]; then
  echo "SRP-S4 WP-2.2 VIOLATION: warming executor read from the RPC/API layer — use get_canonical_account instead:" >&2
  echo "$HITS" >&2
  exit 1
fi
echo "SRP-S4 WP-2.2 tripwire: PASS (no warming executor reads in core/api/src)"
