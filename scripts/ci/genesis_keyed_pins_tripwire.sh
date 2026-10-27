#!/usr/bin/env bash
# genesis_keyed_pins_tripwire.sh: the new hardening rules are scheduled ONLY in the shared
# (chain id, genesis hash) table (citrate_consensus::hardening::GENESIS_ACTIVATIONS).
#
# r1005 and r1006 share chain id 40204. A per-module chain-id pin such as
# `(40204, Some(0))` would switch the rule on for an r1005 node rebuilt from main and fork
# it off the live chain, so these rules have no chain-id pin tables at all. This fails if
#   1. any of SUPPLY_HARDENING_PINS, STORAGE_ROOT_HARDENING_PINS, EXACT_CREATE_CODE_PINS or
#      VRF_CANONICAL_ENCODING_PINS is defined anywhere in the Rust sources, or
#   2. any other `&[(u64, Option<u64>)]` chain-id pin table carries a `Some(..)`, except the
#      two that predate r1006 and are r1005's own rules (PINNED_ACTIVATIONS, the
#      block-validity hardening; AGENT_PRECOMPILES_PINS, the agent fork).
#
#   genesis_keyed_pins_tripwire.sh [ROOT]     scan ROOT (default: the repo)
#   genesis_keyed_pins_tripwire.sh --self-test   negative control + positive control
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORBIDDEN='SUPPLY_HARDENING_PINS|STORAGE_ROOT_HARDENING_PINS|EXACT_CREATE_CODE_PINS|VRF_CANONICAL_ENCODING_PINS'
ALLOWED='PINNED_ACTIVATIONS|AGENT_PRECOMPILES_PINS'

scan() {
  local root="$1" bad=0 hits
  hits=$(grep -rnE --include='*.rs' --exclude-dir=target --exclude-dir=.git \
    "const +($FORBIDDEN)\b" "$root" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    echo "genesis-keyed pins: a per-module chain-id pin table exists (schedule it in GENESIS_ACTIVATIONS):"
    echo "$hits"
    bad=1
  fi
  # A chain-id pin table (one line or several) that carries Some(..).
  hits=$(python3 - "$root" "$ALLOWED" <<'PY'
import os, re, sys
root, allowed = sys.argv[1], re.compile(rf"^({sys.argv[2]})$")
pat = re.compile(r"const\s+([A-Z0-9_]+)\s*:\s*&\[\(u64,\s*Option<u64>\)\]\s*=\s*(&\[.*?\]);", re.S)
for d, dirs, files in os.walk(root):
    dirs[:] = [x for x in dirs if x not in ("target", ".git", "node_modules")]
    for f in files:
        if not f.endswith(".rs"):
            continue
        p = os.path.join(d, f)
        try:
            src = open(p, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        for m in pat.finditer(src):
            if not allowed.match(m.group(1)) and "Some(" in m.group(2):
                line = src.count("\n", 0, m.start()) + 1
                print(f"{p}:{line}: {m.group(1)} carries a height")
PY
)
  if [[ -n "$hits" ]]; then
    echo "genesis-keyed pins: a chain-id pin table carries a height (schedule it in GENESIS_ACTIVATIONS):"
    echo "$hits"
    bad=1
  fi
  return $bad
}

if [[ "${1:-}" == --self-test ]]; then
  T=$(mktemp -d "${TMPDIR:-/tmp}/gkp-tripwire.XXXXXX")
  trap 'rm -rf "${T:?}"' EXIT
  rc=0 n=0 Q="'"
  # must_fail NAME SOURCE: a tree holding only SOURCE must fail the scan.
  must_fail() {
    n=$((n + 1)); mkdir -p "$T/$n"; printf '%s\n' "$2" >"$T/$n/a.rs"
    if scan "$T/$n" >/dev/null; then echo "self-test FAIL: $1 passes"; rc=1; else echo "self-test ok: $1 fails"; fi
  }
  # must_pass NAME SOURCE: a tree holding only SOURCE must pass (negative control).
  must_pass() {
    n=$((n + 1)); mkdir -p "$T/$n"; printf '%s\n' "$2" >"$T/$n/a.rs"
    if scan "$T/$n" >/dev/null; then echo "self-test ok: $1 passes"; else echo "self-test FAIL: $1 fails"; rc=1; fi
  }
  must_pass "the allowed-table fixture" \
    'pub const PINNED_ACTIVATIONS: &[(u64, Option<u64>)] = &[(40204, Some(0))];
pub const AGENT_PRECOMPILES_PINS: &[(u64, Option<u64>)] = &[(40204, Some(0))];'
  must_fail "a per-module table (const)" 'pub const EXACT_CREATE_CODE_PINS: &[(u64, Option<u64>)] = &[];'
  must_fail "a per-module table (static)" 'pub static SUPPLY_HARDENING_PINS: &[(u64, Option<u64>)] = &[];'
  must_fail "a chain-id height (const, multi-line)" 'pub const NEW_RULE_PINS: &[(u64, Option<u64>)] = &[
    (40204, Some(0)),
];'
  must_fail "a chain-id height (static)" 'pub static NEW_RULE_PINS: &[(u64, Option<u64>)] = &[(40204, Some(0))];'
  must_pass "a chain-id table without a height (static)" 'pub static NEW_RULE_PINS: &[(u64, Option<u64>)] = &[(40204, None)];'
  must_fail "a chain-id height (&${Q}static)" "pub const NEW_RULE_PINS: &${Q}static [(u64, Option<u64>)] = &[(40204, Some(0))];"
  must_pass "a chain-id table without a height (&${Q}static)" "pub const NEW_RULE_PINS: &${Q}static [(u64, Option<u64>)] = &[(40204, None)];"
  must_fail "a chain-id height (fixed array)" 'pub const NEW_RULE_PINS: [(u64, Option<u64>); 1] = [(40204, Some(0))];'
  must_pass "a chain-id table without a height (fixed array)" 'pub const NEW_RULE_PINS: [(u64, Option<u64>); 1] = [(40204, None)];'
  must_fail "a chain-id height (match arm)" 'pub fn new_rule_pin(chain_id: u64) -> Option<Option<u64>> {
    match chain_id {
        40204 => Some(Some(0)),
        _ => None,
    }
}'
  must_fail "a chain-id height (match arm, bare Some)" 'fn new_rule_height(id: u64) -> Option<u64> {
    match self.chain_id { 1337 | 40204 => Some(0), _ => None }
}'
  must_pass "a chain-id match without a height" 'pub fn new_rule_pin(chain_id: u64) -> Option<Option<u64>> {
    match chain_id {
        40204 => Some(None),
        _ => None,
    }
}'
  must_pass "a match on something other than a chain id" 'fn f(x: u64) -> Option<u64> {
    match x {
        1000 => Some(5),
        _ => None,
    }
}'
  exit $rc
fi
ROOT="${1:-$HERE/../..}"
if scan "$ROOT"; then
  echo "genesis-keyed pins: OK (no per-module chain-id pin table; no new chain-id height)"
else
  exit 1
fi
