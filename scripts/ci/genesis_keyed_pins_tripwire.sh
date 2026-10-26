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
  trap 'rm -rf "$T"' EXIT
  rc=0
  mkdir -p "$T/clean" "$T/table" "$T/height"
  printf 'pub const PINNED_ACTIVATIONS: &[(u64, Option<u64>)] = &[(40204, Some(0))];\n' >"$T/clean/a.rs"
  printf 'pub const EXACT_CREATE_CODE_PINS: &[(u64, Option<u64>)] = &[];\n' >"$T/table/a.rs"
  printf 'pub const NEW_RULE_PINS: &[(u64, Option<u64>)] = &[\n    (40204, Some(0)),\n];\n' >"$T/height/a.rs"
  scan "$T/clean" >/dev/null && echo "self-test ok: the allowed tables pass" || { echo "self-test FAIL: the allowed tables fail"; rc=1; }
  scan "$T/table" >/dev/null && { echo "self-test FAIL: a per-module table passes"; rc=1; } || echo "self-test ok: a per-module table fails"
  scan "$T/height" >/dev/null && { echo "self-test FAIL: a chain-id height passes"; rc=1; } || echo "self-test ok: a chain-id height fails"
  exit $rc
fi
ROOT="${1:-$HERE/../..}"
if scan "$ROOT"; then
  echo "genesis-keyed pins: OK (no per-module chain-id pin table; no new chain-id height)"
else
  exit 1
fi
