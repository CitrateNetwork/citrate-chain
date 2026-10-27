#!/usr/bin/env bash
# genesis_keyed_pins_tripwire.sh: the new hardening rules are scheduled ONLY in the shared
# (chain id, genesis hash) table (citrate_consensus::hardening::GENESIS_ACTIVATIONS).
#
# r1005 and r1006 share chain id 40204. A per-module chain-id pin such as
# `(40204, Some(0))` would switch the rule on for an r1005 node rebuilt from main and fork
# it off the live chain, so these rules have no chain-id pin tables at all. This fails if
#   1. any of SUPPLY_HARDENING_PINS, STORAGE_ROOT_HARDENING_PINS, EXACT_CREATE_CODE_PINS or
#      VRF_CANONICAL_ENCODING_PINS is defined (`const` or `static`) anywhere in the Rust
#      sources, or
#   2. any other chain-id pin table of `(u64, Option<u64>)` pairs carries a `Some(..)`,
#      however it is spelled: `const` or `static`, `&[..]`, `&'static [..]` or a fixed
#      array `[..; N]`. The two that predate r1006 and are r1005's own rules are allowed
#      (PINNED_ACTIVATIONS, the block-validity hardening; AGENT_PRECOMPILES_PINS, the
#      agent fork), or
#   3. a `match` on a chain id has an arm that returns a height (`N => Some(Some(h))` or
#      `N => Some(h)`); `Some(None)` and `None` arms are fine.
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
    "(const|static) +(mut +)?($FORBIDDEN)\b" "$root" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    echo "genesis-keyed pins: a per-module chain-id pin table exists (schedule it in GENESIS_ACTIVATIONS):"
    echo "$hits"
    bad=1
  fi
  # A chain-id pin table (one line or several) that carries Some(..), or a chain-id match
  # that returns a height. A scanner error fails the scan (never a silent pass).
  if ! hits=$(python3 - "$root" "$ALLOWED" <<'PY'
import os, re, sys
root, allowed = sys.argv[1], re.compile(rf"^({sys.argv[2]})$")
# const|static NAME: &[..] | &'static [..] | [..; N] = <value>;
pat = re.compile(
    r"\b(?:const|static)\s+(?:mut\s+)?([A-Z0-9_]+)\s*:\s*"
    r"(?:&\s*(?:'static\s*)?)?\[\s*\(\s*u64\s*,\s*Option\s*<\s*u64\s*>\s*\)\s*(?:;\s*[A-Za-z0-9_]+\s*)?\]"
    r"\s*=\s*(.*?);",
    re.S,
)
# `match <expr naming a chain id> {` ... an arm `<int literal(s)> => Some(Some(<h>))` or `=> Some(<h>)`.
match_hdr = re.compile(r"\bmatch\s+([^{;]*?)\{")
arm = re.compile(
    r"(?:^|[,{\n])\s*[0-9][0-9_]*(?:u64)?(?:\s*\|\s*[0-9][0-9_]*(?:u64)?)*\s*=>\s*\{?\s*(?:return\s+)?"
    r"Some\s*\(\s*(?:Some\s*\(\s*)?([0-9A-Za-z_]+)"
)
def body(src, i):
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1 : j]
    return src[i + 1 :]
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
            if not allowed.match(m.group(1)) and re.search(r"Some\s*\(", m.group(2)):
                line = src.count("\n", 0, m.start()) + 1
                print(f"{p}:{line}: {m.group(1)} carries a height")
        for m in match_hdr.finditer(src):
            if "chain" not in m.group(1).lower():
                continue
            for a in arm.finditer(body(src, m.end() - 1)):
                if a.group(1) == "None":
                    continue
                line = src.count("\n", 0, m.start()) + 1
                print(f"{p}:{line}: a match on {m.group(1).strip()} returns a height")
                break
PY
  ); then
    echo "genesis-keyed pins: the scanner itself failed (fail closed)"
    return 1
  fi
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
  # A scanner that cannot run fails the scan: a python3 that exits 1 on a clean tree.
  mkdir -p "$T/bin" "$T/broken"
  printf '#!/bin/sh\nexit 1\n' >"$T/bin/python3"; chmod +x "$T/bin/python3"
  printf 'pub const PINNED_ACTIVATIONS: &[(u64, Option<u64>)] = &[(40204, Some(0))];\n' >"$T/broken/a.rs"
  if (PATH="$T/bin:$PATH" scan "$T/broken" >/dev/null); then
    echo "self-test FAIL: a failed scanner passes"; rc=1
  else
    echo "self-test ok: a failed scanner fails"
  fi
  exit $rc
fi
ROOT="${1:-$HERE/../..}"
if scan "$ROOT"; then
  echo "genesis-keyed pins: OK (no per-module chain-id pin table; no new chain-id height)"
else
  exit 1
fi
