#!/usr/bin/env bash
# amc_surface_tripwire.sh — source-level fences for the AMC provider-governance contracts
# (contracts/src/amc/, AMC 0.5.3 planset 06; spec docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md).
# grep only, seconds, no toolchain. Runs in .github/workflows/amc-tripwires.yml.
#
#   A1  no value path: no `payable`, `receive`, `fallback`, value-bearing or raw low-level
#       call, `delegatecall`, `selfdestruct`, `.transfer(` or `.send(` anywhere in src/amc.
#       The four contracts hold no funds (06 section 1.4, P-15).
#   A2  RT-3: ProviderRegistry stores no host, path, model or URL. The only `string` it may
#       mention is the calldata argument of the pure `providerIdOf`.
#   A3  RT-4: UsageReceipts keeps no count / total / provider on chain. Its Receipt struct is
#       exactly {root, committedAt, blockNumber, schema}.
#   A4  Q-8(b): the direct guardian (RegistryGuardian2of3) can only remove or pause. The interface
#       it calls declares exactly emergencyDelist, veto and pause, nothing that lists or restores.
#
# Usage: amc_surface_tripwire.sh             # scan the tree
#        amc_surface_tripwire.sh --self-test # prove each scan detects its class
set -uo pipefail

REPO_ROOT="${AMC_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Strip // and /* */ comment text so NatSpec prose cannot trip (or hide) a hit.
code_only() { sed -E -e 's://.*$::' -e 's:/\*.*\*/::g' "$1"; }

scan_value_paths() { # <amc dir> ; prints hits, returns 0 iff any
  local dir="$1" f hits=""
  for f in "$dir"/*.sol; do
    [ -e "$f" ] || continue
    local h
    h=$(code_only "$f" | grep -nE '(\bpayable\b|\breceive[[:space:]]*\(|\bfallback[[:space:]]*\(|\.call[[:space:]]*[{(]|\bdelegatecall\b|\bselfdestruct\b|\.transfer[[:space:]]*\(|\.send[[:space:]]*\()' || true)
    [ -n "$h" ] && hits+="$f: $h"$'\n'
  done
  [ -n "$hits" ] && { printf '%s' "$hits"; return 0; }
  return 1
}

scan_registry_strings() { # <ProviderRegistry.sol> ; prints hits, returns 0 iff any
  local f="$1" hits
  [ -e "$f" ] || { echo "missing $f"; return 0; }
  hits=$(code_only "$f" | grep -nE '\bstring\b' | grep -vE 'function providerIdOf\(string calldata id\) external pure' || true)
  [ -n "$hits" ] && { echo "$hits"; return 0; }
  return 1
}

scan_receipt_fields() { # <UsageReceipts.sol> ; prints the struct body, returns 0 iff it drifted
  local f="$1" body expected
  [ -e "$f" ] || { echo "missing $f"; return 0; }
  body=$(code_only "$f" | awk '/struct Receipt[[:space:]]*\{/{on=1;next} on&&/\}/{exit} on' | tr -s '[:space:]' ' ' | sed -E 's/^ //; s/ $//')
  expected='bytes32 root; uint64 committedAt; uint64 blockNumber; uint8 schema;'
  [ "$body" != "$expected" ] && { echo "Receipt struct is '$body', expected '$expected'"; return 0; }
  return 1
}

scan_guardian_actions() { # <RegistryGuardian2of3.sol> ; prints drift, returns 0 iff it drifted
  local f="$1" fns expected
  [ -e "$f" ] || { echo "missing $f"; return 0; }
  fns=$(code_only "$f" | awk '/interface IProviderRegistryGuardianActions[[:space:]]*\{/{on=1;next} on&&/^\}/{exit} on' \
        | grep -oE 'function [A-Za-z0-9_]+' | awk '{print $2}' | sort | tr '\n' ' ' | sed -E 's/ $//')
  expected='emergencyDelist pause veto'
  [ "$fns" != "$expected" ] && { echo "guardian actions are '$fns', expected '$expected'"; return 0; }
  return 1
}

run_scan() { # <root>
  local root="$1" amc="$1/contracts/src/amc" fail=0 out
  if out=$(scan_value_paths "$amc"); then echo "A1 FAIL: value path in src/amc:"; echo "$out"; fail=1; fi
  if out=$(scan_registry_strings "$amc/ProviderRegistry.sol"); then
    echo "A2 FAIL (RT-3): ProviderRegistry mentions a string beyond providerIdOf:"; echo "$out"; fail=1
  fi
  if out=$(scan_receipt_fields "$amc/UsageReceipts.sol"); then echo "A3 FAIL (RT-4): $out"; fail=1; fi
  if out=$(scan_guardian_actions "$amc/RegistryGuardian2of3.sol"); then echo "A4 FAIL (Q-8b): $out"; fail=1; fi
  [ "$fail" -eq 0 ] && echo "amc tripwires: A1 A2 A3 A4 clean"
  return "$fail"
}

self_test() {
  local tmp rc=0
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/amc-tripwire-selftest.XXXXXX")
  mkdir -p "$tmp/contracts/src/amc"
  cp "$REPO_ROOT"/contracts/src/amc/*.sol "$tmp/contracts/src/amc/"
  run_scan "$tmp" >/dev/null || { echo "self-test: clean copy did not pass"; rc=1; }

  printf 'contract X { function f() external payable {} }\n' > "$tmp/contracts/src/amc/Bad.sol"
  scan_value_paths "$tmp/contracts/src/amc" >/dev/null || { echo "self-test: A1 missed payable"; rc=1; }
  printf 'contract X { function f(address a) external { (bool ok,) = a.call{value: 1}(""); ok; } }\n' > "$tmp/contracts/src/amc/Bad.sol"
  scan_value_paths "$tmp/contracts/src/amc" >/dev/null || { echo "self-test: A1 missed call{value}"; rc=1; }
  printf 'contract X { receive() external {} }\n' > "$tmp/contracts/src/amc/Bad.sol"
  scan_value_paths "$tmp/contracts/src/amc" >/dev/null || { echo "self-test: A1 missed receive"; rc=1; }
  rm "$tmp/contracts/src/amc/Bad.sol"

  printf '    mapping(bytes32 => string[]) private _hosts;\n' >> "$tmp/contracts/src/amc/ProviderRegistry.sol"
  scan_registry_strings "$tmp/contracts/src/amc/ProviderRegistry.sol" >/dev/null || { echo "self-test: A2 missed a host store"; rc=1; }

  sed -i.bak -E 's/uint8 schema;/uint8 schema;\n        uint32 count;/' "$tmp/contracts/src/amc/UsageReceipts.sol"
  scan_receipt_fields "$tmp/contracts/src/amc/UsageReceipts.sol" >/dev/null || { echo "self-test: A3 missed a count field"; rc=1; }

  sed -i.bak -E 's/function pause\(uint16 reasonCode\) external;/function pause(uint16 reasonCode) external;\
    function proposeListing(bytes32 id, uint8 kind, bytes32 h, bytes32 p) external;/' "$tmp/contracts/src/amc/RegistryGuardian2of3.sol"
  scan_guardian_actions "$tmp/contracts/src/amc/RegistryGuardian2of3.sol" >/dev/null || { echo "self-test: A4 missed an added action"; rc=1; }

  rm -r "$tmp"
  [ "$rc" -eq 0 ] && echo "amc tripwire self-test: A1 A2 A3 A4 detect their class"
  return "$rc"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") run_scan "$REPO_ROOT" ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
