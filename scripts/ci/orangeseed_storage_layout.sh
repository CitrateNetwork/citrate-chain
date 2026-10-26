#!/usr/bin/env bash
# orangeseed_storage_layout.sh: fence storage-layout drift in the OrangeSeed predeploy.
#
# OrangeSeed sits in the genesis allocation with its storage written directly into
# block 0, and every later version is an upgrade over that storage. Two things must
# not drift:
#   1. `forge inspect … storageLayout` of OrangeSeedV0 equals the committed snapshot.
#      Today it is EMPTY: all state lives in the ERC-7201 namespace, so any plain state
#      variable (which would land in slot 0 and could collide with a future version)
#      shows up here as a diff.
#   2. The namespace: the `erc7201:citrate.storage.OrangeSeed` annotation is present and
#      SEED_STORAGE_LOCATION equals the ERC-7201 formula for that id.
# The order of the fields inside the namespace is pinned by the forge test
# `test_storageLayout_rawSlots` (contracts/test/genesis/OrangeSeed.t.sol).
#
# Usage: orangeseed_storage_layout.sh              # check the tree (needs forge + cast)
#        orangeseed_storage_layout.sh --self-test  # prove the comparison detects drift
#        orangeseed_storage_layout.sh --update     # rewrite the snapshot (review the diff!)
set -uo pipefail

REPO_ROOT="${ORANGESEED_LAYOUT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CONTRACTS="$REPO_ROOT/contracts"
SRC="src/genesis/OrangeSeedV0.sol"
TARGET="$SRC:OrangeSeedV0"
SNAPSHOT="$CONTRACTS/test/genesis/snapshots/OrangeSeedV0.storage-layout.json"
NAMESPACE="citrate.storage.OrangeSeed"

# Normalise a storageLayout JSON to label/slot/offset/type lines (AST ids and file
# paths are not layout).
normalise() { # <json-file>
  python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
rows = sorted((s["slot"], s["offset"], s["label"], s["type"]) for s in d.get("storage", []))
for r in rows:
    print("slot=%s offset=%s label=%s type=%s" % r)
print("entries=%d" % len(rows))
' "$1"
}

compare() { # <actual-json> <snapshot-json> ; returns 0 iff identical
  diff <(normalise "$2") <(normalise "$1")
}

erc7201() { # <namespace id> ; prints the ERC-7201 slot
  local h m
  h="$(cast keccak "$1")" || return 1
  m="$(python3 -I -c 'import sys; print(hex(int(sys.argv[1], 16) - 1))' "$h")"
  python3 -I -c 'import sys; print("0x%064x" % (int(sys.argv[1], 16) & ~0xff))' \
    "$(cast keccak "$(cast abi-encode 'f(uint256)' "$m")")"
}

check_namespace() { # <solidity file>
  local want got
  grep -q "@custom:storage-location erc7201:$NAMESPACE\$" "$1" \
    || { echo "missing '@custom:storage-location erc7201:$NAMESPACE' in $1"; return 1; }
  want="$(erc7201 "$NAMESPACE")" || { echo "cast keccak failed"; return 1; }
  got="$(tr -d ' \n' < "$1" | grep -o 'SEED_STORAGE_LOCATION=0x[0-9a-fA-F]\{64\}' | cut -d= -f2)"
  [ "$(echo "$got" | tr 'A-F' 'a-f')" = "$want" ] \
    || { echo "SEED_STORAGE_LOCATION is '$got', ERC-7201($NAMESPACE) is $want"; return 1; }
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  echo '{"storage":[],"types":{}}' > "$d/empty.json"
  echo '{"storage":[{"astId":1,"contract":"x","label":"owner","offset":0,"slot":"0","type":"t_address"}],"types":{}}' > "$d/drift.json"
  echo '{"storage":[],"types":{"t_x":{}}}' > "$d/types-only.json"
  compare "$d/empty.json" "$d/empty.json" >/dev/null || { echo "self-test: identical layouts compared unequal"; rc=1; }
  compare "$d/types-only.json" "$d/empty.json" >/dev/null || { echo "self-test: type table noise counted as drift"; rc=1; }
  compare "$d/drift.json" "$d/empty.json" >/dev/null && { echo "self-test: a new slot-0 variable was not detected"; rc=1; }
  # Namespace check: a correct file passes, a wrong constant and a missing annotation fail.
  local good="$CONTRACTS/$SRC"
  check_namespace "$good" >/dev/null || { echo "self-test: the real source fails the namespace check"; rc=1; }
  python3 -I -c 'import re,sys; s=sys.stdin.read(); print(re.sub(r"(SEED_STORAGE_LOCATION =\s*)0x[0-9a-fA-F]{64}", r"\g<1>0x" + "11"*32, s))' \
    < "$good" > "$d/bad-slot.sol"
  check_namespace "$d/bad-slot.sol" >/dev/null && { echo "self-test: a wrong namespace constant was not detected"; rc=1; }
  grep -v '@custom:storage-location' "$good" > "$d/no-annotation.sol"
  check_namespace "$d/no-annotation.sol" >/dev/null && { echo "self-test: a missing annotation was not detected"; rc=1; }
  [ "$rc" -eq 0 ] && echo "orangeseed-storage-layout self-test: ok"
  return "$rc"
}

run() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  (cd "$CONTRACTS" && forge inspect "$TARGET" storageLayout --json) > "$d/actual.json" \
    || { echo "forge inspect failed"; return 1; }
  if [ "${1:-}" = "--update" ]; then
    cp "$d/actual.json" "$SNAPSHOT"; echo "updated $SNAPSHOT"; return 0
  fi
  compare "$d/actual.json" "$SNAPSHOT" \
    || { echo "OrangeSeedV0 storage layout drifted from $SNAPSHOT (keep state in the ERC-7201 namespace)"; rc=1; }
  check_namespace "$CONTRACTS/$SRC" || rc=1
  [ "$rc" -eq 0 ] && echo "orangeseed-storage-layout: ok"
  return "$rc"
}

case "${1:-}" in
  --self-test) self_test ;;
  --update) run --update ;;
  "") run ;;
  *) echo "usage: $0 [--self-test|--update]" >&2; exit 2 ;;
esac
