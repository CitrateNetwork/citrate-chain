#!/usr/bin/env bash
# forge_script_tripwire.sh — two fences for Forge scripts under contracts/script/.
#
#   forge-chainid-profile      A script that BRANCHES on `block.chainid` (compares it: ==, !=,
#                              <, >) must resolve the chain through the shared node check,
#                              GenesisProfile._resolveChainProfile (contracts/script/lib/
#                              GenesisProfile.sol). Forge's simulated chain id is set by the
#                              operator (`--chain-id`, `--chain`, FOUNDRY_CHAIN_ID) independently
#                              of the node it broadcasts to, so a bare `block.chainid` test can be
#                              steered onto the wrong profile — past a "not on 40204" guard, or
#                              off the genesis floors — while the run still lands on 40204.
#                              `_resolveChainProfile` asks the node (eth_chainId) and refuses a
#                              mismatch. Logging `block.chainid` is fine; only comparisons count.
#                              A file that calls `_resolveChainProfile(` anywhere is accepted.
#
#   forge-script-address-this  `address(this)` on a Forge script run path. `forge test` accepts
#                              it, but `forge script --broadcast` refuses to use the script
#                              contract's address (it exists only in the simulation), so the
#                              ceremony fails at broadcast time after a green test run. Use the
#                              configured deployer / the broadcaster instead.
#
# Comments (// and /* */) and string contents are stripped before matching (tw_strip_c). Scope: contracts/script/**/*.sol.
#
# Usage: forge_script_tripwire.sh              # scan the tree
#        forge_script_tripwire.sh --self-test  # prove both fences still detect their class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

script_files() { tw_files "$1" | grep -E '^contracts/script/.*\.sol$' || true; }

# Comment-stripped source, one output line per input line: "path:line: code".
strip_comments() { # <root>
  (cd "$1" && script_files . | xargs -r -d '\n' bash -c '. "$0"; tw_strip_c "$@"' "$HERE/lib/tripwire_common.sh") || true
}

scan_chainid() { # <root>
  local code; code="$(strip_comments "$1")"
  local resolved
  resolved="$(echo "$code" | grep -E '_resolveChainProfile\(' | cut -d: -f1 | sort -u)"
  echo "$code" | grep -E 'block\.chainid[[:space:]]*(==|!=|<=?|>=?)|(==|!=|<=?|>=?)[[:space:]]*block\.chainid' \
    | while IFS= read -r h; do
        f="${h%%:*}"
        grep -qxF "$f" <<<"$resolved" && continue
        echo "$h" | sed -E 's/: +/: /'
      done
  return 0
}

scan_address_this() { # <root>
  strip_comments "$1" | grep -E 'address\(this\)' | sed -E 's/: +/: /'
  return 0
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/p/contracts/script" "$d/n/contracts/script/lib" "$d/q/contracts/script" "$d/r/contracts/script"
  cp "$FIXTURES/forge-chainid-profile/positive.s.sol" "$d/p/contracts/script/"
  cp "$FIXTURES/forge-chainid-profile/negative.s.sol" "$d/n/contracts/script/"
  cp "$FIXTURES/forge-chainid-profile/negative_profile.sol" "$d/n/contracts/script/lib/GenesisProfile.sol"
  tw_selftest_case "forge-chainid-profile positive" hit scan_chainid "$d/p" || rc=1
  [ "$(scan_chainid "$d/p" | wc -l)" -eq 3 ] || { echo "self-test: forge-chainid-profile missed a comparison form"; rc=1; }
  tw_selftest_case "forge-chainid-profile negative" clean scan_chainid "$d/n" || rc=1
  tw_selftest_allow "forge-chainid-profile allowlist" forge-chainid-profile scan_chainid "$d/p" || rc=1
  cp "$FIXTURES/forge-script-address-this/positive.s.sol" "$d/q/contracts/script/"
  cp "$FIXTURES/forge-script-address-this/negative.s.sol" "$d/r/contracts/script/"
  tw_selftest_case "forge-script-address-this positive" hit scan_address_this "$d/q" || rc=1
  tw_selftest_case "forge-script-address-this negative" clean scan_address_this "$d/r" || rc=1
  tw_selftest_allow "forge-script-address-this allowlist" forge-script-address-this scan_address_this "$d/q" || rc=1
  [ $rc -eq 0 ] && echo "forge-script tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
rc=0
scan_chainid "$REPO_ROOT" | tw_report forge-chainid-profile "$ALLOW" \
  'inherit GenesisProfile and branch on _resolveChainProfile(..), not on block.chainid alone' || rc=$?
scan_address_this "$REPO_ROOT" | tw_report forge-script-address-this "$ALLOW" \
  'use the configured deployer or the broadcaster, never the script contract address' || { r=$?; [ $r -gt $rc ] && rc=$r; }
exit $rc
