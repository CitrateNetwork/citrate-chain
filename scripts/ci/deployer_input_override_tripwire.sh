#!/usr/bin/env bash
# deployer_input_override_tripwire.sh: the deployer address the deploy scripts derive
# parameters from (treasury and fee recipients, initial owners) has one source.
#
#   1. contracts/script/ScriptEnv.sol deployerAddress() refuses two deployer inputs that name
#      different addresses, and a set input that is not a non-zero address.
#   2. No other contracts/script/**/*.sol reads CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS
#      from the environment directly (that would bypass 1); use deployerAddress().
#   3. No shell script under scripts/ keeps a preset deployer alias (CEREMONY_DEPLOYER_ADDRESS,
#      EMIT_DEPLOYER) in preference to the primary, e.g. X="${X:-$DEPLOYER_ADDRESS}", unless the
#      line carries "# deployer-alias-checked" because the script compared the preset with the
#      primary first.
#
# Usage: deployer_input_override_tripwire.sh [--self-test]
# Exit: 0 clean · 1 violation (or the self-test found the engine blind)
set -uo pipefail

scan() { # root -> prints violations, exit 1 if any
  local root="$1" hits="" se="$1/contracts/script/ScriptEnv.sol" h
  if [[ ! -f "$se" ]] || ! grep -q 'name different deployers' "$se" || ! grep -q 'is set but is not an address' "$se"; then
    hits+="contracts/script/ScriptEnv.sol: deployerAddress() lost the different-deployers / malformed-input guard"$'\n'
  fi
  if [[ -d "$root/contracts/script" ]]; then
    # A presence check (envExists) reads no value; anything else that names the inputs does.
    h=$(grep -rn --include='*.sol' -E 'env[A-Za-z]*\(' "$root/contracts/script" | grep -v '/ScriptEnv\.sol:' |
      sed -E 's/envExists\(\s*"[A-Z_]+"\s*\)//g' |
      grep -E '\benv[A-Za-z]*\(\s*"(CEREMONY_DEPLOYER_ADDRESS|DEPLOYER_ADDRESS)"' || true)
    [[ -z "$h" ]] || hits+="direct deployer env read outside ScriptEnv (use deployerAddress()):"$'\n'"$h"$'\n'
  fi
  if [[ -d "$root/scripts" ]]; then
    h=$(grep -rnE --include='*.sh' '(CEREMONY_DEPLOYER_ADDRESS|EMIT_DEPLOYER)=["'"'"']?\$\{(CEREMONY_DEPLOYER_ADDRESS|EMIT_DEPLOYER)(:?-|:=)|:\s+"?\$\{(CEREMONY_DEPLOYER_ADDRESS|EMIT_DEPLOYER):=' "$root/scripts" |
      grep -v '# deployer-alias-checked' | grep -v '/deployer_input_override_tripwire\.sh:' || true)
    [[ -z "$h" ]] || hits+="a preset deployer alias kept without comparing it to DEPLOYER_ADDRESS:"$'\n'"$h"$'\n'
  fi
  if [[ -n "$hits" ]]; then
    printf 'DEPLOYER-INPUT VIOLATION:\n%s' "$hits" >&2
    return 1
  fi
}

if [[ "${1:-}" == --self-test ]]; then
  t=$(mktemp -d) || exit 1
  trap 'rm -rf "${t:?}"' EXIT
  fixture() { # dir: a clean tree
    mkdir -p "$1/contracts/script" "$1/scripts/ops"
    printf '%s\n' '// "CEREMONY_DEPLOYER_ADDRESS and DEPLOYER_ADDRESS name different deployers"' \
      '// string.concat(key, " is set but is not an address")' >"$1/contracts/script/ScriptEnv.sol"
    printf '%s\n' 'address d = deployerAddress();' >"$1/contracts/script/DeployX.s.sol"
    printf '%s\n' 'export CEREMONY_DEPLOYER_ADDRESS="$DEPLOYER_ADDRESS"' >"$1/scripts/ops/run.sh"
  }
  fail=0
  fixture "$t/clean"
  scan "$t/clean" 2>/dev/null || { echo "self-test: a clean tree was flagged" >&2; fail=1; }
  # Each bad fixture must be caught.
  fixture "$t/a"; : >"$t/a/contracts/script/ScriptEnv.sol"
  fixture "$t/b"; printf '%s\n' 'address d = vm.envAddress("CEREMONY_DEPLOYER_ADDRESS");' >>"$t/b/contracts/script/DeployX.s.sol"
  fixture "$t/c"; printf '%s\n' 'address d = envAddressOr("DEPLOYER_ADDRESS", address(0));' >>"$t/c/contracts/script/DeployX.s.sol"
  fixture "$t/d"; printf '%s\n' 'export CEREMONY_DEPLOYER_ADDRESS="${CEREMONY_DEPLOYER_ADDRESS:-$DEPLOYER_ADDRESS}"' >>"$t/d/scripts/ops/run.sh"
  fixture "$t/e"; printf '%s\n' 'EMIT_DEPLOYER=${EMIT_DEPLOYER-$DEPLOYER_ADDRESS}' >>"$t/e/scripts/ops/run.sh"
  fixture "$t/f"; printf '%s\n' ': "${CEREMONY_DEPLOYER_ADDRESS:=$DEPLOYER_ADDRESS}"' >>"$t/f/scripts/ops/run.sh"
  fixture "$t/h"; printf '%s\n' 'if (vm.envExists("DEPLOYER_ADDRESS")) { d = vm.envOr("DEPLOYER_ADDRESS", d); }' >>"$t/h/contracts/script/DeployX.s.sol"
  for c in a b c d e f h; do
    scan "$t/$c" 2>/dev/null && { echo "self-test: bad fixture $c was not flagged" >&2; fail=1; }
  done
  # The reviewed-escape marker is honoured.
  fixture "$t/g"; printf '%s\n' 'export CEREMONY_DEPLOYER_ADDRESS="${CEREMONY_DEPLOYER_ADDRESS:-$DEPLOYER_ADDRESS}" # deployer-alias-checked' >>"$t/g/scripts/ops/run.sh"
  scan "$t/g" 2>/dev/null || { echo "self-test: a marked line was flagged" >&2; fail=1; }
  fixture "$t/i"; printf '%s\n' 'bool set = vm.envExists("CEREMONY_DEPLOYER_ADDRESS") || vm.envExists("DEPLOYER_ADDRESS");' >>"$t/i/contracts/script/DeployX.s.sol"
  scan "$t/i" 2>/dev/null || { echo "self-test: a presence check was flagged" >&2; fail=1; }
  [[ $fail -eq 0 ]] && echo "deployer-input tripwire self-test: PASS"
  exit "$fail"
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
scan "$ROOT" || exit 1
echo "deployer-input tripwire: PASS (one deployer source; no preset alias kept unchecked)"
