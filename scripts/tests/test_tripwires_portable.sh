#!/usr/bin/env bash
# The scripts/ci/*_tripwire.sh scans run in the pre-push hook on Linux and macOS, so they may
# only use tools and flags that BSD userlands also have, and a scan that cannot run must fail
# rather than report "clean".
#
#   1. Every tripwire's --self-test passes with a BSD-compatible xargs first on PATH (one that
#      rejects GNU-only flags such as -d / --delimiter / -a, as macOS xargs does).
#   2. No tripwire calls xargs with a GNU-only flag.
#   3. Fail closed: when the file listing returns nothing for a tree that has files, every
#      tree scan exits non-zero instead of printing "clean".
#
# Read-only: the tripwires only read the tree. Shims and HOME live in a mktemp dir.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX:?}"' EXIT
export HOME="$SANDBOX/home"
mkdir -p "$HOME"

TRIPWIRES="forge_script historical_state_read rpc_height_index finalization_publish_order
  shell_safety synthetic_pid_signal tla_frame installer_test_sandbox wallet_gate_signing"

fail=0
pass() { echo "ok   - $1"; }
flunk() { echo "FAIL - $1"; fail=1; }

REAL_XARGS="$(command -v xargs)"
REAL_GIT="$(command -v git)"

# A BSD-flag xargs: accepts only the options macOS/FreeBSD xargs document, exits 1 with a usage
# line on anything else (as BSD xargs does), then hands off to the real xargs.
BSD="$SANDBOX/bsd-bin"; mkdir -p "$BSD"
cat > "$BSD/xargs" <<SHIM
#!/usr/bin/env bash
args=("\$@"); i=0
while [ \$i -lt \${#args[@]} ]; do
  a="\${args[\$i]}"
  case "\$a" in
    -0|-o|-p|-r|-t|-x) ;;
    -E|-I|-J|-L|-n|-P|-R|-S|-s) i=\$((i+1)) ;;
    -[EIJLnPRSs]?*) ;;
    -*) echo "xargs: illegal option -- \${a#-}" >&2; echo "usage: xargs [-0opt] [-E eofstr] ..." >&2; exit 1 ;;
    *) break ;;
  esac
  i=\$((i+1))
done
exec "$REAL_XARGS" "\$@"
SHIM
chmod +x "$BSD/xargs"

# 1. Self-tests under BSD xargs flags.
for t in $TRIPWIRES; do
  s="$ROOT/scripts/ci/${t}_tripwire.sh"
  if out="$(PATH="$BSD:$PATH" "$s" --self-test 2>&1)"; then
    pass "$t self-test passes with BSD xargs flags"
  else
    flunk "$t self-test fails with BSD xargs flags"; echo "$out" | head -5 | sed 's/^/       /'
  fi
done

# 2. No GNU-only xargs flags in the tripwires or their shared library.
hits="$(cd "$ROOT" && grep -nE 'xargs([[:space:]]+-[A-Za-z0-9]+)*[[:space:]]+(-[A-Za-z0-9]*[da]|--[a-z])' \
  scripts/ci/*_tripwire.sh scripts/ci/lib/*.sh 2>/dev/null | grep -vE ':[[:space:]]*#')"
if [ -z "$hits" ]; then pass "no GNU-only xargs flags in scripts/ci tripwires"
else flunk "GNU-only xargs flags in scripts/ci tripwires"; echo "$hits" | sed 's/^/       /'; fi

# 3. Fail closed on an empty file listing for a non-empty tree.
EMPTY="$SANDBOX/empty-bin"; mkdir -p "$EMPTY"
cat > "$EMPTY/git" <<SHIM
#!/usr/bin/env bash
for a in "\$@"; do [ "\$a" = ls-files ] && exit 0; done
exec "$REAL_GIT" "\$@"
SHIM
printf '#!/bin/sh\nexit 0\n' > "$EMPTY/find"
chmod +x "$EMPTY/git" "$EMPTY/find"
for t in $TRIPWIRES; do
  s="$ROOT/scripts/ci/${t}_tripwire.sh"
  out="$(PATH="$EMPTY:$PATH" "$s" 2>&1)"; rc=$?
  if [ $rc -ne 0 ]; then pass "$t fails closed when no files are listed (rc=$rc)"
  else flunk "$t reports '$(echo "$out" | tail -1)' when no files are listed"; fi
done

exit $fail
