#!/usr/bin/env bash
# install-hooks.sh — wire local-ci.sh into git so the gate runs without being
# remembered.
#
# Installs a pre-push hook that runs `local-ci.sh --fast` (fmt + clippy +
# unwrap ratchet, ~1 min). Push with scripts/ci/push.sh: it runs the same
# gates BEFORE git connects to the remote, then the hook sees the recorded
# pass and returns at once. A bare `git push` still works, but runs CI while
# the ssh connection sits idle; see push.sh for why that can lose the push. The full suite is deliberately NOT in the hook: a
# multi-minute pre-push gets bypassed with --no-verify within a week, and a
# gate people route around is worse than no gate. Run the full one before a
# merge:
#
#   scripts/ci/local-ci.sh
#
# Bypass a single push (be honest with yourself about why):
#
#   git push --no-verify
#
# Uninstall:
#
#   rm .git/hooks/pre-push
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK_DIR="$(git -C "$REPO_ROOT" rev-parse --git-path hooks)"
HOOK="$HOOK_DIR/pre-push"

mkdir -p "$HOOK_DIR"

if [ -e "$HOOK" ] && ! grep -q "local-ci.sh" "$HOOK" 2>/dev/null; then
  cp "$HOOK" "$HOOK.bak-$(date +%Y%m%d-%H%M%S)"
  echo "existing pre-push hook backed up"
fi

cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# Installed by scripts/ci/install-hooks.sh — runs the fast local CI gates.
# GitHub Actions are dead org-wide; this is the gate that actually runs.
#
# git runs this hook AFTER connecting to the remote, and the connection sits
# idle while CI runs. Prefer scripts/ci/push.sh, which runs CI first; the
# push it then makes finds the recorded pass here and returns at once.
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
URL="${2:-}"

# Read the whole ref list git writes on stdin before anything slow, and keep
# the commits being pushed (deletions are all zeros).
PUSHED=()
while read -r _lref lsha _rref _rsha; do
  case "$lsha" in *[!0]*) PUSHED+=("$lsha") ;; esac
done
exec </dev/null

[ -x "$ROOT/scripts/ci/local-ci.sh" ] || exit 0
STAMP="$ROOT/scripts/ci/local-ci-stamp.sh"

if [ "${#PUSHED[@]}" -eq 0 ]; then
  exit 0   # deletions only: nothing to check
fi
if [ -x "$STAMP" ] && "$STAMP" check "${PUSHED[@]}" 2>/dev/null; then
  echo "pre-push: local CI already passed for ${PUSHED[0]:0:12} (tree unchanged); not re-running."
  exit 0
fi

echo "pre-push: running local CI (--fast). Bypass with --no-verify."
start=$(date +%s)
"$ROOT/scripts/ci/local-ci.sh" --fast
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ $rc -ne 0 ]; then
  echo
  echo "pre-push BLOCKED: local CI failed. Fix, or push with --no-verify."
  exit $rc
fi
[ -x "$STAMP" ] && "$STAMP" record

# A network remote may have dropped the idle connection while CI ran. If it
# did, git exits 141 (SIGPIPE) right after this hook with nothing pushed and
# no message of its own, so say what happened now. The pass is recorded, so
# the re-push does not run CI again.
case "$URL" in
  /*|./*|../*|file://*|http://*|https://*) remote_kind=local-or-http ;;
  *) remote_kind=ssh ;;
esac
max="${LOCAL_CI_HOOK_MAX_SECS:-__MAX_SECS__}"
if [ "$remote_kind" = ssh ] && [ "$elapsed" -gt "$max" ]; then
  echo
  echo "pre-push: local CI passed in ${elapsed}s with the connection to the remote"
  echo "  idle. If git now exits 141, the remote dropped it and NOTHING was pushed:"
  echo "  re-run the push (CI is recorded as passed for this commit and is not"
  echo "  re-run). To avoid this, push with scripts/ci/push.sh."
fi
exit 0
HOOKEOF

chmod +x "$HOOK"
echo "installed: $HOOK"
echo "  runs: scripts/ci/local-ci.sh --fast on every push"
echo "  full suite: scripts/ci/local-ci.sh"
