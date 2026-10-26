#!/usr/bin/env bash
# test_pre_push_hook.sh — end-to-end test of the pre-push hook that
# install-hooks.sh writes, and of scripts/ci/push.sh.
#
# Every case pushes from a throwaway clone to a throwaway bare remote and
# checks the remote with `git ls-remote`, never the push's own output.
#
# The ssh transport is simulated: GIT_SSH_COMMAND points at a stand-in that
# runs git-receive-pack locally under `timeout`, so the "server" drops the
# connection once it has been open for FAKE_SSH_IDLE seconds. That is how a
# remote behaves when a long pre-push hook keeps the connection idle: git
# finishes the hook, writes the pack into a closed pipe, and dies of SIGPIPE
# (exit 141).
#
# local-ci.sh is replaced by a stand-in whose exit code and duration the test
# controls; the real hook, install-hooks.sh, push.sh and local-ci-stamp.sh are
# copied in unchanged.
#
# Nothing outside the temp dir is touched: HOME and the git config are
# overridden and the temp dir is removed by exact path on exit.
#
# Usage: scripts/ci/test_pre_push_hook.sh      exit 0 = all cases pass
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/prepush-test.XXXXXX")"
[ -n "$TMP" ] && [ -d "$TMP" ] || { echo "mktemp failed" >&2; exit 2; }
cleanup() { [ -n "${TMP:-}" ] && [ -d "$TMP" ] && rm -rf -- "$TMP"; }
trap cleanup EXIT

export HOME="$TMP/home"
export GIT_CONFIG_GLOBAL="$TMP/home/.gitconfig"
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
mkdir -p "$HOME"
git config --global user.name test
git config --global user.email test@example.invalid
git config --global init.defaultBranch main
git config --global advice.detachedHead false

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

# Stand-in ssh: `fake-ssh [opts] <host> <command>`. Runs the command locally,
# killed after FAKE_SSH_IDLE seconds, like a server dropping an idle session.
FAKE_SSH="$TMP/bin/fake-ssh"
mkdir -p "$TMP/bin"
cat > "$FAKE_SSH" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 1 ]; do
  case "$1" in -*) shift ;; *) break ;; esac
done
shift                                  # host
exec timeout "${FAKE_SSH_IDLE:-3600}" sh -c "$*"
EOF
chmod +x "$FAKE_SSH"
export GIT_SSH_COMMAND="$FAKE_SSH"

# Stand-in local-ci.sh: sleeps STANDIN_SLEEP, exits STANDIN_RC, counts its runs.
write_standin() {
  cat > "$1/scripts/ci/local-ci.sh" <<'EOF'
#!/usr/bin/env bash
echo run >> "$STANDIN_COUNT"
sleep "${STANDIN_SLEEP:-0}"
if [ "${STANDIN_RC:-0}" -eq 0 ]; then echo "LOCAL CI PASSED"; else echo "LOCAL CI FAILED"; fi
exit "${STANDIN_RC:-0}"
EOF
  chmod +x "$1/scripts/ci/local-ci.sh"
}

# The hook install-hooks.sh wrote before this fix, verbatim. Used by the
# negative control to prove the harness reproduces the reported failure.
write_legacy_hook() {
  cat > "$1/.git/hooks/pre-push" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
[ -x "$ROOT/scripts/ci/local-ci.sh" ] || exit 0
echo "pre-push: running local CI (--fast). Bypass with --no-verify."
"$ROOT/scripts/ci/local-ci.sh" --fast
rc=$?
if [ $rc -ne 0 ]; then
  echo
  echo "pre-push BLOCKED: local CI failed. Fix, or push with --no-verify."
fi
exit $rc
EOF
  chmod +x "$1/.git/hooks/pre-push"
}

N=0
# new_case <name> → sets REPO, BARE, URL, STANDIN_COUNT; installs the real hook.
new_case() {
  N=$((N + 1))
  local d="$TMP/case$N"
  echo "case $N: $1"
  BARE="$d/remote.git"; REPO="$d/work"; URL="ssh://fake-host$BARE"
  git init -q --bare "$BARE"
  git init -q "$REPO"
  mkdir -p "$REPO/scripts/ci"
  local f
  for f in install-hooks.sh push.sh local-ci-stamp.sh; do
    [ -f "$SRC/$f" ] && cp "$SRC/$f" "$REPO/scripts/ci/$f"
  done
  write_standin "$REPO"
  echo one > "$REPO/file.txt"
  git -C "$REPO" add -A
  git -C "$REPO" commit -q -m one
  git -C "$REPO" remote add origin "$URL"
  # Seed the remote without hooks so later cases have something to compare.
  git -C "$REPO" push -q --no-verify origin main 2>/dev/null
  echo two > "$REPO/file.txt"
  git -C "$REPO" commit -q -am two
  STANDIN_COUNT="$d/ci-runs"; : > "$STANDIN_COUNT"; export STANDIN_COUNT
  if [ -f "$REPO/scripts/ci/install-hooks.sh" ]; then
    (cd "$REPO" && bash scripts/ci/install-hooks.sh >/dev/null)
  fi
}

remote_sha() { git -C "$REPO" ls-remote "$URL" refs/heads/main | awk '{print $1}'; }
head_sha()   { git -C "$REPO" rev-parse HEAD; }
ci_runs()    { wc -l < "$STANDIN_COUNT" | tr -d ' '; }
landed()     { [ "$(remote_sha)" = "$(head_sha)" ]; }

push() {        # push <git push args...> → sets RC, OUT
  OUT="$(cd "$REPO" && git push "$@" 2>&1)"; RC=$?
}
wrapper() {     # wrapper <push.sh args...> → sets RC, OUT
  if [ ! -x "$REPO/scripts/ci/push.sh" ]; then
    RC=127; OUT="scripts/ci/push.sh missing"; return
  fi
  OUT="$(cd "$REPO" && scripts/ci/push.sh "$@" 2>&1)"; RC=$?
}

# ── negative control: the harness reproduces the reported failure ─────────
new_case "negative control: legacy hook + CI longer than the idle cutoff"
write_legacy_hook "$REPO"
FAKE_SSH_IDLE=2 STANDIN_SLEEP=4 STANDIN_RC=0 push origin main
if [ "$RC" -eq 141 ] && ! landed && grep -q "LOCAL CI PASSED" <<<"$OUT"; then
  ok "legacy hook prints LOCAL CI PASSED, push exits 141, remote unchanged"
else
  bad "harness did not reproduce the failure (rc=$RC landed=$(landed && echo y || echo n))"
fi

# ── rule out the stdin theory: git ignores a hook that never reads stdin ───
new_case "control: hook that never reads a >64KiB ref list on stdin"
write_legacy_hook "$REPO"
for i in $(seq 1 900); do echo "$(head_sha) refs/tags/t-padding-padding-padding-padding-$i"; done \
  | git -C "$REPO" update-ref --stdin 2>/dev/null \
  || for i in $(seq 1 900); do git -C "$REPO" tag "t-padding-padding-padding-padding-$i"; done
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=0 push origin main --tags
if [ "$RC" -eq 0 ] && landed; then
  ok "push lands (exit 0): an undrained stdin does not SIGPIPE git"
else
  bad "undrained stdin broke the push (rc=$RC)"
fi

# ── the installed hook ─────────────────────────────────────────────────────
new_case "hook: CI passes quickly"
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=0 push origin main
if [ "$RC" -eq 0 ] && landed && [ "$(ci_runs)" -eq 1 ]; then
  ok "push lands, CI ran once"
else
  bad "rc=$RC landed=$(landed && echo y || echo n) runs=$(ci_runs)"
fi

new_case "hook: CI fails"
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=1 push origin main
if [ "$RC" -ne 0 ] && ! landed && grep -q "pre-push BLOCKED" <<<"$OUT"; then
  ok "push refused, remote unchanged, BLOCKED message shown"
else
  bad "rc=$RC landed=$(landed && echo y || echo n)"
fi
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=0 push origin main
if [ "$RC" -eq 0 ] && landed && [ "$(ci_runs)" -eq 2 ]; then
  ok "a failed run records nothing: the next push runs CI again"
else
  bad "after a failure: rc=$RC runs=$(ci_runs)"
fi

new_case "hook: local-ci.sh absent"
rm -f "$REPO/scripts/ci/local-ci.sh"
FAKE_SSH_IDLE=60 push origin main
if [ "$RC" -eq 0 ] && landed; then ok "push lands (hook is a no-op)"; else bad "rc=$RC"; fi

new_case "hook: CI passes but outlasts the connection"
FAKE_SSH_IDLE=2 LOCAL_CI_HOOK_MAX_SECS=1 STANDIN_SLEEP=4 STANDIN_RC=0 push origin main
if [ "$RC" -ne 141 ] && [ "$RC" -ne 0 ] && ! landed && grep -q "re-run the push" <<<"$OUT"; then
  ok "no silent SIGPIPE: the hook stops the push and says why (rc=$RC)"
else
  bad "rc=$RC landed=$(landed && echo y || echo n) (141 = the original bug)"
fi
FAKE_SSH_IDLE=2 LOCAL_CI_HOOK_MAX_SECS=1 STANDIN_SLEEP=4 STANDIN_RC=0 push origin main
if [ "$RC" -eq 0 ] && landed && [ "$(ci_runs)" -eq 1 ]; then
  ok "the re-push lands without re-running CI (pass recorded for this commit)"
else
  bad "re-push: rc=$RC landed=$(landed && echo y || echo n) runs=$(ci_runs)"
fi

new_case "hook: a recorded pass does not cover a changed tree"
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=0 push origin main
echo dirty >> "$REPO/file.txt"
git -C "$REPO" commit -q -am three
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=1 push origin main
if [ "$RC" -ne 0 ] && [ "$(ci_runs)" -eq 2 ] && [ "$(remote_sha)" != "$(head_sha)" ]; then
  ok "new commit: CI re-runs and its failure blocks the push"
else
  bad "new commit: rc=$RC runs=$(ci_runs)"
fi
echo four >> "$REPO/file.txt"
git -C "$REPO" commit -q -am four
(cd "$REPO" && scripts/ci/local-ci-stamp.sh record) >/dev/null 2>&1
echo edit-after-pass >> "$REPO/file.txt"
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=1 push origin main
if [ "$RC" -ne 0 ] && [ "$(ci_runs)" -eq 3 ]; then
  ok "uncommitted edit after a pass: CI re-runs (the pass covered a different tree)"
else
  bad "dirty tree: rc=$RC runs=$(ci_runs)"
fi

# ── scripts/ci/push.sh: CI first, then a short push ────────────────────────
new_case "push.sh: CI passes but takes longer than the idle cutoff"
FAKE_SSH_IDLE=2 STANDIN_SLEEP=4 STANDIN_RC=0 wrapper origin main
if [ "$RC" -eq 0 ] && landed && [ "$(ci_runs)" -eq 1 ]; then
  ok "push lands; CI ran once, before the connection opened"
else
  bad "rc=$RC landed=$(landed && echo y || echo n) runs=$(ci_runs): $OUT"
fi

new_case "push.sh: CI fails"
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=1 wrapper origin main
if [ "$RC" -ne 0 ] && ! landed; then
  ok "push refused, remote unchanged"
else
  bad "rc=$RC landed=$(landed && echo y || echo n)"
fi

new_case "push.sh: reports a push that did not land"
chmod -R a-w "$BARE/objects" 2>/dev/null
FAKE_SSH_IDLE=60 STANDIN_SLEEP=0 STANDIN_RC=0 wrapper origin main
chmod -R u+w "$BARE/objects" 2>/dev/null
if [ "$(id -u)" -eq 0 ]; then
  ok "skipped (root ignores the read-only remote)"
elif [ "$RC" -ne 0 ] && ! landed && grep -q "PUSH FAILED" <<<"$OUT"; then
  ok "nonzero exit and PUSH FAILED, remote unchanged"
else
  bad "rc=$RC landed=$(landed && echo y || echo n)"
fi

echo
echo "pre-push hook tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
