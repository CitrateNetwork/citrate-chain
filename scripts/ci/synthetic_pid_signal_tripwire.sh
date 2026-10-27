#!/usr/bin/env bash
# synthetic_pid_signal_tripwire.sh — no real signal to a made-up process id.
#
# A test that hands a hard-coded or synthetic pid to a signal call sends that signal to
# whatever owns the number on the machine running the test: pid 0 is the caller's own process
# group, -1 is every process the user owns, and a value above i32::MAX wraps to a negative pid
# (a whole group). The check flags a signal call whose target pid is a literal number or a
# MAX-derived value:
#
#   Rust/JS/TS/Python  kill / killpg / libc::kill / signal_pid / kill_now / kill_pid /
#                      kill_process / kill_tree / send_signal / process.kill / os.kill /
#                      Pid::from_raw, with a first argument such as 4242, 0, -1,
#                      u32::MAX, i32::MAX as u32 + 1
#   shell              kill [-SIG] <number>
#
# Signal 0 is a liveness probe that delivers nothing, so `kill(N, 0)`, `signal_pid(N, 0)`
# and `kill -0 N` are not flagged. A file that runs its processes inside a private pid
# namespace (`unshare … --pid`, CLONE_NEWPID) is exempt: its numbers cannot reach the host.
# Comments are ignored. Everything else needs a real pid (one the test spawned), a stubbed
# signal, or a reviewed allowlist entry.
#
# Usage: synthetic_pid_signal_tripwire.sh              # scan the tree
#        synthetic_pid_signal_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/signal-synthetic-pid"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root> ; prints "path:line: text" per signal call aimed at a synthetic pid
  (cd "$1" && tw_files . | grep -E '\.(rs|ts|tsx|js|mjs|cjs|py|sh|bash)$' \
     | tw_xargs grep -lE 'kill|signal_pid|from_raw' 2>/dev/null \
     | tw_xargs grep -LE 'unshare\b.*(--pid\b|[[:space:]]-[a-zA-Z]*p[a-zA-Z]*\b)|CLONE_NEWPID' 2>/dev/null \
     | tw_xargs perl -ne '
    BEGIN {
      $NUM = qr/(?:-\s*)?\d[\d_]*(?:\s*as\s+[\w:]+)?/;
      $MAX = qr/(?:(?:libc::)?(?:u32|i32|u64|i64|pid_t|c_int)::MAX|Number\.MAX_SAFE_INTEGER)(?:\s*as\s+[\w:]+)?(?:\s*[-+]\s*\d[\d_]*)?(?:\s*as\s+[\w:]+)?/;
      $FN  = qr/(?<![\w.])(?:libc::|nix::sys::signal::|signal::|process\.|os\.)?(?:kill|killpg|signal_pid|kill_now|kill_pid|kill_process|kill_tree|send_signal)/;
    }
    my $l = $_;
    next if $l =~ m{^\s*(//|#|\*|/\*)};
    $l =~ s{\s//.*$}{};
    my $hit = 0;
    while ($l =~ /$FN\s*\(\s*($MAX|$NUM)\s*(?:,\s*([^,)]+))?\)/g) {
      my $sig = defined $2 ? $2 : "";
      $sig =~ s/^\s+|\s+$//g;
      next if $sig =~ /^(0|0_?i32|0 as [\w:]+|libc::c_int::from\(0\))$/;   # probe: delivers nothing
      $hit = 1;
    }
    $hit = 1 if $l =~ /Pid::from_raw\(\s*(?:$MAX|$NUM)\s*\)/;
    # shell: kill [-SIG …] [--] <number>; a negative number is a pid only after "--".
    if ($ARGV =~ /\.(sh|bash)$/
        && $l =~ /(?:^|[\s;&|(])kill\s+((?:-[A-Za-z0-9]+\s+)*)(--\s+)?(-?\d+)(?=[\s;)|&]|$)/) {
      my ($opts, $dd, $pid) = ($1, $2, $3);
      $hit = 1 unless $opts =~ /(^|\s)-0\s/ || ($pid =~ /^-/ && !$dd);
    }
    if ($hit) { chomp(my $s = $_); $s =~ s/^\s+//; print "$ARGV:$.: $s\n" }
    close ARGV if eof;') || true
}

self_test() {
  local d rc=0 f
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos" "$d/neg"
  for f in "$FIXTURES"/positive*; do cp "$f" "$d/pos/"; done
  for f in "$FIXTURES"/negative*; do cp "$f" "$d/neg/"; done
  tw_selftest_case "signal-synthetic-pid positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "signal-synthetic-pid markers" "$d/pos" scan || rc=1
  tw_selftest_case "signal-synthetic-pid negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "signal-synthetic-pid allowlist" signal-synthetic-pid scan "$d/pos" || rc=1
  tw_selftest_fail_closed "signal-synthetic-pid fail-closed" "$d/pos" scan || rc=1
  [ $rc -eq 0 ] && echo "signal-synthetic-pid tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report signal-synthetic-pid "$ALLOW" \
  'signal only a pid the test spawned, stub the signal, or run inside unshare --pid'
