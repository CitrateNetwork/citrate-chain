#!/usr/bin/env bash
# installer_test_sandbox_tripwire.sh — a test that runs an installer, deploy, ops, ceremony,
# packaging or release script does so in a sandbox.
#
# Such scripts write to $HOME (~/.citrate*, ~/.cargo/env, ~/.foundry), to install prefixes and
# to service directories. A test that runs one with the developer's real HOME can replace or
# delete real files on the machine running the test, and CI on a fresh Linux runner will not
# notice (the paths it damages may only exist on a workstation). So a test file that EXECUTES
# an in-scope script must, in the same file:
#   * point HOME somewhere else (`HOME=…` / `export HOME=…` in shell, `.env("HOME", …)` in
#     Rust, an env mapping with "HOME" in Python / JS), and
#   * create a temporary directory (mktemp, tempfile/TempDir, mkdtemp, tmp_path, os.tmpdir),
# which is where HOME and every other write should point (through the script's explicit
# override variables).
#
# In-scope scripts: a *.sh / *.bash path with an ops/, ceremony/, installers?/, deploy/,
# release/, genesis/, provision/ or packaging/ directory, or a name containing install, deploy,
# ceremony, regenesis, reroll, provision, bootstrap, release or a package-hook name (postinst,
# preinst, prerm, postrm) — the scope of the shell-pipefail fence.
# Test files: shell (*.sh, *.bash, *.bats) under a test/ or tests/ directory or named test_* /
# *_test.*; Python test_*.py / *_test.py / tests/**.py; JS/TS *.test.* / *.spec.* / tests/** /
# __tests__/**; Rust files under a tests/ directory or named *_tests.rs.
# "Executes": shell — the script path, or a variable assigned it, in command position (line
# start, after ; && || | ( $( { `! ` then do else, or after bash/sh/zsh/source/./env/sudo/timeout and
# leading VAR=value assignments); other languages — the file names the script path and uses a
# process API (subprocess, os.system, Command::new, spawn, exec*, execa, child_process).
# A test that only reads a script (grep, a git pathspec) is not flagged.
#
# Limits (text scan): a HOME override that points at the real home, or that covers only some
# of the invocations, satisfies the check; a script reached through a wrapper in another file or
# a path assembled at run time is not seen; Rust #[cfg(test)] modules inside src/ are not
# scanned; PowerShell tests are out of scope.
#
# Usage: installer_test_sandbox_tripwire.sh              # scan the tree
#        installer_test_sandbox_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/installer-test-sandbox"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

TEST_FILES='(^|/)tests?/.*\.(sh|bash|bats|py|ts|tsx|js|mjs|cjs|rs)$|(^|/)__tests__/|(^|/)test_[^/]*\.(sh|bash|py)$|_test\.(sh|bash|py)$|\.bats$|\.(test|spec)\.(ts|tsx|js|mjs|cjs)$|_tests\.rs$'

scan() { # <root> ; prints "path:line: text" per unsandboxed execution of an in-scope script
  (cd "$1" && tw_files . | grep -E "$TEST_FILES" \
     | xargs -r -d '\n' grep -liE '(install|deploy|ceremony|reroll|provision|bootstrap|release|genesis|packaging|/ops/|postinst|preinst|prerm|postrm)[^[:space:]"'\'']*\.(sh|bash)' 2>/dev/null \
     | xargs -r -d '\n' perl -e '
    my $SCOPE = qr{(?:^|/)(?:ops|ceremony|installers?|deploy|release|genesis|provision|packaging)/|(?:^|/)[^/]*(?:install|deploy|ceremony|regenesis|reroll|provision|bootstrap|release|postinst|preinst|prerm|postrm)[^/]*\.(?:sh|bash)$}i;
    my $PATH = qr{[\w.\/\$\{\}:?-]*\.(?:sh|bash)\b};
    my $ASSIGN = qr{[A-Za-z_]\w*=(?:"[^"]*"|\x27[^\x27]*\x27|[^\s;&|]*)\s+};
    my $CMDPOS = qr{(?:^|[;&|(`\{]|(?:^|\s)!\s|\$\(|\b(?:then|do|else|exec|source|time|nohup)\b|(?:^|\s)\.)\s*(?:$ASSIGN)*(?:(?:env|sudo|bash|sh|zsh|dash|timeout\s+\S+)(?:\s+-[-\w]+)*\s+(?:$ASSIGN)*)*$};
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next; my @L = <$fh>; close $fh;
      my $all = join "", @L;
      my $shell = $f =~ /\.(sh|bash|bats)$/;
      my $tmp = $all =~ /\bmktemp\b|\btempfile\b|TempDir|\btempdir\b|mkdtemp|\btmp_path\b|os\.tmpdir|mkdtempSync/;
      my $home = $shell
        ? $all =~ /(?:^|[\s;(&|])(?:export\s+|local\s+|declare\s+(?:-x\s+)?)?HOME=(?!"?\$\{?HOME\b)/m
        : $all =~ /\.env\(\s*"HOME"|["\x27]HOME["\x27]\s*[\]:,]|\bHOME\s*[:=]/;
      next if $tmp && $home;
      my @hits;
      if ($shell) {
        my %var;
        for my $l (@L) {
          next if $l =~ /^\s*#/;
          while ($l =~ /\b([A-Za-z_]\w*)=["\x27]?($PATH)/g) { my ($v, $t) = ($1, $2); $var{$v} = 1 if $t =~ $SCOPE }
        }
        my $vars = join "|", map { quotemeta } keys %var;
        for my $i (0 .. $#L) {
          my $l = $L[$i];
          next if $l =~ /^\s*#/;
          my $hit = 0;
          while ($l =~ /($PATH)/g) {
            my ($tok, $at) = ($1, $-[1]);
            next unless $tok =~ $SCOPE;
            (my $pre = substr($l, 0, $at)) =~ s/["\x27]$//;
            if ($pre =~ $CMDPOS) { $hit = 1; last }
          }
          if (!$hit && $vars ne "") {
            while ($l =~ /(\$\{?(?:$vars)\}?)(?![\w:])/g) {
              (my $pre = substr($l, 0, $-[1])) =~ s/["\x27]$//;
              if ($pre =~ $CMDPOS) { $hit = 1; last }
            }
          }
          push @hits, $i if $hit;
        }
      } elsif ($all =~ /\bsubprocess\b|os\.system|Command::new|\bspawn(?:Sync)?\b|\bexec(?:File|Sync|FileSync)?\s*\(|\bexeca\b|child_process/) {
        for my $i (0 .. $#L) {
          next if $L[$i] =~ m{^\s*(#|//|\*)};
          while ($L[$i] =~ /($PATH)/g) { if ($1 =~ $SCOPE) { push @hits, $i; last } }
        }
      }
      for my $i (@hits) { (my $s = $L[$i]) =~ s/^\s+|\s+$//g; print "$f:", $i + 1, ": $s\n" }
    }') || true
}

self_test() {
  local d rc=0 f
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/scripts/tests" "$d/pos/node/tests" "$d/neg/scripts/tests" "$d/neg/node/tests" "$d/neg/scripts/ops"
  cp "$FIXTURES/positive_test.sh" "$d/pos/scripts/tests/test_install.sh"
  cp "$FIXTURES/positive_installer.rs" "$d/pos/node/tests/installer.rs"
  cp "$FIXTURES/positive_test.py" "$d/pos/scripts/tests/test_release.py"
  cp "$FIXTURES/negative_test.sh" "$d/neg/scripts/tests/test_install.sh"
  cp "$FIXTURES/negative_static_test.sh" "$d/neg/scripts/tests/test_supply_chain.sh"
  cp "$FIXTURES/negative_installer.rs" "$d/neg/node/tests/installer.rs"
  # not a test file: an ops wrapper that runs another ops script is out of scope
  cp "$FIXTURES/positive_test.sh" "$d/neg/scripts/ops/run-all.sh"
  tw_selftest_case "installer-test-sandbox positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "installer-test-sandbox markers" "$d/pos" scan || rc=1
  tw_selftest_case "installer-test-sandbox negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "installer-test-sandbox allowlist" installer-test-sandbox scan "$d/pos" || rc=1
  [ $rc -eq 0 ] && echo "installer-test-sandbox tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report installer-test-sandbox "$ALLOW" \
  'give the test a mktemp dir, set HOME (and every install/data override) inside it'
