#!/usr/bin/env bash
# shell_safety_tripwire.sh — two shell hygiene fences that protect the machine a script runs on.
#
#   shell-rm-guard   A recursive `rm` (-r / -R / -rf / -fr / --recursive) whose argument starts
#                    with a variable must use the `${VAR:?}` form, so an unset or empty variable
#                    stops the script instead of turning `rm -rf "$DIR/"` into `rm -rf /`.
#                    `"${VAR:?}/sub"` passes; `"$VAR"`, `"${VAR}"`, `$VAR/sub` and `"$(cmd)"`
#                    do not. Scope: every tracked *.sh / *.bash file, every file with a sh or
#                    bash shebang, and the run: blocks of .github/workflows/*.yml.
#
#   shell-pipefail   An ops, install, packaging, release or ceremony script that runs a pipeline
#                    must set pipefail (`set -o pipefail`, `set -euo pipefail`, ...). Without it a
#                    failing producer (`curl … | tar x`, `sha256sum f | awk`) is silently masked
#                    by the last command's success. Scope: shell files whose path has an ops/,
#                    ceremony/, install(ers)/, deploy/, release/, genesis/, provision/ or
#                    packaging/ directory, or whose name says install, deploy, ceremony,
#                    regenesis, reroll, provision, bootstrap, release or a package-hook name.
#                    Quoted text, here-documents, `||` and case-arm patterns are not pipelines.
#
# Usage: shell_safety_tripwire.sh              # scan the tree
#        shell_safety_tripwire.sh --self-test  # prove both fences still detect their class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

# Shell sources under <root>: *.sh, *.bash, workflow files, and shebang scripts.
shell_files() { # <root>
  tw_files "$1" | while IFS= read -r f; do
    case "$f" in
      *.sh|*.bash|.github/workflows/*.yml|.github/workflows/*.yaml) echo "$f" ;;
      *.*) ;;
      *) head -c 64 "$1/$f" 2>/dev/null | head -n 1 | grep -qE '^#!.*/(env )?(ba|da|z)?sh\b' && echo "$f" ;;
    esac
  done
}

scan_rm() { # <root> ; prints "path:line: text" for each unguarded recursive rm
  (cd "$1" && shell_files . | xargs -r -d '\n' perl -ne '
    if ($. == 1) { $hd = "" }
    if ($hd ne "") { $hd = "" if /^\s*\Q$hd\E\s*$/; next }   # inside a here-document: data
    next if /^\s*#/;
    my $line = $_;
    while ($line =~ /(^|[\s;&|({\x27"`])rm\s+((?:-{1,2}[A-Za-z-]+\s+)+)(.*)/g) {
      my ($pre, $opts, $args) = (substr($line, 0, $-[0]), $2, $3);
      next unless $opts =~ /(^|\s)-[A-Za-z]*[rR]|--recursive/;
      next if $pre =~ /\b(echo|printf)\b/;                    # text that only mentions rm
      $args =~ s/\s*(;|&&|\|\||\||\)|\x27|`|\s#).*//s;
      for my $a (split /\s+/, $args) {
        next if $a eq "--" || $a eq "";
        (my $t = $a) =~ s/^"//;
        if ($t =~ /^\$/ && $t !~ /^\$\{[A-Za-z_][A-Za-z0-9_]*:\?/) {
          chomp(my $show = $_); $show =~ s/^\s+//;
          print "$ARGV:$.: $show\n"; last;
        }
      }
    }
    $hd = $1 if /<<-?\s*[\x27"]?([A-Za-z_][A-Za-z0-9_]*)[\x27"]?/ && !/<<</;
    close ARGV if eof;') || true
}

PIPEFAIL_SCOPE='(^|/)(ops|ceremony|installers?|deploy|release|genesis|provision|packaging)/|(^|/)[^/]*(install|deploy|ceremony|regenesis|reroll|provision|bootstrap|release|postinst|preinst|prerm|postrm)[^/]*$'

scan_pipefail() { # <root> ; prints "path:line: text" for each in-scope script without pipefail
  (cd "$1" && shell_files . | grep -E '\.(sh|bash)$|^[^.]*$' | grep -vE '^\.github/' \
     | grep -iE "$PIPEFAIL_SCOPE" | xargs -r -d '\n' perl -ne '
    if ($. == 1) { $hd = ""; $first = ""; $pf = 0 }
    if ($hd ne "") { $hd = "" if /^\s*\Q$hd\E\s*$/; goto END_LINE }
    $pf = 1 if /^\s*[^#]*\bset\s+(-[A-Za-z]*o\s+pipefail|-o\s+pipefail|.*\bpipefail\b)/ || /shopt\s+-so\s+pipefail/;
    if (!/^\s*#/ && $first eq "") {
      my $s = $_;
      # Quoted text is not a pipeline, but a "$( … )" command substitution can hold one.
      $s =~ s/\\.//g; $s =~ s/\x27[^\x27]*\x27//g; $s =~ s/"(?:[^"\$]|\$(?!\())*"//g;
      $s =~ s/(^|\s)#.*$//;
      $s =~ s/\|\|//g;
      my $case_arm = $s =~ /^\s*\(?\s*[^\s()|;]+(\s*\|\s*[^\s()|;]+)*\s*\)/;
      if (!$case_arm && $s =~ /\|/) { chomp(my $show = $_); $show =~ s/^\s+//; $first = "$.: $show" }
    }
    $hd = $1 if /<<-?\s*[\x27"]?([A-Za-z_][A-Za-z0-9_]*)[\x27"]?/ && !/<<</;
    END_LINE:
    if (eof) {
      print "$ARGV:$first (no set -o pipefail in this script)\n" if $first ne "" && !$pf;
      close ARGV;
    }') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/a/scripts/ops" "$d/b/scripts/ops" "$d/c/scripts/ops"
  cp "$FIXTURES/shell-rm-guard/positive.sh" "$d/a/scripts/ops/x.sh"
  cp "$FIXTURES/shell-rm-guard/negative.sh" "$d/b/scripts/ops/x.sh"
  tw_selftest_case "shell-rm-guard positive" hit scan_rm "$d/a" || rc=1
  tw_selftest_case "shell-rm-guard negative" clean scan_rm "$d/b" || rc=1
  [ "$(scan_rm "$d/a" | wc -l)" -eq 6 ] || { echo "self-test: shell-rm-guard missed a positive form"; rc=1; }
  tw_selftest_allow "shell-rm-guard allowlist" shell-rm-guard scan_rm "$d/a" || rc=1
  cp "$FIXTURES/shell-pipefail/positive.sh" "$d/a/scripts/ops/y.sh"
  cp "$FIXTURES/shell-pipefail/positive_in_substitution.sh" "$d/a/scripts/ops/w.sh"
  cp "$FIXTURES/shell-pipefail/negative.sh" "$d/c/scripts/ops/y.sh"
  cp "$FIXTURES/shell-pipefail/negative_no_pipeline.sh" "$d/c/scripts/ops/z-install.sh"
  rm -f "$d/a/scripts/ops/x.sh"
  tw_selftest_case "shell-pipefail positive" hit scan_pipefail "$d/a" || rc=1
  [ "$(scan_pipefail "$d/a" | wc -l)" -eq 2 ] || { echo 'self-test: shell-pipefail missed a pipeline inside a command substitution'; rc=1; }
  tw_selftest_case "shell-pipefail negative" clean scan_pipefail "$d/c" || rc=1
  tw_selftest_allow "shell-pipefail allowlist" shell-pipefail scan_pipefail "$d/a" || rc=1
  [ $rc -eq 0 ] && echo "shell-safety tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi

rc=0
scan_rm "$REPO_ROOT" | tw_report shell-rm-guard "$ALLOW" \
  'use "${VAR:?}" for every variable an rm -r argument starts with' || rc=$?
scan_pipefail "$REPO_ROOT" | tw_report shell-pipefail "$ALLOW" \
  'add `set -euo pipefail` (bash) near the top of the script' || { r=$?; [ $r -gt $rc ] && rc=$r; }
exit $rc
