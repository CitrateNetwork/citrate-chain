# tripwire_common.sh — shared helpers for the scripts/ci/*_tripwire.sh scans.
# Sourced, not executed. The same file is carried by citrate-chain, citrate-core and
# citrate-landing so the three repos read their allowlists the same way.
#
# ALLOWLIST (scripts/ci/tripwire-allowlist.txt), one reviewed exception per line:
#
#   <tripwire-id> | <path or glob> | <key> | <ref> | <reason>
#
#   tripwire-id  the id the tripwire prints (e.g. shell-rm-guard).
#   path         repo-relative path; `*` matches within one directory, `**` across them.
#   key          a literal substring of the flagged line (or of the label a tripwire prints
#                before it), or `*` for every hit of that tripwire in the file. Keys are text,
#                not line numbers, so an entry survives unrelated edits above it.
#   ref          the board item / issue / PR that tracks removing the exception. Required.
#   reason       why the exception is acceptable until then. Required (10+ characters).
#
# A malformed entry fails the scan (exit 2). An entry that matches nothing is reported as
# stale on stderr but does not fail the scan: the fix that makes it stale may land before the
# entry is removed, and that must not turn main red.

# Git exports repository variables (GIT_DIR, GIT_INDEX_FILE, ...) to hooks, and the pre-push hook
# runs these scans. They would override `git -C <dir>` below, so clear them.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars 2>/dev/null) \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR 2>/dev/null || true

# Engine failures (a file listing that came back empty for a non-empty tree, a scan command that
# could not run) are recorded in one file per tripwire run, shared with sub-shells through the
# environment. tw_report fails when it is non-empty, so a scan that did not run never reads as
# clean. Portable to bash 3.2 and BSD userlands (macOS pre-push): no xargs -d, no mapfile.
if [ -z "${TW_ENGINE_FAIL:-}" ]; then
  TW_ENGINE_FAIL="$(mktemp "${TMPDIR:-/tmp}/tw-engine.XXXXXX")" || TW_ENGINE_FAIL=""
  export TW_ENGINE_FAIL
  [ -n "$TW_ENGINE_FAIL" ] && trap 'rm -f "${TW_ENGINE_FAIL:?}"' EXIT
fi

# tw_engine_fail <message> — record that the scan could not do its job.
tw_engine_fail() {
  echo "tripwire engine: $*" >&2
  if [ -n "${TW_ENGINE_FAIL:-}" ]; then echo "$*" >> "$TW_ENGINE_FAIL"; fi
}

# tw_files <root> — the files a scan should look at, repo-relative, one per line. Tracked files
# when <root> is a git work tree (so build output and vendored trees stay out); every file
# otherwise (the self-test sandboxes). Fixture trees are never scanned as source. An empty
# listing for a non-empty <root> is an engine failure, not a clean tree.
tw_files() {
  local root="$1" list
  if [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" = "$(cd "$root" && pwd -P)" ]; then
    list="$(git -C "$root" ls-files)"
  else
    list="$(cd "$root" && find . -type f -not -path './.git/*' -not -path '*/node_modules/*' \
       -not -path '*/target/*' | sed 's|^\./||')"
  fi
  if [ -z "$list" ]; then
    if [ -n "$(ls -A "$root" 2>/dev/null)" ]; then tw_engine_fail "no files listed under $root, which is not empty"; fi
    return 0
  fi
  printf '%s\n' "$list" | grep -vE '^scripts/ci/fixtures/|(^|/)node_modules/|^contracts/lib/' || true
}

# tw_xargs <command...> — stdin: one path per line; runs <command> with the paths appended, in
# batches of 200 (like `xargs -r -d '\n'`, which BSD xargs lacks). Paths may contain spaces.
# Nothing runs on empty input. The status of the last batch is returned; a command that could
# not be run (status 126/127) or was killed (128+) is an engine failure.
tw_xargs() {
  local f n=0 r=0
  local -a batch
  batch=()
  while IFS= read -r f || [ -n "$f" ]; do
    [ -n "$f" ] || continue
    batch[n]="$f"; n=$((n + 1))
    if [ "$n" -ge 200 ]; then
      "$@" "${batch[@]}"; r=$?
      [ "$r" -ge 126 ] && tw_engine_fail "'$1' could not run (status $r)"
      batch=(); n=0
    fi
  done
  if [ "$n" -gt 0 ]; then
    "$@" "${batch[@]}"; r=$?
    [ "$r" -ge 126 ] && tw_engine_fail "'$1' could not run (status $r)"
  fi
  return "$r"
}

# tw_filter <tripwire-id> <allowlist-file> — stdin: hits as "path:line: text"; stdout: the hits
# no entry allows. Exit 2 on a malformed allowlist.
tw_filter() {
  perl -e '
    my ($id, $file) = @ARGV;
    my (@e, $bad);
    if (open(my $fh, "<", $file)) {
      while (my $l = <$fh>) {
        chomp $l;
        next if $l =~ /^\s*(#|$)/;
        my @f = split /\s+\|\s+/, $l, 5;
        next unless $f[0] eq $id;
        if (@f < 5 || $f[1] !~ /\S/ || $f[2] !~ /\S/ || $f[3] !~ /\S/ || length($f[4]) < 10) {
          print STDERR "allowlist: malformed entry (need: id | path | key | ref | reason): $l\n";
          $bad = 1; next;
        }
        my $g = quotemeta $f[1];
        $g =~ s/\\\*\\\*/.*/g; $g =~ s/\\\*/[^\/]*/g;
        push @e, { re => qr/^$g$/, path => $f[1], key => $f[2], used => 0 };
      }
    }
    exit 2 if $bad;
    while (my $h = <STDIN>) {
      chomp $h;
      my ($p, $rest) = $h =~ /^([^:]+):(.*)$/ or next;
      my $ok = 0;
      for my $x (@e) {
        if ($p =~ $x->{re} && ($x->{key} eq "*" || index($rest, $x->{key}) >= 0)) { $x->{used}++; $ok = 1; }
      }
      print "$h\n" unless $ok;
    }
    for my $x (@e) {
      print STDERR "allowlist: stale entry for $id (matches nothing; remove it): $x->{path} | $x->{key}\n"
        unless $x->{used};
    }
  ' "$1" "$2"
}

# tw_report <tripwire-id> <allowlist-file> <fix-hint> — stdin: raw hits. Prints the hits that
# are not allowlisted; exit 0 clean, 1 violations, 2 malformed allowlist.
tw_report() {
  local id="$1" allow="$2" hint="$3" out rc
  out="$(tw_filter "$id" "$allow")"; rc=$?
  [ "$rc" -eq 2 ] && return 2
  if [ "$rc" -ne 0 ] || [ -s "${TW_ENGINE_FAIL:-/dev/null}" ] || [ -z "${TW_ENGINE_FAIL:-}" ]; then
    echo "$id tripwire: FAILED — the scan did not run, so the tree is not known to be clean"
    [ "$rc" -ne 0 ] && echo "  allowlist filter exited $rc"
    [ -s "${TW_ENGINE_FAIL:-/dev/null}" ] && sed 's/^/  /' "$TW_ENGINE_FAIL"
    [ -z "${TW_ENGINE_FAIL:-}" ] && echo "  could not create the engine-failure record (mktemp)"
    return 1
  fi
  if [ -n "$out" ]; then
    echo "$out" | sed "s/^/$id: /"
    echo "$id tripwire: FAILED — $hint"
    echo "  (a reviewed exception goes in scripts/ci/tripwire-allowlist.txt with a ref and a reason)"
    return 1
  fi
  echo "$id tripwire: clean"
  return 0
}

# tw_selftest_case <name> <expect: hit|clean> <command...> — run a scan on a fixture tree and
# check the outcome. Prints a line only on failure; returns 1 on failure.
tw_selftest_case() {
  local name="$1" want="$2"; shift 2
  local out; out="$("$@" 2>/dev/null)"
  if [ "$want" = hit ] && [ -z "$out" ]; then echo "self-test: $name: expected a hit, got none"; return 1; fi
  if [ "$want" = clean ] && [ -n "$out" ]; then echo "self-test: $name: expected clean, got:"; echo "$out" | sed 's/^/    /'; return 1; fi
  return 0
}

# tw_selftest_allow <name> <tripwire-id> <command...> — the allowlist half of a self-test: the
# hits <command> prints must all be suppressed by a well-formed entry for their files, and an
# entry without a ref / reason must be refused (exit 2). Returns 1 on failure.
tw_selftest_allow() {
  local name="$1" id="$2"; shift 2
  local tmp out rc=0 hits
  tmp="$(mktemp)"
  hits="$("$@" 2>/dev/null)"
  [ -n "$hits" ] || { echo "self-test: $name: no hits to allowlist"; rm -f "$tmp"; return 1; }
  echo "$hits" | cut -d: -f1 | sort -u \
    | sed "s/\$/ | * | self-test | fixture exception exercising the allowlist path/; s/^/$id | /" > "$tmp"
  out="$(echo "$hits" | tw_filter "$id" "$tmp" 2>/dev/null)"
  [ -z "$out" ] || { echo "self-test: $name: a matching allowlist entry did not suppress the hit"; rc=1; }
  echo "$id | $(echo "$hits" | head -1 | cut -d: -f1) | * | | " > "$tmp"
  echo "$hits" | tw_filter "$id" "$tmp" >/dev/null 2>&1
  [ $? -eq 2 ] || { echo "self-test: $name: an entry without ref/reason was accepted"; rc=1; }
  rm -f "$tmp"
  return $rc
}

# tw_selftest_marked <name> <root> <command...> — every fixture line under <root> that carries
# the marker FLAG must be reported by <command> (run on <root>), and nothing else may be.
tw_selftest_marked() {
  local name="$1" root="$2"; shift 2
  local want got
  want="$(cd "$root" && grep -rn 'FLAG' . | sed 's|^\./||' | cut -d: -f1,2 | sort)"
  got="$("$@" "$root" 2>/dev/null | cut -d: -f1,2 | sort)"
  [ "$want" = "$got" ] && return 0
  echo "self-test: $name: flagged lines differ from the fixture's FLAG markers"
  diff <(echo "$want") <(echo "$got") | sed 's/^</    missed:/; s/^>/    extra: /' | grep -E 'missed|extra'
  return 1
}

# tw_selftest_fail_closed <name> <root> <command...> — the scan must not pass silently: with a
# file listing that returns nothing for <root> (find and `git ls-files` shimmed to print
# nothing), `<command> <root> | tw_report` must exit non-zero, not print "clean". Returns 1 on
# failure.
tw_selftest_fail_closed() {
  local name="$1" root="$2"; shift 2
  local shim rec rc
  shim="$(mktemp -d)" || { echo "self-test: $name: mktemp failed"; return 1; }
  rec="$(mktemp)" || { rm -rf "${shim:?}"; echo "self-test: $name: mktemp failed"; return 1; }
  printf '#!/bin/sh\nexit 0\n' > "$shim/find"
  printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = ls-files ] && exit 0; done\nexec "%s" "$@"\n' \
    "$(command -v git)" > "$shim/git"
  chmod +x "$shim/find" "$shim/git"
  ( PATH="$shim:$PATH"; TW_ENGINE_FAIL="$rec"; "$@" "$root" | tw_report self-test /dev/null x ) >/dev/null 2>&1
  rc=$?
  rm -rf "${shim:?}"; rm -f "${rec:?}"
  [ "$rc" -ne 0 ] && return 0
  echo "self-test: $name: an empty file listing for a non-empty tree reported clean"
  return 1
}

# tw_strip_c <file...> — C-family sources (Rust, Solidity, JS/TS) with comments removed and
# string-literal contents blanked, one output line per input line: "path:line: code". A small
# lexer, so a `/*` inside a `//` comment or a string, a `//` inside a string ("http://..."), or a
# nested Rust block comment does not desynchronise it. Raw strings (r"..", r#".."#) and the
# char literal '"' are recognised; other char literals and lifetimes pass through as code.
tw_strip_c() {
  perl -e '
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next; local $/; my $src = <$fh>; close $fh;
      my ($out, $i, $n, $depth) = ("", 0, length $src, 0);
      while ($i < $n) {
        my $c = substr($src, $i, 1); my $two = substr($src, $i, 2);
        if ($depth) {
          if ($two eq "*/") { $depth--; $i += 2; $out .= "  "; next }
          if ($two eq "/*") { $depth++; $i += 2; $out .= "  "; next }
          $out .= $c eq "\n" ? "\n" : " "; $i++; next;
        }
        if ($two eq "//") { my $e = index($src, "\n", $i); $e = $n if $e < 0; $out .= " " x ($e - $i); $i = $e; next }
        if ($two eq "/*") { $depth = 1; $i += 2; $out .= "  "; next }
        if (substr($src, $i, 3) eq "\x27\"\x27") { $out .= "\x27\"\x27"; $i += 3; next }
        if ($c eq "r" && substr($src, $i) =~ /^r(#*)"/ && ($i == 0 || substr($src, $i - 1, 1) !~ /\w/)) {
          my $close = "\"" . $1; my $start = $i + 2 + length $1;
          my $e = index($src, $close, $start); $e = $n - length($close) if $e < 0;
          my $body = substr($src, $start, $e - $start); $body =~ s/[^\n]/ /g;
          $out .= "r$1\"" . $body . $close; $i = $e + length $close; next;
        }
        if ($c eq "\"") {
          my $j = $i + 1;
          while ($j < $n) { my $d = substr($src, $j, 1); if ($d eq "\\") { $j += 2; next } last if $d eq "\""; $j++ }
          my $body = substr($src, $i + 1, $j - $i - 1); $body =~ s/[^\n]/ /g;
          $out .= "\"" . $body . "\""; $i = $j + 1; next;
        }
        $out .= $c; $i++;
      }
      my $ln = 0;
      print "$f:", ++$ln, ": $_\n" for split /\n/, $out, -1;
    }' "$@"
}
