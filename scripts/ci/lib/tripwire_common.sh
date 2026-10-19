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

# tw_files <root> — the files a scan should look at, repo-relative, one per line. Tracked files
# when <root> is a git work tree (so build output and vendored trees stay out); every file
# otherwise (the self-test sandboxes). Fixture trees are never scanned as source.
tw_files() {
  local root="$1"
  if [ "$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" = "$(cd "$root" && pwd -P)" ]; then
    git -C "$root" ls-files
  else
    (cd "$root" && find . -type f -not -path './.git/*' -not -path '*/node_modules/*' \
       -not -path '*/target/*' | sed 's|^\./||')
  fi | grep -vE '^scripts/ci/fixtures/|(^|/)node_modules/|^contracts/lib/' || true
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
