#!/usr/bin/env bash
# finalization_publish_order_tripwire.sh — a finalization hook never publishes RPC state before
# the certificate is persisted.
#
# `checkpoint::FinalizationGuard::before_finalize` runs BEFORE the finalization is visible and
# before the certificate record is written. If anything reachable from it publishes the
# finalized pair to RPC (`finalized` / `safe`), a crash between the publish and the write
# restarts the node without the certificate, and it can abandon a block it already reported as
# finalized. Publication belongs in `after_finalize`, and only once
# `CheckpointManager::is_certificate_persisted` confirms the write.
#
# The check is structural but name-anchored. In every production .rs file that implements
# `FinalizationGuard` outside test code (`*_tests.rs` files and `#[cfg(test)]` modules are out
# of scope):
#   P1  "publication" = a write to the RPC-visible finalized state: a call of `record`, `store`,
#       `fetch_max`, `set` or `insert` on `verified_pairs`, `verified_height`, `finalized_pairs`
#       or an `rpc_finalized*` handle. A fn containing one is a publication fn.
#   P2  Nothing reachable from a `before_finalize` body (following calls to fns defined in the
#       same file, 5 levels deep) may be a publication fn or contain a publication.
#   P3  Every publication fn checks `is_certificate_persisted(` before its first publication.
#   P4  A file that implements FinalizationGuard but has no publication anchor at all fails
#       closed: the anchors above no longer describe how it publishes, so update them here.
# Limits: calls into other files and dynamic dispatch are not followed; a publication through a
# handle with a different name is invisible until it is added to the P1 anchor list.
#
# On main this guards code that is still on the finality branches (it scans clean when no file
# implements the trait); the self-test proves the engine on fixtures either way.
#
# Usage: finalization_publish_order_tripwire.sh              # scan the tree
#        finalization_publish_order_tripwire.sh --self-test  # prove the scan detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/finalization-publish-order"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root>
  (cd "$1" && tw_files . | grep -E '\.rs$' | grep -vE '_tests?\.rs$|(^|/)tests/' \
     | xargs -r -d '\n' grep -lE 'impl[[:space:]]+([A-Za-z_:]+::)?FinalizationGuard[[:space:]]+for' 2>/dev/null \
     | xargs -r -d '\n' perl -e '
    my $PUB = qr/\b(?:verified_pairs|verified_height|finalized_pairs|rpc_finalized\w*)\s*\.\s*(?:record|store|fetch_max|set|insert)\s*\(/;
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next; my @raw = <$fh>; close $fh;
      my @L;
      for my $n (0 .. $#raw) {
        my $l = $raw[$n];
        # a #[cfg(test)] module ends the production code (a cfg(test) fn does not)
        if ($l =~ /^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) {
          my $m = $n + 1; $m++ while $m <= $#raw && $raw[$m] =~ /^\s*#\[/;
          last if $m <= $#raw && $raw[$m] =~ /^\s*(pub(\([^)]*\))?\s+)?mod\s/;
        }
        (my $c = $l) =~ s{//.*$}{};
        $c =~ s{"(?:[^"\\]|\\.)*"}{""}g;
        push @L, $c;
      }
      next unless join("", @L) =~ /impl\s+(?:[A-Za-z_:]+::)?FinalizationGuard\s+for/;
      # fn name -> list of [start, end] (0-based line indexes); bodies by brace depth.
      my (%fns, @order);
      for (my $i = 0; $i <= $#L; $i++) {
        next unless $L[$i] =~ /\bfn\s+(\w+)/;
        my $name = $1; my ($depth, $open, $j) = (0, 0, $i);
        for (; $j <= $#L; $j++) {
          my $t = $L[$j]; $t =~ s/^.*?\bfn\s+\w+// if $j == $i;
          for my $ch (split //, $t) {
            if ($ch eq "{") { $depth++; $open = 1 } elsif ($ch eq "}") { $depth-- }
            elsif ($ch eq ";" && !$open) { $depth = -99 }   # a body-less trait method
          }
          last if $depth == -99 || ($open && $depth <= 0);
        }
        next if $depth == -99;
        push @{ $fns{$name} }, [$i, $j]; push @order, [$name, $i, $j];
      }
      my $body = sub { my ($r) = @_; join "", @L[$r->[0] .. $r->[1]] };
      my (%pubfn, $anchors);
      for my $o (@order) {
        my ($name, $s, $e) = @$o;
        for my $k ($s .. $e) {
          next unless $L[$k] =~ $PUB;
          $anchors++; $pubfn{$name} = 1;
          my $pre = join "", @L[$s .. $k];
          if ($pre !~ /\bis_certificate_persisted\s*\(/) {
            (my $t = $raw[$k]) =~ s/^\s+|\s+$//g;
            print "$f:", $k + 1, ": [P3 $name publishes without is_certificate_persisted] $t\n";
          }
          last;
        }
      }
      if (!$anchors) {
        print "$f:1: [P4 implements FinalizationGuard but no publication anchor matched: update the P1 list]\n";
        next;
      }
      for my $r (@{ $fns{before_finalize} || [] }) {
        my %seen = (before_finalize => 1); my @q = ([$r, 0, "before_finalize"]);
        while (my $x = shift @q) {
          my ($rr, $d, $path) = @$x;
          my $b = $body->($rr);
          while ($b =~ /\b(\w+)\s*(?:::<[^>]*>)?\s*\(/g) {
            my $callee = $1;
            next if $seen{$callee} || !$fns{$callee};
            $seen{$callee} = 1;
            if ($pubfn{$callee}) {
              my $at = $fns{$callee}[0][0];
              (my $t = $raw[$r->[0]]) =~ s/^\s+|\s+$//g;
              print "$f:", $r->[0] + 1, ": [P2 before_finalize reaches publication: $path -> $callee] $t\n";
              next;
            }
            push @q, [$_, $d + 1, "$path -> $callee"] for ($d < 5 ? @{ $fns{$callee} } : ());
          }
        }
      }
    }') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/node/src" "$d/neg/node/src" "$d/stale/node/src"
  cp "$FIXTURES/positive.rs" "$d/pos/node/src/finality_floor.rs"
  cp "$FIXTURES/negative.rs" "$d/neg/node/src/finality_floor.rs"
  cp "$FIXTURES/positive.rs" "$d/neg/node/src/finality_floor_tests.rs"   # test files are out of scope
  cp "$FIXTURES/positive_unanchored.rs" "$d/stale/node/src/guard.rs"
  tw_selftest_case "finalization-publish-order positive" hit scan "$d/pos" || rc=1
  scan "$d/pos" | grep -q 'P2 ' || { echo "self-test: P2 (publish reachable from before_finalize) missed"; rc=1; }
  scan "$d/pos" | grep -q 'P3 ' || { echo "self-test: P3 (publish without persistence check) missed"; rc=1; }
  tw_selftest_case "finalization-publish-order stale anchors" hit scan "$d/stale" || rc=1
  tw_selftest_case "finalization-publish-order negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "finalization-publish-order allowlist" finalization-publish-order scan "$d/pos" || rc=1
  [ $rc -eq 0 ] && echo "finalization-publish-order tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report finalization-publish-order "$ALLOW" \
  'publish in after_finalize, after is_certificate_persisted confirms the certificate write'
