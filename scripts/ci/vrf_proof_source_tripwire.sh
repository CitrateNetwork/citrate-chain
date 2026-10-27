#!/usr/bin/env bash
# vrf_proof_source_tripwire.sh — no production code builds a stub or placeholder VRF proof.
#
# A block header carries a `VrfProof { proof, output }`. The only valid proof is a real
# RFC 9381 ECVRF proof from `citrate_consensus::ecvrf::prove`. The producer once fell back
# to a SHA3 hash in the `proof` field when proving failed; every peer rejected those
# blocks, so the producer wasted its slots and looked forked. The fix skips the slot
# instead. This fence keeps any stub/placeholder proof out of production code:
#
#   R1  A `VrfProof {` struct literal in production code must carry a
#       `// VRF-PROOF-SOURCE:` comment on the same line or within the 3 lines above it,
#       naming the real ECVRF output it is built from.
#   R2  A production `VrfProof {` literal must never sit within 12 lines of a SHA3 /
#       Keccak hasher or a zero-filled buffer (`vec![0`), even when annotated: that is
#       the stub shape this tripwire exists for.
#
# Production = *.rs outside tests/ benches/ examples/ fuzz/ target/, not a
# `*_tests.rs` / `*_test.rs` file, and not inside a `#[cfg(test)]` item.
#
# Usage: vrf_proof_source_tripwire.sh              # scan the tree
#        vrf_proof_source_tripwire.sh --self-test  # prove both rules still detect their class
set -uo pipefail

REPO_ROOT="${VRF_PROOF_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

prod_files() { # <root>
  find "$1" -name '*.rs' \
    -not -path '*/target/*' -not -path '*/tests/*' -not -path '*/benches/*' \
    -not -path '*/examples/*' -not -path '*/fuzz/*' -not -path '*/node_modules/*' \
    -not -path '*/contracts/lib/*' -not -name '*_tests.rs' -not -name '*_test.rs' 2>/dev/null
}

scan() { # <root> ; prints violations, returns 0 iff any found
  local out
  out="$(prod_files "$1" | xargs -r perl -e '
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next;
      my @l = <$fh>; close $fh;
      # Blank out #[cfg(test)] items (brace-matched) so test fixtures are out of scope.
      my ($skip, $depth, $pending) = (0, 0, 0);
      for my $i (0..$#l) {
        my $s = $l[$i];
        if (!$skip && $s =~ /^\s*#\[cfg\(test\)\]/) { $pending = 1; $l[$i] = "\n"; next; }
        if ($pending && !$skip) {
          if ($s =~ /^\s*#\[/) { $l[$i] = "\n"; next; }
          $pending = 0;
          my $o = () = $s =~ /\{/g; my $c = () = $s =~ /\}/g;
          if ($o > $c) { $skip = 1; $depth = $o - $c; }
          $l[$i] = "\n"; next;
        }
        if ($skip) {
          my $o = () = $s =~ /\{/g; my $c = () = $s =~ /\}/g;
          $depth += $o - $c;
          $skip = 0 if $depth <= 0;
          $l[$i] = "\n"; next;
        }
      }
      for my $i (0..$#l) {
        next unless $l[$i] =~ /\bVrfProof\s*\{/;
        next if $l[$i] =~ /^\s*(pub(\([^)]*\))?\s+)?struct\s/;
        next if $l[$i] =~ /^\s*\/\//;
        next if $l[$i] =~ /->\s*(Result<\s*)?VrfProof\s*\{/;   # return type, not a literal
        next if $l[$i] =~ /\bimpl\b.*\bVrfProof\s*\{/;        # impl block
        my $n = $i + 1;
        my $lo = $i - 12 < 0 ? 0 : $i - 12;
        my $hi = $i + 12 > $#l ? $#l : $i + 12;
        my $win = join("", @l[$lo..$hi]);
        if ($win =~ /Sha3_256|Keccak256|sha3::|vec!\[\s*0/) {
          print "$f:$n: R2 VrfProof literal next to a hash/zero placeholder (stub proof): $l[$i]";
          next;
        }
        my $ok = ($l[$i] =~ /VRF-PROOF-SOURCE:/);
        for my $k (1..3) { last if $ok || $i - $k < 0; $ok = 1 if $l[$i-$k] =~ /\/\/\s*VRF-PROOF-SOURCE:/; }
        print "$f:$n: R1 VrfProof literal without // VRF-PROOF-SOURCE: annotation: $l[$i]" unless $ok;
      }
    }')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  mkdir -p "$d/node/src" "$d/node/tests"
  # R2 positive (negative control): the old SHA3 fallback shape must be caught, even annotated.
  cat > "$d/node/src/a.rs" <<'EOF'
fn gen(alpha: &[u8]) -> VrfProof {
    let mut hasher = Sha3_256::new();
    hasher.update(alpha);
    let out = hasher.finalize();
    // VRF-PROOF-SOURCE: not really
    VrfProof {
        proof: out.to_vec(),
        output: Hash::from_bytes(&out),
    }
}
EOF
  scan "$d" >/dev/null || { echo "self-test: R2 did not detect a SHA3 stub proof"; rc=1; }
  # R1 positive: an unannotated literal must be caught.
  printf 'fn gen(p: Vec<u8>, o: Hash) -> VrfProof {\n    VrfProof { proof: p, output: o }\n}\n' > "$d/node/src/a.rs"
  scan "$d" >/dev/null || { echo "self-test: R1 did not detect an unannotated VrfProof literal"; rc=1; }
  # R1 negative: an annotated real-ECVRF literal passes.
  printf 'fn gen(p: EcvrfProof, b: [u8; 32]) -> VrfProof {\n    // VRF-PROOF-SOURCE: ecvrf::prove output\n    VrfProof { proof: p.to_bytes(), output: Hash::from_bytes(&b) }\n}\n' > "$d/node/src/a.rs"
  scan "$d" >/dev/null && { echo "self-test: R1 flagged an annotated ECVRF literal"; rc=1; }
  # Test code is out of scope: tests/ dirs and #[cfg(test)] modules.
  printf '#[cfg(test)]\nmod tests {\n    fn f() -> VrfProof {\n        VrfProof { proof: vec![0; 32], output: Hash::default() }\n    }\n}\n' > "$d/node/src/a.rs"
  printf 'fn f() -> VrfProof { VrfProof { proof: vec![0; 32], output: Hash::default() } }\n' > "$d/node/tests/t.rs"
  scan "$d" >/dev/null && { echo "self-test: scanned test code"; rc=1; }
  # Production code AFTER a #[cfg(test)] item is still scanned.
  printf '#[cfg(test)]\nfn helper() {}\nfn gen(p: Vec<u8>, o: Hash) -> VrfProof {\n    VrfProof { proof: p, output: o }\n}\n' > "$d/node/src/a.rs"
  scan "$d" >/dev/null || { echo "self-test: skipped production code after a cfg(test) item"; rc=1; }
  [ $rc -eq 0 ] && echo "vrf-proof-source tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if out="$(scan "$REPO_ROOT")"; then
  echo "$out"
  echo "vrf-proof-source tripwire: FAILED (a block's VRF proof must come from ecvrf::prove; skip the slot on failure)"
  exit 1
fi
echo "vrf-proof-source tripwire: clean"
exit 0
