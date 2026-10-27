#!/usr/bin/env bash
# salt_supply_tripwire.sh — keep the contracts' SALT supply basis on the canon.
#
# Two checks:
#   1. contracts/src/lib/SaltSupply.sol TOTAL_SUPPLY equals `TOTAL_SUPPLY` in
#      core/economics/src/lib.rs (whole SALT; the Solidity side is `<n> ether`).
#   2. No deploy script under contracts/script passes a numeric literal as
#      TreasuryGovernor's supply argument (its last constructor argument). The
#      supply must come from SaltSupply.TOTAL_SUPPLY. A literal 1B here once set
#      the governor's quorum to a thousandth of the 1T canon.
#
# Usage: salt_supply_tripwire.sh              # scan the tree
#        salt_supply_tripwire.sh --self-test  # prove both checks still detect drift
set -uo pipefail

REPO_ROOT="${SALT_SUPPLY_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

norm() { tr -d '_ '; }

# check_constant <root> ; prints a problem and returns 1 on drift
check_constant() {
  local rs sol r s
  rs="$1/core/economics/src/lib.rs"; sol="$1/contracts/src/lib/SaltSupply.sol"
  [ -f "$rs" ] || { echo "missing $rs"; return 1; }
  [ -f "$sol" ] || { echo "missing $sol"; return 1; }
  r="$(sed -nE 's/^pub const TOTAL_SUPPLY: u128 = ([0-9_]+);.*/\1/p' "$rs" | head -1 | norm)"
  s="$(sed -nE 's/.*uint256 internal constant TOTAL_SUPPLY = ([0-9_]+) ether;.*/\1/p' "$sol" | head -1 | norm)"
  [ -n "$r" ] || { echo "$rs: TOTAL_SUPPLY not found"; return 1; }
  [ -n "$s" ] || { echo "$sol: TOTAL_SUPPLY (<n> ether) not found"; return 1; }
  [ "$r" = "$s" ] || { echo "SaltSupply.TOTAL_SUPPLY ($s ether) != core/economics TOTAL_SUPPLY ($r)"; return 1; }
  return 0
}

# check_literals <root> ; prints violations, returns 1 if any
check_literals() {
  local out
  out="$(find "$1/contracts/script" -name '*.sol' 2>/dev/null | sort | xargs -r perl -0777 -ne '
    my $src = $_;
    my $paren = qr/(\((?:[^()]++|(?-1))*\))/;
    while ($src =~ /(?:new\s+TreasuryGovernor\s*(?:\{[^}]*\})?\s*|type\(\s*TreasuryGovernor\s*\)\.creationCode\s*,\s*abi\.encode\s*)$paren/g) {
      my ($args, $at) = ($1, $-[0]);
      $args = substr($args, 1, -1);
      $args =~ s{//[^\n]*}{}g;
      $args =~ s{/\*.*?\*/}{}gs;
      my @parts; my ($depth, $cur) = (0, "");
      for my $c (split //, $args) {
        $depth++ if $c eq "(";
        $depth-- if $c eq ")";
        if ($c eq "," && $depth == 0) { push @parts, $cur; $cur = ""; } else { $cur .= $c; }
      }
      push @parts, $cur;
      my $last = $parts[-1]; $last =~ s/^\s+|\s+$//g;
      if ($last =~ /^[0-9][0-9_]*(?:\s*(?:ether|gwei|wei|e[0-9]+))?(?:\s*\*\s*[0-9e_]+(?:\s*ether)?)*$/) {
        my $line = 1 + (substr($src, 0, $at) =~ tr/\n//);
        print "$ARGV:$line: TreasuryGovernor supply passed as a literal ($last); use SaltSupply.TOTAL_SUPPLY\n";
      }
    }')"
  [ -n "$out" ] && { echo "$out"; return 1; }
  return 0
}

scan() { local rc=0; check_constant "$1" || rc=1; check_literals "$1" || rc=1; return $rc; }

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  mkdir -p "$d/core/economics/src" "$d/contracts/src/lib" "$d/contracts/script"
  printf 'pub const TOTAL_SUPPLY: u128 = 1_000_000_000_000;\n' > "$d/core/economics/src/lib.rs"
  printf 'library SaltSupply {\n    uint256 internal constant TOTAL_SUPPLY = 1_000_000_000_000 ether;\n}\n' > "$d/contracts/src/lib/SaltSupply.sol"
  cat > "$d/contracts/script/Ok.s.sol" <<'SOL'
contract S { function f() external {
  TreasuryGovernor g = new TreasuryGovernor{salt: Salts.salt("TreasuryGovernor")}(
    address(pool), address(treasury), guardian, // guardian
    SaltSupply.TOTAL_SUPPLY // canonical
  );
  bytes memory c = abi.encodePacked(type(TreasuryGovernor).creationCode, abi.encode(address(pool), address(treasury), guardian, SaltSupply.TOTAL_SUPPLY));
} }
SOL
  scan "$d" >/dev/null || { echo "self-test: flagged a clean tree"; rc=1; }
  # negative controls: each must be caught
  printf 'pub const TOTAL_SUPPLY: u128 = 1_000_000_000;\n' > "$d/core/economics/src/lib.rs"
  check_constant "$d" >/dev/null && { echo "self-test: missed a Rust/Solidity supply drift"; rc=1; }
  printf 'pub const TOTAL_SUPPLY: u128 = 1_000_000_000_000;\n' > "$d/core/economics/src/lib.rs"
  cat > "$d/contracts/script/Bad1.s.sol" <<'SOL'
contract B { function f() external {
  new TreasuryGovernor{salt: Salts.salt("TreasuryGovernor")}(
    address(pool), address(treasury), guardian,
    1_000_000_000 ether // total SALT supply (1B)
  );
} }
SOL
  check_literals "$d" >/dev/null && { echo "self-test: missed a literal in new TreasuryGovernor(...)"; rc=1; }
  rm -f "$d/contracts/script/Bad1.s.sol"
  printf 'contract B { bytes c = abi.encodePacked(type(TreasuryGovernor).creationCode, abi.encode(address(p), address(t), g, 1e30)); }\n' > "$d/contracts/script/Bad2.s.sol"
  check_literals "$d" >/dev/null && { echo "self-test: missed a literal in abi.encode for TreasuryGovernor"; rc=1; }
  [ $rc -eq 0 ] && echo "salt-supply tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if ! scan "$REPO_ROOT"; then
  echo "salt-supply tripwire: FAILED (pass SaltSupply.TOTAL_SUPPLY; keep it equal to core/economics TOTAL_SUPPLY)"
  exit 1
fi
echo "salt-supply tripwire: clean"
