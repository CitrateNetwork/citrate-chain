#!/usr/bin/env bash
# Rehearsal export bundle: one command produces the files core and design build against.
#
#   scripts/rehearsal/export-r1.sh --rpc URL --expect-genesis 0xHASH [options]   # rehearsal day
#   scripts/rehearsal/export-r1.sh --offline [options]                           # dry run, repo files only
#
# Output: a new directory (default out/rehearsal/<label>-<UTC date>-<chain id>/) holding
#   ui-truth-fixture.json   the UI truth contract fixture (scripts/ui-truth/export-fixtures.sh)
#   addresses-<id>.json     the frozen address book, byte-for-byte
#   claims.json             verification/claims.json, byte-for-byte
#   MANIFEST.json           provenance: git SHA, chain id, genesis hash, RPC height, sha256 per file
#   SHA256SUMS              `sha256sum -c SHA256SUMS` verifies the bundle
#
# Read-only. Online mode makes JSON-RPC reads only (eth_chainId, eth_blockNumber,
# eth_getBlockByNumber, eth_getCode, eth_call). No keys, no signing, no transactions.
#
# The export refuses (non-zero exit, nothing left behind) when an input is missing or the
# inputs disagree: book/claims chain id, RPC chain id, expected genesis hash, a contract the
# fixture needs is absent or malformed, the claims or address-code gate fails, or the address
# book / claims file differs from the committed HEAD (unless --allow-dirty, which the manifest
# then records).
#
# Options:
#   --rpc URL              JSON-RPC endpoint (online mode; required unless --offline)
#   --expect-genesis HASH  genesis block hash recorded at the cut; required online
#   --offline              no network: copy the newest committed fixture instead of exporting
#   --fixture PATH         offline only: the fixture file to bundle (default: newest committed)
#   --book PATH            address book (default contracts/addresses/40204.json)
#   --out DIR              output directory (must not exist or be empty)
#   --label NAME           bundle label (default r1)
#   --allow-dirty          accept an address book / claims file that differs from HEAD
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

die() { echo "export-r1: $*" >&2; exit 2; }

MODE=online RPC="" EXPECT_GENESIS="" FIXTURE_IN="" OUT="" LABEL=r1 ALLOW_DIRTY=false
BOOK=contracts/addresses/40204.json
CLAIMS=verification/claims.json
while [ $# -gt 0 ]; do
  case "$1" in
    --rpc) RPC=${2:?--rpc needs a URL}; shift 2 ;;
    --expect-genesis) EXPECT_GENESIS=${2:?--expect-genesis needs a hash}; shift 2 ;;
    --offline) MODE=offline; shift ;;
    --fixture) FIXTURE_IN=${2:?--fixture needs a path}; shift 2 ;;
    --book) BOOK=${2:?--book needs a path}; shift 2 ;;
    --out) OUT=${2:?--out needs a directory}; shift 2 ;;
    --label) LABEL=${2:?--label needs a name}; shift 2 ;;
    --allow-dirty) ALLOW_DIRTY=true; shift ;;
    -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ "$LABEL" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "--label must be lowercase letters, digits and dashes"

for t in jq sha256sum python3 git; do command -v "$t" >/dev/null || die "$t is required"; done
if [ "$MODE" = online ]; then
  for t in curl cast; do command -v "$t" >/dev/null || die "$t is required for an online export"; done
  [ -n "$RPC" ] || die "--rpc URL is required (or pass --offline for a dry run)"
  [[ "$EXPECT_GENESIS" =~ ^0x[0-9a-fA-F]{64}$ ]] \
    || die "--expect-genesis 0x<64 hex> is required online: the genesis hash recorded at the cut"
  [ -z "$FIXTURE_IN" ] || die "--fixture is for --offline only; online mode exports a fresh fixture"
fi

# ── 1. Inputs exist, parse, and agree with each other ────────────────────────────────────
[ -f "$BOOK" ] || die "address book not found: $BOOK"
[ -f "$CLAIMS" ] || die "claims file not found: $CLAIMS"
jq -e . "$BOOK" >/dev/null 2>&1 || die "address book is not valid JSON: $BOOK"
jq -e . "$CLAIMS" >/dev/null 2>&1 || die "claims file is not valid JSON: $CLAIMS"

missing=$(jq -r --slurpfile s contracts/addresses/schema.json '. as $b | $s[0].required[] | select($b[.] == null)' "$BOOK")
[ -z "$missing" ] || die "address book lacks required field(s): $(echo $missing)"

BOOK_CHAIN=$(jq -r '.chainId' "$BOOK")
[[ "$BOOK_CHAIN" =~ ^[1-9][0-9]*$ ]] || die "address book chainId is not a positive integer: $BOOK_CHAIN"
CLAIMS_CHAIN=$(jq -r '.claims.chain_id.value // empty' "$CLAIMS")
[ "$CLAIMS_CHAIN" = "$BOOK_CHAIN" ] \
  || die "chain id mismatch: address book says $BOOK_CHAIN, claims.json chain_id says ${CLAIMS_CHAIN:-nothing}"

# Every published address is a 20-byte hex address.
bad=$(jq -r '[(.contracts, .aaStack, .genesis) // {} | to_entries[]]
             + [(.governance // {}) | to_entries[] | select(.key == "GOVERNANCE" or .key == "GUARDIAN")]
             | .[] | select((.value | type) != "string" or (.value | test("^0x[0-9a-fA-F]{40}$") | not)) | .key' "$BOOK")
[ -z "$bad" ] || die "address book has malformed address(es): $(echo $bad)"

# The contracts the fixture reads (scripts/ui-truth/export-fixtures.sh), resolved the same way.
NEEDED="ValidatorRegistry MembershipStakeVault CitrateMemberSBT IPFSIncentivesV3 SkillRegistry ModelRegistry GOVERNANCE GUARDIAN"
for k in $NEEDED; do
  a=$(jq -r --arg k "$k" '.contracts[$k] // .[$k] // .governance[$k] // empty' "$BOOK")
  [[ "$a" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "address book has no usable address for $k (the UI truth fixture reads it)"
  [[ "$a" =~ ^0x0{40}$ ]] && die "address book maps $k to the zero address"
done

# Provenance: the bundled book and claims must be what HEAD says, or the git SHA proves nothing.
GIT_SHA=$(git rev-parse HEAD)
dirty=()
for f in "$BOOK" "$CLAIMS" verification/address-code.snapshot.json scripts/ui-truth/export-fixtures.sh; do
  rel=$(realpath --relative-to="$ROOT" "$f")
  if [[ "$rel" == ../* ]] || ! git ls-files --error-unmatch -- "$rel" >/dev/null 2>&1 \
     || ! git diff --quiet HEAD -- "$rel"; then dirty+=("$rel"); fi
done
if [ ${#dirty[@]} -gt 0 ] && [ "$ALLOW_DIRTY" != true ]; then
  die "inputs differ from HEAD $GIT_SHA: ${dirty[*]} (commit the frozen book first, or pass --allow-dirty for a scratch run)"
fi

# ── 2. Gates that already guard public claims ───────────────────────────────────────────
python3 -I verification/check_claims.py --root "$ROOT" >/dev/null \
  || die "verification/check_claims.py failed; fix claims.json before exporting"
if [ "$MODE" = offline ]; then
  python3 -I verification/check_address_code.py --offline --book "$BOOK" >/dev/null \
    || die "verification/check_address_code.py --offline failed (snapshot, book and claims disagree)"
fi

# ── 3. Online: the RPC is the chain the book describes ──────────────────────────────────
RPC_HEIGHT=null GENESIS=null RPC_CHAIN=null
rpc_result() {
  curl -fsS -m 20 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC" 2>/dev/null \
    | jq -r '.result // empty' 2>/dev/null || true
}
if [ "$MODE" = online ]; then
  q=$(rpc_result eth_chainId '[]')
  [[ "$q" =~ ^0x[0-9a-fA-F]{1,16}$ ]] || die "eth_chainId unavailable or malformed from $RPC (${q:-no response})"
  RPC_CHAIN=$(printf '%d' "$q")
  [ "$RPC_CHAIN" = "$BOOK_CHAIN" ] || die "chain id mismatch: RPC $RPC serves $RPC_CHAIN, address book says $BOOK_CHAIN"
  GENESIS=$(rpc_result eth_getBlockByNumber '["0x0",false]' | jq -r '.hash // empty' 2>/dev/null || true)
  [[ "$GENESIS" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "genesis block hash unavailable or malformed from $RPC"
  [ "${GENESIS,,}" = "${EXPECT_GENESIS,,}" ] \
    || die "genesis mismatch: RPC $RPC has $GENESIS, the cut recorded $EXPECT_GENESIS"
  q=$(rpc_result eth_blockNumber '[]')
  [[ "$q" =~ ^0x[0-9a-fA-F]{1,15}$ ]] || die "eth_blockNumber unavailable or malformed from $RPC"
  RPC_HEIGHT=$(printf '%d' "$q")
  python3 -I verification/check_address_code.py --check --rpc "$RPC" --book "$BOOK" >/dev/null \
    || die "address-code check failed against $RPC: the book, the committed snapshot and live code disagree (re-probe and commit the snapshot at the freeze)"
fi

# ── 4. Build the bundle in a scratch dir; move into place only when complete ────────────
DATE=$(date -u +%Y-%m-%d)
OUT=${OUT:-out/rehearsal/$LABEL-$DATE-$BOOK_CHAIN}
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  die "output directory exists and is not empty: $OUT (bundles are never overwritten)"
fi
mkdir -p "$(dirname "$OUT")"
STAGE=$(mktemp -d "$(dirname "$OUT")/.export-r1.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

BOOK_NAME="addresses-$BOOK_CHAIN.json"
cp "$BOOK" "$STAGE/$BOOK_NAME"
cp "$CLAIMS" "$STAGE/claims.json"

if [ "$MODE" = online ]; then
  UI_TRUTH_BOOK="$BOOK" scripts/ui-truth/export-fixtures.sh "$RPC" "$STAGE/ui-truth-fixture.json" >&2 \
    || die "scripts/ui-truth/export-fixtures.sh failed; no bundle written"
  FIXTURE_SRC="exported from $RPC"
else
  if [ -z "$FIXTURE_IN" ]; then
    FIXTURE_IN=$(git ls-files "docs/ui-truth/fixtures/$BOOK_CHAIN-*.json" | sort | tail -1)
    [ -n "$FIXTURE_IN" ] || die "no committed fixture for chain $BOOK_CHAIN under docs/ui-truth/fixtures/"
  fi
  [ -f "$FIXTURE_IN" ] || die "fixture not found: $FIXTURE_IN"
  cp "$FIXTURE_IN" "$STAGE/ui-truth-fixture.json"
  FIXTURE_SRC="copied from $FIXTURE_IN (offline dry run, not a rehearsal export)"
fi

# The fixture must describe the same chain (and, online, the same genesis).
FX="$STAGE/ui-truth-fixture.json"
jq -e '.fixture == true and (.reads | type == "array")' "$FX" >/dev/null 2>&1 || die "fixture is not a UI truth fixture"
fx_chain=$(jq -r '.reads[] | select(.id == "chain_id") | .value' "$FX")
[[ "$fx_chain" =~ ^0x[0-9a-fA-F]+$ ]] && [ "$(printf '%d' "$fx_chain")" = "$BOOK_CHAIN" ] \
  || die "fixture chain_id ($fx_chain) does not match address book chain $BOOK_CHAIN"
if [ "$MODE" = online ]; then
  fx_gen=$(jq -r '.reads[] | select(.id == "genesis_hash") | .value' "$FX")
  [ "${fx_gen,,}" = "${GENESIS,,}" ] || die "fixture genesis_hash ($fx_gen) differs from the RPC genesis $GENESIS"
fi

(cd "$STAGE" && sha256sum ui-truth-fixture.json "$BOOK_NAME" claims.json > SHA256SUMS)
files=$(cd "$STAGE" && for f in ui-truth-fixture.json "$BOOK_NAME" claims.json; do
  jq -cn --arg n "$f" --arg h "$(sha256sum "$f" | cut -d' ' -f1)" --argjson b "$(stat -c %s "$f")" \
    '{name:$n, sha256:$h, bytes:$b}'; done | jq -s .)
dirty_json=$(printf '%s\n' "${dirty[@]+"${dirty[@]}"}" | jq -R . | jq -s 'map(select(length > 0))')

jq -n --arg label "$LABEL" --arg mode "$MODE" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg sha "$GIT_SHA" --arg describe "$(git describe --always --dirty 2>/dev/null || echo "$GIT_SHA")" \
  --arg branch "$(git rev-parse --abbrev-ref HEAD)" --argjson dirty "$dirty_json" \
  --argjson chain "$BOOK_CHAIN" --argjson rpc_chain "$RPC_CHAIN" \
  --arg rpc "${RPC:-}" --argjson height "$RPC_HEIGHT" \
  --arg genesis "$([ "$GENESIS" = null ] && echo "" || echo "$GENESIS")" \
  --arg book "$BOOK" --arg deployed "$(jq -r '.deployedAt // empty' "$BOOK")" \
  --arg fixture_src "$FIXTURE_SRC" --argjson files "$files" \
  '{bundle: $label, mode: $mode, generated_at: $at,
    rehearsal_export: ($mode == "online"),
    note: (if $mode == "online" then "Read-only export from a live RPC. Fixture values are latest-state reads; see the fixture header."
           else "OFFLINE DRY RUN from repo files. Not a rehearsal export: no RPC was read." end),
    source: {repo: "citrate-chain", git_sha: $sha, git_describe: $describe, branch: $branch,
             inputs_differ_from_head: $dirty},
    chain: {chain_id: $chain, rpc_chain_id: $rpc_chain,
            rpc_url: (if $rpc == "" then null else $rpc end),
            genesis_hash: (if $genesis == "" then null else $genesis end),
            rpc_block_height: $height,
            rpc_block_height_note: (if $height == null then "not read (offline)" else "eth_blockNumber read before the fixture export started" end)},
    address_book: {path: $book, deployed_at: $deployed},
    fixture: {source: $fixture_src},
    gates: ([ "inputs parse; book, claims and fixture chain ids agree",
              "required address-book fields and fixture contracts present",
              "verification/check_claims.py" ]
            + (if $mode == "online"
               then ["RPC chain id matches the book", "RPC genesis matches --expect-genesis",
                     "verification/check_address_code.py --check (live)", "fixture genesis matches RPC"]
               else ["verification/check_address_code.py --offline"] end)),
    files: $files,
    consumers: ["citrate-core (MAC lane)", "design"]}' > "$STAGE/MANIFEST.json"

(cd "$STAGE" && sha256sum -c --quiet SHA256SUMS) || die "bundle failed its own checksum verification"
mkdir -p "$OUT"
mv "$STAGE"/* "$OUT"/
echo "export-r1: wrote $OUT ($MODE; chain $BOOK_CHAIN; git $GIT_SHA; height $RPC_HEIGHT)"
[ ${#dirty[@]} -eq 0 ] || echo "export-r1: WARNING inputs differ from HEAD: ${dirty[*]}" >&2
