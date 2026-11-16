#!/usr/bin/env bash
# The Homebrew formula (homebrew/citrate.rb) must install what the release
# workflow (.github/workflows/release.yml) actually ships:
#   - every `bin.install "X"` is a binary the release copies into the tarball;
#   - every binary the formula runs (bin/"X", opt_bin/"X") is one it installs;
#   - every url names a tarball the release builds: citrate-chain-<target>.tar.gz
#     for a target in the release matrix;
#   - no shell-completion generation unless citrate-cli has a `completion` command;
#   - every sha256 is a real digest or the fail-closed PENDING_RELEASE_DIGEST marker;
#   - homebrew/README.md names no stale tap, placeholder digest or non-canonical org.
# Usage: test_homebrew_formula.sh [repo-root]   (default: this repo). Reads files only.
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
FORMULA="$ROOT/homebrew/citrate.rb"
README="$ROOT/homebrew/README.md"
RELEASE="$ROOT/.github/workflows/release.yml"
CLI_MAIN="$ROOT/cli/src/main.rs"
for f in "$FORMULA" "$README" "$RELEASE" "$CLI_MAIN"; do
    [[ -f "$f" ]] || { echo "FAIL - missing $f"; exit 2; }
done
fail=0
bad() { echo "FAIL - $*"; fail=1; }

# Binaries the release puts in dist/$STAGE/: `cp "<src>" "dist/$STAGE/<name>$EXE"`
# names it explicitly; `cp "<dir>/<name>$EXE" "dist/$STAGE/"` keeps the source name.
shipped=$(grep -E '^\s*cp "\$TARGET_DIR/' "$RELEASE" | sed -E \
    -e 's#.*"dist/\$STAGE/([A-Za-z0-9_-]+)\$EXE".*#\1#' \
    -e 's#.*"\$TARGET_DIR/([A-Za-z0-9_-]+)\$EXE" +"dist/\$STAGE/".*#\1#' | sort -u)
[[ -n "$shipped" ]] || bad "could not read the shipped binaries from $RELEASE"

installed=$(grep -oE 'bin\.install "[^"]+"' "$FORMULA" | sed -E 's/bin\.install "([^"]+)"/\1/' | sort -u)
[[ -n "$installed" ]] || bad "the formula installs nothing"
for b in $installed; do
    grep -qx "$b" <<<"$shipped" || bad "formula installs \"$b\", which the release tarball does not ship (ships: $(echo $shipped))"
done

for b in $(grep -oE '(opt_)?bin/"[^"]+"' "$FORMULA" | sed -E 's/.*"([^"]+)"/\1/' | sort -u); do
    grep -qx "$b" <<<"$installed" || bad "formula runs \"$b\", which it does not install"
done

targets=$(grep -E '^\s*- target: ' "$RELEASE" | sed -E 's/.*target: *//' | grep -v windows | sort -u)
urls=$(grep -oE 'url "[^"]+"' "$FORMULA" | sed -E 's/url "([^"]+)"/\1/')
[[ -n "$urls" ]] || bad "the formula has no url"
while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    [[ "$u" == https://github.com/CitrateNetwork/citrate-chain/releases/download/* ]] || bad "url is not a CitrateNetwork/citrate-chain release: $u"
    file="${u##*/}"
    ok=0
    for t in $targets; do [[ "$file" == "citrate-chain-$t.tar.gz" ]] && ok=1; done
    [[ $ok -eq 1 ]] || bad "url names $file, which the release does not build (builds: $(for t in $targets; do printf 'citrate-chain-%s.tar.gz ' "$t"; done))"
done <<<"$urls"

if grep -q 'generate_completions_from_executable' "$FORMULA" && ! grep -qE '^\s*Completion' "$CLI_MAIN"; then
    bad "formula generates shell completions, but citrate-cli has no completion command"
fi

while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    [[ "$d" =~ ^[0-9a-f]{64}$ || "$d" == "PENDING_RELEASE_DIGEST" ]] || bad "sha256 \"$d\" is neither a digest nor PENDING_RELEASE_DIGEST"
done < <(grep -oE 'sha256 "[^"]*"' "$FORMULA" | sed -E 's/sha256 "([^"]*)"/\1/')

if grep -nE 'lattice|citrate-ai/|\bTBD\b' "$README" >/dev/null; then
    bad "homebrew/README.md names a stale tap or placeholder: $(grep -nE 'lattice|citrate-ai/|\bTBD\b' "$README" | tr '\n' ' ')"
fi

if [[ $fail -ne 0 ]]; then exit 1; fi
echo "ok   - homebrew formula matches the release tarball"
