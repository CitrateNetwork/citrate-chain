#!/usr/bin/env bash
# Pins the release source of scripts/deploy_testnet.sh.
#
# The deploy script builds every download and clone URL from the
# RELEASE_REPO variable, so a grep for literal owner names cannot see a
# change to that variable. This test reads the variable itself and every
# GitHub URL the script can reach, and fails unless all of them resolve to
# CitrateNetwork/citrate-chain. Read-only: it never runs the deploy script.
#
# Usage: test_deploy_testnet_release_source.sh [repo-root]
#        test_deploy_testnet_release_source.sh --self-test
set -uo pipefail

EXPECTED_REPO="CitrateNetwork/citrate-chain"

check_script() { # <deploy script> ; prints failures, returns 0 iff clean
    local script="$1" fail=0 assigns repo urls bad
    assigns=$(grep -cE '^[[:space:]]*RELEASE_REPO=' "$script")
    if [[ "$assigns" -ne 1 ]]; then
        echo "FAIL - RELEASE_REPO must be assigned exactly once (found $assigns)"; fail=1
    fi
    repo=$(sed -nE 's/^[[:space:]]*RELEASE_REPO="?([^"[:space:]]*)"?.*/\1/p' "$script" | head -1)
    if [[ "$repo" != "$EXPECTED_REPO" ]]; then
        echo "FAIL - RELEASE_REPO is '$repo', expected '$EXPECTED_REPO'"; fail=1
    fi
    # Every GitHub URL must name the pinned repo, literally or via the variable.
    urls=$(grep -oE 'github\.com/[^"[:space:])]+' "$script" | sort -u)
    bad=$(printf '%s\n' "$urls" | grep -vE "^github\.com/(\\\$RELEASE_REPO|\\\$\{RELEASE_REPO\}|${EXPECTED_REPO})([/.]|$)" | grep -v '^$' || true)
    if [[ -n "$bad" ]]; then
        echo "FAIL - GitHub URLs outside $EXPECTED_REPO:"; printf '       %s\n' $bad; fail=1
    fi
    # The clone and the download must both go through the pinned variable.
    grep -qE 'git clone .*https://github\.com/\$RELEASE_REPO\.git' "$script" \
        || { echo "FAIL - --build-from-source clone is not built from RELEASE_REPO"; fail=1; }
    grep -qE 'BASE_URL="https://github\.com/\$RELEASE_REPO/releases/download/\$VERSION"' "$script" \
        || { echo "FAIL - release download URL is not built from RELEASE_REPO at --version"; fail=1; }
    return "$fail"
}

self_test() {
    local tmp rc=0
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp:?}"' RETURN
    local good='RELEASE_REPO="CitrateNetwork/citrate-chain"
git clone --depth 1 --branch "$VERSION" "https://github.com/$RELEASE_REPO.git" "$BUILD_DIR"
BASE_URL="https://github.com/$RELEASE_REPO/releases/download/$VERSION"
# github.com/CitrateNetwork/citrate-chain releases'
    printf '%s\n' "$good" > "$tmp/ok.sh"
    check_script "$tmp/ok.sh" >/dev/null || { echo "self-test: clean script flagged"; rc=1; }
    printf '%s\n' "${good/CitrateNetwork\/citrate-chain\"/someone-else/citrate-chain\"}" > "$tmp/owner.sh"
    check_script "$tmp/owner.sh" >/dev/null && { echo "self-test: changed RELEASE_REPO missed"; rc=1; }
    printf '%s\ncurl -fsSL https://github.com/other/repo/raw/x.sh\n' "$good" > "$tmp/url.sh"
    check_script "$tmp/url.sh" >/dev/null && { echo "self-test: foreign URL missed"; rc=1; }
    printf '%s\nRELEASE_REPO="x/y"\n' "$good" > "$tmp/twice.sh"
    check_script "$tmp/twice.sh" >/dev/null && { echo "self-test: reassignment missed"; rc=1; }
    printf '%s\n' "${good//\$RELEASE_REPO\/releases/other/repo/releases}" > "$tmp/dl.sh"
    check_script "$tmp/dl.sh" >/dev/null && { echo "self-test: hard-coded download URL missed"; rc=1; }
    [[ "$rc" -eq 0 ]] && echo "self-test OK"
    return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit $?
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
if check_script "$ROOT/scripts/deploy_testnet.sh"; then
    echo "ok   - deploy_testnet.sh installs only from $EXPECTED_REPO"
    exit 0
fi
exit 1
