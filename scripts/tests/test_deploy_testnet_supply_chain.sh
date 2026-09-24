#!/usr/bin/env bash
# Tripwire for PBA-L6-001 / PBA-L6-006 (2026-09-24 pre-bounty audit):
# the public testnet deploy script must only install code from a
# CitrateNetwork-owned source, at an explicit version, after verifying the
# checksum and the cosign signature. Also guards the release workflow's
# signing step against failing open.
#
# Runs as an unprivileged user: argument validation in deploy_testnet.sh
# happens before its root check, so the bail paths are testable here.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/deploy_testnet.sh"
RELEASE_WFS=("$ROOT/.github/workflows/release.yml" "$ROOT/.github/workflows/release-tier2.yml")
# GitHub owners that are NOT registered to Citrate. Anyone can claim them,
# so no script may fetch from them. Extend when a dead owner is found.
UNOWNED_OWNERS=("citrate-ai")

fail=0
pass() { echo "ok   - $1"; }
flunk() { echo "FAIL - $1"; fail=1; }

# 1. No script fetches from an unowned GitHub owner.
for owner in "${UNOWNED_OWNERS[@]}"; do
    if grep -rIn "github.com/${owner}/" "$ROOT/scripts" --exclude="$(basename "$0")" >/dev/null; then
        flunk "scripts reference unowned GitHub owner '${owner}'"
        grep -rIn "github.com/${owner}/" "$ROOT/scripts" --exclude="$(basename "$0")" | sed 's/^/       /'
    else
        pass "no script references unowned owner '${owner}'"
    fi
done

# 2. No script installs whatever happens to be 'latest'.
if grep -rIn 'releases/latest' "$ROOT/scripts" --exclude="$(basename "$0")" >/dev/null; then
    flunk "scripts download from releases/latest (unpinned)"
else
    pass "no releases/latest downloads"
fi

run_args() { bash "$SCRIPT" "$@" 2>&1; }
coinbase="0x1111111111111111111111111111111111111111"

# 3. An explicit version is required.
out=$(run_args testnet.example.org --coinbase "$coinbase"); rc=$?
if [[ $rc -ne 0 && "$out" == *"--version"* ]]; then pass "bails without --version"; else flunk "must bail without --version (rc=$rc)"; fi

# 4. An operator-supplied coinbase is required and validated.
out=$(run_args testnet.example.org --version v0.5.0-beta1); rc=$?
if [[ $rc -ne 0 && "$out" == *"--coinbase"* ]]; then pass "bails without --coinbase"; else flunk "must bail without --coinbase (rc=$rc)"; fi
out=$(run_args testnet.example.org --version v0.5.0-beta1 --coinbase 0x1234); rc=$?
if [[ $rc -ne 0 && "$out" == *"coinbase"* ]]; then pass "rejects malformed coinbase"; else flunk "must reject malformed coinbase (rc=$rc)"; fi
if grep -q 'sha256sum' "$SCRIPT" && grep -q 'COINBASE_SEED' "$SCRIPT"; then flunk "coinbase must not be derived from a hash"; else pass "coinbase not hash-derived"; fi

# 5. Verification is present, pinned and fail-closed.
grep -q 'cosign verify-blob' "$SCRIPT" && pass "cosign verify-blob present" || flunk "cosign verify-blob missing"
grep -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "$SCRIPT" \
    && pass "OIDC issuer pinned" || flunk "OIDC issuer not pinned"
grep -q -- '--certificate-identity-regexp' "$SCRIPT" && grep -q 'CitrateNetwork/citrate-chain/\\.github/workflows/' "$SCRIPT" \
    && pass "certificate identity pinned to CitrateNetwork/citrate-chain workflows" || flunk "certificate identity not pinned"
grep -q 'sha256sum -c' "$SCRIPT" && pass "checksum verified" || flunk "checksum verification missing"
if grep -nE '(cosign verify-blob|sha256sum -c)[^|]*\|\|[[:space:]]*true' "$SCRIPT" >/dev/null; then
    flunk "verification step fails open (|| true)"
else
    pass "verification does not fail open"
fi

# 6. No release pipeline may publish when signing fails. release.yml signs the
#    tarballs this script verifies; release-tier2.yml signs the installers.
for wf in "${RELEASE_WFS[@]}"; do
    if grep -nE 'cosign sign-blob' -A4 "$wf" | grep -qE '\|\|[[:space:]]*true'; then
        flunk "$(basename "$wf") cosign sign-blob ends in '|| true' (unsigned artifacts ship silently)"
    else
        pass "$(basename "$wf") signing fails closed"
    fi
done

exit $fail
