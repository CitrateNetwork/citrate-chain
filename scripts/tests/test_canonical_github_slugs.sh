#!/usr/bin/env bash
# Tripwire (2026-09-24 pre-bounty audit): every GitHub link to Citrate code
# must use the canonical org, github.com/CitrateNetwork/<repo>.
#   - citrate-ai, citrate-network: NOT registered to Citrate; anyone can claim
#     them and serve code or releases at those paths (PBA-L6-001/-004).
#   - SaulBuilds/citrate: the private pre-split monorepo; a 404 for the public.
# Usage: test_canonical_github_slugs.sh [repo-root]   (default: this repo)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
# Fail closed: a bad path must not read as "no hits".
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || { echo "FAIL - not a git repository: $ROOT"; exit 2; }
PATTERN='(github\.com[/:]|raw\.githubusercontent\.com/)(citrate-ai|citrate-network|SaulBuilds/citrate([^A-Za-z0-9_-]|$))'
hits=$(git -C "$ROOT" grep -I -n -i -E "$PATTERN" -- . \
    ':!contracts/lib/**' ':!**/node_modules/**' ':!**/vendor/**' \
    ':!scripts/tests/test_canonical_github_slugs.sh' \
    ':!scripts/tests/test_deploy_testnet_supply_chain.sh' 2>/dev/null)
if [[ -n "$hits" ]]; then
    echo "FAIL - non-canonical GitHub owner slugs (use github.com/CitrateNetwork/<repo>):"
    echo "$hits" | sed 's/^/       /'
    exit 1
fi
echo "ok   - all GitHub links use github.com/CitrateNetwork/"
