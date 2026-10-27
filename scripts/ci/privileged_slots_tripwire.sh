#!/usr/bin/env bash
# privileged_slots_tripwire.sh: every privileged slot of a DeployAll contract is
# read by the post-deploy deployer/factory sweep (contracts/script/lib/AdminChecks.sol)
# or exempt for a stated reason (contracts/script/lib/privileged_slots.json).
# See privileged_slots_tripwire.py for the rules.
#
# Usage: privileged_slots_tripwire.sh              # scan the tree
#        privileged_slots_tripwire.sh --self-test  # prove each negative control is caught
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -I "$here/privileged_slots_tripwire.py" "$@"
