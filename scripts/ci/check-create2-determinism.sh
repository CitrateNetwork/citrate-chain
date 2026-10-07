#!/usr/bin/env bash
# ============================================================================
# check-create2-determinism.sh — CREATE2 reproducibility gate.
# ============================================================================
#
# Proves every ceremony contract's address is a pure function of
# (Arachnid factory, salt, init_code) and therefore reproducible on any box —
# the property the whole reroll-stable address book relies on (see
# contracts/script/Salts.sol). Run in solidity-ci and by scripts/ops/regenesis.sh.
#
# It does NOT assert frozen literals (a FRESH-KEYS reroll deliberately moves the
# key-derived addresses — owner ruling + MAC audit). It asserts the RELATIONSHIPS:
#   * deploys go through CREATE2 (nonce-independent), and
#   * each script's projection helper == the CREATE2 cheatcode, and
#   * key-independent contracts DON'T move while key-derived ones DO.
#
# Determinism holds ONLY under the DEFAULT foundry profile (solc 0.8.36,
# optimizer 200, via_ir, bytecode_hash=none) — see the test headers.
#
# Exit codes: 0 all determinism suites pass · 1 a suite failed · 2 setup error
# ============================================================================
set -euo pipefail

# Determinism is a property of the DEFAULT (non-reroll) deploy: the reroll switch
# (CITRATE_REROLL) flips _keptLive()/regGov in DeployAll, which moves addresses and
# would make these relationship assertions test a different graph than the canonical
# one. regenesis.sh and the ceremony env export CITRATE_REROLL, so scrub it here so
# the gate is reroll-agnostic no matter what environment invoked it.
unset CITRATE_REROLL

# Run the determinism suites SINGLE-THREADED. `vm.setEnv` is process-global in
# foundry, and some suites mutate env (e.g. AaDeterminismHardening sets
# CITRATE_AA_OWNER/IDENTITY_SIGNER/SPONSOR_SIGNER) while other tests read the same
# vars. Under the default parallel runner, with the ceremony env loaded, that races
# ~2/12 and yields a FALSE "do not proceed" at the cut. Serial execution removes the
# race so the gate is deterministic regardless of the ambient (ceremony) environment.
FORGE_DET_FLAGS="--threads 1"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS="${REPO_ROOT}/contracts"

log() { echo "[check-create2] $*"; }
err() { echo "[check-create2] ERROR: $*" >&2; }

command -v forge >/dev/null || { err "forge not on PATH"; exit 2; }
cd "$CONTRACTS"

# Determinism test suites (whole-repo profile).
SUITES=(
  "test/aa/AaDeterminism.t.sol"
  "test/aa/AaDeterminismHardening.t.sol"
  "test/ValidatorRegistryCreate2.t.sol"
  "test/Create2Determinism.t.sol"
  "test/pba_r2/PBA_R2_DeployAllKeepLive.t.sol"
)

rc=0
for s in "${SUITES[@]}"; do
  if [[ -f "$s" ]]; then
    log "→ $s"
    if ! FOUNDRY_PROFILE=default forge test $FORGE_DET_FLAGS --match-path "$s" >/dev/null 2>&1; then
      err "determinism suite FAILED: $s"
      FOUNDRY_PROFILE=default forge test $FORGE_DET_FLAGS --match-path "$s" || true
      rc=1
    fi
  else
    log "skip (absent): $s"
  fi
done

# CoreMembership CREATE2 gate runs under its own closure-scoped profile
# (foundry.toml [profile.membership]) — a whole-repo compile can move the
# via-IR bytecode, so it must run isolated. See MAC item #5.
if [[ -f "test/CoreMembershipCreate2.t.sol" ]]; then
  log "→ test/CoreMembershipCreate2.t.sol (profile=membership, closure-scoped)"
  if ! FOUNDRY_PROFILE=membership forge test $FORGE_DET_FLAGS >/dev/null 2>&1; then
    err "membership CREATE2 gate FAILED"
    FOUNDRY_PROFILE=membership forge test $FORGE_DET_FLAGS || true
    rc=1
  fi
fi

if [[ "$rc" == "0" ]]; then
  log "✅ CREATE2 determinism verified (all suites reproducible)."
else
  err "CREATE2 determinism check FAILED — do not proceed with the reroll."
fi
exit "$rc"
