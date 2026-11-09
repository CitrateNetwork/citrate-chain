#!/usr/bin/env bash
# finality_finalize_retry_wired_tripwire.sh — the finality driver's periodic
# tick retries quorum checkpoints whose certificate write failed.
#
# `finalize_checkpoint` is fail-closed: when the certificate cannot be written
# durably nothing finalizes and the checkpoint stays pending with its votes.
# If the only retry is "the next vote for that height", finality stalls for
# good once every committee member has voted. The retry lives in
# `FinalityGadget::retry_finalizations`, driven by the 1 s driver tick through
# `finality_driver::retry_finalizations`. The unit/integration tests drive that
# step directly; this tripwire pins the call in the spawned loop itself.
#
# Rule: in node/src/finality_driver.rs, the body of `pub fn spawn` (above the
# first `#[cfg(test)]`) contains a non-comment call `retry_finalizations(`.
#
# Usage: finality_finalize_retry_wired_tripwire.sh              # scan the tree
#        finality_finalize_retry_wired_tripwire.sh --self-test  # prove the rule still detects its class
set -uo pipefail

REPO_ROOT="${FINALITY_RETRY_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

wired() { # <file> ; returns 0 iff spawn's body calls retry_finalizations(
  [ -f "$1" ] || return 1
  # shellcheck disable=SC2016  # the single-quoted block is a perl program, not shell
  perl -ne '
    $test = 1 if /^#\[cfg\(test\)\]/;
    next if $test || /^\s*\/\//;
    if (!$in && /^pub fn spawn\b/) { $in = 1; }
    if ($in) {
      $found = 1 if /\bretry_finalizations\(/;
      $in = 0 if /^\}/;
    }
    END { exit($found ? 0 : 1) }' "$1"
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  # Positive (wired): the loop calls the retry step.
  printf 'pub fn spawn(g: G) -> H {\n    tokio::spawn(async move {\n        loop {\n            tick.tick().await;\n            retry_finalizations(&g, Instant::now()).await;\n        }\n    })\n}\n' > "$d/a.rs"
  wired "$d/a.rs" || { echo "self-test: missed a wired retry"; rc=1; }
  # Negative: the call commented out, only in another fn, or only in tests.
  printf 'pub fn spawn(g: G) -> H {\n    tokio::spawn(async move {\n        loop {\n            tick.tick().await;\n            // retry_finalizations(&g, Instant::now()).await;\n        }\n    })\n}\npub async fn retry_finalizations(g: &G, now: Instant) {}\nfn other() { retry_finalizations(&g, now); }\n#[cfg(test)]\nmod tests {\n    pub fn spawn() { retry_finalizations(&g, now); }\n}\n' > "$d/a.rs"
  wired "$d/a.rs" && { echo "self-test: accepted a loop that never retries"; rc=1; }
  [ $rc -eq 0 ] && echo "finality finalize-retry wiring tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if ! wired "$REPO_ROOT/node/src/finality_driver.rs"; then
  echo "finality finalize-retry wiring tripwire: FAILED (finality_driver::spawn must call retry_finalizations on its tick)"
  exit 1
fi
echo "finality finalize-retry wiring tripwire: clean"
