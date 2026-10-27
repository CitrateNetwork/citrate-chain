#!/usr/bin/env bash
# finality_certificate_durable_write_tripwire.sh — finalized checkpoint
# certificates are written with a synced write.
#
# The finalized checkpoint certificate (`DAG_METADATA` `checkpoint:{height}`)
# backs the finality floor and the finalized/safe RPC tags. It must be on
# stable storage before either moves, so it is written with
# `KvStore::kv_put_durable` (RocksDB `write_batch_sync`). A plain `kv_put` is a
# buffered write: it survives a process crash, not a power loss (#362).
#
# Rule: in production code (above the first `#[cfg(test)]`) of any Rust file in
# core/consensus/src or node/src that builds a `"checkpoint:` key, no `kv_put(`
# call is allowed. Use `kv_put_durable(`. (Test modules may write records
# directly to stage a store; `*_tests.rs` / `tests.rs` files are test-only.)
#
# Usage: finality_certificate_durable_write_tripwire.sh              # scan the tree
#        finality_certificate_durable_write_tripwire.sh --self-test  # prove the rule still detects its class
set -uo pipefail

REPO_ROOT="${FINALITY_CERT_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

scan() { # <dir>... ; prints violations, returns 0 iff any found
  local out
  # shellcheck disable=SC2016  # the single-quoted block is a perl program, not shell
  out="$(find "$@" -name '*.rs' -not -name '*_tests.rs' -not -name 'tests.rs' -not -path '*/tests/*' -not -path '*/target/*' 2>/dev/null | sort \
    | xargs -r perl -ne '
        $test = 1 if /^\s*#\[cfg\(test\)\]/;
        unless ($test || /^\s*\/\//) {
          $cert = 1 if /"checkpoint:/;
          push @puts, "$ARGV:$.: $_" if /\bkv_put\(/;
        }
        if (eof) {
          print @puts if $cert;
          close ARGV; @puts = (); $cert = 0; $test = 0;
        }')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  # Positive: a certificate record written with the buffered kv_put.
  printf 'fn persist(kv: &K, h: u64, b: &[u8]) {\n    let key = format!("checkpoint:{}", h);\n    if let Err(e) = kv.kv_put(cf::DAG_METADATA, key.as_bytes(), b) {\n        warn!("{}", e);\n    }\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null || { echo "self-test: did not detect a buffered certificate write"; rc=1; }
  # Negative: the synced write, and a kv_put confined to the test module.
  printf 'fn persist(kv: &K, h: u64, b: &[u8]) -> Result<(), String> {\n    let key = format!("checkpoint:{}", h);\n    kv.kv_put_durable(cf::DAG_METADATA, key.as_bytes(), b)\n}\n#[cfg(test)]\nmod tests {\n    fn stage(kv: &K) { kv.kv_put("m", b"checkpoint:1", b"x").unwrap(); }\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null && { echo "self-test: flagged a synced write or a test-only write"; rc=1; }
  # Negative: a file with no certificate key may use kv_put.
  printf 'fn other(kv: &K) { kv.kv_put("m", b"pruning_point", b"x").ok(); }\n' > "$d/a.rs"
  scan "$d" >/dev/null && { echo "self-test: flagged a file with no certificate key"; rc=1; }
  [ $rc -eq 0 ] && echo "finality certificate durable-write tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if scan "$REPO_ROOT/core/consensus/src" "$REPO_ROOT/node/src"; then
  echo "finality certificate durable-write tripwire: FAILED (write checkpoint certificates with KvStore::kv_put_durable, not kv_put)"
  exit 1
fi
echo "finality certificate durable-write tripwire: clean"
