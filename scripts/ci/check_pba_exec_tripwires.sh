#!/usr/bin/env bash
# check_pba_exec_tripwires.sh — source-level fences for the PBA-R2 CHAIN-EXEC
# finding classes (pre-bounty audit 2026-09-24). Cheap (grep only), so it runs
# in `local-ci.sh --fast` and on every PR (.github/workflows/pba-tripwires.yml).
#
#   T1  PBA-L1a-007  no shipped script / unit / config disables tx signature
#                    verification (CITRATE_REQUIRE_VALID_SIGNATURE=0/false/...).
#   T2  PBA-L1a-003  every shipped citrate-node build uses the DEFAULT feature
#                    set (no --features / --no-default-features on a citrate-node
#                    build line), and node/Cargo.toml's default enables
#                    commd-fold-verify. Mixed feature sets fork on 0x0130.
#   T3  PBA-L1a-017  node/src/main.rs keeps the periodic Mempool::clear_expired.
#   T4  PBA-L1a-024  the metrics server never defaults to 0.0.0.0.
#   T5  PBA-R2       node/src/main.rs publishes the activation height from
#                    citrate_consensus::hardening::init_pba_hardening_height
#                    (config + env override), never from the raw config field.
#
# Usage: check_pba_exec_tripwires.sh            # scan the tree
#        check_pba_exec_tripwires.sh --self-test # prove each scan detects its class
set -uo pipefail

REPO_ROOT="${PBA_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# T1: a falsy assignment of the signature switch.
SIG_BYPASS_RE='CITRATE_REQUIRE_VALID_SIGNATURE[[:space:]]*[=:][[:space:]]*"?(0|false|no|off)([^[:alnum:]_]|$)'
# T2: a citrate-node build line that changes the feature set.
node_build_lines() { grep -E 'cargo[[:space:]]+(build|install|run)[[:space:]].*(-p[[:space:]]+citrate-node|--bin[[:space:]]+citrate(-node)?([^[:alnum:]_-]|$)|--package[[:space:]]+citrate-node)' "$@" 2>/dev/null; }
FEATURE_FLAG_RE='(--features|--all-features|--no-default-features)'

existing() { local p; for p in "$@"; do [ -e "$p" ] && printf '%s\n' "$p"; done; }

scan_sig_bypass() { # <root> ; prints hits, returns 0 iff any
  local root="$1" paths hits
  paths=$(existing "$root/scripts" "$root/docker" "$root/.github" "$root/node/config" \
            "$root/config" "$root/homebrew" "$root"/Dockerfile* "$root"/docker-compose*.yml)
  [ -n "$paths" ] || return 1
  # shellcheck disable=SC2086
  hits=$(grep -rInE "$SIG_BYPASS_RE" $paths 2>/dev/null | grep -v 'check_pba_exec_tripwires.sh' || true)
  [ -n "$hits" ] && { echo "$hits"; return 0; }
  return 1
}

scan_node_features() { # <root> ; prints hits, returns 0 iff any
  local root="$1" paths files hits
  paths=$(existing "$root/scripts" "$root/.github" "$root/docker" "$root"/Dockerfile*)
  [ -n "$paths" ] || return 1
  # shellcheck disable=SC2086
  files=$(grep -rlE 'citrate-node|--bin[[:space:]]+citrate' $paths 2>/dev/null \
          | grep -v 'check_pba_exec_tripwires.sh' || true)
  [ -n "$files" ] || return 1
  # shellcheck disable=SC2086
  hits=$(node_build_lines $files | grep -E "$FEATURE_FLAG_RE" || true)
  [ -n "$hits" ] && { echo "$hits"; return 0; }
  return 1
}

default_features_ok() { # <node Cargo.toml>
  grep -qE '^default[[:space:]]*=[[:space:]]*\[[^]]*"commd-fold-verify"' "$1"
}

clear_expired_wired() { # <node main.rs>
  grep -qE '\.clear_expired\(\)' "$1"
}

metrics_wildcard() { # <node main.rs>
  grep -nE '"0\.0\.0\.0:9100"|Ipv4Addr::UNSPECIFIED,[[:space:]]*9100' "$1" 2>/dev/null
}

activation_resolved() { # <node main.rs>
  grep -q 'init_pba_hardening_height(' "$1" 2>/dev/null \
    && ! grep -qE 'set_pba_hardening_height\([[:space:]]*config\.chain\.pba_hardening_height' "$1" 2>/dev/null
}

run_scan() { # <root>
  local root="$1" rc=0 out
  if out=$(scan_sig_bypass "$root"); then
    echo "T1 PBA-L1a-007: signature verification disabled in a shipped file:"; echo "$out"; rc=1
  fi
  if out=$(scan_node_features "$root"); then
    echo "T2 PBA-L1a-003: citrate-node built with a non-default feature set:"; echo "$out"; rc=1
  fi
  if ! default_features_ok "$root/node/Cargo.toml"; then
    echo "T2 PBA-L1a-003: node/Cargo.toml default features must include commd-fold-verify"; rc=1
  fi
  if ! clear_expired_wired "$root/node/src/main.rs"; then
    echo "T3 PBA-L1a-017: node/src/main.rs no longer calls Mempool::clear_expired"; rc=1
  fi
  if out=$(metrics_wildcard "$root/node/src/main.rs"); then
    echo "T4 PBA-L1a-024: metrics server defaults to 0.0.0.0:"; echo "$out"; rc=1
  fi
  if ! activation_resolved "$root/node/src/main.rs"; then
    echo "T5 PBA-R2: main.rs must publish via init_pba_hardening_height (config + env override)"; rc=1
  fi
  return "$rc"
}

self_test() {
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/scripts" "$tmp/node/src" "$tmp/node/config" "$tmp/.github" "$tmp/docker" "$tmp/config" "$tmp/homebrew"
  # A clean tree must pass...
  printf '[features]\ndefault = ["commd-fold-verify"]\n' > "$tmp/node/Cargo.toml"
  printf 'fn f(){ m.clear_expired().await; let a = "127.0.0.1:9100"; let p = init_pba_hardening_height(x); }\n' > "$tmp/node/src/main.rs"
  printf 'cargo build --release -p citrate-node\n' > "$tmp/scripts/build.sh"
  run_scan "$tmp" >/dev/null || { echo "self-test: clean tree flagged"; return 1; }
  # ...and each seeded violation must be caught.
  local fails=0
  printf 'Environment=CITRATE_REQUIRE_VALID_SIGNATURE=0\n' > "$tmp/scripts/unit.sh"
  run_scan "$tmp" >/dev/null && { echo "self-test: T1 missed"; fails=1; }
  rm "$tmp/scripts/unit.sh"
  printf 'cargo build --release -p citrate-node --features commd-fold-verify\n' > "$tmp/scripts/b2.sh"
  run_scan "$tmp" >/dev/null && { echo "self-test: T2 (flag) missed"; fails=1; }
  rm "$tmp/scripts/b2.sh"
  printf '[features]\ndefault = []\n' > "$tmp/node/Cargo.toml"
  run_scan "$tmp" >/dev/null && { echo "self-test: T2 (default) missed"; fails=1; }
  printf '[features]\ndefault = ["commd-fold-verify"]\n' > "$tmp/node/Cargo.toml"
  printf 'fn f(){ let a = "127.0.0.1:9100"; let p = init_pba_hardening_height(x); }\n' > "$tmp/node/src/main.rs"
  run_scan "$tmp" >/dev/null && { echo "self-test: T3 missed"; fails=1; }
  printf 'fn f(){ m.clear_expired().await; let a = "0.0.0.0:9100"; let p = init_pba_hardening_height(x); }\n' > "$tmp/node/src/main.rs"
  run_scan "$tmp" >/dev/null && { echo "self-test: T4 missed"; fails=1; }
  printf 'fn f(){ m.clear_expired().await; set_pba_hardening_height(config.chain.pba_hardening_height); }\n' > "$tmp/node/src/main.rs"
  run_scan "$tmp" >/dev/null && { echo "self-test: T5 missed"; fails=1; }
  [ "$fails" -eq 0 ] && echo "self-test OK"
  return "$fails"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi
if run_scan "$REPO_ROOT"; then
  echo "PBA-R2 CHAIN-EXEC tripwires: clean"
  exit 0
fi
exit 1
