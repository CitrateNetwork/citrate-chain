#!/usr/bin/env bash
# wallet_sdk_wasm_gate.sh — citrate-wallet-sdk must build for wasm32 as-is.
#
# The browser extension loads wallet-sdk/src/wasm.rs (Argon2id KDF,
# constant-time secp256k1) as a wasm-pack `no-modules` bundle. That only works
# if the crate's wasm build carries no native-only dependency: tokio with mio,
# reqwest, or wallet-core's `native` tree do not compile for
# wasm32-unknown-unknown. This gate keeps it that way:
#
#   1. tree      `cargo tree` of the wasm build (--no-default-features
#                --features wasm, target wasm32) has none of the native-only
#                crates below. Negative control: the default (native) build
#                of the same crate must still show tokio, or the scan is blind.
#   2. check     `cargo check --target wasm32-unknown-unknown` with
#                --no-default-features, and with --features wasm.
#   3. wasm-pack `wasm-pack build --target no-modules --release --no-opt` at the
#                pinned wasm-pack and wasm-bindgen, then checks the glue is a
#                classic script that defines the `wasm_bindgen` global and
#                exports the KDF and signer, and prints SHA-256 of both files.
#
# Usage:
#   scripts/ci/wallet_sdk_wasm_gate.sh                 # all steps; step 3 is
#                                                      # skipped (and said so)
#                                                      # if the pinned wasm-pack
#                                                      # is not installed
#   scripts/ci/wallet_sdk_wasm_gate.sh --require-pack  # step 3 is mandatory (CI)
#   scripts/ci/wallet_sdk_wasm_gate.sh --out DIR       # also copy the bundle to DIR
#
# Exit: 0 pass · 1 fail · 3 the wasm32-unknown-unknown target is not installed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Pins. Keep equal to citrate-wallet-extension vendor/wasm/BUILD_PINS.
WASM_PACK_VERSION="0.14.0"
WASM_BINDGEN_VERSION="0.2.118"
TARGET="wasm32-unknown-unknown"
PKG="citrate-wallet-sdk"
OUT_NAME="citrate_wallet_sdk"
# Crates that must never be in the wasm build of the SDK.
NATIVE_ONLY="tokio mio reqwest hyper socket2 citrate-wallet-core citrate-consensus citrate-execution citrate-security"

REQUIRE_PACK=0; OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --require-pack) REQUIRE_PACK=1; shift ;;
    --out) OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

rc=0
fail() { echo "FAIL: $*"; rc=1; }

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
  echo "SKIP: rust target $TARGET not installed (rustup target add $TARGET)"
  exit 3
fi

# ── 1. dependency tree ─────────────────────────────────────────────────────
tree_names() { # <cargo feature args...> ; crate names in the normal-dep tree
  cargo tree --locked --target "$TARGET" -e normal --prefix none -p "$PKG" "$@" 2>/dev/null \
    | awk '{print $1}' | sort -u
}
native_hits() { # <names> ; prints the native-only crates present
  local n
  for n in $NATIVE_ONLY; do grep -qx "$n" <<<"$1" && echo "$n"; done
}
wasm_tree="$(tree_names --no-default-features --features wasm)"
native_tree="$(tree_names)"
if [ -z "$wasm_tree" ] || [ -z "$native_tree" ]; then
  fail "cargo tree produced no output for $PKG"
else
  if ! grep -qx tokio <<<"$native_tree"; then
    fail "negative control: the default build of $PKG no longer shows tokio, so this scan cannot see a native dependency"
  fi
  hits="$(native_hits "$wasm_tree")"
  if [ -n "$hits" ]; then
    fail "the wasm build of $PKG pulls native-only crates: $(echo $hits)"
  else
    echo "tree: wasm build of $PKG has none of: $NATIVE_ONLY"
  fi
fi

# ── 2. cargo check for wasm32 ──────────────────────────────────────────────
for feats in "" "--features wasm"; do
  # shellcheck disable=SC2086
  if out="$(cargo check --locked --target "$TARGET" -p "$PKG" --no-default-features $feats 2>&1)"; then
    echo "check: $TARGET --no-default-features $feats OK"
  else
    echo "$out" | grep -E '^error' | head -5
    fail "cargo check --target $TARGET -p $PKG --no-default-features $feats"
  fi
done

# ── 3. wasm-pack no-modules bundle ─────────────────────────────────────────
have_wp="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
if [ "$have_wp" != "$WASM_PACK_VERSION" ]; then
  msg="wasm-pack ${have_wp:-not installed}, $WASM_PACK_VERSION pinned (cargo install wasm-pack --version $WASM_PACK_VERSION --locked)"
  if [ "$REQUIRE_PACK" -eq 1 ]; then fail "$msg"; else echo "SKIP wasm-pack step: $msg"; fi
  exit "$rc"
fi
lock_bindgen="$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/"/,"",$3); print $3}' Cargo.lock | sort -u)"
if [ "$lock_bindgen" != "$WASM_BINDGEN_VERSION" ]; then
  fail "Cargo.lock has wasm-bindgen '$lock_bindgen', $WASM_BINDGEN_VERSION pinned"
  exit "$rc"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/wallet-sdk-wasm.XXXXXX")"
case "$work" in "${TMPDIR:-/tmp}"/wallet-sdk-wasm.*) ;; *) echo "unexpected temp dir $work"; exit 1 ;; esac
trap 'rm -rf -- "${work:?}"' EXIT
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
# Own target subdir: the remap RUSTFLAGS would otherwise invalidate the
# normal build cache. Source paths are remapped so the bytes do not depend on
# where the repo is checked out.
if ! out="$(
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/wallet-sdk-wasm" \
  RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=/citrate-chain --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup" \
  wasm-pack build wallet-sdk \
    --target no-modules --release --no-opt --no-typescript --no-pack \
    --out-dir "$work/out" --out-name "$OUT_NAME" \
    -- --locked --no-default-features --features wasm 2>&1)"; then
  echo "$out" | grep -E '^(error|Error)' | head -10
  fail "wasm-pack build --target no-modules"
  exit "$rc"
fi
js="$work/out/$OUT_NAME.js"; wasm="$work/out/${OUT_NAME}_bg.wasm"
[ -s "$js" ] && [ -s "$wasm" ] || { fail "wasm-pack did not produce $OUT_NAME.js and ${OUT_NAME}_bg.wasm"; exit "$rc"; }
grep -qE '^let wasm_bindgen' "$js" || fail "glue does not define the global wasm_bindgen (not a no-modules build?)"
grep -qE '^(export|import) |import\.meta' "$js" && fail "glue uses ES module syntax; a classic service worker cannot importScripts() it"
for sym in argon2_v2_derive_key secp256k1_sign_hash secp256k1_public_key secp256k1_address; do
  grep -q "$sym" "$js" || fail "glue does not export $sym"
done
echo "wasm-pack $WASM_PACK_VERSION / wasm-bindgen $WASM_BINDGEN_VERSION, --target no-modules --release --no-opt:"
( cd "$work/out" && sha256sum "$OUT_NAME.js" "${OUT_NAME}_bg.wasm" ) | sed 's/^/  /'
if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR" && cp "$js" "$wasm" "$OUT_DIR/" && echo "copied bundle to $OUT_DIR"
fi
exit "$rc"
