# shellcheck shell=bash
# scripts/genesis/lib.sh: helpers shared by the genesis ceremony scripts. Source it; don't run it.
#
# Conventions every script here follows:
#   * Dry run is the default. Nothing that writes (a broadcast, a file move, a service stop)
#     happens without an explicit --confirm.
#   * Signing is by Foundry keystore account only (--account NAME, optional --password-file
#     PATH). A raw private key is refused on the command line and in the environment, so no
#     script here ever holds, prints or logs key material.
#   * External tools are named through env (CAST, FORGE, SYSTEMCTL, ...) so the tests can
#     substitute fakes and run with no network and no root.

GENESIS_LOG_TAG="${GENESIS_LOG_TAG:-genesis}"

log() { printf '[%s] %s\n' "$GENESIS_LOG_TAG" "$*"; }
err() { printf '[%s] ERROR: %s\n' "$GENESIS_LOG_TAG" "$*" >&2; }
die() {
  err "$1"
  exit "${2:-1}"
}

# is_addr <s>: a 0x-prefixed 20-byte hex address.
is_addr() { [[ "$1" =~ ^0x[0-9a-fA-F]{40}$ ]]; }

# lower <s>
lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }

# is_local_rpc <url>: loopback only. Anything else counts as remote.
is_local_rpc() { [[ "$1" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/.*)?$ ]]; }

# refuse_raw_keys: fail if a raw private key is present in the environment. The names are
# checked, never the values.
refuse_raw_keys() {
  local v
  for v in PRIVATE_KEY DEPLOYER_PRIVATE_KEY DEPLOYER_PK ETH_PRIVATE_KEY; do
    if [[ -n "${!v:-}" ]]; then
      die "$v is set in the environment. These scripts sign with a Foundry keystore account only (--account); unset it." 1
    fi
  done
}

# describe_cmd <argv...>: print a command for a dry-run plan. Arguments that follow
# --password-file are shown as given (a path), never read.
describe_cmd() {
  local out="" a
  for a in "$@"; do
    if [[ "$a" =~ [[:space:]] ]]; then out+=" '$a'"; else out+=" $a"; fi
  done
  printf '    DRYRUN%s\n' "$out"
}
