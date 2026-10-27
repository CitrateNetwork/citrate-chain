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

# refuse_keystore_env <account>: forge also takes its keystore inputs from the environment
# (ETH_PASSWORD: the password file; ETH_KEYSTORE: a keystore path; ETH_KEYSTORE_ACCOUNT: the
# account), and every child process inherits them. The password reaches forge only through
# --password-file, which is checked, so ETH_PASSWORD is refused by name. The keystore selectors
# must be unset or name the same keystore as --account. Values are compared, never printed.
refuse_keystore_env() {
  local acct="$1" ks_dir want have
  if [[ -n "${ETH_PASSWORD+x}" ]]; then
    die "ETH_PASSWORD is set in the environment: forge would read the keystore password through it, outside the --password-file check; unset it and pass --password-file PATH" 1
  fi
  if [[ -n "${ETH_KEYSTORE_ACCOUNT+x}" && "${ETH_KEYSTORE_ACCOUNT}" != "$acct" ]]; then
    die "ETH_KEYSTORE_ACCOUNT is set in the environment and does not name the --account keystore; unset it" 1
  fi
  if [[ -n "${ETH_KEYSTORE+x}" ]]; then
    [[ -n "$acct" ]] || die "ETH_KEYSTORE is set in the environment without --account; unset it" 1
    ks_dir="${HOME:-}/.foundry/keystores"
    want=$("${PY:-python3}" -I -c 'import os,sys; print(os.path.normpath(os.path.abspath(sys.argv[1])))' "$ks_dir/$acct") || die "cannot resolve the --account keystore path" 1
    have=$("${PY:-python3}" -I -c 'import os,sys; print(os.path.normpath(os.path.abspath(sys.argv[1])))' "$ETH_KEYSTORE") || die "cannot resolve ETH_KEYSTORE" 1
    [[ "$have" == "$want" ]] || die "ETH_KEYSTORE is set in the environment and is not the --account keystore; unset it" 1
  fi
}

# password_file_check <path> [identity]: the keystore password file is a regular file (not a
# symlink) of the effective user, with no group or world bits, in a directory no other user can
# change. Prints its identity; with <identity>, also requires the file to be unchanged since
# that check. On refusal prints the reason (never the path) and returns 1. The file is not read.
GENESIS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
password_file_check() { "${PY:-python3}" -I "$GENESIS_LIB_DIR/secret_file_check.py" --password-file "$@"; }

# refuse_forge_output_env [dotenv file...]: the sends-once guard (C10) and the book checks read this run's
# broadcast records from contracts/broadcast/. forge takes that directory and its script cache
# from its config, which FOUNDRY_BROADCAST, FOUNDRY_CACHE_PATH, FOUNDRY_CACHE, FOUNDRY_PROFILE,
# FOUNDRY_CONFIG (and DAPP_ forms, any case) change: a send recorded elsewhere is invisible to
# the guard. Each is refused by name, in the environment and in the dotenv files forge loads
# (forge_output_check.py lists them and why); values are never printed.
refuse_forge_output_env() {
  local why
  why=$("${PY:-python3}" -I "$GENESIS_LIB_DIR/forge_output_check.py" env --dotenv "$@" 2>&1) || die "$why" 1
}
# forge_output_config_check <contracts dir> <forge>: what forge resolves (`forge config --json`
# in that directory, so a global ~/.foundry/foundry.toml or a profile counts too) records
# broadcasts in <dir>/broadcast and its script cache in <dir>/cache. Prints the reason and fails
# otherwise. Reads only; sends nothing.
forge_output_config_check() {
  local cfg
  cfg=$(cd "$1" && "$2" config --json 2>/dev/null) || {
    echo "cannot read forge's config (forge config --json in $1)"
    return 1
  }
  printf '%s' "$cfg" | "${PY:-python3}" -I "$GENESIS_LIB_DIR/forge_output_check.py" config --contracts "$1" 2>&1
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
