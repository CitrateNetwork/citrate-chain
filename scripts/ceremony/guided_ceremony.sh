#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
readonly REAL_CHAIN_ID="40204"
readonly REHEARSAL_CHAIN_ID="40205"
readonly DEFAULT_OUTPUT_BASE="$REPO_ROOT/ceremony-output"

MODE=""
CHAIN_ID=""
RPC_URL=""
DEPLOYER_ACCOUNT=""
DEPLOYER_ADDRESS=""
SIGNER_1=""
SIGNER_2=""
SIGNER_3=""
GOVERNANCE=""
RELAYER=""
SALT_USD_RATE=""
GENESIS_FILE=""
INCLUDE_MODEL_ACCESS_CONTROL="1"
ENV_FILE=""
AUTO_RUN="1"

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_info() { echo -e "${CYAN}$1${NC}"; }
log_ok()   { echo -e "${GREEN}$1${NC}"; }
log_warn() { echo -e "${YELLOW}$1${NC}"; }
log_err()  { echo -e "${RED}$1${NC}" >&2; }

usage() {
    cat <<'EOF'
Usage:
  ./citrate_v0.01.1/scripts/ceremony/guided_ceremony.sh [options]

Options:
  --prepare-only   Collect values and write the temp env file, but do not run ceremony.sh
  -h, --help       Show this help

This wrapper prompts for the public values the ceremony needs, helps you pick
or create the deployer keystore account, writes a temporary env file under
/tmp, and can launch ceremony.sh for you.
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_err "Missing required command: $cmd"
        exit 1
    fi
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

prompt_text() {
    local prompt="$1"
    local default="${2:-}"
    local reply
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply || exit 1
        reply="${reply:-$default}"
    else
        read -r -p "$prompt: " reply || exit 1
    fi
    trim "$reply"
}

prompt_required() {
    local prompt="$1"
    local default="${2:-}"
    local value=""
    while [ -z "$value" ]; do
        value="$(prompt_text "$prompt" "$default")"
    done
    printf '%s' "$value"
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    local reply
    local suffix="[Y/n]"
    if [ "$default" = "n" ]; then
        suffix="[y/N]"
    fi

    while true; do
        read -r -p "$prompt $suffix: " reply || exit 1
        reply="$(trim "${reply:-$default}")"
        case "${reply,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
        esac
    done
}

is_address() {
    [[ "$1" =~ ^0x[a-fA-F0-9]{40}$ ]]
}

prompt_address_required() {
    local label="$1"
    local value=""
    while true; do
        value="$(prompt_required "$label")"
        if is_address "$value"; then
            printf '%s' "$value"
            return 0
        fi
        log_err "Expected an EVM address like 0xabc..."
    done
}

prompt_address_optional() {
    local label="$1"
    local value
    while true; do
        value="$(prompt_text "$label")"
        if [ -z "$value" ] || is_address "$value"; then
            printf '%s' "$value"
            return 0
        fi
        log_err "Expected an EVM address like 0xabc..., or leave it blank."
    done
}

print_existing_accounts() {
    log_info "Foundry keystore accounts visible on this host:"
    if ! cast wallet list 2>/dev/null; then
        log_warn "No existing accounts listed, or Foundry keystore not initialized yet."
    fi
}

ensure_account_missing() {
    local account="$1"
    local keystore_path="$HOME/.foundry/keystores/$account"
    if [ -e "$keystore_path" ]; then
        log_err "Keystore account already exists: $account"
        log_err "Choose a different name or use the existing-account path."
        exit 1
    fi
}

derive_account_address() {
    local account="$1"
    local addr
    addr="$(cast wallet address --account "$account" 2>/dev/null || true)"
    if ! is_address "$addr"; then
        log_err "Could not derive address for Foundry account: $account"
        exit 1
    fi
    printf '%s' "$addr"
}

choose_mode() {
    local mode_choice
    echo
    log_info "Step 1: Ceremony mode"
    echo "  1) real      -> actual shared 40204 ceremony"
    echo "  2) rehearsal -> disposable practice on 40205"
    while true; do
        mode_choice="$(prompt_required "Choose mode (1 or 2)" "1")"
        case "$mode_choice" in
            1|real)
                MODE="real"
                CHAIN_ID="$REAL_CHAIN_ID"
                return 0
                ;;
            2|rehearsal)
                MODE="rehearsal"
                CHAIN_ID="$REHEARSAL_CHAIN_ID"
                return 0
                ;;
        esac
        log_err "Enter 1 for real or 2 for rehearsal."
    done
}

choose_deployer_account() {
    local choice account_name
    echo
    log_info "Step 2: Deployer keystore account"
    echo "  1) use an existing Foundry keystore account"
    echo "  2) create a fresh Foundry keystore account now"
    echo "  3) import an existing EVM private key interactively"

    while true; do
        choice="$(prompt_required "Choose account flow (1, 2, or 3)" "1")"
        case "$choice" in
            1)
                print_existing_accounts
                account_name="$(prompt_required "Existing account name")"
                DEPLOYER_ACCOUNT="$account_name"
                DEPLOYER_ADDRESS="$(derive_account_address "$DEPLOYER_ACCOUNT")"
                return 0
                ;;
            2)
                mkdir -p "$HOME/.foundry/keystores"
                account_name="$(prompt_required "New account name" "ceremony-deployer")"
                ensure_account_missing "$account_name"
                log_info "Creating encrypted keystore entry. Foundry will prompt for a passphrase."
                cast wallet new "$HOME/.foundry/keystores" "$account_name"
                DEPLOYER_ACCOUNT="$account_name"
                DEPLOYER_ADDRESS="$(derive_account_address "$DEPLOYER_ACCOUNT")"
                return 0
                ;;
            3)
                mkdir -p "$HOME/.foundry/keystores"
                account_name="$(prompt_required "Imported account name" "ceremony-deployer")"
                ensure_account_missing "$account_name"
                log_info "Foundry will prompt for the private key locally. Nothing is sent to chat."
                cast wallet import "$account_name" --interactive
                DEPLOYER_ACCOUNT="$account_name"
                DEPLOYER_ADDRESS="$(derive_account_address "$DEPLOYER_ACCOUNT")"
                return 0
                ;;
        esac
        log_err "Enter 1, 2, or 3."
    done
}

collect_public_inputs() {
    local scope_choice

    echo
    log_info "Step 3: Public ceremony values"
    RPC_URL="$(prompt_required "RPC URL")"

    echo
    log_info "Vault signer addresses"
    SIGNER_1="$(prompt_address_required "SIGNER_1")"
    SIGNER_2="$(prompt_address_required "SIGNER_2")"
    SIGNER_3="$(prompt_address_required "SIGNER_3")"

    echo
    log_info "Optional addresses"
    echo "Leave blank only if you intentionally want the underlying deploy script"
    echo "to fall back to the deployer address."
    GOVERNANCE="$(prompt_address_optional "GOVERNANCE address (blank => deployer)")"
    RELAYER="$(prompt_address_optional "RELAYER address (blank => deployer)")"

    echo
    log_info "Contract scope"
    echo "  1) 36-contract ceremony (includes ModelAccessControl)"
    echo "  2) 35-contract ceremony (excludes ModelAccessControl)"
    while true; do
        scope_choice="$(prompt_required "Choose scope (1 or 2)" "1")"
        case "$scope_choice" in
            1|36)
                INCLUDE_MODEL_ACCESS_CONTROL="1"
                break
                ;;
            2|35)
                INCLUDE_MODEL_ACCESS_CONTROL="0"
                break
                ;;
        esac
        log_err "Enter 1 for 36 contracts or 2 for 35 contracts."
    done

    echo
    log_info "Optional overrides"
    SALT_USD_RATE="$(prompt_text "SALT_USD_RATE basis points (blank => script default 100)")"
    GENESIS_FILE="$(prompt_text "Genesis file path (blank => fetch block 0 from RPC)")"
}

write_env_file() {
    local timestamp
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    ENV_FILE="/tmp/citrate-ceremony-env.$timestamp.sh"
    umask 077
    : > "$ENV_FILE"

    {
        printf 'export CEREMONY_MODE=%q\n' "$MODE"
        printf 'export CEREMONY_CHAIN_ID=%q\n' "$CHAIN_ID"
        printf 'export CEREMONY_RPC_URL=%q\n' "$RPC_URL"
        printf 'export CEREMONY_DEPLOYER_ACCOUNT=%q\n' "$DEPLOYER_ACCOUNT"
        printf 'export CEREMONY_DEPLOYER_ADDRESS=%q\n' "$DEPLOYER_ADDRESS"
        printf 'export SIGNER_1=%q\n' "$SIGNER_1"
        printf 'export SIGNER_2=%q\n' "$SIGNER_2"
        printf 'export SIGNER_3=%q\n' "$SIGNER_3"
        printf 'export CEREMONY_INCLUDE_MODEL_ACCESS_CONTROL=%q\n' "$INCLUDE_MODEL_ACCESS_CONTROL"
        printf 'export CEREMONY_OUTPUT_DIR=%q\n' "$DEFAULT_OUTPUT_BASE"
        if [ -n "$GOVERNANCE" ]; then
            printf 'export GOVERNANCE=%q\n' "$GOVERNANCE"
        fi
        if [ -n "$RELAYER" ]; then
            printf 'export RELAYER=%q\n' "$RELAYER"
        fi
        if [ -n "$SALT_USD_RATE" ]; then
            printf 'export SALT_USD_RATE=%q\n' "$SALT_USD_RATE"
        fi
        if [ -n "$GENESIS_FILE" ]; then
            printf 'export CEREMONY_GENESIS_FILE=%q\n' "$GENESIS_FILE"
        fi
    } >> "$ENV_FILE"

    chmod 600 "$ENV_FILE"
}

print_summary() {
    echo
    echo -e "${BOLD}Ceremony summary${NC}"
    echo "  Mode:                     $MODE"
    echo "  Chain ID:                 $CHAIN_ID"
    echo "  RPC URL:                  $RPC_URL"
    echo "  Deployer account:         $DEPLOYER_ACCOUNT"
    echo "  Deployer address:         $DEPLOYER_ADDRESS"
    echo "  SIGNER_1:                 $SIGNER_1"
    echo "  SIGNER_2:                 $SIGNER_2"
    echo "  SIGNER_3:                 $SIGNER_3"
    echo "  GOVERNANCE:               ${GOVERNANCE:-<defaults to deployer>}"
    echo "  RELAYER:                  ${RELAYER:-<defaults to deployer>}"
    if [ "$INCLUDE_MODEL_ACCESS_CONTROL" = "1" ]; then
        echo "  Contract scope:           36 contracts"
    else
        echo "  Contract scope:           35 contracts"
    fi
    echo "  SALT_USD_RATE:            ${SALT_USD_RATE:-<script default 100>}"
    echo "  Genesis file:             ${GENESIS_FILE:-<fetch block 0 from RPC>}"
    echo "  Temp env file:            $ENV_FILE"
    echo
    log_warn "This env file contains only public values and account names, not private keys."
}

run_ceremony() {
    local ceremony_bin="$SCRIPT_DIR/ceremony.sh"
    log_ok "Launching ceremony runner..."
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    "$ceremony_bin"
}

main() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --prepare-only)
                AUTO_RUN="0"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_err "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    require_cmd cast
    require_cmd forge
    require_cmd jq

    echo -e "${BOLD}=================================================${NC}"
    echo -e "${BOLD}      Citrate Guided Ceremony Wrapper${NC}"
    echo -e "${BOLD}=================================================${NC}"
    echo "This helper collects the public ceremony inputs, sets up the deployer"
    echo "keystore path locally, writes a temp env file, and can launch ceremony.sh."
    echo

    choose_mode
    choose_deployer_account

    echo
    log_ok "Derived deployer address: $DEPLOYER_ADDRESS"
    if ! prompt_yes_no "Continue with this deployer address?" "y"; then
        log_err "Aborted by operator."
        exit 1
    fi

    collect_public_inputs
    write_env_file
    print_summary

    echo
    echo "If you want to run later instead of now, use:"
    echo "  source '$ENV_FILE' && '$SCRIPT_DIR/ceremony.sh'"

    if [ "$AUTO_RUN" = "0" ]; then
        log_ok "Prepared only. Nothing has been deployed."
        exit 0
    fi

    if prompt_yes_no "Run ceremony.sh now with the values above?" "y"; then
        run_ceremony
    else
        log_ok "Nothing deployed. Re-run later with:"
        echo "  source '$ENV_FILE' && '$SCRIPT_DIR/ceremony.sh'"
    fi
}

main "$@"
