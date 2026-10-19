#!/usr/bin/env bash
# keep_check.sh: the address-book freeze gate. Read-only.
#
# Proves that a set of contracts sits on a chain exactly as pinned: same address, same
# runtime code (keccak256(eth_getCode)), and, for an ERC-1967 proxy, the same implementation
# slot. For the genesis it runs twice:
#   * at rehearsal 1 (address book freeze), `pin` records the frozen set from the rehearsal
#     chain into a KEEP list that is reviewed and committed with the release;
#   * at the genesis cut, `verify` checks the same list against the new chain. The book is
#     CREATE2-deterministic, so the addresses and code must match exactly.
#
# Ported from the R2 redeploy's keep_check.sh (2026-09-25), with the hard-coded row set
# replaced by a keys file, and a --dry-run mode that needs no RPC.
#
# The gate FAILS (exit 1) if, for any KEEP row:
#   * the address has no code, or keccak256(code) differs from the pinned hash;
#   * the row is a proxy and its implementation slot differs from the pin;
#   * ADDRESS_BOOK is given and maps the key to a different address (or drops it), in its
#     section or in a root-level entry of the same name;
#   * BROADCAST_DIR is given and a broadcast there CREATE/CREATE2-deploys the row's contract
#     at an address that is NOT pinned for that contract name (the contract was redeployed
#     somewhere else). A deployment AT the pinned address is the expected deterministic genesis
#     deployment and passes. Only broadcasts for this chain are read (contracts/broadcast/
#     <script>/<chain id>/run-latest.json, chain id from the RPC), and with BROADCAST_SINCE
#     (unix seconds; the ceremony passes the block-0 timestamp) runs recorded before it are
#     ignored, so an earlier chain's runs on the same chain id are not evidence. A broadcast
#     that cannot be read or has an unexpected shape, or an in-scope deployment with no
#     address, fails the gate; a malformed file never stops the later files being examined;
#   * any helper fails: the broadcast scanner exits non-zero or its output is incomplete, a
#     book read crashes, or an RPC read fails. The script runs under `set -euo pipefail`, and
#     every subprocess whose status bash would otherwise drop (command substitutions, the
#     scanner) is checked explicitly.
#
# Usage
#   RPC=<url> keep_check.sh verify KEEP_LIST.tsv
#       optional env: ADDRESS_BOOK=<book.json>  BROADCAST_DIR=<contracts/broadcast>
#                     BROADCAST_SINCE=<unix seconds>
#   keep_check.sh verify --dry-run KEEP_LIST.tsv
#       checks the list's format (and the book, if ADDRESS_BOOK is set) and prints the reads
#       it would make. No RPC.
#   ADDRESS_BOOK=<book.json> keep_check.sh keys SECTION[,SECTION...] > KEEP_KEYS.tsv
#       one row per address in those book sections (proxy=no; mark proxies by hand).
#   RPC=<url> ADDRESS_BOOK=<book.json> keep_check.sh pin KEEP_KEYS.tsv > KEEP_LIST.tsv
#       records the hashes from the chain. Only for a deliberate, reviewed freeze.
#
# File formats (tab-separated, '#' comments):
#   KEEP_KEYS.tsv: key  section  contract_name(- = skip redeploy detection)  proxy(yes|no)
#   KEEP_LIST.tsv: key  section  address  contract_name  code_hash  expected_impl(- = not a proxy)
#
# Exit: 0 pass · 1 gate failed · 2 usage or input error
# Needs: cast (Foundry; override with CAST=...), python3.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/genesis/lib.sh
. "$HERE/lib.sh"
GENESIS_LOG_TAG=keep_check
# A command that fails outside an explicit check stops the script non-zero (set -e); say where.
trap 'err "unexpected failure (exit $?) at line $LINENO; the gate did not pass"' ERR

CAST="${CAST:-${FOUNDRY_BIN:+$FOUNDRY_BIN/}cast}"
PY="${PYTHON:-python3}"
# keccak256("eip1967.proxy.implementation") - 1, the public ERC-1967 slot constant.
EIP1967_IMPL=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 2
}

MODE="${1:-}"
[[ -n "$MODE" ]] || usage
shift
DRY=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h | --help) usage ;;
    *) ARGS+=("$a") ;;
  esac
done

codehash() { # addr -> keccak256(code), EMPTY or RPC-ERROR
  local code
  code=$("$CAST" code "$1" --rpc-url "$RPC" 2>/dev/null) || {
    echo "RPC-ERROR"
    return
  }
  if [[ -z "$code" || "$code" == "0x" ]]; then
    echo "EMPTY"
    return
  fi
  local h
  h=$("$CAST" keccak "$code" 2>/dev/null) || {
    echo "KECCAK-ERROR"
    return
  }
  lower "$h"
}

impl_of() { # addr -> 0x<40 hex> from the ERC-1967 slot
  local w
  w=$("$CAST" storage "$1" "$EIP1967_IMPL" --rpc-url "$RPC" 2>/dev/null) || {
    echo "RPC-ERROR"
    return
  }
  [[ "$w" =~ ^0x[0-9a-fA-F]{64}$ ]] || {
    echo "RPC-ERROR"
    return
  }
  lower "0x${w: -40}"
}

book_get() { # book section key -> lowercased address, MISSING, - for a non-string, or BOOK-ERROR
  local out
  out=$(book_get_raw "$@") || out="BOOK-ERROR"
  [[ -n "$out" ]] || out="BOOK-ERROR"
  printf '%s\n' "$out"
}
book_get_raw() {
  "$PY" - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sec, key = sys.argv[2], sys.argv[3]
v = d.get(key) if sec == "<root>" else d.get(sec, {}).get(key, "MISSING")
print(v.lower() if isinstance(v, str) else ("MISSING" if v is None and sec != "<root>" else "-"))
PY
}

case "$MODE" in
keys)
  [[ ${#ARGS[@]} -eq 1 ]] || usage
  [[ -n "${ADDRESS_BOOK:-}" ]] || die "keys needs ADDRESS_BOOK" 2
  [[ -f "$ADDRESS_BOOK" ]] || die "address book not found: $ADDRESS_BOOK" 2
  printf '# KEEP keys from %s (sections %s). Mark ERC-1967 proxies yes by hand.\n' "$ADDRESS_BOOK" "${ARGS[0]}"
  printf '# key\tsection\tcontract_name\tproxy\n'
  if "$PY" - "$ADDRESS_BOOK" "${ARGS[0]}" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
for sec in sys.argv[2].split(","):
    entries = d.get(sec)
    if not isinstance(entries, dict):
        sys.exit(f"section {sec!r} is not in the book")
    for k in sorted(entries):
        v = entries[k]
        if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", v) and int(v, 16) != 0:
            print(f"{k}\t{sec}\t{k}\tno")
PY
  then exit 0; else die "cannot read sections ${ARGS[0]} from $ADDRESS_BOOK" 2; fi
  ;;
pin)
  [[ ${#ARGS[@]} -eq 1 ]] || usage
  KEYS="${ARGS[0]}"
  [[ -f "$KEYS" ]] || die "keys file not found: $KEYS" 2
  [[ -n "${ADDRESS_BOOK:-}" ]] || die "pin needs ADDRESS_BOOK" 2
  if [[ $DRY -eq 1 ]]; then
    while IFS=$'\t' read -r key sec cname proxy; do
      [[ -z "$key" || "$key" == \#* ]] && continue
      addr=$(book_get "$ADDRESS_BOOK" "$sec" "$key")
      is_addr "$addr" || die "book has no address for $sec.$key" 2
      describe_cmd "$CAST" code "$addr" --rpc-url '$RPC'
      if [[ "$proxy" == yes ]]; then describe_cmd "$CAST" storage "$addr" "$EIP1967_IMPL" --rpc-url '$RPC'; fi
    done <"$KEYS"
    exit 0
  fi
  [[ -n "${RPC:-}" ]] || die "pin needs RPC" 2
  blk=$("$CAST" block-number --rpc-url "$RPC") || die "RPC unreachable: $RPC" 2
  cid=$("$CAST" chain-id --rpc-url "$RPC") || die "RPC unreachable: $RPC" 2
  printf '# KEEP list pinned from chain %s at block %s (keccak256(eth_getCode)). Do not edit by hand.\n' "$cid" "$blk"
  printf '# key\tsection\taddress\tcontract_name\tcode_hash\texpected_impl\n'
  while IFS=$'\t' read -r key sec cname proxy; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    addr=$(book_get "$ADDRESS_BOOK" "$sec" "$key")
    is_addr "$addr" || die "book has no address for $sec.$key" 2
    h=$(codehash "$addr")
    [[ "$h" =~ ^0x[0-9a-f]{64}$ ]] || die "cannot pin $key at $addr: $h" 2
    impl="-"
    if [[ "$proxy" == yes ]]; then
      impl=$(impl_of "$addr")
      is_addr "$impl" || die "cannot pin the implementation of $key at $addr: $impl" 2
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$sec" "$addr" "${cname:--}" "$h" "$impl"
  done <"$KEYS"
  exit 0
  ;;
verify) ;;
*) usage ;;
esac

# ---- verify ----
[[ ${#ARGS[@]} -eq 1 ]] || usage
LIST="${ARGS[0]}"
[[ -f "$LIST" ]] || die "KEEP list not found: $LIST" 2
[[ $DRY -eq 1 || -n "${RPC:-}" ]] || die "verify needs RPC (or pass --dry-run)" 2

fail=0
n=0
say() { printf '%s\n' "$*"; }
row_ok() { # addr code_hash impl extra
  [[ -z "$4" && -n "$3" ]] || return 1
  is_addr "$1" || return 1
  [[ "$2" =~ ^0x[0-9a-f]{64}$ ]] || return 1
  [[ "$3" == "-" ]] || is_addr "$3"
}
lineno=0
while IFS=$'\t' read -r key sec addr cname want impl extra; do
  lineno=$((lineno + 1))
  [[ -z "$key" || "$key" == \#* ]] && continue
  if ! row_ok "$addr" "$want" "${impl:-}" "${extra:-}"; then
    say "KEEP-FAIL    line $lineno is malformed (want 6 tab-separated fields)"
    fail=1
    continue
  fi
  n=$((n + 1))
  addr=$(lower "$addr")
  if [[ $DRY -eq 1 ]]; then
    describe_cmd "$CAST" code "$addr" --rpc-url '$RPC'
    if [[ "$impl" != "-" ]]; then describe_cmd "$CAST" storage "$addr" "$EIP1967_IMPL" --rpc-url '$RPC'; fi
  else
    got=$(codehash "$addr")
    if [[ "$got" == "$want" ]]; then
      say "KEEP-OK      $key $addr code=$got"
    else
      say "KEEP-FAIL    $key $addr code changed: want $want got $got"
      fail=1
    fi
    if [[ "$impl" != "-" ]]; then
      gi=$(impl_of "$addr")
      if [[ "$gi" == "$(lower "$impl")" ]]; then
        say "KEEP-OK      $key impl=$gi"
      else
        say "KEEP-FAIL    $key implementation slot changed: want $impl got $gi"
        fail=1
      fi
    fi
  fi
  if [[ -n "${ADDRESS_BOOK:-}" ]]; then
    b=$(book_get "$ADDRESS_BOOK" "$sec" "$key")
    if [[ "$b" == "$addr" ]]; then
      say "KEEP-OK      $key book.$sec=$b"
    else
      say "KEEP-FAIL    $key book.$sec moved: want $addr got $b"
      fail=1
    fi
    r=$(book_get "$ADDRESS_BOOK" "<root>" "$key")
    if [[ "$r" != "-" ]]; then
      if [[ "$r" == "$addr" ]]; then
        say "KEEP-OK      $key book.<root>=$r"
      else
        say "KEEP-FAIL    $key book.<root> moved: want $addr got $r"
        fail=1
      fi
    fi
  fi
done <"$LIST"

if [[ -n "${BROADCAST_DIR:-}" && -d "$BROADCAST_DIR" && $DRY -eq 0 ]]; then
  bcid=$("$CAST" chain-id --rpc-url "$RPC" 2>/dev/null) || bcid=""
  if [[ ! "$bcid" =~ ^[0-9]+$ ]]; then
    say "KEEP-FAIL    cannot read the chain id to select broadcasts under $BROADCAST_DIR"
    fail=1
  elif [[ -n "${BROADCAST_SINCE:-}" && ! "${BROADCAST_SINCE}" =~ ^[0-9]+$ ]]; then
    say "KEEP-FAIL    BROADCAST_SINCE must be unix seconds"
    fail=1
  else
    # name<TAB>address for every KEEP row with a contract name: the pinned deployments.
    pins=$(awk -F'\t' '!/^#/ && NF>=4 && $4!="-"{print $4 "\t" tolower($3)}' "$LIST")
    # The scanner validates every run and transaction it reads; a malformed one is reported
    # as BAD and the scan goes on to the rest. It ends with a DONE line. A non-zero exit, a
    # missing DONE, or a line of an unknown kind fails the gate: a crash part-way through
    # must never read as "nothing moved".
    scan_rc=0
    bc=$("$PY" - "$BROADCAST_DIR" "$bcid" "${BROADCAST_SINCE:-0}" "$pins" <<'PY'
import json, sys, pathlib
root, cid, since, pins_raw = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
pinned = {}
for line in pins_raw.splitlines():
    if "\t" in line:
        n, a = line.split("\t", 1)
        pinned.setdefault(n, set()).add(a.strip().lower())


def scan(f, script):
    try:
        with open(f) as fh:
            run = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"BAD\t{script}\tunreadable broadcast {f}: {e}")
        return
    if not isinstance(run, dict):
        print(f"BAD\t{script}\tbroadcast {f} is not a JSON object")
        return
    ts = run.get("timestamp")
    if ts is not None and (isinstance(ts, bool) or not isinstance(ts, (int, float))):
        print(f"BAD\t{script}\tbroadcast {f} has a non-numeric timestamp")
        return
    if since:
        if ts is None:
            print(f"BAD\t{script}\tbroadcast {f} has no timestamp to compare with BROADCAST_SINCE")
            return
        ts = ts / 1000 if ts > 10**12 else ts  # older Foundry wrote milliseconds
        if ts < since:
            print(f"SKIP\t{script}\trun recorded before BROADCAST_SINCE")
            return
    txs = run.get("transactions")
    if txs is None:
        txs = []
    if not isinstance(txs, list):
        print(f"BAD\t{script}\tbroadcast {f}: transactions is not a list")
        return
    for i, t in enumerate(txs):
        if not isinstance(t, dict):
            print(f"BAD\t{script}\tbroadcast {f}: transaction {i} is not an object")
            continue
        kind, name, a = t.get("transactionType"), t.get("contractName"), t.get("contractAddress")
        if not isinstance(kind, (str, type(None))) or not isinstance(name, (str, type(None))):
            print(f"BAD\t{script}\tbroadcast {f}: transaction {i} has a malformed type or contract name")
            continue
        if kind not in ("CREATE", "CREATE2") or name not in pinned:
            continue
        if not isinstance(a, str) or not a:
            print(f"BAD\t{script}\t{name} deployment has no contractAddress")
            continue
        a = a.lower()
        if a in pinned[name]:
            print(f"PIN\t{script}\t{name} at {a}")
        else:
            print(f"MOVE\t{script}\t{name} at {a}")


for f in sorted(root.glob(f"*/{cid}/run-latest.json")):
    script = f.parent.parent.name
    try:
        scan(f, script)
    except Exception as e:  # any shape the checks above missed: report it, keep scanning
        print(f"BAD\t{script}\tbroadcast {f} could not be scanned: {type(e).__name__}: {e}")
print("DONE\t-\tscan complete")
PY
    ) || scan_rc=$?
    nbad=0
    done_seen=0
    if [[ $scan_rc -ne 0 ]]; then
      say "KEEP-FAIL    the broadcast scanner exited $scan_rc; its output is not evidence"
      nbad=1
    fi
    while IFS=$'\t' read -r kind s detail; do
      case "$kind" in
        PIN) say "KEEP-OK      $s deploys $detail (the pinned address)" ;;
        SKIP) say "KEEP-SKIP    $s: $detail" ;;
        MOVE)
          say "KEEP-FAIL    $s redeploys $detail (not the pinned address)"
          nbad=1
          ;;
        BAD)
          say "KEEP-FAIL    $s: $detail"
          nbad=1
          ;;
        DONE) done_seen=1 ;;
        "") ;;
        *)
          say "KEEP-FAIL    unexpected broadcast scanner output: $kind"
          nbad=1
          ;;
      esac
    done <<<"$bc"
    if [[ $done_seen -ne 1 ]]; then
      say "KEEP-FAIL    the broadcast scan did not complete"
      nbad=1
    fi
    if [[ $nbad -ne 0 ]]; then
      fail=1
    else
      say "KEEP-OK      no chain-$bcid broadcast under $BROADCAST_DIR deploys a KEEP contract away from its pin"
    fi
  fi
fi

if [[ $n -eq 0 ]]; then
  say "KEEP-FAIL    empty KEEP list"
  fail=1
fi
if [[ $DRY -eq 1 ]]; then
  if [[ $fail -eq 0 ]]; then say "=> KEEP dry run OK ($n entries; no RPC read)"; else say "=> KEEP dry run FAIL"; fi
elif [[ $fail -eq 0 ]]; then
  say "=> KEEP gate PASS ($n entries)"
else
  say "=> KEEP gate FAIL"
fi
exit $fail
