#!/usr/bin/env python3
"""alloc_keys_check.py: GO-K step 3 for the 0.6.0 ceremony-genesis allocation.

Runbook (federation ops/r1007-ceremony/RUNBOOK.md section 0.6 step 3): block 0 funds and
references only known keys (an allowlist). Every EOA the allocation funds or references must be
  - an address in the r1007 key inventory (GENESIS_KEY_INVENTORY, role-tagged JSON
    {address: [roles]}; any role counts here, since this is about being known, not a seat);
  - a producer staker, read from the --stakers file (a validators.json; a parameter, with no
    built-in path, so the 0.6.0 producer set is named explicitly); or
  - the ceremony deployer, with balance 0.
Anything else fails, whether or not it is on an r1006 list. --retired-keys adds the extra
denylist: none of those addresses may be funded or referenced at all.

  funded      an account with a nonzero balance and no code, and every baseAllocations entry
  referenced  a 32-byte storage word whose top 12 bytes are zero and whose low 20 bytes are an
              address at or above 2**104, or the same 32-byte pattern pushed by PUSH32 in an
              account's code (an address immutable), when that address has no code in the
              allocation. Smaller nonzero words cannot be told from counters, timestamps or
              amounts; each one is listed as GOK3-UNCHECKED with its account and slot.

Limits (it is an extra check; GO-K step 4, reading every role member on chain, stays the
hard gate):
  - an address packed into a slot beside other fields is not found (only whole words whose top
    12 bytes are zero are read);
  - an address that appears only as a mapping key (hashed into the slot) is not found;
  - an address below 2**104 (7 or more leading zero bytes) is listed as GOK3-UNCHECKED, not
    judged;
  - the code scan is not aligned to instructions: it matches PUSH32 bytes anywhere, including
    inside data or other push arguments. So it can only refuse wrongly (a false match on an
    unknown address), never let an address through that a true PUSH32 holds.

Usage: alloc_keys_check.py --alloc FILE --key-inventory JSON --stakers FILE --deployer ADDR
                           [--retired-keys ADDR,ADDR,...]
Exit: 0 ok, 1 a check failed, 2 usage or unreadable input.
"""
import argparse
import json
import re
import sys

ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
WORD = re.compile(r"^(?:0x)?([0-9a-fA-F]{64})$")
PUSH32_ADDR = re.compile(r"7f000000000000000000000000([0-9a-f]{40})")
# Words at or above 2**104 (an address with at most 6 leading zero bytes) are checked as
# addresses. Measured on the r1006 alloc: no counter, timestamp or amount lies between 2**104
# and 2**152, and the largest non-address word is ~2**102 (an amount). Every nonzero word below
# the floor is listed (GOK3-UNCHECKED) with its account and slot, never silently skipped.
FLOOR = 2**104


def die(msg, code=2):
    print(f"alloc_keys_check: {msg}", file=sys.stderr)
    sys.exit(code)


def load_json(path, what):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        die(f"cannot read {what} {path}: {e}")


def inventory(raw):
    def once(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                die(f"the key inventory names {k} more than once")
            out[k] = v
        return out

    try:
        d = json.loads(raw, object_pairs_hook=once)
    except ValueError as e:
        die(f"the key inventory is not JSON: {e}")
    if not isinstance(d, dict) or not d:
        die("the key inventory is not a JSON object {address: [roles]}")
    out = set()
    for a in d:
        if not ADDR.match(a):
            die(f"the key inventory has a malformed address {a!r}")
        if a.lower() in out:
            die(f"the key inventory names {a.lower()} more than once")
        out.add(a.lower())
    return out


def stakers(path):
    d = load_json(path, "the producer stakers")
    try:
        return {v["staker"].lower() for v in d["validators"]}
    except (KeyError, TypeError, AttributeError) as e:
        die(f"cannot read the producer stakers from {path}: {e}")


def address_of(word_hex):
    """The address in a 32-byte word, or None when it is not one this check can identify."""
    if not word_hex.startswith("0" * 24):
        return None
    v = int(word_hex[24:], 16)
    return "0x" + word_hex[24:] if v >= FLOOR else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--alloc", required=True)
    ap.add_argument("--key-inventory", required=True, help="role-tagged JSON {address: [roles]}")
    ap.add_argument("--stakers", required=True, help="the producer set's validators.json")
    ap.add_argument("--deployer", required=True)
    ap.add_argument("--retired-keys", default="")
    a = ap.parse_args()
    if not ADDR.match(a.deployer):
        die("--deployer is not an address")
    known = inventory(a.key_inventory)
    staker_set = stakers(a.stakers)
    deployer = a.deployer.lower()
    retired = set()
    for x in filter(None, (y.strip() for y in a.retired_keys.split(","))):
        if not ADDR.match(x):
            die(f"--retired-keys has a malformed address {x!r}")
        retired.add(x.lower())
    alloc = load_json(a.alloc, "the allocation")
    accounts = alloc.get("accounts") if isinstance(alloc, dict) else None
    if not isinstance(accounts, list):
        die(f"{a.alloc} has no accounts list")

    has_code = {acc["address"].lower() for acc in accounts if (acc.get("code") or "0x") not in ("0x", "")}
    problems, unchecked = [], []

    def judge(who, how, where):
        if who in retired:
            problems.append(f"{where} {how} {who}, a key retired at the r1007 ceremony (D-K3)")
        elif who in known or who in staker_set:
            return
        elif who == deployer:
            return  # its balance is checked below; a reference is emit_alloc's scan_privileged
        else:
            problems.append(f"{where} {how} {who}, which is not in the key inventory, not a producer staker and not the deployer")

    for acc in accounts:
        addr = acc["address"].lower()
        code = (acc.get("code") or "0x").lower()
        try:
            bal = int(acc.get("balance") or "0x0", 16)
        except ValueError:
            die(f"{addr}: unreadable balance {acc.get('balance')!r}")
        if addr == deployer and bal != 0:
            problems.append(f"block 0: the ceremony deployer {addr} has balance {bal}; it must have none")
        elif bal != 0 and addr not in has_code:
            judge(addr, "funds", "block 0")
        for slot, v in (acc.get("storage") or {}).items():
            m = WORD.match(v if isinstance(v, str) else "")
            if not m:
                continue
            w = m.group(1).lower().rjust(64, "0")
            who = address_of(w)
            if who is None:
                if w[:24] == "0" * 24 and int(w, 16) != 0:
                    unchecked.append(f"{addr} storage {slot} {hex(int(w, 16))}")
                continue
            if who not in has_code:
                judge(who, "references", f"{addr} storage {slot}")
        for m in PUSH32_ADDR.finditer(code):
            who = address_of("0" * 24 + m.group(1))
            if who is not None and who not in has_code:
                judge(who, "references", f"{addr} code (immutable)")

    # The base allocations (treasury, faucet, team) are funded at block 0 from the alloc's own
    # list, beside the ceremony state's accounts.
    for b in alloc.get("baseAllocations") or []:
        who = (b.get("address") or "").lower()
        if not ADDR.match(who):
            die(f"a base allocation has no address: {b!r}")
        if who == deployer:
            problems.append(f"baseAllocations: the ceremony deployer {who} has balance; it must have none")
        elif who not in has_code:
            judge(who, "funds", f"baseAllocations ({b.get('role', '?')})")

    for u in unchecked:
        print(f"GOK3-UNCHECKED {u}")
    for p in problems:
        print(f"GOK3-FAIL {p}")
    if problems:
        print(f"alloc_keys_check: {len(problems)} problem(s)")
        return 1
    print(f"alloc_keys_check: OK ({len(accounts)} accounts; {len(unchecked)} storage words below the address floor listed as GOK3-UNCHECKED)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
