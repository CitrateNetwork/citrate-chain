#!/usr/bin/env python3
"""emit_book.py: the r1006 address book, from the ceremony's books and the genesis alloc.

r1006's contracts are in block 0, so no deployer transaction on the live chain names them
and the usual export (emit-address-table.sh over broadcasts) has nothing to read. This
writes the book in the same schema as contracts/addresses/40204.json directly from:
  * the ceremony's recorded stack book (P2, the generator's output; C8),
  * the P1/P3/P4 books (governance, team vesting, dormant ledgers) and the P4 stand-ins,
  * the genesis alloc, which must hold CODE at every contract address the book names
    (checked; any address without code fails, exit 1).
Not checked for code: `deployer` (an EOA) and `precompiles` (native, no EVM code).

  emit_book.py --work DIR --alloc ALLOC --out contracts/addresses/r1006/40204.json
  emit_book.py --check BOOK --alloc ALLOC        (re-check a written book)

Deterministic: fixed key order, `deployedAt` is the genesis timestamp, LF.
"""
import argparse
import json
import re
import sys

ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
GENESIS_ISO = "2026-01-01T00:00:00Z"  # CANONICAL_GENESIS_TIMESTAMP, r1006's block 0
SKIP_KEYS = {"deployer", "precompiles", "$schema"}


def fail(msg):
    print(f"emit_book: {msg}", file=sys.stderr)
    sys.exit(1)


def addresses(node, path=""):
    """Every (path, address) in a JSON tree, skipping SKIP_KEYS subtrees."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in SKIP_KEYS:
                continue
            yield from addresses(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from addresses(v, f"{path}[{i}]")
    elif isinstance(node, str) and ADDR.match(node):
        yield path, node.lower()


def code_set(alloc_path):
    alloc = json.load(open(alloc_path))
    if alloc.get("format") != "citrate-genesis-alloc-v1":
        fail(f"{alloc_path} is not a citrate-genesis-alloc-v1 file")
    return {a["address"] for a in alloc["accounts"] if a.get("code") and a["code"] != "0x"}


def check(book, codes):
    missing = [(p, a) for p, a in addresses(book) if a not in codes]
    if missing:
        for p, a in missing:
            print(f"emit_book: {p} = {a} has no code in the genesis alloc", file=sys.stderr)
        fail(f"{len(missing)} book address(es) without code in block 0")
    return sum(1 for _ in addresses(book))


def contracts_of(path):
    try:
        return json.load(open(path)).get("contracts", {})
    except FileNotFoundError:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work")
    ap.add_argument("--alloc", required=True)
    ap.add_argument("--out")
    ap.add_argument("--check")
    a = ap.parse_args()
    codes = code_set(a.alloc)
    if a.check:
        n = check(json.load(open(a.check)), codes)
        print(f"emit_book: {a.check}: {n} addresses, every one has code in the genesis alloc")
        return
    if not (a.work and a.out):
        fail("--work and --out are required (or --check)")
    book = json.load(open(f"{a.work}/book/40204.json"))
    extra = {}
    for name in ("team-vesting.json", "dormant-ledgers.json", "library.json"):
        extra.update(contracts_of(f"{a.work}/book/{name}"))
    contracts = dict(book.get("contracts", {}))
    for k, v in extra.items():
        if k in contracts and contracts[k].lower() != v.lower():
            fail(f"{k}: the stack book says {contracts[k]}, a phase book says {v}")
        contracts[k] = v.lower()
    book["contracts"] = contracts
    # The OrangeSeed predeploy is in block 0 from the alloc, not from a deploy transaction.
    os_rec = json.load(open(a.alloc)).get("orangeseed")
    if os_rec:
        g = book.setdefault("genesis", {})
        g["OrangeSeed"] = os_rec["proxy"]
        g["OrangeSeedV0"] = os_rec["implementation"]
    book["$schema"] = "../schema.json"
    book["deployedAt"] = GENESIS_ISO
    book["regenerator"] = "scripts/genesis/r1006/emit_book.py"
    book["comment"] = ("r1006 contract-address table for chain 40204. Every contract here is in "
                       "block 0 (genesis from ceremony state); written from the ceremony's books "
                       "and checked against the genesis alloc by scripts/genesis/r1006/emit_book.py.")
    n = check(book, codes)
    with open(a.out, "w", newline="\n") as f:
        f.write(json.dumps(book, indent=2) + "\n")
    print(f"emit_book: wrote {a.out}: {n} addresses, every one has code in the genesis alloc", file=sys.stderr)


if __name__ == "__main__":
    main()
