#!/usr/bin/env python3
"""Address-book getCode check / tripwire).

Reads contracts/addresses/40204.json, calls eth_getCode (READ-ONLY) for every
entry against the chain RPC, and reports which entries have no code.

Modes:
  --probe   write verification/address-code.snapshot.json from the live chain.
  --check   (default) probe live and FAIL (exit 1) when
              * the live set of codeless entries differs from the committed
                snapshot, or
              * claims.json deployed_contracts.with_code_on_chain disagrees
                with the live count.
  --offline validate the snapshot against claims.json and the book without
            any network call (what CI runs on every PR).

Precompile entries are codeless by design and are reported separately.
Only JSON-RPC reads are made (eth_chainId, eth_blockNumber, eth_getCode).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOK = ROOT / "contracts" / "addresses" / "40204.json"
CLAIMS = ROOT / "verification" / "claims.json"
SNAPSHOT = ROOT / "verification" / "address-code.snapshot.json"


def book_entries(book: dict) -> list[tuple[str, str]]:
    """Every (section.name, address) the book publishes, precompiles included."""
    out: list[tuple[str, str]] = []
    for section in ("contracts", "aaStack", "genesis", "precompiles"):
        for name, addr in (book.get(section) or {}).items():
            if isinstance(addr, str) and addr.startswith("0x"):
                out.append((f"{section}.{name}", addr))
    for key, val in book.items():
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42 and key not in ("deployer",):
            out.append((key, val))
    return out


def rpc(url: str, method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (fixed https RPC URL)
        data = json.loads(resp.read())
    if "error" in data:
        raise RuntimeError(f"{method}: {data['error']}")
    return data["result"]


def probe(url: str, book: dict) -> dict:
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    if chain_id != book["chainId"]:
        raise SystemExit(f"RPC chainId {chain_id} != book chainId {book['chainId']}")
    block = int(rpc(url, "eth_blockNumber", []), 16)
    codeless, with_code, precompile = [], [], []
    for name, addr in book_entries(book):
        code = rpc(url, "eth_getCode", [addr, hex(block)])
        has = isinstance(code, str) and code not in ("0x", "0x0", "")
        if name.startswith("precompiles."):
            precompile.append(name)
        elif has:
            with_code.append(name)
        else:
            codeless.append(name)
        time.sleep(0.05)  # stay polite to the public RPC
    return {
        "chainId": chain_id,
        "block": block,
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "book_deployedAt": book.get("deployedAt"),
        "with_code_count": len(with_code),
        "codeless": sorted(codeless),
        "precompiles_codeless_by_design": len(precompile),
    }


def app_counts(book: dict, codeless: list[str]) -> dict:
    """The claims.json counting rule: contracts + aaStack entries that have code."""
    app = [f"contracts.{n}" for n in book.get("contracts", {})] + [f"aaStack.{n}" for n in book.get("aaStack", {})]
    live = [n for n in app if n not in set(codeless)]
    return {"book_entries": len(app), "with_code": len(live), "codeless": len(app) - len(live)}


def check_claims(book: dict, snap: dict) -> list[str]:
    errs: list[str] = []
    claims = json.loads(CLAIMS.read_text())["claims"]
    dc = claims.get("deployed_contracts", {}).get("value", {})
    counts = app_counts(book, snap["codeless"])
    if dc.get("with_code_on_chain") != counts["with_code"]:
        errs.append(
            f"claims.json deployed_contracts.with_code_on_chain={dc.get('with_code_on_chain')} "
            f"but the snapshot says {counts['with_code']} of {counts['book_entries']} have code"
        )
    if dc.get("codeless_in_book") != counts["codeless"]:
        errs.append(
            f"claims.json deployed_contracts.codeless_in_book={dc.get('codeless_in_book')} "
            f"but the snapshot says {counts['codeless']}"
        )
    known = {n for n, _ in book_entries(book)}
    stale = [n for n in snap["codeless"] if n not in known]
    if stale:
        errs.append(f"snapshot lists entries that are not in the book (regenerate with --probe): {stale}")
    if snap.get("book_deployedAt") != book.get("deployedAt"):
        errs.append(
            f"snapshot was probed for book deployedAt={snap.get('book_deployedAt')} but the book is "
            f"deployedAt={book.get('deployedAt')}; re-run with --probe after a re-roll"
        )
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--offline", action="store_true")
    ap.add_argument("--rpc", default=None, help="JSON-RPC URL (default: book rpcUrl)")
    ap.add_argument("--book", default=str(BOOK))
    ap.add_argument("--snapshot", default=str(SNAPSHOT))
    args = ap.parse_args()

    book = json.loads(Path(args.book).read_text())
    url = args.rpc or book["rpcUrl"]

    if args.probe:
        snap = probe(url, book)
        Path(args.snapshot).write_text(json.dumps(snap, indent=2) + "\n")
        c = app_counts(book, snap["codeless"])
        print(f"[address-code] block {snap['block']}: {c['with_code']}/{c['book_entries']} app+AA entries have code; "
              f"{len(snap['codeless'])} codeless: {', '.join(snap['codeless'])}")
        return 0

    snap = json.loads(Path(args.snapshot).read_text())
    errs = check_claims(book, snap)

    if not args.offline:
        live = probe(url, book)
        if sorted(live["codeless"]) != sorted(snap["codeless"]):
            gained = sorted(set(snap["codeless"]) - set(live["codeless"]))
            lost = sorted(set(live["codeless"]) - set(snap["codeless"]))
            errs.append(f"live chain differs from snapshot: now have code {gained}; now codeless {lost}")

    if errs:
        for e in errs:
            print(f"[address-code] FAIL: {e}", file=sys.stderr)
        return 1
    c = app_counts(book, snap["codeless"])
    print(f"[address-code] OK: {c['with_code']}/{c['book_entries']} app+AA entries have code "
          f"({'offline' if args.offline else 'live'} check)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
