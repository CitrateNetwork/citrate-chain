#!/usr/bin/env python3
"""Append the HUP registry redeploy to contracts/addresses/40204.provenance.json.

Runbook step 4 (HUP-S7.1, federation F-4). Run by the chain operator AFTER
scripts/ops/hup-book-update.py has written the book from the same broadcast. It
never signs, sends or deploys anything.

The provenance ledger records every transaction that deployed something on 40204:
nonce, block, transaction hash, kind, forge artifact, address, and whether the
entry is what the book pins (`canonical`). This tool adds one row per transaction
of the DeployHupRegistries broadcast and marks the rows the redeploy replaced in the
book as `superseded`, so the ledger and the book agree again.

What it checks, all before anything is written (fail closed):
  * every transaction in the broadcast is a HUP CREATE2 deploy whose address
    re-derives from the init code it sent (hup-book-update.parse_broadcast), and
    there is no other transaction (the ledger must hold every one);
  * the book already pins each deployed name at that address (run the book tool
    first: the ledger follows the book, never the other way round);
  * the ledger is for chain 40204; a deployer transaction continues the ledger's
    nonce sequence with no gap; a transaction already in the ledger is identical
    (a rerun is a no-op) and no (sender, nonce) is recorded twice;
  * with --rpc: chain id 40204, block-0 hash == --genesis == the ledger's recorded
    block-0 hash, and for every row the chain's transaction
    (sender, nonce, block), a successful receipt, and code at the address.
  * with --backfill (and --rpc): deployer transactions the ledger is missing before
    the redeploy are read from the chain and recorded first, but only plain value
    transfers and calls with a successful receipt; anything that created a contract
    refuses, because it needs a person to classify it.
Writing needs --rpc and --genesis; offline, only --check runs.

Usage:
  scripts/ops/hup-provenance-update.py \\
      --broadcast contracts/broadcast/DeployHupRegistries.s.sol/40204/run-latest.json \\
      --book contracts/addresses/40204.json \\
      --provenance contracts/addresses/40204.provenance.json \\
      --genesis 0x<block-0 hash> --rpc https://rpc.citrate.ai
  add --check to verify only (no write).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("hup_book_update", _HERE / "hup-book-update.py")
if _spec is None or _spec.loader is None:  # pragma: no cover - the file ships beside this one
    raise SystemExit("hup-provenance-update: hup-book-update.py not found beside this script")
hbu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hbu)

BookError = hbu.BookError
CHAIN_ID = hbu.CHAIN_ID
SCRIPT = "DeployHupRegistries.s.sol"


def _int(v, what: str) -> int:
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str):
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            pass
    raise BookError(f"{what} is not a number: {v!r}")


def _addr(v, what: str) -> str:
    if not isinstance(v, str) or not hbu.ADDR.match(v):
        raise BookError(f"{what} is not an address: {v!r}")
    return v.lower()


def broadcast_rows(run: dict, ledger_deployer: str) -> list:
    """One ledger row per transaction of the broadcast, in broadcast order."""
    found = hbu.parse_broadcast(run)
    by_tx = {f["tx"]: name for name, f in found.items()}
    receipts = {(r.get("transactionHash") or "").lower(): r for r in run.get("receipts") or []}
    rows = []
    for t in run.get("transactions") or []:
        th = (t.get("hash") or "").lower()
        name = by_tx.get(th)
        if name is None:
            raise BookError(
                f"broadcast transaction {th or '(no hash)'} ({t.get('transactionType')} "
                f"{t.get('contractName')}) is not a HUP registry deploy; the ledger must record "
                "every deployer transaction, so record it by hand first"
            )
        tx = t.get("transaction") or {}
        sender = _addr(tx.get("from"), f"{name} transaction sender")
        rc = receipts.get(th)
        if rc is None:
            raise BookError(f"{name}: the broadcast has no receipt for {th}; was it broadcast?")
        contract = found[name]["contract"]
        row = {
            "nonce": _int(tx.get("nonce"), f"{name} nonce"),
            "block": _int(rc.get("blockNumber"), f"{name} block"),
            "tx": th,
            "kind": "CREATE2",
            "artifact": f"{contract}.sol:{contract}",
            "address": hbu.to_checksum(found[name]["address"]),
            "status": "canonical",
            "section": "contracts",
            "name": name,
        }
        if sender != ledger_deployer:
            row["from"] = hbu.to_checksum(sender)
        rows.append(row)
    if not rows:
        raise BookError("the broadcast deployed nothing (a rerun that skipped every registry adds no rows)")
    return rows


def check_book(book: dict, rows: list) -> None:
    contracts = book.get("contracts") or {}
    if int(book.get("chainId", 0)) != CHAIN_ID:
        raise BookError(f"book chainId {book.get('chainId')} != {CHAIN_ID}")
    for r in rows:
        pinned = contracts.get(r["name"])
        if not isinstance(pinned, str) or pinned.lower() != r["address"].lower():
            raise BookError(
                f"the book pins {r['name']} at {pinned or '(absent)'}, not {r['address']}: "
                "run hup-book-update.py with this broadcast first"
            )


def merge(prov: dict, rows: list) -> tuple:
    """Return (new ledger document, rows added, rows superseded)."""
    if int(prov.get("chainId", 0)) != CHAIN_ID:
        raise BookError(f"ledger chainId {prov.get('chainId')} != {CHAIN_ID}")
    deployer = _addr(prov.get("deployer"), "ledger deployer")
    out = json.loads(json.dumps(prov))
    ledger = out.get("ledger")
    if not isinstance(ledger, list):
        raise BookError("the ledger has no `ledger` list")
    by_tx = {(e.get("tx") or "").lower(): e for e in ledger}
    seen_nonce = {((e.get("from") or deployer).lower(), e.get("nonce")) for e in ledger}
    deployer_nonces = [e["nonce"] for e in ledger if not e.get("from") and isinstance(e.get("nonce"), int)]
    next_nonce = max(deployer_nonces) + 1 if deployer_nonces else 0

    added, superseded = [], []
    last_by_sender: dict = {}
    for r in rows:
        prior = by_tx.get(r["tx"])
        if prior is not None:
            same = all(prior.get(k) == r.get(k) for k in ("nonce", "kind", "address", "name", "to"))
            if not same:
                raise BookError(f"tx {r['tx']} is already in the ledger with different fields")
            continue
        sender = (r.get("from") or deployer).lower()
        key = (sender, r["nonce"])
        if key in seen_nonce:
            raise BookError(f"the ledger already records nonce {r['nonce']} of {sender} under another tx")
        label = r.get("name") or f"{r.get('kind')} {r['tx']}"
        if sender == deployer:
            if r["nonce"] != next_nonce:
                raise BookError(
                    f"{label}: deployer nonce {r['nonce']} does not continue the ledger (next is "
                    f"{next_nonce}); record the deployer's transactions in between first "
                    "(--backfill reads plain transfers and calls from the chain)"
                )
            next_nonce += 1
        elif r["nonce"] <= last_by_sender.get(sender, -1):
            raise BookError(f"{label}: nonces of {sender} are out of order in the broadcast")
        last_by_sender[sender] = r["nonce"]
        seen_nonce.add(key)
        for e in ledger:
            if (
                r.get("name")
                and e.get("status") == "canonical"
                and e.get("name") == r["name"]
                and (e.get("address") or "").lower() != r["address"].lower()
            ):
                e["status"] = "superseded"
                e["why"] = (
                    f"replaced in the book by the HUP registry redeploy (HUP-S7.1, {SCRIPT}), "
                    f"tx {r['tx']}"
                )
                superseded.append(e)
        row = dict(r)  # the ledger owns its rows; the caller's list stays untouched
        ledger.append(row)
        added.append(row)

    names = {}
    for e in ledger:
        if e.get("status") == "canonical" and e.get("name"):
            if e["name"] in names:
                raise BookError(f"two canonical ledger rows name {e['name']}")
            names[e["name"]] = e
    if added:
        runs = out.setdefault("appendedRuns", [])
        runs.append(
            {
                "script": SCRIPT,
                "txs": [r["tx"] for r in added],
                "firstBlock": min(r["block"] for r in added),
                "lastBlock": max(r["block"] for r in added),
                "tool": "scripts/ops/hup-provenance-update.py",
            }
        )
    return out, added, superseded


def check_ledger_chain(prov: dict, genesis: str) -> None:
    """The ledger names its chain by the block-0 hash.

    The committed ledger keeps it under `genesisStateRoot` (the value there equals the block-0
    hash of 40204, which is also the core book's `genesisHash`, not the block's state root).
    """
    recorded = (prov.get("genesisHash") or prov.get("genesisStateRoot") or "").lower()
    if recorded and recorded != genesis.lower():
        raise BookError(
            f"the ledger was built for the chain with block-0 hash {recorded}, not --genesis {genesis}: "
            "regenerate the ledger after a reroll instead of appending to it"
        )


def verify_live(url: str, genesis: str, prov: dict, rows: list) -> None:
    rpc = hbu.rpc
    cid = int(rpc(url, "eth_chainId", []), 16)
    if cid != CHAIN_ID:
        raise BookError(f"{url} is chain {cid}, not {CHAIN_ID}")
    b0 = rpc(url, "eth_getBlockByNumber", ["0x0", False]) or {}
    if (b0.get("hash") or "").lower() != genesis.lower():
        raise BookError(f"{url} genesis {b0.get('hash')} != --genesis {genesis}")
    check_ledger_chain(prov, genesis)
    deployer = (prov.get("deployer") or "").lower()
    for r in rows:
        r = {**r, "name": r.get("name") or f"{r.get('kind')} nonce {r['nonce']}"}
        tx = rpc(url, "eth_getTransactionByHash", [r["tx"]])
        if not tx:
            raise BookError(f"{r['name']}: tx {r['tx']} is not on {url}")
        sender = (r.get("from") or deployer).lower()
        if (tx.get("from") or "").lower() != sender:
            raise BookError(f"{r['name']}: tx {r['tx']} was sent by {tx.get('from')}, not {sender}")
        if _int(tx.get("nonce"), "chain nonce") != r["nonce"]:
            raise BookError(f"{r['name']}: tx {r['tx']} has nonce {tx.get('nonce')} on chain, not {r['nonce']}")
        if _int(tx.get("blockNumber"), "chain block") != r["block"]:
            raise BookError(f"{r['name']}: tx {r['tx']} is in block {tx.get('blockNumber')}, not {r['block']}")
        rc = rpc(url, "eth_getTransactionReceipt", [r["tx"]])
        if not rc or str(rc.get("status")) != "0x1":
            raise BookError(f"{r['name']}: tx {r['tx']} has no successful receipt on {url}")
        if not r.get("address"):
            continue  # a backfilled transfer or call created nothing
        if rpc(url, "eth_getCode", [r["address"], "latest"]) in (None, "0x", "0x0"):
            raise BookError(f"no code on chain at {r['name']} {r['address']}")


def _batch_blocks(url: str, numbers: list) -> list:
    body = [
        {"jsonrpc": "2.0", "id": n, "method": "eth_getBlockByNumber", "params": [hex(n), True]} for n in numbers
    ]
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.load(r)
    if not isinstance(out, list):
        raise BookError(f"{url} does not answer batched requests: {str(out)[:200]}")
    blocks = []
    for x in out:
        if "error" in x:
            raise BookError(f"eth_getBlockByNumber failed: {x['error']}")
        if x.get("result"):
            blocks.append(x["result"])
    return blocks


def backfill(url: str, prov: dict, upto_nonce: int, last_block: int, batch: int = 100) -> list:
    """Ledger rows for the deployer's transactions between the ledger's end and `upto_nonce`.

    Reads blocks from the block after the ledger's last row up to `last_block` (the block before
    the redeploy's first transaction) and keeps the deployer's transactions with a nonce the
    ledger has not recorded. Only mechanical rows are written: a plain value transfer
    (`TRANSFER`) or a call to an existing contract (`CALL`, with its selector), each with a
    successful receipt. A contract creation, a call to the CREATE2 factory, a failed receipt or a
    missing nonce refuses: those need a person to classify them (artifact, canonical or orphan).
    """
    deployer = _addr(prov.get("deployer"), "ledger deployer")
    own = [e for e in prov.get("ledger") or [] if not e.get("from")]
    nxt = max((e["nonce"] for e in own if isinstance(e.get("nonce"), int)), default=-1) + 1
    if nxt >= upto_nonce:
        return []
    first_block = max((e["block"] for e in own if isinstance(e.get("block"), int)), default=-1) + 1
    want = set(range(nxt, upto_nonce))
    found: dict = {}
    for start in range(first_block, last_block + 1, batch):
        numbers = list(range(start, min(start + batch, last_block + 1)))
        for blk in _batch_blocks(url, numbers):
            for t in blk.get("transactions") or []:
                if not isinstance(t, dict) or (t.get("from") or "").lower() != deployer:
                    continue
                n = _int(t.get("nonce"), "chain nonce")
                if n in want:
                    found[n] = (t, _int(blk.get("number"), "block number"))
        if len(found) == len(want):
            break
    missing = sorted(want - set(found))
    if missing:
        raise BookError(
            f"deployer nonces {missing} were not found in blocks {first_block}..{last_block}; "
            "record them by hand"
        )
    rows = []
    for n in sorted(found):
        t, block = found[n]
        th = (t.get("hash") or "").lower()
        to = t.get("to")
        data = t.get("input") or t.get("data") or "0x"
        if not to:
            raise BookError(f"deployer nonce {n} (tx {th}) created a contract; classify it by hand")
        if to.lower() == hbu.ARACHNID_FACTORY:
            raise BookError(f"deployer nonce {n} (tx {th}) is a CREATE2 deploy; classify it by hand")
        transfer = data in ("0x", "")
        rc = hbu.rpc(url, "eth_getTransactionReceipt", [th])
        note = None
        if rc is None:
            # The 40204 RPC does not serve receipts by hash for older blocks. A plain transfer with
            # exactly 21000 gas to an account with no code cannot revert once it is in a block (the
            # sender's balance is checked before inclusion), so inclusion is its success. Anything
            # else needs its receipt.
            plain = transfer and _int(t.get("gas"), "gas") == 21000
            if not plain or hbu.rpc(url, "eth_getCode", [to, "latest"]) not in (None, "0x", "0x0"):
                raise BookError(f"deployer nonce {n} (tx {th}): the RPC has no receipt for it; record it by hand")
            note = "receipt not served by the RPC; a 21000-gas transfer to an account without code cannot revert"
        elif str(rc.get("status")) != "0x1":
            raise BookError(f"deployer nonce {n} (tx {th}) did not succeed; record it by hand")
        elif rc.get("contractAddress"):
            raise BookError(f"deployer nonce {n} (tx {th}) created a contract; classify it by hand")
        row = {"nonce": n, "block": block, "tx": th}
        if transfer:
            row.update({"kind": "TRANSFER", "artifact": None, "to": hbu.to_checksum(to),
                        "value": hex(_int(t.get("value") or "0x0", "value")), "status": "call"})
            if note:
                row["why"] = note
        else:
            row.update({"kind": "CALL", "artifact": None, "to": hbu.to_checksum(to),
                        "selector": data[:10].lower(), "status": "call"})
        rows.append(row)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--broadcast", required=True, help="forge broadcast run-latest.json of DeployHupRegistries")
    ap.add_argument("--book", required=True, help="contracts/addresses/40204.json, already updated by hup-book-update.py")
    ap.add_argument("--provenance", required=True, help="contracts/addresses/40204.provenance.json")
    ap.add_argument("--rpc", help="RPC of the chain the broadcast landed on (verifies before writing)")
    ap.add_argument("--genesis", help="block-0 hash of that chain (required with --rpc)")
    ap.add_argument("--check", action="store_true", help="verify only; do not write")
    ap.add_argument("--backfill", action="store_true",
                    help="first record the deployer's plain transfers and calls the ledger is missing (needs --rpc)")
    ap.add_argument("--scan-rpc",
                    help="RPC that serves the chain's history for --backfill (default --rpc; a local anvil fork "
                         "cannot decode Citrate blocks, so the rehearsal passes the forked chain's own RPC)")
    a = ap.parse_args(argv)
    try:
        if a.rpc and not (a.genesis and hbu.HASH.match(a.genesis)):
            raise BookError("--genesis 0x<64 hex> is required with --rpc")
        if not a.rpc and not a.check:
            raise BookError("writing the ledger needs --rpc and --genesis (on-chain checks); use --check offline")
        if a.backfill and not a.rpc:
            raise BookError("--backfill reads the chain: it needs --rpc and --genesis")
        run = json.loads(Path(a.broadcast).read_text())
        chain = run.get("chain")
        if chain is not None and int(chain) != CHAIN_ID:
            raise BookError(f"broadcast is for chain {chain}, not {CHAIN_ID}")
        book = json.loads(Path(a.book).read_text())
        prov = json.loads(Path(a.provenance).read_text())
        if a.genesis:
            check_ledger_chain(prov, a.genesis)
        deployer = _addr(prov.get("deployer"), "ledger deployer")
        rows = broadcast_rows(run, deployer)
        check_book(book, rows)
        if a.backfill:
            own = [r for r in rows if not r.get("from")]
            if own:
                # Read the chain only after it is known to be the ledger's chain.
                scan = a.scan_rpc or a.rpc
                verify_live(scan, a.genesis, prov, [])
                filled = backfill(scan, prov, min(r["nonce"] for r in own), min(r["block"] for r in own) - 1)
                for r in filled:
                    print(f"  backfill nonce {r['nonce']} block {r['block']} {r['kind']} to {r['to']}")
                rows = filled + rows
        out, added, superseded = merge(prov, rows)
        if a.rpc:
            verify_live(a.rpc, a.genesis, prov, [r for r in added if r.get("address")])
            # Backfilled rows were read from the blocks of the chain checked above (backfill).
        else:
            print("hup-provenance-update: WARNING: no --rpc, on-chain checks skipped", file=sys.stderr)
        for r in added:
            print(f"  + nonce {r['nonce']} block {r['block']} {r.get('name') or r['kind']} {r.get('address') or r.get('to')}")
        for e in superseded:
            print(f"  ~ {e.get('name')} {e.get('address')} (nonce {e.get('nonce')}) -> superseded")
        if a.check:
            print(f"hup-provenance-update: OK ({len(added)} rows to add, {len(superseded)} to supersede)")
            return 0
        if not added:
            print("hup-provenance-update: nothing to add (every transaction is already recorded)")
            return 0
        Path(a.provenance).write_text(json.dumps(out, indent=1) + "\n")
        print(f"hup-provenance-update: wrote {a.provenance} ({len(added)} added, {len(superseded)} superseded)")
        return 0
    except (BookError, OSError, ValueError, KeyError, TypeError) as e:
        print(f"hup-provenance-update: ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
