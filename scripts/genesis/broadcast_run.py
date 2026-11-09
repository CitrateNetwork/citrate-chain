#!/usr/bin/env python3
"""broadcast_run.py: what a forge broadcast record proves was sent.

forge 1.8.3 writes broadcast/<script>/<chain>/run-*.json even when a script stops part-way
(the RPC drops, the node dies): the record then lists transactions that were never sent
("hash": null) and keeps the ones it did not see confirmed in "pending", with no receipt for
them. Such a record names contract addresses that may hold no code. So:

  * a run is COMPLETE only when "pending" is empty and every transaction has a hash with a
    receipt whose status is 0x1; anything else is PARTIAL (the script stopped part-way);
  * a CREATE/CREATE2 counts as deployed only from a complete run (its hash, and a receipt
    with status 0x1).

The genesis ceremony's sends-once guard, its book checks and library_book.py read records
through this module. A script with a partial run since this chain's block 0 is never treated
as sent and never sent again by the ceremony: it stops and escalates (runbook §6.4).

  scripts --broadcast DIR --chain ID --since TS SCRIPT...
      one line per script that has a run since TS: "sent <script>" (every run complete) or
      "partial <script> <why>" (a run is partial or unreadable)
"""
import argparse
import glob
import json
import os
import sys


def _ok_status(s):
    return s is True or s == 1 or (isinstance(s, str) and s.lower() in ("0x1", "1", "0x01"))


def run_status(run):
    """(True, "") for a complete run, else (False, why)."""
    if not isinstance(run, dict):
        return False, "the record is not a JSON object"
    pending = run.get("pending") or []
    if pending:
        return False, f"{len(pending)} transaction(s) still pending, unconfirmed"
    ok = set()
    for r in run.get("receipts") or []:
        if isinstance(r, dict) and isinstance(r.get("transactionHash"), str) and _ok_status(r.get("status")):
            ok.add(r["transactionHash"].lower())
    for tx in run.get("transactions") or []:
        if not isinstance(tx, dict):
            return False, "a transaction entry is not an object"
        h = tx.get("hash")
        name = tx.get("contractName") or tx.get("transactionType") or "a transaction"
        if not isinstance(h, str) or not h:
            return False, f"{name} was never sent (no hash)"
        if h.lower() not in ok:
            return False, f"{name} ({h}) has no receipt with status 0x1"
    return True, ""


def confirmed_creates(run):
    """[(contractName, contractAddress, tx)] for the CREATE/CREATE2 of a complete run."""
    done, _ = run_status(run)
    if not done:
        return []
    return [(tx.get("contractName"), tx.get("contractAddress"), tx)
            for tx in run.get("transactions") or []
            if tx.get("transactionType") in ("CREATE", "CREATE2")]


def ts_of(run):
    ts = run.get("timestamp") if isinstance(run, dict) else None
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None
    return ts / 1000 if ts > 10**12 else ts


def script_state(bdir, since):
    """None (no run since <since>), ("sent", ""), or ("partial", why) for one script's dir."""
    seen = False
    for f in sorted(glob.glob(os.path.join(bdir, "run-*.json"))):
        if os.path.basename(f) == "run-latest.json":
            continue
        try:
            with open(f) as fh:
                run = json.load(fh)
        except (OSError, ValueError) as e:
            return "partial", f"{os.path.basename(f)} cannot be read ({e})"
        ts = ts_of(run)
        if ts is None:
            return "partial", f"{os.path.basename(f)} has no timestamp"
        if ts < since:
            continue
        seen = True
        done, why = run_status(run)
        if not done:
            return "partial", f"{os.path.basename(f)}: {why}"
    if not seen:
        # forge also writes run-latest.json; a tree holding only that (a copied record) counts too.
        f = os.path.join(bdir, "run-latest.json")
        if os.path.exists(f):
            try:
                with open(f) as fh:
                    run = json.load(fh)
            except (OSError, ValueError) as e:
                return "partial", f"run-latest.json cannot be read ({e})"
            ts = ts_of(run)
            if ts is None:
                return "partial", "run-latest.json has no timestamp"
            if ts >= since:
                done, why = run_status(run)
                return ("sent", "") if done else ("partial", f"run-latest.json: {why}")
        return None
    return "sent", ""


def main(argv):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scripts")
    s.add_argument("--broadcast", required=True)
    s.add_argument("--chain", required=True)
    s.add_argument("--since", required=True, type=int)
    s.add_argument("script", nargs="+")
    a = ap.parse_args(argv)
    for sc in a.script:
        st = script_state(os.path.join(a.broadcast, sc, str(a.chain)), a.since)
        if st is None:
            continue
        print(f"sent {sc}" if st[0] == "sent" else f"partial {sc} {st[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
