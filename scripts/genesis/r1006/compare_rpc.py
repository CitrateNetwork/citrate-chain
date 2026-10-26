#!/usr/bin/env python3
"""compare_rpc.py: a node booted from the r1006 genesis serves the ceremony devnet's state.

For EVERY account in the genesis alloc: eth_getCode on the r1006 node equals eth_getCode on
the ceremony devnet (and the alloc); eth_getBalance and eth_getTransactionCount equal the
alloc. For EVERY storage slot the devnet dump holds for those accounts: eth_getStorageAt
equal on both nodes (and equal to the alloc). Read-only JSON-RPC over loopback.

  compare_rpc.py --alloc alloc.json --dump dump.json --devnet URL --r1006 URL
Exit 0 when everything matches; 1 with every mismatch listed.
"""
import argparse
import json
import sys
import urllib.request


def rpc_one(url, method, params):
    """One call, retried: the node's RPC rate limiter may answer a burst with an error."""
    import time
    last = None
    for attempt in range(30):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            r = json.load(urllib.request.urlopen(req, timeout=60))
        except Exception as e:  # noqa: BLE001 - retried, then reported
            last = repr(e)
            time.sleep(0.2 * (attempt + 1))
            continue
        if isinstance(r, dict) and "result" in r and "error" not in r:
            return r["result"]
        last = r
        time.sleep(0.2 * (attempt + 1))
    raise SystemExit(f"compare_rpc: {url} {method} {params}: {last}")


def rpc_batch(url, calls):
    return [rpc_one(url, m, p) for m, p in calls]


def q(v):
    return int(v, 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alloc", required=True)
    ap.add_argument("--dump", required=True)
    ap.add_argument("--devnet", required=True)
    ap.add_argument("--r1006", required=True)
    a = ap.parse_args()
    alloc = json.load(open(a.alloc))["accounts"]
    dump = {x["address"].lower(): x for x in json.load(open(a.dump))["accounts"]}
    bad = []
    addrs = [x["address"] for x in alloc]
    # Accounts the builder adds beside the ceremony state (OrangeSeed) are not on the devnet:
    # they are checked against the alloc on the r1006 node only.
    on_devnet = [x for x in alloc if x["address"] in dump]
    for node, accts in (("devnet", on_devnet), ("r1006", alloc)):
        url = getattr(a, node)
        codes = rpc_batch(url, [("eth_getCode", [x["address"], "latest"]) for x in accts])
        for x, c in zip(accts, codes):
            if c.lower() != x.get("code", "0x"):
                bad.append(f"{node} {x['address']}: code {len(c) // 2 - 1} bytes, alloc {len(x.get('code', '0x')) // 2 - 1}")
    bals = rpc_batch(a.r1006, [("eth_getBalance", [ad, "latest"]) for ad in addrs])
    nonces = rpc_batch(a.r1006, [("eth_getTransactionCount", [ad, "latest"]) for ad in addrs])
    for x, b, n in zip(alloc, bals, nonces):
        if q(b) != q(x["balance"]):
            bad.append(f"r1006 {x['address']}: balance {b}, alloc {x['balance']}")
        if q(n) != x["nonce"]:
            bad.append(f"r1006 {x['address']}: nonce {q(n)}, alloc {x['nonce']}")
    slots = []
    for x in alloc:
        d = dump.get(x["address"], {})
        keys = set((d.get("storage") or {}).keys()) | set((x.get("storage") or {}).keys())
        slots += [(x["address"], k, (x.get("storage") or {}).get(k, "0x" + "0" * 64)) for k in sorted(keys)]
    for node in ("devnet", "r1006"):
        sl = [x for x in slots if node == "r1006" or x[0] in dump]
        vals = rpc_batch(getattr(a, node), [("eth_getStorageAt", [ad, k, "latest"]) for ad, k, _ in sl])
        for (ad, k, want), got in zip(sl, vals):
            if q(got) != q(want):
                bad.append(f"{node} {ad} slot {k}: {got}, alloc {want}")
    n_code = sum(1 for x in alloc if x.get("code"))
    if bad:
        print("\n".join(bad[:200]))
        print(f"compare_rpc: FAIL, {len(bad)} mismatch(es)")
        sys.exit(1)
    print(f"compare_rpc: PASS: {len(alloc)} accounts ({n_code} with code) and {len(slots)} storage slots; "
          f"{len(on_devnet)} ceremony accounts identical on the devnet and the r1006 node, "
          f"{len(alloc) - len(on_devnet)} builder-added (OrangeSeed) equal to the alloc; balances and nonces equal the alloc")


if __name__ == "__main__":
    main()
