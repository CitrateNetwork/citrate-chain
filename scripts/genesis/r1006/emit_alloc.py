#!/usr/bin/env python3
"""emit_alloc.py: a ceremony devnet's state dump -> the r1006 genesis allocation.

Input: the `state-dump` JSON of the stopped ceremony devnet, the inputs file it ran with and
the ceremony's run manifest (for the deployer). Output: the canonical allocation the node's
`r1006` profile embeds (core/economics/assets/r1006/alloc.json).

What is kept (and why):
  * every account with code or storage: the ceremony's contracts, with their balance, nonce,
    code and storage exactly as dumped (the Arachnid CREATE2 factory too, with the nonce the
    ceremony left it at);
  * the ceremony deployer, with its nonce and a ZERO balance: the nonce keeps every CREATE
    address it used spent; its key is public (a throwaway), so it must hold nothing.
What is dropped: every other account without code or storage (the devnet's dev accounts,
the funder, the block-reward coinbase). The r1006 base allocations come from the profile,
not from the devnet.

The output is canonical (sorted, lowercase hex, fixed key order, LF, no trailing spaces),
so the same dump gives the same bytes.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys

HEX = re.compile(r"^0x[0-9a-f]*$")
ADDR = re.compile(r"^0x[0-9a-f]{40}$")
WORD = re.compile(r"^0x[0-9a-f]{64}$")
ORANGESEED_PROXY = "0x000000000000000000000000000000c17a7e5eed"


def fail(msg):
    sys.exit(f"emit_alloc: {msg}")


def norm_qty(v):
    if not isinstance(v, str) or not HEX.match(v) or v == "0x":
        fail(f"bad quantity {v!r}")
    return hex(int(v, 16))


def read_inputs(path):
    raw = open(path, "rb").read()
    status = None
    for line in raw.decode().splitlines():
        if line.startswith("R1006_INPUTS_STATUS="):
            status = line.split("=", 1)[1].strip()
    if status not in ("placeholder", "final"):
        fail("inputs file must set R1006_INPUTS_STATUS=placeholder|final")
    return status, hashlib.sha256(raw).hexdigest()


def keccak_hex(data):
    """keccak256 of raw bytes, through Foundry's cast (no Python crypto dependency)."""
    out = subprocess.run(["cast", "keccak", "0x" + data.hex()], capture_output=True, text=True, check=True)
    return out.stdout.strip().removeprefix("0x")


def read_validators(path):
    raw = open(path, "rb").read()
    v = json.loads(raw)
    status = v.get("status")
    if status not in ("placeholder", "final"):
        fail("validators file must have status placeholder|final")
    return status, keccak_hex(raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", required=True)
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--validators", required=True)
    ap.add_argument("--orangeseed", help="the OrangeSeed PR's GenesisOrangeSeed output (alloc JSON)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    dump = json.load(open(a.dump))
    if dump.get("format") != "citrate-state-dump-v1":
        fail("not a citrate-state-dump-v1 file")
    deployer = json.load(open(a.manifest))["deployer"].lower()
    if not ADDR.match(deployer):
        fail(f"bad deployer {deployer!r} in the manifest")
    status, inputs_sha = read_inputs(a.inputs)
    v_status, v_keccak = read_validators(a.validators)

    accounts = []
    seen_deployer = False
    for acc in dump["accounts"]:
        addr = acc["address"].lower()
        if not ADDR.match(addr):
            fail(f"bad address {addr!r}")
        code = (acc.get("code") or "").lower()
        storage = {k.lower(): v.lower() for k, v in (acc.get("storage") or {}).items()}
        for k, v in storage.items():
            if not WORD.match(k) or not WORD.match(v):
                fail(f"{addr}: bad storage slot {k}={v}")
        storage = {k: v for k, v in storage.items() if int(v, 16) != 0}
        if addr == deployer:
            seen_deployer = True
            if code or storage:
                fail("the ceremony deployer has code or storage")
            accounts.append({"address": addr, "balance": "0x0", "nonce": int(acc["nonce"])})
            continue
        if not code and not storage:
            continue
        if code and not HEX.match(code):
            fail(f"{addr}: bad code")
        out = {"address": addr, "balance": norm_qty(acc["balance"]), "nonce": int(acc["nonce"])}
        if code:
            out["code"] = code
        if storage:
            out["storage"] = dict(sorted(storage.items()))
        accounts.append(out)
    if not seen_deployer:
        fail(f"the deployer {deployer} is not in the dump")
    orangeseed = None
    if a.orangeseed:
        o = json.load(open(a.orangeseed))
        taken = {x["address"] for x in accounts}
        addrs = sorted(k.lower() for k in o["alloc"])
        if ORANGESEED_PROXY not in addrs or len(addrs) != 2:
            fail(f"the OrangeSeed alloc must hold the proxy {ORANGESEED_PROXY} and one implementation, got {addrs}")
        for k, v in o["alloc"].items():
            addr = k.lower()
            if addr in taken:
                fail(f"OrangeSeed account {addr} collides with a ceremony account")
            code = v["code"].lower()
            if not HEX.match(code) or code == "0x":
                fail(f"OrangeSeed {addr}: no code")
            st = {kk.lower(): vv.lower() for kk, vv in (v.get("storage") or {}).items() if int(vv, 16) != 0}
            ent = {"address": addr, "balance": norm_qty(v["balance"]), "nonce": int(v["nonce"], 0) if isinstance(v["nonce"], str) else int(v["nonce"]), "code": code}
            if st:
                ent["storage"] = dict(sorted(st.items()))
            accounts.append(ent)
        orangeseed = {"proxy": ORANGESEED_PROXY, "implementation": [x for x in addrs if x != ORANGESEED_PROXY][0]}
    accounts.sort(key=lambda x: x["address"])

    alloc = {
        "format": "citrate-genesis-alloc-v1",
        "profile": "r1006",
        "inputsStatus": status,
        "inputsSha256": inputs_sha,
        "validatorsStatus": v_status,
        "validatorsKeccak256": v_keccak,
        "orangeseed": orangeseed,
        "deployer": deployer,
        "accounts": accounts,
    }
    text = json.dumps(alloc, indent=1, sort_keys=False, separators=(",", ": ")) + "\n"
    with open(a.out, "w", newline="\n") as f:
        f.write(text)
    n_code = sum(1 for x in accounts if "code" in x)
    n_slots = sum(len(x.get("storage", {})) for x in accounts)
    print(f"alloc: {len(accounts)} accounts ({n_code} with code, {n_slots} slots), "
          f"inputs {status}, sha256 {hashlib.sha256(text.encode()).hexdigest()}", file=sys.stderr)


if __name__ == "__main__":
    main()
