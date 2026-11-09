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
ARACHNID_FACTORY = "0x4e59b44847b379578588920ca78fbf26c0b4956c"


def holds(hexdata, addr):
    """Whether `addr` (20 bytes) appears byte-aligned anywhere in `hexdata` (0x-hex):
    left-padded in a word, or packed beside other fields."""
    h, a = hexdata[2:].lower(), addr[2:].lower()
    i = h.find(a)
    while i >= 0:
        if i % 2 == 0:
            return True
        i = h.find(a, i + 1)
    return False


def scan_privileged(accounts, deployer):
    """Block 0 keeps no reference to the ceremony deployer (a public, throwaway key) or to
    the CREATE2 factory in any account's storage, nor the deployer in any runtime code
    (an immutable). The factory's own account is exempt from the code scan."""
    for acc in accounts:
        for k, v in (acc.get("storage") or {}).items():
            for who, name in ((deployer, "the ceremony deployer"), (ARACHNID_FACTORY, "the CREATE2 factory")):
                if holds(v, who):
                    fail(f"{acc['address']}: storage slot {k} holds {name} ({v})")
        code = acc.get("code") or "0x"
        if holds(code, deployer):
            fail(f"{acc['address']}: runtime code holds the ceremony deployer (an immutable)")
ORANGESEED_IMPL = "0x000000000000000000000000000000c17a7e5ee0"
# Pinned from chain#389's GenesisOrangeSeed output (its PR body lists the same hashes). The
# code is taken from that script's output, never recompiled here.
ORANGESEED_CODEHASHES = {
    ORANGESEED_PROXY: "46a010df31eb642b47284650e80051e8f6239a0c995003d230b437810bc4b9b4",
    ORANGESEED_IMPL: "d2a228771b614b678ea1bf4c9ecf415ceefc8f6af7462267d90947c91df6e96c",
}


def fail(msg):
    sys.exit(f"emit_alloc: {msg}")


def norm_qty(v):
    if not isinstance(v, str) or not HEX.match(v) or v == "0x":
        fail(f"bad quantity {v!r}")
    return hex(int(v, 16))


VALUE_OK = re.compile(r"^(0x[0-9a-fA-F]{40}(,0x[0-9a-fA-F]{40})*|[0-9]{1,40}|placeholder|final)$")
SALT = 10**18
# r1006 base allocations when the inputs name fresh base accounts (owner decision
# 2026-10-26: fresh keys, no account that transacted on an earlier 40204 chain is funded).
# The amounts keep r1005's 585B pre-allocation: TREASURY takes r1005's treasury (500B),
# reserve (50B), deployer (10B) and validator (5B) shares; FAUCET and TEAM keep 10B each.
BASE_AMOUNTS = {"BASE_TREASURY": 565_000_000_000, "BASE_FAUCET": 10_000_000_000, "BASE_TEAM": 10_000_000_000}


def check_inputs(path):
    """The inputs file holds addresses and numbers only: never key material."""
    vals = {}
    for n, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, eq, v = line.partition("=")
        if not eq or not re.match(r"^[A-Z0-9_]+$", k):
            fail(f"{path}:{n}: not KEY=VALUE")
        if re.search(r"0x[0-9a-fA-F]{64}", v) or re.search(r"\b[0-9a-fA-F]{64}\b", v):
            fail(f"{path}:{n}: {k} holds a 32-byte hex value; the inputs file must never hold key material")
        if not VALUE_OK.match(v):
            fail(f"{path}:{n}: {k} is not an address, an address list or a number")
        vals[k] = v
    return vals


def read_inputs(path):
    raw = open(path, "rb").read()
    vals = check_inputs(path)
    status = vals.get("R1006_INPUTS_STATUS")
    if status not in ("placeholder", "final"):
        fail("inputs file must set R1006_INPUTS_STATUS=placeholder|final")
    base = None
    if any(k in vals for k in BASE_AMOUNTS):
        missing = [k for k in BASE_AMOUNTS if k not in vals]
        if missing:
            fail(f"inputs name some base accounts but not {missing}")
        base = [{"role": k[5:].lower(), "address": vals[k].lower(), "balance": hex(BASE_AMOUNTS[k] * SALT)}
                for k in BASE_AMOUNTS]
    elif status == "final":
        fail("final inputs must name the fresh base accounts (BASE_TREASURY, BASE_FAUCET, BASE_TEAM)")
    return status, hashlib.sha256(raw).hexdigest(), base


def keccak_hex(data):
    """keccak256 of raw bytes, through Foundry's cast (no Python crypto dependency)."""
    out = subprocess.run(["cast", "keccak", "0x" + data.hex()], capture_output=True, text=True, check=True)
    return out.stdout.strip().removeprefix("0x")


def main():
    if sys.argv[1:2] == ["--check-inputs"] and len(sys.argv) == 3:
        check_inputs(sys.argv[2])
        print(f"emit_alloc: {sys.argv[2]}: addresses and numbers only")
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", required=True)
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--book", required=True, help="the ceremony's stack book (contracts/addresses/40204.json)")
    ap.add_argument("--orangeseed", help="the OrangeSeed PR's GenesisOrangeSeed output (alloc JSON)")
    ap.add_argument("--governance-book", help="the same ceremony's governance.json (required with --orangeseed)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    dump = json.load(open(a.dump))
    if dump.get("format") != "citrate-state-dump-v1":
        fail("not a citrate-state-dump-v1 file")
    deployer = json.load(open(a.manifest))["deployer"].lower()
    if not ADDR.match(deployer):
        fail(f"bad deployer {deployer!r} in the manifest")
    status, inputs_sha, base = read_inputs(a.inputs)
    vr = json.load(open(a.book))["contracts"]["ValidatorRegistry"].lower()
    if not ADDR.match(vr):
        fail(f"bad ValidatorRegistry {vr!r} in the book")

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
        if not a.governance_book:
            fail("--orangeseed needs --governance-book (the same ceremony's governance.json)")
        gov = json.load(open(a.governance_book))["contracts"]["GovernanceTimelock"].lower()
        og = str(o.get("params", {}).get("governance", "")).lower()
        if not ADDR.match(gov) or int(gov, 16) == 0:
            fail(f"bad GovernanceTimelock {gov!r} in the governance book")
        if og != gov:
            fail(f"OrangeSeed was generated for governance {og or 'none'}, not this ceremony's GovernanceTimelock {gov}")
        gov_word = "0x" + "0" * 24 + gov[2:]
        dep_word = "0x" + "0" * 24 + deployer[2:]
        proxy_vals = {vv.lower() for vv in (o["alloc"].get(next(k for k in o["alloc"] if k.lower() == ORANGESEED_PROXY), {}).get("storage") or {}).values()}
        if gov_word not in proxy_vals:
            fail("the OrangeSeed proxy's storage does not name this ceremony's GovernanceTimelock (its upgrade authority)")
        for k, v in o["alloc"].items():
            if any(vv.lower() == dep_word for vv in (v.get("storage") or {}).values()):
                fail(f"OrangeSeed {k.lower()}: a storage slot holds the ceremony deployer")
        taken = {x["address"] for x in accounts}
        addrs = sorted(k.lower() for k in o["alloc"])
        if addrs != sorted(ORANGESEED_CODEHASHES):
            fail(f"the OrangeSeed alloc must hold exactly {sorted(ORANGESEED_CODEHASHES)}, got {addrs}")
        for k, v in o["alloc"].items():
            addr = k.lower()
            if addr in taken:
                fail(f"OrangeSeed account {addr} collides with a ceremony account")
            code = v["code"].lower()
            if not HEX.match(code) or code == "0x":
                fail(f"OrangeSeed {addr}: no code")
            if keccak_hex(bytes.fromhex(code[2:])) != ORANGESEED_CODEHASHES[addr]:
                fail(f"OrangeSeed {addr}: code hash is not the pinned {ORANGESEED_CODEHASHES[addr]}")
            st = {kk.lower(): vv.lower() for kk, vv in (v.get("storage") or {}).items() if int(vv, 16) != 0}
            ent = {"address": addr, "balance": norm_qty(v["balance"]), "nonce": int(v["nonce"], 0) if isinstance(v["nonce"], str) else int(v["nonce"]), "code": code}
            if st:
                ent["storage"] = dict(sorted(st.items()))
            accounts.append(ent)
        orangeseed = {"proxy": ORANGESEED_PROXY, "implementation": ORANGESEED_IMPL}
    accounts.sort(key=lambda x: x["address"])
    scan_privileged(accounts, deployer)

    alloc = {
        "format": "citrate-genesis-alloc-v1",
        "profile": "r1006",
        "inputsStatus": status,
        "inputsSha256": inputs_sha,
        "validatorRegistry": vr,
        "baseAllocations": base,
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
