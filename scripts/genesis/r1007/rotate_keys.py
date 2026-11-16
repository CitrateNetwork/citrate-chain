#!/usr/bin/env python3
"""rotate_keys.py: the r1007 genesis allocation from the r1006 block-0 state with fresh role keys.

D-K3 (owner 2026-11-10): every non-producer EVM key the r1006 block 0 names is rotated at the
r1007 ceremony; producer keys and stakers stay. This tool reads

  - core/economics/assets/r1006/alloc.json   (the r1006 ceremony state, read in place),
  - scripts/genesis/r1006/inputs.r1006.env   (the r1006 role addresses, public),
  - scripts/genesis/r1007/inputs.r1007.env   (the fresh r1007 role addresses, public),

and writes core/economics/assets/r1007/alloc.json: the same accounts, code and storage, with
every occurrence of each rotated r1006 address replaced by its r1007 address:

  1. account addresses (accounts re-sorted by address);
  2. storage values, wherever the 20 address bytes sit in the word (packed slots included);
  3. storage keys of address-keyed mappings, keccak256(pad32(addr) ++ uint256(slot)) for
     slot < 64, recomputed for the new address;
  4. the header fields (baseAllocations, deployer).

It refuses (exit 1) if an old address remains anywhere in the output, if an old address occurs
in contract code (an immutable would need a rebuild, not an edit), or if the role sets do not
line up. Keys of every kind the r1006 state holds for these contracts were classified when this
tool was written (2026-11-11: small slots, dynamic-array elements, address-keyed mappings at
slot 1, and EIP-1967 / ERC-7201 namespaced slots); no nested address-keyed mapping holds a
rotated key. Deterministic: the same inputs give byte-identical output.

  rotate_keys.py [--check]     write the alloc, or (--check) fail if the committed one differs
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

CHAIN = Path(__file__).resolve().parents[3]
R1006_ALLOC = CHAIN / "core/economics/assets/r1006/alloc.json"
R1006_INPUTS = CHAIN / "scripts/genesis/r1006/inputs.r1006.env"
R1007_INPUTS = CHAIN / "scripts/genesis/r1007/inputs.r1007.env"
R1007_ALLOC = CHAIN / "core/economics/assets/r1007/alloc.json"
MAPPING_SLOTS = range(64)

ADDR = re.compile(r"0x[0-9a-fA-F]{40}")


class Refuse(Exception):
    pass


def env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v.strip()
    return out


def keccak(data: bytes) -> bytes:
    """keccak256 through Foundry's cast, as scripts/genesis/r1006/emit_alloc.py does."""
    r = subprocess.run(["cast", "keccak", "0x" + data.hex()], capture_output=True, text=True, check=True)
    return bytes.fromhex(r.stdout.strip()[2:])


def role_map(alloc: dict) -> dict[str, tuple[str, str]]:
    """role -> (r1006 address, r1007 address), lower-case hex without 0x."""
    old = env(R1006_INPUTS)
    new = env(R1007_INPUTS)
    if new.get("R1007_INPUTS_STATUS") != "final":
        raise Refuse(f"{R1007_INPUTS}: R1007_INPUTS_STATUS is not final")
    olds: dict[str, str] = {}
    for i, a in enumerate(old["GOV_OWNERS"].split(","), 1):
        olds[f"GOV_OWNER_{i}"] = a
    for i, a in enumerate(old["GRD_OWNERS"].split(","), 1):
        olds[f"GRD_OWNER_{i}"] = a
    for r in ("MEMBERSHIP_GRANTOR", "SIGNER_1", "SIGNER_2", "SIGNER_3", "RELAYER",
              "CITRATE_AA_OWNER", "CITRATE_AA_IDENTITY_SIGNER", "CITRATE_AA_SPONSOR_SIGNER", "TREASURY"):
        olds[r] = old[r]
    olds["FAUCET"] = old["BASE_FAUCET"]
    olds["TEAM"] = old["BASE_TEAM"]
    olds["DEPLOYER"] = alloc["deployer"]
    if old["BASE_TREASURY"].lower() != old["TREASURY"].lower():
        raise Refuse("inputs.r1006.env: BASE_TREASURY differs from TREASURY")
    if old["TEAM_VESTING_BENEFICIARY"].lower() != old["BASE_TEAM"].lower():
        raise Refuse("inputs.r1006.env: TEAM_VESTING_BENEFICIARY differs from BASE_TEAM")
    roles = {k for k in new if k != "R1007_INPUTS_STATUS"}
    if roles != set(olds):
        raise Refuse(f"role sets differ: only r1006 {sorted(set(olds) - roles)}, only r1007 {sorted(roles - set(olds))}")
    out = {}
    for r in sorted(olds):
        for a in (olds[r], new[r]):
            if not ADDR.fullmatch(a):
                raise Refuse(f"{r}: {a!r} is not an address")
        out[r] = (olds[r].lower()[2:], new[r].lower()[2:])
    fresh = [n for _, n in out.values()]
    if len(set(fresh)) != len(fresh):
        raise Refuse("two r1007 roles share an address")
    retired = {o for o, _ in out.values()}
    if retired & set(fresh):
        raise Refuse("an r1007 key is a retired r1006 key")
    return out


def pad(a: str) -> bytes:
    return bytes(12) + bytes.fromhex(a)


def w32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def rotate(alloc: dict, roles: dict[str, tuple[str, str]]) -> dict:
    swap = {o: n for o, n in roles.values()}
    key_swap = {}
    for o, n in swap.items():
        for s in MAPPING_SLOTS:
            key_swap["0x" + keccak(pad(o) + w32(s)).hex()] = "0x" + keccak(pad(n) + w32(s)).hex()

    def sub_hex(text: str) -> str:
        t = text.lower()
        for o, n in swap.items():
            t = t.replace(o, n)
        return t

    def norm_key(k: str) -> str:
        return "0x" + k[2:].lower().rjust(64, "0")

    accounts = []
    for acc in alloc["accounts"]:
        a = dict(acc)
        code = a.get("code") or ""
        for o in swap:
            if o in code.lower():
                raise Refuse(f"{acc['address']}: the code holds rotated address 0x{o}; rebuild, do not edit")
        a["address"] = "0x" + sub_hex(acc["address"][2:])
        st = {}
        for k, v in (acc.get("storage") or {}).items():
            nk = key_swap.get(norm_key(k), k)
            nv = "0x" + sub_hex(v[2:])
            if nk in st:
                raise Refuse(f"{acc['address']}: two storage keys collide after rotation")
            st[nk] = nv
        a["storage"] = st
        accounts.append(a)
    accounts.sort(key=lambda x: bytes.fromhex(x["address"][2:]))
    out = dict(alloc)
    out["profile"] = "r1007"
    out["inputsStatus"] = "final"
    out["inputsSha256"] = hashlib.sha256(R1007_INPUTS.read_bytes()).hexdigest()
    out["rotatedFrom"] = {
        "alloc": "core/economics/assets/r1006/alloc.json",
        "allocSha256": hashlib.sha256(R1006_ALLOC.read_bytes()).hexdigest(),
        "inputs": "scripts/genesis/r1007/inputs.r1007.env",
        "rule": "D-K3 (owner 2026-11-10): every non-producer key rotated; producers and stakers kept",
    }
    out["baseAllocations"] = [
        dict(b, address="0x" + sub_hex(b["address"][2:])) for b in alloc["baseAllocations"]
    ]
    out["deployer"] = "0x" + sub_hex(alloc["deployer"][2:])
    out["accounts"] = accounts
    text = json.dumps(out, indent=1, sort_keys=False, separators=(",", ": ")).lower()
    for r, (o, _) in roles.items():
        if o in text:
            raise Refuse(f"{r}: 0x{o} remains in the output")
    for k in key_swap:
        if k[2:] in text:
            raise Refuse("an r1006 mapping key remains in the output")
    return out


def main(argv: list[str]) -> int:
    try:
        alloc = json.loads(R1006_ALLOC.read_text())
        if alloc.get("profile") != "r1006" or alloc.get("inputsStatus") != "final":
            raise Refuse(f"{R1006_ALLOC} is not the final r1006 alloc")
        out = rotate(alloc, role_map(alloc))
        text = json.dumps(out, indent=1, sort_keys=False, separators=(",", ": ")) + "\n"
        if "--check" in argv:
            if not R1007_ALLOC.is_file() or R1007_ALLOC.read_text() != text:
                print(f"rotate_keys: {R1007_ALLOC} differs from a fresh rotation", file=sys.stderr)
                return 1
            print("rotate_keys: the committed r1007 alloc is the rotation of r1006")
            return 0
        R1007_ALLOC.parent.mkdir(parents=True, exist_ok=True)
        R1007_ALLOC.write_text(text)
        print(f"rotate_keys: wrote {R1007_ALLOC} ({len(out['accounts'])} accounts)")
        return 0
    except Refuse as e:
        print(f"rotate_keys: refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
