#!/usr/bin/env python3
"""Render the r1006 network profile for one producer host, and check a genesis fill.

  render_profile.py profile --template scripts/producers/profiles/r1006.json \
      --producers state/r1006-producers.json --fill state/genesis/fill-result.json \
      --host citrate-prod-3 --out state/profiles/citrate-prod-3.json
  render_profile.py check-fill --producers state/r1006-producers.json \
      --stakes state/r1006-stakes.json --fill state/genesis/fill-result.json
  render_profile.py stakes --producers state/r1006-producers.json --stake-salt 32000 \
      --liquid-salt 100 --out state/r1006-stakes.json

The profile is the template (status pending-genesis) with the values that only exist
after the keys and the genesis: the genesis hash and profile, the ValidatorRegistry and
activation height from the fill, and the bootnodes, which are the OTHER producers
(private bring-up: the public bootnodes are not used). RPC stays on loopback
(gen_node_config.py always binds it there). The result is what gen_node_config.py
--profile <path> reads on the host.

The fill result (written by the genesis builder's validator-set fill) is the contract
between the genesis builder and this bring-up:

  {"schema": "r1006-genesis-fill/1",
   "genesis_hash": "0x<32 bytes>",              block 0 of the filled genesis
   "genesis_profile": "r1006" | null,           compiled-in profile the node selects
   "genesis_file": "genesis.json" | null,       a genesis the hosts receive as a file
   "alloc_file": "genesis.json",                {"alloc": {addr: {"code": "0x.."}}}: smoke's code check
   "address_book": "book.json" | null,          CheckDeployedAdmins input (DEPLOYER-ADMIN 0)
   "orangeseed": "0x<20 bytes>" | null,
   "validator_registry": "0x<20 bytes>",
   "validator_activation_height": N,
   "validators": [{"proposer_pubkey", "staker", "stake_wei"}],
   "validators_at_genesis": true | false,       true: the set is in block 0 (activation may be 0)
   "source": "<what produced it>"}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

B32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
WEI_PER_SALT = 10**18


class RenderError(Exception):
    pass


def load(p: Path) -> dict:
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RenderError(f"cannot read {p}: {e}") from None
    if not isinstance(d, dict):
        raise RenderError(f"{p} is not a JSON object")
    return d


def check_fill(fill: dict, producers: dict, stakes: dict | None) -> list[str]:
    """Problems with a fill result against the producer set (empty list = consistent)."""
    out = []
    if fill.get("schema") != "r1006-genesis-fill/1":
        out.append(f"schema is {fill.get('schema')!r}, not r1006-genesis-fill/1")
    if not B32.match(str(fill.get("genesis_hash", ""))):
        out.append("genesis_hash is not a 32-byte hash")
    if not ADDR.match(str(fill.get("validator_registry", ""))):
        out.append("validator_registry is not an address")
    h = fill.get("validator_activation_height")
    if not isinstance(h, int) or h < 0:
        out.append("validator_activation_height is not a height")
    if not fill.get("genesis_profile") and not fill.get("genesis_file"):
        out.append("neither genesis_profile nor genesis_file is set: the hosts cannot select this genesis")
    vals = fill.get("validators")
    if not isinstance(vals, list):
        return out + ["validators is not a list"]
    want = {p["proposer_pubkey"].lower(): p["staker_address"].lower() for p in producers["producers"]}
    got = {}
    for v in vals:
        pk, st = str(v.get("proposer_pubkey", "")).lower(), str(v.get("staker", "")).lower()
        if pk in got:
            out.append(f"validator {pk} appears twice")
        got[pk] = st
        if stakes is not None:
            s = stakes["stakes"].get(st)
            if s is None:
                out.append(f"validator staker {st} has no stake allocation")
            elif int(v.get("stake_wei", -1)) != int(s["stake_wei"]):
                out.append(f"validator {st} stake {v.get('stake_wei')} is not the allocated {s['stake_wei']}")
    if got != want:
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        wrong = sorted(k for k in set(got) & set(want) if got[k] != want[k])
        if missing:
            out.append(f"validators missing from the fill: {', '.join(missing)}")
        if extra:
            out.append(f"validators in the fill that are not producers: {', '.join(extra)}")
        if wrong:
            out.append(f"validators with the wrong staker: {', '.join(wrong)}")
    return out


def render(template: dict, producers: dict, fill: dict, host: str) -> dict:
    names = [p["name"] for p in producers["producers"]]
    if host not in names:
        raise RenderError(f"{host} is not in the producer set ({', '.join(names)})")
    prof = dict(template)
    prof["name"] = f"r1006-{host}"
    prof["status"] = "ready"
    prof["chain_id"] = int(producers["chain_id"])
    prof["genesis_hash"] = fill["genesis_hash"]
    prof["genesis_profile"] = fill.get("genesis_profile")
    prof["validator_registry"] = fill["validator_registry"]
    prof["validator_activation_height"] = int(fill["validator_activation_height"])
    prof["validators_at_genesis"] = fill.get("validators_at_genesis") is True
    prof["public_rpc"] = "http://127.0.0.1:8545"
    prof["bootstrap_nodes"] = [p["bootnode"] for p in producers["producers"] if p["name"] != host]
    src = dict(template.get("sources", {}))
    src.update(
        {
            "genesis_hash": f"genesis fill ({fill.get('source', 'unknown')})",
            "bootstrap_nodes": "r1006-producers.json: the other producers (private bring-up)",
            "validator_registry": "genesis fill",
            "validator_activation_height": "genesis fill",
        }
    )
    prof["sources"] = src
    return prof


def stakes_doc(producers: dict, stake_salt: int, liquid_salt: int) -> dict:
    return {
        "schema": "r1006-stakes/1",
        "note": "Per producer staker: bonded stake in the ValidatorRegistry plus a liquid balance for gas.",
        "stakes": {
            p["staker_address"].lower(): {
                "name": p["name"],
                "stake_wei": str(stake_salt * WEI_PER_SALT),
                "liquid_wei": str(liquid_salt * WEI_PER_SALT),
            }
            for p in producers["producers"]
        },
    }


def write(p: Path, d: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, indent=2) + "\n")
    tmp.replace(p)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("profile")
    a1.add_argument("--template", required=True, type=Path)
    a1.add_argument("--producers", required=True, type=Path)
    a1.add_argument("--fill", required=True, type=Path)
    a1.add_argument("--host", required=True)
    a1.add_argument("--out", required=True, type=Path)
    a2 = sub.add_parser("check-fill")
    a2.add_argument("--producers", required=True, type=Path)
    a2.add_argument("--stakes", type=Path)
    a2.add_argument("--fill", required=True, type=Path)
    a3 = sub.add_parser("stakes")
    a3.add_argument("--producers", required=True, type=Path)
    a3.add_argument("--stake-salt", type=int, default=32000)
    a3.add_argument("--liquid-salt", type=int, default=100)
    a3.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "stakes":
            if a.stake_salt < 32000:
                raise RenderError("stake below minStake (32,000 SALT)")
            write(a.out, stakes_doc(load(a.producers), a.stake_salt, a.liquid_salt))
            print(f"stakes -> {a.out}")
        elif a.cmd == "check-fill":
            probs = check_fill(load(a.fill), load(a.producers), load(a.stakes) if a.stakes else None)
            for p in probs:
                print(f"FAIL  {p}")
            if probs:
                return 1
            print("fill consistent with the producer set")
        else:
            fill, producers = load(a.fill), load(a.producers)
            probs = check_fill(fill, producers, None)
            if probs:
                raise RenderError("fill result is not usable: " + "; ".join(probs))
            write(a.out, render(load(a.template), producers, fill, a.host))
            print(f"profile -> {a.out}")
        return 0
    except RenderError as e:
        print(f"render_profile: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
