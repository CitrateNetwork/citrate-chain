#!/usr/bin/env python3
"""Merge the producers' public identities into r1006-producers.json.

Input: one `identity.pub.json` per host (the output of `citrate host-identity`, read
back by `host_agent.sh pub`, which cats that file and nothing else), plus the
inventory. Output: the producer set the genesis builder's validator-set fill reads.

Every input is checked against the public schema before anything is written: exactly
the known fields, each in its public form (a peer id, 32-byte public keys, a compressed
P-256 point, 20-byte addresses). Anything else, including an extra field, is refused:
a private key never has a place to hide in this file. Keys must be distinct across
hosts (one key on two hosts is equivocation) and the staker must be the coinbase
(executor check 3c).

  collect.py --inventory inv.json --pub-dir state/pub --out state/r1006-producers.json \
      [--proofs-out state/r1006-registration-proofs.json --registry 0x..]

With --proofs-out, each host's `<name>.proof.json` (its `citrate registration-proof`
output, already checked on the host and by guard.py) is checked again against that
host's identity and the registry, and written in inventory order as
{"schema": "r1006-registration-proofs/1", "proofs": [...]}, the input of
scripts/genesis/r1006/fill_producers.py.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_IN = "citrate-host-identity/1"
SCHEMA_OUT = "r1006-producers/1"
FIELDS = {
    "schema": re.compile(r"^citrate-host-identity/1$"),
    "peer_id": re.compile(r"^noise_[0-9a-f]{64}$"),
    "noise_pubkey": re.compile(r"^[0-9a-f]{64}$"),
    "proposer_pubkey": re.compile(r"^0x[0-9a-f]{64}$"),
    "vrf_pubkey": re.compile(r"^0x0[23][0-9a-f]{64}$"),
    "staker_address": re.compile(r"^0x[0-9a-f]{40}$"),
    "coinbase_address": re.compile(r"^0x[0-9a-f]{40}$"),
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


class CollectError(Exception):
    pass


def check_identity(name: str, raw: str) -> dict:
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CollectError(f"{name}: public identity is not JSON ({e.msg})") from None
    if not isinstance(d, dict):
        raise CollectError(f"{name}: public identity is not an object")
    extra = sorted(set(d) - set(FIELDS))
    missing = sorted(set(FIELDS) - set(d))
    if extra:
        raise CollectError(f"{name}: unexpected field(s) {', '.join(extra)}; refusing (only public fields are allowed)")
    if missing:
        raise CollectError(f"{name}: missing field(s) {', '.join(missing)}")
    for k, rx in FIELDS.items():
        v = d[k]
        if not isinstance(v, str) or not rx.match(v):
            raise CollectError(f"{name}: {k} is not in its public form")
    if d["peer_id"] != f"noise_{d['noise_pubkey']}":
        raise CollectError(f"{name}: peer_id does not match noise_pubkey")
    if d["staker_address"] != d["coinbase_address"]:
        raise CollectError(f"{name}: staker and coinbase differ (consensus requires coinbase == staker)")
    return d


def load_inventory(path: Path) -> list[dict]:
    inv = json.loads(path.read_text())
    hosts = inv.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise CollectError(f"{path}: no hosts")
    names = set()
    for h in hosts:
        if not NAME_RE.match(str(h.get("name", ""))):
            raise CollectError(f"{path}: bad host name {h.get('name')!r}")
        m = IP_RE.match(str(h.get("ip", "")))
        if not m or any(int(x) > 255 for x in m.groups()):
            raise CollectError(f"{path}: {h['name']} has no IPv4 address")
        if h["name"] in names:
            raise CollectError(f"{path}: {h['name']} listed twice")
        names.add(h["name"])
    return hosts


def collect(inventory: Path, pub_dir: Path, chain_id: int, p2p_port: int) -> dict:
    hosts = load_inventory(inventory)
    producers = []
    seen: dict[str, str] = {}
    for h in hosts:
        f = pub_dir / f"{h['name']}.pub.json"
        if not f.is_file():
            raise CollectError(f"{h['name']}: no public identity at {f}")
        d = check_identity(h["name"], f.read_text())
        for k in ("noise_pubkey", "proposer_pubkey", "vrf_pubkey", "staker_address"):
            if d[k] in seen:
                raise CollectError(f"{h['name']}: {k} is the same as {seen[d[k]]}'s; every host needs its own keys")
            seen[d[k]] = h["name"]
        producers.append(
            {
                "name": h["name"],
                "region": h.get("region", ""),
                "ip": h["ip"],
                "p2p_port": p2p_port,
                "bootnode": f"{d['peer_id']}@{h['ip']}:{p2p_port}",
                **{k: d[k] for k in FIELDS if k != "schema"},
            }
        )
    return {
        "schema": SCHEMA_OUT,
        "chain_id": chain_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Public parts only. Each producer's keys were minted on its own host and never left it.",
        "producers": producers,
    }


def collect_proofs(inventory: Path, pub_dir: Path, producers: dict, registry: str) -> dict:
    import guard  # noqa: E402  (same directory; guard imports this module)
    by_name = {p["name"]: p for p in producers["producers"]}
    proofs = []
    for h in load_inventory(inventory):
        f = pub_dir / f"{h['name']}.proof.json"
        if not f.is_file():
            raise CollectError(f"{h['name']}: no registration proof at {f}")
        p = by_name[h["name"]]
        try:
            proofs.append(guard.check_proof(h["name"], f.read_text(), p["staker_address"], p["proposer_pubkey"],
                                            registry))
        except guard.GuardError as e:
            raise CollectError(str(e)) from None
    return {"schema": "r1006-registration-proofs/1", "registry": registry.lower(),
            "note": "Each producer's proposer-key signature over the registry's registration digest, made on "
                    "its own host. Public values only.",
            "proofs": proofs}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inventory", required=True, type=Path)
    ap.add_argument("--pub-dir", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--chain-id", type=int, default=40204)
    ap.add_argument("--p2p-port", type=int, default=30303)
    ap.add_argument("--bootnodes-out", type=Path,
                    help="also write the public bootnode list (noise id @ ip:port) for the cutover network profile")
    ap.add_argument("--proofs-out", type=Path, help="also write r1006-registration-proofs.json")
    ap.add_argument("--registry", help="the r1006 ValidatorRegistry the proofs must name (with --proofs-out)")
    a = ap.parse_args(argv)
    try:
        doc = collect(a.inventory, a.pub_dir, a.chain_id, a.p2p_port)
        proofs = None
        if a.proofs_out:
            if not a.registry:
                raise CollectError("--proofs-out needs --registry")
            proofs = collect_proofs(a.inventory, a.pub_dir, doc, a.registry)
    except (CollectError, OSError, json.JSONDecodeError) as e:
        print(f"collect: {e}", file=sys.stderr)
        return 2
    tmp = a.out.with_suffix(a.out.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")
    tmp.replace(a.out)
    print(f"collect: {len(doc['producers'])} producer(s) -> {a.out}")
    if a.bootnodes_out:
        b = {"schema": "r1006-public-bootnodes/1",
             "note": "The r1006 producers as bootnodes, for the network profile at cutover. Before cutover "
                     "they are only each other's bootnodes; boot1-3 do discovery only and rpc-1 joins at cutover.",
             "bootstrap_nodes": [p["bootnode"] for p in doc["producers"]]}
        t2 = a.bootnodes_out.with_suffix(a.bootnodes_out.suffix + ".tmp")
        t2.write_text(json.dumps(b, indent=2) + "\n")
        t2.replace(a.bootnodes_out)
        print(f"collect: public bootnode list -> {a.bootnodes_out}")
    if proofs is not None:
        t3 = a.proofs_out.with_suffix(a.proofs_out.suffix + ".tmp")
        t3.write_text(json.dumps(proofs, indent=2) + "\n")
        t3.replace(a.proofs_out)
        print(f"collect: {len(proofs['proofs'])} registration proof(s) -> {a.proofs_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
