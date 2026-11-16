#!/usr/bin/env python3
"""emit_r1007_books.py: the r1007 genesis book and post-genesis book, from the on-chain probe.

r1007 (block 0 at 2026-11-12T14:00:00Z) rebuilt r1006's block-0 state with new keys for every
non-producer role. The block-0 contracts are CREATE2 deployments whose addresses the rotation did
not move, so the r1007 genesis book is the r1006 genesis book (contracts/addresses/r1006/40204.json)
with the r1007 genesis deployer and date. The post-genesis contracts were deployed after block 0 by
the fresh r1007 POSTGENESIS_DEPLOYER at nonces 0-28, in r1006's script order.

Both books are built from contracts/addresses/r1007/40204.provenance.json, a read-only probe of the
live chain (block-0 hash, eth_getCode per address, the deployer's nonce). This script refuses to
write a book that names an address the probe did not find code at:

  * every contracts / aaStack / genesis entry of the r1006 genesis book must be in the probe's
    blockZero at the same address, with a codehash;
  * every post-genesis entry must be the probe's nonce-k address with a codehash, and nonce k must be
    `cast compute-address --nonce k <deployer>` (checked here with RLP + keccak);
  * the accounts (bundler, faucet) must be in the probe with no code.

Nonce 4 (an AgentDecisionRegistryV2 duplicate) stays out of the post-genesis book, as on r1006: the
genesis book already defines AgentDecisionRegistryV2, and the root book refuses a name defined twice.

  emit_r1007_books.py           write contracts/addresses/r1007/40204.json and 40204.postgenesis.json
  emit_r1007_books.py --check   exit 1 if either committed book differs from what this would write

Deterministic: no clock, no network; two-space JSON with a trailing LF.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
R1006_GENESIS_BOOK = "contracts/addresses/r1006/40204.json"
PROVENANCE = "contracts/addresses/r1007/40204.provenance.json"
OUT_GENESIS = "contracts/addresses/r1007/40204.json"
OUT_POST = "contracts/addresses/r1007/40204.postgenesis.json"
REGENERATOR = "scripts/addresses/emit_r1007_books.py"
CHAIN_ID = 40204
EXCLUDED_NONCES = {4: "AgentDecisionRegistryV2"}
POSTGENESIS_DEPLOYED_AT = "2026-11-12T00:00:00Z"
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH32 = re.compile(r"^0x[0-9a-f]{64}$")
GENESIS_SECTIONS = ("contracts", "aaStack", "genesis")


class BookError(Exception):
    pass


# --- keccak-256 (the Ethereum variant, pad 0x01), so the nonce check needs no dependency ---
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        blk = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        a = _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    n = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(n)]) + n + b


def create_address(deployer: str, nonce: int) -> str:
    """The CREATE address of `deployer` at `nonce`: keccak(rlp([deployer, nonce]))[12:]."""
    payload = _rlp_bytes(bytes.fromhex(deployer[2:])) + _rlp_bytes(nonce.to_bytes((nonce.bit_length() + 7) // 8, "big"))
    if len(payload) > 55:
        raise BookError("rlp list too long")
    return "0x" + keccak256(bytes([0xC0 + len(payload)]) + payload)[12:].hex()


def _addr(where: str, v: object) -> str:
    if not isinstance(v, str) or not ADDR.match(v):
        raise BookError(f"{where}: not a 20-byte hex address: {v!r}")
    return v


def build(r1006: dict, prov: dict) -> tuple[dict, dict]:
    if r1006.get("chainId") != CHAIN_ID or prov.get("chainId") != CHAIN_ID:
        raise BookError(f"chain id must be {CHAIN_ID}")
    genesis_hash = prov.get("genesisHash")
    if not isinstance(genesis_hash, str) or not HASH32.match(genesis_hash):
        raise BookError(f"provenance genesisHash is not a 32-byte lowercase hash: {genesis_hash!r}")
    genesis_deployer = _addr("provenance.genesisDeployer", prov.get("genesisDeployer"))
    post_deployer = _addr("provenance.postGenesisDeployer.address", (prov.get("postGenesisDeployer") or {}).get("address"))

    probed = prov.get("blockZero") or {}
    for s in GENESIS_SECTIONS:
        for name, a in r1006.get(s, {}).items():
            e = probed.get(f"{s}.{name}")
            if not e or e.get("address", "").lower() != a.lower():
                raise BookError(f"{s}.{name} {a}: not in the r1007 probe at that address")
            if not (isinstance(e.get("codehash"), str) and HASH32.match(e["codehash"])):
                raise BookError(f"{s}.{name} {a}: the probe found no code")
    extra = sorted(set(probed) - {f"{s}.{n}" for s in GENESIS_SECTIONS for n in r1006.get(s, {})})
    if extra:
        raise BookError(f"the probe names block-0 entries the r1006 genesis book does not: {extra}")
    for p in ("CitrateMemberSBT", "MembershipStakeVault"):
        if r1006[p].lower() != r1006["contracts"][p].lower():
            raise BookError(f"top-level {p} is not contracts.{p}")

    genesis = dict(r1006)
    genesis["deployer"] = genesis_deployer
    genesis["deployedAt"] = prov["genesisTimestamp"]
    genesis["regenerator"] = REGENERATOR
    genesis["comment"] = (
        "Contract addresses present in r1007 block 0 (genesis " + genesis_hash + "). r1007 rebuilt r1006's "
        "block-0 state with new keys for every non-producer role; the contracts are CREATE2 deployments the "
        "rotation did not move, so the addresses equal the r1006 genesis book's. Every entry was checked for "
        "code on r1007 (contracts/addresses/r1007/40204.provenance.json). Generated by " + REGENERATOR
        + "; never edit by hand."
    )

    posts = prov.get("postGenesis") or []
    if [p.get("nonce") for p in posts] != list(range(29)):
        raise BookError("the probe must list post-genesis nonces 0..28 in order")
    contracts = {}
    for p in posts:
        n = p["nonce"]
        a = _addr(f"postGenesis nonce {n}", p.get("address"))
        want = create_address(post_deployer, n)
        if a.lower() != want:
            raise BookError(f"nonce {n} {p.get('name')}: {a} is not the deployer's nonce-{n} address {want}")
        if not (isinstance(p.get("codehash"), str) and HASH32.match(p["codehash"])):
            raise BookError(f"nonce {n} {p.get('name')} {a}: the probe found no code")
        if n in EXCLUDED_NONCES:
            continue
        name = p.get("name")
        if not isinstance(name, str) or not name or name in contracts:
            raise BookError(f"nonce {n}: bad or duplicate name {name!r}")
        contracts[name] = a.lower()

    accounts = {}
    for k, e in sorted((prov.get("accounts") or {}).items()):
        if e.get("code") != "0x":
            raise BookError(f"account {k} has code: it is not an EOA")
        accounts[k] = _addr(f"accounts.{k}", e.get("address"))

    post = {
        "chainId": CHAIN_ID,
        "chainName": r1006["chainName"],
        "rpcUrl": r1006["rpcUrl"],
        "explorerUrl": r1006["explorerUrl"],
        "deployer": post_deployer,
        "deployedAt": POSTGENESIS_DEPLOYED_AT,
        "comment": (
            "r1007 contracts deployed after block 0 by the r1007 POSTGENESIS_DEPLOYER, nonces 0-28 in r1006's "
            "script order (nonce 4, an AgentDecisionRegistryV2 duplicate, is left out; nonce 29 is "
            "TenantHierarchy.initRoot). Each address is the deployer's CREATE address for its nonce and has "
            "code on r1007 (contracts/addresses/r1007/40204.provenance.json). Quorum's AnchorRegistry is keyed "
            "Quorum.AnchorRegistry so it never shadows the genesis AnchorRegistry. `accounts` are operator "
            "EOAs (no code). Generated by " + REGENERATOR + "; never edit by hand."
        ),
        "genesisHash": genesis_hash,
        "contracts": dict(sorted(contracts.items())),
        "accounts": accounts,
    }
    return genesis, post


def render(root: Path = ROOT) -> dict[str, str]:
    r1006 = json.loads((root / R1006_GENESIS_BOOK).read_text())
    prov = json.loads((root / PROVENANCE).read_text())
    g, p = build(r1006, prov)
    dump = lambda d: json.dumps(d, indent=2, ensure_ascii=False) + "\n"  # noqa: E731
    return {OUT_GENESIS: dump(g), OUT_POST: dump(p)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if a committed r1007 book is stale")
    ap.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    root = Path(a.root)
    try:
        out = render(root)
    except (BookError, OSError, ValueError, KeyError) as e:
        print(f"emit_r1007_books: {e}", file=sys.stderr)
        return 1
    if a.check:
        stale = [rel for rel, text in out.items() if not (root / rel).exists() or (root / rel).read_text() != text]
        if stale:
            print(f"emit_r1007_books: stale: {', '.join(stale)}; run {REGENERATOR}", file=sys.stderr)
            return 1
        print("emit_r1007_books: the r1007 books match the probe")
        return 0
    for rel, text in out.items():
        (root / rel).write_text(text)
        print(f"emit_r1007_books: wrote {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
