#!/usr/bin/env python3
"""Merge the HUP registry redeploy into contracts/addresses/40204.json.

Run by the chain operator AFTER `forge script script/DeployHupRegistries.s.sol
--broadcast` has landed on chain 40204 (HUP-S7.1, federation F-4). It never signs,
sends or deploys anything: it reads the forge broadcast file, re-derives every
address from what was actually sent, checks it on the chain, and only then
rewrites the book. citrate-core's scripts/sync-addresses.py then generates the
app's embedded copy from this book.

What it checks, all before anything is written (fail closed):
  * each CREATE2 transaction in the broadcast went to the Arachnid factory, its
    salt is Salts.salt(<book name>) for one of the HUP names, and the address
    keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))[12:] equals the
    address forge recorded;
  * every HUP name resolves to exactly one address (from the broadcast, or, for a
    registry the idempotent rerun skipped, from the book with --keep-existing);
  * no two book names share an address;
  * with --rpc: chain id 40204, block-0 hash == --genesis, every receipt status 1,
    code at every address, owner() of the admin-gated registries == --admin (which
    must itself have code), and AgentSBT.orgContract() == OrganizationSBT.

Usage (the runbook has the full sequence):
  scripts/ops/hup-book-update.py \\
      --broadcast contracts/broadcast/DeployHupRegistries.s.sol/40204/run-latest.json \\
      --book contracts/addresses/40204.json \\
      --admin 0x<multisig> --genesis 0x<block-0 hash> --rpc https://rpc.citrate.ai
  add --check to verify only (no write).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

CHAIN_ID = 40204
ARACHNID_FACTORY = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
SALT_VERSION = "citrate.v1."  # contracts/script/Salts.sol VERSION

# Book name -> forge contract name. The salt (Salts.salt(book name)) is what ties a
# broadcast transaction to a book name; the contract name is a cross-check.
HUP_NAMES = {
    "OrganizationSBT": "OrganizationSBT",
    "AgentSBT": "AgentSBT",
    "CapsuleRegistry": "CapsuleRegistry",
    "AnchorRegistry": "AnchorRegistry",
    "BenchmarkRegistry": "BenchmarkRegistry",
    "SkillRegistry": "SkillRegistry",
}
# Deployed by the script only when it had to create the admin timelock itself.
OPTIONAL_NAMES = {"CitAgentTimelock": "MultisigTimelock2of3"}
OWNED = ("OrganizationSBT", "AgentSBT", "CapsuleRegistry")

ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")



class BookError(Exception):
    """A check failed; nothing was written."""


# ── keccak256 (Keccak-f[1600], original padding 0x01), stdlib only ──────────────

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _keccak_f(a: list) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


def to_checksum(addr: str) -> str:
    """EIP-55 checksum of a 0x address."""
    if not ADDR.match(addr):
        raise BookError(f"not an address: {addr!r}")
    low = addr[2:].lower()
    h = keccak256(low.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(low))


def salt_for(name: str) -> str:
    return "0x" + keccak256((SALT_VERSION + name).encode()).hex()


def create2_address(factory: str, salt_hex: str, init_code: bytes) -> str:
    raw = b"\xff" + bytes.fromhex(factory[2:]) + bytes.fromhex(salt_hex[2:]) + keccak256(init_code)
    return "0x" + keccak256(raw)[12:].hex()


def _selector(sig: str) -> str:
    return "0x" + keccak256(sig.encode())[:4].hex()


SEL_OWNER = _selector("owner()")  # 0x8da5cb5b
SEL_ORG_CONTRACT = _selector("orgContract()")


# ── broadcast parsing ────────────────────────────────────────────────────────────

def _hexbytes(s: str) -> bytes:
    s = s[2:] if s.startswith("0x") else s
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise BookError(f"bad hex in broadcast: {e}") from e


def parse_broadcast(run: dict) -> dict:
    """Return {book name: {"address", "tx", "contract"}} for every HUP CREATE2 tx."""
    salts = {salt_for(n): n for n in list(HUP_NAMES) + list(OPTIONAL_NAMES)}
    expected_contract = {**HUP_NAMES, **OPTIONAL_NAMES}
    receipts = {}
    for r in run.get("receipts") or []:
        th = (r.get("transactionHash") or "").lower()
        if th:
            receipts[th] = r
    found: dict = {}
    for t in run.get("transactions") or []:
        if t.get("transactionType") != "CREATE2":
            continue
        tx = t.get("transaction") or {}
        to = (tx.get("to") or "").lower()
        if to != ARACHNID_FACTORY:
            raise BookError(f"CREATE2 tx {t.get('hash')} did not go to the Arachnid factory (to={to})")
        data = _hexbytes(tx.get("input") or tx.get("data") or "0x")
        if len(data) < 33:
            raise BookError(f"CREATE2 tx {t.get('hash')} input is too short")
        salt = "0x" + data[:32].hex()
        name = salts.get(salt)
        if name is None:
            continue  # not one of ours (the script only sends ours; tolerate extras)
        contract = t.get("contractName")
        if contract != expected_contract[name]:
            raise BookError(f"salt for {name} carried contract {contract!r}, expected {expected_contract[name]!r}")
        derived = create2_address(ARACHNID_FACTORY, salt, data[32:])
        recorded = (t.get("contractAddress") or "").lower()
        if derived != recorded:
            raise BookError(f"{name}: forge recorded {recorded} but the sent init code derives {derived}")
        th = (t.get("hash") or "").lower()
        rc = receipts.get(th)
        if rc is not None and str(rc.get("status")) not in ("0x1", "1", "True", "true"):
            raise BookError(f"{name}: receipt status {rc.get('status')} for tx {th}")
        if name in found:
            raise BookError(f"{name} deployed twice in one broadcast")
        found[name] = {"address": derived, "tx": th, "contract": contract}
    return found


# ── RPC ──────────────────────────────────────────────────────────────────────────

def rpc(url: str, method: str, params: list):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.load(r)
    if "error" in body:
        raise BookError(f"{method} failed: {body['error']}")
    return body.get("result")


def _word_address(word: str) -> str:
    if not isinstance(word, str) or len(word) < 66:
        raise BookError(f"call returned no address word: {word!r}")
    return "0x" + word[-40:].lower()


def verify_live(url: str, genesis: str, admin: str, pins: dict, txs: dict) -> None:
    cid = int(rpc(url, "eth_chainId", []), 16)
    if cid != CHAIN_ID:
        raise BookError(f"{url} is chain {cid}, not {CHAIN_ID}")
    g = ((rpc(url, "eth_getBlockByNumber", ["0x0", False]) or {}).get("hash") or "").lower()
    if g != genesis.lower():
        raise BookError(f"{url} genesis {g} != --genesis {genesis}: wrong chain or stale book")
    for name, th in txs.items():
        rc = rpc(url, "eth_getTransactionReceipt", [th])
        if not rc or str(rc.get("status")) != "0x1":
            raise BookError(f"{name}: tx {th} has no successful receipt on {url}")
    for name, addr in pins.items():
        if rpc(url, "eth_getCode", [addr, "latest"]) in (None, "0x", "0x0"):
            raise BookError(f"no code on chain at {name} {addr}")
    if rpc(url, "eth_getCode", [admin, "latest"]) in (None, "0x", "0x0"):
        raise BookError(f"--admin {admin} has no code: the admin must be a deployed multisig")
    for name in OWNED:
        got = _word_address(rpc(url, "eth_call", [{"to": pins[name], "data": SEL_OWNER}, "latest"]))
        if got != admin.lower():
            raise BookError(f"{name}.owner() is {got}, not --admin {admin}")
    org = _word_address(rpc(url, "eth_call", [{"to": pins["AgentSBT"], "data": SEL_ORG_CONTRACT}, "latest"]))
    if org != pins["OrganizationSBT"].lower():
        raise BookError(f"AgentSBT.orgContract() is {org}, not OrganizationSBT {pins['OrganizationSBT']}")


# ── merge ────────────────────────────────────────────────────────────────────────

def resolve_pins(book: dict, found: dict, keep_existing: bool) -> dict:
    pins = {}
    contracts = book.get("contracts") or {}
    for name in HUP_NAMES:
        if name in found:
            pins[name] = found[name]["address"]
        elif keep_existing and isinstance(contracts.get(name), str) and ADDR.match(contracts[name]):
            pins[name] = contracts[name].lower()
        else:
            raise BookError(
                f"{name} is not in the broadcast"
                + ("" if keep_existing else " (pass --keep-existing if the rerun skipped it as already deployed)")
            )
    if "CitAgentTimelock" in found:
        pins["CitAgentTimelock"] = found["CitAgentTimelock"]["address"]
    return pins


def merged_book(book: dict, pins: dict) -> dict:
    if int(book.get("chainId", 0)) != CHAIN_ID:
        raise BookError(f"book chainId {book.get('chainId')} != {CHAIN_ID}")
    out = json.loads(json.dumps(book))  # deep copy, key order kept
    contracts = out.setdefault("contracts", {})
    for name, addr in pins.items():
        contracts[name] = to_checksum(addr)
    seen: dict = {}
    for section in ("contracts", "aaStack", "genesis"):
        for name, addr in (out.get(section) or {}).items():
            if isinstance(addr, str) and ADDR.match(addr):
                low = addr.lower()
                if low in seen and seen[low] != name:
                    raise BookError(f"{name} and {seen[low]} share address {addr}")
                seen[low] = name
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--broadcast", required=True, help="forge broadcast run-latest.json of DeployHupRegistries")
    ap.add_argument("--book", required=True, help="contracts/addresses/40204.json")
    ap.add_argument("--admin", required=True, help="the multisig that owns the admin-gated registries")
    ap.add_argument("--rpc", help="RPC of the chain the broadcast landed on (verifies before writing)")
    ap.add_argument("--genesis", help="block-0 hash of that chain (required with --rpc)")
    ap.add_argument("--keep-existing", action="store_true",
                    help="accept a book entry for a registry the idempotent rerun skipped")
    ap.add_argument("--check", action="store_true", help="verify only; do not write")
    a = ap.parse_args(argv)
    try:
        if not ADDR.match(a.admin):
            raise BookError(f"--admin must be a 0x address, got {a.admin!r}")
        if a.rpc and not (a.genesis and HASH.match(a.genesis)):
            raise BookError("--genesis 0x<64 hex> is required with --rpc")
        run = json.loads(Path(a.broadcast).read_text())
        chain = run.get("chain")
        if chain is not None and int(chain) != CHAIN_ID:
            raise BookError(f"broadcast is for chain {chain}, not {CHAIN_ID}")
        book = json.loads(Path(a.book).read_text())
        found = parse_broadcast(run)
        pins = resolve_pins(book, found, a.keep_existing)
        out = merged_book(book, pins)
        if a.rpc:
            verify_live(a.rpc, a.genesis, a.admin, pins, {n: f["tx"] for n, f in found.items() if f["tx"]})
        else:
            print("hup-book-update: WARNING: no --rpc, on-chain checks skipped", file=sys.stderr)
        changes = [
            (n, (book.get("contracts") or {}).get(n), out["contracts"][n])
            for n in pins
            if (book.get("contracts") or {}).get(n) != out["contracts"][n]
        ]
        for n, old, new in changes:
            print(f"  {n}: {old or '(absent)'} -> {new}")
        if a.check:
            print(f"hup-book-update: OK ({len(pins)} pins, {len(changes)} would change)")
            return 0
        Path(a.book).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
        print(f"hup-book-update: wrote {a.book} ({len(changes)} changed)")
        print("next: citrate-core scripts/sync-addresses.py --book <this book> --genesis <hash> --rpc <rpc>")
        return 0
    except (BookError, OSError, ValueError, KeyError) as e:
        print(f"hup-book-update: ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
