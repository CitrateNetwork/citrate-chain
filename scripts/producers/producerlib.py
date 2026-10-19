"""Shared helpers for the producer operator tools (scripts/producers/).

Standard library only, so an operator host needs nothing beyond python3 (3.10+).

Data sources (Rule 7):
  - Network profiles: scripts/producers/profiles/<name>.json (this repo).
  - Chain reads: JSON-RPC against the profile's public RPC (eth_chainId,
    eth_getBlockByNumber, eth_call on ValidatorRegistry, eth_getBalance,
    eth_getTransactionCount). Read-only: nothing here signs or sends a transaction.
  - ValidatorRegistry selectors and geometry: contracts/src/ValidatorRegistry.sol.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROFILE_DIR = HERE / "profiles"

# ValidatorRegistry geometry (contracts/src/ValidatorRegistry.sol). The node uses the
# identical math (node/src/registry_sync.rs, core/consensus/src/vrf.rs).
EPOCH = 1000
SNAPSHOT_LAG = 200
MAX_ACTIVE_SET = 100
STATUS_NAMES = {0: "None", 1: "Active", 2: "Exiting", 3: "Slashed"}

# 4-byte selectors, keccak256(signature)[:4]. Pinned here because python's stdlib has no
# keccak; tests/test_producerlib.py recomputes every one with a reference keccak.
SELECTORS = {
    "registerValidator(bytes32,bytes)": "10f53ba1",
    "registrationNonce(address)": "7c360a1d",
    "validatorInfo(bytes32)": "00408838",
    "isActive(bytes32)": "5c36901c",
    "currentEpoch()": "76671808",
    "activeSet()": "fd4665ae",
    "minStake()": "375b3c0a",
    "activeCount()": "4331ed1f",
    "pubkeyOfStaker(address)": "e7be529e",
    "pubkeyEverRegistered(bytes32)": "6d25f9d4",
    "stakeOf(bytes32)": "07177c9c",
}

# ValidatorRegistry events that change neither a bonded stake, the active set nor minStake
# (topic0 = keccak256(signature), pinned and re-checked like SELECTORS). Every OTHER registry
# log (registration, stake change, unbond, eviction, slash, demotion, ParamExecuted, or any
# event this list does not know) counts as a change to the committee inputs.
REGISTRY_EVENTS_NO_STAKE_EFFECT = {
    "RewardCredited(bytes32,uint256,uint256)": "e8f08f8e2d5a793bc43cf83eece124128850204c74c6c9406db3ef2c0ac59862",
    "RewardsClaimed(bytes32,address,uint256)": "fec539b3c42d74cd492c3ecf7966bf014b327beef98e935cdc3ec5e54a6901c7",
    "BountyClaimed(address,uint256)": "ac56e31790f51d5ee1fd63f4e99bd0bb5363ff7e23dd9005bdfb0bb52da5a4a6",
    "ParamQueued(bytes32,uint256,uint256)": "da63fef2ee390b6d1933db896ed0e564a4705c828df03b0d9e1523da5018c9b6",
    "SlasherQueued(address,uint256)": "ec5446b54b1b9913e906d8238b2369acee39b4dedc20d0834d2539ff5b6fd978",
    "SlasherSet(address)": "93984378289228ac490c326f8dbcc3f9b2c703753c272e7c572949e115da985e",
}
# The node's eth_getLogs serves at most 1000 blocks per call (core/api/src/eth_rpc.rs) and
# silently truncates a longer range, so ranges are read in chunks no larger than this.
LOGS_CHUNK = 500

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
B32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
QTY_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")

WEI_PER_SALT = 10**18


class ToolError(Exception):
    """A check or input failed; the message is written for the operator."""


class RpcError(ToolError):
    """The RPC call failed or returned something malformed. Never read as zero."""


# ─────────────────────────────────────────────────────────────────────────────
# Profiles
# ─────────────────────────────────────────────────────────────────────────────

PROFILE_REQUIRED = (
    "name",
    "status",
    "chain_id",
    "genesis_hash",
    "public_rpc",
    "block_time",
    "ghostdag_k",
    "bootstrap_nodes",
    "validator_registry",
    "validator_activation_height",
    "env",
    "checkpoint",
)


@dataclass(frozen=True)
class Profile:
    raw: dict[str, Any]

    def __getitem__(self, k: str) -> Any:
        return self.raw[k]

    @property
    def name(self) -> str:
        return str(self.raw["name"])


def load_profile(name_or_path: str, *, allow_pending: bool = False) -> Profile:
    """Load a network profile by name (profiles/<name>.json) or path.

    A profile whose status is not "ready" is refused unless allow_pending (dry runs),
    because its genesis or registry is not fixed yet and a node configured from it
    would join the wrong chain or none.
    """
    p = Path(name_or_path)
    if not p.suffix:
        p = PROFILE_DIR / f"{name_or_path}.json"
    if not p.is_file():
        known = sorted(x.stem for x in PROFILE_DIR.glob("*.json"))
        raise ToolError(f"profile {name_or_path!r} not found (known: {', '.join(known)})")
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise ToolError(f"profile {p} is not valid JSON: {e}") from e
    missing = [k for k in PROFILE_REQUIRED if k not in raw]
    if missing:
        raise ToolError(f"profile {p} is missing {', '.join(missing)}")
    prof = Profile(raw)
    problems = profile_problems(prof)
    if raw["status"] != "ready" or problems:
        if not allow_pending:
            why = "; ".join(problems) if problems else f"status is {raw['status']!r}"
            raise ToolError(
                f"profile {prof.name} is not ready ({why}). Its values are set by the chain "
                f"team when that network's genesis is cut; use --dry-run to preview."
            )
    return prof


def profile_problems(prof: Profile) -> list[str]:
    r = prof.raw
    out = []
    if not isinstance(r["chain_id"], int) or r["chain_id"] <= 0:
        out.append("chain_id unset")
    if not B32_RE.match(str(r["genesis_hash"])):
        out.append("genesis_hash unset")
    if not ADDR_RE.match(str(r["validator_registry"])):
        out.append("validator_registry unset")
    if not isinstance(r["validator_activation_height"], int) or r["validator_activation_height"] < (
        EPOCH - SNAPSHOT_LAG
    ):
        out.append("validator_activation_height unset or below S(1)=800")
    if not str(r["public_rpc"]).startswith(("https://", "http://")):
        out.append("public_rpc unset")
    if not r["bootstrap_nodes"]:
        out.append("bootstrap_nodes empty")
    for b in r["bootstrap_nodes"]:
        if not re.match(r"^noise_[0-9a-f]{64}@[A-Za-z0-9.\-]+:\d+$", str(b)):
            out.append(f"bootstrap node {b!r} is not in trusted form noise_<hex>@host:port")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Encoding
# ─────────────────────────────────────────────────────────────────────────────


def norm_addr(a: str) -> str:
    a = a.strip()
    if not a.startswith("0x"):
        a = "0x" + a
    if not ADDR_RE.match(a):
        raise ToolError(f"{a!r} is not a 20-byte 0x address")
    if int(a, 16) == 0:
        raise ToolError("the zero address is not allowed")
    return a.lower()


def norm_b32(b: str) -> str:
    b = b.strip()
    if not b.startswith("0x"):
        b = "0x" + b
    if not B32_RE.match(b):
        raise ToolError(f"{b!r} is not a 32-byte 0x value")
    return b.lower()


def calldata(sig: str, *words: str) -> str:
    """Selector + static 32-byte words (addresses left-padded, bytes32 as-is)."""
    out = "0x" + SELECTORS[sig]
    for w in words:
        h = w[2:] if w.startswith("0x") else w
        out += h.rjust(64, "0")
    return out


def qty(n: int) -> str:
    if n < 0:
        raise ToolError("negative quantity")
    return hex(n)


def parse_qty(v: Any, what: str) -> int:
    if not isinstance(v, str) or not QTY_RE.match(v):
        raise RpcError(f"{what}: expected a hex quantity, got {v!r}")
    return int(v, 16)


def words(ret: Any, what: str) -> list[int]:
    if not isinstance(ret, str) or not ret.startswith("0x"):
        raise RpcError(f"{what}: eth_call returned {ret!r}")
    body = ret[2:]
    if len(body) == 0 or len(body) % 64 != 0:
        raise RpcError(f"{what}: return is {len(body) // 2} bytes, not whole words")
    return [int(body[i : i + 64], 16) for i in range(0, len(body), 64)]


def decode_validator_info(ret: str) -> dict[str, Any]:
    w = words(ret, "validatorInfo")
    if len(w) != 10:
        raise RpcError(f"validatorInfo: expected 10 words, got {len(w)}")
    status = w[8]
    if status not in STATUS_NAMES:
        raise RpcError(f"validatorInfo: unknown status {status}")
    return {
        "staker": "0x" + f"{w[0]:064x}"[24:],
        "bonded": w[1],
        "rewards": w[2],
        "escrow": w[3],
        "admission_min": w[4],
        "act_epoch": w[5],
        "exit_epoch": w[6],
        "escrow_unlock": w[7],
        "status": STATUS_NAMES[status],
        "claimable_now": w[9],
    }


def decode_active_set(ret: str) -> list[tuple[str, int]]:
    """Decode `activeSet() returns (bytes32[] pubkeys, uint256[] effStakes)`."""
    w = words(ret, "activeSet")
    if len(w) < 4:
        raise RpcError("activeSet: return too short")
    off_a, off_b = w[0], w[1]
    if off_a % 32 or off_b % 32:
        raise RpcError("activeSet: misaligned offsets")
    ia, ib = off_a // 32, off_b // 32
    if ia >= len(w) or ib >= len(w):
        raise RpcError("activeSet: offset out of range")
    n, m = w[ia], w[ib]
    if n != m:
        raise RpcError(f"activeSet: {n} keys but {m} stakes")
    if n > MAX_ACTIVE_SET:
        raise RpcError(f"activeSet: {n} entries exceeds MAX_ACTIVE_SET")
    if ia + n >= len(w) or ib + m >= len(w):
        raise RpcError("activeSet: array truncated")
    keys = ["0x" + f"{w[ia + 1 + i]:064x}" for i in range(n)]
    stakes = [w[ib + 1 + i] for i in range(m)]
    return list(zip(keys, stakes))


def bool_word(ret: str, what: str) -> bool:
    w = words(ret, what)
    if len(w) != 1 or w[0] not in (0, 1):
        raise RpcError(f"{what}: not a bool")
    return w[0] == 1


def uint_word(ret: str, what: str) -> int:
    w = words(ret, what)
    if len(w) != 1:
        raise RpcError(f"{what}: expected one word")
    return w[0]


# ─────────────────────────────────────────────────────────────────────────────
# Epoch math (contracts/src/ValidatorRegistry.sol; core/consensus/src/vrf.rs)
# ─────────────────────────────────────────────────────────────────────────────


def epoch_of(height: int) -> int:
    return height // EPOCH


def snapshot_height(e: int) -> int:
    return e * EPOCH - SNAPSHOT_LAG


def governing_snapshot_epoch(height: int) -> int | None:
    """E such that S(E) is the snapshot whose set governs a block at `height`:
    the greatest S(E) (E >= 1) strictly below height (vrf.rs governing_snapshot)."""
    if height < 1:
        return None
    e = (height - 1 + SNAPSHOT_LAG) // EPOCH
    return e if e >= 1 else None


# ─────────────────────────────────────────────────────────────────────────────
# JSON-RPC
# ─────────────────────────────────────────────────────────────────────────────


class Rpc:
    """Minimal JSON-RPC client. Every failure raises RpcError; nothing defaults to 0."""

    def __init__(self, url: str, timeout: float = 15.0):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def _post(self, payload: Any) -> Any:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url, data=data, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RpcError(f"RPC {self.url} unreachable: {e}") from e
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise RpcError(f"RPC {self.url} returned non-JSON") from e

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        out = self._post({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        if not isinstance(out, dict) or "result" not in out:
            err = out.get("error") if isinstance(out, dict) else out
            raise RpcError(f"{method} failed: {err}")
        return out["result"]

    def batch(self, calls: list[tuple[str, list[Any]]]) -> list[Any]:
        payload = []
        for i, (m, p) in enumerate(calls):
            payload.append({"jsonrpc": "2.0", "id": i, "method": m, "params": p})
        out = self._post(payload)
        if not isinstance(out, list):
            raise RpcError("batch: response is not a list")
        by_id = {}
        for r in out:
            if isinstance(r, dict) and "result" in r and isinstance(r.get("id"), int):
                by_id[r["id"]] = r["result"]
        missing = [i for i in range(len(calls)) if i not in by_id]
        if missing:
            raise RpcError(f"batch: {len(missing)} of {len(calls)} calls failed")
        return [by_id[i] for i in range(len(calls))]

    def eth_call(self, to: str, data: str) -> str:
        return self.call("eth_call", [{"to": to, "data": data}, "latest"])


def check_network(rpc: Rpc, prof: Profile) -> dict[str, Any]:
    """Chain id AND genesis hash must both match: three profiles share 40204
    (UI truth contract §6)."""
    cid = parse_qty(rpc.call("eth_chainId", []), "eth_chainId")
    if cid != prof["chain_id"]:
        raise ToolError(f"RPC chain id {cid} != profile chain id {prof['chain_id']}")
    g = rpc.call("eth_getBlockByNumber", ["0x0", False])
    gh = g.get("hash") if isinstance(g, dict) else None
    if not isinstance(gh, str) or gh.lower() != str(prof["genesis_hash"]).lower():
        raise ToolError(f"RPC genesis {gh} != profile genesis {prof['genesis_hash']}")
    head = parse_qty(rpc.call("eth_blockNumber", []), "eth_blockNumber")
    return {"chain_id": cid, "genesis_hash": gh, "head": head}


def salt_to_wei(amount: str) -> int:
    """Exact decimal SALT -> wei (no float rounding)."""
    from decimal import Decimal, InvalidOperation

    try:
        d = Decimal(str(amount).replace(",", ""))
    except InvalidOperation as e:
        raise ToolError(f"{amount!r} is not a SALT amount") from e
    wei = d * WEI_PER_SALT
    if d <= 0 or wei != wei.to_integral_value():
        raise ToolError(f"{amount!r} is not a positive SALT amount with at most 18 decimals")
    return int(wei)


def salt(wei: int) -> str:
    whole, frac = divmod(wei, WEI_PER_SALT)
    if frac == 0:
        return f"{whole:,} SALT"
    return f"{whole:,}.{str(frac).rjust(18, '0').rstrip('0')} SALT"
