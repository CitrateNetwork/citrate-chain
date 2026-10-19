"""Test-only JSON-RPC stand-in for a 40204 node, so the producer tools can be tested
without a network. It is never imported by the tools themselves.

FakeChain holds a tiny ValidatorRegistry state and a block list; RpcStub serves it over
HTTP on 127.0.0.1 (single and batch requests).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SEL = {
    "10f53ba1": "registerValidator",
    "7c360a1d": "registrationNonce",
    "00408838": "validatorInfo",
    "5c36901c": "isActive",
    "76671808": "currentEpoch",
    "fd4665ae": "activeSet",
    "375b3c0a": "minStake",
    "4331ed1f": "activeCount",
    "e7be529e": "pubkeyOfStaker",
    "6d25f9d4": "pubkeyEverRegistered",
    "07177c9c": "stakeOf",
}
STATUS = {"None": 0, "Active": 1, "Exiting": 2, "Slashed": 3}
GENESIS = "0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"
REGISTRY = "0xde4f679632be7810d915f637cc6a72bf076a3bd9"


def w(n: int) -> str:
    return f"{n:064x}"


class FakeChain:
    def __init__(self) -> None:
        self.chain_id = 40204
        self.genesis = GENESIS
        self.head = 512_694
        self.min_stake = 32_000 * 10**18
        self.validators: dict[str, dict[str, Any]] = {}
        self.nonces: dict[str, int] = {}
        self.balances: dict[str, int] = {}
        self.tx_counts: dict[str, int] = {}
        self.producers: dict[int, tuple[str, str]] = {}  # height -> (pubkey, miner)
        self.default_producer = ("0x" + "3f" * 32, "0x" + "aa" * 20)
        self.finalized = 0
        self.fail_methods: set[str] = set()
        self.registry_code = "0x6080"
        self.logs: list[dict[str, Any]] = []  # {"block": int, "topic0": hex64}
        self.log_queries: list[tuple[int, int]] = []

    def add_validator(self, pubkey: str, staker: str, stake: int, act_epoch: int, status: str = "Active") -> None:
        self.validators[pubkey.lower()] = {
            "staker": staker.lower(),
            "stake": stake,
            "act_epoch": act_epoch,
            "status": status,
        }

    @property
    def epoch(self) -> int:
        return self.head // 1000

    def active(self) -> list[tuple[str, dict[str, Any]]]:
        return sorted((k, v) for k, v in self.validators.items() if v["status"] == "Active")

    def call(self, to: str, data: str) -> str:
        if to.lower() != REGISTRY:
            return "0x"
        sel, args = data[2:10], data[10:]
        name = SEL.get(sel)
        arg0 = args[:64]
        if name == "registrationNonce":
            return "0x" + w(self.nonces.get("0x" + arg0[24:], 0))
        if name == "pubkeyOfStaker":
            staker = "0x" + arg0[24:]
            for k, v in self.validators.items():
                if v["staker"] == staker and v["status"] == "Active":
                    return "0x" + k[2:]
            return "0x" + w(0)
        if name == "validatorInfo":
            v = self.validators.get("0x" + arg0)
            if v is None:
                return "0x" + w(0) * 10
            return "0x" + "".join(
                [
                    w(int(v["staker"], 16)),
                    w(v["stake"]),
                    w(0),
                    w(0),
                    w(self.min_stake),
                    w(v["act_epoch"]),
                    w(0),
                    w(0),
                    w(STATUS[v["status"]]),
                    w(0),
                ]
            )
        if name == "isActive":
            v = self.validators.get("0x" + arg0)
            return "0x" + w(1 if v and v["status"] == "Active" else 0)
        if name == "pubkeyEverRegistered":
            return "0x" + w(1 if ("0x" + arg0) in self.validators else 0)
        if name == "currentEpoch":
            return "0x" + w(self.epoch)
        if name == "minStake":
            return "0x" + w(self.min_stake)
        if name == "activeCount":
            return "0x" + w(len(self.active()))
        if name == "activeSet":
            act = self.active()
            n = len(act)
            off_b = 64 + 32 * (n + 1)
            body = w(64) + w(off_b) + w(n) + "".join(k[2:] for k, _ in act) + w(n)
            body += "".join(w(v["stake"]) for _, v in act)
            return "0x" + body
        return "0x"

    def block(self, h: int) -> dict[str, Any] | None:
        if h > self.head:
            return None
        if h == 0:
            return {"number": "0x0", "hash": self.genesis, "proposerPubkey": "0x" + "00" * 32, "miner": "0x" + "00" * 20}
        pk, miner = self.producers.get(h, self.default_producer)
        return {"number": hex(h), "hash": "0x" + f"{h:064x}", "proposerPubkey": pk, "miner": miner}

    def handle(self, method: str, params: list[Any]) -> Any:
        if method in self.fail_methods:
            raise ValueError(f"{method} disabled")
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            tag = params[0]
            if tag == "finalized":
                return self.block(self.finalized)
            if tag == "latest":
                return self.block(self.head)
            return self.block(int(tag, 16))
        if method == "eth_call":
            return self.call(params[0]["to"], params[0]["data"])
        if method == "eth_getCode":
            return self.registry_code if params[0].lower() == REGISTRY else "0x"
        if method == "eth_getLogs":
            f = params[0]
            lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            self.log_queries.append((lo, hi))
            hi = min(hi, lo + 1000)  # the node's per-call cap
            if str(f.get("address", "")).lower() != REGISTRY:
                return []
            return [
                {"address": REGISTRY, "blockNumber": hex(lg["block"]), "topics": ["0x" + lg["topic0"]]}
                for lg in self.logs
                if lo <= lg["block"] <= hi
            ]
        if method == "eth_getBalance":
            return hex(self.balances.get(params[0].lower(), 0))
        if method == "eth_getTransactionCount":
            return hex(self.tx_counts.get(params[0].lower(), 0))
        raise ValueError(f"unsupported {method}")


class RpcStub:
    def __init__(self, chain: FakeChain) -> None:
        self.chain = chain
        self.requests: list[str] = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:  # quiet
                pass

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                reqs = body if isinstance(body, list) else [body]
                out = []
                for r in reqs:
                    stub.requests.append(r["method"])
                    try:
                        out.append({"jsonrpc": "2.0", "id": r["id"], "result": stub.chain.handle(r["method"], r["params"])})
                    except ValueError as e:
                        out.append({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32000, "message": str(e)}})
                data = json.dumps(out if isinstance(body, list) else out[0]).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "RpcStub":
        self.thread.start()
        return self

    def __exit__(self, *a: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
