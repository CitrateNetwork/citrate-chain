#!/usr/bin/env python3
"""Tests for scripts/ops/hup-book-update.py (stdlib unittest; no network).

Run: python3 -m unittest discover -s scripts/ops/tests -p 'test_hup_*.py'
"""
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("hup_book_update", HERE.parent / "hup-book-update.py")
hbu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hbu)

ADMIN = "0x" + "ad" * 20
GENESIS = "0x" + "9e" * 32
FACTORY = hbu.ARACHNID_FACTORY


def _code(tag: str) -> bytes:
    # Distinct, non-empty fake init code per contract (the tool only hashes it).
    return b"\x60\x80" + tag.encode()


def _tx(name: str, contract: str, init: bytes, nonce: int, *, address=None, to=FACTORY, status="0x1"):
    salt = hbu.salt_for(name)
    derived = hbu.create2_address(FACTORY, salt, init)
    th = "0x" + hbu.keccak256(f"tx-{name}-{nonce}".encode()).hex()
    t = {
        "hash": th,
        "transactionType": "CREATE2",
        "contractName": contract,
        "contractAddress": address or derived,
        "transaction": {"to": to, "input": salt + init.hex(), "nonce": hex(nonce)},
    }
    r = {"transactionHash": th, "status": status}
    return t, r, derived


def _broadcast(names=None, **overrides):
    names = names or list(hbu.HUP_NAMES)
    txs, rcs, addrs = [], [], {}
    for i, n in enumerate(names):
        contract = {**hbu.HUP_NAMES, **hbu.OPTIONAL_NAMES}[n]
        t, r, a = _tx(n, contract, _code(n), i, **overrides.get(n, {}))
        txs.append(t)
        rcs.append(r)
        addrs[n] = a
    return {"chain": 40204, "transactions": txs, "receipts": rcs}, addrs


def _book():
    return {
        "chainId": 40204,
        "contracts": {
            "ModelRegistry": "0x807cB7eE477Ae58C321cAEd980CEB11D78048e84",
            "AgentSBT": "0xd16b1ad6e744F3E92223C65F492c35D36ae07c7b",
        },
        "aaStack": {"EntryPoint": "0x97d5391a647429233E202f99231743C53a648f3c"},
    }


class KeccakAndChecksum(unittest.TestCase):
    def test_keccak_vectors(self):
        self.assertEqual(
            hbu.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )
        self.assertEqual(
            hbu.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )
        # Longer than one 136-byte block.
        self.assertEqual(len(hbu.keccak256(b"x" * 300)), 32)

    def test_selectors(self):
        self.assertEqual(hbu.SEL_OWNER, "0x8da5cb5b")

    def test_eip55(self):
        # EIP-55 reference vector.
        self.assertEqual(
            hbu.to_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        )
        self.assertEqual(hbu.to_checksum(FACTORY), "0x4e59b44847b379578588920cA78FbF26c0B4956C")

    def test_create2_reference(self):
        # EIP-1014 example 0: deployer 0x0, salt 0x0, init code 0x00.
        self.assertEqual(
            hbu.create2_address("0x" + "00" * 20, "0x" + "00" * 32, b"\x00"),
            "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38",
        )


class ParseBroadcast(unittest.TestCase):
    def test_all_names_found(self):
        run, addrs = _broadcast()
        found = hbu.parse_broadcast(run)
        self.assertEqual(set(found), set(hbu.HUP_NAMES))
        for n, f in found.items():
            self.assertEqual(f["address"], addrs[n])

    def test_recorded_address_must_match_init_code(self):
        run, _ = _broadcast(**{"AgentSBT": {"address": "0x" + "11" * 20}})
        with self.assertRaisesRegex(hbu.BookError, "AgentSBT: forge recorded"):
            hbu.parse_broadcast(run)

    def test_create2_must_use_the_factory(self):
        run, _ = _broadcast(**{"SkillRegistry": {"to": "0x" + "22" * 20}})
        with self.assertRaisesRegex(hbu.BookError, "Arachnid factory"):
            hbu.parse_broadcast(run)

    def test_failed_receipt_refused(self):
        run, _ = _broadcast(**{"AnchorRegistry": {"status": "0x0"}})
        with self.assertRaisesRegex(hbu.BookError, "receipt status"):
            hbu.parse_broadcast(run)

    def test_contract_name_cross_check(self):
        run, _ = _broadcast()
        run["transactions"][0]["contractName"] = "SomethingElse"
        with self.assertRaisesRegex(hbu.BookError, "carried contract"):
            hbu.parse_broadcast(run)

    def test_foreign_salts_ignored_and_plain_create_ignored(self):
        run, _ = _broadcast(names=["AgentSBT"])
        t, r, _ = _tx("ModelRegistry", "ModelRegistry", _code("m"), 9)
        run["transactions"].append(t)
        run["transactions"].append({"transactionType": "CREATE", "contractName": "AgentSBT"})
        self.assertEqual(set(hbu.parse_broadcast(run)), {"AgentSBT"})

    def test_timelock_optional(self):
        run, addrs = _broadcast(names=list(hbu.HUP_NAMES) + ["CitAgentTimelock"])
        found = hbu.parse_broadcast(run)
        self.assertEqual(found["CitAgentTimelock"]["address"], addrs["CitAgentTimelock"])


class Merge(unittest.TestCase):
    def test_missing_name_refused_without_keep_existing(self):
        run, _ = _broadcast(names=["OrganizationSBT", "CapsuleRegistry"])
        with self.assertRaisesRegex(hbu.BookError, "AgentSBT is not in the broadcast"):
            hbu.resolve_pins(_book(), hbu.parse_broadcast(run), keep_existing=False)

    def test_keep_existing_needs_a_book_entry(self):
        run, _ = _broadcast(names=["OrganizationSBT"])
        with self.assertRaisesRegex(hbu.BookError, "CapsuleRegistry is not in the broadcast"):
            hbu.resolve_pins(_book(), hbu.parse_broadcast(run), keep_existing=True)

    def test_merge_writes_checksummed_and_keeps_other_keys(self):
        run, addrs = _broadcast()
        pins = hbu.resolve_pins(_book(), hbu.parse_broadcast(run), keep_existing=False)
        out = hbu.merged_book(_book(), pins)
        self.assertEqual(out["contracts"]["ModelRegistry"], _book()["contracts"]["ModelRegistry"])
        self.assertEqual(out["contracts"]["AgentSBT"], hbu.to_checksum(addrs["AgentSBT"]))
        self.assertEqual(out["aaStack"], _book()["aaStack"])
        # Key order: existing keys keep their place, new ones are appended.
        self.assertEqual(list(out["contracts"])[:2], ["ModelRegistry", "AgentSBT"])

    def test_shared_address_refused(self):
        run, addrs = _broadcast()
        book = _book()
        book["contracts"]["ModelRegistry"] = hbu.to_checksum(addrs["SkillRegistry"])
        pins = hbu.resolve_pins(book, hbu.parse_broadcast(run), keep_existing=False)
        with self.assertRaisesRegex(hbu.BookError, "share address"):
            hbu.merged_book(book, pins)

    def test_wrong_chain_book_refused(self):
        run, _ = _broadcast()
        book = _book()
        book["chainId"] = 1
        pins = hbu.resolve_pins(book, hbu.parse_broadcast(run), keep_existing=False)
        with self.assertRaisesRegex(hbu.BookError, "chainId"):
            hbu.merged_book(book, pins)


class _FakeChain(BaseHTTPRequestHandler):
    """Minimal JSON-RPC stand-in. `state` is set per test."""

    state: dict = {}

    def log_message(self, *args):  # keep test output quiet
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["content-length"])))
        m, p = req["method"], req["params"]
        s = self.state
        if m == "eth_chainId":
            res = hex(s["chain"])
        elif m == "eth_getBlockByNumber":
            res = {"hash": s["genesis"]}
        elif m == "eth_getTransactionReceipt":
            res = {"status": s["receipt_status"]}
        elif m == "eth_getCode":
            res = "0x" if p[0].lower() in s["no_code"] else "0x6080"
        elif m == "eth_call":
            to, data = p[0]["to"].lower(), p[0]["data"]
            if data == hbu.SEL_OWNER:
                res = "0x" + "00" * 12 + s["owners"].get(to, ADMIN)[2:]
            else:
                res = "0x" + "00" * 12 + s["org"][2:]
        else:
            res = None
        body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class VerifyLiveAndCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _FakeChain)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.run_json, self.addrs = _broadcast()
        _FakeChain.state = {
            "chain": 40204,
            "genesis": GENESIS,
            "receipt_status": "0x1",
            "no_code": set(),
            "owners": {},
            "org": self.addrs["OrganizationSBT"],
        }
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.bpath = d / "run-latest.json"
        self.bpath.write_text(json.dumps(self.run_json))
        self.book = d / "40204.json"
        self.book.write_text(json.dumps(_book(), indent=2) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _cli(self, *extra):
        return hbu.main(
            ["--broadcast", str(self.bpath), "--book", str(self.book), "--admin", ADMIN,
             "--rpc", self.url, "--genesis", GENESIS, *extra]
        )

    def test_happy_path_writes_book(self):
        self.assertEqual(self._cli(), 0)
        out = json.loads(self.book.read_text())
        for n, a in self.addrs.items():
            self.assertEqual(out["contracts"][n], hbu.to_checksum(a))

    def test_check_mode_does_not_write(self):
        before = self.book.read_text()
        self.assertEqual(self._cli("--check"), 0)
        self.assertEqual(self.book.read_text(), before)

    def test_wrong_genesis_refused_and_nothing_written(self):
        _FakeChain.state["genesis"] = "0x" + "01" * 32
        before = self.book.read_text()
        self.assertEqual(self._cli(), 1)
        self.assertEqual(self.book.read_text(), before)

    def test_wrong_chain_refused(self):
        _FakeChain.state["chain"] = 1
        self.assertEqual(self._cli(), 1)

    def test_no_code_refused(self):
        _FakeChain.state["no_code"] = {self.addrs["BenchmarkRegistry"]}
        self.assertEqual(self._cli(), 1)

    def test_eoa_admin_refused(self):
        _FakeChain.state["no_code"] = {ADMIN}
        self.assertEqual(self._cli(), 1)

    def test_wrong_owner_refused(self):
        _FakeChain.state["owners"] = {self.addrs["CapsuleRegistry"]: "0x" + "ee" * 20}
        self.assertEqual(self._cli(), 1)

    def test_wrong_org_link_refused(self):
        _FakeChain.state["org"] = "0x" + "ab" * 20
        self.assertEqual(self._cli(), 1)

    def test_failed_receipt_on_chain_refused(self):
        _FakeChain.state["receipt_status"] = "0x0"
        self.assertEqual(self._cli(), 1)

    def test_rpc_requires_genesis(self):
        rc = hbu.main(["--broadcast", str(self.bpath), "--book", str(self.book), "--admin", ADMIN, "--rpc", self.url])
        self.assertEqual(rc, 1)

    def test_broadcast_for_other_chain_refused(self):
        self.run_json["chain"] = 31337
        self.bpath.write_text(json.dumps(self.run_json))
        self.assertEqual(self._cli(), 1)


if __name__ == "__main__":
    unittest.main()
