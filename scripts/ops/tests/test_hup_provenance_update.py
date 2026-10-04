#!/usr/bin/env python3
"""Tests for scripts/ops/hup-provenance-update.py (stdlib unittest; no network).

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
_spec = importlib.util.spec_from_file_location("hup_provenance_update", HERE.parent / "hup-provenance-update.py")
hpu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hpu)
hbu = hpu.hbu

REAL_LEDGER = HERE.parent.parent.parent / "contracts" / "addresses" / "40204.provenance.json"
DEPLOYER = "0x" + "d3" * 20
OTHER = "0x" + "0e" * 20
GENESIS = "0x" + "9e" * 32
OLD = {
    "OrganizationSBT": "0x" + "a1" * 20,
    "AgentSBT": "0x" + "a2" * 20,
    "AnchorRegistry": "0x" + "a4" * 20,
}


def _broadcast(names=None, sender=DEPLOYER, first_nonce=3, first_block=100):
    names = names or list(hbu.HUP_NAMES)
    txs, rcs, addrs = [], [], {}
    for i, n in enumerate(names):
        contract = {**hbu.HUP_NAMES, **hbu.OPTIONAL_NAMES}[n]
        init = b"\x60\x80" + n.encode()
        salt = hbu.salt_for(n)
        addr = hbu.create2_address(hbu.ARACHNID_FACTORY, salt, init)
        th = "0x" + hbu.keccak256(f"tx-{n}-{i}".encode()).hex()
        txs.append({
            "hash": th,
            "transactionType": "CREATE2",
            "contractName": contract,
            "contractAddress": addr,
            "transaction": {
                "from": sender, "to": hbu.ARACHNID_FACTORY, "input": salt + init.hex(), "nonce": hex(first_nonce + i),
            },
        })
        rcs.append({"transactionHash": th, "status": "0x1", "blockNumber": hex(first_block + i)})
        addrs[n] = addr
    return {"chain": 40204, "transactions": txs, "receipts": rcs}, addrs


def _ledger():
    rows = [
        {"nonce": 0, "block": 1, "tx": "0x" + "01" * 32, "kind": "CREATE", "artifact": "X.sol:X",
         "address": hbu.to_checksum("0x" + "b0" * 20), "status": "canonical", "section": "governance",
         "name": "GOVERNANCE"},
        {"nonce": 1, "block": 2, "tx": "0x" + "02" * 32, "kind": "CREATE", "artifact": "OrganizationSBT.sol:OrganizationSBT",
         "address": hbu.to_checksum(OLD["OrganizationSBT"]), "status": "canonical", "section": "contracts",
         "name": "OrganizationSBT"},
        {"nonce": 2, "block": 3, "tx": "0x" + "03" * 32, "kind": "CREATE", "artifact": "AnchorRegistry.sol:AnchorRegistry",
         "address": hbu.to_checksum(OLD["AnchorRegistry"]), "status": "canonical", "section": "contracts",
         "name": "AnchorRegistry"},
    ]
    return {"chainId": 40204, "deployer": hbu.to_checksum(DEPLOYER), "genesisStateRoot": GENESIS,
            "method": "test", "ledger": rows}


def _book(addrs):
    contracts = {"ModelRegistry": hbu.to_checksum("0x" + "c0" * 20)}
    contracts.update({n: hbu.to_checksum(a) for n, a in addrs.items()})
    return {"chainId": 40204, "contracts": contracts}


class Rows(unittest.TestCase):
    def test_one_row_per_transaction(self):
        run, addrs = _broadcast()
        rows = hpu.broadcast_rows(run, DEPLOYER)
        self.assertEqual([r["name"] for r in rows], list(hbu.HUP_NAMES))
        r = rows[0]
        self.assertEqual(r["nonce"], 3)
        self.assertEqual(r["block"], 100)
        self.assertEqual(r["kind"], "CREATE2")
        self.assertEqual(r["artifact"], "OrganizationSBT.sol:OrganizationSBT")
        self.assertEqual(r["address"], hbu.to_checksum(addrs["OrganizationSBT"]))
        self.assertEqual(r["status"], "canonical")
        self.assertNotIn("from", r)

    def test_other_sender_is_recorded(self):
        run, _ = _broadcast(sender=OTHER)
        rows = hpu.broadcast_rows(run, DEPLOYER)
        self.assertEqual(rows[0]["from"], hbu.to_checksum(OTHER))

    def test_unrecognised_transaction_refused(self):
        run, _ = _broadcast()
        run["transactions"].append({"hash": "0x" + "77" * 32, "transactionType": "CALL", "transaction": {}})
        with self.assertRaisesRegex(hbu.BookError, "not a HUP registry deploy"):
            hpu.broadcast_rows(run, DEPLOYER)

    def test_missing_receipt_refused(self):
        run, _ = _broadcast()
        run["receipts"].pop()
        with self.assertRaisesRegex(hbu.BookError, "no receipt"):
            hpu.broadcast_rows(run, DEPLOYER)

    def test_tampered_address_refused(self):
        run, _ = _broadcast()
        run["transactions"][1]["contractAddress"] = "0x" + "11" * 20
        with self.assertRaisesRegex(hbu.BookError, "forge recorded"):
            hpu.broadcast_rows(run, DEPLOYER)

    def test_empty_broadcast_refused(self):
        with self.assertRaisesRegex(hbu.BookError, "deployed nothing"):
            hpu.broadcast_rows({"chain": 40204, "transactions": [], "receipts": []}, DEPLOYER)


class BookFollows(unittest.TestCase):
    def test_book_must_already_pin_the_broadcast(self):
        run, addrs = _broadcast()
        rows = hpu.broadcast_rows(run, DEPLOYER)
        hpu.check_book(_book(addrs), rows)
        stale = _book({**addrs, "AgentSBT": OLD["AgentSBT"]})
        with self.assertRaisesRegex(hbu.BookError, "run hup-book-update.py"):
            hpu.check_book(stale, rows)


class Merge(unittest.TestCase):
    def test_appends_and_supersedes(self):
        run, addrs = _broadcast()
        out, added, superseded = hpu.merge(_ledger(), hpu.broadcast_rows(run, DEPLOYER))
        self.assertEqual(len(added), 6)
        self.assertEqual([e["nonce"] for e in out["ledger"]], [0, 1, 2, 3, 4, 5, 6, 7, 8])
        old_org = out["ledger"][1]
        self.assertEqual(old_org["status"], "superseded")
        self.assertIn(added[0]["tx"], old_org["why"])
        self.assertEqual(out["ledger"][2]["status"], "superseded")
        self.assertEqual({e.get("name") for e in superseded}, {"OrganizationSBT", "AnchorRegistry"})
        self.assertEqual(out["ledger"][0]["status"], "canonical")
        canon = [e["name"] for e in out["ledger"] if e["status"] == "canonical"]
        self.assertEqual(sorted(canon), sorted(["GOVERNANCE", *hbu.HUP_NAMES]))
        self.assertEqual(out["appendedRuns"][0]["txs"], [r["tx"] for r in added])
        self.assertEqual(out["appendedRuns"][0]["firstBlock"], 100)

    def test_input_is_not_mutated(self):
        run, _ = _broadcast()
        prov = _ledger()
        before = json.dumps(prov)
        hpu.merge(prov, hpu.broadcast_rows(run, DEPLOYER))
        self.assertEqual(json.dumps(prov), before)

    def test_rerun_is_a_no_op(self):
        run, _ = _broadcast()
        rows = hpu.broadcast_rows(run, DEPLOYER)
        once, _, _ = hpu.merge(_ledger(), rows)
        twice, added, superseded = hpu.merge(once, rows)
        self.assertEqual(added, [])
        self.assertEqual(superseded, [])
        self.assertEqual(twice["ledger"], once["ledger"])

    def test_nonce_gap_refused(self):
        run, _ = _broadcast(first_nonce=5)
        with self.assertRaisesRegex(hbu.BookError, "does not continue the ledger"):
            hpu.merge(_ledger(), hpu.broadcast_rows(run, DEPLOYER))

    def test_reused_nonce_refused(self):
        run, _ = _broadcast(first_nonce=2)
        with self.assertRaisesRegex(hbu.BookError, "already records nonce 2"):
            hpu.merge(_ledger(), hpu.broadcast_rows(run, DEPLOYER))

    def test_other_sender_needs_no_continuation(self):
        run, _ = _broadcast(sender=OTHER, first_nonce=40)
        out, added, _ = hpu.merge(_ledger(), hpu.broadcast_rows(run, DEPLOYER))
        self.assertEqual(len(added), 6)
        self.assertTrue(all(r["from"] == hbu.to_checksum(OTHER) for r in added))

    def test_same_tx_with_other_fields_refused(self):
        run, _ = _broadcast()
        rows = hpu.broadcast_rows(run, DEPLOYER)
        once, _, _ = hpu.merge(_ledger(), rows)
        once["ledger"][-1]["address"] = hbu.to_checksum("0x" + "99" * 20)
        with self.assertRaisesRegex(hbu.BookError, "different fields"):
            hpu.merge(once, rows)

    def test_wrong_chain_ledger_refused(self):
        run, _ = _broadcast()
        prov = _ledger()
        prov["chainId"] = 1
        with self.assertRaisesRegex(hbu.BookError, "ledger chainId"):
            hpu.merge(prov, hpu.broadcast_rows(run, DEPLOYER))

    def test_real_ledger_merges_with_a_continuing_deployer_run(self):
        # The committed 40204 ledger: a redeploy from its deployer at the next nonce supersedes
        # exactly the six HUP names it pins today, and nothing else.
        prov = json.loads(REAL_LEDGER.read_text())
        nxt = max(e["nonce"] for e in prov["ledger"]) + 1
        run, _ = _broadcast(sender=prov["deployer"], first_nonce=nxt, first_block=9000)
        out, added, superseded = hpu.merge(prov, hpu.broadcast_rows(run, prov["deployer"].lower()))
        self.assertEqual(len(added), 6)
        self.assertEqual(sorted(e["name"] for e in superseded), sorted(hbu.HUP_NAMES))
        self.assertEqual(len(out["ledger"]), len(prov["ledger"]) + 6)
        untouched = [e for e in prov["ledger"] if e.get("name") not in hbu.HUP_NAMES]
        self.assertEqual([e for e in out["ledger"] if e.get("name") not in hbu.HUP_NAMES and e not in added],
                         untouched)


class _FakeChain(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *args):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if isinstance(req, list):  # batched eth_getBlockByNumber (the backfill scan)
            out = [{"jsonrpc": "2.0", "id": q["id"],
                    "result": self.state["blocks"].get(int(q["params"][0], 16))} for q in req]
            return self._reply(out)
        m, p = req["method"], req["params"]
        s = self.state
        if m == "eth_chainId":
            res = hex(s["chain"])
        elif m == "eth_getBlockByNumber":
            res = {"hash": s["genesis"]}
        elif m == "eth_getTransactionByHash":
            res = s["txs"].get(p[0])
        elif m == "eth_getTransactionReceipt":
            if p[0] in s.get("null_receipts", ()):
                res = None
            else:
                res = s.get("receipts", {}).get(p[0]) or {"status": s["receipt_status"]}
        elif m == "eth_getCode":
            res = "0x" if p[0].lower() in s["no_code"] else "0x6080"
        else:
            res = None
        self._reply({"jsonrpc": "2.0", "id": req["id"], "result": res})

    def _reply(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _FakeChain)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.run_json, self.addrs = _broadcast()
        txs = {}
        for t, r in zip(self.run_json["transactions"], self.run_json["receipts"]):
            txs[t["hash"]] = {"from": DEPLOYER, "nonce": t["transaction"]["nonce"], "blockNumber": r["blockNumber"]}
        _FakeChain.state = {
            "chain": 40204, "genesis": GENESIS, "txs": txs,
            "receipt_status": "0x1", "no_code": set(),
        }
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.bpath = d / "run-latest.json"
        self.bpath.write_text(json.dumps(self.run_json))
        self.book = d / "40204.json"
        self.book.write_text(json.dumps(_book(self.addrs), indent=2) + "\n")
        self.prov = d / "40204.provenance.json"
        self.prov.write_text(json.dumps(_ledger(), indent=1) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _cli(self, *extra, rpc=True):
        args = ["--broadcast", str(self.bpath), "--book", str(self.book), "--provenance", str(self.prov)]
        if rpc:
            args += ["--rpc", self.url, "--genesis", GENESIS]
        return hpu.main(args + list(extra))

    def test_writes_the_ledger_in_its_own_format(self):
        self.assertEqual(self._cli(), 0)
        text = self.prov.read_text()
        out = json.loads(text)
        self.assertEqual(text, json.dumps(out, indent=1) + "\n")
        self.assertEqual(len(out["ledger"]), 9)
        # A second run adds nothing and leaves the file as it is.
        self.assertEqual(self._cli(), 0)
        self.assertEqual(self.prov.read_text(), text)

    def test_check_does_not_write(self):
        before = self.prov.read_text()
        self.assertEqual(self._cli("--check"), 0)
        self.assertEqual(self._cli("--check", rpc=False), 0)
        self.assertEqual(self.prov.read_text(), before)

    def test_write_without_rpc_refused(self):
        before = self.prov.read_text()
        self.assertEqual(self._cli(rpc=False), 1)
        self.assertEqual(self.prov.read_text(), before)

    def _refused(self):
        before = self.prov.read_text()
        self.assertEqual(self._cli(), 1)
        self.assertEqual(self.prov.read_text(), before)

    def test_stale_book_refused(self):
        self.book.write_text(json.dumps(_book({**self.addrs, "SkillRegistry": "0x" + "5c" * 20})))
        self._refused()

    def test_wrong_genesis_refused(self):
        _FakeChain.state["genesis"] = "0x" + "01" * 32
        self._refused()

    def test_ledger_of_another_chain_refused(self):
        # A ledger from before a reroll: its block-0 hash is not the chain's.
        prov = _ledger()
        prov["genesisStateRoot"] = "0x" + "02" * 32
        self.prov.write_text(json.dumps(prov, indent=1) + "\n")
        self._refused()

    def test_committed_ledger_names_the_live_block0_hash(self):
        # The committed ledger's genesisStateRoot is the 40204 block-0 hash (also the core book's
        # genesisHash), which is what check_ledger_chain compares.
        prov = json.loads(REAL_LEDGER.read_text())
        hpu.check_ledger_chain(prov, prov["genesisStateRoot"])
        with self.assertRaisesRegex(hbu.BookError, "regenerate the ledger"):
            hpu.check_ledger_chain(prov, GENESIS)

    def test_sender_mismatch_refused(self):
        first = self.run_json["transactions"][0]["hash"]
        _FakeChain.state["txs"][first]["from"] = OTHER
        self._refused()

    def test_block_mismatch_refused(self):
        first = self.run_json["transactions"][0]["hash"]
        _FakeChain.state["txs"][first]["blockNumber"] = hex(7)
        self._refused()

    def test_missing_tx_refused(self):
        _FakeChain.state["txs"] = {}
        self._refused()

    def test_failed_receipt_refused(self):
        _FakeChain.state["receipt_status"] = "0x0"
        self._refused()

    def test_no_code_refused(self):
        _FakeChain.state["no_code"] = {self.addrs["CapsuleRegistry"]}
        self._refused()

    def test_wrong_chain_refused(self):
        _FakeChain.state["chain"] = 1
        self._refused()

    # ── --backfill: deployer transactions between the ledger's end and the redeploy ──

    def _gap(self, *txs):
        """Shift the broadcast to start at nonce 5 and put `txs` (nonces 3, 4) in blocks 50.."""
        self.run_json, self.addrs = _broadcast(first_nonce=3 + len(txs))
        self.bpath.write_text(json.dumps(self.run_json))
        self.book.write_text(json.dumps(_book(self.addrs), indent=2) + "\n")
        chain_txs, blocks = {}, {}
        for t, r in zip(self.run_json["transactions"], self.run_json["receipts"]):
            chain_txs[t["hash"]] = {"from": DEPLOYER, "nonce": t["transaction"]["nonce"], "blockNumber": r["blockNumber"]}
        for i, t in enumerate(txs):
            th = "0x" + hbu.keccak256(f"gap-{i}".encode()).hex()
            full = {"hash": th, "from": DEPLOYER, "nonce": hex(3 + i), **t}
            blocks[50 + 2 * i] = {"number": hex(50 + 2 * i), "transactions": [
                {"hash": "0x" + "ee" * 32, "from": OTHER, "nonce": "0x3", "to": OTHER, "input": "0x"}, full]}
            chain_txs[th] = {"from": DEPLOYER, "nonce": hex(3 + i), "blockNumber": hex(50 + 2 * i)}
        _FakeChain.state.update({"txs": chain_txs, "blocks": blocks})

    def test_without_backfill_a_gap_refuses(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x10"}, {"to": OTHER, "input": "0x", "value": "0x20"})
        self._refused()

    def test_backfill_records_transfers_and_calls_first(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x10"},
                  {"to": "0x" + "c1" * 20, "input": "0xa9059cbb" + "00" * 64, "value": "0x0"})
        self.assertEqual(self._cli("--backfill"), 0)
        out = json.loads(self.prov.read_text())
        self.assertEqual([e["nonce"] for e in out["ledger"]], list(range(11)))
        t, c = out["ledger"][3], out["ledger"][4]
        self.assertEqual((t["kind"], t["block"], t["to"], t["value"], t["status"]),
                         ("TRANSFER", 50, hbu.to_checksum(OTHER), "0x10", "call"))
        self.assertEqual((c["kind"], c["selector"], c["status"]), ("CALL", "0xa9059cbb", "call"))
        self.assertNotIn("name", t)
        # Rerun: nothing new, file unchanged.
        text = self.prov.read_text()
        self.assertEqual(self._cli("--backfill"), 0)
        self.assertEqual(self.prov.read_text(), text)

    def test_backfill_refuses_a_contract_creation(self):
        self._gap({"to": None, "input": "0x6080", "value": "0x0"})
        self._refused_with("--backfill")

    def test_backfill_refuses_a_factory_deploy(self):
        self._gap({"to": hbu.ARACHNID_FACTORY, "input": "0x" + "00" * 40, "value": "0x0"})
        self._refused_with("--backfill")

    def test_backfill_refuses_a_failed_transaction(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x1"})
        gap_tx = "0x" + hbu.keccak256(b"gap-0").hex()
        _FakeChain.state["receipts"] = {gap_tx: {"status": "0x0"}}
        self._refused_with("--backfill")

    def test_backfill_refuses_a_nonce_it_cannot_find(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x1"}, {"to": OTHER, "input": "0x", "value": "0x2"})
        _FakeChain.state["blocks"].pop(52)
        self._refused_with("--backfill")

    def test_backfill_accepts_a_plain_transfer_without_a_served_receipt(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x10", "gas": "0x5208"})
        gap_tx = "0x" + hbu.keccak256(b"gap-0").hex()
        _FakeChain.state["receipts"] = {gap_tx: None}
        _FakeChain.state["null_receipts"] = {gap_tx}
        _FakeChain.state["no_code"] = {OTHER}
        self.assertEqual(self._cli("--backfill"), 0)
        row = json.loads(self.prov.read_text())["ledger"][3]
        self.assertEqual(row["kind"], "TRANSFER")
        self.assertIn("receipt not served", row["why"])

    def test_backfill_refuses_a_call_without_a_served_receipt(self):
        self._gap({"to": "0x" + "c1" * 20, "input": "0xa9059cbb", "value": "0x0", "gas": "0x5208"})
        gap_tx = "0x" + hbu.keccak256(b"gap-0").hex()
        _FakeChain.state["null_receipts"] = {gap_tx}
        self._refused_with("--backfill")

    def test_backfill_refuses_a_transfer_to_code_without_a_served_receipt(self):
        self._gap({"to": OTHER, "input": "0x", "value": "0x10", "gas": "0x5208"})
        gap_tx = "0x" + hbu.keccak256(b"gap-0").hex()
        _FakeChain.state["null_receipts"] = {gap_tx}
        self._refused_with("--backfill")

    def test_backfill_needs_rpc(self):
        self.assertEqual(self._cli("--backfill", "--check", rpc=False), 1)

    def _refused_with(self, *extra):
        before = self.prov.read_text()
        self.assertEqual(self._cli(*extra), 1)
        self.assertEqual(self.prov.read_text(), before)


if __name__ == "__main__":
    unittest.main()
