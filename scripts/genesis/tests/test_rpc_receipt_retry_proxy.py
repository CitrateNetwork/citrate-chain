#!/usr/bin/env python3
"""Tests for scripts/genesis/rpc_receipt_retry_proxy.py (no network beyond loopback).

Run: python3 -I scripts/genesis/tests/test_rpc_receipt_retry_proxy.py
"""
import http.server
import json
import os
import socket
import sys
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import rpc_receipt_retry_proxy as P  # noqa: E402

TX = "0x" + "ab" * 32


class Script:
    """A fake upstream: answers per method from a list (the last answer repeats)."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls = []

    def raw(self, body):
        req = json.loads(body)
        reqs = req if isinstance(req, list) else [req]
        out = []
        for q in reqs:
            self.calls.append(q["method"])
            seq = self.answers[q["method"]]
            ans = seq.pop(0) if len(seq) > 1 else seq[0]
            out.append({"jsonrpc": "2.0", "id": q.get("id"), **ans})
        return json.dumps(out if isinstance(req, list) else out[0]).encode()


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def call(method, i=1):
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": [TX]}


class ProxyTest(unittest.TestCase):
    def run_one(self, up, req, wait=20, poll=0.5):
        c = Clock()
        out = P.handle(up, json.dumps(req).encode(), wait, poll, sleep=c.sleep, now=c.now)
        return json.loads(out), c

    def test_null_receipt_is_reasked_until_the_block_is_stored(self):
        up = Script({"eth_getTransactionReceipt": [{"result": None}, {"result": None}, {"result": {"status": "0x1"}}]})
        out, c = self.run_one(up, call("eth_getTransactionReceipt"))
        self.assertEqual(out["result"], {"status": "0x1"})
        self.assertEqual(up.calls.count("eth_getTransactionReceipt"), 3)

    def test_null_transaction_is_reasked(self):
        up = Script({"eth_getTransactionByHash": [{"result": None}, {"result": {"hash": TX}}]})
        out, _ = self.run_one(up, call("eth_getTransactionByHash"))
        self.assertEqual(out["result"]["hash"], TX)

    def test_a_transaction_that_never_lands_stays_null_after_the_wait(self):
        up = Script({"eth_getTransactionReceipt": [{"result": None}]})
        out, c = self.run_one(up, call("eth_getTransactionReceipt"), wait=5, poll=0.5)
        self.assertIsNone(out["result"])
        self.assertGreaterEqual(c.t, 5)
        self.assertLessEqual(up.calls.count("eth_getTransactionReceipt"), 12)

    def test_other_methods_pass_through_unchanged(self):
        # Negative control: a null from any other method is NOT retried.
        up = Script({"eth_getBlockByNumber": [{"result": None}, {"result": {"number": "0x1"}}]})
        raw = up.raw  # the exact bytes the upstream returns
        body = json.dumps(call("eth_getBlockByNumber")).encode()
        c = Clock()
        expected = Script({"eth_getBlockByNumber": [{"result": None}]}).raw(body)
        out = P.handle(up, body, 20, 0.5, sleep=c.sleep, now=c.now)
        self.assertEqual(out, expected)
        self.assertEqual(up.calls, ["eth_getBlockByNumber"])
        self.assertEqual(c.t, 0)
        del raw

    def test_errors_pass_through_and_are_not_retried(self):
        up = Script({"eth_getTransactionReceipt": [{"error": {"code": -32000, "message": "x"}}]})
        out, c = self.run_one(up, call("eth_getTransactionReceipt"))
        self.assertEqual(out["error"]["code"], -32000)
        self.assertEqual(up.calls, ["eth_getTransactionReceipt"])

    def test_non_null_answer_bytes_are_untouched(self):
        up = Script({"eth_getTransactionReceipt": [{"result": {"status": "0x1"}}]})
        body = json.dumps(call("eth_getTransactionReceipt")).encode()
        want = Script({"eth_getTransactionReceipt": [{"result": {"status": "0x1"}}]}).raw(body)
        self.assertEqual(P.handle(up, body, 20, 0.5), want)

    def test_batch_retries_only_the_null_receipt_entry(self):
        up = Script({
            "eth_getTransactionReceipt": [{"result": None}, {"result": {"status": "0x1"}}],
            "eth_chainId": [{"result": "0x9d0c"}],
        })
        c = Clock()
        out = json.loads(P.handle(up, json.dumps([call("eth_chainId", 1), call("eth_getTransactionReceipt", 2)]).encode(), 20, 0.5, sleep=c.sleep, now=c.now))
        self.assertEqual(out[0]["result"], "0x9d0c")
        self.assertEqual(out[1]["result"], {"status": "0x1"})
        self.assertEqual(up.calls.count("eth_chainId"), 1)

    def test_only_a_loopback_upstream_is_accepted(self):
        for ok in ("http://127.0.0.1:8545", "http://localhost:8545", "http://[::1]:8545"):
            self.assertTrue(P.is_loopback_url(ok), ok)
        for bad in ("https://rpc.citrate.ai", "http://10.0.0.5:8545", "http://127.0.0.1.example.com:8545", "file:///etc/passwd"):
            self.assertFalse(P.is_loopback_url(bad), bad)
        self.assertEqual(P.main(["--listen", "18999", "--upstream", "https://rpc.citrate.ai"]), 2)

    def test_end_to_end_over_loopback(self):
        state = {"n": 0}

        class Up(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state["n"] += 1
                res = None if state["n"] < 3 else {"status": "0x1"}
                data = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        threading.Thread(target=P.serve, args=(port, P.Upstream(f"http://127.0.0.1:{up.server_address[1]}"), 5, 0.05), daemon=True).start()
        body = json.dumps(call("eth_getTransactionReceipt")).encode()
        for _ in range(50):
            try:
                r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}", data=body, headers={"Content-Type": "application/json"}), timeout=10)
                break
            except OSError:
                import time
                time.sleep(0.05)
        self.assertEqual(json.loads(r.read())["result"], {"status": "0x1"})
        self.assertEqual(state["n"], 3)
        up.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=1)
