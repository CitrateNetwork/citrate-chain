#!/usr/bin/env python3
"""rpc_receipt_retry_proxy.py: a loopback JSON-RPC proxy for a PRIVATE genesis devnet.

Genesis tooling only. Use it when you rehearse the genesis ceremony against a private local
Citrate devnet. Never put it in front of a fleet or public node: it listens on 127.0.0.1 only
and refuses an upstream that is not loopback.

Why: a Citrate node can answer null to eth_getTransactionByHash and eth_getTransactionReceipt
for a transaction that has left the mempool but whose block is not stored yet. Forge then
gives up on the receipt of a transaction that is mined a moment later, and a ceremony step
stops part-way. `forge script --resume` does not recover from that: it miscounts the nonce,
because the transactions it took as dropped were mined. Node issue: chain#397.

What it does: for those two methods only, a null result is re-asked every POLL seconds for up
to WAIT seconds. Every other call, every error and every non-null result passes through
byte-for-byte. It never invents an answer, so a transaction that never lands still ends null.

  rpc_receipt_retry_proxy.py --listen 18755 --upstream http://127.0.0.1:18745 [--wait 20] [--poll 0.5]

Exit: 2 usage (non-loopback upstream, bad port).
"""
import argparse
import http.server
import json
import sys
import time
import urllib.parse
import urllib.request

RETRY_METHODS = ("eth_getTransactionByHash", "eth_getTransactionReceipt")
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def is_loopback_url(url):
    try:
        u = urllib.parse.urlparse(url)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and u.hostname in LOOPBACK


class Upstream:
    def __init__(self, url, timeout=60):
        self.url, self.timeout = url, timeout

    def raw(self, body):
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read()


def settle(upstream, req, resp, wait, poll, sleep=time.sleep, now=time.monotonic):
    """The answer to one request: `resp`, or for a retry method a later non-null answer."""
    if not isinstance(req, dict) or req.get("method") not in RETRY_METHODS:
        return resp
    if not isinstance(resp, dict) or "error" in resp or resp.get("result") is not None:
        return resp
    deadline = now() + wait
    while now() < deadline:
        sleep(poll)
        resp = json.loads(upstream.raw(json.dumps(req).encode()))
        if not isinstance(resp, dict) or "error" in resp or resp.get("result") is not None:
            return resp
    return resp


def handle(upstream, body, wait, poll, sleep=time.sleep, now=time.monotonic):
    """Bytes in, bytes out. Passes the upstream bytes through unless a retry changed them."""
    raw = upstream.raw(body)
    try:
        req, resp = json.loads(body), json.loads(raw)
    except ValueError:
        return raw
    if isinstance(req, list) and isinstance(resp, list) and len(req) == len(resp):
        out = [settle(upstream, q, r, wait, poll, sleep, now) for q, r in zip(req, resp)]
        return raw if out == resp else json.dumps(out).encode()
    if isinstance(req, dict) and isinstance(resp, dict):
        out = settle(upstream, req, resp, wait, poll, sleep, now)
        return raw if out is resp else json.dumps(out).encode()
    return raw


def serve(port, upstream, wait, poll):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            try:
                data = handle(upstream, body, wait, poll)
            except Exception as e:  # the upstream is down: say so, as a JSON-RPC error
                data = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": f"proxy upstream: {e}"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--wait", type=float, default=20.0)
    ap.add_argument("--poll", type=float, default=0.5)
    a = ap.parse_args(argv)
    if not is_loopback_url(a.upstream):
        print(f"rpc_receipt_retry_proxy: the upstream must be a loopback URL (a private devnet), got {a.upstream}", file=sys.stderr)
        return 2
    if not 0 < a.listen < 65536:
        print("rpc_receipt_retry_proxy: --listen must be a port", file=sys.stderr)
        return 2
    serve(a.listen, Upstream(a.upstream), a.wait, a.poll)
    return 0


if __name__ == "__main__":
    sys.exit(main())
