"""Stub JSON-RPC node for testing export-fixtures.sh. Not a chain: it exists so the export's
provenance logic (head drift, epoch crossing, producer sampling) can be tested offline.

  python3 stub_rpc.py <port> <start_head> <step_per_blockNumber_call>

Every eth_blockNumber call advances the head by <step>, which models blocks landing while
an export runs. Blocks alternate between two proposers. eth_call returns uint256(1).
"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, HEAD, STEP = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
state = {"head": HEAD}


def answer(req):
    m, p = req.get("method"), req.get("params") or []
    if m == "eth_blockNumber":
        state["head"] += STEP
        res = hex(state["head"])
    elif m == "eth_chainId":
        res = "0x9d0c"
    elif m == "net_version":
        res = "40204"
    elif m == "eth_syncing":
        res = False
    elif m == "net_peerCount":
        res = "0x3"
    elif m == "eth_getBlockByNumber":
        tag = p[0] if p else "latest"
        n = state["head"] if tag == "latest" else int(tag, 16)
        res = {"number": hex(n), "hash": "0x" + f"{n:064x}", "timestamp": hex(2 * n),
               "baseFeePerGas": "0x3b9aca00", "proposerPubkey": "0x" + ("aa" if n % 2 else "bb") * 32}
    elif m == "eth_call":
        res = "0x" + "0" * 63 + "1"
    elif m == "eth_gasPrice":
        res = "0x3b9aca00"
    else:
        return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "stub: " + str(m)}}
    return {"jsonrpc": "2.0", "id": req.get("id"), "result": res}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        out = [answer(r) for r in body] if isinstance(body, list) else answer(body)
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
