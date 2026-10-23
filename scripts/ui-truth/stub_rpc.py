"""Stub JSON-RPC node for testing export-fixtures.sh. Not a chain: it exists so the export's
provenance logic (head drift, epoch crossing, producer sampling) can be tested offline.

  python3 stub_rpc.py <port> <start_head> <step_per_blockNumber_call> [fail_mod] [batch_fault]

Every eth_blockNumber call advances the head by <step>, which models blocks landing while
an export runs. Blocks alternate between two proposers. eth_call returns uint256(1).
With [fail_mod] > 0, every block whose number is divisible by it fails: odd multiples return
a JSON-RPC error, even multiples return a null block (models a partial producer sample).
With [batch_fault] = http500 or badjson, the batch request covering the current head (the
final producer batch) fails at the transport or parse level instead. With [batch_fault] =
headbad, eth_blockNumber returns a malformed quantity; with hostilets, block timestamps are a
Bash arithmetic-injection string (the exporter must never evaluate it).
ValidatorRegistry reads are ABI-encoded: two validators, one with actEpoch <= currentEpoch
(7) and one pending (actEpoch 9).
Environment (used by scripts/rehearsal/test-export-r1.sh): STUB_CHAIN_ID overrides the chain id
(default 0x9d0c = 40204); eth_getCode returns non-empty code for every address except those in
STUB_CODELESS (comma-separated, any case), which return "0x"; eth_call to an address in
STUB_CALL_FAIL (comma-separated) returns a JSON-RPC error.
"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, HEAD, STEP = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
FAIL_MOD = int(sys.argv[4]) if len(sys.argv) > 4 else 0
BATCH_FAULT = sys.argv[5] if len(sys.argv) > 5 else ""
MARKER = sys.argv[6] if len(sys.argv) > 6 else "/nonexistent/stub-marker"
state = {"head": HEAD}
W = lambda v: f"{v:064x}"
K1, K2 = "11" * 32, "22" * 32


def registry_call(data):
    """Minimal ABI-encoded ValidatorRegistry responses; everything else is uint256(1)."""
    sel = data[2:10]
    if sel == "76671808":  # currentEpoch()
        return "0x" + W(7)
    if sel == "fd4665ae":  # activeSet() -> (bytes32[], uint256[])
        return "0x" + W(64) + W(64 + 32 * 3) + W(2) + K1 + K2 + W(2) + W(32000) + W(32000)
    if sel == "00408838":  # validatorInfo(bytes32): actEpoch is the 6th word
        act = 5 if data[10:74] == K1 else 9
        return "0x" + W(1) + W(32000) + W(0) + W(0) + W(32000) + W(act) + W(0) + W(0) + W(1) + W(0)
    return "0x" + W(1)


def answer(req):
    m, p = req.get("method"), req.get("params") or []
    if m == "eth_blockNumber":
        if BATCH_FAULT == "headbad":
            return {"jsonrpc": "2.0", "id": req.get("id"), "result": "not-a-quantity"}
        state["head"] += STEP
        res = hex(state["head"])
    elif m == "eth_chainId":
        res = os.environ.get("STUB_CHAIN_ID", "0x9d0c")
    elif m == "eth_getCode":
        codeless = {a.strip().lower() for a in os.environ.get("STUB_CODELESS", "").split(",") if a.strip()}
        res = "0x" if (p and str(p[0]).lower() in codeless) else "0x6080604052"
    elif m == "net_version":
        res = "40204"
    elif m == "eth_syncing":
        res = False
    elif m == "net_peerCount":
        res = "0x3"
    elif m == "eth_getBlockByNumber":
        tag = p[0] if p else "latest"
        n = state["head"] if tag == "latest" else int(tag, 16)
        if FAIL_MOD and n % FAIL_MOD == 0 and tag != "latest" and n > 1000:
            if (n // FAIL_MOD) % 2:
                return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32000, "message": "stub: unavailable"}}
            return {"jsonrpc": "2.0", "id": req.get("id"), "result": None}
        ts = "a[$(touch " + MARKER + ")]" if BATCH_FAULT == "hostilets" else hex(2 * n)
        res = {"number": hex(n), "hash": "0x" + f"{n:064x}", "timestamp": ts,
               "baseFeePerGas": "0x3b9aca00", "proposerPubkey": "0x" + ("aa" if n % 2 else "bb") * 32}
    elif m == "eth_call":
        failing = {a.strip().lower() for a in os.environ.get("STUB_CALL_FAIL", "").split(",") if a.strip()}
        if p and str((p[0] or {}).get("to", "")).lower() in failing:
            return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": 3, "message": "execution reverted"}}
        data = ((p[0] or {}).get("data") or (p[0] or {}).get("input") or "") if p else ""
        res = registry_call(data)
    elif m == "eth_gasPrice":
        res = "0x3b9aca00"
    else:
        return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "stub: " + str(m)}}
    return {"jsonrpc": "2.0", "id": req.get("id"), "result": res}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        final_batch = isinstance(body, list) and any(r.get("id") == state["head"] for r in body)
        if BATCH_FAULT == "http500" and final_batch:
            self.send_response(500); self.send_header("content-length", "0"); self.end_headers(); return
        out = [answer(r) for r in body] if isinstance(body, list) else answer(body)
        data = json.dumps(out).encode()
        if BATCH_FAULT == "badjson" and final_batch:
            data = data[: len(data) // 2]
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
