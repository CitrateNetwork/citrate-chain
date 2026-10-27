#!/usr/bin/env bash
# Test fixture for scripts/ops/tests/test_r1006_bringup.py: stands in for the `citrate`
# binary so the bring-up can be tested without a node build.
#
# `host-identity`: writes CANARY-derived "secrets" in the real formats into the files the
# real command mints (0600): noise.key and proposer.key as 32 raw bytes, the password as
# 64 hex characters, a keystore JSON with a ciphertext. The public identity is derived
# from nothing secret. FAKE_PUB_EXTRA='"k": "v"' injects an extra field into the public
# file (negative control for the collector).
#
# `--config FILE`: a fake node. It serves eth_getBlockByNumber / eth_blockNumber /
# net_peerCount / eth_chainId on the [rpc] listen_addr, answers block 0 with the hash in
# <root>/fake-block0 (root = the dir holding usr/local/bin/<this file>, the host's
# R1006_ROOT; default below), and appends "start mining=<true|false> block0=<hash> t=<time> probe=<0|1>" to
# <root>/fake-node.log (probe=1: started by host_agent.sh probe-genesis).
#
# Set R1006_TEST_KEYTOOL to a real `citrate` binary to run the key tests against it.
set -euo pipefail
if [[ "${1:-}" == --config ]]; then
  exec python3 - "$0" "$2" <<'PY'
import json, os, re, signal, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
me, cfg = sys.argv[1], sys.argv[2]
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(me)))))
text = open(cfg).read()
sec, mining, listen = "", False, "127.0.0.1:8545"
for line in text.splitlines():
    m = re.match(r"^\[(\w+)\]", line)
    if m:
        sec = m.group(1)
    if sec == "mining" and line.startswith("enabled ="):
        mining = line.split("=", 1)[1].strip() == "true"
    if sec == "rpc" and line.startswith("listen_addr ="):
        listen = json.loads(line.split("=", 1)[1].strip())
try:
    block0 = open(os.path.join(root, "fake-block0")).read().strip()
except OSError:
    block0 = "0x" + "e1" * 32
with open(os.path.join(root, "fake-node.log"), "a") as f:
    probe = 1 if "r1006-probe." in cfg else 0
    f.write(f"start mining={'true' if mining else 'false'} block0={block0} t={time.time():.3f} probe={probe}\n")
coinbase = "0x" + "00" * 20
for line in text.splitlines():
    if line.startswith("coinbase ="):
        coinbase = "0x" + json.loads(line.split("=", 1)[1].strip())
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["content-length"])))
        m, p = req.get("method"), req.get("params") or []
        if m == "eth_getBlockByNumber":
            n = p[0] if p else "0x0"
            res = {"hash": block0, "number": "0x0"} if n in ("0x0", "finalized") else \
                  {"hash": "0x" + "ab" * 32, "number": n, "miner": coinbase}
        elif m == "eth_blockNumber":
            res = "0x0"
        elif m == "net_peerCount":
            res = "0x10"
        elif m == "eth_chainId":
            res = hex(40204)
        else:
            res = None
        body = json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": res}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
host, port = listen.rsplit(":", 1)
srv = HTTPServer((host, int(port)), H)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
srv.serve_forever()
PY
fi
[[ "${1:-}" == host-identity ]] || { echo "fake_keytool: only host-identity or --config" >&2; exit 2; }
shift
dir="" ks="" pw="" out="" mint=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity-dir) dir="$2"; shift 2 ;;
    --staker-keystore) ks="$2"; shift 2 ;;
    --staker-password-file) pw="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --mint) mint=1; shift ;;
    *) echo "fake_keytool: unknown $1" >&2; exit 2 ;;
  esac
done
canary="${CANARY:?}"
# mk FILE KIND: create FILE (0600) once, from the canary, in KIND's real format.
mk() {
  [[ -e "$1" ]] && return 0
  [[ $mint -eq 1 ]] || { echo "missing $1 (--mint)" >&2; exit 1; }
  (umask 077; python3 - "$1" "$2" "$canary|$dir" <<'PY'
import hashlib, json, sys
path, kind, salt = sys.argv[1], sys.argv[2], sys.argv[3]
d = hashlib.sha256(f"{salt}|{kind}".encode()).digest()
if kind in ("noise", "proposer"):
    data = d                                       # 32 raw bytes, like the node's loaders
elif kind == "password":
    data = d.hex().encode()                        # 64 hex characters, like host-identity
else:
    data = json.dumps({"address": hashlib.sha256(salt.encode()).hexdigest()[:40],
                       "crypto": {"ciphertext": d.hex(), "cipher": "aes-128-ctr"}}).encode()
open(path, "wb").write(data)
PY
  )
}
mk "$dir/noise.key" noise
mk "$dir/proposer.key" proposer
mk "$pw" password
mk "$ks" keystore
h=$(sha256sum <<<"$dir" | cut -d' ' -f1)
a=$(cut -c1-40 <<<"$h")
v=$(sha256sum <<<"v$dir" | cut -d' ' -f1)
p=$(sha256sum <<<"p$dir" | cut -d' ' -f1)
json="{\"schema\":\"citrate-host-identity/1\",\"peer_id\":\"noise_$h\",\"noise_pubkey\":\"$h\",\"proposer_pubkey\":\"0x$p\",\"vrf_pubkey\":\"0x02$v\",\"staker_address\":\"0x$a\",\"coinbase_address\":\"0x$a\"${FAKE_PUB_EXTRA:+,$FAKE_PUB_EXTRA}}"
[[ -n "$out" ]] && printf '%s\n' "$json" >"$out"
printf '%s\n' "$json"
