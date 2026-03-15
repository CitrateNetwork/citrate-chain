#!/usr/bin/env python3
"""
Citrate Metrics Bridge — polls node RPC and exposes Prometheus metrics.

Use this when the node's built-in metrics-exporter-prometheus HTTP listener
isn't binding (known issue with metrics-exporter-prometheus 0.12.x on macOS).

Usage:
    python3 metrics-bridge.py [--rpc http://localhost:8545] [--port 9090] [--interval 5]
"""

import argparse
import json
import time
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

RPC_URL = "http://localhost:8545"
POLL_INTERVAL = 5

# Shared metrics state
metrics = {
    "citrate_block_height": 0,
    "citrate_chain_id": 0,
    "citrate_peer_count": 0,
    "citrate_mempool_size": 0,
    "citrate_gas_price_gwei": 0.0,
    "citrate_bridge_up": 1,
    "citrate_bridge_last_poll_timestamp": 0,
}

def rpc_call(method, params=None):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params or [],
        "id": 1,
    }).encode()
    req = urllib.request.Request(
        RPC_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read()).get("result")
    except Exception:
        return None


def poll_metrics():
    while True:
        try:
            # Block height
            result = rpc_call("eth_blockNumber")
            if result:
                metrics["citrate_block_height"] = int(result, 16)

            # Chain ID
            result = rpc_call("eth_chainId")
            if result:
                metrics["citrate_chain_id"] = int(result, 16)

            # Peer count
            result = rpc_call("net_peerCount")
            if result:
                metrics["citrate_peer_count"] = int(result, 16)
            else:
                metrics["citrate_peer_count"] = 0

            # Gas price
            result = rpc_call("eth_gasPrice")
            if result:
                metrics["citrate_gas_price_gwei"] = int(result, 16) / 1e9

            # Mempool snapshot (custom)
            result = rpc_call("citrate_getMempoolSnapshot")
            if result and isinstance(result, dict):
                metrics["citrate_mempool_size"] = result.get("size", 0)
            else:
                metrics["citrate_mempool_size"] = 0

            metrics["citrate_bridge_up"] = 1
            metrics["citrate_bridge_last_poll_timestamp"] = time.time()

        except Exception:
            metrics["citrate_bridge_up"] = 0

        time.sleep(POLL_INTERVAL)


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        lines = []
        lines.append("# HELP citrate_block_height Current block height")
        lines.append("# TYPE citrate_block_height gauge")
        lines.append(f'citrate_block_height{{network="devnet"}} {metrics["citrate_block_height"]}')

        lines.append("# HELP citrate_chain_id Chain ID")
        lines.append("# TYPE citrate_chain_id gauge")
        lines.append(f'citrate_chain_id{{network="devnet"}} {metrics["citrate_chain_id"]}')

        lines.append("# HELP citrate_peer_count Connected peers")
        lines.append("# TYPE citrate_peer_count gauge")
        lines.append(f'citrate_peer_count{{network="devnet"}} {metrics["citrate_peer_count"]}')

        lines.append("# HELP citrate_mempool_size Transactions in mempool")
        lines.append("# TYPE citrate_mempool_size gauge")
        lines.append(f'citrate_mempool_size{{network="devnet"}} {metrics["citrate_mempool_size"]}')

        lines.append("# HELP citrate_gas_price_gwei Current gas price in gwei")
        lines.append("# TYPE citrate_gas_price_gwei gauge")
        lines.append(f'citrate_gas_price_gwei{{network="devnet"}} {metrics["citrate_gas_price_gwei"]}')

        lines.append("# HELP citrate_bridge_up Metrics bridge connectivity")
        lines.append("# TYPE citrate_bridge_up gauge")
        lines.append(f'citrate_bridge_up {metrics["citrate_bridge_up"]}')

        body = "\n".join(lines) + "\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # Silence request logs


def main():
    global RPC_URL, POLL_INTERVAL

    parser = argparse.ArgumentParser(description="Citrate Metrics Bridge")
    parser.add_argument("--rpc", default="http://localhost:8545", help="Node RPC URL")
    parser.add_argument("--port", type=int, default=9090, help="Metrics HTTP port")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval (seconds)")
    args = parser.parse_args()

    RPC_URL = args.rpc
    POLL_INTERVAL = args.interval

    # Start background poller
    poller = Thread(target=poll_metrics, daemon=True)
    poller.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", args.port), MetricsHandler)
    print(f"Metrics bridge: http://0.0.0.0:{args.port}/metrics (polling {RPC_URL} every {POLL_INTERVAL}s)")
    server.serve_forever()


if __name__ == "__main__":
    main()
