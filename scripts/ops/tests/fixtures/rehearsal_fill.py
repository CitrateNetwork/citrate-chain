#!/usr/bin/env python3
"""REHEARSAL STAND-IN for the genesis builder's validator-set fill. Test fixture only.

The real fill (a PR stacked on chain#375) writes the producers' validator set into the
r1006 genesis. Until it lands, the local dry run of r1006_bringup.sh uses this stand-in
so every later step can run. It does NOT put the validators in the genesis: it selects
the compiled `default` devnet genesis profile, measures that genesis's block 0 with the
real binary in an isolated network namespace, and writes a fill-result.json whose
`source` says so. With --genesis-hash it skips the probe and writes that hash with
--profile (default r1006): the unit tests use it to plant a fill. The validator list echoes the producer set so the bring-up's
consistency check has something to compare; the genesis does not contain it.

  rehearsal_fill.py --producers P --stakes S --out DIR --bin CITRATE_BINARY
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# Arachnid's deterministic-deployment-proxy runtime (69 bytes), the code the compiled
# genesis profiles place at 0x4e59b44847b379578588920ca78fbf26c0b4956c. Source: the
# Arachnid/deterministic-deployment-proxy project (an independent reference, not read
# back from the node).
ARACHNID = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
ARACHNID_CODE = ("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0"
                 "3601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3")
REHEARSAL_REGISTRY = "0x0000000000000000000000000000000000001006"  # no code: a stand-in value


def probe_block0(binary: str) -> str:
    t = Path(tempfile.mkdtemp(prefix="dgx-r1006fill."))
    try:
        (t / "node.toml").write_text(f"""[chain]
chain_id = 40204
genesis_hash = ""
block_time = 2
ghostdag_k = 18
genesis_profile = "default"

[network]
listen_addr = "127.0.0.1:30399"
bootstrap_nodes = []
max_peers = 4
allowed_peers = []

[rpc]
enabled = true
listen_addr = "127.0.0.1:8545"
ws_addr = "127.0.0.1:8546"
allow_eth_send_transaction = false

[storage]
data_dir = "{t}/data"
pruning = false
keep_blocks = 100000

[mining]
enabled = false
coinbase = "{'11' * 20}"
target_block_time = 2
min_gas_price = 1000000000
""")
        script = f"""ip link set lo up
"{binary}" --config "{t}/node.toml" >"{t}/log" 2>&1 &
p=$!
for i in $(seq 1 120); do
  h=$(python3 -c '
import json,urllib.request
r=urllib.request.Request("http://127.0.0.1:8545",json.dumps({{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",False]}}).encode(),{{"content-type":"application/json"}})
print(json.load(urllib.request.urlopen(r,timeout=2))["result"]["hash"])' 2>/dev/null) && break
  sleep 0.5
done
kill $p; wait $p 2>/dev/null
printf '%s' "$h"
"""
        out = subprocess.run(["unshare", "--net", "bash", "-c", script], capture_output=True, text=True, timeout=120)
        h = out.stdout.strip()
        if not h.startswith("0x"):
            sys.exit(f"rehearsal_fill: probe gave no block 0 ({out.stderr.strip()[-300:]}; {(t / 'log').read_text()[-500:] if (t / 'log').exists() else ''})")
        return h
    finally:
        shutil.rmtree(t)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--producers", required=True, type=Path)
    ap.add_argument("--stakes", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--bin")
    ap.add_argument("--genesis-hash", help="write this block 0 instead of probing (tests)")
    ap.add_argument("--profile", default="r1006", help="genesis_profile to write (tests; 'null' = None)")
    ap.add_argument("--genesis-file", help="genesis_file to write (tests)")
    a = ap.parse_args()
    if not a.genesis_hash and not a.bin:
        ap.error("--bin or --genesis-hash")
    prod = json.loads(a.producers.read_text())
    stakes = json.loads(a.stakes.read_text())["stakes"]
    gh = a.genesis_hash or probe_block0(a.bin)
    profile = None if a.profile == "null" else a.profile
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "alloc.json").write_text(json.dumps({"alloc": {ARACHNID: {"code": ARACHNID_CODE}}}, indent=2))
    fill = {
        "schema": "r1006-genesis-fill/1",
        "genesis_hash": gh,
        "genesis_profile": profile if a.genesis_hash else "default",
        "genesis_file": a.genesis_file,
        "alloc_file": "alloc.json",
        "address_book": None,
        "orangeseed": None,
        "validator_registry": REHEARSAL_REGISTRY,
        "validator_activation_height": 800,
        "validators": [{"proposer_pubkey": p["proposer_pubkey"], "staker": p["staker_address"],
                        "stake_wei": stakes[p["staker_address"].lower()]["stake_wei"]} for p in prod["producers"]],
        "source": "REHEARSAL STAND-IN (scripts/ops/tests/fixtures/rehearsal_fill.py): compiled default devnet "
                  "genesis; the validator set is NOT in this genesis",
    }
    (a.out / "fill-result.json").write_text(json.dumps(fill, indent=2) + "\n")
    print(f"rehearsal_fill: block 0 {gh} (default profile; validators NOT in genesis)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
