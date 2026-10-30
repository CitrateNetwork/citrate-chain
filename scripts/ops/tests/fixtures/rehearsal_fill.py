#!/usr/bin/env python3
"""REHEARSAL STAND-IN for the genesis builder's validator-set fill. Test fixture only.

The real fill (chain#398's scripts/genesis/r1006/fill_producers.py) writes the
producers' validator set into the r1006 genesis. For the local rehearsal this stand-in
measures the block 0 that the binary's compiled `r1006` profile builds (with
CITRATE_R1006_REHEARSAL=1, in an isolated network namespace) and writes a
fill-result.json selecting that profile. A binary without the r1006 profile refuses it,
so the stand-in fails closed. The validator list echoes the producer set so the bring-up's
consistency check has something to compare; this stand-in does not change the genesis.
So the devnet producers are NOT registered, and a rehearsal chain halts at the validator
activation height (block 1000; the last block is 999). It says so on stderr. To run past
activation, use the real fill and a throwaway rebuild that pins its genesis
(scripts/ops/r1006/local_devnet.sh header, docs/ops/R1006_BRINGUP.md).
With --genesis-hash it skips the probe and writes that hash with --profile (default
r1006): the unit tests use it to plant a fill.

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
# The committed r1006 book's ValidatorRegistry (the bring-up runs the fill from the repo root).
BOOK = Path("contracts/addresses/r1006/40204.json")
# The r1006 validator activation height the fill result records.
ACTIVATION = 1000


def probe_block0(binary: str) -> str:
    t = Path(tempfile.mkdtemp(prefix="dgx-r1006fill."))
    try:
        (t / "node.toml").write_text(f"""[chain]
chain_id = 40204
genesis_hash = ""
block_time = 2
ghostdag_k = 18
genesis_profile = "r1006"

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
        out = subprocess.run(["unshare", "--net", "bash", "-c", script], capture_output=True, text=True, timeout=120,
                             env=dict(os.environ, CITRATE_R1006_REHEARSAL="1"))
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
    ap.add_argument("--registry", help="validator_registry to write instead of the committed book's (tests)")
    ap.add_argument("--address-book", action="store_true", help="copy the committed book to OUT/book.json (tests)")
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
        "genesis_profile": profile if a.genesis_hash else "r1006",
        "genesis_file": a.genesis_file,
        "alloc_file": "alloc.json",
        "address_book": "book.json" if a.address_book else None,
        "orangeseed": None,
        "validator_registry": a.registry or json.loads(BOOK.read_text())["contracts"]["ValidatorRegistry"].lower(),
        "validator_activation_height": ACTIVATION,
        "validators_at_genesis": True,
        "validators": [{"proposer_pubkey": p["proposer_pubkey"], "staker": p["staker_address"],
                        "stake_wei": stakes[p["staker_address"].lower()]["stake_wei"]} for p in prod["producers"]],
        "source": "REHEARSAL STAND-IN (scripts/ops/tests/fixtures/rehearsal_fill.py): compiled r1006 profile "
                  "genesis; its validator set is the build's, not these producers'",
    }
    if a.address_book:
        (a.out / "book.json").write_text(BOOK.read_text())
    (a.out / "fill-result.json").write_text(json.dumps(fill, indent=2) + "\n")
    print(f"rehearsal_fill: block 0 {gh} (profile {fill['genesis_profile']})")
    print(f"rehearsal_fill: WARNING: REHEARSAL STAND-IN: the genesis keeps the compiled profile's validator set, "
          f"not these {len(prod['producers'])} producers; they are not registered, so the chain halts at block "
          f"{ACTIVATION} (the validator activation height; the last block is {ACTIVATION - 1}). To run past it use the "
          "real fill (python3 scripts/genesis/r1006/fill_producers.py {producers} {stakes} {out}) and rebuild at a "
          "throwaway commit that pins its genesis (docs/ops/R1006_BRINGUP.md).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
