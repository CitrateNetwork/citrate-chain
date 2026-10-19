#!/usr/bin/env python3
"""Test-only stand-in for `citrate-node registration-proof` (the real subcommand is
tested in node/src/registration_proof.rs). Echoes its inputs into the same JSON shape,
with a log line first, as the real binary may print. Records its argv to $FAKE_NODE_LOG."""
import json
import os
import sys

args = sys.argv[1:]
if os.environ.get("FAKE_NODE_LOG"):
    with open(os.environ["FAKE_NODE_LOG"], "a") as f:
        f.write(json.dumps(args) + "\n")
if os.environ.get("FAKE_NODE_FAIL"):
    print("Error: proposer.key does not exist", file=sys.stderr)
    sys.exit(1)
get = lambda k: args[args.index(k) + 1]
pk = "0x" + "5e" * 32
sig = "0x" + "77" * 64
print("2026-10-19T00:00:00Z INFO citrate: config loaded")
print(json.dumps({
    "chain_id": 40204,
    "registry": get("--registry").lower(),
    "staker": get("--staker").lower(),
    "registration_nonce": int(get("--nonce")),
    "proposer_pubkey": pk,
    "register_digest": "0x" + "ab" * 32,
    "ed25519_signature": sig,
    "calldata": "0x10f53ba1" + pk[2:] + f"{64:064x}" + f"{64:064x}" + sig[2:],
}, indent=2))
