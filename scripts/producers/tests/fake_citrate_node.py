#!/usr/bin/env python3
"""Test-only stand-in for chain#398's `citrate --config C registration-proof --registry R
[--staker S]` (the real subcommand is tested in node/src/registration_proof.rs there). It
accepts exactly those arguments, as the real CLI does (`--nonce` is an unexpected argument:
the proof is always for registration nonce 0), prints a log line first as the real binary
may, then the proof in schema citrate-registration-proof/1. FAKE_NODE_CHAIN_ID stands in for
the node.toml's chain id; FAKE_NODE_STAKER for its coinbase (default: --staker);
FAKE_NODE_EXTRA adds a field. Records its argv to $FAKE_NODE_LOG."""
import json
import os
import sys

args = sys.argv[1:]
if os.environ.get("FAKE_NODE_LOG"):
    with open(os.environ["FAKE_NODE_LOG"], "a") as f:
        f.write(json.dumps(args) + "\n")
if os.environ.get("FAKE_NODE_FAIL"):
    print("Error: no proposer key at \"/x/proposer.key\"", file=sys.stderr)
    sys.exit(1)
if len(args) < 3 or args[0] != "--config" or args[2] != "registration-proof":
    print("error: usage: citrate --config C registration-proof --registry R [--staker S]", file=sys.stderr)
    sys.exit(2)
opts, rest = {}, args[3:]
while rest:
    k = rest.pop(0)
    if k not in ("--registry", "--staker") or not rest:
        print(f"error: unexpected argument '{k}' found", file=sys.stderr)
        sys.exit(2)
    opts[k] = rest.pop(0)
if "--registry" not in opts:
    print("error: the following required arguments were not provided: --registry <REGISTRY>", file=sys.stderr)
    sys.exit(2)
staker = os.environ.get("FAKE_NODE_STAKER") or opts.get("--staker") or "0x" + "c1" * 20
proof = {
    "schema": "citrate-registration-proof/1",
    "chain_id": int(os.environ.get("FAKE_NODE_CHAIN_ID", "40204")),
    "registry": opts["--registry"].lower(),
    "staker": staker.lower(),
    "proposer_pubkey": "0x" + "5e" * 32,
    "registration_sig": "0x" + "77" * 64,
}
if os.environ.get("FAKE_NODE_EXTRA"):
    proof["seed"] = "0x" + "00" * 32
print("2026-10-19T00:00:00Z INFO citrate: config loaded")
print(json.dumps(proof, indent=2))
