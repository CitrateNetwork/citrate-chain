#!/usr/bin/env python3
"""Build the UNSIGNED ValidatorRegistry.registerValidator transaction for this producer.

Run it on the producer host, as the `citrate` user (it needs read access to the node's
proposer.key, which it never prints or copies). It:

  1. checks the public RPC is the profile's network (chain id AND genesis hash);
  2. reads, from public RPC: registrationNonce(staker), pubkeyOfStaker(staker),
     minStake(), activeCount(), the staker's balance and account nonce;
  3. runs `citrate-node registration-proof`, which signs the Register digest with
     proposer.key (the ed25519 proof-of-control the contract checks);
  4. checks the proposer pubkey is not already registered;
  5. prints the unsigned legacy transaction (to, value, data, nonce, gas, gasPrice,
     chainId) and writes it to --out.

It never touches the staker key and never broadcasts. The operator signs the printed
transaction with their own wallet (hardware wallet recommended) and submits it.
Chain 40204 accepts LEGACY (type-0) transactions only.

  python3 build_registration_tx.py --profile 40204-r1005 --staker 0x... --config /etc/citrate/node.toml
  python3 build_registration_tx.py --profile rehearsal-1 --staker 0x... --config ... --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import producerlib as pl  # noqa: E402

DEFAULT_STAKE_SALT = 32_000  # used only in --dry-run when minStake can't be read


def run_registration_proof(
    binary: str, config: str, staker: str, registry: str, nonce: int, chain_id: int
) -> dict:
    exe = shutil.which(binary) or (binary if os.path.isfile(binary) else None)
    if exe is None:
        raise pl.ToolError(f"node binary {binary!r} not found (pass --citrate-bin)")
    cmd = [
        exe,
        "--config",
        config,
        "registration-proof",
        "--staker",
        staker,
        "--registry",
        registry,
        "--nonce",
        str(nonce),
    ]
    env = dict(os.environ, RUST_LOG="error", LOG_FORMAT="compact")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise pl.ToolError(f"running {exe} registration-proof failed: {e}") from e
    if cp.returncode != 0:
        raise pl.ToolError(f"registration-proof failed: {cp.stderr.strip() or cp.stdout.strip()}")
    # The JSON object starts at the first line that is exactly "{" (log lines, if any,
    # come before it on stdout).
    lines = cp.stdout.splitlines()
    try:
        start = lines.index("{")
        proof = json.loads("\n".join(lines[start:]))
    except (ValueError, json.JSONDecodeError) as e:
        raise pl.ToolError(f"registration-proof printed no JSON: {cp.stdout[:400]!r}") from e
    for k in (
        "proposer_pubkey",
        "ed25519_signature",
        "calldata",
        "staker",
        "registry",
        "registration_nonce",
        "chain_id",
    ):
        if k not in proof:
            raise pl.ToolError(f"registration-proof output lacks {k}")
    if proof["staker"].lower() != staker or proof["registry"].lower() != registry.lower():
        raise pl.ToolError("registration-proof bound a different staker or registry")
    if int(proof["registration_nonce"]) != nonce:
        raise pl.ToolError("registration-proof bound a different nonce")
    # The proof is signed over the node config's chain id; the transaction uses the profile's.
    # A mismatch would produce a transaction the registry rejects, so stop here.
    try:
        proof_chain = int(proof["chain_id"])
    except (TypeError, ValueError) as e:
        raise pl.ToolError(f"registration-proof chain_id is not a number: {proof['chain_id']!r}") from e
    if proof_chain != chain_id:
        raise pl.ToolError(
            f"registration-proof is bound to chain {proof_chain} (from {config}), but the profile is "
            f"chain {chain_id}: use this network's node.toml (or the matching --profile)"
        )
    return proof


def read_chain(rpc: pl.Rpc, prof: pl.Profile, staker: str) -> dict:
    reg = prof["validator_registry"]
    net = pl.check_network(rpc, prof)
    code = rpc.call("eth_getCode", [reg, "latest"])
    if not isinstance(code, str) or len(code) <= 2:
        raise pl.ToolError(f"no contract code at ValidatorRegistry {reg}")
    return {
        **net,
        "registration_nonce": pl.uint_word(
            rpc.eth_call(reg, pl.calldata("registrationNonce(address)", staker)), "registrationNonce"
        ),
        "pubkey_of_staker": "0x"
        + f"{pl.uint_word(rpc.eth_call(reg, pl.calldata('pubkeyOfStaker(address)', staker)), 'pubkeyOfStaker'):064x}",
        "min_stake": pl.uint_word(rpc.eth_call(reg, pl.calldata("minStake()")), "minStake"),
        "active_count": pl.uint_word(rpc.eth_call(reg, pl.calldata("activeCount()")), "activeCount"),
        "balance": pl.parse_qty(rpc.call("eth_getBalance", [staker, "latest"]), "eth_getBalance"),
        "account_nonce": pl.parse_qty(
            rpc.call("eth_getTransactionCount", [staker, "latest"]), "eth_getTransactionCount"
        ),
    }


def check_pubkey_free(rpc: pl.Rpc, reg: str, pubkey: str) -> None:
    info = pl.decode_validator_info(rpc.eth_call(reg, pl.calldata("validatorInfo(bytes32)", pubkey)))
    ever = pl.bool_word(
        rpc.eth_call(reg, pl.calldata("pubkeyEverRegistered(bytes32)", pubkey)), "pubkeyEverRegistered"
    )
    if info["status"] != "None" or ever:
        raise pl.ToolError(
            f"proposer pubkey {pubkey} is already registered (status {info['status']}); "
            "pubkeys are single-use. Run verify_producer.py instead."
        )


def build(args: argparse.Namespace) -> dict:
    staker = pl.norm_addr(args.staker)
    prof = pl.load_profile(args.profile, allow_pending=args.dry_run)
    reg = prof["validator_registry"] if pl.ADDR_RE.match(str(prof["validator_registry"])) else None
    gas_price = int(args.gas_price or prof.raw.get("gas_price_wei", 1_000_000_000))
    gas_limit = int(args.gas_limit or prof.raw.get("registration_gas_limit", 600_000))
    warnings: list[str] = []

    if args.dry_run:
        chain = {
            "registration_nonce": args.registration_nonce or 0,
            "account_nonce": args.account_nonce or 0,
            "min_stake": DEFAULT_STAKE_SALT * pl.WEI_PER_SALT,
        }
        if reg is None:
            reg = "0x" + "00" * 19 + "01"
            warnings.append("profile has no registry yet; a placeholder registry address is bound")
    else:
        if args.registration_nonce is not None or args.account_nonce is not None:
            raise pl.ToolError("--registration-nonce/--account-nonce are for --dry-run; live nonces come from RPC")
        rpc = pl.Rpc(args.rpc or prof["public_rpc"])
        chain = read_chain(rpc, prof, staker)
        if chain["pubkey_of_staker"] != "0x" + "00" * 32:
            raise pl.ToolError(
                f"staker {staker} already has validator {chain['pubkey_of_staker']} (one per staker)"
            )
        if chain["active_count"] >= pl.MAX_ACTIVE_SET:
            warnings.append(
                "the active set is full: registration needs a stake 25% above the smallest member"
            )

    stake_wei = pl.salt_to_wei(args.stake_salt) if args.stake_salt else chain["min_stake"]
    if stake_wei < chain["min_stake"]:
        raise pl.ToolError(f"stake {pl.salt(stake_wei)} is below minStake {pl.salt(chain['min_stake'])}")
    max_fee = gas_limit * gas_price
    if not args.dry_run and chain["balance"] < stake_wei + max_fee:
        raise pl.ToolError(
            f"staker balance {pl.salt(chain['balance'])} < stake + max gas "
            f"{pl.salt(stake_wei + max_fee)}; fund the staker first"
        )

    proof = run_registration_proof(
        args.citrate_bin, args.config, staker, reg, chain["registration_nonce"], int(prof["chain_id"])
    )
    if not args.dry_run:
        check_pubkey_free(rpc, reg, proof["proposer_pubkey"])

    tx = {
        "type": "0x0",
        "chainId": pl.qty(int(prof["chain_id"])),
        "nonce": pl.qty(chain["account_nonce"]),
        "from": staker,
        "to": reg,
        "value": pl.qty(stake_wei),
        "gas": pl.qty(gas_limit),
        "gasPrice": pl.qty(gas_price),
        "data": proof["calldata"],
    }
    return {
        "dry_run": bool(args.dry_run),
        "profile": prof.name,
        "unsigned_tx": tx,
        "summary": {
            "staker": staker,
            "proposer_pubkey": proof["proposer_pubkey"],
            "stake": pl.salt(stake_wei),
            "registration_nonce": chain["registration_nonce"],
            "account_nonce": chain["account_nonce"],
            "max_gas_cost": pl.salt(max_fee),
        },
        "proof": {k: proof[k] for k in ("register_digest", "ed25519_signature")},
        "warnings": warnings,
    }


def signing_help(out: dict, rpc_url: str) -> str:
    tx = out["unsigned_tx"]
    s = out["summary"]
    sig = out["proof"]["ed25519_signature"]
    return f"""
Sign this with YOUR staker wallet, on the machine that holds it. Example with Foundry
and a Ledger (use --trezor, or --keystore <file>, for other wallets):

  cast mktx --legacy --ledger --chain {int(tx['chainId'], 16)} --nonce {int(tx['nonce'], 16)} \\
    --gas-limit {int(tx['gas'], 16)} --gas-price {int(tx['gasPrice'], 16)} --value {int(tx['value'], 16)} \\
    {tx['to']} 'registerValidator(bytes32,bytes)' {s['proposer_pubkey']} {sig}

Check that cast's calldata equals "data" above (cast calldata 'registerValidator(bytes32,bytes)' ...),
then submit the signed bytes:

  cast publish --rpc-url {rpc_url} <signed-tx-hex>

Then run verify_producer.py. Activation is at epoch boundaries: expect
"Registered · active from epoch N" first.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--staker", required=True, help="the address that will sign and send the tx")
    ap.add_argument("--config", default="/etc/citrate/node.toml", help="this node's node.toml")
    ap.add_argument("--citrate-bin", default="citrate-node")
    ap.add_argument("--stake-salt", help="stake in SALT (default: the registry's minStake)")
    ap.add_argument("--rpc", help="override the profile's public RPC")
    ap.add_argument("--gas-price", type=int)
    ap.add_argument("--gas-limit", type=int)
    ap.add_argument("--out", help="write the result JSON here")
    ap.add_argument("--dry-run", action="store_true", help="no RPC; nonces from flags (default 0); output is marked DO NOT SIGN")
    ap.add_argument("--registration-nonce", type=int)
    ap.add_argument("--account-nonce", type=int)
    args = ap.parse_args(argv)
    try:
        out = build(args)
    except pl.ToolError as e:
        print(f"build_registration_tx: {e}", file=sys.stderr)
        return 2
    text = json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
    print(text)
    if out["dry_run"]:
        print("\nDRY RUN: nonces and stake were not read from the chain. DO NOT SIGN THIS.")
    else:
        prof = pl.load_profile(args.profile)
        print(signing_help(out, args.rpc or prof["public_rpc"]))
    for w in out["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
