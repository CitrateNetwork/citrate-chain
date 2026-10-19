#!/usr/bin/env python3
"""Post-join verification: is this producer registered, eligible, in the committee and
producing? Reads PUBLIC RPC only (no keys, no transactions) and reports in the words of
the UI truth contract (docs/ui-truth/UI_TRUTH_CONTRACT.md §1-§2).

  python3 verify_producer.py --profile 40204-r1005 --staker 0x...
  python3 verify_producer.py --profile 40204-r1005 --pubkey 0x<proposer pubkey>
  python3 verify_producer.py --profile 40204-r1005 --staker 0x... --require registered,eligible
  python3 verify_producer.py --profile 40204-r1005 --staker 0x... --dry-run

Checks and their sources:
  network     eth_chainId AND eth_getBlockByNumber(0x0).hash equal the profile's.
  registered  ValidatorRegistry.validatorInfo(pubkey).status == Active and isActive(pubkey);
              the registered staker equals --staker; pubkeyOfStaker(staker) == pubkey.
              "Registered · active from epoch N" while actEpoch > currentEpoch().
  eligible    "Validator active": isActive(pubkey) and actEpoch <= currentEpoch() (live
              registry; consensus follows the epoch snapshot and can lag up to an epoch).
  committee   DERIVED, not observed: no RPC exposes the consensus snapshot or the checkpoint
              committee. The committee for a checkpoint is the governing snapshot S(E)'s
              members at or above minStake (core/consensus/src/vrf.rs epoch_committee_set),
              all of them while the set is <= committee_size (checkpoint.rs select). The
              registry can only be read at latest (eth_call ignores historical block tags),
              so the latest stakes, set and minStake stand in for S(E)'s ONLY when
              eth_getLogs shows no stake-, set- or parameter-changing registry event from
              block S(E) to the head; otherwise, or if the logs cannot be read, the check is
              UNKNOWN. Finality status is reported from the `finalized` block tag.
  producing   "Producing blocks": a block in the last --window blocks has proposerPubkey ==
              pubkey; every such block's miner (coinbase) must equal the staker.

Exit status: 0 every required check passed; 1 a required check failed; 3 a read failed
(unknown is not zero: an unreadable check is never reported as passed or failed).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import producerlib as pl  # noqa: E402

CHECKS = ("network", "registered", "eligible", "committee", "producing")
MIN_FINALITY_COMMITTEE = 4  # CHECKPOINT_FINALITY_WIRING.md D-2a
BATCH = 100


class Result:
    def __init__(self) -> None:
        self.checks: dict[str, dict[str, Any]] = {}
        self.network: dict[str, Any] = {}

    def set(self, cid: str, ok: bool | None, state: str, source: str, **detail: Any) -> None:
        self.checks[cid] = {"ok": ok, "state": state, "source": source, **detail}


def planned_calls(prof: pl.Profile, staker: str | None, pubkey: str | None, window: int) -> list[str]:
    reg = prof["validator_registry"] or "<registry>"
    who = pubkey or "<pubkeyOfStaker(staker)>"
    calls = [
        "eth_chainId",
        "eth_getBlockByNumber(0x0)",
        "eth_blockNumber",
        'eth_getBlockByNumber("finalized")',
    ]
    if staker and not pubkey:
        calls.append(f"eth_call {reg}.pubkeyOfStaker({staker})")
    calls += [
        f"eth_call {reg}.validatorInfo({who})",
        f"eth_call {reg}.isActive({who})",
        f"eth_call {reg}.currentEpoch()",
        f"eth_call {reg}.minStake()",
        f"eth_call {reg}.activeCount()",
        f"eth_call {reg}.activeSet()",
        f"eth_call {reg}.validatorInfo(k) for each active-set member k (eligible count)",
        f"eth_getLogs {reg} from the governing snapshot block to the head, {pl.LOGS_CHUNK} blocks per call",
        f"eth_getBlockByNumber(n) for the last {window} blocks, in batches of {BATCH}",
    ]
    return calls


def fetch_window(rpc: pl.Rpc, head: int, window: int) -> list[dict[str, Any]] | None:
    lo = max(1, head - window + 1)
    blocks: list[dict[str, Any]] = []
    for s in range(lo, head + 1, BATCH):
        e = min(s + BATCH - 1, head)
        try:
            res = rpc.batch([("eth_getBlockByNumber", [pl.qty(h), False]) for h in range(s, e + 1)])
        except pl.RpcError:
            return None
        for h, b in zip(range(s, e + 1), res):
            if not isinstance(b, dict):
                return None
            pk = str(b.get("proposerPubkey", ""))
            miner = str(b.get("miner", ""))
            if not pl.B32_RE.match(pk) or not pl.ADDR_RE.match(miner):
                return None
            blocks.append({"height": h, "proposer": pk.lower(), "miner": miner.lower()})
    return blocks


def registry_changes_since(rpc: pl.Rpc, reg: str, start: int, head: int) -> list[str] | None:
    """Registry logs from `start` to `head` that can change stakes, the set or minStake, as
    "block:topic0" strings. None when the logs cannot be read completely."""
    benign = set(pl.REGISTRY_EVENTS_NO_STAKE_EFFECT.values())
    changes: list[str] = []
    for lo in range(start, head + 1, pl.LOGS_CHUNK):
        hi = min(lo + pl.LOGS_CHUNK - 1, head)
        try:
            logs = rpc.call(
                "eth_getLogs", [{"address": reg, "fromBlock": pl.qty(lo), "toBlock": pl.qty(hi)}]
            )
        except pl.RpcError:
            return None
        if not isinstance(logs, list):
            return None
        for lg in logs:
            if not isinstance(lg, dict):
                return None
            topics = lg.get("topics") or []
            t0 = str(topics[0]).lower().removeprefix("0x") if topics else ""
            if t0 not in benign:
                changes.append(f"{lg.get('blockNumber')}:{t0[:8] or 'anonymous'}")
    return changes


def block_hash(rpc: pl.Rpc, height: int) -> str | None:
    """Canonical hash at `height` per the RPC, lowercased; None when absent or unreadable."""
    try:
        b = rpc.call("eth_getBlockByNumber", [pl.qty(height), False])
    except pl.RpcError:
        return None
    h = b.get("hash") if isinstance(b, dict) else None
    return h.lower() if isinstance(h, str) else None


def read_bracket(rpc: pl.Rpc, head_before: int, hash_before: str | None) -> tuple[int, str] | str:
    """Close the bracket around the registry reads, which all use `latest`.

    Every value the reads returned is the state at some canonical block in
    [head_before, head_after], provided the block at head_before is still canonical (no
    reorg during the reads). Returns (head_after, hash_after) when that holds, or the reason
    it cannot be shown."""
    if hash_before is None:
        return f"could not read the hash of block {head_before} before the registry reads"
    try:
        head_after = pl.parse_qty(rpc.call("eth_blockNumber", []), "eth_blockNumber")
    except (pl.RpcError, pl.ToolError) as e:
        return f"could not read the head after the registry reads: {e}"
    if head_after < head_before:
        return f"the head went back from {head_before} to {head_after} during the reads"
    if block_hash(rpc, head_before) != hash_before:
        return f"block {head_before} changed during the reads (reorganisation)"
    hash_after = block_hash(rpc, head_after)
    if hash_after is None:
        return f"could not read the hash of block {head_after} after the registry reads"
    return head_after, hash_after


def verify(args: argparse.Namespace) -> Result:
    prof = pl.load_profile(args.profile)
    rpc = pl.Rpc(args.rpc or prof["public_rpc"])
    reg = prof["validator_registry"]
    r = Result()

    try:
        net = pl.check_network(rpc, prof)
        r.set("network", True, f"{prof.name} (chain {net['chain_id']})", "eth_chainId + genesis hash")
    except pl.RpcError as e:
        r.set("network", None, f"unavailable: {e}", "eth_chainId + genesis hash")
        return r
    except pl.ToolError as e:
        r.set("network", False, str(e), "eth_chainId + genesis hash")
        return r
    head = net["head"]

    staker = pl.norm_addr(args.staker) if args.staker else None
    pubkey = pl.norm_b32(args.pubkey) if args.pubkey else None
    bound: int | None = None
    try:
        if staker is not None:
            bound = pl.uint_word(
                rpc.eth_call(reg, pl.calldata("pubkeyOfStaker(address)", staker)), "pubkeyOfStaker"
            )
            if pubkey is None:
                if bound == 0:
                    r.set("registered", False, "Not a validator", "pubkeyOfStaker(staker) == 0", staker=staker)
                    return r
                pubkey = f"0x{bound:064x}"
        if pubkey is None:
            raise pl.ToolError("pass --staker or --pubkey")
        # Open the bracket: the registry reads below use `latest`, and the head can move (or
        # reorganise) while they run. The committee check needs to know which blocks' state
        # they could have seen (see read_bracket).
        hash_before = block_hash(rpc, head)
        info = pl.decode_validator_info(rpc.eth_call(reg, pl.calldata("validatorInfo(bytes32)", pubkey)))
        in_set = pl.bool_word(rpc.eth_call(reg, pl.calldata("isActive(bytes32)", pubkey)), "isActive")
        cur_epoch = pl.uint_word(rpc.eth_call(reg, pl.calldata("currentEpoch()")), "currentEpoch")
        min_stake = pl.uint_word(rpc.eth_call(reg, pl.calldata("minStake()")), "minStake")
        registered_count = pl.uint_word(rpc.eth_call(reg, pl.calldata("activeCount()")), "activeCount")
        aset = pl.decode_active_set(rpc.eth_call(reg, pl.calldata("activeSet()")))
        member_epochs = []
        for k, _ in aset:
            mi = pl.decode_validator_info(rpc.eth_call(reg, pl.calldata("validatorInfo(bytes32)", k)))
            member_epochs.append(mi["act_epoch"])
        fin = rpc.call("eth_getBlockByNumber", ["finalized", False])
        finalized = pl.parse_qty(fin.get("number") if isinstance(fin, dict) else None, "finalized.number")
        bracket = read_bracket(rpc, head, hash_before)
    except pl.RpcError as e:
        r.set("registered", None, f"unavailable: {e}", "ValidatorRegistry reads")
        return r

    eligible_count = sum(1 for ae in member_epochs if ae <= cur_epoch)
    r.network = {
        "head": head,
        "current_epoch": cur_epoch,
        "registered_validators": registered_count,
        "eligible_validators": eligible_count,
        "pending_activation": len(member_epochs) - eligible_count,
        "min_stake": pl.salt(min_stake),
        "finalized_height": finalized,
    }
    binding_problems = []
    if staker is None:
        staker = info["staker"]
    elif info["staker"] != staker:
        binding_problems.append(f"registered staker is {info['staker']}, not {staker}")
    if bound is not None and bound != int(pubkey, 16):
        binding_problems.append(f"pubkeyOfStaker({staker}) is 0x{bound:064x}, not this pubkey")

    # registered
    status, act = info["status"], info["act_epoch"]
    if status == "Active" and in_set:
        word = f"Registered · active from epoch {act}" if act > cur_epoch else "Validator active"
        r.set(
            "registered",
            not binding_problems,
            "; ".join([word, *binding_problems]),
            "validatorInfo(pubkey).status/staker, isActive(pubkey), pubkeyOfStaker(staker)",
            pubkey=pubkey,
            staker=info["staker"],
            stake=pl.salt(info["bonded"]),
            activation_epoch=act,
        )
    else:
        word = {"None": "Not a validator", "Exiting": "Exiting", "Slashed": "Slashed"}.get(status, status)
        r.set("registered", False, word, "validatorInfo(pubkey).status", pubkey=pubkey)

    # eligible (live registry)
    reg_ok = r.checks["registered"]["ok"] is True
    if reg_ok and act <= cur_epoch:
        r.set("eligible", True, "Validator active (eligible, live registry)", "isActive + actEpoch <= currentEpoch()")
    elif reg_ok:
        r.set(
            "eligible",
            False,
            f"Registered · active from epoch {act} (now epoch {cur_epoch}; about {(act * pl.EPOCH - head) * int(prof['block_time'])} s)",
            "actEpoch vs currentEpoch()",
        )
    else:
        r.set("eligible", False, "not registered", "validatorInfo")

    # committee (derived)
    e_gov = pl.governing_snapshot_epoch(head + 1)
    eff = dict(aset).get(pubkey)
    finality_note = (
        "checkpoint finality is not running on this network (the finalized tag returns genesis)"
        if finalized == 0
        else f"finalized height {finalized}"
    )
    snapshot_members = sum(1 for ae in member_epochs if e_gov is not None and ae <= e_gov)
    # The stakes, set and minStake read above are LATEST. They describe S(E) only if nothing
    # that changes them happened from the snapshot block to the head.
    # The reads saw state from some block in [head, head_after] (read_bracket), so the scan
    # must run to head_after, and the snapshot governing must be the same across that span.
    changes: list[str] | None = []
    bracket_problem: str | None = None
    scan_to = head
    if isinstance(bracket, str):
        bracket_problem = bracket
    else:
        scan_to, hash_after = bracket
        if pl.governing_snapshot_epoch(scan_to + 1) != e_gov:
            bracket_problem = (
                f"the head crossed a snapshot boundary during the reads ({head} -> {scan_to}); re-run"
            )
    if reg_ok and e_gov is not None and act <= e_gov and bracket_problem is None:
        changes = registry_changes_since(rpc, reg, pl.snapshot_height(e_gov), scan_to)
        # The scanned logs must belong to the chain the reads saw.
        if changes is not None and block_hash(rpc, scan_to) != hash_after:
            bracket_problem = f"block {scan_to} changed during the log scan (reorganisation); re-run"
    snap_src = f"eth_getLogs {reg} blocks {pl.snapshot_height(e_gov) if e_gov else '-'}..{scan_to}"
    if not reg_ok or e_gov is None:
        r.set("committee", False, "not in the committee", "derived: S(E) membership rule", finality=finality_note)
    elif act > e_gov:
        r.set(
            "committee",
            False,
            f"not yet: joins the snapshot S({act}) = block {pl.snapshot_height(act)}",
            "derived: actEpoch vs governing snapshot epoch",
            governing_snapshot_epoch=e_gov,
            finality=finality_note,
        )
    elif bracket_problem is not None:
        r.set(
            "committee",
            None,
            f"unknown: {bracket_problem}. The registry reads use the latest state, so they cannot be "
            f"tied to snapshot S({e_gov})",
            "eth_blockNumber + block hashes around the registry reads",
            governing_snapshot_epoch=e_gov,
            finality=finality_note,
        )
    elif changes is None:
        r.set(
            "committee",
            None,
            f"unknown: cannot confirm the registry is unchanged since snapshot S({e_gov}) "
            f"(block {pl.snapshot_height(e_gov)}); the snapshot's stakes are not readable over RPC",
            snap_src,
            governing_snapshot_epoch=e_gov,
            finality=finality_note,
        )
    elif changes:
        r.set(
            "committee",
            None,
            f"unknown: the registry changed after snapshot S({e_gov}) (block {pl.snapshot_height(e_gov)}): "
            f"{len(changes)} stake/set/parameter event(s), first at {changes[0]}. Latest state does not "
            f"describe S({e_gov}); re-check after the next snapshot S({e_gov + 1}) = block "
            f"{pl.snapshot_height(e_gov + 1)}",
            snap_src,
            governing_snapshot_epoch=e_gov,
            registry_changes=changes[:10],
            finality=finality_note,
        )
    elif eff is None or eff < min_stake:
        r.set(
            "committee",
            False,
            "below minStake: filtered out of the committee",
            "activeSet().effStakes vs minStake(), registry unchanged since S(E)",
        )
    else:
        size_ok = snapshot_members <= int(prof["checkpoint"]["committee_size"])
        r.set(
            "committee",
            True if size_ok else None,
            (
                f"in the checkpoint committee for snapshot S({e_gov}) (derived from the registry rule; "
                f"no RPC exposes the committee). {snapshot_members} members"
                + (
                    f"; finality needs at least {MIN_FINALITY_COMMITTEE}"
                    if snapshot_members < MIN_FINALITY_COMMITTEE
                    else ""
                )
                + f". {finality_note[0].upper()}{finality_note[1:]}"
                if size_ok
                else "set larger than committee_size: membership is a VRF draw, not derivable here"
            ),
            "derived: vrf.rs epoch_committee_set + checkpoint.rs select; " + snap_src + " shows no change",
            governing_snapshot_epoch=e_gov,
            snapshot_members=snapshot_members,
            finality=finality_note,
        )

    # producing
    blocks = fetch_window(rpc, head, args.window)
    if blocks is None:
        r.set("producing", None, "unavailable: block sample incomplete", "eth_getBlockByNumber window")
    else:
        mine = [b for b in blocks if b["proposer"] == pubkey]
        producers = {b["proposer"] for b in blocks}
        r.network["producing_validators"] = len(producers)
        r.network["producing_window"] = [blocks[0]["height"] if blocks else head, head]
        bad_miner = [b["height"] for b in mine if b["miner"] != staker]
        if mine and not bad_miner:
            r.set(
                "producing",
                True,
                f"Producing blocks: {len(mine)} of the last {len(blocks)}, latest at {mine[-1]['height']}",
                "eth_getBlockByNumber(n).proposerPubkey / miner",
            )
        elif bad_miner:
            r.set(
                "producing",
                False,
                f"blocks at {bad_miner[:5]} carry a coinbase other than the staker: fix [mining] coinbase",
                "eth_getBlockByNumber(n).miner",
            )
        else:
            r.set(
                "producing",
                False,
                f"not seen producing in the last {len(blocks)} blocks",
                "eth_getBlockByNumber(n).proposerPubkey",
            )
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--staker", help="the staker address that registered")
    ap.add_argument("--pubkey", help="the proposer pubkey (citrate-node registration-proof)")
    ap.add_argument("--rpc", help="override the profile's public RPC")
    ap.add_argument("--window", type=int, default=1000, help="blocks to scan for production")
    ap.add_argument("--require", default=",".join(CHECKS), help=f"subset of {','.join(CHECKS)}")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the reads it would make; no network")
    args = ap.parse_args(argv)
    try:
        if not args.staker and not args.pubkey:
            raise pl.ToolError("pass --staker or --pubkey")
        required = [c.strip() for c in args.require.split(",") if c.strip()]
        unknown = [c for c in required if c not in CHECKS]
        if unknown:
            raise pl.ToolError(f"unknown checks: {', '.join(unknown)}")
        if not 1 <= args.window <= 10_000:
            raise pl.ToolError("--window must be 1..10000")
        if args.dry_run:
            prof = pl.load_profile(args.profile, allow_pending=True)
            print(f"DRY RUN against {args.rpc or prof['public_rpc']} (profile {prof.name}, status {prof['status']}):")
            for c in planned_calls(prof, args.staker, args.pubkey, args.window):
                print(f"  {c}")
            print(f"required checks: {', '.join(required)}")
            return 0
        res = verify(args)
    except pl.ToolError as e:
        print(f"verify_producer: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"network": res.network, "checks": res.checks}, indent=2))
    else:
        for k, v in res.network.items():
            print(f"  {k:24} {v}")
        for c in CHECKS:
            if c not in res.checks:
                continue
            v = res.checks[c]
            mark = {True: "PASS", False: "FAIL", None: "UNKNOWN"}[v["ok"]]
            req = "" if c in required else " (not required)"
            print(f"[{mark}] {c:10} {v['state']}{req}")
    statuses = [res.checks.get(c, {"ok": None})["ok"] for c in required]
    if any(s is False for s in statuses):
        return 1
    if any(s is None for s in statuses):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
