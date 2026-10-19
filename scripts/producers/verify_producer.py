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
  state       The registry reads are eth_call at `latest`, which runs on the node's APPLIED
              state; eth_blockNumber and block hashes come from its stored headers. A node
              that is syncing or replaying stores headers ahead of the state it has
              applied, so its registry answers can be older than its head. Before the
              registry reads (and again after them, for the committee check) the node must
              show that its state has caught up: eth_syncing is exactly `false` (the node
              reports {currentBlock, highestBlock} while its applied tip is behind the
              highest block it has seen) AND its head block's timestamp is at most
              --max-head-age seconds old (a node replaying from disk after a restart, or cut
              off from its peers, can report `false` while its head is stale). If either
              fails or cannot be read, registered/eligible/committee are UNKNOWN.
  registered  ValidatorRegistry.validatorInfo(pubkey).status == Active and isActive(pubkey);
              the registered staker equals --staker; pubkeyOfStaker(staker) == pubkey.
              "Registered · active from epoch N" while actEpoch > currentEpoch().
  registered  With --pubkey alone, the staker is validatorInfo(pubkey).staker and
              pubkeyOfStaker(that staker) must still name this pubkey.
  eligible    "Validator active": isActive(pubkey), actEpoch <= currentEpoch() and its
              activeSet() effective stake >= minStake() (live registry; consensus follows
              the epoch snapshot and can lag up to an epoch; vrf.rs is_eligible_proposer).
  committee   DERIVED, not observed: no RPC exposes the consensus snapshot or the checkpoint
              committee. The committee for a checkpoint is the governing snapshot S(E)'s
              members at or above minStake (core/consensus/src/vrf.rs is_eligible_proposer),
              all of them while the set is <= committee_size (checkpoint.rs select). The
              registry can only be read at latest (eth_call ignores historical block tags),
              so the latest stakes, set and minStake stand in for S(E)'s ONLY when
              eth_getLogs shows no stake-, set- or parameter-changing registry event from
              block S(E) to the head; otherwise, or if the logs cannot be read, the check is
              UNKNOWN. The committee counts only members that are BOTH activation-ready
              for S(E) and at or above minStake. Checkpoint finality needs an effective
              committee of at least MIN_FINALITY_COMMITTEE (checkpoint.rs, quorum
              floor(2n/3)+1); a smaller committee never finalizes, so the check FAILS even
              when this validator is in it. Finality status is reported from the
              `finalized` block tag.
  producing   "Producing blocks": a block in the last --window blocks has proposerPubkey ==
              pubkey; every such block's miner (coinbase) must equal the staker.

Exit status: 0 every required check passed; 1 a required check failed; 3 a read failed
(unknown is not zero: an unreadable check is never reported as passed or failed).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import producerlib as pl  # noqa: E402

CHECKS = ("network", "registered", "eligible", "committee", "producing")
# Checkpoint finality constants, mirrored from core/consensus/src/checkpoint.rs
# (MIN_FINALITY_COMMITTEE and derived_quorum; CHECKPOINT_FINALITY_WIRING.md D-2/D-2a).
# tests/test_verify_producer.py parses that file and fails if these drift.
MIN_FINALITY_COMMITTEE = 4
BATCH = 100
# The head block must be at most this old, or MAX_HEAD_AGE_BLOCKS block times if longer,
# for the node's state to count as caught up (see "state" above). Overridable with
# --max-head-age.
MAX_HEAD_AGE_FLOOR_S = 120
MAX_HEAD_AGE_BLOCKS = 30


def default_max_head_age(prof: pl.Profile) -> int:
    return max(MAX_HEAD_AGE_FLOOR_S, MAX_HEAD_AGE_BLOCKS * int(prof["block_time"]))


def derived_quorum(n: int) -> int:
    """checkpoint.rs derived_quorum: floor(2n/3) + 1."""
    return (n * 2) // 3 + 1


def qualifying_members(members: list[tuple[int, int]], epoch: int | None, min_stake: int) -> int:
    """Members of snapshot S(epoch) that the consensus counts: activation epoch <= epoch AND
    effective stake >= minStake (vrf.rs is_eligible_proposer; checkpoint committee input).
    `members` is (activation epoch, effective stake) per activeSet() entry."""
    if epoch is None:
        return 0
    return sum(1 for ae, stake in members if ae <= epoch and stake >= min_stake)


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
        "eth_syncing + eth_getBlockByNumber(head).timestamp (applied state caught up), before and after the registry reads",
        'eth_getBlockByNumber("finalized")',
    ]
    if staker:
        calls.append(f"eth_call {reg}.pubkeyOfStaker({staker})")
    calls += [
        f"eth_call {reg}.validatorInfo({who})",
        f"eth_call {reg}.isActive({who})",
    ]
    if not staker:
        calls.append(f"eth_call {reg}.pubkeyOfStaker(validatorInfo({who}).staker) (binding check)")
    calls += [
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


def applied_state_problem(rpc: pl.Rpc, head: int, max_age: int, now: float | None = None) -> str | None:
    """None when the node shows its applied state has caught up with its head; otherwise
    the reason it cannot be shown (see "state" in the module docstring). Unreadable or
    malformed evidence is a reason too: it is never read as "caught up"."""
    try:
        syncing = rpc.call("eth_syncing", [])
    except pl.RpcError as e:
        return f"could not read the node's sync status (eth_syncing): {e}"
    if syncing is not False:
        if not isinstance(syncing, dict):
            return f"eth_syncing returned {syncing!r}, not false or a progress object"
        try:
            cur = pl.parse_qty(syncing.get("currentBlock"), "eth_syncing.currentBlock")
            top = pl.parse_qty(syncing.get("highestBlock"), "eth_syncing.highestBlock")
        except pl.RpcError as e:
            return f"the node reports it is syncing, with a malformed progress object ({e})"
        return (
            f"the node is syncing or replaying: its applied state is at block {cur}, behind the "
            f"highest block it has seen ({top}; its head {head})"
        )
    try:
        b = rpc.call("eth_getBlockByNumber", [pl.qty(head), False])
        ts = pl.parse_qty(b.get("timestamp") if isinstance(b, dict) else None, f"block {head} timestamp")
    except pl.RpcError as e:
        return f"could not read the head block's timestamp: {e}"
    age = int((time.time() if now is None else now) - ts)
    if age > max_age:
        return (
            f"the head block {head} is {age} s old (limit {max_age} s): the node is behind the "
            f"network or replaying, so its state can lag its headers"
        )
    return None


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
    max_age = args.max_head_age if args.max_head_age is not None else default_max_head_age(prof)
    # The registry reads below run on the node's applied state. Refuse to read it as
    # current unless the node shows that state has caught up with its head.
    lag = applied_state_problem(rpc, head, max_age)
    r.network["applied_state"] = "caught up" if lag is None else f"not shown: {lag}"
    if lag is not None:
        for cid in ("registered", "eligible", "committee"):
            r.set(
                cid,
                None,
                f"unknown: {lag}. The registry reads run on the node's applied state, which "
                "can be older than its head; re-run when the node has caught up, or use an RPC "
                "node that has",
                "eth_syncing + head block timestamp",
            )
        return r

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
        if staker is None and info["status"] == "Active":
            # --pubkey alone: bind the identity both ways, as with --staker.
            bound = pl.uint_word(
                rpc.eth_call(reg, pl.calldata("pubkeyOfStaker(address)", info["staker"])), "pubkeyOfStaker"
            )
        in_set = pl.bool_word(rpc.eth_call(reg, pl.calldata("isActive(bytes32)", pubkey)), "isActive")
        cur_epoch = pl.uint_word(rpc.eth_call(reg, pl.calldata("currentEpoch()")), "currentEpoch")
        min_stake = pl.uint_word(rpc.eth_call(reg, pl.calldata("minStake()")), "minStake")
        registered_count = pl.uint_word(rpc.eth_call(reg, pl.calldata("activeCount()")), "activeCount")
        aset = pl.decode_active_set(rpc.eth_call(reg, pl.calldata("activeSet()")))
        if len(aset) != registered_count:
            # Both are _activeSet.length; a difference means the reads saw different states
            # or a malformed reply. The member count would be wrong either way.
            raise pl.RpcError(f"activeSet() has {len(aset)} entries but activeCount() is {registered_count}")
        # (activation epoch, effective stake) per member: the committee rule needs both.
        members: list[tuple[int, int]] = []
        for k, eff_k in aset:
            mi = pl.decode_validator_info(rpc.eth_call(reg, pl.calldata("validatorInfo(bytes32)", k)))
            members.append((mi["act_epoch"], eff_k))
        fin = rpc.call("eth_getBlockByNumber", ["finalized", False])
        finalized = pl.parse_qty(fin.get("number") if isinstance(fin, dict) else None, "finalized.number")
        bracket = read_bracket(rpc, head, hash_before)
        if not isinstance(bracket, str):
            # Close the applied-state check too: the reads must not have run while the node
            # fell behind (a restart into replay, a stall) between the two checks.
            lag_after = applied_state_problem(rpc, bracket[0], max_age)
            if lag_after is not None:
                bracket = f"after the registry reads, {lag_after}"
    except pl.RpcError as e:
        r.set("registered", None, f"unavailable: {e}", "ValidatorRegistry reads")
        return r

    eligible_count = qualifying_members(members, cur_epoch, min_stake)
    e_gov = pl.governing_snapshot_epoch(head + 1)
    committee_size = int(prof["checkpoint"]["committee_size"])
    snapshot_members = qualifying_members(members, e_gov, min_stake)
    effective_committee = min(snapshot_members, committee_size)
    r.network = {
        **r.network,
        "head": head,
        "current_epoch": cur_epoch,
        "registered_validators": registered_count,
        "eligible_validators": eligible_count,
        "pending_activation": sum(1 for ae, _ in members if ae > cur_epoch),
        "below_min_stake": sum(1 for _, st in members if st < min_stake),
        "min_stake": pl.salt(min_stake),
        "finalized_height": finalized,
        # Latest-registry view of the governing snapshot's committee; the committee check
        # says whether it can be tied to S(E).
        "committee_qualifying_members": snapshot_members,
        "committee_size": committee_size,
        "min_finality_committee": MIN_FINALITY_COMMITTEE,
        "finality_quorum": (
            derived_quorum(effective_committee) if effective_committee >= MIN_FINALITY_COMMITTEE else None
        ),
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
    eff = dict(aset).get(pubkey)
    if reg_ok and eff is None:
        r.set(
            "eligible",
            None,
            "unknown: isActive(pubkey) is true but the pubkey is absent from activeSet() (the reads "
            "straddled a change); re-run",
            "isActive vs activeSet()",
        )
    elif reg_ok and eff < min_stake:
        r.set(
            "eligible",
            False,
            f"below minStake: effective stake {pl.salt(eff)} < {pl.salt(min_stake)}",
            "activeSet().effStakes vs minStake()",
        )
    elif reg_ok and act <= cur_epoch:
        r.set(
            "eligible",
            True,
            "Validator active (eligible, live registry)",
            "isActive + actEpoch <= currentEpoch() + effective stake >= minStake()",
        )
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
    finality_note = (
        "checkpoint finality is not running on this network (the finalized tag returns genesis)"
        if finalized == 0
        else f"finalized height {finalized}"
    )
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
            "eth_blockNumber + block hashes + eth_syncing/head timestamp around the registry reads",
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
    elif eff is None:
        r.set(
            "committee",
            None,
            "unknown: the pubkey is absent from activeSet() although isActive(pubkey) is true; re-run",
            "isActive vs activeSet()",
            governing_snapshot_epoch=e_gov,
            finality=finality_note,
        )
    elif eff < min_stake:
        r.set(
            "committee",
            False,
            "below minStake: filtered out of the committee",
            "activeSet().effStakes vs minStake(), registry unchanged since S(E)",
        )
    else:
        src = "derived: vrf.rs is_eligible_proposer + checkpoint.rs select/MIN_FINALITY_COMMITTEE; " + snap_src + " shows no change"
        size = (
            f"{snapshot_members} qualifying members (activation-ready for S({e_gov}) and at or above "
            f"minStake {pl.salt(min_stake)}), committee_size {committee_size}"
        )
        detail = {
            "governing_snapshot_epoch": e_gov,
            "snapshot_members": snapshot_members,
            "effective_committee": effective_committee,
            "min_finality_committee": MIN_FINALITY_COMMITTEE,
            "finality": finality_note,
            # This validator is a member either way below; whether the committee as a whole can
            # finalize decides ok. Automation reads this field, operators read the state words.
            "in_committee": snapshot_members <= committee_size,
        }
        if effective_committee < MIN_FINALITY_COMMITTEE:
            # Never OK: a committee below the minimum proposes and votes but never finalizes.
            r.set(
                "committee",
                False,
                f"in the checkpoint committee for snapshot S({e_gov}), but the committee is too small to "
                f"finalize: {size}; effective committee {effective_committee} < the minimum "
                f"{MIN_FINALITY_COMMITTEE} (quorum {derived_quorum(MIN_FINALITY_COMMITTEE)} of "
                f"{MIN_FINALITY_COMMITTEE}). {finality_note[0].upper()}{finality_note[1:]}",
                src,
                **detail,
            )
        elif snapshot_members > committee_size:
            r.set(
                "committee",
                None,
                f"unknown: {size}; the set is larger than committee_size, so membership is a VRF draw, "
                "not derivable here",
                src,
                **detail,
            )
        else:
            r.set(
                "committee",
                True,
                f"in the checkpoint committee for snapshot S({e_gov}) (derived from the registry rule; "
                f"no RPC exposes the committee). {size}; finality quorum "
                f"{derived_quorum(effective_committee)} of {effective_committee} (minimum committee "
                f"{MIN_FINALITY_COMMITTEE}). {finality_note[0].upper()}{finality_note[1:]}",
                src,
                quorum=derived_quorum(effective_committee),
                **detail,
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
    ap.add_argument(
        "--max-head-age",
        type=int,
        default=None,
        help=f"seconds; the head block must be at most this old for the node's state to count as "
        f"caught up (default max({MAX_HEAD_AGE_FLOOR_S}, {MAX_HEAD_AGE_BLOCKS} x profile block_time))",
    )
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
        if args.max_head_age is not None and not 1 <= args.max_head_age <= 86_400:
            raise pl.ToolError("--max-head-age must be 1..86400 seconds")
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
