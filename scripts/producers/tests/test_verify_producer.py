"""Tests for verify_producer.py against a fake 40204 RPC: every UI-truth state word, the
coinbase rule, derived committee membership, and unknown-is-not-zero."""

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import producerlib as pl  # noqa: E402
import verify_producer as v  # noqa: E402
from rpcstub import FakeChain, RpcStub  # noqa: E402

PK = "0x" + "5e" * 32
STAKER = "0x" + "c1" * 20
STAKE = 32_000 * 10**18


def others(c: FakeChain, n: int = 4) -> None:
    for i in range(n):
        c.add_validator("0x" + f"{i + 1:02x}" * 32, "0x" + f"{i + 0xa1:02x}" * 20, STAKE, 3)


def run(url: str, *extra: str):
    out, err = io.StringIO(), io.StringIO()
    argv = ["--profile", "40204-r1005", "--rpc", url, "--json", *extra]
    with redirect_stdout(out), redirect_stderr(err):
        rc = v.main(argv)
    body = json.loads(out.getvalue()) if out.getvalue().strip().startswith("{") else None
    return rc, body, err.getvalue()


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.c = FakeChain()
        others(self.c)

    def test_active_producing_validator_passes_everything(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        for h in range(c.head - 50, c.head + 1, 4):
            c.producers[h] = (PK, STAKER)
        with RpcStub(c) as s:
            rc, body, err = run(s.url, "--staker", STAKER)
        self.assertEqual(rc, 0, err)
        ch = body["checks"]
        self.assertEqual(ch["registered"]["state"], "Validator active")
        self.assertTrue(ch["eligible"]["ok"])
        self.assertTrue(ch["committee"]["ok"])
        self.assertIn("derived", ch["committee"]["state"])
        self.assertIn("not running", ch["committee"]["state"])
        self.assertTrue(ch["producing"]["state"].startswith("Producing blocks"))
        self.assertEqual(body["network"]["registered_validators"], 5)
        self.assertEqual(body["network"]["eligible_validators"], 5)
        self.assertEqual(body["network"]["producing_validators"], 2)

    def test_pending_activation_uses_the_contract_words(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, c.epoch + 1)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "registered")
            self.assertEqual(rc, 0)
            self.assertEqual(body["checks"]["registered"]["state"], f"Registered · active from epoch {c.epoch + 1}")
            self.assertFalse(body["checks"]["eligible"]["ok"])
            self.assertEqual(body["network"]["pending_activation"], 1)
            rc, _, _ = run(s.url, "--staker", STAKER, "--require", "registered,eligible")
            self.assertEqual(rc, 1)

    def test_committee_follows_the_governing_snapshot_not_the_live_set(self):
        c = self.c
        c.head = 512_900  # past S(513) = 512,800: blocks from 512,801 follow snapshot S(513)
        c.add_validator(PK, STAKER, STAKE, 513)  # registered before S(513), active from epoch 513
        with RpcStub(c) as s:
            _, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertTrue(body["checks"]["committee"]["ok"], body["checks"]["committee"])
        self.assertFalse(body["checks"]["eligible"]["ok"])  # live epoch is still 512
        c2 = FakeChain()
        others(c2)
        c2.head = 512_700  # before S(513): the governing snapshot is still S(512)
        c2.add_validator(PK, STAKER, STAKE, 513)
        with RpcStub(c2) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertEqual(rc, 1)
        self.assertIn("S(513) = block 512800", body["checks"]["committee"]["state"])

    def test_committee_unknown_when_stake_changed_after_the_snapshot(self):
        # A stake change after S(E) means the latest stakes do not describe S(E).
        c = self.c
        c.head = 512_900  # governing snapshot S(513) = block 512,800
        c.add_validator(PK, STAKER, STAKE, 3)
        stake_increased = "8a12a1190b63d1c04ed6ccb47df714257f26e7f702cbff29ca2c079eac2e4d83"
        c.logs.append({"block": 512_850, "topic0": stake_increased})
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        com = body["checks"]["committee"]
        self.assertIsNone(com["ok"], com)
        self.assertEqual(rc, 3)
        self.assertIn("changed after snapshot S(513)", com["state"])

    def test_committee_unknown_when_a_governance_param_executed(self):
        # ParamExecuted (e.g. a minStake change) after S(E): neither PASS nor FAIL is provable,
        # including the below-minStake branch.
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE, 3)
        c.min_stake = STAKE + 1  # latest minStake now above the stake
        param_executed = "ff" * 32  # any registry event not on the no-effect list counts
        c.logs.append({"block": 512_801, "topic0": param_executed})
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertIsNone(body["checks"]["committee"]["ok"], body["checks"]["committee"])
        self.assertEqual(rc, 3)

    def test_committee_ignores_reward_only_events(self):
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE, 3)
        c.logs.append({"block": 512_850, "topic0": pl.REGISTRY_EVENTS_NO_STAKE_EFFECT["RewardCredited(bytes32,uint256,uint256)"]})
        with RpcStub(c) as s:
            _, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertTrue(body["checks"]["committee"]["ok"], body["checks"]["committee"])

    def test_committee_unknown_when_logs_unreadable(self):
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE, 3)
        c.fail_methods.add("eth_getLogs")
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertIsNone(body["checks"]["committee"]["ok"])
        self.assertIn("cannot confirm", body["checks"]["committee"]["state"])
        self.assertEqual(rc, 3)

    def test_committee_log_scan_covers_snapshot_to_head_in_capped_chunks(self):
        c = self.c
        c.head = 513_799  # the longest range: S(513) = block 512,800 still governs block 513,800
        c.add_validator(PK, STAKER, STAKE, 3)
        with RpcStub(c) as s:
            run(s.url, "--staker", STAKER, "--require", "committee")
        q = sorted(c.log_queries)
        self.assertEqual(q[0][0], 512_800)
        self.assertEqual(q[-1][1], 513_799)
        self.assertTrue(all(hi - lo < 1000 for lo, hi in q), q)
        for (_, hi), (lo2, _) in zip(q, q[1:]):
            self.assertEqual(lo2, hi + 1)
        # A change at the end of the range is seen.
        c.logs.append({"block": 513_799, "topic0": "ab" * 32})
        with RpcStub(c) as s:
            _, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertIsNone(body["checks"]["committee"]["ok"])

    # ── the registry reads use `latest` while the head moves ──────────────────────

    def _advance_on_first(self, selector: str, fn):
        """Run fn(chain) once, right before the first eth_call with this selector."""
        fired = []

        def hook(chain, _to, data):
            if not fired and data[2:10] == selector:
                fired.append(1)
                fn(chain)

        return hook

    def test_committee_stake_change_after_the_head_read_is_not_missed(self):
        # Below minStake at S(513); the stake rises in block head+1, after the head was read
        # but before activeSet() is read. The scan must reach the block the reads could see.
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE - 1, 3)
        c.min_stake = STAKE
        stake_increased = "8a12a1190b63d1c04ed6ccb47df714257f26e7f702cbff29ca2c079eac2e4d83"

        def raise_stake(chain):
            chain.head += 1
            chain.validators[PK]["stake"] = STAKE
            chain.logs.append({"block": chain.head, "topic0": stake_increased})

        c.on_call = self._advance_on_first("fd4665ae", raise_stake)  # activeSet()
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        com = body["checks"]["committee"]
        self.assertIsNone(com["ok"], com)
        self.assertEqual(rc, 3)
        self.assertIn("changed after snapshot S(513)", com["state"])
        self.assertEqual(max(hi for _, hi in c.log_queries), 512_901, c.log_queries)

    def test_committee_passes_when_the_head_only_advances(self):
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE, 3)

        def advance(chain):
            chain.head += 3

        c.on_call = self._advance_on_first("fd4665ae", advance)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertTrue(body["checks"]["committee"]["ok"], body["checks"]["committee"])
        self.assertEqual(rc, 0)
        self.assertEqual(max(hi for _, hi in c.log_queries), 512_903)

    def test_committee_unknown_on_a_reorg_during_the_reads(self):
        c = self.c
        c.head = 512_900
        c.add_validator(PK, STAKER, STAKE, 3)

        def reorg(chain):
            chain.hash_override[512_900] = "0x" + "ee" * 32

        c.on_call = self._advance_on_first("fd4665ae", reorg)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        com = body["checks"]["committee"]
        self.assertIsNone(com["ok"], com)
        self.assertIn("reorganisation", com["state"])
        self.assertEqual(rc, 3)

    def test_committee_unknown_when_the_reads_cross_a_snapshot_boundary(self):
        c = self.c
        c.head = 512_799  # the next block follows S(512); from 512,801 S(513) governs
        c.add_validator(PK, STAKER, STAKE, 3)

        def advance(chain):
            chain.head += 2

        c.on_call = self._advance_on_first("fd4665ae", advance)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        com = body["checks"]["committee"]
        self.assertIsNone(com["ok"], com)
        self.assertIn("snapshot boundary", com["state"])
        self.assertEqual(rc, 3)

    def test_small_committee_is_flagged(self):
        c = FakeChain()
        c.add_validator(PK, STAKER, STAKE, 3)
        with RpcStub(c) as s:
            _, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertIn("finality needs at least 4", body["checks"]["committee"]["state"])

    def test_unregistered_staker(self):
        with RpcStub(self.c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER)
        self.assertEqual(rc, 1)
        self.assertEqual(body["checks"]["registered"]["state"], "Not a validator")

    def test_exiting_and_slashed(self):
        for status in ("Exiting", "Slashed"):
            c = FakeChain()
            others(c)
            c.add_validator(PK, STAKER, STAKE, 3, status=status)
            with RpcStub(c) as s:
                rc, body, _ = run(s.url, "--pubkey", PK)
            self.assertEqual(rc, 1)
            self.assertEqual(body["checks"]["registered"]["state"], status)

    def test_coinbase_other_than_staker_fails_producing(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        c.producers[c.head] = (PK, "0x" + "ee" * 20)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER)
        self.assertEqual(rc, 1)
        self.assertIn("coinbase", body["checks"]["producing"]["state"])

    def test_wrong_staker_for_pubkey(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--pubkey", PK, "--staker", "0x" + "d2" * 20, "--require", "registered")
        self.assertEqual(rc, 1)
        self.assertIn("registered staker is", body["checks"]["registered"]["state"])

    def test_not_producing_is_not_the_same_as_unknown(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER, "--window", "100")
        self.assertEqual(rc, 1)
        self.assertIn("not seen producing in the last 100 blocks", body["checks"]["producing"]["state"])

    def test_registry_read_failure_is_unknown_exit_3(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        c.fail_methods.add("eth_call")
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER)
        self.assertEqual(rc, 3)
        self.assertIsNone(body["checks"]["registered"]["ok"])

    def test_wrong_network_fails(self):
        c = self.c
        c.genesis = "0x" + "99" * 32
        with RpcStub(c) as s:
            rc, body, _ = run(s.url, "--staker", STAKER)
        self.assertEqual(rc, 1)
        self.assertIn("genesis", body["checks"]["network"]["state"])

    def test_finalized_height_reported(self):
        c = self.c
        c.add_validator(PK, STAKER, STAKE, 3)
        c.finalized = c.head - 10
        with RpcStub(c) as s:
            _, body, _ = run(s.url, "--staker", STAKER, "--require", "committee")
        self.assertEqual(body["network"]["finalized_height"], c.head - 10)
        self.assertIn(f"finalized height {c.head - 10}", body["checks"]["committee"]["state"].lower())

    def test_dry_run_makes_no_requests(self):
        c = self.c
        with RpcStub(c) as s:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = v.main(["--profile", "rehearsal-1", "--rpc", s.url, "--staker", STAKER, "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertEqual(s.requests, [])
        self.assertIn("validatorInfo", out.getvalue())

    def test_input_validation(self):
        for argv in (["--profile", "40204-r1005"], ["--profile", "40204-r1005", "--staker", STAKER, "--require", "bogus"]):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(v.main(argv), 2)


if __name__ == "__main__":
    unittest.main()
