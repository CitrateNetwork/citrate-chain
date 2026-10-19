#!/usr/bin/env python3
"""Unit tests for verification/check_claims.py's checkpoint-finality tripwire.

Offline, stdlib only. Each case builds a minimal tree in a temporary directory
(gadget pin tables, a node file, claims.json, an empty address book) and runs
the same `check()` CI runs. The last case runs it against this repository.

Run: python3 -m unittest discover -s verification/tests
"""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))

import check_claims  # noqa: E402

GADGET_TMPL = """
pub const CHECKPOINT_VOTING_PINS: &[(u64, bool)] = &[(40204, {voting})];
pub const CHECKPOINT_ENFORCEMENT_PINS: &[(u64, bool)] = &[(40204, {enforcement})];

pub fn on_buried(key: &Key) {{
    {sign}
}}

#[cfg(test)]
mod tests {{
    fn t() {{ let _ = sign_checkpoint_vote(40204, 2, h, &k); }}
}}
"""

SIGN_CALL = "let vote = sign_checkpoint_vote(chain_id, height, block_hash, key);"

DRIVER_BUILDS = """
fn to_message(vote: &CheckpointVote) -> NetworkMessage {
    NetworkMessage::CheckpointVote {
        height: vote.height,
        block_hash: vote.block_hash,
        voter_pubkey: vote.voter.as_bytes().to_vec(),
        signature: vote.signature.as_bytes().to_vec(),
    }
}
pub async fn broadcast_votes(peers: &PeerManager, votes: &[CheckpointVote]) {
    for vote in votes {
        let _ = peers.broadcast(&to_message(vote)).await;
    }
}
"""

INBOUND_ONLY = """
async fn handle(msg: NetworkMessage, pm: &PeerManager) {
    match msg {
        NetworkMessage::CheckpointVote {
            height,
            block_hash,
            voter_pubkey,
            signature,
        } => {
            let _ = (height, block_hash, voter_pubkey, signature);
        }
        other => { let _ = pm.broadcast(&other).await; }
    }
}
"""


def claims(running: bool) -> dict:
    status = "measured-here" if running else "specified-not-running"
    finality = "deterministic checkpoint" if running else "probabilistic (checkpoint committee specified, not running)"
    return {
        "claims": {
            "deterministic_checkpoint_finality": {"value": {"running": running}, "verification_status": status},
            "consensus_ghostdag": {"value": {"finality": finality}},
            "confirmation_latency": {"value": {"deterministic_checkpoint_seconds_estimate": None}},
        }
    }


class Tree:
    """A throwaway source tree for one case."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.write("contracts/addresses/40204.json", "{}")

    def close(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))

    def gadget(self, voting: bool, enforcement: bool, sign: bool = True) -> None:
        self.write(
            check_claims.GADGET,
            GADGET_TMPL.format(
                voting=str(voting).lower(),
                enforcement=str(enforcement).lower(),
                sign=SIGN_CALL if sign else "",
            ),
        )

    def claim(self, running: bool) -> None:
        self.write("verification/claims.json", json.dumps(claims(running)))

    def check(self) -> tuple[list[str], list[str]]:
        return check_claims.check(self.root)


class FinalityTripwire(unittest.TestCase):
    def setUp(self) -> None:
        self.t = Tree()

    def tearDown(self) -> None:
        self.t.close()

    def test_pins_off_is_not_running_and_honest_claim_passes(self) -> None:
        self.t.gadget(voting=False, enforcement=False)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=False)
        ev = check_claims.finality_evidence(self.t.root, [])
        self.assertFalse(ev["running"])
        self.assertTrue(ev["sign_callers"], "the production signer is still found")
        self.assertEqual(ev["outbound_files"], ["node/src/finality_driver.rs"])
        errs, warns = self.t.check()
        self.assertEqual(errs, [])
        self.assertEqual(warns, [])

    def test_running_claim_with_pins_off_fails(self) -> None:
        self.t.gadget(voting=False, enforcement=False)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=True)
        errs, _ = self.t.check()
        self.assertTrue(errs and "asserts a running mechanism" in errs[0], errs)
        self.assertIn("CHECKPOINT_VOTING_PINS is not ON", errs[0])
        self.assertIn("CHECKPOINT_ENFORCEMENT_PINS is not ON", errs[0])

    def test_voting_on_enforcement_off_is_not_running(self) -> None:
        self.t.gadget(voting=True, enforcement=False)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=True)
        errs, _ = self.t.check()
        self.assertTrue(errs and "asserts a running mechanism" in errs[0], errs)
        self.assertIn("CHECKPOINT_ENFORCEMENT_PINS is not ON", errs[0])
        self.assertNotIn("CHECKPOINT_VOTING_PINS", errs[0])

    def test_everything_on_is_running(self) -> None:
        self.t.gadget(voting=True, enforcement=True)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=True)
        errs, warns = self.t.check()
        self.assertEqual(errs, [])
        self.assertEqual(warns, [])

    def test_running_code_with_stale_claim_warns(self) -> None:
        self.t.gadget(voting=True, enforcement=True)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=False)
        errs, warns = self.t.check()
        self.assertEqual(errs, [])
        self.assertEqual(len(warns), 1, warns)
        self.assertIn("pinned ON", warns[0])

    def test_test_only_signer_does_not_count(self) -> None:
        self.t.gadget(voting=True, enforcement=True, sign=False)
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=True)
        self.assertEqual(check_claims.production_sign_callers(self.t.root), [])
        errs, _ = self.t.check()
        self.assertTrue(errs and "asserts a running mechanism" in errs[0], errs)
        self.assertIn("sign_checkpoint_vote(", errs[0])

    def test_inbound_match_arm_is_not_an_outbound_path(self) -> None:
        self.t.gadget(voting=True, enforcement=True)
        self.t.write("node/src/main.rs", INBOUND_ONLY)
        self.t.claim(running=True)
        self.assertEqual(check_claims.outbound_vote_files(self.t.root), [])
        errs, _ = self.t.check()
        self.assertTrue(errs and "asserts a running mechanism" in errs[0], errs)
        self.assertIn("builds NetworkMessage::CheckpointVote", errs[0])

    def test_commented_out_pin_and_missing_table_are_off_with_warning(self) -> None:
        self.t.write(
            check_claims.GADGET,
            "// pub const CHECKPOINT_VOTING_PINS: &[(u64, bool)] = &[(40204, true)];\n"
            "pub const CHECKPOINT_ENFORCEMENT_PINS: &[(u64, bool)] = &[(40204, true)];\n"
            "fn f() { " + SIGN_CALL + " }\n",
        )
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=False)
        errs, warns = self.t.check()
        self.assertEqual(errs, [])
        self.assertTrue(any("CHECKPOINT_VOTING_PINS not found" in w for w in warns), warns)
        ev = check_claims.finality_evidence(self.t.root, [])
        self.assertFalse(ev["voting_pin"])
        self.assertTrue(ev["enforcement_pin"])
        self.assertFalse(ev["running"])

    def test_missing_gadget_file_is_off_with_warning(self) -> None:
        self.t.write("node/src/finality_driver.rs", DRIVER_BUILDS)
        self.t.claim(running=False)
        errs, warns = self.t.check()
        self.assertEqual(errs, [])
        self.assertEqual(len([w for w in warns if "not found" in w]), 2, warns)

    def test_other_chain_pinned_on_does_not_count(self) -> None:
        self.t.write(
            check_claims.GADGET,
            "pub const CHECKPOINT_VOTING_PINS: &[(u64, bool)] = &[(1337, true), (40204, false)];\n"
            "pub const CHECKPOINT_ENFORCEMENT_PINS: &[(u64, bool)] = &[(1337, true)];\n",
        )
        warns: list[str] = []
        self.assertFalse(check_claims.pin_on(self.t.root, check_claims.VOTING_PINS, 40204, warns))
        self.assertFalse(check_claims.pin_on(self.t.root, check_claims.ENFORCEMENT_PINS, 40204, warns))
        self.assertTrue(check_claims.pin_on(self.t.root, check_claims.VOTING_PINS, 1337, warns))
        self.assertEqual(warns, [])


class ThisRepository(unittest.TestCase):
    def test_repository_passes_and_finality_is_not_running(self) -> None:
        errs, _ = check_claims.check(REPO)
        self.assertEqual(errs, [])
        ev = check_claims.finality_evidence(REPO, [])
        self.assertFalse(ev["voting_pin"], "40204 voting is pinned OFF in this release")
        self.assertFalse(ev["enforcement_pin"], "40204 enforcement is pinned OFF in this release")
        self.assertFalse(ev["running"])
        self.assertIn("node/src/finality_driver.rs", ev["outbound_files"])
        self.assertNotIn("node/src/main.rs", ev["outbound_files"], "inbound handler only")


if __name__ == "__main__":
    unittest.main()
