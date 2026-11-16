"""Tests for stamp_genesis.py (no cargo: the re-pin step is exercised with a given hash).

  python3 -m unittest scripts/genesis/r1007/test_stamp_genesis.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHAIN = HERE.parents[2]
sys.path.insert(0, str(HERE))
import stamp_genesis as S  # noqa: E402


class Stamp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        for rel in (S.R1007_RS, S.HARDENING):
            (self.tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(CHAIN / rel, self.tmp / rel)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stamp_sets_the_timestamp_and_only_it(self):
        before = (self.tmp / S.R1007_RS).read_text()
        S.set_timestamp(self.tmp, 1_800_000_123)
        after = (self.tmp / S.R1007_RS).read_text()
        self.assertEqual(S.read_timestamp(self.tmp), 1_800_000_123)
        self.assertEqual(len(before.splitlines()), len(after.splitlines()))
        changed = [a for a, b in zip(before.splitlines(), after.splitlines()) if a != b]
        self.assertEqual(len(changed), 1, changed)

    def test_repin_writes_the_hash_into_hardening(self):
        h = "ab" * 32
        S.repin(self.tmp, "0x" + h)
        self.assertIn(f'hex32("{h}")', (self.tmp / S.HARDENING).read_text())
        with self.assertRaises(S.StampError):
            S.repin(self.tmp, "0x1234")

    def test_a_timestamp_must_be_plausible(self):
        for bad in (0, 1_600_000_000, 10**11):
            with self.assertRaises(S.StampError):
                S.set_timestamp(self.tmp, bad)


if __name__ == "__main__":
    unittest.main()
