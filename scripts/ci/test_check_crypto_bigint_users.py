#!/usr/bin/env python3
"""Self-test for check-crypto-bigint-users.py (the RUSTSEC-2026-0387 ignore guard).

The fixture lockfiles are the negative controls: a new direct parent of an
unpatched crypto-bigint must fail, as must an expired or stale ignore.

  python3 <dir>/test_check_crypto_bigint_users.py
"""
import datetime as dt
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures" / "crypto-bigint"
_spec = importlib.util.spec_from_file_location("guard", HERE / "check-crypto-bigint-users.py")
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

ALLOWED = frozenset({"elliptic-curve"})
BEFORE = guard.EXPIRES
AFTER = guard.EXPIRES + dt.timedelta(days=1)
PRESENT = [FIX / "ignore-present.toml"]
ABSENT = [FIX / "ignore-absent.toml"]


def run(locks, ignores=PRESENT, today=BEFORE):
    errors, _ = guard.check([FIX / n for n in locks], ignores, ALLOWED, today)
    return errors


class GuardSelfTest(unittest.TestCase):
    def test_allowlisted_parent_passes(self):
        self.assertEqual(run(["allowed.lock"]), [])

    def test_new_direct_parent_fails(self):
        errors = run(["new-parent.lock"])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("rsa-like -> crypto-bigint 0.5.5", errors[0])

    def test_patched_version_users_are_ignored(self):
        self.assertEqual(run(["multi-version-ok.lock"]), [])

    def test_unpatched_0_7_with_explicit_version_and_source_fails(self):
        errors = run(["multi-version-bad.lock"])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("sneaky -> crypto-bigint 0.7.3", errors[0])

    def test_every_lockfile_is_checked(self):
        errors = run(["allowed.lock", "new-parent.lock"])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("new-parent.lock", errors[0])

    def test_expired_ignore_fails(self):
        errors = run(["allowed.lock"], today=AFTER)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("expired on 2027-01-31", errors[0])

    def test_expiry_day_itself_still_passes(self):
        self.assertEqual(run(["allowed.lock"], today=guard.EXPIRES), [])

    def test_removed_ignore_does_not_trip_expiry(self):
        self.assertEqual(run(["allowed.lock"], ignores=ABSENT, today=AFTER), [])

    def test_stale_ignore_fails(self):
        errors = run(["patched-only.lock"])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("stale", errors[0])

    def test_patched_only_without_ignore_passes(self):
        self.assertEqual(run(["patched-only.lock"], ignores=ABSENT), [])

    def test_cli_exit_codes(self):
        base = ["--allow", "elliptic-curve", "--ignore-file", str(PRESENT[0])]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(guard.main(base + ["--lockfile", str(FIX / "allowed.lock")]), 0)
            self.assertEqual(guard.main(base + ["--lockfile", str(FIX / "new-parent.lock")]), 1)
            self.assertEqual(
                guard.main(base + ["--lockfile", str(FIX / "allowed.lock"), "--today", AFTER.isoformat()]), 1
            )

    def test_repo_config_points_at_real_ignores(self):
        root = guard.repo_root()
        self.assertTrue(guard.IGNORE_FILES, "IGNORE_FILES is empty")
        for rel in guard.IGNORE_FILES:
            self.assertTrue((root / rel).is_file(), rel)
        self.assertEqual(guard.ALLOWED, ALLOWED)

    def test_repo_passes_today(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(guard.main([]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
