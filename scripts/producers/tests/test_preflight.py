"""Tests for preflight.py on a fake host root with scripted command output."""

import argparse
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import preflight as pf  # noqa: E402

GOOD_CMDS = {
    "timedatectl": (0, "yes\n"),
    "sshd": (0, "passwordauthentication no\npermitrootlogin prohibit-password\nkbdinteractiveauthentication no\n"),
    "ufw": (0, "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n30303/tcp                  ALLOW       Anywhere\n"),
    "ss": (0, "LISTEN 0 128 127.0.0.1:8545 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:30303 0.0.0.0:*\n"),
    "env": (0, '2026 INFO x\n{\n  "fingerprint": "0xabc"\n}\n'),
}


def make_root(t: Path, uid: int, mem_kb: int = 33_000_000) -> Path:
    (t / "etc/systemd").mkdir(parents=True)
    (t / "proc").mkdir()
    (t / "etc/os-release").write_text('PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n')
    (t / "proc/meminfo").write_text(f"MemTotal:       {mem_kb} kB\n")
    (t / "proc/mounts").write_text("/dev/sda1 / ext4 rw 0 0\n")
    (t / "etc/passwd").write_text(f"root:x:0:0::/root:/bin/bash\ncitrate:x:{uid}:{uid}::/var/lib/citrate:/bin/bash\n")
    (t / "etc/systemd/journald.conf").write_text("[Journal]\nSystemMaxUse=1G\n")
    data = t / "var/lib/citrate/data"
    data.mkdir(parents=True)
    data.chmod(0o700)
    return data


def args(**kw):
    base = dict(data_dir="/var/lib/citrate/data", user="citrate", binary="/usr/local/bin/citrate-node",
                p2p_port=30303, expect_sha256=None, expect_fingerprint=None, offline=True)
    base.update(kw)
    return argparse.Namespace(**base)


def host(root: Path, cmds=None, cpus=8, arch="x86_64", is_root=True):
    table = dict(GOOD_CMDS, **(cmds or {}))
    return pf.Host(
        root=root,
        run=lambda cmd: table.get(cmd[0], (127, "not installed")),
        cpu_count=lambda: cpus,
        machine=lambda: arch,
        is_root=lambda: is_root,
    )


def levels(rep):
    return {r["check"]: r["level"] for r in rep.rows}


class TestPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = make_root(self.root, os.getuid())
        pf.THRESHOLDS["min_disk_free_gib"] = 0  # the test tmpfs is small; disk logic tested below

    def tearDown(self):
        self.tmp.cleanup()
        pf.THRESHOLDS["min_disk_free_gib"] = 100

    def test_good_host_has_no_failures(self):
        rep = pf.run(host(self.root), args(), None)
        self.assertFalse(rep.failed, rep.rows)
        lv = levels(rep)
        for c in ("arch", "os", "cpu", "memory", "clock", "user", "data-dir", "ssh", "firewall", "listeners", "journald"):
            self.assertEqual(lv[c], "PASS", c)

    def test_small_host_fails(self):
        (self.root / "proc/meminfo").write_text("MemTotal:  4000000 kB\n")
        rep = pf.run(host(self.root, cpus=2, arch="riscv64"), args(), None)
        lv = levels(rep)
        self.assertEqual(lv["cpu"], "FAIL")
        self.assertEqual(lv["memory"], "FAIL")
        self.assertEqual(lv["arch"], "FAIL")
        self.assertTrue(rep.failed)

    def test_disk_threshold(self):
        pf.THRESHOLDS["min_disk_free_gib"] = 10**9
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["disk"], "FAIL")

    def test_tmpfs_data_dir_fails(self):
        (self.root / "proc/mounts").write_text("tmpfs /var/lib/citrate tmpfs rw 0 0\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["disk-type"], "FAIL")

    def test_clock_not_synced_fails(self):
        rep = pf.run(host(self.root, {"timedatectl": (0, "no\n")}), args(), None)
        self.assertEqual(levels(rep)["clock"], "FAIL")

    def test_root_service_user_fails(self):
        (self.root / "etc/passwd").write_text("citrate:x:0:0::/:/bin/sh\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["user"], "FAIL")

    def test_loose_data_dir_and_key_modes_fail_without_reading_keys(self):
        self.data.chmod(0o755)
        key = self.data / "proposer.key"
        key.write_bytes(b"\x01" * 32)
        key.chmod(0o644)
        lv = levels(pf.run(host(self.root), args(), None))
        self.assertEqual(lv["data-dir"], "FAIL")
        self.assertEqual(lv["proposer.key"], "FAIL")
        key.chmod(0o000)  # unreadable: the check must still work (stat only)
        self.data.chmod(0o700)
        lv = levels(pf.run(host(self.root), args(), None))
        self.assertEqual(lv["proposer.key"], "PASS")

    def test_wrong_size_proposer_key_fails(self):
        key = self.data / "proposer.key"
        key.write_bytes(b"\x01" * 31)
        key.chmod(0o600)
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["proposer.key"], "FAIL")

    def test_ssh_password_login_fails(self):
        rep = pf.run(host(self.root, {"sshd": (0, "passwordauthentication yes\npermitrootlogin yes\n")}), args(), None)
        self.assertEqual(levels(rep)["ssh"], "FAIL")

    def test_rpc_exposed_fails(self):
        cmds = {
            "ufw": (0, "Status: active\n\n8545                       ALLOW       Anywhere\n"),
            "ss": (0, "LISTEN 0 128 0.0.0.0:8545 0.0.0.0:*\n"),
        }
        lv = levels(pf.run(host(self.root, cmds), args(), None))
        self.assertEqual(lv["firewall"], "FAIL")
        self.assertEqual(lv["listeners"], "FAIL")

    def test_p2p_closed_and_firewall_inactive_fail(self):
        lv = levels(pf.run(host(self.root, {"ufw": (0, "Status: active\n22/tcp ALLOW Anywhere\n")}), args(), None))
        self.assertEqual(lv["firewall"], "FAIL")
        lv = levels(pf.run(host(self.root, {"ufw": (0, "Status: inactive\n")}), args(), None))
        self.assertEqual(lv["firewall"], "FAIL")

    def test_not_root_is_unknown_not_pass(self):
        lv = levels(pf.run(host(self.root, is_root=False), args(), None))
        self.assertEqual(lv["ssh"], "UNKNOWN")

    def test_binary_hash_and_fingerprint(self):
        binp = self.root / "usr/local/bin/citrate-node"
        binp.parent.mkdir(parents=True)
        binp.write_bytes(b"binary")
        import hashlib

        good = hashlib.sha256(b"binary").hexdigest()
        lv = levels(pf.run(host(self.root), args(expect_sha256=good, expect_fingerprint="0xABC"), None))
        self.assertEqual(lv["binary-sha256"], "PASS")
        self.assertEqual(lv["fingerprint"], "PASS")
        lv = levels(pf.run(host(self.root), args(expect_sha256="00" * 32, expect_fingerprint="0xdef"), None))
        self.assertEqual(lv["binary-sha256"], "FAIL")
        self.assertEqual(lv["fingerprint"], "FAIL")

    def test_rejected_binary_is_never_executed(self):
        binp = self.root / "usr/local/bin/citrate-node"
        binp.parent.mkdir(parents=True)
        binp.write_bytes(b"tampered")
        seen = []
        h = host(self.root)
        inner = h.run

        def recording(cmd):
            seen.append(list(cmd))
            return inner(cmd)

        h.run = recording
        rep = pf.run(h, args(expect_sha256="00" * 32, expect_fingerprint="0xABC"), None)
        lv = levels(rep)
        self.assertEqual(lv["binary-sha256"], "FAIL")
        self.assertEqual(lv["fingerprint"], "FAIL")
        self.assertTrue(rep.failed)
        self.assertFalse(
            any(str(binp) in cmd for cmd in seen),
            f"the rejected binary reached the command runner: {seen}",
        )
        # A matching hash does execute it (once) for the fingerprint.
        import hashlib

        seen.clear()
        pf.run(h, args(expect_sha256=hashlib.sha256(b"tampered").hexdigest()), None)
        self.assertTrue(any(str(binp) in cmd for cmd in seen), seen)

    def test_missing_journal_cap_warns(self):
        (self.root / "etc/systemd/journald.conf").write_text("[Journal]\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["journald"], "WARN")
        d = self.root / "etc/systemd/journald.conf.d"
        d.mkdir()
        (d / "cap.conf").write_text("[Journal]\nSystemMaxUse=2G\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["journald"], "PASS")

    def test_journal_cap_last_assignment_wins(self):
        (self.root / "etc/systemd/journald.conf").write_text("[Journal]\nSystemMaxUse=1G\n")
        d = self.root / "etc/systemd/journald.conf.d"
        d.mkdir()
        (d / "z-reset.conf").write_text("[Journal]\nSystemMaxUse=\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["journald"], "WARN")
        (d / "z-reset.conf").write_text("[Journal]\nSystemMaxUse=infinity\n")
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["journald"], "WARN")

    def test_unreadable_journal_dropin_is_unknown_not_pass(self):
        (self.root / "etc/systemd/journald.conf").write_text("[Journal]\nSystemMaxUse=1G\n")
        d = self.root / "etc/systemd/journald.conf.d"
        d.mkdir()
        (d / "broken.conf").mkdir()  # reading it raises OSError (IsADirectoryError), even as root
        self.assertEqual(levels(pf.run(host(self.root), args(), None))["journald"], "UNKNOWN")

    def test_dry_run_lists_checks(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = pf.main(["--profile", "rehearsal-1", "--dry-run"])
        self.assertEqual(rc, 0)
        for name, _, _ in pf.CHECKS:
            self.assertIn(name, out.getvalue())


if __name__ == "__main__":
    unittest.main()
