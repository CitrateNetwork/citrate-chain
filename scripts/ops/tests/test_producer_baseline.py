"""Tests for scripts/ops/producer_baseline.sh.

The script provisions real hosts, so `apply` and `check` are proven on the hosts
themselves (PR evidence). These tests cover what can run without touching this
machine: the disk alert it installs, the node unit template it installs, and a
tripwire that the script can never change the state of citrate-node.

Run: python3 -m unittest discover -s scripts/ops/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ops/producer_baseline.sh"
GEN = ROOT / "scripts/producers/gen_node_config.py"

# A systemctl verb that changes a unit's state, aimed at citrate-node.
STATE_CHANGE = re.compile(
    r"systemctl\b[^\n#|;&]*\b(enable|disable|start|stop|restart|reload|kill|mask|try-restart|reload-or-restart)\b"
    r"[^\n#|;&]*\bcitrate-node\b"
)
# Reading anything inside a keys dir or a *.key file.
KEY_READ = re.compile(r"\b(cat|less|head|tail|xxd|od|base64|cp|scp|rsync)\b[^\n#]*(/keys\b|\.key\b)")


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir()}
    e.update(env or {})
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=60)


class DiskAlertTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dgx-baseline-")
        self.alert = Path(self.tmp) / "citrate-disk-alert"
        out = run("print-disk-alert")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.alert.write_text(out.stdout)
        self.alert.chmod(0o755)

    def tearDown(self) -> None:
        if self.alert.exists():
            self.alert.unlink()
        os.rmdir(self.tmp)

    def alert_run(self, pct: str, paths: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "CITRATE_DISK_ALERT_PCT": pct,
            "CITRATE_DISK_ALERT_PATHS": paths,
            "CITRATE_DISK_ALERT_SYSLOG": "0",  # never write to this host's journal
        }
        return subprocess.run([str(self.alert)], capture_output=True, text=True, env=env, timeout=30)

    def test_alerts_loudly_at_threshold(self) -> None:
        r = self.alert_run("0", self.tmp)  # every filesystem is >= 0% used
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("DISK ALERT", r.stderr)
        self.assertIn("threshold 0%", r.stderr)

    def test_quiet_below_threshold(self) -> None:  # negative control
        r = self.alert_run("101", self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("DISK ALERT", r.stdout + r.stderr)
        self.assertIn("ok ", r.stdout)

    def test_bad_threshold_is_refused(self) -> None:
        for bad in ("", "80%", "-1", "eighty"):
            r = self.alert_run(bad, self.tmp) if bad else self.alert_run("x", self.tmp)
            self.assertEqual(r.returncode, 2, f"{bad!r}: {r.stdout}{r.stderr}")

    def test_missing_path_is_skipped_and_mounts_deduplicated(self) -> None:
        r = self.alert_run("101", f"{self.tmp}/does-not-exist {self.tmp} {self.tmp}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("ok "), 1, r.stdout)


class UnitTemplateTest(unittest.TestCase):
    def template(self) -> str:
        r = run("print-unit")
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_unit_runs_as_citrate_and_always_restarts(self) -> None:
        t = self.template()
        for line in (
            "User=citrate",
            "Group=citrate",
            "Restart=always",
            "LimitNOFILE=65536",
            "ExecStart=/usr/local/bin/citrate-node --config /etc/citrate/node.toml",
            "EnvironmentFile=/etc/citrate/citrate-node.env",
            "ReadWritePaths=/var/lib/citrate/data",
        ):
            self.assertIn(line + "\n", t)

    def test_unit_matches_gen_node_config(self) -> None:
        if not GEN.exists():
            self.skipTest("scripts/producers/gen_node_config.py is not on this tree yet")
        spec = importlib.util.spec_from_file_location("gen_node_config", GEN)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        want = mod.render_unit(mod.DEFAULT_OUT, mod.DEFAULT_DATA, mod.DEFAULT_BIN)
        self.assertEqual(self.template(), want)


class TripwireTest(unittest.TestCase):
    def test_script_never_changes_citrate_node_state(self) -> None:
        src = SCRIPT.read_text()
        hits = [l for l in src.splitlines() if STATE_CHANGE.search(l)]
        self.assertEqual(hits, [], "producer_baseline.sh must not enable/start/stop citrate-node")

    def test_script_never_reads_keys(self) -> None:
        src = SCRIPT.read_text()
        hits = [l for l in src.splitlines() if KEY_READ.search(l)]
        self.assertEqual(hits, [])

    def test_tripwires_detect_their_class(self) -> None:  # negative controls
        for bad in (
            "systemctl enable --now citrate-node",
            "  systemctl restart citrate-node.service",
            "systemctl disable citrate-node >/dev/null",
        ):
            self.assertTrue(STATE_CHANGE.search(bad), bad)
        for fine in (
            "systemctl is-enabled citrate-node",
            "systemctl is-active citrate-node",
            "systemctl enable --now citrate-disk-alert.timer",
        ):
            self.assertFalse(STATE_CHANGE.search(fine), fine)
        self.assertTrue(KEY_READ.search("cat /opt/citrate/keys/proposer.key"))
        self.assertTrue(KEY_READ.search("cp /var/lib/citrate/data/noise.key /root/"))
        self.assertFalse(KEY_READ.search("install -d -m 0700 /opt/citrate/keys"))

    def test_syntax_and_usage(self) -> None:
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)]).returncode, 0)
        self.assertEqual(run().returncode, 2)
        self.assertEqual(run("bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
