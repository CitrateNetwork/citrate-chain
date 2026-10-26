"""Tests for scripts/ops/producer_baseline.sh.

The script provisions real hosts, so a full `apply` and `check` is proven on the
hosts themselves (PR evidence). These tests cover what can run without touching
this machine: the disk alert and the node unit it installs, tripwires (it never
changes the state of citrate-node), and behavioural tests of the apply steps.

The behavioural tests source the script in library mode (PRODUCER_BASELINE_LIB=1)
with every path under a temp root (PRODUCER_BASELINE_ROOT) and PATH shims for
ufw, sshd, systemctl, apt-get, install, chown, getent, id, useradd, groupadd and
curl. Each shim appends its argv to a call log in the temp dir, so the tests
assert what ran and in what order. Nothing outside the temp dir is written.

Run: python3 -m unittest discover -s scripts/ops/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
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

    def test_unit_caps_node_memory_for_an_8gb_host(self) -> None:
        t = self.template()
        for line in ("MemoryHigh=6G", "MemoryMax=6656M", "MemorySwapMax=1G"):
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


GOOD_UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
30303/tcp                  ALLOW IN    Anywhere
30303/udp                  ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
30303/tcp (v6)             ALLOW IN    Anywhere (v6)
30303/udp (v6)             ALLOW IN    Anywhere (v6)
"""


class FirewallTest(unittest.TestCase):
    def verdict(self, text: str) -> subprocess.CompletedProcess[str]:
        e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir()}
        return subprocess.run(["bash", str(SCRIPT), "check-ufw-status"], input=text,
                              capture_output=True, text=True, env=e, timeout=30)

    def test_runbook_policy_passes(self) -> None:
        r = self.verdict(GOOD_UFW)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_policy_violations_fail(self) -> None:  # negative controls
        bad = {
            "inactive": GOOD_UFW.replace("Status: active", "Status: inactive"),
            "allow incoming": GOOD_UFW.replace("deny (incoming)", "allow (incoming)"),
            "deny outgoing": GOOD_UFW.replace("allow (outgoing)", "deny (outgoing)"),
            "no ssh": GOOD_UFW.replace("22/tcp                     ALLOW IN    Anywhere\n", ""),
            "no p2p udp": GOOD_UFW.replace("30303/udp                  ALLOW IN    Anywhere\n", ""),
            "rpc open": GOOD_UFW + "8545/tcp                   ALLOW IN    Anywhere\n",
            "metrics open": GOOD_UFW + "9090                       ALLOW IN    Anywhere\n",
            "extra port": GOOD_UFW + "80/tcp                     ALLOW IN    Anywhere\n",
            "empty": "",
        }
        for name, text in bad.items():
            r = self.verdict(text)
            self.assertEqual(r.returncode, 1, f"{name}: {r.stdout}{r.stderr}")

    def apply_firewall_body(self) -> list[str]:
        src = SCRIPT.read_text()
        m = re.search(r"^apply_firewall\(\) \{\n(.*?)^\}", src, re.S | re.M)
        self.assertIsNotNone(m, "apply_firewall() not found")
        assert m
        return [l.strip() for l in m.group(1).splitlines() if l.strip() and not l.strip().startswith("#")]

    @staticmethod
    def allow_before_enable(lines: list[str]) -> bool:
        def first(pat: str) -> int:
            return next((i for i, l in enumerate(lines) if re.search(pat, l)), -1)
        enable = first(r"\bufw\b.*\benable\b")
        ssh = first(r"\bufw\b.*\ballow 22/tcp\b")
        return enable >= 0 and 0 <= ssh < enable

    def test_ssh_allowed_before_enable(self) -> None:
        lines = self.apply_firewall_body()
        self.assertTrue(self.allow_before_enable(lines), "ufw allow 22/tcp must come before ufw enable")
        for rule in ("allow 22/tcp", "allow 30303/tcp", "allow 30303/udp", "default deny incoming",
                     "default allow outgoing"):
            self.assertTrue(any(f"ufw {rule}" in l for l in lines), rule)

    def test_order_check_detects_enable_first(self) -> None:  # negative control
        self.assertFalse(self.allow_before_enable(["ufw --force enable", "ufw allow 22/tcp"]))
        self.assertFalse(self.allow_before_enable(["ufw allow 30303/tcp", "ufw --force enable"]))
        self.assertTrue(self.allow_before_enable(["ufw allow 22/tcp", "ufw --force enable"]))


class LayoutTest(unittest.TestCase):
    def test_single_layout_no_opt_citrate_dirs_created(self) -> None:
        src = SCRIPT.read_text()
        self.assertNotRegex(src, r"install -d[^\n]*/opt/citrate")
        self.assertNotRegex(src, r"mkdir[^\n]*/opt/citrate")

    def test_legacy_cleanup_only_rmdir(self) -> None:
        src = SCRIPT.read_text()
        self.assertRegex(src, r"rmdir[^\n]*/opt/citrate")
        # Nothing in the script deletes recursively or by glob.
        self.assertEqual([l for l in src.splitlines() if re.search(r"\brm\s+-[a-zA-Z]*r", l)], [])


# ---- behavioural tests with PATH shims --------------------------------------

SHIM = r"""#!/bin/bash
# Test shim: logs argv, never touches the host.
name="$(basename "$0")"
printf '%s\n' "$name $*" >>"$SHIM_LOG"
case "$name" in
  sshd)
    if [ "${1:-}" = -t ]; then exit "${SHIM_SSHD_T_RC:-0}"; fi
    if [ "${1:-}" = -T ]; then exec cat "$SHIM_DIR/sshd_T"; fi ;;
  systemctl)
    if [ "${1:-}" = is-active ]; then
      for a in "$@"; do [ "$a" = ssh.socket ] && exit "${SHIM_SOCKET_ACTIVE_RC:-3}"; done
      exit 0
    fi
    if [ "${1:-}" = show ]; then echo "${SHIM_SOCKET_LISTEN:-}"; exit 0; fi ;;
  ufw)
    case "${1:-}" in
      allow)
        if [ -n "${SHIM_UFW_FAIL:-}" ] && [ "$2" = "$SHIM_UFW_FAIL" ]; then exit 1; fi
        if [ -z "${SHIM_UFW_DROP:-}" ] || [ "$2" != "$SHIM_UFW_DROP" ]; then
          echo "ufw allow $2" >>"$SHIM_DIR/ufw_added"
        fi ;;
      show)
        echo "Added user rules (see 'ufw status' for running firewall):"
        cat "$SHIM_DIR/ufw_added" 2>/dev/null ;;
      status) echo "Status: inactive" ;;
    esac ;;
  install)
    args=()
    while [ $# -gt 0 ]; do
      case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    exec /usr/bin/install "${args[@]}" ;;
  getent)
    if [ "$1" = passwd ]; then grep "^$2:" "$SHIM_DIR/passwd"; exit; fi
    exit 0 ;;
  id)
    if [ "$*" = "-u" ]; then echo 0; else echo 996; fi ;;
  curl) exit 7 ;;
esac
exit 0
"""
SHIMMED = ("sshd", "systemctl", "ufw", "apt-get", "install", "chown", "getent", "id",
           "useradd", "groupadd", "curl", "sysctl", "swapon", "timedatectl", "chronyc")
DEFAULT_SSHD_T = (
    "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n"
    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
    "passwordauthentication no\n"
    # Real `sshd -T` prints ~150 lines; pad well past a pipe buffer so a reader
    # that stops early (awk exit, grep -q) makes sshd die of SIGPIPE under pipefail.
    + "".join(f"x11displayoffset{i} 10\n" for i in range(20000))
)


class Sandbox:
    """A temp root, a shim bin dir and a call log. Removed in cleanup()."""

    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="dgx-pbshim-"))
        self.root = self.tmp / "root"
        self.bin = self.tmp / "bin"
        self.log = self.tmp / "calls.log"
        for d in (self.root, self.bin, self.tmp / "t", self.tmp / "home",
                  self.root / "root/.ssh", self.root / "home/alice/.ssh"):
            d.mkdir(parents=True)
        shim = self.bin / "_shim"
        shim.write_text(SHIM)
        shim.chmod(0o755)
        for n in SHIMMED:
            (self.bin / n).symlink_to("_shim")
        (self.tmp / "sshd_T").write_text(DEFAULT_SSHD_T)
        (self.tmp / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text("ID=ubuntu\nPRETTY_NAME=test\n")
        (self.root / "etc/logrotate.conf").write_text("weekly\ninclude /etc/logrotate.d\n")
        self.log.write_text("")

    def add_key(self, user_home: str = "root", name: str = "authorized_keys") -> None:
        kdir = self.tmp / "k"
        kdir.mkdir(exist_ok=True)
        key = kdir / "id"
        if not key.exists():  # throwaway key, never leaves the temp dir
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(key)],
                           check=True, capture_output=True)
        (self.root / user_home / ".ssh" / name).write_text("no-pty " + (kdir / "id.pub").read_text())

    def run(self, body: str, **env: str) -> subprocess.CompletedProcess[str]:
        e = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.tmp / "home"),
            "TMPDIR": str(self.tmp / "t"),
            "PRODUCER_BASELINE_LIB": "1",
            "PRODUCER_BASELINE_ROOT": str(self.root),
            "SHIM_LOG": str(self.log),
            "SHIM_DIR": str(self.tmp),
        }
        e.update(env)
        return subprocess.run(["bash", "-c", f'source "$1"; {body}', "harness", str(SCRIPT)],
                              capture_output=True, text=True, env=e, timeout=60)

    def calls(self, prog: str | None = None) -> list[str]:
        lines = [l for l in self.log.read_text().splitlines() if l]
        return [l for l in lines if prog is None or l.split(" ", 1)[0] == prog]

    def cleanup(self) -> None:
        # Only ever the exact dir mkdtemp made for this test.
        assert self.tmp.name.startswith("dgx-pbshim-") and self.tmp.parent == Path(tempfile.gettempdir())
        shutil.rmtree(self.tmp)


class ShimTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = Sandbox()
        self.addCleanup(self.sb.cleanup)


class LockoutGuardTest(ShimTestCase):
    """apply refuses before any change when the operator could be locked out."""

    def test_preflight_passes_with_port_22_and_a_root_key(self) -> None:
        self.sb.add_key()
        r = self.sb.run("preflight")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_refuses_when_sshd_listens_on_another_port(self) -> None:
        self.sb.add_key()
        for cfg in ("port 2222\nlistenaddress 0.0.0.0:2222\n",
                    "port 22\nport 2222\n",
                    "port 22\nlistenaddress 10.0.0.5:2200\n"):
            (self.sb.tmp / "sshd_T").write_text(cfg + "authorizedkeysfile .ssh/authorized_keys\n")
            r = self.sb.run("preflight")
            self.assertEqual(r.returncode, 2, f"{cfg!r}: {r.stdout}{r.stderr}")
            self.assertIn("port", r.stderr)

    def test_refuses_when_ssh_socket_listens_on_another_port(self) -> None:
        self.sb.add_key()
        r = self.sb.run("preflight", SHIM_SOCKET_ACTIVE_RC="0", SHIM_SOCKET_LISTEN="[::]:2222 (Stream)")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        r = self.sb.run("preflight", SHIM_SOCKET_ACTIVE_RC="0", SHIM_SOCKET_LISTEN="[::]:22 (Stream)")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)  # negative control

    def test_refuses_when_sshd_config_is_unreadable(self) -> None:
        self.sb.add_key()
        (self.sb.tmp / "sshd_T").write_text("")
        r = self.sb.run("preflight")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_refuses_without_an_authorized_key(self) -> None:
        cases = {
            "no file": None,
            "empty file": "",
            "comments only": "# nothing here\n\n",
            "garbage": "not a key\n",
        }
        for name, content in cases.items():
            ak = self.sb.root / "root/.ssh/authorized_keys"
            if content is None:
                ak.unlink(missing_ok=True)
            else:
                ak.write_text(content)
            r = self.sb.run("preflight")
            self.assertEqual(r.returncode, 2, f"{name}: {r.stdout}{r.stderr}")
            self.assertIn("authorized key", r.stderr)

    def test_key_in_any_authorizedkeysfile_counts(self) -> None:
        self.sb.add_key(name="authorized_keys2")
        r = self.sb.run("preflight")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_absolute_authorizedkeysfile_with_tokens(self) -> None:
        (self.sb.tmp / "sshd_T").write_text("port 22\nauthorizedkeysfile /etc/ssh/keys/%u\n")
        (self.sb.root / "etc/ssh/keys").mkdir(parents=True)
        self.sb.add_key()
        r = self.sb.run("preflight")
        self.assertEqual(r.returncode, 2, "key only in ~/.ssh must not count here: " + r.stdout + r.stderr)
        shutil.copy(self.sb.root / "root/.ssh/authorized_keys", self.sb.root / "etc/ssh/keys/root")
        r = self.sb.run("preflight")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_sudo_user_key_is_the_one_checked(self) -> None:
        self.sb.add_key()  # root has a key, alice does not
        r = self.sb.run("preflight", SUDO_USER="alice")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("alice", r.stderr)
        self.sb.add_key(user_home="home/alice")
        r = self.sb.run("preflight", SUDO_USER="alice")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_apply_fails_closed_before_any_change(self) -> None:
        # No authorized key: do_apply must stop before apt, ufw, sshd reload or any file.
        r = self.sb.run("do_apply")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        mutating = [c for c in self.sb.calls()
                    if c.split(" ", 1)[0] in ("apt-get", "ufw", "install", "chown", "useradd", "groupadd")
                    or (c.startswith("systemctl ") and not c.startswith(("systemctl is-active", "systemctl show")))]
        self.assertEqual(mutating, [])
        written = sorted(str(p.relative_to(self.sb.root)) for p in self.sb.root.rglob("*") if p.is_file())
        self.assertEqual(written, ["etc/logrotate.conf", "etc/os-release"])

    def test_apply_fails_closed_on_wrong_port(self) -> None:  # second guard, same property
        self.sb.add_key()
        (self.sb.tmp / "sshd_T").write_text("port 2222\nauthorizedkeysfile .ssh/authorized_keys\n")
        r = self.sb.run("do_apply")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(self.sb.calls("apt-get") + self.sb.calls("ufw"), [])


class ApplyStepsTest(ShimTestCase):
    def test_ssh_dropin_is_key_only(self) -> None:
        r = self.sb.run("apply_ssh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (self.sb.root / "etc/ssh/sshd_config.d/10-citrate.conf").read_text().splitlines()
        for want in ("PasswordAuthentication no", "KbdInteractiveAuthentication no",
                     "ChallengeResponseAuthentication no", "PermitRootLogin prohibit-password",
                     "PubkeyAuthentication yes", "PermitEmptyPasswords no"):
            self.assertIn(want, conf)
        self.assertEqual([l for l in conf if re.search(r"\byes\b", l) and "Pubkey" not in l], [])

    def test_ssh_reload_gated_on_sshd_t(self) -> None:
        r = self.sb.run("apply_ssh", SHIM_SSHD_T_RC="1")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual([c for c in self.sb.calls("systemctl") if "reload" in c or "restart" in c], [])

    def test_ssh_reloads_on_every_run(self) -> None:
        for _ in range(2):
            r = self.sb.run("apply_ssh")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.sb.calls()
        self.assertEqual(calls.count("systemctl reload ssh"), 2, calls)
        # sshd -t comes before each reload
        idx = [i for i, c in enumerate(calls) if c in ("sshd -t", "systemctl reload ssh")]
        self.assertEqual([calls[i] for i in idx], ["sshd -t", "systemctl reload ssh"] * 2)

    def test_journald_restarted_on_every_run(self) -> None:
        for _ in range(2):
            r = self.sb.run("apply_logs")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sb.calls().count("systemctl restart systemd-journald"), 2)

    def test_unattended_never_reboots(self) -> None:
        r = self.sb.run("apply_unattended")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (self.sb.root / "etc/apt/apt.conf.d/52citrate-unattended").read_text().splitlines()
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', conf)
        self.assertIn('Unattended-Upgrade::Automatic-Reboot-WithUsers "false";', conf)
        self.assertEqual([l for l in conf if '"true"' in l and "Reboot" in l], [])

    def test_dirs_modes(self) -> None:
        r = self.sb.run("apply_user_dirs")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        mode = lambda p: (self.sb.root / p).stat().st_mode & 0o7777
        self.assertEqual(mode("var/lib/citrate/data"), 0o700)
        self.assertEqual(mode("var/lib/citrate"), 0o750)
        self.assertEqual(mode("etc/citrate"), 0o755)
        installs = self.sb.calls("install")
        self.assertIn(f"install -d -o root -g citrate -m 0750 {self.sb.root}/var/lib/citrate", installs)
        self.assertIn(f"install -d -o citrate -g citrate -m 0700 {self.sb.root}/var/lib/citrate/data", installs)

    def test_dir_changes_are_reported(self) -> None:
        d = self.sb.root / "var/lib/citrate"
        d.mkdir(parents=True)
        d.chmod(0o755)  # the earlier layout
        body = 'apply_user_dirs >/dev/null; printf "%s\\n" "${CHANGED[@]}"'
        r = self.sb.run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("/var/lib/citrate", r.stdout.splitlines())
        r = self.sb.run(body)
        self.assertEqual(r.stdout.strip(), "", "a converged run reports no change")  # negative control

    def test_dirs_refuse_symlinks(self) -> None:
        target = self.sb.root / "elsewhere"
        target.mkdir(mode=0o755)
        target.chmod(0o755)
        for link in ("var/lib/citrate", "var/lib/citrate/data", "etc/citrate"):
            p = self.sb.root / link
            p.parent.mkdir(parents=True, exist_ok=True)
            p.symlink_to(target)
            r = self.sb.run("apply_user_dirs")
            self.assertEqual(r.returncode, 2, f"{link}: {r.stdout}{r.stderr}")
            self.assertIn("symlink", r.stderr)
            self.assertEqual(target.stat().st_mode & 0o7777, 0o755, link)
            r = self.sb.run("preflight")
            self.assertEqual(r.returncode, 2, f"preflight {link}: {r.stdout}{r.stderr}")
            p.unlink()

    def test_firewall_allows_then_defaults_then_enable(self) -> None:
        r = self.sb.run("apply_firewall")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ufw = [c for c in self.sb.calls("ufw") if not c.startswith(("ufw status", "ufw show"))]
        self.assertEqual(ufw, [
            "ufw allow 22/tcp", "ufw allow 30303/tcp", "ufw allow 30303/udp",
            "ufw default deny incoming", "ufw default allow outgoing", "ufw --force enable",
        ])

    def test_firewall_not_enabled_without_ssh_rule(self) -> None:
        r = self.sb.run("apply_firewall", SHIM_UFW_DROP="22/tcp")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual([c for c in self.sb.calls("ufw") if "enable" in c or "default" in c], [])

    def test_firewall_failed_allow_leaves_defaults_alone(self) -> None:
        r = self.sb.run("apply_firewall", SHIM_UFW_FAIL="30303/udp")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual([c for c in self.sb.calls("ufw") if "enable" in c or "default" in c], [])

    def test_changed_tracks_piped_files(self) -> None:
        r = self.sb.run('apply_disk_alert >/dev/null; apply_unit_template >/dev/null; printf "%s\\n" "${CHANGED[@]}"')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        changed = r.stdout.splitlines()
        self.assertIn("/usr/local/sbin/citrate-disk-alert", changed)
        self.assertIn("/etc/systemd/system/citrate-node.service", changed)
        r = self.sb.run('apply_disk_alert >/dev/null; apply_unit_template >/dev/null; echo "n=${#CHANGED[@]}"')
        self.assertIn("n=0", r.stdout)  # negative control: second run changes nothing

    def test_dispatch_refuses_a_test_root(self) -> None:
        for mode in ("apply", "check"):
            e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.sb.tmp / "home"),
                 "PRODUCER_BASELINE_ROOT": str(self.sb.root)}
            r = subprocess.run(["bash", str(SCRIPT), mode], capture_output=True, text=True, env=e, timeout=30)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("PRODUCER_BASELINE_ROOT", r.stderr)


class DoAgentKeyTest(ShimTestCase):
    def gen_key(self, gh: Path, uid: str) -> tuple[Path, str]:
        subprocess.run(["gpg", "--batch", "--quiet", "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "never"],
                       env={"GNUPGHOME": str(gh), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                       check=True, capture_output=True)
        out = subprocess.run(["gpg", "--batch", "--with-colons", "--list-keys", uid],
                             env={"GNUPGHOME": str(gh)}, check=True, capture_output=True, text=True).stdout
        fpr = next(l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:"))
        asc = self.sb.tmp / f"{uid}.asc"
        asc.write_text(subprocess.run(["gpg", "--batch", "--armor", "--export", uid], env={"GNUPGHOME": str(gh)},
                                      check=True, capture_output=True, text=True).stdout)
        return asc, fpr

    def test_key_fingerprint_pin(self) -> None:
        if not shutil.which("gpg"):
            self.skipTest("gpg not installed")
        gh = self.sb.tmp / "gnupg"
        gh.mkdir(mode=0o700)
        a, fa = self.gen_key(gh, "a@test.invalid")
        b, fb = self.gen_key(gh, "b@test.invalid")
        both = self.sb.tmp / "both.asc"
        both.write_text(a.read_text() + b.read_text())
        dearmored = self.sb.tmp / "a.gpg"
        subprocess.run(["gpg", "--dearmor", "-o", str(dearmored), str(a)], check=True, capture_output=True,
                       env={"GNUPGHOME": str(gh)})
        ok = lambda f, fpr: self.sb.run(f'key_fpr_ok "{f}" "{fpr}"').returncode
        self.assertEqual(ok(a, fa), 0)
        self.assertEqual(ok(dearmored, fa), 0)
        self.assertEqual(ok(a, fb), 1)            # wrong key
        self.assertEqual(ok(both, fa), 1)         # extra key smuggled in
        self.assertEqual(ok(self.sb.tmp / "passwd", fa), 1)  # not a key at all

    def test_installer_is_not_piped_to_a_shell(self) -> None:
        src = SCRIPT.read_text()
        self.assertNotRegex(src, r"curl[^\n]*\|\s*(sudo\s+)?(ba)?sh\b")
        self.assertRegex(src, r"DO_AGENT_KEY_FPR=902C44B42EA9A17F8578510977B79B3FFAF7EF65")
        # negative control for the regex
        self.assertRegex("curl -fsSL https://x/install.sh | bash", r"curl[^\n]*\|\s*(sudo\s+)?(ba)?sh\b")

    def test_install_refused_when_key_download_fails(self) -> None:
        r = self.sb.run("install_do_agent")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.sb.root / "etc/apt/sources.list.d/digitalocean-agent.list").exists())
        self.assertEqual([c for c in self.sb.calls("apt-get") if "install" in c], [])


if __name__ == "__main__":
    unittest.main()
