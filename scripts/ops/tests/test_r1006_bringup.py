#!/usr/bin/env python3
"""Tests for scripts/ops/r1006_bringup.sh and scripts/ops/r1006/*.

Everything runs in temp dirs: each "host" is a directory used as R1006_ROOT, the
transport is the inventory's `local` mode without a network namespace, and no host
service, network or real key is touched. The key step runs with
scripts/ops/tests/fixtures/fake_keytool.sh unless R1006_TEST_KEYTOOL names a real
`citrate` binary (then the real `host-identity` command mints real throwaway keys).

  python3 -m unittest scripts/ops/tests/test_r1006_bringup.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OPS = REPO / "scripts" / "ops"
BRINGUP = OPS / "r1006_bringup.sh"
AGENT = OPS / "r1006" / "host_agent.sh"
FAKE = OPS / "tests" / "fixtures" / "fake_keytool.sh"
sys.path.insert(0, str(OPS / "r1006"))
import collect  # noqa: E402
import render_profile  # noqa: E402

SECRET_FILES = ("var/lib/citrate/data/noise.key", "var/lib/citrate/data/proposer.key",
                "etc/citrate/r1006/staker.keystore.json", "etc/citrate/r1006/staker.password")


def good_identity(i: int) -> dict:
    h = f"{i:02x}" * 32
    a = f"{i:02x}" * 20
    return {
        "schema": "citrate-host-identity/1",
        "peer_id": f"noise_{h}",
        "noise_pubkey": h,
        "proposer_pubkey": "0x" + f"{i + 0x40:02x}" * 32,
        "vrf_pubkey": "0x02" + f"{i + 0x80:02x}" * 32,
        "staker_address": "0x" + a,
        "coinbase_address": "0x" + a,
    }


class Env:
    """N fake hosts, a local inventory, a state dir, and a staged 'build'."""

    def __init__(self, n: int = 3, keytool: Path | None = None):
        self.tmp = Path(tempfile.mkdtemp(prefix="dgx-r1006t."))
        self.state = self.tmp / "state"
        self.state.mkdir()
        hosts = []
        for i in range(1, n + 1):
            root = self.tmp / f"h{i}"
            root.mkdir()
            hosts.append({"name": f"p{i}", "region": "lo", "ip": f"10.206.0.{i}", "root": str(root), "netns_pid": ""})
        self.hosts = hosts
        self.inv = self.tmp / "inv.json"
        self.inv.write_text(json.dumps({"schema": "r1006-inventory/1", "transport": "local", "hosts": hosts,
                                        "build_host": {"name": "none", "ip": "127.0.0.1"}}))
        tool = Path(os.environ.get("R1006_TEST_KEYTOOL", "")) if keytool is None else keytool
        if not tool or not tool.is_file():
            tool = FAKE
        self.real_tool = tool != FAKE
        (self.state / "bin").mkdir()
        shutil.copy(tool, self.state / "bin" / "citrate-node")
        os.chmod(self.state / "bin" / "citrate-node", 0o755)
        s256 = subprocess.run(["sha256sum", str(self.state / "bin" / "citrate-node")], capture_output=True,
                              text=True, check=True).stdout.split()[0]
        (self.state / "build.json").write_text(json.dumps({"sha": "0" * 40, "sha256": s256, "fingerprint": "0x",
                                                           "arch": "test", "built_on": "test", "from_main": False}))
        self.env = dict(os.environ, HOME=str(self.tmp), CANARY="CANARY-7f3a9c")

    def run(self, *args: str, env: dict | None = None, agent: Path | None = None) -> subprocess.CompletedProcess:
        e = dict(self.env, **(env or {}))
        script = BRINGUP
        if agent is not None:
            # Run a copy of the orchestrator next to a mutated agent.
            d = self.tmp / "mut"
            if not d.exists():
                shutil.copytree(OPS, d, ignore=shutil.ignore_patterns("tests"))
            shutil.copy(agent, d / "r1006" / "host_agent.sh")
            script = d / "r1006_bringup.sh"
        return subprocess.run(["bash", str(script), *args, "--inventory", str(self.inv), "--state", str(self.state)],
                              capture_output=True, text=True, env=e, timeout=300, stdin=subprocess.DEVNULL)

    def agent(self, host: int, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        e = dict(self.env, R1006_ROOT=self.hosts[host - 1]["root"], R1006_SERVICE="proc", R1006_RUN_AS="", **(env or {}))
        return subprocess.run(["bash", str(AGENT), *args], capture_output=True, text=True, env=e, timeout=120,
                              stdin=subprocess.DEVNULL)

    def secrets(self) -> list[bytes]:
        out = []
        for h in self.hosts:
            for rel in SECRET_FILES:
                p = Path(h["root"]) / rel
                if p.exists():
                    out.append(p.read_bytes())
        return out

    def close(self):
        shutil.rmtree(self.tmp)


def tree_bytes(d: Path) -> bytes:
    return b"\n".join(p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file())


def leak_needles(secret: bytes) -> list[bytes]:
    """Byte strings that would show a secret leaked: the raw bytes, their hex, and
    any CANARY token inside them."""
    needles = [m.group(0) for m in re.finditer(rb"CANARY-[0-9a-f]+-[a-z]+", secret)]
    if not needles and len(secret) >= 16:
        needles = [secret[:32], secret[:32].hex().encode()]
    if secret.startswith(b"{"):  # a real keystore: the ciphertext and the address are what matter
        try:
            needles = [json.loads(secret)["crypto"]["ciphertext"].encode()]
        except (ValueError, KeyError):
            pass
    return needles


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dgx-r1006c."))
        (self.tmp / "pub").mkdir()
        self.inv = self.tmp / "inv.json"
        self.inv.write_text(json.dumps({"hosts": [{"name": f"p{i}", "ip": f"10.0.0.{i}"} for i in (1, 2)]}))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, name: str, d: dict):
        (self.tmp / "pub" / f"{name}.pub.json").write_text(json.dumps(d))

    def collect(self):
        return collect.collect(self.inv, self.tmp / "pub", 40204, 30303)

    def test_good_set(self):
        self.write("p1", good_identity(1))
        self.write("p2", good_identity(2))
        doc = self.collect()
        self.assertEqual([p["name"] for p in doc["producers"]], ["p1", "p2"])
        self.assertEqual(doc["producers"][0]["bootnode"], f"noise_{'01' * 32}@10.0.0.1:30303")

    def test_extra_field_is_refused(self):
        bad = good_identity(1) | {"proposer_seed": "aa" * 32}
        self.write("p1", bad)
        self.write("p2", good_identity(2))
        with self.assertRaisesRegex(collect.CollectError, "unexpected field"):
            self.collect()

    def test_non_public_form_is_refused(self):
        for k, v in [("proposer_pubkey", "0x" + "aa" * 31), ("vrf_pubkey", "0x04" + "aa" * 64),
                     ("staker_address", "0x" + "AA" * 20), ("noise_pubkey", "zz" * 32)]:
            with self.subTest(field=k):
                d = good_identity(1)
                d[k] = v
                if k == "staker_address":
                    d["coinbase_address"] = v
                self.write("p1", d)
                self.write("p2", good_identity(2))
                with self.assertRaises(collect.CollectError):
                    self.collect()

    def test_shared_key_is_refused(self):
        d2 = good_identity(2)
        d2["proposer_pubkey"] = good_identity(1)["proposer_pubkey"]
        self.write("p1", good_identity(1))
        self.write("p2", d2)
        with self.assertRaisesRegex(collect.CollectError, "its own keys"):
            self.collect()

    def test_coinbase_must_be_staker(self):
        d = good_identity(1)
        d["coinbase_address"] = "0x" + "77" * 20
        self.write("p1", d)
        self.write("p2", good_identity(2))
        with self.assertRaisesRegex(collect.CollectError, "coinbase"):
            self.collect()

    def test_peer_id_must_match_noise_key(self):
        d = good_identity(1)
        d["peer_id"] = "noise_" + "09" * 32
        self.write("p1", d)
        self.write("p2", good_identity(2))
        with self.assertRaisesRegex(collect.CollectError, "peer_id"):
            self.collect()

    def test_missing_host_is_refused(self):
        self.write("p1", good_identity(1))
        with self.assertRaisesRegex(collect.CollectError, "p2: no public identity"):
            self.collect()


class KeysStepReadsOnlyPublicOutputs(unittest.TestCase):
    """The key step mints on the host and brings back only the public identity."""

    def test_no_secret_reaches_the_orchestrator(self):
        env = Env(3)
        try:
            r = env.run("keys")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            prod = json.loads((env.state / "r1006-producers.json").read_text())
            self.assertEqual(len(prod["producers"]), 3)
            boot = json.loads((env.state / "r1006-public-bootnodes.json").read_text())
            self.assertEqual(boot["bootstrap_nodes"], [p["bootnode"] for p in prod["producers"]])
            self.assertTrue(all(re.match(r"^noise_[0-9a-f]{64}@10\.206\.0\.\d:30303$", b) for b in boot["bootstrap_nodes"]))
            secrets = env.secrets()
            self.assertEqual(len(secrets), 3 * len(SECRET_FILES), "every secret file was minted on its host")
            seen = tree_bytes(env.state) + r.stdout.encode() + r.stderr.encode()
            for s in secrets:
                for needle in leak_needles(s):
                    self.assertNotIn(needle, seen, "a secret reached the orchestrator's output or state")
            # owner-only on the host
            for h in env.hosts:
                for rel in SECRET_FILES:
                    self.assertEqual(os.stat(Path(h["root"]) / rel).st_mode & 0o077, 0, rel)
            # idempotent: a second run gives the same producers and leaves the keys alone
            before = env.secrets()
            r2 = env.run("keys")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(json.loads((env.state / "r1006-producers.json").read_text())["producers"], prod["producers"])
            self.assertEqual(env.secrets(), before)
        finally:
            env.close()

    def test_negative_control_an_agent_that_reads_the_keystore_is_caught(self):
        """Mutate the agent so `pub` also prints the keystore; the leak check must fire."""
        env = Env(2)
        try:
            src = AGENT.read_text()
            mutated = src.replace('cat -- "$PUB"', 'cat -- "$PUB" "$KEYSTORE"')
            self.assertNotEqual(src, mutated, "the agent's pub command is a single cat of the public file")
            m = env.tmp / "host_agent.mut.sh"
            m.write_text(mutated)
            r = env.run("keys", agent=m)
            seen = tree_bytes(env.state) + r.stdout.encode() + r.stderr.encode()
            leaked = any(n in seen for s in env.secrets() for n in leak_needles(s))
            self.assertTrue(leaked, "the leak check must see the keystore when the agent prints it")
            self.assertFalse((env.state / "r1006-producers.json").exists(), "the collector must refuse that output")
        finally:
            env.close()

    def test_extra_field_in_the_public_file_stops_the_step(self):
        if os.environ.get("R1006_TEST_KEYTOOL"):
            self.skipTest("fake-keytool control")
        env = Env(2)
        try:
            r = env.run("keys", env={"FAKE_PUB_EXTRA": '"note": "x"'})
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("unexpected field", r.stderr)
            self.assertFalse((env.state / "r1006-producers.json").exists())
        finally:
            env.close()

    def test_static_the_orchestrator_never_names_a_secret_file(self):
        # No line that moves or reads data on a host (agent / put / scp / ssh / cat)
        # names a secret file. Help and log text may mention them.
        movers = re.compile(r"^\s*[^#\s].*\b(agent|put|scp|ssh|cat|rsync)\b")
        for n, line in enumerate(BRINGUP.read_text().splitlines(), 1):
            if not movers.search(line) or re.match(r"^\s*(log|echo|die|gate_fail|read)\b", line.strip()):
                continue
            for name in ("noise.key", "proposer.key", "keystore", "password", "KEYSTORE", "PASSWORD"):
                self.assertNotIn(name, line, f"r1006_bringup.sh:{n} moves/reads data and names {name}")
        # The agent's pub command reads exactly one file: the public identity.
        agent = AGENT.read_text()
        body = re.search(r"cmd_pub\(\) \{(.*?)\n\}", agent, re.S).group(1)
        self.assertEqual(re.findall(r"\bcat\b[^\n]*", body), ['cat -- "$PUB"'])
        self.assertIn('PUB="$RDIR/identity.pub.json"', agent)


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.env = Env(1)
        r = self.env.run("keys")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.root = Path(self.env.hosts[0]["root"])

    def tearDown(self):
        self.env.close()

    def test_wipe_refuses_without_the_r1006_marker(self):
        r = self.env.agent(1, "wipe")
        self.assertEqual(r.returncode, 2)
        self.assertIn("marker", r.stderr)

    def test_wipe_keeps_keys_and_removes_chain_data(self):
        data = self.root / "var/lib/citrate/data"
        (data / "chain").mkdir()
        (data / "chain" / "000001.sst").write_text("x")
        (data / ".lock").write_text("")
        (self.root / "etc/citrate/r1006/DEPLOYED").write_text("t")
        r = self.env.agent(1, "wipe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(p.name for p in data.iterdir()), ["noise.key", "proposer.key"])
        for rel in SECRET_FILES:
            self.assertTrue((self.root / rel).exists(), rel)

    def test_wipe_keys_removes_the_identity(self):
        (self.root / "etc/citrate/r1006/DEPLOYED").write_text("t")
        r = self.env.agent(1, "wipe", "--wipe-keys")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in SECRET_FILES:
            self.assertFalse((self.root / rel).exists(), rel)

    def test_wipe_refuses_while_running(self):
        (self.root / "etc/citrate/r1006/DEPLOYED").write_text("t")
        # A live process we own stands in for the node (proc-mode pid file).
        p = subprocess.Popen(["sleep", "30"])
        try:
            (self.root / "run").mkdir(exist_ok=True)
            (self.root / "run/citrate-node.pid").write_text(str(p.pid))
            r = self.env.agent(1, "wipe")
            self.assertEqual(r.returncode, 2)
            self.assertIn("running", r.stderr)
            self.assertTrue((self.root / "var/lib/citrate/data/proposer.key").exists())
        finally:
            p.kill()
            p.wait()

    def test_orchestrator_wipe_keys_needs_a_terminal(self):
        r = self.env.run("wipe", "--wipe-keys")
        self.assertEqual(r.returncode, 2)
        self.assertIn("interactive confirmation", r.stderr)
        self.assertTrue((self.root / "var/lib/citrate/data/proposer.key").exists())

    def test_install_bin_checks_the_hash_and_is_idempotent(self):
        lib = self.root / "usr/local/lib/citrate-r1006/incoming"
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "citrate-node").write_bytes(b"binary-v1")
        good = subprocess.run(["sha256sum", str(lib / "citrate-node")], capture_output=True, text=True).stdout.split()[0]
        r = self.env.agent(1, "install-bin", "ab" * 32)
        self.assertEqual(r.returncode, 2)
        self.assertFalse((self.root / "usr/local/bin/citrate-node").exists())
        r = self.env.agent(1, "install-bin", good)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("installed", r.stdout)
        r = self.env.agent(1, "install-bin", good)
        self.assertIn("unchanged", r.stdout)

    def test_config_check_refuses_a_contribution_recorder(self):
        etc = self.root / "etc/citrate"
        (etc / "node.toml").write_text("[chain]\nchain_id = 40204\n")
        (etc / "citrate-node.env").write_text("CITRATE_BLOCK_V2=1\n")
        r = self.env.agent(1, "config-check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        (etc / "citrate-node.env").write_text("CITRATE_BLOCK_V2=1\nCITRATE_CONTRIBUTION_ACCOUNTING=0x01\n")
        r = self.env.agent(1, "config-check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("CONFIG FAIL", r.stdout)

    def test_log_scan_exempts_only_known_notices(self):
        log = self.root / "var/log/citrate-node.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(
            "\x1b[32m INFO\x1b[0m citrate: Agent precompile fork ACTIVE from height 0 (source: release pin)\n"
            "INFO citrate: runtime reorg: spine rebuild converged to the fork-choice head\n"
            "INFO block 12 imported\n")
        r = self.env.agent(1, "logs-scan", "0")
        self.assertIn("matches 0", r.stdout, r.stdout)
        self.assertIn("exempt 2", r.stdout)
        with log.open("a") as f:
            f.write("WARN citrate: runtime reorg: rebuilding applied state from genesis via the canonical spine (deep-fork self-heal)\n")
            f.write("ERROR state root CONFLICT at 40\n")
        r = self.env.agent(1, "logs-scan", "0")
        self.assertIn("matches 2", r.stdout, r.stdout)

    def test_log_scan_counts_shallow_reorgs_and_fails_deep_ones(self):
        log = self.root / "var/log/citrate-node.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        r_line = "INFO citrate::canonical_apply: execute-on-receive: fork-choice reorged to 0d77df1a @ {h} (reverted {n}, applied {n})\n"
        log.write_text(r_line.format(h=3, n=3) + r_line.format(h=9, n=1))
        r = self.env.agent(1, "logs-scan", "0")
        self.assertIn("matches 0", r.stdout, r.stdout)
        self.assertIn("shallow_reorgs 2", r.stdout)
        self.assertIn("deepest_reorg 3", r.stdout)
        with log.open("a") as f:
            f.write(r_line.format(h=40, n=7))
        r = self.env.agent(1, "logs-scan", "0")
        self.assertIn("matches 1", r.stdout, r.stdout)

    def test_generated_config_has_no_contribution_recorder(self):
        tool = (REPO / "scripts/producers/gen_node_config.py").read_text().lower()
        self.assertNotIn("contribution", tool)

    def test_write_config_refuses_another_hosts_staker(self):
        r = self.env.agent(1, "write-config", "0x" + "12" * 20, "on")
        self.assertEqual(r.returncode, 2)


class RenderProfileTest(unittest.TestCase):
    def setUp(self):
        self.prod = {"chain_id": 40204, "producers": [
            {"name": f"p{i}", "bootnode": f"noise_{f'{i:02x}' * 32}@10.0.0.{i}:30303",
             "proposer_pubkey": good_identity(i)["proposer_pubkey"], "staker_address": good_identity(i)["staker_address"]}
            for i in (1, 2, 3)]}
        self.stakes = render_profile.stakes_doc(self.prod, 32000, 100)
        self.fill = {"schema": "r1006-genesis-fill/1", "genesis_hash": "0x" + "ab" * 32, "genesis_profile": "r1006",
                     "validator_registry": "0x" + "cd" * 20, "validator_activation_height": 0,
                     "validators": [{"proposer_pubkey": p["proposer_pubkey"], "staker": p["staker_address"],
                                     "stake_wei": str(32000 * 10**18)} for p in self.prod["producers"]]}
        self.template = json.loads((REPO / "scripts/producers/profiles/r1006.json").read_text())

    def test_consistent_fill(self):
        self.assertEqual(render_profile.check_fill(self.fill, self.prod, self.stakes), [])

    def test_fill_problems(self):
        f = json.loads(json.dumps(self.fill))
        f["validators"].pop()
        self.assertTrue(any("missing" in p for p in render_profile.check_fill(f, self.prod, self.stakes)))
        f = json.loads(json.dumps(self.fill))
        f["validators"][0]["stake_wei"] = "1"
        self.assertTrue(any("stake" in p for p in render_profile.check_fill(f, self.prod, self.stakes)))
        f = json.loads(json.dumps(self.fill))
        f["validators"][0]["staker"] = "0x" + "99" * 20
        self.assertTrue(any("wrong staker" in p for p in render_profile.check_fill(f, self.prod, None)))
        f = json.loads(json.dumps(self.fill))
        f["genesis_profile"] = None
        self.assertTrue(any("cannot select" in p for p in render_profile.check_fill(f, self.prod, None)))

    def test_profile_bootnodes_are_the_other_producers(self):
        prof = render_profile.render(self.template, self.prod, self.fill, "p2")
        self.assertEqual(prof["status"], "ready")
        self.assertEqual(len(prof["bootstrap_nodes"]), 2)
        self.assertFalse(any("@10.0.0.2:" in b for b in prof["bootstrap_nodes"]))
        self.assertFalse(any("citrate.ai" in b for b in prof["bootstrap_nodes"]), "no public bootnodes")
        self.assertEqual(prof["genesis_hash"], self.fill["genesis_hash"])
        self.assertEqual(prof["genesis_profile"], "r1006")

    def test_rendered_profile_passes_gen_node_config_with_rpc_on_loopback(self):
        prof = render_profile.render(self.template, self.prod, self.fill, "p1")
        prof["validator_activation_height"] = 800
        with tempfile.TemporaryDirectory(prefix="dgx-r1006p.") as d:
            pp = Path(d) / "p1.json"
            pp.write_text(json.dumps(prof))
            out = Path(d) / "etc"
            out.mkdir()
            r = subprocess.run([sys.executable, str(REPO / "scripts/producers/gen_node_config.py"), "--profile", str(pp),
                                "--staker", self.prod["producers"][0]["staker_address"], "--out-dir", str(out),
                                "--data-dir", "/var/lib/citrate/data", "--mining", "on"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            toml = (out / "node.toml").read_text()
            self.assertIn('listen_addr = "127.0.0.1:8545"', toml)
            self.assertIn('genesis_profile = "r1006"', toml)
            self.assertIn("@10.0.0.2:30303", toml)
            self.assertNotIn("@10.0.0.1:30303", toml)

    def test_activation_zero_only_with_a_genesis_validator_set(self):
        for at_genesis, want_rc in ((True, 0), (False, 2)):
            with self.subTest(validators_at_genesis=at_genesis):
                fill = dict(self.fill, validator_activation_height=0, validators_at_genesis=at_genesis)
                prof = render_profile.render(self.template, self.prod, fill, "p1")
                with tempfile.TemporaryDirectory(prefix="dgx-r1006p.") as d:
                    pp = Path(d) / "p1.json"
                    pp.write_text(json.dumps(prof))
                    r = subprocess.run([sys.executable, str(REPO / "scripts/producers/gen_node_config.py"), "--profile",
                                        str(pp), "--staker", self.prod["producers"][0]["staker_address"], "--out-dir", d],
                                       capture_output=True, text=True)
                    self.assertEqual(r.returncode, want_rc, r.stderr)

    def test_template_is_refused_until_rendered(self):
        r = subprocess.run([sys.executable, str(REPO / "scripts/producers/gen_node_config.py"), "--profile", "r1006",
                            "--staker", "0x" + "11" * 20, "--out-dir", "/nonexistent"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not ready", r.stderr)


class DryRunTest(unittest.TestCase):
    def test_every_step_dry_runs_without_touching_a_host(self):
        env = Env(2)
        try:
            for step in (["keys"], ["genesis-fill", "--fill-cmd", "x"], ["distribute"], ["start"], ["smoke"],
                         ["stop"], ["wipe"], ["status"], ["tunnels", "up"]):
                before = tree_bytes(env.tmp)
                r = env.run(*step, "--dry-run")
                self.assertEqual(r.returncode, 0, f"{step}: {r.stdout}{r.stderr}")
                self.assertIn("DRY RUN", r.stdout)
                self.assertEqual(tree_bytes(env.tmp), before, f"{step} --dry-run changed files")
        finally:
            env.close()


if __name__ == "__main__":
    unittest.main()
