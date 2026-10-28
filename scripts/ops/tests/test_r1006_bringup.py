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
FILL_FIXTURE = OPS / "tests" / "fixtures" / "rehearsal_fill.py"
GUARD = OPS / "r1006" / "guard.py"
HARDENING = REPO / "core" / "consensus" / "src" / "hardening.rs"
# r1005's block 0 (RELEASE_GENESIS[0]) and the r1006 genesis the test "build" compiles.
R1005 = "0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"
R1006_TEST = "0x" + "06" * 32
# The ValidatorRegistry the test repo's committed r1006 book names.
REG_TEST = "0x" + "f5" * 20
R1006_CONST = re.compile(r"pub const R1006_GENESIS: \[u8; 32\] =\s*hex32\(\"[0-9a-f]{64}\"\);")
PINNED_INV = json.loads((OPS / "r1006" / "inventory.r1006.json").read_text())
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
                                                           "arch": "test", "built_on": "test", "from_main": False,
                                                           "r1006_genesis": R1006_TEST}))
        self.env = dict(os.environ, HOME=str(self.tmp), TMPDIR=str(self.tmp), CANARY="CANARY-7f3a9c",
                        PYTHONDONTWRITEBYTECODE="1")
        # A repo tree the orchestrator runs from: the real scripts, plus the committed r1006
        # genesis pin (core/consensus/src/hardening.rs) and address book this test controls.
        self.repo = self.tmp / "repo"
        shutil.copytree(OPS, self.repo / "scripts" / "ops", ignore=shutil.ignore_patterns("tests", "__pycache__"))
        shutil.copytree(REPO / "scripts" / "producers", self.repo / "scripts" / "producers",
                        ignore=shutil.ignore_patterns("tests", "__pycache__"))
        self.set_committed(R1006_TEST, REG_TEST)
        (self.repo / "contracts/script").mkdir(parents=True, exist_ok=True)
        (self.repo / "contracts/script/CheckDeployedAdmins.s.sol").write_text("// stub: tests use a fake forge\n")
        self._git_history()

    def _git_history(self) -> None:
        """The repo is a git checkout with this history (empty commits; the tree stays
        untracked): old -> floor -> new, and side branching off old. `floor` is the
        reviewed MIN_CHAIN_REV; every host's fake binary reports `new` (12-char short
        sha, like the real build stamp) unless a test writes another <root>/fake-git-sha."""
        def git(*a: str) -> str:
            return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                   "-c", "commit.gpgsign=false", *a], capture_output=True, text=True, check=True,
                                  env=dict(self.env, GIT_CONFIG_NOSYSTEM="1")).stdout.strip()
        git("init", "-q", "-b", "main")
        self.rev = {}
        for name in ("old", "floor", "new"):
            git("commit", "-q", "--allow-empty", "-m", name)
            self.rev[name] = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "side", self.rev["old"])
        git("commit", "-q", "--allow-empty", "-m", "side")
        self.rev["side"] = git("rev-parse", "HEAD")
        git("checkout", "-q", "main")
        self.min_rev_file = self.repo / "scripts/ops/r1006/min_chain_rev"
        self.min_rev_file.write_text(f"# reviewed floor (test)\n{self.rev['floor']}\n")
        for h in self.hosts:
            (Path(h["root"]) / "fake-git-sha").write_text(self.rev["new"][:12])

    def set_committed(self, genesis: str | None, registry: str | None = REG_TEST) -> None:
        """Write the repo's committed r1006 pin (None: no R1006_GENESIS const) and book."""
        h = self.repo / "core/consensus/src/hardening.rs"
        h.parent.mkdir(parents=True, exist_ok=True)
        src = R1006_CONST.sub("", HARDENING.read_text())
        if genesis is not None:
            src += f'\npub const R1006_GENESIS: [u8; 32] =\n    hex32("{genesis[2:]}");\n'
        h.write_text(src)
        b = self.repo / "contracts/addresses/r1006/40204.json"
        b.parent.mkdir(parents=True, exist_ok=True)
        if registry is None:
            b.unlink(missing_ok=True)
        else:
            b.write_text(json.dumps({"chainId": 40204, "contracts": {"ValidatorRegistry": registry}}))

    @property
    def bringup(self) -> Path:
        return self.repo / "scripts/ops/r1006_bringup.sh"

    def run(self, *args: str, env: dict | None = None, agent: Path | None = None,
            state: bool = True) -> subprocess.CompletedProcess:
        e = dict(self.env, **(env or {}))
        script = self.bringup
        if agent is not None:
            # The orchestrator next to a mutated agent.
            shutil.copy(agent, self.repo / "scripts/ops/r1006/host_agent.sh")
        st = ["--state", str(self.state)] if state else []
        return subprocess.run(["bash", str(script), *args, "--inventory", str(self.inv), *st],
                              capture_output=True, text=True, env=e, timeout=300, stdin=subprocess.DEVNULL)

    def fill_cmd(self, genesis_hash: str, profile: str = "r1006", genesis_file: str | None = None,
                 registry: str | None = None) -> str:
        gf = f" --genesis-file {genesis_file}" if genesis_file else ""
        gf += f" --registry {registry}" if registry else ""
        return (f"python3 {FILL_FIXTURE} --producers {{producers}} --stakes {{stakes}} --out {{out}} "
                f"--genesis-hash {genesis_hash} --profile {profile}{gf}")

    def plant_fill(self, genesis_hash: str, profile: str | None = "r1006") -> None:
        """A fill-result.json in the state dir as if genesis-fill had accepted it."""
        prod = json.loads((self.state / "r1006-producers.json").read_text())
        (self.state / "genesis").mkdir(exist_ok=True)
        (self.state / "genesis" / "fill-result.json").write_text(json.dumps({
            "schema": "r1006-genesis-fill/1", "genesis_hash": genesis_hash, "genesis_profile": profile,
            "genesis_file": None, "alloc_file": None, "address_book": None, "orangeseed": None,
            "validator_registry": REG_TEST, "validator_activation_height": 1000,
            "validators_at_genesis": True,
            "validators": [{"proposer_pubkey": p["proposer_pubkey"], "staker": p["staker_address"],
                            "stake_wei": str(32000 * 10**18)} for p in prod["producers"]],
            "source": "test plant"}))

    def host_root(self, i: int) -> Path:
        return Path(self.hosts[i - 1]["root"])

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

    def test_extra_field_in_the_public_file_stops_the_step(self):
        if os.environ.get("R1006_TEST_KEYTOOL"):
            self.skipTest("fake-keytool control")
        env = Env(2)
        try:
            r = env.run("keys", env={"FAKE_PUB_EXTRA": '"note": "x"'})
            self.assertNotEqual(r.returncode, 0)
            # refused on the host already (strict re-serialisation), else by the collector
            self.assertRegex(r.stderr, "unexpected field|not exactly a public host identity")
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
        # The agent's pub command reads exactly one file, the public identity, and prints
        # only its re-serialised checked fields.
        agent = AGENT.read_text()
        body = re.search(r"cmd_pub\(\) \{(.*?)\n\}", agent, re.S).group(1)
        self.assertEqual(re.findall(r"\bcat\b[^\n]*", body), [])
        self.assertEqual(sorted(set(re.findall(r"\$\{?([A-Z_]+)", body))), ["PUB", "PUB_CHECK"])
        self.assertIn('PUB="$RDIR/identity.pub.json"', agent)


def mutate(src: str, options: list[tuple[str, str]]) -> str:
    """Apply the first (anchor, replacement) whose anchor is in src."""
    for old, new in options:
        if old in src:
            return src.replace(old, new, 1)
    raise AssertionError(f"no mutation anchor found among {[o for o, _ in options]}")


# The reviewer's three leak modes, as agent mutations. Each list covers the agent before
# and after the containment change, so the same test runs red on the old agent.
LEAK_MODES = {
    "pub prints proposer.key after the JSON": [
        ('python3 -c "$PUB_CHECK" "$PUB"', 'python3 -c "$PUB_CHECK" "$PUB"; cat -- "$DATA/proposer.key"'),
        ('cat -- "$PUB"', 'cat -- "$PUB" "$DATA/proposer.key"'),
    ],
    "pub prints noise.key before the JSON": [
        ('python3 -c "$PUB_CHECK" "$PUB"', 'cat -- "$DATA/noise.key"; python3 -c "$PUB_CHECK" "$PUB"'),
        ('cat -- "$PUB"', 'cat -- "$DATA/noise.key" "$PUB"'),
    ],
    "keys cats the password file to stderr": [
        ('  chmod 0644 "$PUB"\n', '  chmod 0644 "$PUB"\n  cat -- "$PASSWORD" >&2\n'),
    ],
}
# Disables the on-host output check, to prove the orchestrator's own check holds alone.
NO_HOST_SCAN = [('withhold_secrets "$out" "$err"', 'true')]


class KeyLeakContainment(unittest.TestCase):
    """A host whose agent leaks key material: the step fails, nothing is written under the
    state dir, and nothing secret is echoed. Checked with the on-host output check and,
    separately, with it disabled (the orchestrator's in-memory check alone)."""

    def _run(self, mode: str, host_scan: bool):
        env = Env(2)
        try:
            src = mutate(AGENT.read_text(), LEAK_MODES[mode])
            if not host_scan and 'withhold_secrets "$out" "$err"' in src:
                src = mutate(src, NO_HOST_SCAN)
            m = env.tmp / "host_agent.mut.sh"
            m.write_text(src)
            before = {p.relative_to(env.state) for p in env.state.rglob("*") if p.is_file()}
            r = env.run("keys", agent=m)
            secrets = env.secrets()
            self.assertTrue(secrets, "the hosts minted keys")
            self.assertNotEqual(r.returncode, 0, f"{mode}: the step must fail\n{r.stdout}{r.stderr}")
            after = {p.relative_to(env.state) for p in env.state.rglob("*") if p.is_file()}
            self.assertEqual(sorted(str(p) for p in after - before if p.name != "timings.log"), [],
                             f"{mode}: files written under the state dir")
            needles = [n for s_ in secrets for n in leak_needles(s_)]
            state_bytes = tree_bytes(env.state)
            for n in needles:
                self.assertNotIn(n, state_bytes, f"{mode}: a secret is on the orchestrator's disk")
                self.assertNotIn(n, r.stdout.encode(), f"{mode}: a secret was echoed (stdout)")
                self.assertNotIn(n, r.stderr.encode(), f"{mode}: a secret was echoed (stderr)")
            self.assertFalse((env.state / "r1006-producers.json").exists())
        finally:
            env.close()

    def test_pub_prints_proposer_key_after_the_json(self):
        for scan in (True, False):
            with self.subTest(host_scan=scan):
                self._run("pub prints proposer.key after the JSON", scan)

    def test_pub_prints_noise_key_before_the_json(self):
        for scan in (True, False):
            with self.subTest(host_scan=scan):
                self._run("pub prints noise.key before the JSON", scan)

    def test_keys_cats_the_password_file_to_stderr(self):
        for scan in (True, False):
            with self.subTest(host_scan=scan):
                self._run("keys cats the password file to stderr", scan)

    def test_the_host_withholds_its_own_secrets(self):
        """The agent alone (no orchestrator): a leaking command's output never leaves the host."""
        env = Env(1)
        try:
            r = env.run("keys")
            self.assertEqual(r.returncode, 0, r.stderr)
            src = AGENT.read_text()
            for mode, opts in LEAK_MODES.items():
                with self.subTest(mode=mode):
                    m = env.tmp / "agent.mut.sh"
                    m.write_text(mutate(src, opts))
                    e = dict(env.env, R1006_ROOT=env.hosts[0]["root"], R1006_SERVICE="proc", R1006_RUN_AS="")
                    cmd = "pub" if mode.startswith("pub") else "keys"
                    args = [cmd] + ([json.loads((env.state / "build.json").read_text())["sha256"]]
                                    if cmd == "keys" else [])
                    rr = subprocess.run(["bash", str(m), *args], capture_output=True, env=e, timeout=120,
                                        stdin=subprocess.DEVNULL)
                    self.assertEqual(rr.returncode, 3, rr.stderr)
                    for n in (n for s_ in env.secrets() for n in leak_needles(s_)):
                        self.assertNotIn(n, rr.stdout + rr.stderr)
                    self.assertIn(b"withheld", rr.stderr)
        finally:
            env.close()

    def test_negative_control_clean_keys_still_pass_through(self):
        env = Env(2)
        try:
            r = env.run("keys")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len(list((env.state / "pub").glob("*.pub.json"))), 2)
        finally:
            env.close()

    def test_guard_relay_patterns(self):
        import guard  # noqa: E402
        h = b"ab" * 32
        self.assertEqual(guard.find_leak(b"PROBE OK block 0 0x" + h + b"\n", b""), None, "hashes on stdout are fine")
        self.assertEqual(guard.find_leak(b"", b"host_agent: staged sha256 abababababab... differs\n"), None)
        self.assertEqual(guard.find_leak(b"", h + b"\n"), "stderr", "a bare 32-byte hex value on stderr")
        self.assertEqual(guard.find_leak(b"", b"0x" + h), "stderr")
        self.assertEqual(guard.find_leak(b"", b"\x8f\x01raw"), "stderr", "raw key bytes")
        self.assertEqual(guard.find_leak(b'{"crypto": {"ciphertext": "00"}}', b""), "stdout", "a keystore")
        self.assertEqual(guard.find_leak(b"-----BEGIN PRIVATE KEY-----", b""), "stdout")
        self.assertEqual(guard.find_leak(b"", b"password=hunter2"), "stderr")


class DefaultStateDir(unittest.TestCase):
    def test_default_state_is_home_r1006_state_0700(self):
        env = Env(1)
        try:
            r = env.run("status", "--dry-run", state=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            d = env.tmp / "r1006-state"
            self.assertTrue(d.is_dir(), "default state dir is ~/r1006-state")
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
            self.assertFalse((Path.cwd() / "r1006-state").exists() and Path.cwd() == REPO)
        finally:
            env.close()

    def test_repo_gitignore_covers_in_repo_state_dirs(self):
        for rel in ("r1006-state/pub/x.pub.json", "scripts/ops/r1006-state/genesis/fill-result.json"):
            r = subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q", "--no-index", rel])
            self.assertEqual(r.returncode, 0, f"{rel} is not gitignored")

    def test_state_dir_inside_the_repo_must_be_ignored(self):
        env = Env(1)
        try:
            d = REPO / "scripts" / "ops" / "tests" / f"not-ignored-state-{os.getpid()}"
            r = subprocess.run(["bash", str(BRINGUP), "status", "--dry-run", "--inventory", str(env.inv),
                                "--state", str(d)], capture_output=True, text=True, env=env.env,
                               stdin=subprocess.DEVNULL)
            try:
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("gitignore", r.stderr)
            finally:
                if d.exists():
                    shutil.rmtree(d)
        finally:
            env.close()


class FakeFleet:
    """PATH shims for ssh, scp and doctl that record every call and connect nowhere."""

    def __init__(self, tmp: Path, doctl_pairs: list[tuple[str, str]] | None = None, doctl_rc: int = 0):
        self.bin = tmp / "fakebin"
        self.bin.mkdir(exist_ok=True)
        self.calls = tmp / "calls.log"
        for tool in ("ssh", "scp"):
            p = self.bin / tool
            p.write_text(f'#!/bin/sh\necho "{tool} $*" >>"{self.calls}"\ncat >/dev/null 2>&1 || true\nexit 0\n')
            p.chmod(0o755)
        pairs = doctl_pairs if doctl_pairs is not None else \
            [(h["name"], h["ip"]) for h in PINNED_INV["hosts"]] + [("citrate-rpc-1", "142.93.58.145"),
                                                                  ("citrate-core-linux-build", "167.99.155.183")]
        (tmp / "doctl-all.txt").write_text("".join(f"{n}    {ip}\n" for n, ip in pairs))
        (tmp / "doctl-tag.txt").write_text("".join(f"{n}    {ip}\n" for n, ip in pairs if n.startswith("citrate-prod-")))
        d = self.bin / "doctl"
        d.write_text(f'#!/bin/sh\necho "doctl $*" >>"{self.calls}"\n'
                     f'case "$*" in *--tag-name*) cat "{tmp}/doctl-tag.txt" ;; *) cat "{tmp}/doctl-all.txt" ;; esac\n'
                     f'exit {doctl_rc}\n')
        d.chmod(0o755)

    def env(self) -> dict:
        return {"PATH": f"{self.bin}:{os.environ['PATH']}"}

    def ssh_calls(self) -> list[str]:
        if not self.calls.exists():
            return []
        return [l for l in self.calls.read_text().splitlines() if l.startswith(("ssh ", "scp "))]


SSH_STEPS = (["build", "--sha", "a" * 40], ["keys"], ["genesis-fill", "--fill-cmd", "true"], ["distribute"],
             ["start"], ["smoke"], ["stop"], ["wipe"], ["status"], ["tunnels", "up"], ["tunnels", "down"])


class HostAllowlist(unittest.TestCase):
    """Only citrate-prod-1..7 at their pinned IPs; the build host only for `build`."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dgx-r1006a."))
        self.state = self.tmp / "state"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def inv(self, hosts: list[tuple[str, str]], build=("citrate-core-linux-build", "167.99.155.183")) -> Path:
        p = self.tmp / "inv.json"
        d = dict(PINNED_INV, hosts=[{"name": n, "region": "x", "ip": ip} for n, ip in hosts],
                 build_host={"name": build[0], "ip": build[1], "arch": "x86_64-unknown-linux-gnu"})
        d.pop("ssh_key", None)
        p.write_text(json.dumps(d))
        return p

    def bring(self, inv: Path, *args: str, fleet: FakeFleet) -> subprocess.CompletedProcess:
        e = dict(os.environ, HOME=str(self.tmp), **fleet.env())
        return subprocess.run(["bash", str(BRINGUP), *args, "--inventory", str(inv), "--state", str(self.state)],
                              capture_output=True, text=True, env=e, timeout=120, stdin=subprocess.DEVNULL)

    def pinned(self) -> list[tuple[str, str]]:
        return [(h["name"], h["ip"]) for h in PINNED_INV["hosts"]]

    def test_pinned_table_matches_the_committed_inventory(self):
        import guard  # noqa: E402
        self.assertEqual(dict(self.pinned()), guard.PRODUCERS)
        self.assertEqual(sorted(guard.PRODUCERS), [f"citrate-prod-{i}" for i in range(1, 8)])
        self.assertEqual((PINNED_INV["build_host"]["name"], PINNED_INV["build_host"]["ip"]), guard.BUILD_HOST)
        self.assertNotIn(guard.BUILD_HOST[1], guard.PRODUCERS.values())

    def test_a_non_producer_host_is_refused_for_every_subcommand_before_connecting(self):
        bad = {
            "rpc-1": ("citrate-rpc-1", "142.93.58.145"),
            "unknown host": ("citrate-prod-8", "10.20.30.40"),
            "producer name at another IP": ("citrate-prod-3", "142.93.58.145"),
            "build host as a node": ("citrate-core-linux-build", "167.99.155.183"),
        }
        for label, pair in bad.items():
            hosts = self.pinned()[:2] + [pair] if pair[0] != "citrate-prod-3" else \
                [p for p in self.pinned() if p[0] != "citrate-prod-3"] + [pair]
            inv = self.inv(hosts)
            for step in SSH_STEPS:
                for dry in ((), ("--dry-run",)):
                    with self.subTest(host=label, step=step[0], dry=bool(dry)):
                        fleet = FakeFleet(self.tmp)
                        if fleet.calls.exists():
                            fleet.calls.unlink()
                        r = self.bring(inv, *step, *dry, fleet=fleet)
                        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                        self.assertIn("REFUSED", r.stderr)
                        self.assertEqual(fleet.ssh_calls(), [], "connected to a host before refusing")

    def test_build_refuses_any_build_host_but_the_approved_one(self):
        for b in (("citrate-rpc-1", "142.93.58.145"), ("citrate-core-linux-build", "142.93.58.145"),
                  ("citrate-prod-1", "206.189.35.49")):
            with self.subTest(build_host=b):
                fleet = FakeFleet(self.tmp)
                if fleet.calls.exists():
                    fleet.calls.unlink()
                r = self.bring(self.inv(self.pinned(), build=b), "build", "--sha", "a" * 40, fleet=fleet)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(fleet.ssh_calls(), [])

    def test_positive_control_status_reaches_exactly_the_pinned_producers(self):
        fleet = FakeFleet(self.tmp)
        r = self.bring(self.inv(self.pinned()), "status", fleet=fleet)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        targets = sorted({re.search(r"@([0-9.]+)", c).group(1) for c in fleet.ssh_calls()})
        self.assertEqual(targets, sorted(ip for _, ip in self.pinned()))
        self.assertTrue(any("--tag-name citrate-producer" in l for l in fleet.calls.read_text().splitlines()),
                        "live doctl cross-check ran")

    def test_positive_control_build_reaches_only_the_build_host(self):
        fleet = FakeFleet(self.tmp)
        r = self.bring(self.inv(self.pinned()), "build", "--sha", "a" * 40, fleet=fleet)
        # the fake ssh prints no build record, so the step fails after connecting
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        targets = {re.search(r"@([0-9.]+)", c).group(1) for c in fleet.ssh_calls()}
        self.assertEqual(targets, {"167.99.155.183"})

    def test_live_cross_check_mismatch_or_failure_refuses(self):
        moved = [(n, "10.9.9.9" if n == "citrate-prod-3" else ip) for n, ip in self.pinned()]
        for label, fleet in (("prod-3 moved", FakeFleet(self.tmp, doctl_pairs=moved)),
                             ("doctl fails", FakeFleet(self.tmp, doctl_rc=1))):
            with self.subTest(label):
                if fleet.calls.exists():
                    fleet.calls.unlink()
                r = self.bring(self.inv(self.pinned()), "status", fleet=fleet)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("live cross-check", r.stderr)
                self.assertEqual(fleet.ssh_calls(), [])


class GenesisRefusal(unittest.TestCase):
    """r1005's block 0 (or any release network's, or anything but the build's compiled
    r1006 genesis) is refused at genesis-fill, distribute and start."""

    def test_release_genesis_mirror_matches_hardening_rs(self):
        import guard  # noqa: E402
        src = HARDENING.read_text()
        block = src[src.index("pub const RELEASE_GENESIS"):]
        block = block[:block.index("];")]
        pinned = {"0x" + h for h in re.findall(r'hex32\("([0-9a-f]{64})"\)', block)}
        self.assertEqual(len(pinned), 3)
        self.assertEqual(set(guard.RELEASE_GENESIS), pinned)
        self.assertIn(R1005, pinned)
        agent = re.search(r"RELEASE_GENESIS_HASHES=\(([^)]*)\)", AGENT.read_text())
        self.assertIsNotNone(agent, "the host agent carries the release genesis list")
        self.assertEqual(set(agent.group(1).split()), pinned)

    def test_check_genesis_unit(self):
        import guard  # noqa: E402
        env = Env(1)
        try:
            repo = env.repo
            build = {"r1006_genesis": R1006_TEST}
            ok = {"genesis_hash": R1006_TEST, "genesis_profile": "r1006", "genesis_file": None,
                  "validator_registry": REG_TEST}
            self.assertEqual(guard.check_genesis(ok, build, repo), [])
            for label, fill, b in (
                ("r1005 hash", dict(ok, genesis_hash=R1005), build),
                ("team_testnet hash", dict(ok, genesis_hash="0x90044175c36a6491309d769bd0fa684afbf7b90b64136446db8e2e6ff0927553"), build),
                ("profile testnet_beta", dict(ok, genesis_profile="testnet_beta"), build),
                ("profile null", dict(ok, genesis_profile=None), build),
                ("profile default", dict(ok, genesis_profile="default"), build),
                ("genesis file", dict(ok, genesis_file="genesis.json"), build),
                ("not the committed r1006 genesis", dict(ok, genesis_hash="0x" + "07" * 32), build),
                ("another registry", dict(ok, validator_registry="0x" + "ee" * 20), build),
                ("build has no r1006 genesis", ok, {}),
                ("build compiles another r1006 genesis", ok, {"r1006_genesis": "0x" + "07" * 32}),
            ):
                with self.subTest(label):
                    self.assertNotEqual(guard.check_genesis(fill, b, repo), [], label)
        finally:
            env.close()

    def _keys(self, n=2) -> Env:
        env = Env(n)
        r = env.run("keys")
        self.assertEqual(r.returncode, 0, r.stderr)
        return env

    def test_genesis_fill_refuses_r1005_and_anything_but_the_r1006_genesis(self):
        env = self._keys()
        try:
            for label, cmd in (("r1005, testnet_beta", env.fill_cmd(R1005, "testnet_beta")),
                               ("r1005 under the r1006 name", env.fill_cmd(R1005, "r1006")),
                               ("profile null", env.fill_cmd(R1005, "null")),
                               ("another hash", env.fill_cmd("0x" + "07" * 32, "r1006")),
                               ("genesis file", env.fill_cmd(R1006_TEST, "r1006", "genesis.json"))):
                with self.subTest(label):
                    r = env.run("genesis-fill", "--fill-cmd", cmd)
                    self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertRegex(r.stdout + r.stderr, r"REFUSED|FAIL ")
                    self.assertFalse((env.state / "genesis" / "fill-result.json").exists(),
                                     "a refused fill must not be kept for distribute")
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1006_TEST))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((env.state / "genesis" / "fill-result.json").exists())
        finally:
            env.close()

    def test_the_expected_hash_is_the_committed_r1006_pin_read_at_run_time(self):
        """Re-pinning (after the fill, after the final rebuild) moves the expected hash: it is
        read from core/consensus/src/hardening.rs at run time, never from a constant."""
        env = self._keys()
        try:
            new = "0x" + "a8" * 32
            env.set_committed(new)
            # the recorded build still compiles the old pin: refused until it is rebuilt
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(new))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("rebuild", r.stdout + r.stderr)
            b = json.loads((env.state / "build.json").read_text())
            (env.state / "build.json").write_text(json.dumps(dict(b, r1006_genesis=new)))
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(new))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            # a fill of the OLD pin is now refused, though the old pin was valid before
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1006_TEST))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        finally:
            env.close()

    def test_no_committed_r1006_pin_fails_closed(self):
        env = self._keys()
        try:
            env.set_committed(None)
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1006_TEST))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("R1006_GENESIS", r.stdout + r.stderr)
            self.assertFalse((env.state / "genesis" / "fill-result.json").exists())
        finally:
            env.close()

    def test_a_committed_pin_equal_to_r1005_is_refused(self):
        env = self._keys()
        try:
            env.set_committed(R1005)
            b = json.loads((env.state / "build.json").read_text())
            (env.state / "build.json").write_text(json.dumps(dict(b, r1006_genesis=R1005)))
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1005))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse((env.state / "genesis" / "fill-result.json").exists())
        finally:
            env.close()

    def test_genesis_fill_refuses_a_fill_for_another_registry(self):
        env = self._keys()
        try:
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1006_TEST, registry="0x" + "ee" * 20))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("registry", r.stdout + r.stderr)
        finally:
            env.close()

    def test_genesis_fill_refuses_a_build_without_the_r1006_genesis(self):
        env = self._keys()
        try:
            b = json.loads((env.state / "build.json").read_text())
            b.pop("r1006_genesis")
            (env.state / "build.json").write_text(json.dumps(b))
            r = env.run("genesis-fill", "--fill-cmd", env.fill_cmd(R1006_TEST))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("no r1006 genesis", r.stdout + r.stderr)
        finally:
            env.close()

    def test_distribute_and_start_refuse_a_planted_r1005_fill_before_touching_a_host(self):
        for profile in ("testnet_beta", "r1006", None):
            with self.subTest(profile=profile):
                env = self._keys()
                try:
                    env.plant_fill(R1005, profile)
                    for step in (["distribute"], ["start"]):
                        r = env.run(*step)
                        self.assertEqual(r.returncode, 2, f"{step}: {r.stdout}{r.stderr}")
                        self.assertIn("REFUSED", r.stderr)
                    for i in (1, 2):
                        root = env.host_root(i)
                        self.assertFalse((root / "usr/local/bin/citrate-node").exists(), "binary installed")
                        self.assertEqual(list((root / "usr/local/lib/citrate-r1006/incoming").glob("*")), [])
                        self.assertFalse((root / "fake-node.log").exists(), "a node was started")
                finally:
                    env.close()

    def test_host_agent_refuses_release_genesis_hashes(self):
        env = self._keys(1)
        try:
            for args in (["probe-genesis", R1005], ["start", R1005], ["enable-mining", R1005]):
                with self.subTest(cmd=args[0]):
                    r = env.agent(1, *args)
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertIn("release", r.stderr)
            lib = env.host_root(1) / "usr/local/lib/citrate-r1006"
            (lib / "tools").mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO / "scripts/producers/gen_node_config.py", lib / "tools")
            shutil.copy(REPO / "scripts/producers/producerlib.py", lib / "tools")
            tmpl = json.loads((REPO / "scripts/producers/profiles/r1006.json").read_text())
            pub = json.loads((env.state / "pub" / "p1.pub.json").read_text())
            for label, gh, gp in (("r1005 hash", R1005, "r1006"), ("testnet_beta profile", R1006_TEST, "testnet_beta"),
                                  ("no profile", R1006_TEST, None)):
                with self.subTest(label):
                    prof = dict(tmpl, status="ready", genesis_hash=gh, genesis_profile=gp,
                                validator_registry="0x" + "00" * 18 + "1006", validators_at_genesis=True,
                                bootstrap_nodes=[])
                    (lib / "profile.json").write_text(json.dumps(prof))
                    r = env.agent(1, "write-config", pub["staker_address"], "off")
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertFalse((env.host_root(1) / "etc/citrate/node.toml").exists())
        finally:
            env.close()


def _unshare_ok() -> bool:
    try:
        return subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@unittest.skipUnless(_unshare_ok(), "needs unprivileged user + network namespaces")
class StartGateMiningOnlyOnTheR1006Genesis(unittest.TestCase):
    """keys -> genesis-fill -> distribute -> start --mining on, each host a fake node in
    its own network namespace (inside one user + net + pid namespace: nothing reaches the
    host's network). Mining is switched on only after EVERY host's block 0 is verified."""

    def _fleet(self, n: int, wrong_after_distribute: dict[int, str], after_start: str = "",
               fill_extra: str = "", pre_start=None,
               inv_extra: dict[str, dict] | None = None) -> tuple[Env, subprocess.CompletedProcess]:
        """after_start / pre_start: shell snippets (a str, or a function of the Env).
        inv_extra: extra inventory fields per host name (e.g. serve_recent_state_tags)."""
        env = Env(n)
        (env.tmp / "inv_extra.json").write_text(json.dumps(inv_extra or {}))
        if callable(after_start):
            after_start = after_start(env)
        pre_start = pre_start(env) if callable(pre_start) else (pre_start or "")
        inner = env.tmp / "inner.sh"
        sets = "\n".join(f'printf %s {h} >"{env.host_root(i)}/fake-block0"' for i, h in wrong_after_distribute.items())
        inner.write_text(f"""set -u
ip link set lo up
pids=""
for i in $(seq 1 {n}); do
  unshare --net sleep 600 &
  p=$!; pids="$pids $p"; sleep 0.2
  nsenter --net=/proc/$p/ns/net ip link set lo up
done
python3 - "{env.inv}" "{env.tmp}" $pids <<'PY'
import json, sys
inv, tmp, pids = sys.argv[1], sys.argv[2], sys.argv[3:]
hosts = [{{"name": f"p{{i}}", "region": "lo", "ip": f"10.206.0.{{i}}", "root": f"{{tmp}}/h{{i}}", "netns_pid": p}}
         for i, p in enumerate(pids, 1)]
extra = json.load(open(f"{{tmp}}/inv_extra.json"))
for h in hosts:
    h.update(extra.get(h["name"], {{}}))
json.dump({{"schema": "r1006-inventory/1", "transport": "local", "build_host": {{"name": "none", "ip": "127.0.0.1"}},
           "hosts": hosts}}, open(inv, "w"))
PY
B() {{ s="$1"; shift; bash {env.bringup} "$s" --inventory {env.inv} --state {env.state} "$@"; }}
for i in $(seq 1 {n}); do printf %s {R1006_TEST} >"{env.tmp}/h$i/fake-block0"; done
B keys || exit 10
B genesis-fill --fill-cmd "{env.fill_cmd(R1006_TEST)}{fill_extra}" || exit 11
B distribute || exit 12
{sets}
{pre_start}
B start --mining on --min-peers 0 --skip-producing-gate --gate-minutes 1
rc=$?
{after_start}
B stop >/dev/null 2>&1
exit $rc
""")
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork",
                            "--mount-proc", "sh", "-c", f"bash {inner}"],
                           capture_output=True, text=True, env=env.env, timeout=600, stdin=subprocess.DEVNULL)
        return env, r

    @staticmethod
    def starts(env: Env, i: int) -> list[tuple[bool, str, float]]:
        p = env.host_root(i) / "fake-node.log"
        out = []
        for line in (p.read_text().splitlines() if p.exists() else []):
            m = re.match(r"start mining=(true|false) block0=(\S+) t=([0-9.]+) probe=(\d)", line)
            if m and m.group(4) == "0":
                out.append((m.group(1) == "true", m.group(2), float(m.group(3))))
        return out

    def test_mining_is_enabled_only_after_every_host_shows_the_r1006_block0(self):
        env, r = self._fleet(3, {})
        try:
            self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
            for i in (1, 2, 3):
                self.assertTrue(self.starts(env, i), f"p{i} was started")
                self.assertFalse(self.starts(env, i)[0][0], f"p{i}: the first start must have mining off")
            mining_on = [t for i in (1, 2, 3) for (m, _, t) in self.starts(env, i) if m]
            verified_starts = [max(t for (m, _, t) in self.starts(env, i) if not m) for i in (1, 2, 3)]
            self.assertEqual(len(mining_on), 3, "each host restarted once with mining on")
            self.assertGreater(min(mining_on), max(verified_starts),
                               "a host mined before every host's block 0 was verified")
        finally:
            env.close()

    # A fake forge that enforces chain#398's CheckDeployedAdmins env contract on r1006, where
    # the GovernanceTimelock is in block 0 with no role history: genesis-chain mode (forced
    # by GENESIS_CHAIN=1, auto-detected when unset) needs GENESIS_ALLOC, the block-0 alloc,
    # or TIMELOCK-HOLDERS and GENESIS-FLOOR fail and the script reverts. forge reads only
    # under contracts/ (fs_permissions ./addresses), so both files must be staged there.
    # FAKE_FORGE_MODE (negative controls): th1rc0 = a TIMELOCK-HOLDERS failure with rc 0,
    # nocode1 = one NO-CODE entry, nofloor = no GENESIS-FLOOR line, rc1 = all 0 but rc 1.
    FAKE_FORGE = r"""#!/bin/sh
log="$(dirname "$0")/forge.calls"
echo "GENESIS_CHAIN=${GENESIS_CHAIN-<unset>} GENESIS_ALLOC=${GENESIS_ALLOC-<unset>} ADDRESS_BOOK=${ADDRESS_BOOK-<unset>}" >>"$log"
echo "$*" >>"$(dirname "$0")/forge.args"
readable() { case "$1" in addresses/*) [ -f "$1" ] ;; *) echo "vm.readFile: the path $1 is not allowed to be accessed for read operations"; exit 1 ;; esac; }
readable "$ADDRESS_BOOK" || { echo "no such book $ADDRESS_BOOK"; exit 1; }
th=0 floor=0
if [ "${GENESIS_CHAIN:-}" != 0 ]; then
  if [ -z "${GENESIS_ALLOC:-}" ]; then
    echo "  TIMELOCK-HOLDERS GovernanceTimelock: genesis-chain mode needs GENESIS_ALLOC (the block-0 allocation) to prove the holder sets complete"
    th=1 floor=1
  else
    readable "$GENESIS_ALLOC" || { echo "no such alloc $GENESIS_ALLOC"; exit 1; }
    grep -q '"alloc"' "$GENESIS_ALLOC" || { echo "  TIMELOCK-HOLDERS the timelock's storage is not in GENESIS_ALLOC"; th=1; }
    cp "$GENESIS_ALLOC" "$(dirname "$0")/alloc.seen"
  fi
fi
nocode=0 rc=0
case "${FAKE_FORGE_MODE:-}" in th1rc0) th=1 ;; nocode1) nocode=1 ;; rc1) rc=1 ;; esac
echo "  FACTORY-ADMIN failures: 0"
echo "  DEPLOYER-ADMIN failures: 0"
echo "  NO-CODE entries (reported): $nocode"
echo "  VERIFIER present: true"
echo "  TIMELOCK-HOLDERS failures: $th"
[ "${FAKE_FORGE_MODE:-}" = nofloor ] || echo "  GENESIS-FLOOR failures: $floor"
[ "${FAKE_FORGE_MODE:-}" = th1rc0 ] && exit 0
[ $th -eq 0 ] && [ $floor -eq 0 ] && [ $nocode -eq 0 ] || exit 1
exit $rc
"""

    def test_smoke_admins_run_in_genesis_chain_mode_with_the_staged_alloc_and_every_class_0(self):
        """smoke passes GENESIS_CHAIN=1 and GENESIS_ALLOC (the fill's alloc staged under
        contracts/addresses like the book), requires forge rc 0 and exactly one 0 for
        FACTORY-ADMIN, DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS and GENESIS-FLOOR, and
        removes both staged files afterwards."""
        d = Path(tempfile.mkdtemp(prefix="dgx-r1006f."))
        fake = d / "forge"
        fake.write_text(self.FAKE_FORGE)
        fake.chmod(0o755)
        modes = ("ok", "th1rc0", "nocode1", "nofloor", "rc1")
        smoke = "\n".join(f'FAKE_FORGE_MODE={m} FORGE={fake} B smoke --min-height 0 --gate-minutes 1 '
                          f'--skip code,orangeseed,logs >"{d}/smoke-{m}.out" 2>&1' for m in modes)
        env, r = self._fleet(2, {}, after_start=smoke, fill_extra=" --address-book",
                             inv_extra={"p1": {"serve_recent_state_tags": 64}})
        try:
            out = {m: (d / f"smoke-{m}.out").read_text() for m in modes}
            self.assertIn("PASS  admins (genesis-chain mode): FACTORY-ADMIN, DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS, "
                          "GENESIS-FLOOR all 0", out["ok"], out["ok"][-2500:])
            calls = (d / "forge.calls").read_text().splitlines()
            self.assertEqual(len(calls), len(modes), calls)
            for c in calls:
                self.assertRegex(c, r"^GENESIS_CHAIN=1 GENESIS_ALLOC=addresses/\.r1006-smoke-\S+\.json "
                                    r"ADDRESS_BOOK=addresses/\.r1006-smoke-\S+\.json$")
            self.assertEqual(json.loads((d / "alloc.seen").read_text()),
                             json.loads((env.state / "genesis/alloc.json").read_text()),
                             "forge read the fill's own genesis alloc")
            for m in modes[1:]:
                with self.subTest(negative_control=m):
                    self.assertIn("FAIL  admins (genesis-chain mode)", out[m], out[m][-2500:])
                    self.assertNotIn("PASS  admins", out[m])
            self.assertEqual(list((env.repo / "contracts/addresses").glob(".r1006-smoke-*")), [],
                             "the staged book and alloc are removed after the check")
        finally:
            env.close()
            shutil.rmtree(d)

    def test_smoke_admins_fail_closed_without_a_genesis_alloc_in_the_fill(self):
        d = Path(tempfile.mkdtemp(prefix="dgx-r1006f."))
        fake = d / "forge"
        fake.write_text(self.FAKE_FORGE)
        fake.chmod(0o755)
        def smoke(e: Env) -> str:
            drop = ("python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d[\"alloc_file\"]=None; "
                    f"json.dump(d,open(p,\"w\"))' \"{e.state}/genesis/fill-result.json\"")
            return (f'{drop}\nFORGE={fake} B smoke --min-height 0 --gate-minutes 1 --skip code,orangeseed,logs '
                    f'>"{d}/smoke.out" 2>&1')
        env, r = self._fleet(2, {}, after_start=smoke, fill_extra=" --address-book",
                             inv_extra={"p1": {"serve_recent_state_tags": 64}})
        try:
            out = (d / "smoke.out").read_text()
            self.assertIn("FAIL  admins (genesis-chain mode)", out, out[-2500:])
            self.assertFalse((d / "forge.calls").exists(), "forge is not run without the block-0 alloc")
        finally:
            env.close()
            shutil.rmtree(d)

    def test_smoke_forge_reads_use_the_operator_host_and_the_log_window_is_reported(self):
        """Since chain#425 a node refuses a state read pinned to a block that is no longer
        its executed head, and forge pins every read to the block it started at. So smoke
        runs forge only against the host whose inventory entry sets
        serve_recent_state_tags (distribute writes it into that host's [rpc] section, and
        only that host's), never blindly the first tunnel; with no such host the admins
        check fails naming the key, without running forge. The log window (--logs-since,
        default the recorded start) is printed in the log check's PASS/FAIL line."""
        d = Path(tempfile.mkdtemp(prefix="dgx-r1006o."))
        fake = d / "forge"
        fake.write_text(self.FAKE_FORGE)
        fake.chmod(0o755)
        common = "--min-height 0 --gate-minutes 1 --skip code,orangeseed"
        def smoke(e: Env) -> str:
            undesignate = ("python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); "
                           "[h.pop(\"serve_recent_state_tags\", None) for h in d[\"hosts\"]]; "
                           f"json.dump(d,open(p,\"w\"))' \"{e.inv}\"")
            return "\n".join([
                f'FORGE={fake} B smoke {common} >"{d}/smoke-p2.out" 2>&1',
                f'FORGE={fake} B smoke {common} --only p1 >"{d}/smoke-only-p1.out" 2>&1',
                f'FORGE={fake} B smoke {common} --logs-since 1234567890 >"{d}/smoke-since.out" 2>&1',
                f'B smoke {common} --logs-since 12x >"{d}/smoke-badsince.out" 2>&1; echo $? >"{d}/badsince.rc"',
                f'cp "{e.host_root(1)}/etc/citrate/node.toml" "{d}/p1.toml"',
                f'cp "{e.host_root(2)}/etc/citrate/node.toml" "{d}/p2.toml"',
                undesignate,
                f'mv "{d}/forge.args" "{d}/forge.args.designated" 2>/dev/null',
                f'FORGE={fake} B smoke {common} >"{d}/smoke-none.out" 2>&1',
            ])
        env, r = self._fleet(2, {}, after_start=smoke, fill_extra=" --address-book",
                             inv_extra={"p2": {"serve_recent_state_tags": 64}})
        try:
            p2_url = "--rpc-url http://127.0.0.1:18546"
            out = {k: (d / f"smoke-{k}.out").read_text() for k in ("p2", "only-p1", "since", "none")}
            # distribute: the window is in the designated host's node.toml only
            self.assertRegex((d / "p2.toml").read_text(), r"(?m)^serve_recent_state_tags = 64$")
            self.assertNotIn("serve_recent_state_tags", (d / "p1.toml").read_text())
            # smoke: forge goes to p2's tunnel (the second, not urls[0]), also with --only p1
            args = (d / "forge.args.designated").read_text().splitlines() if (d / "forge.args.designated").exists() else []
            self.assertEqual(len(args), 3, args)
            for a in args:
                self.assertIn(p2_url, a)
            self.assertIn("PASS  admins (genesis-chain mode)", out["p2"], out["p2"][-2500:])
            self.assertIn("PASS  admins (genesis-chain mode)", out["only-p1"], out["only-p1"][-2500:])
            self.assertIn("via p2", out["p2"])
            # no designated host: a clear failure naming the key, and forge is not run
            self.assertFalse((d / "forge.args").exists(), "forge ran with no operator host")
            self.assertRegex(out["none"], r"FAIL  admins.*serve_recent_state_tags")
            # the log window is printed in the log check's line
            started = (env.state / "started_at").read_text().strip()
            self.assertRegex(out["p2"], rf"(PASS|FAIL)  .*CONFLICT / fork.*epoch {started}, from the start record")
            self.assertRegex(out["since"], r"(PASS|FAIL)  .*CONFLICT / fork.*epoch 1234567890, from --logs-since")
            self.assertEqual((d / "badsince.rc").read_text().strip(), "2", (d / "smoke-badsince.out").read_text())
        finally:
            env.close()
            shutil.rmtree(d)

    def test_start_refuses_a_host_binary_older_than_min_chain_rev_before_any_start(self):
        """Pre-join guard: every host's installed binary must report a clean build rev that
        is MIN_CHAIN_REV or a descendant of it in the local checkout (git merge-base
        --is-ancestor). Anything else, or no MIN_CHAIN_REV at all, refuses before any host
        is started. The final start (all hosts on a descendant) is the positive control."""
        cases = {
            "old": 'printf %s "$(git -C {repo} rev-parse --short=12 HEAD~2)" >{h2}/fake-git-sha',
            "side": 'printf %s "$(git -C {repo} rev-parse --short=12 side)" >{h2}/fake-git-sha',
            "unknown": 'printf unknown >{h2}/fake-git-sha',
            "notinrepo": 'printf %s 0123456789ab >{h2}/fake-git-sha',
            "dirty": 'touch {h2}/fake-git-dirty',
            "unset": 'mv {minf} {minf}.off',
            "badmin": 'printf "%s\\n" "$(git -C {repo} rev-parse --short=12 HEAD~1)" >{minf}',
            "minnotinrepo": 'printf "%s\\n" 1111111111111111111111111111111111111111 >{minf}',
            "lowerflag": "",
        }
        restore = ('printf %s "$(git -C {repo} rev-parse --short=12 HEAD)" >{h2}/fake-git-sha; rm -f {h2}/fake-git-dirty; '
                   'printf "%s\\n" "$(git -C {repo} rev-parse HEAD~1)" >{minf}')
        pre = []
        for name, setup in cases.items():
            extra = '--min-chain-rev "$(git -C {repo} rev-parse HEAD~2)"' if name == "lowerflag" else ""
            pre.append(f'{setup}\nB start --mining on --min-peers 0 --skip-producing-gate --gate-minutes 1 {extra} '
                       f'>"{{tmp}}/case-{name}.out" 2>&1; echo $? >"{{tmp}}/case-{name}.rc"\n'
                       f'cat {{h1}}/fake-node.log {{h2}}/fake-node.log 2>/dev/null | grep -c "probe=0" >"{{tmp}}/case-{name}.starts"\n'
                       f'{restore}')
        def fmt(e: Env) -> str:
            return "\n".join(pre).format(repo=e.repo, h1=e.host_root(1), h2=e.host_root(2), minf=e.min_rev_file,
                                         tmp=e.tmp)
        env, r = self._fleet(2, {}, pre_start=fmt)
        try:
            self.assertEqual(r.returncode, 0, "the final start (every host past the floor) passes: "
                             + r.stdout[-3000:] + r.stderr[-3000:])
            for name in cases:
                with self.subTest(case=name):
                    out = (env.tmp / f"case-{name}.out").read_text()
                    self.assertEqual((env.tmp / f"case-{name}.rc").read_text().strip(), "2", out[-2500:])
                    self.assertIn("MIN_CHAIN_REV", out, out[-2500:])
                    self.assertEqual((env.tmp / f"case-{name}.starts").read_text().strip(), "0",
                                     f"{name}: a node was started before the refusal: {out[-1500:]}")
            self.assertTrue(self.starts(env, 1) and self.starts(env, 2), "the positive control started both hosts")
        finally:
            env.close()

    def test_mining_is_never_enabled_when_a_host_shows_r1005s_block0(self):
        env, r = self._fleet(3, {2: R1005})
        try:
            self.assertNotEqual(r.returncode, 0, r.stdout[-3000:])
            self.assertNotIn(r.returncode, (10, 11, 12), "keys/genesis-fill/distribute must pass: " + r.stdout[-3000:])
            self.assertTrue(self.starts(env, 1), "p1 was started (the gate ran)")
            for i in (1, 2, 3):
                self.assertFalse(any(m for (m, _, _) in self.starts(env, i)),
                                 f"p{i} was started with mining on: {self.starts(env, i)}")
        finally:
            env.close()


class RegistrationProofs(unittest.TestCase):
    """keys also collects each host's `citrate registration-proof --registry <committed
    ValidatorRegistry>` into r1006-registration-proofs.json, through the same on-host and
    in-memory checks as the identities."""

    def test_keys_collects_one_checked_proof_per_host(self):
        env = Env(3)
        try:
            r = env.run("keys")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((env.state / "r1006-registration-proofs.json").exists(), "keys wrote no proofs file")
            doc = json.loads((env.state / "r1006-registration-proofs.json").read_text())
            prod = json.loads((env.state / "r1006-producers.json").read_text())["producers"]
            self.assertEqual(len(doc["proofs"]), 3)
            for p, v in zip(doc["proofs"], prod):
                self.assertEqual(sorted(p), ["chain_id", "proposer_pubkey", "registration_sig", "registry", "schema",
                                             "staker"])
                self.assertEqual(p["schema"], "citrate-registration-proof/1")
                self.assertEqual(p["chain_id"], 40204)
                self.assertEqual(p["registry"], REG_TEST)
                self.assertEqual(p["staker"], v["staker_address"])
                self.assertEqual(p["proposer_pubkey"], v["proposer_pubkey"])
                self.assertRegex(p["registration_sig"], r"^0x[0-9a-f]{128}$")
            seen = tree_bytes(env.state) + r.stdout.encode() + r.stderr.encode()
            for n in (n for s_ in env.secrets() for n in leak_needles(s_)):
                self.assertNotIn(n, seen)
        finally:
            env.close()

    def test_a_proof_for_another_staker_or_registry_is_refused(self):
        if os.environ.get("R1006_TEST_KEYTOOL"):
            self.skipTest("fake-keytool control")
        for label, extra in (("staker", {"FAKE_PROOF_STAKER": "0x" + "77" * 20}),
                             ("registry", {"FAKE_PROOF_REGISTRY": "0x" + "ee" * 20}),
                             ("extra field", {"FAKE_PROOF_EXTRA": '"seed": "00"'})):
            with self.subTest(label):
                env = Env(2)
                try:
                    r = env.run("keys", env=extra)
                    self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertFalse((env.state / "r1006-registration-proofs.json").exists())
                    self.assertEqual(list((env.state / "pub").glob("*.proof.json")), [])
                finally:
                    env.close()

    def test_a_proof_step_that_leaks_the_proposer_key_is_contained(self):
        for scan in (True, False):
            with self.subTest(host_scan=scan):
                env = Env(2)
                try:
                    src = mutate(AGENT.read_text(), [(PROOF_ANCHOR, PROOF_ANCHOR + '\n  cat -- "$DATA/proposer.key" >&2')])
                    if not scan:
                        src = mutate(src, NO_HOST_SCAN)
                    m = env.tmp / "agent.mut.sh"
                    m.write_text(src)
                    r = env.run("keys", agent=m)
                    self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertFalse((env.state / "r1006-registration-proofs.json").exists())
                    seen = tree_bytes(env.state) + r.stdout.encode() + r.stderr.encode()
                    for n in (n for s_ in env.secrets() for n in leak_needles(s_)):
                        self.assertNotIn(n, seen)
                finally:
                    env.close()

    def test_no_committed_registry_fails_closed(self):
        env = Env(2)
        try:
            env.set_committed(R1006_TEST, None)
            r = env.run("keys")
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("ValidatorRegistry", r.stdout + r.stderr)
        finally:
            env.close()


# The line in host_agent.sh after which a mutation leaks from the proof step.
PROOF_ANCHOR = 'proof_tool_rc=0'


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

    def test_log_scan_counts_mp_s1_skipped_rounds(self):
        # The producer's MP-S1 guard declines to seal on a fork-choice parent its executor has
        # not applied (it would commit a state root no peer reproduces) and skips the round.
        # That is the guard working, seen on the live r1006 fleet at start: counted and shown,
        # not failed. Any other line naming a fork still fails.
        log = self.root / "var/log/citrate-node.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        skip = ("ERROR citrate::producer: Failed to produce block: MP-S1: fork-choice selected parent 3539c0e1 "
                "but this node's applied tip is 8dea4fea @ 35 \u2014 the executor holds the applied tip's state, "
                "so sealing on 3539c0e1 would commit a state_root no peer can reproduce (the 2026-07-27 "
                "concurrent-producer fork). Skipping this production round; the execute-on-receive "
                "drain/reorg will converge the applied tip.\n")
        log.write_text(skip + skip)
        r = self.env.agent(1, "logs-scan", "0")
        self.assertIn("matches 0", r.stdout, r.stdout)
        self.assertIn("producer_skips 2", r.stdout)
        with log.open("a") as f:
            f.write("ERROR MP-S1: concurrent-producer fork detected, state root mismatch\n")
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
                     "validator_registry": "0x" + "cd" * 20, "validator_activation_height": 1000,
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

    def test_activation_below_s1_is_refused_even_with_a_genesis_validator_set(self):
        """The node refuses a validator activation height below S(1)=800 (r1006: 1000)."""
        for h, at_genesis, want_rc in ((0, True, 2), (799, True, 2), (0, False, 2), (800, True, 0), (1000, True, 0)):
            with self.subTest(height=h, validators_at_genesis=at_genesis):
                fill = dict(self.fill, validator_activation_height=h, validators_at_genesis=at_genesis)
                self.assertEqual(render_profile.check_fill(fill, self.prod, None) == [], want_rc == 0)
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


class OperatorEndpoint(unittest.TestCase):
    """[rpc] serve_recent_state_tags: one designated operator host (inventory field), whose
    tunnel smoke uses for forge; every other host stays strict (chain#425)."""

    def test_committed_inventory_designates_only_prod1_at_64(self):
        got = [(h["name"], h["serve_recent_state_tags"]) for h in PINNED_INV["hosts"] if "serve_recent_state_tags" in h]
        self.assertEqual(got, [("citrate-prod-1", 64)])

    def test_guard_checks_the_window_value(self):
        import guard
        base = {"transport": "local", "hosts": [{"name": "p1", "ip": "10.0.0.1"}, {"name": "p2", "ip": "10.0.0.2"}]}
        for v in (0, 1, 64, 1024):
            with self.subTest(ok=v):
                inv = json.loads(json.dumps(base))
                inv["hosts"][1]["serve_recent_state_tags"] = v
                self.assertEqual(guard.check_inventory(inv), [])
        for v in (1025, -1, True, "64", 1.5, None, 10**30):
            with self.subTest(bad=v):
                inv = json.loads(json.dumps(base))
                inv["hosts"][1]["serve_recent_state_tags"] = v
                probs = guard.check_inventory(inv)
                self.assertTrue(any("serve_recent_state_tags" in p for p in probs), probs)

    def test_render_profile_sets_the_window_only_when_asked(self):
        rp = RenderProfileTest("test_consistent_fill")
        rp.setUp()
        prof = render_profile.render(rp.template, rp.prod, rp.fill, "p1")
        self.assertNotIn("rpc", prof)
        prof = render_profile.render(rp.template, rp.prod, rp.fill, "p1", serve_recent_state_tags=0)
        self.assertNotIn("rpc", prof)
        prof = render_profile.render(rp.template, rp.prod, rp.fill, "p1", serve_recent_state_tags=64)
        self.assertEqual(prof["rpc"], {"serve_recent_state_tags": 64})
        for bad in (1025, -1, True):
            with self.subTest(bad=bad), self.assertRaises(render_profile.RenderError):
                render_profile.render(rp.template, rp.prod, rp.fill, "p1", serve_recent_state_tags=bad)

    def test_smoke_dry_run_names_the_operator_endpoint_and_the_log_window(self):
        env = Env(2)
        try:
            r = env.run("smoke", "--dry-run")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("serve_recent_state_tags", r.stdout)
            self.assertIn("no inventory host sets", r.stdout)
            self.assertIn("since the start record", r.stdout)
            inv = json.loads(env.inv.read_text())
            inv["hosts"][1]["serve_recent_state_tags"] = 64
            env.inv.write_text(json.dumps(inv))
            r = env.run("smoke", "--dry-run", "--logs-since", "1234567890")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("forge via p2 (serve_recent_state_tags = 64)", r.stdout)
            self.assertIn("epoch 1234567890, from --logs-since", r.stdout)
            for bad in ("12x", "", "-5"):
                with self.subTest(logs_since=bad):
                    r = env.run("smoke", "--dry-run", "--logs-since", bad)
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            inv["hosts"][1]["serve_recent_state_tags"] = 4096
            env.inv.write_text(json.dumps(inv))
            r = env.run("smoke", "--dry-run")
            self.assertEqual(r.returncode, 2, "an out-of-range window is refused before any step")
        finally:
            env.close()


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



class BuildRevRunsAsNodeUser(unittest.TestCase):
    """build-rev runs the installed binary as the node user. `consensus --json` reads the
    data dir's block 0 (chain#398), so run as root it leaves root-owned RocksDB files in the
    node's data dir and the node (User=citrate) then fails on LOCK: Permission denied
    (r1006 bring-up, citrate-prod-1, 2026-10-27)."""

    def test_build_rev_goes_through_runuser(self):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            root, shim = t / "root", t / "shim"
            (root / "usr/local/bin").mkdir(parents=True)
            shim.mkdir()
            log = t / "calls.log"
            node = root / "usr/local/bin/citrate-node"
            node.write_text("#!/usr/bin/env bash\n"
                            f'echo "node uid-switched=${{RUNUSER_SHIM:-no}} $*" >>"{log}"\n'
                            'echo \'{"git_sha":"9a32147e2aac","git_dirty":false}\'\n')
            node.chmod(0o755)
            (shim / "runuser").write_text("#!/usr/bin/env bash\n"
                                          f'echo "runuser $*" >>"{log}"\n'
                                          '[[ "$1" == -u && "$3" == -- ]] || exit 9\n'
                                          'shift 3; RUNUSER_SHIM="$RUNUSER_U" exec "$@"\n')
            (shim / "runuser").chmod(0o755)
            env = dict(os.environ, R1006_ROOT=str(root), R1006_SERVICE="proc", R1006_RUN_AS="citrate",
                       RUNUSER_U="citrate", PATH=f"{shim}:{os.environ['PATH']}", HOME=str(t))
            r = subprocess.run(["bash", str(AGENT), "build-rev"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(r.stdout.strip(), "9a32147e2aac false")
            calls = log.read_text()
            self.assertIn("runuser -u citrate -- ", calls)
            self.assertIn("node uid-switched=citrate consensus --json", calls)
            self.assertNotIn("uid-switched=no", calls)

if __name__ == "__main__":
    unittest.main()
