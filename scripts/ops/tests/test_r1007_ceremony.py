#!/usr/bin/env python3
"""Tests for scripts/ops/r1007/{params,ceremony,node_agent}.py.

Everything runs in temp dirs; no host, network or real key is touched. The node binary
is replaced, where one is needed, by a small script that prints a consensus manifest.
The end-to-end bring-up with the real binary in network namespaces is
scripts/ops/r1007/devnet.sh (Linux).

  python3 -m unittest scripts/ops/tests/test_r1007_ceremony.py -v
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
R7 = REPO / "scripts" / "ops" / "r1007"
sys.path.insert(0, str(R7))
sys.path.insert(0, str(REPO / "scripts" / "producers"))
import ceremony as C  # noqa: E402
import node_agent as NA  # noqa: E402
import params as P  # noqa: E402

SRC = P.load(REPO)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fleet_guard  # noqa: E402

# Every ssh-transport test uses this copy of the committed fleet: the same hosts, with ssh
# aliases that cannot resolve (RFC 2606 .invalid). ceremony.HERE points at its directory, so
# the tool's "committed fleet" checks accept it (fed #467 round 3).
_FLEET_DIR = Path(tempfile.mkdtemp(prefix="r1007-fleet-copy-"))
FLEET = _FLEET_DIR / "fleet.r1007.json"
_HERE_REAL = C.HERE


def setUpModule():
    fleet_guard.install()
    f = json.loads((R7 / "fleet.r1007.json").read_text())
    for h in f["hosts"]:
        h["ssh"] = h["name"] + ".invalid"
    FLEET.write_text(json.dumps(f))
    C.HERE = _FLEET_DIR


def tearDownModule():
    C.HERE = _HERE_REAL
    fleet_guard.uninstall()
    shutil.rmtree(_FLEET_DIR, ignore_errors=True)


def peer(i: int) -> str:
    return "noise_" + f"{i:02x}" * 32


def local_fleet(tmp: Path, nprod: int = 3) -> Path:
    hosts = []
    i = 0
    for role, names in (("boot", ["citrate-boot-1", "citrate-boot-2", "citrate-boot-3"]),
                        ("producer", [f"citrate-prod-{k}" for k in range(1, nprod + 1)]),
                        ("rpc", ["citrate-rpc-1"])):
        for n in names:
            i += 1
            root = tmp / "hosts" / n
            root.mkdir(parents=True)
            hosts.append({"name": n, "role": role, "p2p_host": f"10.207.0.{i}", "peer_id": None, "root": str(root), "netns_pid": ""})
    hosts[-1]["indexer"] = True
    f = tmp / "fleet.json"
    f.write_text(json.dumps({"schema": "r1007-fleet/1", "chain_id": 40204, "transport": "local", "p2p_port": 30303, "hosts": hosts}))
    ids = {h["name"]: {"peer_id": peer(k + 1), "proposer_pubkey": "0x" + "aa" * 32, "staker_address": "0x" + f"{k + 1:02x}" * 20}
           for k, h in enumerate(hosts)}
    (tmp / "state").mkdir()
    (tmp / "state" / "identities.json").write_text(json.dumps({"schema": "r1007-identities/1", "hosts": ids}))
    return f


def fake_binary(tmp: Path, *, params: str | None = None, genesis: str | None = None, fingerprint: str = "0xfp") -> Path:
    """Stands in for `citrate --config X consensus --json` (prints a manifest)."""
    m = {
        "genesis_hash": genesis or SRC["r1007_genesis"],
        "genesis_rules": "mpt_state_root:0|pba_hardening:0|params:" + (params or SRC["params_render"]),
        "fingerprint": fingerprint,
        "r1007_genesis": SRC["r1007_genesis"],
    }
    b = tmp / f"citrate-{abs(hash((params, genesis, fingerprint)))}"
    # Like the real node: log lines on stdout first, then the pretty-printed manifest.
    b.write_text("#!/bin/sh\necho '  2026-11-09T15:00:33Z INFO citrate_storage: RocksDB opened'\ncat <<'EOF'\n" + json.dumps(m, indent=2) + "\nEOF\n")
    b.chmod(0o755)
    return b


class FleetIsolation(unittest.TestCase):
    """fed #467 round 3 (BerryManifold P1): no test in this module can reach a fleet host.
    scripts/ops/tests/fleet_guard.py blocks ssh/scp/doctl and os.system for the whole
    module, and every ssh-transport test uses a copy of the fleet whose aliases end in
    .invalid. Each probe below would be harmless even without the guard (`ssh -G` does not
    connect; 192.0.2.1 is TEST-NET-1)."""

    def test_the_guard_is_installed_for_this_module(self):
        import fleet_guard  # noqa: F401  (red: absent at 2beaa095)
        self.assertTrue(fleet_guard.installed())

    def test_a_real_ssh_or_doctl_call_raises(self):
        import fleet_guard
        self.assertTrue(fleet_guard.installed())
        for argv in (["ssh", "-G", "citrate-boot-1"], ["scp", "-h"], ["doctl", "version"]):
            with self.assertRaises(fleet_guard.FleetCallBlocked, msg=argv):
                subprocess.run(argv, capture_output=True, timeout=5)
            with self.assertRaises(fleet_guard.FleetCallBlocked, msg=argv):
                subprocess.check_output(argv, timeout=5)
        with self.assertRaises(fleet_guard.FleetCallBlocked):
            os.system("true")

    def test_a_non_loopback_connection_raises(self):
        import socket
        import fleet_guard
        self.assertTrue(fleet_guard.installed())
        with self.assertRaises(fleet_guard.FleetCallBlocked):
            socket.create_connection(("192.0.2.1", 9), timeout=0.5)

    def test_child_processes_get_an_ssh_that_refuses(self):
        import fleet_guard
        self.assertTrue(fleet_guard.installed())
        r = subprocess.run(["sh", "-c", "ssh -G host.invalid"], capture_output=True, text=True, timeout=5)
        self.assertEqual(r.returncode, 97, r.stdout + r.stderr)

    def test_ssh_tests_use_a_fleet_copy_that_cannot_resolve(self):
        fleet = json.loads(FLEET.read_text())
        self.assertEqual(fleet["transport"], "ssh")
        self.assertTrue(all(h["ssh"].endswith(".invalid") for h in fleet["hosts"]), fleet["hosts"])
        self.assertNotEqual(FLEET.resolve(), (R7 / "fleet.r1007.json").resolve())
        self.assertEqual((C.HERE / "fleet.r1007.json").resolve(), FLEET.resolve())


class _Stack:
    """Enter several context managers as one."""

    def __init__(self, *cms):
        self.cms = cms

    def __enter__(self):
        for c in self.cms:
            c.__enter__()
        return self

    def __exit__(self, *exc):
        for c in reversed(self.cms):
            c.__exit__(*exc)
        return False


def run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = C.main(argv)
    return rc, buf.getvalue()


class Params(unittest.TestCase):
    def test_reads_the_compiled_values(self):
        self.assertEqual(SRC["r1007_genesis"], "0x" + re.search(r'R1007_GENESIS: \[u8; 32\] =\s*hex32\("([0-9a-f]{64})"\)',
                                                                (REPO / P.HARDENING).read_text()).group(1))
        self.assertEqual(SRC["params"]["checkpoint_interval"], 50)
        self.assertEqual(SRC["default_vote_depth"], SRC["params"]["checkpoint_vote_depth"])
        self.assertEqual(len(SRC["producers"]), 7)

    def test_render_matches_the_rust_rendering_format(self):
        # GenesisChainParams::render(): name=value in field order, joined by ','.
        r = SRC["params_render"]
        self.assertEqual([kv.split("=")[0] for kv in r.split(",")], list(P.PARAM_FIELDS))
        self.assertIn("pruning_depth=10000,undo_window=10000", r)

    def test_a_changed_struct_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            (t / P.GENESIS_PARAMS).parent.mkdir(parents=True)
            src = (REPO / P.GENESIS_PARAMS).read_text().replace("    slot_duration_secs: 1,\n", "", 1)
            (t / P.GENESIS_PARAMS).write_text(src)
            with self.assertRaises(P.ParamsError):
                P.chain_params(t)


class RenderAndCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1007t."))
        self.fleet = local_fleet(self.tmp)
        self.bin = fake_binary(self.tmp)
        self.base = ["--fleet", str(self.fleet), "--state", str(self.tmp / "state"), "--binary", str(self.bin)]
        rc, _ = run(["render", *self.base, "--network", "r1007"])
        self.assertEqual(rc, 0)
        self.rdir = self.tmp / "state" / "render" / "r1007"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check(self, binary: bool = False) -> tuple[int, str]:
        args = ["check", "--fleet", str(self.fleet), "--state", str(self.tmp / "state"), "--network", "r1007"]
        if binary:
            args += ["--binary", str(self.bin)]
        return run(args)

    def edit(self, host: str, name: str, fn, rehash: bool = True) -> None:
        f = self.rdir / host / name
        f.write_text(fn(f.read_text()))
        if rehash:
            m = json.loads((self.rdir / host / "manifest.json").read_text())
            m["files"][name] = C.sha256(f)
            (self.rdir / host / "manifest.json").write_text(json.dumps(m))

    def test_every_role_is_rendered_and_passes(self):
        rc, out = self.check(binary=True)
        self.assertEqual(rc, 0, out)
        man = json.loads((self.rdir / "render-manifest.json").read_text())
        self.assertEqual(man["params_render"], SRC["params_render"])
        self.assertEqual(len(man["hosts"]), 7)
        self.assertTrue((self.rdir / "citrate-prod-1" / "node.mine.toml").exists())
        self.assertFalse((self.rdir / "citrate-boot-1" / "node.mine.toml").exists())
        self.assertFalse((self.rdir / "citrate-rpc-1" / "node.mine.toml").exists())

    def test_rendered_values(self):
        t = C.parse_toml((self.rdir / "citrate-prod-2" / "node.mine.toml").read_text())
        self.assertEqual(t["chain"]["genesis_profile"], "r1007")
        self.assertEqual(t["checkpoint"]["interval"], SRC["params"]["checkpoint_interval"])
        self.assertEqual(t["checkpoint"]["committee_size"], SRC["params"]["committee_size"])
        self.assertTrue(t["mining"]["enabled"])
        self.assertTrue(t["storage"]["data_dir"].endswith("/var/lib/citrate/gen/r1007"))
        boots = t["network"]["bootstrap_nodes"]
        self.assertEqual(len(boots), 3 + 2)  # 3 boots + the 2 other producers, not itself, not rpc
        self.assertNotIn(f"{peer(5)}@10.207.0.5:30303", boots)
        env = C.parse_env((self.rdir / "citrate-prod-2" / "citrate-node.env").read_text())
        self.assertEqual(env["CITRATE_DAG_PRUNE_RETAIN"], str(SRC["params"]["pruning_depth"]))
        self.assertEqual(env["CITRATE_VALIDATOR_REGISTRY"].lower(), SRC["validator_registry"])
        unit = (self.rdir / "citrate-prod-2" / "citrate-node.service").read_text()
        self.assertIn("KillSignal=SIGINT", unit)  # the node ignores SIGTERM (rehearsal 2026-11-09)
        b = C.parse_toml((self.rdir / "citrate-boot-1" / "node.sync.toml").read_text())
        self.assertFalse(b["mining"]["enabled"])
        self.assertEqual(b["mining"]["coinbase"], "0" * 40)

    def test_a_changed_checkpoint_interval_fails(self):
        self.edit("citrate-prod-1", "node.mine.toml", lambda s: s.replace("interval = 50", "interval = 40"))
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("[checkpoint] interval 40 != 50", out)

    def test_a_vote_depth_override_fails(self):
        self.edit("citrate-prod-3", "node.sync.toml", lambda s: s.replace("[checkpoint]\n", "[checkpoint]\nvote_depth = 5\n"))
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("vote_depth 5 != 3", out)

    def test_a_different_retention_fails(self):
        self.edit("citrate-rpc-1", "citrate-node.env", lambda s: s.replace("CITRATE_DAG_PRUNE_RETAIN=10000", "CITRATE_DAG_PRUNE_RETAIN=5000"))
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("CITRATE_DAG_PRUNE_RETAIN 5000 != pruning_depth 10000", out)
        self.assertIn("consensus environment differs", out)

    def test_a_mining_boot_fails(self):
        self.edit("citrate-boot-2", "node.sync.toml", lambda s: s.replace("enabled = false", "enabled = true", 1).replace("[mining]\nenabled = false", "[mining]\nenabled = true"))
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("citrate-boot-2/node.sync.toml: mining enabled = True", out)

    def test_an_edit_after_render_is_caught(self):
        self.edit("citrate-prod-1", "citrate-node.env", lambda s: s + "\n", rehash=False)
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("changed after render", out)

    def test_key_material_in_a_rendered_file_fails(self):
        self.edit("citrate-prod-1", "citrate-node.env", lambda s: s + "CITRATE_X=" + "ab" * 32 + "\n")
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("unexplained 32-byte hex value", out)
        self.edit("citrate-prod-2", "node.sync.toml", lambda s: s + '\n# private_key = "x"\n')
        rc, out = self.check()
        self.assertIn("key-material pattern", out)

    def test_the_binary_must_bind_the_same_params(self):
        self.bin = fake_binary(self.tmp, params=SRC["params_render"].replace("checkpoint_interval=50", "checkpoint_interval=40"))
        rc, out = self.check(binary=True)
        self.assertEqual(rc, 1)
        self.assertIn("genesis binding does not end in", out)

    def test_the_binary_must_bind_the_r1007_genesis(self):
        self.bin = fake_binary(self.tmp, genesis=SRC["r1006_genesis"])
        rc, out = self.check(binary=True)
        self.assertEqual(rc, 1)
        self.assertIn("binds genesis", out)

    def test_a_stale_render_is_refused_after_a_param_change(self):
        m = json.loads((self.rdir / "render-manifest.json").read_text())
        m["params_render"] = m["params_render"].replace("merge_depth=100", "merge_depth=99")
        (self.rdir / "render-manifest.json").write_text(json.dumps(m))
        rc, out = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("re-render", out)

    def test_render_needs_every_peer_id(self):
        ids = json.loads((self.tmp / "state" / "identities.json").read_text())
        del ids["hosts"]["citrate-prod-2"]
        (self.tmp / "state" / "identities.json").write_text(json.dumps(ids))
        rc, _ = run(["render", *self.base, "--network", "r1007"])
        self.assertEqual(rc, 2)


class PlanAndGuards(unittest.TestCase):
    def test_the_plan_order(self):
        fleet = C.Fleet(FLEET)
        steps = C.plan_steps(fleet)
        self.assertEqual([s["step"] for s in steps], ["prepare", "cut", "boots", "producers", "rpc", "indexer", "health", "rollback"])
        by = {s["step"]: s for s in steps}
        self.assertEqual(by["boots"]["hosts"], ["citrate-boot-1", "citrate-boot-2", "citrate-boot-3"])
        self.assertEqual(by["producers"]["hosts"], [f"citrate-prod-{i}" for i in range(1, 8)])
        self.assertEqual(by["cut"]["hosts"][0], "citrate-rpc-1")
        self.assertEqual(by["indexer"]["hosts"], ["citrate-rpc-1"])
        for s in ("prepare", "cut", "indexer", "rollback"):
            self.assertTrue(by[s]["owner_go"], s)

    def test_the_committed_fleet_holds_no_secret_and_matches_validators(self):
        text = (R7 / "fleet.r1007.json").read_text()
        for rx in C.SECRET_RES:
            self.assertIsNone(rx.search(text))
        names = [h["name"] for h in json.loads(text)["hosts"] if h["role"] == "producer"]
        self.assertEqual(names, [p["name"] for p in SRC["producers"]])

    def test_the_committed_fleet_names_each_hosts_r1006_layout(self):
        f = json.loads((R7 / "fleet.r1007.json").read_text())
        lay = {h["name"]: h.get("r1006_layout", "producer") for h in f["hosts"]}
        for n in ("citrate-boot-1", "citrate-boot-2", "citrate-boot-3", "citrate-rpc-1"):
            self.assertEqual(lay[n], "home", n)
        for n in [x for x in lay if "prod" in x]:
            self.assertEqual(lay[n], "producer", n)

    def test_the_agent_is_told_each_hosts_layout(self):
        fleet = C.Fleet(FLEET)
        t = C.Transport(fleet, None)
        boot = fleet.hosts("boot")[0]
        prod = fleet.hosts("producer")[0]
        self.assertIn("--r1006-layout", t._base(boot))
        self.assertEqual(t._base(boot)[t._base(boot).index("--r1006-layout") + 1], "home")
        self.assertEqual(t._base(prod)[t._base(prod).index("--r1006-layout") + 1], "producer")

    def test_ssh_steps_need_the_owner_go(self):
        fleet = C.Fleet(FLEET)
        h = fleet.hosts("boot")[0]
        with self.assertRaises(C.Refuse):
            C.Transport(fleet, None).agent(h, "stop", step="cut")
        go = {"ceremony": "r1007", "genesis": SRC["r1007_genesis"], "approved_by": "owner", "approved_at": "x", "steps": ["prepare"]}
        with self.assertRaises(C.Refuse):
            C.Transport(fleet, go).agent(h, "stop", step="cut")

    # fed #495: the cut stops the explorer indexer first, and the indexer step backs the
    # explorer DB up as a managed-cluster fork from the operator machine, never a pg_dump on
    # rpc-1's disk.
    def _ssh_fleet(self, steps):
        fleet = C.Fleet(FLEET)
        go = {"ceremony": "r1007", "genesis": SRC["r1007_genesis"], "approved_by": "owner", "approved_at": "x", "steps": steps}
        return fleet, C.Transport(fleet, go)

    def _record(self, forks_listed=()):
        calls = []
        def agent(_self, h, *args, mutating=True, step=""):
            if mutating:
                _self.require_go(step, h)
            calls.append(("agent", h["name"], args))
            return {}
        def ssh_run(t, h, cmd, step):
            t.require_go(step, h)
            calls.append(("host", h["name"], cmd))
        def operator_run(argv):
            calls.append(("operator", "", " ".join(argv)))
            if argv[:3] == ["doctl", "databases", "list"]:
                listed = [{"name": n, "id": "fork-" + n, "status": "online"} for n in forks_listed]
                if any(c[0] == "operator" and " fork " in f" {c[2]} " for c in calls):
                    listed.append({"name": C.INDEXER_FORK_NAME, "id": "fork-new", "status": "online"})
                return json.dumps(listed)
            return ""
        return calls, agent, ssh_run, operator_run

    def _patched(self, agent, ssh_run, operator_run):
        """Recorders for every way a step can reach a host or the cloud. subprocess.run is
        blocked too: these tests use the committed ssh fleet, and a real ssh from a test
        would reach the production hosts."""
        from unittest import mock
        block = mock.patch.object(C.subprocess, "run", side_effect=AssertionError("a test step tried a real subprocess"))
        return (_Stack(mock.patch.object(C.Transport, "agent", agent), block),
                mock.patch.object(C, "ssh_run", ssh_run, create=True),
                mock.patch.object(C, "operator_run", operator_run, create=True))

    def _args(self, **kw):
        import types
        base = {"db_cluster_id": "3d4c6713-5987-404c-8ea5-e58afa94adad", "db_fork_rule": "ip_addr:203.0.113.7",
                "gate_minutes": 0.01, "state": tempfile.mkdtemp()}
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_cut_stops_the_indexer_before_any_node(self):
        fleet, t = self._ssh_fleet(["cut"])
        calls, agent, ssh_run, operator_run = self._record()
        p1, p2, p3 = self._patched(agent, ssh_run, operator_run)
        with p1, p2, p3, redirect_stdout(io.StringIO()):
            C.step_cut(self._args(), fleet, t, SRC)
        self.assertTrue(calls, "the cut did nothing")
        first = calls[0]
        self.assertEqual(first[0], "host", f"the first cut action is not on the indexer host: {first}")
        self.assertEqual(first[1], "citrate-rpc-1")
        self.assertIn("systemctl stop citratescan-indexer", first[2])
        self.assertIn("is-active", first[2], "the stop is not confirmed")
        self.assertTrue(any(c[0] == "agent" and c[2] == ("stop",) for c in calls[1:]))

    def test_indexer_step_forks_the_cluster_and_writes_no_dump_on_the_host(self):
        fleet, t = self._ssh_fleet(["indexer"])
        calls, agent, ssh_run, operator_run = self._record()
        p1, p2, p3 = self._patched(agent, ssh_run, operator_run)
        with p1, p2, p3, redirect_stdout(io.StringIO()):
            C.step_indexer(self._args(), fleet, t, SRC)
        text = "\n".join(c[2] for c in calls)
        self.assertNotIn("pg_dump", text)
        self.assertNotIn("/var/backups", text)
        ops = [c[2] for c in calls if c[0] == "operator"]
        fork = [i for i, c in enumerate(calls) if c[0] == "operator" and c[2].startswith("doctl databases fork ")]
        self.assertEqual(len(fork), 1, ops)
        self.assertIn("--restore-from-cluster-id 3d4c6713-5987-404c-8ea5-e58afa94adad", calls[fork[0]][2])
        self.assertIn("--wait", calls[fork[0]][2])
        self.assertTrue(any(c.startswith("doctl databases firewalls append fork-new --rule ip_addr:203.0.113.7") for c in ops), ops)
        confirm = [i for i, c in enumerate(calls) if c[0] == "host" and "--confirm" in c[2]]
        self.assertEqual(len(confirm), 1)
        self.assertLess(fork[0], confirm[0], "the reset runs before the backup fork exists")

    def test_indexer_step_refuses_without_a_cluster_id_or_fork_rule(self):
        for kw in ({"db_cluster_id": None}, {"db_cluster_id": "not-a-uuid"}, {"db_fork_rule": None}, {"db_fork_rule": "0.0.0.0/0"}):
            fleet, t = self._ssh_fleet(["indexer"])
            calls, agent, ssh_run, operator_run = self._record()
            p1, p2, p3 = self._patched(agent, ssh_run, operator_run)
            with p1, p2, p3, redirect_stdout(io.StringIO()):
                with self.assertRaises(C.Refuse, msg=str(kw)):
                    C.step_indexer(self._args(**kw), fleet, t, SRC)
            self.assertEqual(calls, [], kw)

    def test_indexer_step_refuses_a_stale_fork_of_the_same_name(self):
        fleet, t = self._ssh_fleet(["indexer"])
        calls, agent, ssh_run, operator_run = self._record(forks_listed=["citratescan-r1007-precut"])
        p1, p2, p3 = self._patched(agent, ssh_run, operator_run)
        with p1, p2, p3, redirect_stdout(io.StringIO()):
            with self.assertRaises(C.Refuse):
                C.step_indexer(self._args(), fleet, t, SRC)
        self.assertFalse(any(c[0] == "host" and "indexer:reset" in c[2] for c in calls))

    def test_a_failed_trusted_source_deletes_the_open_fork(self):
        # BerryManifold P3 (fed #467 round 3): a fork left with no trusted source admits any
        # IP, and a re-run then refuses on the existing name.
        fleet, t = self._ssh_fleet(["indexer"])
        calls, agent, ssh_run, operator_run = self._record()
        def failing(argv):
            if argv[:4] == ["doctl", "databases", "firewalls", "append"]:
                calls.append(("operator", "", " ".join(argv)))
                raise subprocess.CalledProcessError(1, argv)
            return operator_run(argv)
        p1, p2, p3 = self._patched(agent, ssh_run, failing)
        with p1, p2, p3, redirect_stdout(io.StringIO()):
            with self.assertRaises(C.Fail):
                C.step_indexer(self._args(), fleet, t, SRC)
        ops = [c[2] for c in calls if c[0] == "operator"]
        self.assertIn("doctl databases delete fork-new --force", ops)
        self.assertFalse(any(c[0] == "host" and "indexer:reset" in c[2] for c in calls))

    def test_collect_reads_the_live_r1006_staker_keystore_path(self):
        # 2026-11-11, first read-only collect on the fleet: host-identity failed on prod-1
        # because collect looked for /etc/citrate/keys/staker.keystore.json. The r1006 bring-up
        # put the staker keystore and password under /etc/citrate/r1006/ on every producer.
        from unittest import mock
        fleet = C.Fleet(FLEET)
        cmds = []
        def fake_run(argv, *a, **kw):
            cmds.append(argv)
            host = argv[1]
            p = next(x for x in SRC["producers"] if host.startswith(x["name"]))
            pub = {"schema": "citrate-host-identity/1", "peer_id": "noise_" + "ab" * 32, "noise_pubkey": "0x" + "cd" * 32,
                   "proposer_pubkey": p["proposer_pubkey"], "vrf_pubkey": "0x" + "ef" * 33,
                   "staker_address": p["staker"], "coinbase_address": p["staker"]}
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(pub), stderr="")
        import types
        state = tempfile.mkdtemp()
        with mock.patch.object(C.subprocess, "run", fake_run), redirect_stdout(io.StringIO()):
            rc = C.cmd_collect(types.SimpleNamespace(mint=False, state=state, binary=None), fleet, SRC)
        self.assertEqual(rc, 0)
        self.assertEqual(len(cmds), 7)
        for argv in cmds:
            self.assertIn("--staker-keystore /etc/citrate/r1006/staker.keystore.json", argv[-1])
            self.assertIn("--staker-password-file /etc/citrate/r1006/staker.password", argv[-1])
            self.assertNotIn("/etc/citrate/keys", argv[-1])
            # absolute: over ssh the tool has no root prefix, and a relative path lands in ~root
            self.assertIn("--identity-dir /var/lib/citrate/data ", argv[-1])

    def test_an_owner_go_for_another_genesis_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "go.json"
            f.write_text(json.dumps({"ceremony": "r1007", "genesis": SRC["r1006_genesis"], "approved_by": "o", "approved_at": "x", "steps": ["cut"]}))
            with self.assertRaises(C.Refuse):
                C.load_go(str(f), SRC["r1007_genesis"])

    def test_devnet_only_actions_are_refused_on_the_fleet(self):
        rc, _ = run(["collect", "--fleet", str(FLEET), "--mint", "--state", tempfile.mkdtemp()])
        self.assertEqual(rc, 2)
        rc, _ = run(["render", "--fleet", str(FLEET), "--network", "r1006", "--binary", sys.executable, "--state", tempfile.mkdtemp()])
        self.assertEqual(rc, 2)


class DevnetHarness(unittest.TestCase):
    """devnet.sh's stand-in r1006 health gate (P5, 2026-11-11). Every producer stays in
    initial sync for about a minute after start ("refusing to produce: initial sync since
    start has not completed"), so a 20 s settle made health-r1006 fail on 2 of 7
    producers in two of three runs on the stamped gc3 binary. Run 3, with a 90 s settle,
    passed. So did the rehearsal-stamp run (P5b)."""

    def test_the_r1006_health_gate_waits_out_initial_sync(self):
        import re as _re
        text = (R7 / "devnet.sh").read_text()
        m = _re.search(r"^SETTLE=(\d+)$", text, _re.M)
        self.assertIsNotNone(m, "devnet.sh has no SETTLE default")
        self.assertGreaterEqual(int(m.group(1)), 90)
        line = next(l for l in text.splitlines() if l.strip().startswith("health-r1006)"))
        self.assertIn('sleep "$SETTLE"', line)
        self.assertIn("--settle-seconds", text)


class DevnetTxLoad(unittest.TestCase):
    """P5 tx-load phase (lead, 2026-11-11). Under about 30 tx/s the G4 devnet split six ways on
    "Acceptance commitment mismatch" (execute-on-receive). P5 now runs a sustained load after
    the producers step and gates on zero mismatch and zero "block disqualified" lines."""

    TXL = R7 / "devnet_txload.sh"

    def _work(self, logs: dict, included: dict, expected=None, target: int = 0) -> Path:
        """included: worker id -> included count (sent = included + 3). expected: the worker ids
        `run` started (default: the keys of included). target: tx the run aimed for."""
        w = Path(tempfile.mkdtemp(prefix="r1007txl."))
        self.addCleanup(shutil.rmtree, w, True)
        for host, text in logs.items():
            d = w / "hosts" / host / "var/lib/citrate/ceremony"
            d.mkdir(parents=True)
            (d / "node-r1007.log").write_text(text)
        (w / "txload").mkdir()
        for wid, n in included.items():
            (w / "txload" / f"{wid}.included").write_text(f"{n}\n")
            (w / "txload" / f"{wid}.sent").write_text(f"{n + 3}\n")
        (w / "txload" / "expected").write_text("\n".join(expected if expected is not None else included) + "\n")
        (w / "txload" / "target").write_text(f"{target}\n")
        return w

    def gate(self, w: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.TXL), "gate", "--work", str(w)], capture_output=True, text=True, timeout=30)

    def test_devnet_runs_the_load_after_producers_and_passes_its_options_through_the_reexec(self):
        text = (R7 / "devnet.sh").read_text()
        steps = re.search(r'^STEPS="([^"]+)"', text, re.M).group(1).split()
        self.assertIn("txload", steps)
        self.assertLess(steps.index("producers"), steps.index("txload"))
        self.assertLess(steps.index("txload"), steps.index("health-r1007"))
        reexec = text[text.index("exec unshare"):text.index("fi", text.index("exec unshare"))]
        for opt in ("--settle-seconds", "--tx-tps", "--tx-seconds"):
            self.assertIn(opt, reexec, f"{opt} is lost at the namespace re-exec")
        self.assertIn("devnet_txload.sh", text)

    def test_the_internal_sender_entry_keeps_its_work_dir(self):
        # The first fleet-shape run (2026-11-11 22:03Z) failed with "usage" from every sender:
        # the defaults line reset WORK after the _sender branch had set it.
        text = self.TXL.read_text()
        self.assertLess(text.index('FLEET="" WORK=""'), text.index('if [[ "$MODE" == _producer ]]'))

    def test_gate_passes_clean_logs_with_included_load(self):
        r = self.gate(self._work({"citrate-prod-1": "INFO sealed\n", "citrate-prod-2": "INFO ok\n"}, {"citrate-prod-1": 40, "citrate-prod-2": 38}))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("included=78", r.stdout)

    def test_gate_fails_on_an_acceptance_commitment_mismatch(self):
        r = self.gate(self._work({"citrate-prod-3": "WARN Acceptance commitment mismatch at 0xab\n"}, {"citrate-prod-3": 10}))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("acceptance_commitment_mismatch=1", r.stdout)

    def test_gate_fails_on_a_disqualified_block(self):
        r = self.gate(self._work({"citrate-prod-4": "ERROR Block disqualified: bad state root\n"}, {"citrate-prod-4": 10}))
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_gate_is_a_harness_error_when_no_load_was_included(self):
        r = self.gate(self._work({"citrate-prod-1": "INFO ok\n"}, {"citrate-prod-1": 0}))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("proved nothing", r.stdout)

    # 2026-11-11 22:12Z run: prod-7's sender died while funding (no .sent), so the load came
    # from 6 of 7 producers and the gate never noticed. A harness shortfall must never read as a
    # pass, nor as a consensus failure: it is exit 2.
    def test_gate_is_a_harness_error_when_an_expected_sender_never_ran(self):
        r = self.gate(self._work({"citrate-prod-1": "INFO ok\n"}, {"citrate-prod-1-w1": 40},
                                 expected=["citrate-prod-1-w1", "citrate-prod-7-w1"]))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("citrate-prod-7-w1", r.stdout)

    def test_gate_is_a_harness_error_when_the_load_fell_short_of_its_target(self):
        r = self.gate(self._work({"citrate-prod-1": "INFO ok\n"}, {"citrate-prod-1-w1": 100}, target=3600))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("below", r.stdout)

    def test_a_divergence_is_reported_even_when_the_load_fell_short(self):
        r = self.gate(self._work({"citrate-prod-4": "Acceptance commitment mismatch\n"}, {"citrate-prod-4-w1": 100}, target=3600))
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_the_default_load_reaches_30_tps(self):
        # 3 workers per producer reached about 26 tx/s on the fleet-shape devnet (22:29Z run).
        # One cast worker manages about 2.5 tx/s, so 7 producers x 4 workers covers 30 tx/s
        # with margin (lead, 2026-11-11).
        text = self.TXL.read_text()
        self.assertIsNotNone(re.search(r"\bWORKERS=4\b", text), "the default is not 4 workers")

    def test_workers_pace_against_a_schedule_not_a_fixed_sleep(self):
        # 23:12Z run: 28 workers at a 1.07 tx/s target each sent 0.96 tx/s (27 tx/s total).
        # Each loop slept the full period on top of the time cast itself took, so the
        # rate fell short by that overhead. Pacing must sleep only until the next slot.
        text = self.TXL.read_text()
        self.assertIn("EPOCHREALTIME", text)
        self.assertNotIn('sleep "$period"', text)

    def test_run_starts_several_workers_per_producer_and_funds_them_serially(self):
        text = self.TXL.read_text()
        self.assertIn("--workers", text)
        self.assertIn("expected", text)


class Agent(unittest.TestCase):
    """node_agent.py's generation slots, in a temp root (proc mode)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="r1007a."))
        self.base = ["--root", str(self.root), "--mode", "proc", "--run-as", ""]

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def agent(self, *args: str) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = NA.main([*self.base, *args])
        return rc, json.loads(buf.getvalue().strip().splitlines()[-1])

    def bundle(self, gen: str = "r1007") -> Path:
        inc = self.root / "incoming"
        inc.mkdir(exist_ok=True)
        files = {"node.sync.toml": "sync", "node.mine.toml": "mine", "citrate-node.env": "CITRATE_A=1\n", "citrate-node.service": "unit",
                 "launch.json": json.dumps({"binary": f"/usr/local/lib/citrate-gen/{gen}/citrate-node", "config": f"/etc/citrate/gen/{gen}/node.toml",
                                            "env_file": f"/etc/citrate/gen/{gen}/citrate-node.env", "data_dir": f"/var/lib/citrate/gen/{gen}"}),
                 "citrate-node": "#!/bin/sh\nsleep 60\n"}
        man = {}
        for n, c in files.items():
            (inc / n).write_text(c)
            man[n] = NA.sha(inc / n)
        (inc / "manifest.json").write_text(json.dumps({"network": gen, "files": man}))
        return inc

    def seed_r1006_keys(self) -> Path:
        d = self.root / "var/lib/citrate/data"
        d.mkdir(parents=True)
        (d / "noise.key").write_bytes(b"N" * 32)
        (d / "proposer.key").write_bytes(b"P" * 32)
        return d

    def test_stage_installs_and_starts_mining_off(self):
        rc, _ = self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        self.assertEqual(rc, 0)
        etc = self.root / "etc/citrate/gen/r1007"
        self.assertEqual((etc / "node.toml").read_text(), "sync")
        self.assertTrue(os.access(self.root / "usr/local/lib/citrate-gen/r1007/citrate-node", os.X_OK))
        self.assertEqual(stat.S_IMODE((self.root / "var/lib/citrate/gen/r1007").stat().st_mode), 0o700)

    def test_stage_refuses_a_tampered_bundle_or_another_network(self):
        inc = self.bundle()
        (inc / "node.mine.toml").write_text("mine but different")
        rc, res = self.agent("stage", "--gen", "r1007", "--incoming", str(inc))
        self.assertEqual(rc, 2)
        self.assertIn("manifest hash", res["refused"])
        rc, res = self.agent("stage", "--gen", "r1006", "--incoming", str(self.bundle()))
        self.assertEqual(rc, 2)

    def test_seed_keys_copies_host_locally_0600_and_never_prints_them(self):
        self.seed_r1006_keys()
        self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = NA.main([*self.base, "seed-keys", "--keys", "noise,proposer"])
        self.assertEqual(rc, 0)
        self.assertNotIn("NNNN", buf.getvalue())
        self.assertNotIn("PPPP", buf.getvalue())
        k = self.root / "var/lib/citrate/gen/r1007/proposer.key"
        self.assertEqual(k.read_bytes(), b"P" * 32)
        self.assertEqual(stat.S_IMODE(k.stat().st_mode), 0o600)
        # Idempotent, and never overwrites a different key.
        self.assertEqual(self.agent("seed-keys", "--keys", "noise,proposer")[0], 0)
        k.write_bytes(b"X" * 32)
        rc, res = self.agent("seed-keys", "--keys", "proposer")
        self.assertEqual(rc, 2)
        self.assertIn("refusing to overwrite", res["refused"])

    def test_park_records_r1006_without_moving_it(self):
        unit = self.root / "etc/systemd/system/citrate-node.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Service]\nExecStart=/usr/local/bin/citrate-node --config /etc/citrate/node.toml\n")
        (self.root / "etc/citrate").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/citrate/node.toml").write_text("r1006 config")
        d = self.seed_r1006_keys()
        rc, res = self.agent("park-r1006")
        self.assertEqual(rc, 0)
        self.assertEqual((self.root / "etc/citrate/node.toml").read_text(), "r1006 config")
        self.assertTrue((d / "proposer.key").exists())
        self.assertEqual((self.root / "etc/citrate/gen/r1006/citrate-node.service").read_text(), unit.read_text())
        self.assertEqual((self.root / "etc/citrate/active").read_text().strip(), "r1006")
        self.assertTrue(self.agent("park-r1006")[1]["already"])

    # 2026-11-11 read-only fleet check: boot-1..3 and rpc-1 run r1006 from the "home" layout
    # (/home/citrate/bin/citrate-node --config /home/citrate/.citrate/node.toml, data and
    # noise.key in /home/citrate/.citrate) with unit drop-ins that inject r1006 consensus env
    # (CITRATE_VALIDATOR_REGISTRY, ...). Producers use the "producer" layout.
    def home_r1006(self) -> Path:
        unit = self.root / "etc/systemd/system/citrate-node.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Service]\nUser=citrate\nExecStart=/home/citrate/bin/citrate-node --config /home/citrate/.citrate/node.toml\n")
        dd = self.root / "etc/systemd/system/citrate-node.service.d"
        dd.mkdir(parents=True, exist_ok=True)
        (dd / "r1006-consensus.conf").write_text("[Service]\nEnvironment=CITRATE_VALIDATOR_ACTIVATION_HEIGHT=1000\n")
        (dd / "10-restart-always.conf").write_text("[Service]\nRestart=always\n")
        home = self.root / "home/citrate/.citrate"
        home.mkdir(parents=True, exist_ok=True)
        (home / "node.toml").write_text("r1006 home config")
        (home / "noise.key").write_bytes(b"H" * 32)
        b = self.root / "home/citrate/bin"
        b.mkdir(parents=True, exist_ok=True)
        (b / "citrate-node").write_text("#!/bin/sh\n")
        return home

    def systemd_base(self):
        """systemd mode with a fake systemctl first on PATH (inactive unit, daemon-reload ok)."""
        fake = self.root / "fakebin"
        fake.mkdir(exist_ok=True)
        (fake / "systemctl").write_text("#!/bin/sh\necho \"$*\" >> \"$(dirname \"$0\")/systemctl.log\"\n"
                                         "case \"$1\" in is-active) exit 3 ;; is-enabled) exit 1 ;; *) exit 0 ;; esac\n")
        (fake / "systemctl").chmod(0o755)
        os.environ["PATH"] = str(fake) + os.pathsep + os.environ["PATH"]
        self.addCleanup(lambda: os.environ.__setitem__("PATH", os.environ["PATH"].replace(str(fake) + os.pathsep, "", 1)))
        return ["--root", str(self.root), "--mode", "systemd", "--run-as", "", "--r1006-layout", "home"]

    def test_park_home_layout_records_its_files_and_dropins(self):
        self.home_r1006()
        self.base = ["--root", str(self.root), "--mode", "proc", "--run-as", "", "--r1006-layout", "home"]
        rc, res = self.agent("park-r1006")
        self.assertEqual(rc, 0, res)
        parked = json.loads((self.root / "etc/citrate/gen/r1006/parked.json").read_text())
        self.assertEqual(parked["data_dir"], "/home/citrate/.citrate")
        self.assertIn("/home/citrate/.citrate/node.toml", parked["files"])
        self.assertIn("/home/citrate/bin/citrate-node", parked["files"])
        saved = self.root / "etc/citrate/gen/r1006/dropins"
        self.assertEqual(sorted(x.name for x in saved.iterdir()), ["10-restart-always.conf", "r1006-consensus.conf"])
        self.assertEqual((self.root / "home/citrate/.citrate/node.toml").read_text(), "r1006 home config")

    def test_seed_keys_reads_the_home_layout(self):
        self.home_r1006()
        self.base = ["--root", str(self.root), "--mode", "proc", "--run-as", "", "--r1006-layout", "home"]
        self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        rc, res = self.agent("seed-keys", "--keys", "noise")
        self.assertEqual(rc, 0, res)
        self.assertEqual((self.root / "var/lib/citrate/gen/r1007/noise.key").read_bytes(), b"H" * 32)

    def test_switch_to_r1007_leaves_no_r1006_dropin_and_switching_back_restores_them(self):
        self.home_r1006()
        self.base = self.systemd_base()
        dd = self.root / "etc/systemd/system/citrate-node.service.d"
        before = {f.name: f.read_bytes() for f in dd.iterdir()}
        self.assertEqual(self.agent("park-r1006")[0], 0)
        self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        rc, res = self.agent("switch", "--gen", "r1007")
        self.assertEqual(rc, 0, res)
        self.assertEqual(sorted(dd.iterdir()) if dd.exists() else [], [], "an r1006 drop-in would apply to r1007")
        rc, res = self.agent("switch", "--gen", "r1006")
        self.assertEqual(rc, 0, res)
        self.assertEqual({f.name: f.read_bytes() for f in dd.iterdir()}, before)

    def test_switch_refuses_an_unknown_live_dropin(self):
        self.home_r1006()
        self.base = self.systemd_base()
        self.assertEqual(self.agent("park-r1006")[0], 0)
        self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        (self.root / "etc/systemd/system/citrate-node.service.d/99-added-later.conf").write_text("[Service]\nNice=5\n")
        rc, res = self.agent("switch", "--gen", "r1007")
        self.assertEqual(rc, 2)
        self.assertIn("drop-in", res["refused"])
        self.assertTrue((self.root / "etc/systemd/system/citrate-node.service.d/99-added-later.conf").exists())

    def test_switch_refuses_while_running_and_snapshot_is_written_once(self):
        self.agent("stage", "--gen", "r1007", "--incoming", str(self.bundle()))
        st = self.root / "var/lib/citrate/ceremony"
        st.mkdir(parents=True)
        (st / "node.pid").write_text(str(os.getpid()))  # "running"
        rc, s1 = self.agent("snapshot")
        self.assertTrue(s1["snapshot"]["running"])
        rc, res = self.agent("switch", "--gen", "r1007")
        self.assertEqual(rc, 2)
        (st / "node.pid").unlink()
        self.assertEqual(self.agent("switch", "--gen", "r1007")[0], 0)
        rc, s2 = self.agent("snapshot")
        self.assertTrue(s2["already"])
        self.assertTrue(s2["snapshot"]["running"])  # the pre-cut state, not today's
        self.assertEqual(self.agent("rollback-target")[1]["running"], True)


if __name__ == "__main__":
    unittest.main()
