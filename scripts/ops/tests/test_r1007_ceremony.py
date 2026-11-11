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
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
R7 = REPO / "scripts" / "ops" / "r1007"
sys.path.insert(0, str(R7))
sys.path.insert(0, str(REPO / "scripts" / "producers"))
import ceremony as C  # noqa: E402
import node_agent as NA  # noqa: E402
import params as P  # noqa: E402

SRC = P.load(REPO)


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

    def test_a_local_rehearsal_render_records_that_r1007_is_pending(self):
        man = json.loads((self.rdir / "render-manifest.json").read_text())
        self.assertEqual(man["r1007_pending"], SRC["r1007_pending"])

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
        fleet = C.Fleet(R7 / "fleet.r1007.json")
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

    def test_ssh_steps_need_the_owner_go(self):
        fleet = C.Fleet(R7 / "fleet.r1007.json")
        h = fleet.hosts("boot")[0]
        with self.assertRaises(C.Refuse):
            C.Transport(fleet, None).agent(h, "stop", step="cut")
        go = {"ceremony": "r1007", "genesis": SRC["r1007_genesis"], "approved_by": "owner", "approved_at": "x", "steps": ["prepare"]}
        with self.assertRaises(C.Refuse):
            C.Transport(fleet, go).agent(h, "stop", step="cut")

    def test_an_owner_go_for_another_genesis_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "go.json"
            f.write_text(json.dumps({"ceremony": "r1007", "genesis": SRC["r1006_genesis"], "approved_by": "o", "approved_at": "x", "steps": ["cut"]}))
            with self.assertRaises(C.Refuse):
                C.load_go(str(f), SRC["r1007_genesis"])

    def test_r1007_is_no_longer_pending_with_the_fresh_keys_alloc(self):
        # D-K3: the fresh-keys alloc (core/economics/assets/r1007/alloc.json,
        # inputsStatus final) exists in this checkout, so nothing is pending.
        self.assertEqual(SRC["r1007_pending"], [])

    def test_r1007_is_pending_without_a_final_alloc(self):
        # A checkout without the alloc (or with non-final inputs) is pending and
        # names the roles, read from the Rust table.
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / P.R1007_RS).parent.mkdir(parents=True)
            shutil.copy(REPO / P.R1007_RS, root / P.R1007_RS)
            pending = P.r1007_pending(root)
            self.assertTrue(pending)
            text = " ".join(pending)
            self.assertIn("D-K3", text)
            for role in ("TREASURY", "DEPLOYER", "GOV_OWNER_1", "MEMBERSHIP_GRANTOR"):
                self.assertIn(role, text)
            (root / P.R1007_ALLOC).parent.mkdir(parents=True)
            (root / P.R1007_ALLOC).write_text(json.dumps({"inputsStatus": "placeholder"}))
            self.assertTrue(P.r1007_pending(root))

    def test_rendering_r1007_for_the_fleet_is_refused_while_pending(self):
        fleet = C.Fleet(R7 / "fleet.r1007.json")
        import argparse
        a = argparse.Namespace(network="r1007", binary=sys.executable, state=tempfile.mkdtemp())
        src = dict(SRC, r1007_pending=["D-K3: r1007 is pending (test)"])
        with self.assertRaises(C.Refuse) as e:
            C.cmd_render(a, fleet, src)
        self.assertIn("D-K3", str(e.exception))

    def test_the_r1007_genesis_timestamp_is_read_from_the_checkout(self):
        self.assertIsInstance(SRC["r1007_genesis_timestamp"], int)
        self.assertGreater(SRC["r1007_genesis_timestamp"], 1_700_000_000)

    def test_rendering_r1007_for_the_fleet_refuses_a_stale_or_far_future_genesis_timestamp(self):
        import argparse
        fleet = C.Fleet(R7 / "fleet.r1007.json")
        a = argparse.Namespace(network="r1007", binary=sys.executable, state=tempfile.mkdtemp())
        now = 1_800_000_000
        for ts, ok in ((now - 3_601, False), (now + 3_601, False), (now - 3_600, True), (now + 60, True)):
            src = dict(SRC, r1007_pending=[], r1007_genesis_timestamp=ts)
            try:
                C.check_genesis_timestamp(fleet, src, now)
                refused = None
            except C.Refuse as e:
                refused = str(e)
            self.assertEqual(refused is None, ok, f"{ts}: {refused}")
            if not ok:
                self.assertIn("stamp_genesis.py", refused)
        # A local (devnet) rehearsal does not check it.
        local = C.Fleet(local_fleet(Path(tempfile.mkdtemp())))
        C.check_genesis_timestamp(local, dict(SRC, r1007_genesis_timestamp=0), now)

    def test_rendering_r1007_for_the_fleet_works_with_a_final_alloc_and_a_fresh_stamp(self):
        import argparse, time as _t
        tmp = Path(tempfile.mkdtemp())
        ids = {h["name"]: {"peer_id": h.get("peer_id") or peer(k + 1)}
               for k, h in enumerate(json.loads((R7 / "fleet.r1007.json").read_text())["hosts"])}
        (tmp / "identities.json").write_text(json.dumps({"schema": "r1007-identities/1", "hosts": ids}))
        a = argparse.Namespace(network="r1007", binary=sys.executable, state=str(tmp))
        src = dict(SRC, r1007_pending=[], r1007_genesis_timestamp=int(_t.time()))
        fleet = C.Fleet(R7 / "fleet.r1007.json")
        self.assertEqual(C.cmd_render(a, fleet, src), 0)
        man = json.loads((tmp / "render" / "r1007" / "render-manifest.json").read_text())
        self.assertEqual(man["genesis"], SRC["r1007_genesis"])
        self.assertEqual(man["r1007_genesis_timestamp"], src["r1007_genesis_timestamp"])
        self.assertEqual(sorted(man["hosts"]), sorted(h["name"] for h in fleet.hosts()))

    def test_devnet_only_actions_are_refused_on_the_fleet(self):
        rc, _ = run(["collect", "--fleet", str(R7 / "fleet.r1007.json"), "--mint", "--state", tempfile.mkdtemp()])
        self.assertEqual(rc, 2)
        rc, _ = run(["render", "--fleet", str(R7 / "fleet.r1007.json"), "--network", "r1006", "--binary", sys.executable, "--state", tempfile.mkdtemp()])
        self.assertEqual(rc, 2)


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
