"""Tests for gen_node_config.py: schema conformance with node/src/config.rs, consensus
env, the coinbase == staker rule, dry run, and refusal paths."""

import io
import re
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import gen_node_config as g  # noqa: E402
import producerlib as pl  # noqa: E402

REPO = HERE.parents[2]
STAKER = "0x" + "Ab" * 20
SECTIONS = {
    "chain": "ChainConfig",
    "network": "NetworkConfig",
    "rpc": "RpcConfig",
    "storage": "StorageConfig",
    "mining": "MiningConfig",
    "vrf": "VrfConfig",
    "checkpoint": "CheckpointNodeConfig",
    "validator": "ValidatorConfig",
}


def struct_fields(src: str, name: str) -> set[str]:
    m = re.search(rf"pub struct {name} \{{(.*?)\n\}}", src, re.S)
    assert m, name
    return set(re.findall(r"^\s*pub (\w+):", m.group(1), re.M))


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = g.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestRender(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def gen(self, *extra):
        return run(["--profile", "40204-r1005", "--staker", STAKER, "--out-dir", str(self.out), *extra])

    def test_writes_three_files_that_match_the_node_schema(self):
        rc, _, err = self.gen()
        self.assertEqual(rc, 0, err)
        cfg = tomllib.loads((self.out / "node.toml").read_text())
        src = (REPO / "node/src/config.rs").read_text()
        top = struct_fields(src, "NodeConfig")
        for section, body in cfg.items():
            self.assertIn(section, top, f"[{section}] is not a NodeConfig field")
            allowed = struct_fields(src, SECTIONS[section])
            unknown = set(body) - allowed
            self.assertFalse(unknown, f"[{section}] keys {unknown} would be rejected (deny_unknown_fields)")
        self.assertEqual(cfg["chain"]["chain_id"], 40204)
        self.assertEqual(cfg["rpc"]["listen_addr"], "127.0.0.1:8545")
        self.assertFalse(cfg["rpc"]["allow_eth_send_transaction"])
        self.assertEqual(cfg["storage"]["data_dir"], "/var/lib/citrate/data")

    def test_coinbase_is_the_staker_and_mining_defaults_off(self):
        self.gen()
        cfg = tomllib.loads((self.out / "node.toml").read_text())
        self.assertEqual(cfg["mining"]["coinbase"], "ab" * 20)
        self.assertFalse(cfg["mining"]["enabled"])

    def test_mining_on(self):
        self.gen("--mining", "on")
        self.assertTrue(tomllib.loads((self.out / "node.toml").read_text())["mining"]["enabled"])

    def test_bootnodes_and_checkpoint_come_from_the_profile(self):
        self.gen()
        cfg = tomllib.loads((self.out / "node.toml").read_text())
        prof = pl.load_profile("40204-r1005")
        self.assertEqual(cfg["network"]["bootstrap_nodes"], prof["bootstrap_nodes"])
        self.assertEqual(cfg["checkpoint"], prof["checkpoint"])

    def test_env_carries_the_shared_consensus_values(self):
        self.gen()
        env = dict(
            l.split("=", 1) for l in (self.out / "citrate-node.env").read_text().splitlines() if l and not l.startswith("#")
        )
        self.assertEqual(env["CITRATE_VALIDATOR_REGISTRY"], "0xde4F679632be7810D915F637Cc6a72bf076A3BD9")
        self.assertEqual(env["CITRATE_VALIDATOR_ACTIVATION_HEIGHT"], "2000")
        self.assertEqual(env["CITRATE_BLOCK_V2"], "1")
        self.assertEqual(env["CITRATE_DAG_PRUNE_RETAIN"], "10000")
        self.assertEqual(env["CITRATE_METRICS"], "1")
        self.assertNotIn("CITRATE_METRICS_ADDR", env)  # loopback default (PBA-L1a-024)

    def test_env_names_are_read_by_the_node(self):
        main_rs = (REPO / "node/src/main.rs").read_text() + (REPO / "node/src/dag_prune.rs").read_text()
        self.gen()
        for line in (self.out / "citrate-node.env").read_text().splitlines():
            if line and not line.startswith("#"):
                self.assertIn(f'"{line.split("=")[0]}"', main_rs)

    def test_unit_runs_as_citrate_with_the_env_file(self):
        self.gen()
        unit = (self.out / "citrate-node.service").read_text()
        self.assertIn("User=citrate", unit)
        self.assertIn(f"EnvironmentFile={self.out}/citrate-node.env", unit)
        self.assertIn(f"--config {self.out}/node.toml", unit)
        self.assertIn("ReadWritePaths=/var/lib/citrate/data", unit)
        self.assertIn("Restart=always", unit)

    def test_refuses_to_overwrite_without_force(self):
        self.gen()
        rc, _, err = self.gen()
        self.assertEqual(rc, 2)
        self.assertIn("--force", err)
        rc, _, _ = self.gen("--force", "--mining", "on")
        self.assertEqual(rc, 0)

    def test_dry_run_writes_nothing(self):
        rc, out, _ = self.gen("--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("[mining]", out)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_pending_profile_refused_but_previewable(self):
        rc, _, err = run(["--profile", "rehearsal-1", "--staker", STAKER, "--out-dir", str(self.out)])
        self.assertEqual(rc, 2)
        self.assertIn("not ready", err)
        rc, out, _ = run(["--profile", "rehearsal-1", "--staker", STAKER, "--out-dir", str(self.out), "--dry-run"])
        self.assertEqual(rc, 0)
        self.assertIn("NOT usable", out)

    def test_bad_inputs(self):
        for extra in (["--staker", "0x1234"], ["--data-dir", "relative/dir"], ["--p2p-port", "80"]):
            argv = ["--profile", "40204-r1005", "--staker", STAKER, "--out-dir", str(self.out), *extra]
            rc, _, _ = run(argv)
            self.assertEqual(rc, 2, extra)


if __name__ == "__main__":
    unittest.main()
