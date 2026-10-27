"""Tests for build_registration_tx.py: the unsigned tx it prints, every refusal, dry run,
and (when CITRATE_NODE_BIN points at a built node) the real registration-proof path."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import build_registration_tx as b  # noqa: E402
import gen_node_config as g  # noqa: E402
from rpcstub import REGISTRY, FakeChain, RpcStub  # noqa: E402

FAKE_BIN = str(HERE / "fake_citrate_node.py")
STAKER = "0x" + "c1" * 20
MIN = 32_000 * 10**18


def run(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = b.main(list(argv))
    text = out.getvalue()
    body = json.loads(text[: text.index("\n}\n") + 2]) if text.startswith("{") else None
    return rc, body, text, err.getvalue()


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "argv.log"
        os.environ["FAKE_NODE_LOG"] = str(self.log)
        os.environ.pop("FAKE_NODE_FAIL", None)
        self.c = FakeChain()
        self.c.balances[STAKER] = MIN + 10**18
        self.c.nonces[STAKER] = 2
        self.c.tx_counts[STAKER] = 5

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("FAKE_NODE_LOG", None)
        os.environ.pop("FAKE_NODE_FAIL", None)
        os.environ.pop("FAKE_NODE_CHAIN_ID", None)

    def build(self, url, *extra):
        return run("--profile", "40204-r1005", "--rpc", url, "--staker", STAKER, "--config", "/x/node.toml",
                   "--citrate-bin", FAKE_BIN, *extra)

    def test_unsigned_legacy_tx(self):
        with RpcStub(self.c) as s:
            rc, body, text, err = self.build(s.url)
        self.assertEqual(rc, 0, err)
        tx = body["unsigned_tx"]
        self.assertEqual(tx["type"], "0x0")
        self.assertEqual(int(tx["chainId"], 16), 40204)
        self.assertEqual(tx["to"].lower(), REGISTRY)
        self.assertEqual(int(tx["value"], 16), MIN)
        self.assertEqual(int(tx["nonce"], 16), 5)
        self.assertEqual(int(tx["gasPrice"], 16), 1_000_000_000)
        self.assertTrue(tx["data"].startswith("0x10f53ba1"))
        self.assertFalse(body["dry_run"])
        self.assertIn("cast mktx --legacy", text)
        argv = json.loads(self.log.read_text().splitlines()[0])
        self.assertEqual(argv[argv.index("--nonce") + 1], "2")  # registrationNonce from chain
        self.assertNotIn("sendRawTransaction", " ".join(s.requests))

    def test_never_sends_a_transaction(self):
        with RpcStub(self.c) as s:
            self.build(s.url)
        self.assertTrue(all(not m.startswith("eth_send") for m in s.requests), s.requests)

    def test_explicit_stake_and_below_min(self):
        with RpcStub(self.c) as s:
            self.c.balances[STAKER] = 50_000 * 10**18
            rc, body, _, _ = self.build(s.url, "--stake-salt", "40000")
            self.assertEqual(rc, 0)
            self.assertEqual(int(body["unsigned_tx"]["value"], 16), 40_000 * 10**18)
            rc, _, _, err = self.build(s.url, "--stake-salt", "31999.99")
            self.assertEqual(rc, 2)
            self.assertIn("below minStake", err)

    def test_refuses_low_balance(self):
        self.c.balances[STAKER] = MIN
        with RpcStub(self.c) as s:
            rc, _, _, err = self.build(s.url)
        self.assertEqual(rc, 2)
        self.assertIn("fund the staker", err)

    def test_refuses_staker_with_a_validator(self):
        self.c.add_validator("0x" + "01" * 32, STAKER, MIN, 3)
        with RpcStub(self.c) as s:
            rc, _, _, err = self.build(s.url)
        self.assertEqual(rc, 2)
        self.assertIn("already has validator", err)

    def test_refuses_registered_pubkey(self):
        self.c.add_validator("0x" + "5e" * 32, "0x" + "d2" * 20, MIN, 3, status="Exiting")
        with RpcStub(self.c) as s:
            rc, _, _, err = self.build(s.url)
        self.assertEqual(rc, 2)
        self.assertIn("single-use", err)

    def test_refuses_wrong_network_and_missing_registry(self):
        with RpcStub(self.c) as s:
            self.c.chain_id = 1
            rc, _, _, err = self.build(s.url)
            self.assertEqual(rc, 2)
            self.assertIn("chain id", err)
            self.c.chain_id = 40204
            self.c.registry_code = "0x"
            rc, _, _, err = self.build(s.url)
            self.assertEqual(rc, 2)
            self.assertIn("no contract code", err)

    def test_proof_failure_is_reported(self):
        os.environ["FAKE_NODE_FAIL"] = "1"
        with RpcStub(self.c) as s:
            rc, _, _, err = self.build(s.url)
        self.assertEqual(rc, 2)
        self.assertIn("proposer.key does not exist", err)

    def test_refuses_a_proof_for_another_chain(self):
        # node.toml from another network: the proof is signed for its chain id, the profile is
        # 40204. The builder must stop instead of emitting a transaction the registry rejects.
        os.environ["FAKE_NODE_CHAIN_ID"] = "31337"
        with RpcStub(self.c) as s:
            rc, _, text, err = self.build(s.url)
        self.assertEqual(rc, 2)
        self.assertIn("bound to chain 31337", err)
        self.assertNotIn("unsigned_tx", text)
        os.environ["FAKE_NODE_CHAIN_ID"] = "31337"
        rc, _, _, err = run("--profile", "rehearsal-1", "--staker", STAKER, "--config", "/x/node.toml",
                            "--citrate-bin", FAKE_BIN, "--dry-run")
        self.assertEqual(rc, 2, err)
        self.assertIn("bound to chain 31337", err)

    def test_dry_run_reads_nothing_and_is_marked(self):
        with RpcStub(self.c) as s:
            rc, body, text, _ = run("--profile", "rehearsal-1", "--rpc", s.url, "--staker", STAKER,
                                    "--config", "/x", "--citrate-bin", FAKE_BIN, "--dry-run",
                                    "--registration-nonce", "4", "--account-nonce", "9")
            self.assertEqual(s.requests, [])
        self.assertEqual(rc, 0)
        self.assertTrue(body["dry_run"])
        self.assertEqual(int(body["unsigned_tx"]["nonce"], 16), 9)
        self.assertIn("DO NOT SIGN", text)
        self.assertTrue(body["warnings"])

    def test_live_mode_rejects_dry_run_nonces_and_pending_profile(self):
        with RpcStub(self.c) as s:
            rc, _, _, err = self.build(s.url, "--registration-nonce", "1")
            self.assertEqual(rc, 2)
            rc, _, _, err = run("--profile", "rehearsal-1", "--rpc", s.url, "--staker", STAKER,
                                "--citrate-bin", FAKE_BIN)
            self.assertEqual(rc, 2)
            self.assertIn("not ready", err)

    def test_out_file(self):
        out = Path(self.tmp.name) / "tx.json"
        with RpcStub(self.c) as s:
            rc, body, _, _ = self.build(s.url, "--out", str(out))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.read_text())["unsigned_tx"], body["unsigned_tx"])


@unittest.skipUnless(os.environ.get("CITRATE_NODE_BIN"), "set CITRATE_NODE_BIN to a built citrate binary")
class TestWithRealBinary(unittest.TestCase):
    """End to end through the real `citrate registration-proof` with a throwaway test key."""

    def test_real_proof(self):
        binary = os.environ["CITRATE_NODE_BIN"]
        with tempfile.TemporaryDirectory() as t:
            data = Path(t) / "data"
            data.mkdir(mode=0o700)
            key = data / "proposer.key"
            key.write_bytes(bytes(range(32)))  # a throwaway test seed, never a real key
            key.chmod(0o600)
            etc = Path(t) / "etc"
            etc.mkdir()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(g.main(["--profile", "40204-r1005", "--staker", STAKER,
                                         "--out-dir", str(etc), "--data-dir", str(data)]), 0)
            c = FakeChain()
            c.balances[STAKER] = MIN * 2
            with RpcStub(c) as s:
                rc, body, _, err = run("--profile", "40204-r1005", "--rpc", s.url, "--staker", STAKER,
                                       "--config", str(etc / "node.toml"), "--citrate-bin", binary)
            self.assertEqual(rc, 0, err)
            pk = body["summary"]["proposer_pubkey"]
            sig = body["proof"]["ed25519_signature"]
            self.assertEqual(body["unsigned_tx"]["data"],
                             "0x10f53ba1" + pk[2:] + f"{64:064x}" + f"{64:064x}" + sig[2:])
            # pubkey-only mode prints the same key
            cp = subprocess.run([binary, "--config", str(etc / "node.toml"), "registration-proof"],
                                capture_output=True, text=True, env=dict(os.environ, RUST_LOG="error"))
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn(pk, cp.stdout)
            self.assertNotIn(bytes(range(32)).hex(), cp.stdout + body.__repr__())


if __name__ == "__main__":
    unittest.main()
