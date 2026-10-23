"""Tests for producerlib: selectors, ABI decoding, epoch math, profiles, RPC errors."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import producerlib as pl  # noqa: E402
from rpcstub import FakeChain, RpcStub  # noqa: E402


def keccak256(data: bytes) -> bytes:
    """Reference Keccak-256 (the pre-NIST padding Ethereum uses), test-only."""
    rc = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    rot = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    mask = (1 << 64) - 1

    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (64 - n))) & mask if n else x

    def f(a: list[list[int]]) -> None:
        for r in rc:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    a[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], rot[x][y])
            for x in range(5):
                for y in range(5):
                    a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
            a[0][0] ^= r

    rate = 136
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate:
        msg += b"\x00"
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off : off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        f(a)
    out = b""
    for i in range(4):
        x, y = i % 5, i // 5
        out += a[x][y].to_bytes(8, "little")
    return out


class TestKeccakAndSelectors(unittest.TestCase):
    def test_reference_keccak_vectors(self):
        self.assertEqual(
            keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )
        self.assertEqual(keccak256(b"transfer(address,uint256)")[:4].hex(), "a9059cbb")

    def test_every_pinned_event_topic(self):
        src = (HERE.parents[2] / "contracts/src/ValidatorRegistry.sol").read_text()
        for sig, topic in pl.REGISTRY_EVENTS_NO_STAKE_EFFECT.items():
            self.assertEqual(keccak256(sig.encode()).hex(), topic, sig)
            self.assertIn(f"event {sig.split('(')[0]}(", src, sig)

    def test_every_pinned_selector(self):
        for sig, sel in pl.SELECTORS.items():
            self.assertEqual(keccak256(sig.encode())[:4].hex(), sel, sig)

    def test_registry_source_still_declares_each_function(self):
        src = (HERE.parents[2] / "contracts/src/ValidatorRegistry.sol").read_text()
        for sig in pl.SELECTORS:
            name = sig.split("(")[0]
            self.assertRegex(src, rf"(function {name}\(|public {name};|public {name}\b)", sig)

    def test_registry_geometry_matches_contract(self):
        src = (HERE.parents[2] / "contracts/src/ValidatorRegistry.sol").read_text()
        self.assertIn(f"EPOCH = {pl.EPOCH};", src)
        self.assertIn(f"SNAPSHOT_LAG = {pl.SNAPSHOT_LAG};", src)
        self.assertIn(f"MAX_ACTIVE_SET = {pl.MAX_ACTIVE_SET};", src)


class TestEncoding(unittest.TestCase):
    def test_calldata_pads_address(self):
        cd = pl.calldata("registrationNonce(address)", "0x" + "22" * 20)
        self.assertEqual(cd, "0x7c360a1d" + "00" * 12 + "22" * 20)

    def test_norm_addr(self):
        self.assertEqual(pl.norm_addr("AB" * 20), "0x" + "ab" * 20)
        for bad in ("0x12", "0x" + "00" * 20, "0x" + "zz" * 20):
            with self.assertRaises(pl.ToolError):
                pl.norm_addr(bad)

    def test_salt_to_wei_exact(self):
        self.assertEqual(pl.salt_to_wei("32000"), 32_000 * 10**18)
        self.assertEqual(pl.salt_to_wei("0.000000000000000001"), 1)
        self.assertEqual(pl.salt_to_wei("32,000.5"), 32_000_500_000_000_000_000_000)
        for bad in ("0", "-1", "1e-19", "abc"):
            with self.assertRaises(pl.ToolError):
                pl.salt_to_wei(bad)

    def test_salt_format(self):
        self.assertEqual(pl.salt(32_000 * 10**18), "32,000 SALT")
        self.assertEqual(pl.salt(10**18 + 5 * 10**17), "1.5 SALT")

    def test_decode_active_set_roundtrip_and_truncation(self):
        c = FakeChain()
        c.add_validator("0x" + "01" * 32, "0x" + "a1" * 20, 40_000, 3)
        c.add_validator("0x" + "02" * 32, "0x" + "a2" * 20, 50_000, 3)
        ret = c.call("0xde4f679632be7810d915f637cc6a72bf076a3bd9", "0xfd4665ae")
        got = pl.decode_active_set(ret)
        self.assertEqual(got, [("0x" + "01" * 32, 40_000), ("0x" + "02" * 32, 50_000)])
        with self.assertRaises(pl.RpcError):
            pl.decode_active_set(ret[:-64])
        with self.assertRaises(pl.RpcError):
            pl.decode_active_set("0x")

    def test_decode_active_set_rejects_duplicate_keys(self):
        # A repeated pubkey would inflate the member count the committee check relies on.
        k = "01" * 32
        ret = "0x" + "".join(f"{x:064x}" for x in (64, 160, 2)) + k + k + "".join(f"{x:064x}" for x in (2, 5, 5))
        with self.assertRaises(pl.RpcError):
            pl.decode_active_set(ret)

    def test_decode_validator_info(self):
        c = FakeChain()
        c.add_validator("0x" + "01" * 32, "0x" + "a1" * 20, 7, 9)
        info = pl.decode_validator_info(c.call("0xde4f679632be7810d915f637cc6a72bf076a3bd9", "0x00408838" + "01" * 32))
        self.assertEqual(info["staker"], "0x" + "a1" * 20)
        self.assertEqual(info["act_epoch"], 9)
        self.assertEqual(info["status"], "Active")
        with self.assertRaises(pl.RpcError):
            pl.decode_validator_info("0x" + "00" * 64 * 8 + f"{9:064x}" + "00" * 32)

    def test_errors_are_never_zero(self):
        for bad in (None, "", "0x", "0x1", 0):
            with self.assertRaises(pl.RpcError):
                pl.uint_word(bad, "x")  # type: ignore[arg-type]
        with self.assertRaises(pl.RpcError):
            pl.parse_qty(None, "x")


class TestEpochMath(unittest.TestCase):
    def test_governing_snapshot_matches_vrf_rs(self):
        # vrf.rs: greatest S(E) strictly below height; S(1)=800, S(2)=1800.
        self.assertIsNone(pl.governing_snapshot_epoch(800))
        self.assertEqual(pl.governing_snapshot_epoch(801), 1)
        self.assertEqual(pl.governing_snapshot_epoch(1800), 1)
        self.assertEqual(pl.governing_snapshot_epoch(1801), 2)
        self.assertEqual(pl.snapshot_height(2), 1800)

    def test_registration_is_always_inside_its_activation_snapshot(self):
        # firstEpochAfterSnapshot(b) = (b + 200) // 1000 + 1, and b < S(actEpoch) for all b.
        for b in range(0, 5000, 7):
            act = (b + pl.SNAPSHOT_LAG) // pl.EPOCH + 1
            self.assertLess(b, pl.snapshot_height(act))


class TestProfiles(unittest.TestCase):
    def test_live_profile_is_ready_and_consistent_with_repo(self):
        p = pl.load_profile("40204-r1005")
        repo = HERE.parents[2]
        book = json.loads((repo / "contracts/addresses/40204.json").read_text())
        self.assertEqual(p["validator_registry"].lower(), book["contracts"]["ValidatorRegistry"].lower())
        beta = (repo / "node/config/testnet-beta.toml").read_text()
        for b in p["bootstrap_nodes"]:
            self.assertIn(b, beta)

    def test_pending_profile_refused_unless_dry_run(self):
        with self.assertRaises(pl.ToolError) as cm:
            pl.load_profile("rehearsal-1")
        self.assertIn("not ready", str(cm.exception))
        self.assertEqual(pl.load_profile("rehearsal-1", allow_pending=True).name, "rehearsal-1")

    def test_ready_status_with_bad_values_is_refused(self):
        raw = json.loads((pl.PROFILE_DIR / "40204-r1005.json").read_text())
        raw["validator_activation_height"] = 100  # below S(1)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(raw, f)
        with self.assertRaises(pl.ToolError):
            pl.load_profile(f.name)
        Path(f.name).unlink()


class TestRpc(unittest.TestCase):
    def test_check_network_requires_chain_and_genesis(self):
        prof = pl.load_profile("40204-r1005")
        c = FakeChain()
        with RpcStub(c) as s:
            self.assertEqual(pl.check_network(pl.Rpc(s.url), prof)["head"], c.head)
            c.genesis = "0x" + "11" * 32
            with self.assertRaises(pl.ToolError):
                pl.check_network(pl.Rpc(s.url), prof)
            c.genesis = prof["genesis_hash"]
            c.chain_id = 1337
            with self.assertRaises(pl.ToolError):
                pl.check_network(pl.Rpc(s.url), prof)

    def test_unreachable_rpc_raises(self):
        with self.assertRaises(pl.RpcError):
            pl.Rpc("http://127.0.0.1:9", timeout=2).call("eth_chainId", [])


if __name__ == "__main__":
    unittest.main()
