"""The r1007 genesis and post-genesis books are built from the on-chain probe and nothing else.

scripts/addresses/emit_r1007_books.py writes contracts/addresses/r1007/40204.json and
40204.postgenesis.json from contracts/addresses/r1006/40204.json plus the read-only r1007 probe
(contracts/addresses/r1007/40204.provenance.json). No network here.

The tests fail when:
  * a committed r1007 book drifts from the builder;
  * the builder accepts a block-0 entry the probe found no code at;
  * it accepts a post-genesis address that is not the deployer's CREATE address for its nonce;
  * it accepts an "account" that has code.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADDRS = ROOT / "contracts" / "addresses"
R1007_GENESIS = "0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631"
POSTGENESIS_DEPLOYER = "0x402c63FdbCdeF652b3989ad1522a4Ba9da309414"

_spec = importlib.util.spec_from_file_location("emit_r1007_books", ROOT / "scripts" / "addresses" / "emit_r1007_books.py")
eb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(eb)


def load(rel):
    return json.loads((ADDRS / rel).read_text())


class BooksAreGenerated(unittest.TestCase):
    def test_committed_books_equal_builder_output(self):
        for rel, text in eb.render(ROOT).items():
            self.assertEqual((ROOT / rel).read_text(), text, f"{rel} is stale: run scripts/addresses/emit_r1007_books.py")

    def test_check_mode_passes(self):
        self.assertEqual(eb.main(["--check"]), 0)


class Content(unittest.TestCase):
    def setUp(self):
        self.g = load("r1007/40204.json")
        self.p = load("r1007/40204.postgenesis.json")
        self.r1006 = load("r1006/40204.json")
        self.prov = load("r1007/40204.provenance.json")

    def test_block_0_addresses_are_r1006s_with_the_r1007_deployer(self):
        for s in ("contracts", "aaStack", "genesis", "precompiles"):
            self.assertEqual(self.g[s], self.r1006[s], s)
        self.assertEqual(self.g["governance"], self.r1006["governance"])
        self.assertEqual(self.g["deployer"], self.prov["genesisDeployer"])
        self.assertNotEqual(self.g["deployer"].lower(), self.r1006["deployer"].lower())
        self.assertEqual(self.g["deployedAt"], "2026-11-12T14:00:00Z")

    def test_post_genesis_is_nonces_0_to_28_without_the_nonce_4_duplicate(self):
        self.assertEqual(self.p["genesisHash"], R1007_GENESIS)
        self.assertEqual(self.p["deployer"], POSTGENESIS_DEPLOYER)
        self.assertEqual(len(self.p["contracts"]), 28)
        self.assertNotIn("AgentDecisionRegistryV2", self.p["contracts"])
        by_nonce = {e["nonce"]: e for e in self.prov["postGenesis"]}
        self.assertEqual(self.p["contracts"]["TenantHierarchy"], by_nonce[0]["address"])
        self.assertEqual(self.p["contracts"]["ReleaseManifestRegistry"], by_nonce[28]["address"])
        # Same contract names as r1006's post-genesis book, every address new.
        old = load("r1006/40204.postgenesis.json")["contracts"]
        self.assertEqual(set(self.p["contracts"]), set(old))
        self.assertFalse({a.lower() for a in self.p["contracts"].values()} & {a.lower() for a in old.values()})

    def test_every_probed_address_has_code_and_accounts_have_none(self):
        for k, e in self.prov["blockZero"].items():
            self.assertRegex(e["codehash"], r"^0x[0-9a-f]{64}$", k)
        for e in self.prov["postGenesis"]:
            self.assertRegex(e["codehash"], r"^0x[0-9a-f]{64}$", e["name"])
        for k, e in self.prov["accounts"].items():
            self.assertEqual(e["code"], "0x", k)
        self.assertEqual(self.p["accounts"], {k: e["address"] for k, e in self.prov["accounts"].items()})


class Primitives(unittest.TestCase):
    def test_keccak_empty_vector(self):
        self.assertEqual(eb.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_create_address_matches_cast(self):
        # cast compute-address --nonce N 0x402c63FdbCdeF652b3989ad1522a4Ba9da309414
        self.assertEqual(eb.create_address(POSTGENESIS_DEPLOYER, 0), "0x92f2bc7e1b33841de1b138fe28cf202222562cc3")
        self.assertEqual(eb.create_address(POSTGENESIS_DEPLOYER, 28), "0xd6a8b3134340ca1e78843db5eb6640b1dbbc8b20")
        # The r1006 deployer's nonce 0 is the r1006 TenantHierarchy.
        self.assertEqual(eb.create_address("0x68dd27190b7eb113134da0da78abb8478d1904a8", 0),
                         "0xe1c1674962792ec89dc28f72e99cf9d0edd6bc18")


class BuilderRefuses(unittest.TestCase):
    def setUp(self):
        self.r1006 = load("r1006/40204.json")
        self.prov = load("r1007/40204.provenance.json")

    def refuses(self, r1006, prov, needle):
        with self.assertRaises(eb.BookError) as cm:
            eb.build(r1006, prov)
        self.assertIn(needle, str(cm.exception))

    def test_a_block_0_entry_without_code(self):
        p = copy.deepcopy(self.prov)
        p["blockZero"]["contracts.ModelRegistry"]["codehash"] = None
        self.refuses(self.r1006, p, "found no code")

    def test_a_block_0_entry_the_probe_does_not_have(self):
        p = copy.deepcopy(self.prov)
        del p["blockZero"]["aaStack.EntryPoint"]
        self.refuses(self.r1006, p, "not in the r1007 probe")

    def test_a_block_0_entry_at_another_address(self):
        p = copy.deepcopy(self.prov)
        p["blockZero"]["contracts.ModelRegistry"]["address"] = "0x" + "11" * 20
        self.refuses(self.r1006, p, "not in the r1007 probe")

    def test_a_post_genesis_address_that_is_not_its_nonces(self):
        p = copy.deepcopy(self.prov)
        p["postGenesis"][3]["address"] = p["postGenesis"][2]["address"]
        self.refuses(self.r1006, p, "is not the deployer's nonce-3 address")

    def test_a_post_genesis_entry_without_code(self):
        p = copy.deepcopy(self.prov)
        p["postGenesis"][5]["codehash"] = None
        self.refuses(self.r1006, p, "found no code")

    def test_a_missing_nonce(self):
        p = copy.deepcopy(self.prov)
        del p["postGenesis"][10]
        self.refuses(self.r1006, p, "nonces 0..28")

    def test_an_account_with_code(self):
        p = copy.deepcopy(self.prov)
        p["accounts"]["Faucet"]["code"] = "0x6080"
        self.refuses(self.r1006, p, "not an EOA")

    def test_a_malformed_genesis_hash(self):
        p = copy.deepcopy(self.prov)
        p["genesisHash"] = "0x1234"
        self.refuses(self.r1006, p, "genesisHash")


if __name__ == "__main__":
    unittest.main()
