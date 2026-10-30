"""The r1006 post-genesis address book (contracts deployed after block 0).

Core pins the genesis book (contracts/addresses/r1006/40204.json) by sha256 and never reads this one, so the
post-genesis book must never redefine a genesis name (a later merge into the pinned book would shadow it, e.g.
Quorum's AnchorRegistry over the genesis AnchorRegistry), must hold well-formed unique addresses, and must name
the r1006 genesis it was deployed on.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOKS = ROOT / "contracts" / "addresses" / "r1006"
R1006_GENESIS = "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4"
ADDR = re.compile(r"^0x[0-9a-f]{40}$")


def load(name):
    return json.loads((BOOKS / name).read_text())


class PostGenesisBook(unittest.TestCase):
    def setUp(self):
        self.genesis = load("40204.json")
        self.post = load("40204.postgenesis.json")

    def genesis_names(self):
        names = set(self.genesis["contracts"])
        for section in ("aaStack", "genesis", "precompiles", "governance"):
            names |= set(self.genesis.get(section, {}))
        return names | {k for k, v in self.genesis.items() if isinstance(v, str) and ADDR.match(v.lower())}

    def test_names_the_r1006_genesis(self):
        self.assertEqual(self.post["chainId"], 40204)
        self.assertEqual(self.post["genesisHash"], R1006_GENESIS)

    def test_no_genesis_name_is_redefined(self):
        clash = sorted(set(self.post["contracts"]) & self.genesis_names())
        self.assertEqual(clash, [], f"post-genesis names shadow genesis names: {clash}")

    def test_addresses_are_well_formed_and_unique(self):
        addrs = list(self.post["contracts"].values())
        for name, a in self.post["contracts"].items():
            self.assertRegex(a, ADDR, name)
        self.assertEqual(len(addrs), len(set(addrs)), "an address is listed twice")
        genesis_addrs = {v.lower() for v in self.genesis["contracts"].values()}
        self.assertEqual(sorted(set(addrs) & genesis_addrs), [], "a post-genesis address is also in the genesis book")


if __name__ == "__main__":
    unittest.main()
