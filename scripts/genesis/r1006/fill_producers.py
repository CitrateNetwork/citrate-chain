#!/usr/bin/env python3
"""fill_producers.py: fill the r1006 producer set (the validators registered at genesis).

The r1006 genesis registers its 7 producers in the ValidatorRegistry during the ceremony,
so block 0 already has them in the active set. Each producer supplies PUBLIC values only:

  name             a label (operator / host)
  staker           the staker EOA (pays the bond on the ceremony devnet; holds the validator)
  proposerPubkey   the node's ed25519 proposer public key (32 bytes, 0x-hex)
  registrationSig  the proposer key's ed25519 signature over the registration digest
                   (`digest` below), 64 bytes, 0x-hex: proof that the producer holds the key
  stake            bond in wei (decimal string), >= the registry's 32,000 SALT minimum

Commands
  digest --registry VR --staker S --pubkey P
      prints the 32-byte digest a producer signs (chain 40204, nonce 0), the same bytes the
      contract and citrate_consensus::crypto::registration_digest build.
  fill --registry VR --from producers.json [--out PATH]
      checks every entry (7 producers, distinct stakers and keys, every signature verifies
      for this registry) and writes the validators file with status "final". Rebuild the
      genesis afterwards (build_r1006_genesis.sh): the alloc records this file's hash, and
      the r1006 profile is release-ready only when the two agree.
  check [--path PATH]
      re-verifies a filled file; exit 1 on any problem, and on a placeholder.

Exit: 0 ok, 1 invalid input, 2 usage.
"""
import argparse
import json
import re
import subprocess
import sys

DEFAULT_PATH = "core/economics/assets/r1006/validators.json"
CHAIN_ID = 40204
COUNT = 7
MIN_STAKE = 32_000 * 10**18
REGISTER_TYPE = "Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)"
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
B32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
B64 = re.compile(r"^0x[0-9a-fA-F]{128}$")
DOC = ("The r1006 producer set (7). Filled by scripts/genesis/r1006/fill_producers.py; "
       "public values only: staker address, proposer public key, registration signature, stake.")


def fail(msg):
    print(f"fill_producers: {msg}", file=sys.stderr)
    sys.exit(1)


def keccak(data: bytes) -> bytes:
    out = subprocess.run(["cast", "keccak", "0x" + data.hex()], capture_output=True, text=True, check=True)
    return bytes.fromhex(out.stdout.strip()[2:])


def word_u(n: int) -> bytes:
    return n.to_bytes(32, "big")


def word_a(a: str) -> bytes:
    return bytes(12) + bytes.fromhex(a[2:])


def digest(registry: str, staker: str, pubkey: str, nonce: int = 0) -> bytes:
    return keccak(keccak(REGISTER_TYPE.encode()) + word_u(CHAIN_ID) + word_a(registry) + word_a(staker)
                  + bytes.fromhex(pubkey[2:]) + word_u(nonce))


def verify(pubkey: str, sig: str, msg: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey[2:])).verify(bytes.fromhex(sig[2:]), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def check_entries(registry, producers):
    if not ADDR.match(registry or "") or int(registry, 16) == 0:
        fail(f"registry {registry!r} is not an address")
    if len(producers) != COUNT:
        fail(f"{len(producers)} producers, want {COUNT}")
    stakers, keys, names = set(), set(), set()
    out = []
    for i, p in enumerate(producers):
        if not isinstance(p, dict):
            fail(f"producer {i}: not filled")
        extra = set(p) - {"name", "staker", "proposerPubkey", "registrationSig", "stake"}
        if extra:
            fail(f"producer {i}: unknown fields {sorted(extra)}")
        name, staker, pk, sig = p.get("name"), p.get("staker", ""), p.get("proposerPubkey", ""), p.get("registrationSig", "")
        if not isinstance(name, str) or not re.match(r"^[A-Za-z0-9_.-]{1,40}$", name):
            fail(f"producer {i}: bad name {name!r}")
        if not ADDR.match(staker) or int(staker, 16) == 0:
            fail(f"{name}: bad staker {staker!r}")
        if not B32.match(pk) or int(pk, 16) == 0:
            fail(f"{name}: proposerPubkey must be 32 bytes of 0x-hex")
        if not B64.match(sig):
            fail(f"{name}: registrationSig must be 64 bytes of 0x-hex")
        try:
            stake = int(str(p.get("stake")), 10)
        except ValueError:
            fail(f"{name}: stake must be a decimal wei string")
        if stake < MIN_STAKE:
            fail(f"{name}: stake {stake} is below the 32,000 SALT minimum")
        staker, pk, sig = staker.lower(), pk.lower(), sig.lower()
        for seen, v, what in ((names, name, "name"), (stakers, staker, "staker"), (keys, pk, "proposerPubkey")):
            if v in seen:
                fail(f"{name}: duplicate {what} {v}")
            seen.add(v)
        if not verify(pk, sig, digest(registry.lower(), staker, pk)):
            fail(f"{name}: registrationSig does not verify for registry {registry} and staker {staker}")
        out.append({"name": name, "staker": staker, "proposerPubkey": pk, "registrationSig": sig, "stake": str(stake)})
    return out


def write(path, registry, producers):
    v = {"_doc": DOC, "status": "final", "validatorRegistry": registry.lower(), "producers": producers}
    with open(path, "w", newline="\n") as f:
        f.write(json.dumps(v, indent=1) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("digest")
    d.add_argument("--registry", required=True)
    d.add_argument("--staker", required=True)
    d.add_argument("--pubkey", required=True)
    f = sub.add_parser("fill")
    f.add_argument("--registry", required=True)
    f.add_argument("--from", dest="src", required=True)
    f.add_argument("--out", default=DEFAULT_PATH)
    c = sub.add_parser("check")
    c.add_argument("--path", default=DEFAULT_PATH)
    a = ap.parse_args()
    if a.cmd == "digest":
        for v, rx, w in ((a.registry, ADDR, "registry"), (a.staker, ADDR, "staker"), (a.pubkey, B32, "pubkey")):
            if not rx.match(v):
                fail(f"bad {w} {v!r}")
        print("0x" + digest(a.registry.lower(), a.staker.lower(), a.pubkey.lower()).hex())
    elif a.cmd == "fill":
        src = json.load(open(a.src))
        producers = src["producers"] if isinstance(src, dict) else src
        write(a.out, a.registry, check_entries(a.registry, producers))
        print(f"fill_producers: {COUNT} producers verified for registry {a.registry.lower()}; wrote {a.out}")
    else:
        v = json.load(open(a.path))
        if v.get("status") != "final":
            fail(f"{a.path} is a placeholder (status {v.get('status')!r})")
        check_entries(v.get("validatorRegistry"), v.get("producers", []))
        print(f"fill_producers: {a.path} OK")


if __name__ == "__main__":
    main()
