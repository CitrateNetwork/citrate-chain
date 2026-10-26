#!/usr/bin/env python3
"""fill_producers.py: the r1006 validator-set fill (the producers registered at block 0).

The bring-up (scripts/ops/r1006_bringup.sh genesis-fill, chain#390) calls it as

  fill_producers.py PRODUCERS STAKES OUT

  PRODUCERS  r1006-producers.json (schema r1006-producers/1, public parts only, from
             `citrate host-identity` via collect.py): per producer name, proposer_pubkey,
             staker_address (== coinbase_address, a consensus rule)
  STAKES     r1006-stakes.json (schema r1006-stakes/1): per staker stake_wei (bonded in the
             ValidatorRegistry) and liquid_wei (the staker's balance at genesis, for gas)
  OUT        a directory; receives fill-result.json (schema r1006-genesis-fill/1, the
             contract in chain#390's render_profile.py), genesis-alloc.json and book.json

What it does, in order (any failure exits non-zero and writes no fill-result.json):
  1. checks both inputs (schemas, exact field forms, distinct keys and stakers, staker ==
     coinbase, every producer staked >= 32,000 SALT);
  2. computes the ValidatorRegistry's block-0 state with the producers registered, by
     running the registry's own code from the genesis alloc in a local EVM
     (contracts/script/GenesisValidators.s.sol; no chain, nothing signed);
  3. writes core/economics/assets/r1006/validators.json (status final);
  4. builds the r1006 genesis from the compiled profile (cargo run of the economics
     example r1006_genesis_hash) and pins its hash as R1006_GENESIS in
     core/consensus/src/hardening.rs;
  5. writes OUT/fill-result.json and the files it names.
Then commit the two changed files and build the release binary: the node embeds the
genesis, so the hosts select it by profile (genesis_profile "r1006", genesis_file null).

  fill_producers.py validate PRODUCERS STAKES        step 1 only (no forge, no cargo)
  fill_producers.py check [--path validators.json]   re-check a filled set (exit 1 on a
                                                     placeholder or any problem)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ASSETS = ROOT / "core/economics/assets/r1006"
HARDENING = ROOT / "core/consensus/src/hardening.rs"
BOOK = ROOT / "contracts/addresses/r1006/40204.json"
MIN_STAKE = 32_000 * 10**18
MIN_PRODUCERS = 4
ADDR = re.compile(r"^0x[0-9a-f]{40}$")
B32 = re.compile(r"^0x[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
ORANGESEED = "0x000000000000000000000000000000c17a7e5eed"
DOC = ("The r1006 producer set, registered in the ValidatorRegistry at block 0. Written by "
       "scripts/genesis/r1006/fill_producers.py from the bring-up's public producer set; public "
       "values only.")


def fail(msg):
    print(f"fill_producers: {msg}", file=sys.stderr)
    sys.exit(1)


def load(p):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot read {p}: {e}")


def check_inputs(producers, stakes):
    if producers.get("schema") != "r1006-producers/1":
        fail("producers: schema is not r1006-producers/1")
    if producers.get("chain_id", 40204) != 40204:
        fail("producers: chain_id is not 40204")
    if stakes.get("schema") != "r1006-stakes/1":
        fail("stakes: schema is not r1006-stakes/1")
    ps = producers.get("producers")
    if not isinstance(ps, list) or len(ps) < MIN_PRODUCERS:
        fail(f"producers: need at least {MIN_PRODUCERS}")
    st = {k.lower(): v for k, v in stakes.get("stakes", {}).items()}
    out, seen = [], {}
    for p in ps:
        name = p.get("name", "")
        if not NAME.match(str(name)):
            fail(f"producers: bad name {name!r}")
        pk, staker, cb = (str(p.get(k, "")) for k in ("proposer_pubkey", "staker_address", "coinbase_address"))
        if not B32.match(pk) or int(pk, 16) == 0:
            fail(f"{name}: proposer_pubkey is not a 32-byte key (lowercase 0x-hex)")
        if not ADDR.match(staker) or int(staker, 16) == 0:
            fail(f"{name}: staker_address is not an address (lowercase 0x-hex)")
        if cb != staker:
            fail(f"{name}: staker and coinbase differ (consensus requires coinbase == staker)")
        for k, v in (("name", name), ("proposer_pubkey", pk), ("staker", staker)):
            if (k, v) in seen:
                fail(f"{name}: {k} is the same as {seen[(k, v)]}'s")
            seen[(k, v)] = name
        s = st.get(staker)
        if s is None:
            fail(f"{name}: staker {staker} has no stake allocation")
        try:
            stake, liquid = int(s["stake_wei"]), int(s["liquid_wei"])
        except (KeyError, ValueError):
            fail(f"{name}: stake_wei / liquid_wei must be decimal wei strings")
        if stake < MIN_STAKE:
            fail(f"{name}: stake {stake} is below the 32,000 SALT minimum")
        if liquid < 0:
            fail(f"{name}: negative liquid_wei")
        out.append({"name": name, "proposer_pubkey": pk, "staker": staker,
                    "stake_wei": str(stake), "liquid_wei": str(liquid)})
    if set(st) - {v["staker"] for v in out}:
        fail(f"stakes: allocations for stakers that are not producers: {sorted(set(st) - {v['staker'] for v in out})}")
    return out


def registry_delta(alloc, validators, ts):
    vr = alloc["validatorRegistry"]
    acct = next((a for a in alloc["accounts"] if a["address"] == vr), None)
    if acct is None or not acct.get("code"):
        fail(f"the ValidatorRegistry {vr} has no code in the alloc")
    forge = shutil.which("forge") or fail("forge is required")
    with tempfile.TemporaryDirectory(prefix="r1006-fill-") as t:
        t = Path(t)
        (t / "script").mkdir()
        (t / "lib").mkdir()
        (t / "genesis").mkdir()
        os.symlink(ROOT / "contracts/lib/forge-std", t / "lib/forge-std")
        shutil.copy(ROOT / "contracts/script/GenesisValidators.s.sol", t / "script/")
        (t / "foundry.toml").write_text(
            '[profile.default]\nsrc = "script"\nlibs = ["lib"]\nevm_version = "cancun"\n'
            'fs_permissions = [{ access = "read-write", path = "./genesis" }]\n')
        (t / "remappings.txt").write_text("forge-std/=lib/forge-std/src/\n")
        state = {"code": acct["code"], "balance": acct["balance"], "storage": acct.get("storage", {})}
        (t / "genesis/vr.json").write_text(json.dumps(state))
        (t / "genesis/validators.json").write_text(json.dumps({"count": len(validators), "validators": validators}))
        env = dict(os.environ, FOUNDRY_OFFLINE="true", GENESIS_VR=vr, GENESIS_VR_STATE="genesis/vr.json",
                   GENESIS_VALIDATORS="genesis/validators.json", GENESIS_TIMESTAMP=str(ts),
                   GENESIS_VALIDATORS_OUT="genesis/out.json")
        r = subprocess.run([forge, "script", "script/GenesisValidators.s.sol"], cwd=t, env=env,
                           capture_output=True, text=True)
        if r.returncode != 0 or not (t / "genesis/out.json").exists():
            fail(f"GenesisValidators failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
        out = json.loads((t / "genesis/out.json").read_text())
    st = out["storage"]
    if isinstance(st, str):
        st = json.loads(st)
    return {"balance": str(int(str(out["balance"]), 0)), "activationEpoch": int(out["activationEpoch"]),
            "storage": {k.lower(): v.lower() for k, v in sorted(st.items())}}


def genesis_hash():
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0")
    r = subprocess.run(["cargo", "run", "--locked", "-q", "-p", "citrate-economics", "--example", "r1006_genesis_hash"],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    m = re.search(r"R1006_GENESIS=0x([0-9a-f]{64})", r.stdout)
    if r.returncode != 0 or not m:
        fail(f"cannot build the r1006 genesis:\n{r.stdout[-2000:]}\n{r.stderr[-3000:]}")
    return m.group(1)


def pin_hash(h):
    src = HARDENING.read_text()
    new, n = re.subn(r'(pub const R1006_GENESIS: \[u8; 32\] =\s*hex32\(")[0-9a-f]{64}("\);)', rf"\g<1>{h}\g<2>", src)
    if n != 1:
        fail(f"cannot find the R1006_GENESIS pin in {HARDENING}")
    HARDENING.write_text(new)


def write_json(p, d):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, indent=1) + "\n")
    tmp.replace(p)


def main(argv):
    if argv[:1] == ["validate"] and len(argv) == 3:
        v = check_inputs(load(argv[1]), load(argv[2]))
        print(f"fill_producers: {len(v)} producers and their stakes are well formed")
        return
    if argv[:1] == ["check"]:
        path = argv[2] if len(argv) > 2 and argv[1] == "--path" else ASSETS / "validators.json"
        v = load(path)
        if v.get("status") != "final" or not v.get("registry"):
            fail(f"{path} is a placeholder (status {v.get('status')!r})")
        print(f"fill_producers: {path}: {len(v['validators'])} producers, registry {v['validatorRegistry']}")
        return
    if len(argv) != 3:
        fail("usage: fill_producers.py PRODUCERS STAKES OUT  |  fill_producers.py check [--path P]")
    producers, stakes, out = load(argv[0]), load(argv[1]), Path(argv[2])
    validators = check_inputs(producers, stakes)
    alloc = load(ASSETS / "alloc.json")
    if not ADDR.match(alloc.get("validatorRegistry", "")) or int(alloc["validatorRegistry"], 16) == 0:
        fail("the compiled alloc names no ValidatorRegistry (build the ceremony alloc first)")
    reg = registry_delta(alloc, validators, 1767225600)
    write_json(ASSETS / "validators.json", {"_doc": DOC, "schema": "r1006-validators/1", "status": "final",
                                            "validatorRegistry": alloc["validatorRegistry"],
                                            "validators": validators, "registry": reg})
    h = genesis_hash()
    pin_hash(h)
    h2 = genesis_hash()
    if h2 != h:
        fail(f"the genesis hash moved after pinning ({h} -> {h2})")
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "genesis-alloc.json",
               {"alloc": {a["address"]: {"code": a["code"]} for a in alloc["accounts"] if a.get("code")}})
    if BOOK.exists():
        shutil.copy(BOOK, out / "book.json")
    write_json(out / "fill-result.json", {
        "schema": "r1006-genesis-fill/1",
        "genesis_hash": "0x" + h,
        "genesis_profile": "r1006",
        "genesis_file": None,
        "alloc_file": "genesis-alloc.json",
        "address_book": "book.json" if BOOK.exists() else None,
        "orangeseed": ORANGESEED if alloc.get("orangeseed") else None,
        "validator_registry": alloc["validatorRegistry"],
        "validator_activation_height": 0,
        "validators": [{"proposer_pubkey": v["proposer_pubkey"], "staker": v["staker"], "stake_wei": v["stake_wei"]}
                       for v in validators],
        "validators_at_genesis": True,
        "source": f"scripts/genesis/r1006/fill_producers.py (ceremony alloc inputs {alloc['inputsStatus']}, "
                  f"{len(validators)} producers registered at block 0)",
    })
    print(f"fill_producers: {len(validators)} producers registered at block 0 in {alloc['validatorRegistry']}; "
          f"genesis 0x{h}; wrote {out}/fill-result.json. Commit {ASSETS / 'validators.json'} and {HARDENING}, "
          f"then build the release binary.")


if __name__ == "__main__":
    main(sys.argv[1:])
