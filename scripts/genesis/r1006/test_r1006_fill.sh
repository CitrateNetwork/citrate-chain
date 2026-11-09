#!/usr/bin/env bash
# test_r1006_fill.sh: the validator-set fill path against the REAL ceremony registry.
#
# Runs fill_producers.py's proof check and contracts/script/GenesisValidators.s.sol on the
# committed r1006 alloc's ValidatorRegistry (its runtime code and storage), with 7 producers
# whose throwaway ed25519 keys sign the real registration digest. Checks:
#   * the 7 register (224,000 SALT bonded, the active set is the 7);
#   * a signature the fill did not verify is REFUSED by the registry itself (the script
#     answers the ed25519 precompile only for verified inputs; no catch-all);
# No chain, no RPC; writes only under a mktemp dir. Needs forge, cast, python3 (cryptography),
# and FOUNDRY_SOLC (or solc 0.8.36 in forge's cache) when offline.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v forge >/dev/null || { echo "SKIP test_r1006_fill (no forge)"; exit 0; }
T=$(mktemp -d "${TMPDIR:-/tmp}/r1006-fill-test.XXXXXX")
trap 'rm -rf "${T:?}"' EXIT
cd "$HERE" && python3 - "$T" <<'PY'
import json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import fill_producers as fp
t = sys.argv[1]
alloc = json.load(open(fp.ASSETS / "alloc.json"))
vr = alloc["validatorRegistry"]
vals, fails = [], 0
for i in range(7):
    k = Ed25519PrivateKey.from_private_bytes(bytes([0x40 + i]) * 32)  # throwaway test keys
    pk = "0x" + k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    st = "0x" + f"{0xb0 + i:02x}" * 20
    vals.append({"name": f"prod-{i}", "proposer_pubkey": pk, "staker": st, "stake_wei": str(32000 * 10**18),
                 "liquid_wei": "0", "registration_sig": "0x" + k.sign(fp.registration_digest(vr, st, pk)).hex()})
ok = lambda c, m: print(("ok   " if c else "FAIL ") + m) or (0 if c else 1)
d = fp.registry_delta(alloc, [dict(v) for v in vals], 1767225600)
fails += ok(int(d["balance"]) - int(next(a for a in alloc["accounts"] if a["address"] == vr)["balance"], 16) == 7 * 32000 * 10**18,
            "7 producers registered through the registry's own code: 224,000 SALT bonded")
fails += ok(len(d["storage"]) > 0 and d["activationEpoch"] == 1, "registry storage written; activation epoch 1")
bad = [dict(v) for v in vals]
bad[2]["registration_sig"] = vals[3]["registration_sig"]  # a real signature, by another key
import contextlib, io
err = io.StringIO()
try:
    with contextlib.redirect_stderr(err):
        fp.registry_delta(alloc, bad, 1767225600)
    fails += ok(False, "the registry refuses a signature the fill did not verify")
except SystemExit:
    fails += ok("GenesisValidators failed" in err.getvalue() and "BadSig" in err.getvalue(),
                "the registry refuses a signature the fill did not verify (BadSig)")
print(f"\n{2 + 1 - fails} passed, {fails} failed")
sys.exit(1 if fails else 0)
PY
