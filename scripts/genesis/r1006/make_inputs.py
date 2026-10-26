#!/usr/bin/env python3
"""make_inputs.py: the FINAL r1006 ceremony inputs (addresses only) from the owner's decision.

  make_inputs.py --addresses ~/.citrate-r1006-keys/addresses.env > inputs.r1006.env

GOVERNANCE (3-of-5) = the three R2 governance signers + the fresh GOV4, GOV5; GUARDIAN
(2-of-3) = the three R2 guardian signers; every other role is a fresh key (new_role_keys.sh).
Refuses anything that is not a 20-byte address, a duplicate, or a council overlap.
"""
import argparse
import re
import sys

R2_GOVERNANCE = ["0xB4E186CBeab88C8220F3D69f4263FfFCf4C6aDA9", "0xa6BB945bD72684951721ff99AecFDdb48aE22B8b",
                 "0xe154af73bb03bC6073A4f08d6868184774014daf"]
R2_GUARDIAN = ["0xcC9eE1f2c11C53E2B9C30C61848Ee50F12a690Dc", "0x1B0C84e457605a065Beb0B2306efa0Fb54B33e8A",
               "0x8547D47D144877a75dE0097D5E35DA8A355C8E3F"]
FRESH = ["TREASURY", "FAUCET", "RELAYER", "TEAM", "SIGNER_1", "SIGNER_2", "SIGNER_3", "CITRATE_AA_OWNER",
         "CITRATE_AA_IDENTITY_SIGNER", "CITRATE_AA_SPONSOR_SIGNER", "MEMBERSHIP_GRANTOR", "GOV4", "GOV5"]
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def fail(m):
    sys.exit(f"make_inputs: {m}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addresses", required=True)
    a = ap.parse_args()
    got = {}
    for line in open(a.addresses):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        if not ADDR.match(v):
            fail(f"{k}: not an address")
        got[k] = v.lower()
    missing = [r for r in FRESH if r not in got]
    if missing:
        fail(f"missing fresh role addresses: {missing}")
    gov = [x.lower() for x in R2_GOVERNANCE] + [got["GOV4"], got["GOV5"]]
    grd = [x.lower() for x in R2_GUARDIAN]
    every = gov + grd + [got[r] for r in FRESH if r not in ("GOV4", "GOV5")]
    if len(set(every)) != len(every):
        fail("an address appears in two roles")
    out = ["# r1006 ceremony inputs: PUBLIC ADDRESSES ONLY. STATUS final (owner decision 2026-10-26):",
           "# GOVERNANCE = R2 governance signers + fresh GOV4/GOV5; GUARDIAN = R2 guardian signers;",
           "# every other role a fresh key (new_role_keys.sh). Written by make_inputs.py.",
           "R1006_INPUTS_STATUS=final",
           f"GOV_OWNERS={','.join(gov)}", "GOV_THRESHOLD=3", "GOV_MIN_DELAY=172800", "GOV_PROPOSAL_TTL=1209600",
           f"GRD_OWNERS={','.join(grd)}", "GRD_THRESHOLD=2", "GRD_MIN_DELAY=3600", "GRD_PROPOSAL_TTL=1209600"]
    for r in ("MEMBERSHIP_GRANTOR", "SIGNER_1", "SIGNER_2", "SIGNER_3", "RELAYER", "CITRATE_AA_OWNER",
              "CITRATE_AA_IDENTITY_SIGNER", "CITRATE_AA_SPONSOR_SIGNER"):
        out.append(f"{r}={got[r]}")
    out += ["# Base allocations (replaces r1005's funded accounts; see core/economics/src/r1006.rs).",
            f"BASE_TREASURY={got['TREASURY']}", f"BASE_FAUCET={got['FAUCET']}", f"BASE_TEAM={got['TEAM']}",
            "# P3: one team-vesting grant to TEAM (A-4 amounts/schedule open). Start 2027-10-28T00:00:00Z.",
            f"TEAM_VESTING_BENEFICIARY={got['TEAM']}", "TEAM_VESTING_START=1824681600",
            "TEAM_VESTING_DURATION=126144000", "TEAM_VESTING_CLIFF=31536000", "TEAM_VESTING_AMOUNT=100000000000000000000"]
    print("\n".join(out))


if __name__ == "__main__":
    main()
