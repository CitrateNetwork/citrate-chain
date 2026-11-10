#!/usr/bin/env python3
"""make_inputs.py: ceremony inputs (addresses only) from an addresses.env.

  make_inputs.py --addresses ~/.citrate-r1007-keys/addresses.env > inputs.env

Every owner is a parameter: GOVERNANCE (3-of-5) = GOV1..GOV5, GUARDIAN (2-of-3) = GRD1..GRD3,
and every other role below, all read from addresses.env. Nothing is hard-coded, so a rebuild
cannot silently keep an earlier chain's owners (fed #493; owner 2026-11-10: rotate every
non-producer EVM key for r1007). r1006 kept the three R2 governance and three R2 guardian
owners; reproducing its inputs means passing those as GOV1-3 / GRD1-3 explicitly.
Refuses a missing role, anything that is not a 20-byte address, and an address in two roles.
"""
import argparse
import re
import sys

GOV = ["GOV1", "GOV2", "GOV3", "GOV4", "GOV5"]
GRD = ["GRD1", "GRD2", "GRD3"]
OTHER = ["TREASURY", "FAUCET", "RELAYER", "TEAM", "SIGNER_1", "SIGNER_2", "SIGNER_3", "CITRATE_AA_OWNER",
         "CITRATE_AA_IDENTITY_SIGNER", "CITRATE_AA_SPONSOR_SIGNER", "MEMBERSHIP_GRANTOR"]
REQUIRED = GOV + GRD + OTHER
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
    missing = [r for r in REQUIRED if r not in got]
    if missing:
        fail(f"missing role addresses (every owner is a parameter): {missing}")
    gov = [got[r] for r in GOV]
    grd = [got[r] for r in GRD]
    every = [got[r] for r in REQUIRED]
    if len(set(every)) != len(every):
        fail("an address appears in two roles")
    out = ["# Ceremony inputs: PUBLIC ADDRESSES ONLY. Written by make_inputs.py from addresses.env:",
           "# GOVERNANCE = GOV1..GOV5, GUARDIAN = GRD1..GRD3, every other role as passed.",
           "R1006_INPUTS_STATUS=final",
           f"GOV_OWNERS={','.join(gov)}", "GOV_THRESHOLD=3", "GOV_MIN_DELAY=172800", "GOV_PROPOSAL_TTL=1209600",
           f"GRD_OWNERS={','.join(grd)}", "GRD_THRESHOLD=2", "GRD_MIN_DELAY=3600", "GRD_PROPOSAL_TTL=1209600"]
    for r in ("MEMBERSHIP_GRANTOR", "SIGNER_1", "SIGNER_2", "SIGNER_3", "RELAYER", "CITRATE_AA_OWNER",
              "CITRATE_AA_IDENTITY_SIGNER", "CITRATE_AA_SPONSOR_SIGNER"):
        out.append(f"{r}={got[r]}")
    out += ["# DeployAll's fee/treasury recipient (#396: required on 40204): the fresh TREASURY.",
            f"TREASURY={got['TREASURY']}"]
    out += ["# Base allocations (replaces r1005's funded accounts; see core/economics/src/r1006.rs).",
            f"BASE_TREASURY={got['TREASURY']}", f"BASE_FAUCET={got['FAUCET']}", f"BASE_TEAM={got['TEAM']}",
            "# P3: one team-vesting grant to TEAM (A-4 amounts/schedule open). Start 2027-10-28T00:00:00Z.",
            f"TEAM_VESTING_BENEFICIARY={got['TEAM']}", "TEAM_VESTING_START=1824681600",
            "TEAM_VESTING_DURATION=126144000", "TEAM_VESTING_CLIFF=31536000", "TEAM_VESTING_AMOUNT=100000000000000000000"]
    print("\n".join(out))


if __name__ == "__main__":
    main()
