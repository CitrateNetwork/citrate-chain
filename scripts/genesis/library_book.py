#!/usr/bin/env python3
"""library_book.py: the genesis library phase (P3L) of genesis_ceremony.sh.

P3L deploys the contracts of the r1005 address book that P1-P4 do not and that the owner
keeps in block 0 (decisions 2026-10-26: the customer DPF set, DeployDpf02Rbac..DeployDpf17Release,
is out, and so is DeployQuorumS6, which needs DeployDpf02Rbac's TenantHierarchy; the agent
decision registry stays, through its own script), by running the forge scripts below in a
fixed order (the r1005 deploy driver's order). P3L runs before P4, whose PatronageLedger takes
the library's KYCRegistry. This file is the single source of that order and of the book name
each deployment gets.

  scripts     print the scripts in order, one per line (the ceremony checks its own list
              against this one)
  build       build the library book from this run's broadcasts of those scripts: every
              CREATE/CREATE2 with a contract name, named by (script, contract name, nth
              occurrence) below. Fails when an expected deployment is missing, when a
              broadcast has a deployment this table does not name, or when an address
              repeats. Writes {"deployer", "governance", "contracts"}.
  expected    print the expected book names, one per line

Exit: 0 ok · 1 a check failed · 2 usage or unreadable input
"""
import argparse
import glob
import json
import os
import re
import sys

ADDR = re.compile(r"0x[0-9a-fA-F]{40}")

# (script, [(forge contractName, book name), ...]) in deploy order. A contract name that
# occurs twice in one script is listed twice, in broadcast order.
LIBRARY = [
    ("DeployComplianceRegistry.s.sol", [
        ("InstitutionTreeV1", "InstitutionTreeV1"),
        ("ComplianceRegistry", "ComplianceRegistry"),
    ]),
    ("DeployScopedSBTs.s.sol", [
        ("FacilitySBT", "FacilitySBTImpl"),
        ("ERC1967Proxy", "FacilitySBT"),
        ("NetworkSBT", "NetworkSBTImpl"),
        ("ERC1967Proxy", "NetworkSBT"),
    ]),
    ("DeployFederatedLearning.s.sol", [
        ("KYCRegistry", "KYCRegistry"),
        ("IPFSIncentivesV2", "IPFSIncentivesV2"),
        ("IPFSIncentivesV3", "IPFSIncentivesV3"),
        ("AggregationChallenge", "AggregationChallenge"),
        ("ComputePoolPipeline", "ComputePoolPipeline"),
    ]),
    # AgentDecisionRegistryV2 alone (its other script, DeployDpf02Rbac, is customer RBAC and
    # out of block 0); before HUP, whose 40204 ceremony-set check needs it in the book.
    ("DeployAgentDecisionRegistryV2.s.sol", [("AgentDecisionRegistryV2", "AgentDecisionRegistryV2")]),
    # HUP_REGISTRY_ADMIN = GOVERNANCE, so the script deploys no CitAgentTimelock of its own.
    ("DeployHupRegistries.s.sol", [
        ("OrganizationSBT", "OrganizationSBT"),
        ("AgentSBT", "AgentSBT"),
        ("CapsuleRegistry", "CapsuleRegistry"),
        ("AnchorRegistry", "AnchorRegistry"),
        ("BenchmarkRegistry", "BenchmarkRegistry"),
        ("SkillRegistry", "SkillRegistry"),
    ]),
]


def die(msg, code=1):
    print(f"library_book: {msg}", file=sys.stderr)
    sys.exit(code)


def expected():
    return [book for _, rows in LIBRARY for _, book in rows]


def runs_since(bdir, since):
    out = []
    for p in sorted(glob.glob(os.path.join(bdir, "run-*.json"))):
        if os.path.basename(p) == "run-latest.json":
            continue
        try:
            with open(p) as f:
                run = json.load(f)
        except (OSError, ValueError) as e:
            die(f"cannot read {p}: {e}", 2)
        ts = run.get("timestamp") if isinstance(run, dict) else None
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            die(f"{p} has no timestamp", 2)
        if (ts / 1000 if ts > 10**12 else ts) >= since:
            out.append((p, run))
    return out


def build(broadcast, chain, since, deployer, governance, partial=False):
    contracts, seen_addr, problems = {}, {}, []
    for script, rows in LIBRARY:
        runs = runs_since(os.path.join(broadcast, script, str(chain)), since)
        if not runs:
            if not partial:
                problems.append(f"{script}: no broadcast since this chain's block 0")
            continue
        creates = []
        for p, run in runs:
            for tx in run.get("transactions") or []:
                if tx.get("transactionType") not in ("CREATE", "CREATE2"):
                    continue
                n, a = tx.get("contractName"), tx.get("contractAddress")
                if not isinstance(n, str) or not isinstance(a, str) or not ADDR.fullmatch(a):
                    problems.append(f"{script}: {os.path.basename(p)} has a deployment without a contract name or address")
                    continue
                creates.append((n, a.lower()))
        want = list(rows)
        for n, a in creates:
            idx = next((i for i, (cn, _) in enumerate(want) if cn == n), None)
            if idx is None:
                problems.append(f"{script}: deployed {n} at {a}, which the library table does not name")
                continue
            _, book = want.pop(idx)
            if a in seen_addr:
                problems.append(f"{book} {a} is also {seen_addr[a]}")
            seen_addr[a] = book
            contracts[book] = a
        if not partial:
            for _, book in want:
                problems.append(f"{script}: {book} is missing from this run's broadcasts")
    if problems:
        for p in problems:
            print(f"LIBRARY-FAIL {p}")
        die(f"{len(problems)} problem(s) in the library broadcasts")
    return {"deployer": deployer.lower(), "governance": governance.lower(), "contracts": contracts}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scripts")
    sub.add_parser("expected")
    b = sub.add_parser("build")
    b.add_argument("--broadcast", required=True)
    b.add_argument("--chain", required=True)
    b.add_argument("--since", required=True, type=int)
    b.add_argument("--deployer", required=True)
    b.add_argument("--governance", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--partial", action="store_true", help="the book so far (P3L inputs): no completeness check")
    a = ap.parse_args()
    if a.cmd == "scripts":
        print("\n".join(s for s, _ in LIBRARY))
        return 0
    if a.cmd == "expected":
        print("\n".join(expected()))
        return 0
    for k in ("deployer", "governance"):
        if not ADDR.fullmatch(getattr(a, k)):
            die(f"--{k} is not an address", 2)
    book = build(a.broadcast, a.chain, a.since, a.deployer, a.governance, a.partial)
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(book, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, a.out)
    print(f"{len(book['contracts'])} library contract(s) from this run's broadcasts of {len(LIBRARY)} scripts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
