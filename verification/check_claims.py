#!/usr/bin/env python3
"""Public-claims truth gate for citrate-chain.

Offline, stdlib only. Fails (exit 1) when:

1. claims.json asserts checkpoint finality is running
   (deterministic_checkpoint_finality.value.running == true, or a status other
   than specified-not-running) while no non-test code path calls `.propose(`
   in node/src or core/consensus/src. The reverse (a production caller exists
   but the claim still says not running) is reported as a warning so the claim
   gets updated when checkpoint finality is wired.
2. consensus_ghostdag / confirmation_latency describe finality as current while
   checkpoint finality is not running.
3. A public README (see PUBLIC_DOCS) describes finality as current, cites the
   stale "76 deployed" / "27 contracts are deployed" counts, names a dead host,
   pipes a script from mutable main into bash, or quotes an address that the
   committed getCode snapshot says has no code (or that is a known-stale
   money-contract address).

Run: python3 verification/check_claims.py [--root DIR]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Every tracked markdown file is public in this repository. Vendored code
# (contracts/lib/**), dated audit records and the agent working tree are excluded.
EXCLUDE_PREFIXES = ("contracts/lib/", ".agentile/", "audits/", "node_modules/", "target/")


def public_docs(root: Path) -> list[str]:
    try:
        import subprocess
        out = subprocess.run(["git", "-C", str(root), "ls-files", "*.md"], capture_output=True, text=True, timeout=60)
        files = out.stdout.split() if out.returncode == 0 and out.stdout.strip() else []
    except Exception:
        files = []
    if not files:  # not a git checkout (e.g. an exported tree): walk the filesystem
        files = [str(f.relative_to(root)) for f in root.rglob("*.md")]
    return sorted(f for f in files if not f.startswith(EXCLUDE_PREFIXES) and "/node_modules/" not in f)


def normalise(text: str) -> str:
    """Collapse line breaks and emphasis so a re-wrapped or bolded claim still matches."""
    t = re.sub(r"-\s*\n\s*", "-", text)
    t = re.sub(r"[*_`]+", "", t)
    return re.sub(r"\s+", " ", t)


def sentences(text: str) -> list[str]:
    return re.split(r"(?<=[.!?|])\s+", normalise(text))

# Finality described as a current property. A line that also says the
# mechanism is specified / not running / a target is allowed.
FINALITY_CURRENT = [
    re.compile(r"deterministic (bft |checkpoint )?finality", re.I),
    re.compile(r"cannot be reorg", re.I),
    re.compile(r"\birreversib\w*\b[^.]{0,30}\b(finality|finali[sz]ed|blocks?)\b|\b(blocks?|finality|checkpoints?|block hash|state root)\b[^.]{0,40}\birreversib", re.I),
    re.compile(r"finality (in|within|after) ~?\d", re.I),
    re.compile(r"reorg(anization)?s? (that would rewrite|below) (a|the) finali[sz]ed", re.I),
    re.compile(r"finality[- ]aware reorg (protection|rejection)", re.I),
    re.compile(r"finality with committee (bft )?checkpoints", re.I),
    re.compile(r"can ?not ever be reorg|can never be reorg|never (be )?reverted below", re.I),
    re.compile(r"\bfinali[sz]ed (after|at|within) ~?\d", re.I),
    re.compile(r"\bseconds of finality", re.I),
    re.compile(r"\bI4 ✅", re.I),
]
# The qualifier must sit next to the claim (same clause), not anywhere on the line.
FINALITY_QUALIFIERS = re.compile(
    r"specified, not running|is specified|\(specified|not running|not yet running|not wired|target design|"
    r"no production caller|tests today|not in effect|once (checkpoint finality|checkpoints|it) runs?|design:",
    re.I,
)
QUAL_WINDOW = 120
FINDING_ID = re.compile(r"\bPBA-[A-Za-z0-9]+-\d+\b")

STALE_COUNTS = [
    re.compile(r"\b76\+? (contracts )?(are )?(deployed|live)", re.I),
    re.compile(r"\b76\+? deployed contracts|all 76 contracts", re.I),
    re.compile(r"\b27 contracts are deployed", re.I),
]
DEAD_HOSTS = re.compile(r"rpc2\.citrate\.ai|scan\.citrate\.ai|wss?://ws\.citrate\.ai|mirror\.citrate\.ai")
CURL_PIPE_MAIN = re.compile(r"curl[^|\n]*raw\.githubusercontent\.com/[^|\n]*/main/[^|\n]*\|\s*(ba)?sh")
# Money-contract addresses from pre-reroll books; codeless on 40204.
KNOWN_STALE = {
    "0x02f03ac1aaff621d458f403965a3355f720d077b",  # ModelRegistry (old)
    "0x4cba023420a6b0aed33204082d9e29f9a450a9a2",  # WrappedSALT (old)
    "0x6003ad2727bf4253a5c0bd9f0d10713829320b98",  # ComputeMarketplace (old)
    "0xe701d7368dd7ff46c63dfa7fe439f61011ceb6b2",  # LearningPool (old)
    "0xcdb76eb5d32ea31dd9c05095c970b8a44ae89390",  # LiquidStakingPool (old)
    "0x05209fe13d705cfece27c7084f741b65ae45c5c8",  # X402Facilitator (old)
    "0x61e324cf",  # MembershipStakeVault (old, prefix)
    "0x3e0c2b1c",  # CitrateMemberSBT (old, prefix)
    "0x1f73bb47",  # wSALT allow-list entry (old, prefix)
}
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")


def strip_tests(src: str) -> str:
    """Drop every `#[cfg(test)]` item (module or fn), matching braces, so test-only callers do not count."""
    out, i = [], 0
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        if m.start() < i:
            continue
        brace = src.find("{", m.end())
        semi = src.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        depth, j = 0, brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append(src[i:m.start()])
        i = j + 1
    out.append(src[i:])
    return "".join(out)


def production_propose_callers(root: Path) -> list[str]:
    hits = []
    for base in ("node/src", "core/consensus/src"):
        for f in sorted((root / base).rglob("*.rs")):
            if "/tests/" in str(f) or f.name.endswith("_tests.rs"):
                continue
            body = strip_tests(f.read_text(errors="replace"))
            for i, line in enumerate(body.splitlines(), 1):
                code = line.split("//", 1)[0]
                if re.search(r"\.propose\s*\(", code):
                    hits.append(f"{f.relative_to(root)}:{i}")
    return hits


def check(root: Path) -> tuple[list[str], list[str]]:
    errs: list[str] = []
    warns: list[str] = []
    claims = json.loads((root / "verification/claims.json").read_text())["claims"]

    dcf = claims.get("deterministic_checkpoint_finality", {})
    running = bool((dcf.get("value") or {}).get("running", True))
    status = dcf.get("verification_status")
    callers = production_propose_callers(root)
    if (running or status != "specified-not-running") and not callers:
        errs.append(
            "claims.json deterministic_checkpoint_finality asserts a running mechanism "
            f"(running={running}, status={status}) but no non-test code calls .propose( "
            "in node/src or core/consensus/src"
        )
    if callers and not running:
        warns.append(
            f"production .propose( callers exist ({', '.join(callers)}); re-verify and update "
            "deterministic_checkpoint_finality if checkpoints now finalize on the live network"
        )
    finality_running = running and bool(callers)

    if not finality_running:
        cg = json.dumps(claims.get("consensus_ghostdag", {}).get("value", {}))
        if "not running" not in cg:
            errs.append("claims.json consensus_ghostdag.value.finality must say checkpoint finality is not running")
        cl = claims.get("confirmation_latency", {}).get("value", {})
        if cl.get("deterministic_checkpoint_seconds_estimate") is not None:
            errs.append("claims.json confirmation_latency publishes a deterministic finality time while finality is not running")

    snap_path = root / "verification/address-code.snapshot.json"
    book = json.loads((root / "contracts/addresses/40204.json").read_text())
    codeless_addrs: dict[str, str] = {}
    if snap_path.exists():
        snap = json.loads(snap_path.read_text())
        for name in snap.get("codeless", []):
            sec, _, key = name.partition(".")
            addr = (book.get(sec) or {}).get(key) if key else book.get(sec)
            if isinstance(addr, str):
                codeless_addrs[addr.lower()] = name

    for rel in public_docs(root):
        p = root / rel
        if not p.exists():
            continue
        text = p.read_text(errors="replace")
        for sent in sentences(text):
            if not finality_running:
                for rx in FINALITY_CURRENT:
                    m = rx.search(sent)
                    if not m:
                        continue
                    near = sent[max(0, m.start() - QUAL_WINDOW): m.end() + QUAL_WINDOW]
                    if not FINALITY_QUALIFIERS.search(near):
                        errs.append(f"{rel}: finality described as current while it is not running: ...{sent[max(0, m.start() - 50): m.end() + 70]}...")
                    break
            fid = FINDING_ID.search(sent)
            if fid:
                errs.append(f"{rel}: names audit finding {fid.group(0)}; public docs must not describe open findings")
            for rx in STALE_COUNTS:
                if rx.search(sent):
                    errs.append(f"{rel}: stale deployed-contract count (verified: see deployed_contracts): {sent[:120]}")
        for n, line in enumerate(text.splitlines(), 1):
            where = f"{rel}:{n}"
            if DEAD_HOSTS.search(line):
                errs.append(f"{where}: dead host: {line.strip()[:120]}")
            if CURL_PIPE_MAIN.search(line):
                errs.append(f"{where}: pipes a script from mutable main into a shell: {line.strip()[:120]}")
            for a in ADDR.findall(line):
                al = a.lower()
                if al in codeless_addrs:
                    errs.append(f"{where}: {a} is {codeless_addrs[al]}, which has no code on 40204")
                elif any(al.startswith(k) for k in KNOWN_STALE):
                    errs.append(f"{where}: {a} is a known-stale, codeless money-contract address")
    return errs, warns


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    root = Path(ap.parse_args().root)
    errs, warns = check(root)
    for w in warns:
        print(f"[check-claims] WARN: {w}")
    for e in errs:
        print(f"[check-claims] FAIL: {e}", file=sys.stderr)
    if errs:
        return 1
    print("[check-claims] OK: claims.json and public READMEs agree with the code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
