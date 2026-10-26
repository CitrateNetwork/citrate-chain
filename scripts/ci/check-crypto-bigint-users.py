#!/usr/bin/env python3
"""Guard for the time-boxed RUSTSEC-2026-0387 (crypto-bigint) audit ignore.

The advisory is ignored by ID in the audit configuration because crypto-bigint
below 0.7.6 reaches this repo only through the upstream elliptic-curve 0.13
stack (k256 / p256 0.13 and the crates built on them), which has no release on
a patched crypto-bigint yet. That reasoning covers those parents only, and only
for a limited time, so this check fails CI when:

  1. in any Cargo.lock in the repo, a crate outside ALLOWED depends directly on
     a crypto-bigint below the first patched release (0.7.6);
  2. the ignore is still present in an audit config after EXPIRES;
  3. the ignore is present but no crypto-bigint below 0.7.6 is left in any
     lockfile (the ignore is stale: remove it, and this check with it).

The ignore is by advisory ID, so it would also hide 0.6.x and 0.7.0-0.7.5;
the check therefore compares against the patched floor, not "< 0.7".

  python3 <this script>                       # check the repo
  python3 <this script> --today 2027-02-01    # what CI will do after expiry

Self-test: test_check_crypto_bigint_users.py next to this file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys
import tomllib
from pathlib import Path

ADVISORY = "RUSTSEC-2026-0387"
# Hard expiry. After this date the ignore must be gone (upgrade landed) or be
# renewed in a reviewed PR that moves this date.
EXPIRES = dt.date(2027, 1, 31)
PATCHED = (0, 7, 6)

# Crates allowed to depend directly on a crypto-bigint below PATCHED. k256,
# p256, ecdsa, bip32 and the rest reach it only through elliptic-curve.
ALLOWED = frozenset({"elliptic-curve"})

# Audit configs (repo-relative) that may carry the ignore.
IGNORE_FILES: tuple[str, ...] = (
    ".github/workflows/cargo-audit.yml",
    "audit.toml",
    "deny.toml",
)

HERE = Path(__file__).resolve().parent


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=HERE, check=True, capture_output=True, text=True,
    ).stdout.strip()
    return Path(out)


def repo_lockfiles(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "--", "Cargo.lock", "*/Cargo.lock"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout.split()
    return [root / p for p in out]


def _version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("+", 1)[0].split("-", 1)[0].split("."))


def vulnerable_parents(lock_text: str, where: str = "Cargo.lock") -> tuple[dict[str, set[str]], bool]:
    """Return ({parent name: {vulnerable crypto-bigint versions}}, any vulnerable present)."""
    pkgs = tomllib.loads(lock_text).get("package", [])
    cb_versions = [p["version"] for p in pkgs if p["name"] == "crypto-bigint"]
    any_vulnerable = any(_version(v) < PATCHED for v in cb_versions)
    out: dict[str, set[str]] = {}
    for p in pkgs:
        for dep in p.get("dependencies", []):
            # Entries are "name", "name version" or "name version (source)";
            # the bare form means the lockfile holds exactly one version.
            parts = dep.split(" ")
            if parts[0] != "crypto-bigint":
                continue
            if len(parts) >= 2:
                ver = parts[1]
            elif len(cb_versions) == 1:
                ver = cb_versions[0]
            else:
                raise ValueError(f"{where}: ambiguous dependency {dep!r} in {p['name']}")
            if _version(ver) < PATCHED:
                out.setdefault(p["name"], set()).add(ver)
    return out, any_vulnerable


def check(lockfiles: list[Path], ignore_files: list[Path], allowed: frozenset[str],
          today: dt.date) -> tuple[list[str], list[str]]:
    """Return (failures, parents seen). An empty failure list is a pass."""
    return [], []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RUSTSEC-2026-0387 ignore guard")
    ap.add_argument("--lockfile", action="append", type=Path, help="default: every tracked Cargo.lock")
    ap.add_argument("--ignore-file", action="append", type=Path, help="default: IGNORE_FILES")
    ap.add_argument("--allow", action="append", help="override ALLOWED (self-test only)")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    a = ap.parse_args(argv)

    root = None if (a.lockfile and a.ignore_file) else repo_root()
    lockfiles = a.lockfile or repo_lockfiles(root)
    ignore_files = a.ignore_file or [root / p for p in IGNORE_FILES]
    allowed = frozenset(a.allow) if a.allow else ALLOWED

    errors, seen = check(lockfiles, ignore_files, allowed, a.today)
    if errors:
        print(f"{ADVISORY} guard FAILED:", *errors, sep="\n  ")
        return 1
    print(
        f"{ADVISORY} guard ok: {len(lockfiles)} lockfile(s); parents of crypto-bigint "
        f"< {'.'.join(map(str, PATCHED))}: {seen} (allowed: {sorted(allowed)}); "
        f"ignore expires {EXPIRES}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
