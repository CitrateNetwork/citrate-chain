#!/usr/bin/env python3
"""Keep the RUSTSEC-2026-0387 audit ignore honest (crypto-bigint < 0.7.6).

The advisory is fixed only in crypto-bigint 0.7.6. Here it comes in through
elliptic-curve 0.13 (the k256 / p256 / p384 0.13 line), and no 0.13.x release
accepts crypto-bigint 0.7, so the lockfile cannot move it. The audit step
ignores the advisory, and this check fails CI when the reason for that ignore
stops being true:

1. a crate other than elliptic-curve 0.13.x depends on a crypto-bigint below
   0.7.6 (the ignore does not cover a new user);
2. no crypto-bigint below 0.7.6 is left in Cargo.lock (the ignore is stale:
   delete it, and this check with it);
3. today is after EXPIRES (decide again; do not renew by reflex).

Usage: check_crypto_bigint_users.py [--lock Cargo.lock] [--self-test]
"""
import argparse
import sys
import tomllib
from datetime import date

ADVISORY = "RUSTSEC-2026-0387"
EXPIRES = date(2026, 11, 9)
FIXED = (0, 7, 6)
ALLOWED_USER = "elliptic-curve"
ALLOWED_USER_LINE = (0, 13)


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("-")[0].split("+")[0].split(".")[:3])


def check(lock: dict, today: date) -> list[str]:
    """Return the failures for one parsed Cargo.lock (empty list = pass)."""
    pkgs = lock.get("package", [])
    versions = [p["version"] for p in pkgs if p.get("name") == "crypto-bigint"]
    old = {v for v in versions if vtuple(v) < FIXED}
    errors = []
    if today > EXPIRES:
        errors.append(f"the {ADVISORY} ignore expired on {EXPIRES}: decide again")
    if not old:
        errors.append(
            f"no crypto-bigint below {'.'.join(map(str, FIXED))} in Cargo.lock: "
            f"the {ADVISORY} ignore is stale, remove it and this check"
        )
        return errors
    for p in pkgs:
        for dep in p.get("dependencies", []):
            parts = dep.split()
            if parts[0] != "crypto-bigint":
                continue
            # A bare name means the lock holds exactly one crypto-bigint.
            dv = parts[1] if len(parts) > 1 else (versions[0] if len(versions) == 1 else None)
            if dv is not None and dv not in old:
                continue
            ok = p["name"] == ALLOWED_USER and vtuple(p["version"])[:2] == ALLOWED_USER_LINE
            if not ok:
                errors.append(
                    f"{p['name']} {p['version']} -> crypto-bigint {dv or '?'}: "
                    f"not covered by the {ADVISORY} ignore"
                )
    return errors


def _lock(*pkgs: tuple[str, str, list[str]]) -> dict:
    return {"package": [{"name": n, "version": v, "dependencies": d} for n, v, d in pkgs]}


def self_test() -> None:
    ok_day = date(2026, 10, 25)
    base = [("crypto-bigint", "0.5.5", []), ("elliptic-curve", "0.13.8", ["crypto-bigint"])]
    cases = [
        ("allowed user only", _lock(*base), ok_day, 0),
        ("expired", _lock(*base), date(2026, 11, 10), 1),
        ("new direct user", _lock(*base, ("rsa", "0.9.8", ["crypto-bigint"])), ok_day, 1),
        ("elliptic-curve 0.14 on old bigint",
         _lock(("crypto-bigint", "0.5.5", []), ("elliptic-curve", "0.14.3", ["crypto-bigint"])), ok_day, 1),
        ("stale: only fixed bigint",
         _lock(("crypto-bigint", "0.7.10", []), ("elliptic-curve", "0.14.3", ["crypto-bigint"])), ok_day, 1),
        ("two versions, new user on the fixed one",
         _lock(("crypto-bigint", "0.5.5", []), ("crypto-bigint", "0.7.10", []),
               ("elliptic-curve", "0.13.8", ["crypto-bigint 0.5.5"]),
               ("rsa", "0.10.0", ["crypto-bigint 0.7.10"])), ok_day, 0),
        ("two versions, new user on the old one",
         _lock(("crypto-bigint", "0.5.5", []), ("crypto-bigint", "0.7.10", []),
               ("elliptic-curve", "0.13.8", ["crypto-bigint 0.5.5"]),
               ("rsa", "0.9.8", ["crypto-bigint 0.5.5"])), ok_day, 1),
    ]
    bad = []
    for name, lock, day, want in cases:
        got = len(check(lock, day))
        if got != want:
            bad.append(f"{name}: expected {want} failure(s), got {got}")
    if bad:
        print("self-test FAILED:", *bad, sep="\n  ")
        sys.exit(1)
    print(f"self-test: {len(cases)} cases pass")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default="Cargo.lock")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    with open(args.lock, "rb") as f:
        lock = tomllib.load(f)
    errors = check(lock, date.today())
    if errors:
        print(f"{ADVISORY} ignore check failed:", *errors, sep="\n  ")
        sys.exit(1)
    print(f"{ADVISORY}: crypto-bigint < 0.7.6 only via {ALLOWED_USER} 0.13; ignore expires {EXPIRES}")


if __name__ == "__main__":
    main()
