#!/usr/bin/env python3
"""Keep the RUSTSEC-2026-0387 audit ignore honest (crypto-bigint < 0.7.6).

The advisory is fixed only in crypto-bigint 0.7.6. Here it comes in through
elliptic-curve 0.13 (the k256 / p256 / p384 0.13 line), and no 0.13.x release
accepts crypto-bigint 0.7, so the lockfile cannot move it. The audit step
ignores the advisory, and this check fails CI when the reason for that ignore
stops being true, in ANY tracked Cargo.lock (not only the root one):

1. a crate other than elliptic-curve 0.13.x depends on a crypto-bigint below
   0.7.6 (the ignore does not cover a new user);
2. no crypto-bigint below 0.7.6 is left in any tracked Cargo.lock (the ignore
   is stale: delete it, and this check with it);
3. today is after EXPIRES (decide again; do not renew by reflex).

EXPIRES is the owner-approved window (2027-01-31): the upstream curve stack
(alloy / revm / openmls) does not move to the patched line before then.

Usage: check_crypto_bigint_users.py [--lock PATH]... [--self-test]
       (no --lock: every Cargo.lock tracked by git in this repository)
"""
import argparse
import os
import subprocess
import sys
import tempfile
import tomllib
from datetime import date, timedelta

ADVISORY = "RUSTSEC-2026-0387"
EXPIRES = date(2026, 11, 9)
FIXED = (0, 7, 6)
ALLOWED_USER = "elliptic-curve"
ALLOWED_USER_LINE = (0, 13)


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("-")[0].split("+")[0].split(".")[:3])


def lock_users(lock: dict) -> tuple[list[str], bool]:
    """For one parsed Cargo.lock: (uncovered users, any crypto-bigint < FIXED)."""
    pkgs = lock.get("package", [])
    versions = [p["version"] for p in pkgs if p.get("name") == "crypto-bigint"]
    old = {v for v in versions if vtuple(v) < FIXED}
    errors = []
    if not old:
        return errors, False
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
    return errors, True


def check_all(locks: dict[str, dict], today: date) -> list[str]:
    """Return the failures across every lockfile (path -> parsed lock); empty = pass."""
    # RED STUB: today's behaviour, only the root Cargo.lock is read.
    locks = {k: v for k, v in locks.items() if k == "Cargo.lock"}
    errors = []
    if today > EXPIRES:
        errors.append(f"the {ADVISORY} ignore expired on {EXPIRES}: decide again")
    any_old = False
    for path, lock in locks.items():
        users, has_old = lock_users(lock)
        any_old |= has_old
        errors.extend(f"{path}: {u}" for u in users)
    if not any_old:
        errors.append(
            f"no crypto-bigint below {'.'.join(map(str, FIXED))} in any tracked Cargo.lock: "
            f"the {ADVISORY} ignore is stale, remove it and this check"
        )
    return errors


def check(lock: dict, today: date) -> list[str]:
    """Single-lockfile form of check_all."""
    return check_all({"Cargo.lock": lock}, today)


def tracked_lockfiles(start: str = ".") -> tuple[str, list[str]]:
    """(repo root, every Cargo.lock git tracks, relative to the root). Fails closed."""
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=start,
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "Cargo.lock", "*/Cargo.lock"], cwd=root,
        check=True, capture_output=True, text=True,
    ).stdout
    paths = sorted(p for p in out.split("\0") if p)
    if not paths:
        sys.exit(f"{ADVISORY} ignore check: no tracked Cargo.lock under {root}")
    return root, paths


def load(paths: list[str], root: str = ".") -> dict[str, dict]:
    locks = {}
    for p in paths:
        with open(os.path.join(root, p), "rb") as f:
            locks[p] = tomllib.load(f)
    return locks


def _lock(*pkgs: tuple[str, str, list[str]]) -> dict:
    return {"package": [{"name": n, "version": v, "dependencies": d} for n, v, d in pkgs]}


def _lock_text(lock: dict) -> str:
    out = ["version = 3", ""]
    for p in lock["package"]:
        out += ["[[package]]", f'name = "{p["name"]}"', f'version = "{p["version"]}"']
        if p["dependencies"]:
            out.append("dependencies = [" + ", ".join(f'"{d}"' for d in p["dependencies"]) + "]")
        out.append("")
    return "\n".join(out)


def _repo_case(files: dict[str, dict]) -> list[str]:
    """Run discovery + check against a throwaway git repo holding `files`."""
    with tempfile.TemporaryDirectory(prefix="cb0387-selftest-") as d:
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run(["git", "init", "-q", d], check=True, env=env)
        for rel, lock in files.items():
            os.makedirs(os.path.join(d, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(d, rel), "w") as f:
                f.write(_lock_text(lock))
        subprocess.run(["git", "add", "-A"], cwd=d, check=True, env=env)
        root, paths = tracked_lockfiles(d)
        return check_all(load(paths, root), EXPIRES)


def self_test() -> None:
    ok_day = EXPIRES
    base = [("crypto-bigint", "0.5.5", []), ("elliptic-curve", "0.13.8", ["crypto-bigint"])]
    rsa_old = [("crypto-bigint", "0.5.5", []), ("rsa", "0.9.8", ["crypto-bigint"])]
    fixed_only = _lock(("crypto-bigint", "0.7.10", []), ("elliptic-curve", "0.14.3", ["crypto-bigint"]))
    no_bigint = _lock(("serde", "1.0.228", []))
    cases = [
        ("allowed user only", _lock(*base), ok_day, 0),
        ("owner window: 2027-01-31 still inside", _lock(*base), date(2027, 1, 31), 0),
        ("owner window: 2027-02-01 expired", _lock(*base), date(2027, 2, 1), 1),
        ("expired", _lock(*base), EXPIRES + timedelta(days=1), 1),
        ("new direct user", _lock(*base, ("rsa", "0.9.8", ["crypto-bigint"])), ok_day, 1),
        ("elliptic-curve 0.14 on old bigint",
         _lock(("crypto-bigint", "0.5.5", []), ("elliptic-curve", "0.14.3", ["crypto-bigint"])), ok_day, 1),
        ("unpatched 0.7.x below the floor",
         _lock(("crypto-bigint", "0.7.5", []), ("rsa", "0.10.0", ["crypto-bigint"])), ok_day, 1),
        ("stale: only fixed bigint", fixed_only, ok_day, 1),
        ("two versions, new user on the fixed one",
         _lock(("crypto-bigint", "0.5.5", []), ("crypto-bigint", "0.7.10", []),
               ("elliptic-curve", "0.13.8", ["crypto-bigint 0.5.5"]),
               ("rsa", "0.10.0", ["crypto-bigint 0.7.10"])), ok_day, 0),
        ("two versions, new user on the old one",
         _lock(("crypto-bigint", "0.5.5", []), ("crypto-bigint", "0.7.10", []),
               ("elliptic-curve", "0.13.8", ["crypto-bigint 0.5.5"]),
               ("rsa", "0.9.8", ["crypto-bigint 0.5.5"])), ok_day, 1),
    ]
    multi = [
        ("every lockfile: new user in a nested lock",
         {"Cargo.lock": _lock(*base), "tools/x/Cargo.lock": _lock(*rsa_old)}, 1),
        ("every lockfile: allowed in all",
         {"Cargo.lock": _lock(*base), "tools/x/Cargo.lock": _lock(*base)}, 0),
        ("stale is repo-wide: old bigint only in a nested lock",
         {"Cargo.lock": no_bigint, "tools/x/Cargo.lock": _lock(*base)}, 0),
        ("stale is repo-wide: no old bigint in any lock",
         {"Cargo.lock": fixed_only, "tools/x/Cargo.lock": no_bigint}, 1),
    ]
    bad = []
    for name, lock, day, want in cases:
        got = len(check(lock, day))
        if got != want:
            bad.append(f"{name}: expected {want} failure(s), got {got}")
    for name, locks, want in multi:
        got = check_all(locks, ok_day)
        if len(got) != want:
            bad.append(f"{name}: expected {want} failure(s), got {got}")
    # End to end: discovery must find a nested tracked lockfile in a real git repo.
    got = _repo_case({"Cargo.lock": _lock(*base), "tools/x/Cargo.lock": _lock(*rsa_old)})
    if len(got) != 1 or not got[0].startswith("tools/x/Cargo.lock:"):
        bad.append(f"git discovery of a nested Cargo.lock: expected 1 failure in tools/x, got {got}")
    if bad:
        print("self-test FAILED:", *bad, sep="\n  ")
        sys.exit(1)
    print(f"self-test: {len(cases) + len(multi) + 1} cases pass")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", action="append", help="repeatable; default: every tracked Cargo.lock")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if args.lock:
        locks = load(args.lock)
    else:
        root, paths = tracked_lockfiles()
        locks = load(paths, root)
    errors = check_all(locks, date.today())
    if errors:
        print(f"{ADVISORY} ignore check failed:", *errors, sep="\n  ")
        sys.exit(1)
    print(f"{ADVISORY}: crypto-bigint < 0.7.6 only via {ALLOWED_USER} 0.13 "
          f"across {len(locks)} lockfile(s); ignore expires {EXPIRES}")


if __name__ == "__main__":
    main()
