#!/usr/bin/env python3
"""Curve-line tripwire: every Cargo.lock in this repo stays on the
elliptic-curve 0.14 line.

WHY THIS EXISTS
  RUSTSEC-2026-0387 (crypto-bigint < 0.7.6) has no fix on the 0.5 line, and
  every 0.13.x curve crate (k256, p256, p384 through elliptic-curve 0.13)
  requires crypto-bigint ^0.5. The only exit is the 0.14 curve line. Once a
  repo has moved, a single new dependency that still needs k256 0.13 would
  quietly bring the advisory back through the lockfile. This gate fails on
  that, in every lockfile (the workspace plus the standalone fuzz, load, bench
  and federated workspaces), without needing a toolchain.

USAGE
  scripts/ci/check_curve_line.py              scan every Cargo.lock in the repo
  scripts/ci/check_curve_line.py --self-test  prove the scanner catches each case
"""

from __future__ import annotations

import pathlib
import sys
import tomllib

# Minimum allowed version per crate. Anything older is the 0.13 curve line
# (or the crypto-bigint the advisory names).
FLOORS: dict[str, tuple[int, int, int]] = {
    "elliptic-curve": (0, 14, 0),
    "k256": (0, 14, 0),
    "p256": (0, 14, 0),
    "p384": (0, 14, 0),
    "ecdsa": (0, 17, 0),
    "primeorder": (0, 14, 0),
    "crypto-bigint": (0, 7, 6),
}

SKIP_DIRS = {"target", ".git", "node_modules"}


def parse_version(v: str) -> tuple[int, int, int]:
    core = v.split("+", 1)[0].split("-", 1)[0]
    parts = (core.split(".") + ["0", "0"])[:3]
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def violations(lock_text: str) -> list[str]:
    data = tomllib.loads(lock_text)
    found = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version", "0.0.0")
        floor = FLOORS.get(name)
        if floor is not None and parse_version(version) < floor:
            want = ".".join(map(str, floor))
            found.append(f"{name} {version} (needs >= {want})")
    return found


def lockfiles(root: pathlib.Path) -> list[pathlib.Path]:
    out = []
    for path in sorted(root.rglob("Cargo.lock")):
        if not SKIP_DIRS.intersection(path.relative_to(root).parts):
            out.append(path)
    return out


def scan(root: pathlib.Path) -> int:
    bad = 0
    files = lockfiles(root)
    for path in files:
        for v in violations(path.read_text()):
            print(f"FAIL {path.relative_to(root)}: {v}")
            bad += 1
    if bad:
        print(
            f"\n{bad} lockfile entr{'y' if bad == 1 else 'ies'} below the elliptic-curve 0.14 line. "
            "A dependency that needs the 0.13 curve crates brings RUSTSEC-2026-0387 back; "
            "move it to the 0.14 line (see scripts/ci/check_curve_line.py)."
        )
        return 1
    print(f"ok: {len(files)} lockfiles on the elliptic-curve 0.14 line")
    return 0


def lock(*pkgs: tuple[str, str]) -> str:
    return "version = 4\n" + "".join(
        f'\n[[package]]\nname = "{n}"\nversion = "{v}"\n' for n, v in pkgs
    )


def self_test() -> int:
    cases = [
        ("clean 0.14 line", lock(("k256", "0.14.0"), ("ecdsa", "0.17.0"), ("crypto-bigint", "0.7.10")), 0),
        ("k256 0.13", lock(("k256", "0.13.4")), 1),
        ("p256 0.13", lock(("p256", "0.13.2")), 1),
        ("p384 0.13", lock(("p384", "0.13.1")), 1),
        ("ecdsa 0.16", lock(("ecdsa", "0.16.9")), 1),
        ("elliptic-curve 0.13", lock(("elliptic-curve", "0.13.8")), 1),
        ("primeorder 0.13", lock(("primeorder", "0.13.6")), 1),
        ("crypto-bigint 0.5", lock(("crypto-bigint", "0.5.5")), 1),
        ("crypto-bigint 0.7.5", lock(("crypto-bigint", "0.7.5")), 1),
        ("pre-release of 0.14 is still 0.14", lock(("k256", "0.14.0-rc.15")), 0),
        ("unrelated crate", lock(("sha2", "0.10.9")), 0),
        ("two versions side by side", lock(("k256", "0.14.0"), ("k256", "0.13.4")), 1),
    ]
    failed = 0
    for name, text, want in cases:
        got = len(violations(text))
        if got != want:
            print(f"SELF-TEST FAIL {name}: {got} violations, want {want}")
            failed += 1
    if failed:
        return 1
    print(f"self-test ok: {len(cases)} cases")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = pathlib.Path(__file__).resolve().parents[2]
    return scan(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
