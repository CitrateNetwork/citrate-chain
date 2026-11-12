#!/usr/bin/env python3
"""stamp_genesis.py: stamp the r1007 block 0 with the ceremony time and re-pin R1007_GENESIS.

Owner 2026-11-11: the r1007 genesis timestamp is set at ceremony time. The ceremony order is

  1. stamp_genesis.py --at <unix seconds> | --now     (sets r1007::GENESIS_TIMESTAMP)
  2. stamp_genesis.py --repin                         (cargo runs the r1007_genesis_hash
                                                       example; R1007_GENESIS takes its value)
  3. build the node binary from that commit, then `ceremony.py check` and `render`
     (render refuses a stamp more than 1 h from the render, GENESIS_STAMP_WINDOW_SECS).

Choosing a time a little ahead (for example 30 minutes) leaves room for the build; producers
wait for the first slot at or after block 0.

  stamp_genesis.py --at 1800000000
  stamp_genesis.py --now [--ahead-minutes 30]
  stamp_genesis.py --repin [--hash 0x...]     (--hash skips cargo; tests and dry runs)
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

CHAIN = Path(__file__).resolve().parents[3]
R1007_RS = Path("core/economics/src/r1007.rs")
HARDENING = Path("core/consensus/src/hardening.rs")
TS_RE = re.compile(r"(pub const GENESIS_TIMESTAMP: u64 = )([0-9_]+)(;)")
PIN_RE = re.compile(r'(pub const R1007_GENESIS: \[u8; 32\] =\s*hex32\(")([0-9a-f]{64})("\);)')
# Plausible ceremony times: after 2026-01-01, before 2100.
MIN_TS, MAX_TS = 1_767_225_600, 4_102_444_800


class StampError(Exception):
    pass


def read_timestamp(root: Path) -> int:
    m = TS_RE.search((root / R1007_RS).read_text())
    if not m:
        raise StampError(f"{R1007_RS}: GENESIS_TIMESTAMP not found")
    return int(m.group(2).replace("_", ""))


def set_timestamp(root: Path, ts: int) -> None:
    if not MIN_TS <= ts < MAX_TS:
        raise StampError(f"{ts} is not a plausible ceremony time (unix seconds)")
    p = root / R1007_RS
    text = p.read_text()
    new, n = TS_RE.subn(lambda m: f"{m.group(1)}{ts}{m.group(3)}", text)
    if n != 1:
        raise StampError(f"{R1007_RS}: expected one GENESIS_TIMESTAMP, found {n}")
    p.write_text(new)


def repin(root: Path, hash_hex: str) -> None:
    h = hash_hex.lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        raise StampError(f"{hash_hex!r} is not a 32-byte hash")
    p = root / HARDENING
    text = p.read_text()
    new, n = PIN_RE.subn(lambda m: f"{m.group(1)}{h}{m.group(3)}", text)
    if n != 1:
        raise StampError(f"{HARDENING}: expected one R1007_GENESIS pin, found {n}")
    p.write_text(new)


def computed_hash(root: Path) -> str:
    r = subprocess.run(["cargo", "run", "-q", "-p", "citrate-economics", "--example", "r1007_genesis_hash"],
                       cwd=root, capture_output=True, text=True)
    m = re.search(r"^R1007_GENESIS=(0x[0-9a-f]{64})$", r.stdout, re.MULTILINE)
    if r.returncode != 0 or not m:
        raise StampError(f"r1007_genesis_hash failed (rc {r.returncode}): {r.stderr[-400:]}")
    return m.group(1)


def main(argv: list[str]) -> int:
    try:
        if "--at" in argv:
            set_timestamp(CHAIN, int(argv[argv.index("--at") + 1]))
        elif "--now" in argv:
            ahead = int(argv[argv.index("--ahead-minutes") + 1]) if "--ahead-minutes" in argv else 0
            set_timestamp(CHAIN, int(time.time()) + 60 * ahead)
        if "--repin" in argv:
            h = argv[argv.index("--hash") + 1] if "--hash" in argv else computed_hash(CHAIN)
            repin(CHAIN, h)
            print(f"R1007_GENESIS={h} (GENESIS_TIMESTAMP={read_timestamp(CHAIN)})")
        else:
            print(f"GENESIS_TIMESTAMP={read_timestamp(CHAIN)}; run --repin next")
        return 0
    except (StampError, ValueError, IndexError) as e:
        print(f"stamp_genesis: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
