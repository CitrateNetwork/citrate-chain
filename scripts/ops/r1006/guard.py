#!/usr/bin/env python3
"""Fail-closed checks for scripts/ops/r1006_bringup.sh: which hosts it may reach, which
genesis it may run, and what host output it may keep.

Hosts. The r1006 bring-up is approved for exactly the seven producers below and, for
the `build` step only, the one build host. The table is compiled in here (reviewed in
the PR), not read from the editable inventory: an inventory may list a subset of these
producers, but a host whose name/IP pair is not in the table is refused before any
connection. The build host is never a producer: it may only run the `build` step, never
a node or key action. Before a real ssh step the targeted pairs are cross-checked live
(read-only) with `doctl compute droplet list`; a missing or failing doctl refuses.

Genesis. A fill, a profile or a probe whose block 0 is a release network's (the
r1005 testnet, team testnet, mainnet: core/consensus/src/hardening.rs RELEASE_GENESIS)
is refused, and so is any block 0 other than the r1006 genesis compiled into the
recorded build (`citrate consensus --json` key `r1006_genesis`). A build that reports no
compiled r1006 genesis is refused (fail closed). The genesis must be selected by the
compiled `r1006` profile; a genesis file is refused, because the node never reads one.

Output. `relay` runs one host-agent call, holds its stdout and stderr in memory and
checks them BEFORE anything is printed or written. A key or password pattern in either
stream fails the call (rc 3) and the output is dropped unseen. In `--identity-out`
mode stdout must be exactly one public host identity; only the re-serialised, checked
object is written (0644 in the 0700 state dir), and on any refusal nothing is written.

  guard.py hosts                                    print the pinned table (name ip role)
  guard.py check-inventory --inventory F            names, IPs and the allowlist
  guard.py live-check --names a,b [--build]         doctl cross-check (read-only)
  guard.py check-genesis --fill F --build B         fill vs the release pins and the build
  guard.py check-hash --hash H --build B            one block-0 hash vs the build
  guard.py relay --host H [--identity-out F] -- CMD...   (stdin is passed to CMD)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect  # noqa: E402

# ---- hosts ---------------------------------------------------------------------------
# The r1006 producer droplets (Citrate Inc. DigitalOcean, tag citrate-producer).
PRODUCERS: dict[str, str] = {
    "citrate-prod-1": "206.189.35.49",
    "citrate-prod-2": "174.138.78.16",
    "citrate-prod-3": "137.184.174.123",
    "citrate-prod-4": "134.209.61.197",
    "citrate-prod-5": "68.183.40.230",
    "citrate-prod-6": "159.223.14.97",
    "citrate-prod-7": "207.154.238.90",
}
PRODUCER_TAG = "citrate-producer"
# Build-only host: `build` may ssh here; no node, key or genesis action ever does.
BUILD_HOST = ("citrate-core-linux-build", "167.99.155.183")

# ---- genesis -------------------------------------------------------------------------
# Mirror of core/consensus/src/hardening.rs RELEASE_GENESIS (a test keeps them equal).
RELEASE_GENESIS: dict[str, str] = {
    "0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1": "r1005 testnet (testnet_beta)",
    "0x90044175c36a6491309d769bd0fa684afbf7b90b64136446db8e2e6ff0927553": "team_testnet",
    "0xba93d716ab8b005f1d7e61d369a65fc1d6a358d6a479e11b640815c74388ab01": "mainnet",
}
R1006_PROFILE = "r1006"
B32 = re.compile(r"^0x[0-9a-f]{64}$")

# ---- output patterns -----------------------------------------------------------------
# In either stream: keystore fields and PEM key blocks.
SECRET_ANY = [
    re.compile(rb'"(ciphertext|cipherparams|kdfparams|crypto)"\s*:', re.I),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"\b(seed|private[_ ]?key|secret[_ ]?key|password)\s*[:=]\s*\S", re.I),
]
# In stderr only: a bare 32-byte hex value (a raw key or the keystore password; the
# agent shortens every hash it prints to stderr).
HEX32 = re.compile(rb"(?<![0-9a-fA-F])(0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
# In either stream: control bytes, which text output never carries (a raw key file).
CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def not_text(data: bytes) -> bool:
    """Bytes that are not plain UTF-8 text: what a raw key file looks like."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return bool(CONTROL.search(data))


class GuardError(Exception):
    pass


def load_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise GuardError(f"cannot read {p}: {e}") from None
    if not isinstance(d, dict):
        raise GuardError(f"{p} is not a JSON object")
    return d


def check_inventory(inv: dict) -> list[str]:
    """Problems with an inventory (empty = usable). Names are checked first, so nothing
    downstream ever splices an unchecked name into code or a path."""
    out = []
    transport = inv.get("transport", "ssh")
    if transport not in ("ssh", "local"):
        return [f"transport {transport!r} is not ssh or local"]
    hosts = inv.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        return ["no hosts"]
    seen = set()
    for h in hosts:
        name, ip = str(h.get("name", "")), str(h.get("ip", ""))
        if not collect.NAME_RE.match(name):
            out.append(f"bad host name {name!r}")
            continue
        if name in seen:
            out.append(f"{name} listed twice")
        seen.add(name)
        m = collect.IP_RE.match(ip)
        if not m or any(int(x) > 255 for x in m.groups()):
            out.append(f"{name}: {ip!r} is not an IPv4 address")
            continue
        if transport == "ssh":
            if (name, ip) == BUILD_HOST or name == BUILD_HOST[0] or ip == BUILD_HOST[1]:
                out.append(f"{name} ({ip}) is the build host: it runs `build` only, never a node or key action")
            elif PRODUCERS.get(name) != ip:
                out.append(f"{name} ({ip}) is not an approved r1006 producer (allowlist: citrate-prod-1..7 at "
                           f"their pinned IPs)")
            elif ip in [PRODUCERS[n] for n in PRODUCERS if n != name]:
                out.append(f"{name}: {ip} is another producer's address")
    if transport == "ssh":
        b = inv.get("build_host")
        if b is not None and (str(b.get("name")), str(b.get("ip"))) != BUILD_HOST:
            out.append(f"build_host {b.get('name')!r} ({b.get('ip')!r}) is not the approved build host "
                       f"{BUILD_HOST[0]} ({BUILD_HOST[1]})")
    return out


def doctl_pairs(args: list[str]) -> set[tuple[str, str]]:
    doctl = os.environ.get("DOCTL", "doctl")
    try:
        r = subprocess.run([doctl, "compute", "droplet", "list", *args, "--format", "Name,PublicIPv4", "--no-header"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GuardError(f"live cross-check: doctl failed ({e}); refusing") from None
    if r.returncode != 0:
        raise GuardError(f"live cross-check: doctl exited {r.returncode}; refusing")
    pairs = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pairs.add((parts[0], parts[1]))
    return pairs


def live_check(names: list[str], build: bool) -> None:
    if build:
        live = doctl_pairs([])
        if BUILD_HOST not in live:
            raise GuardError(f"live cross-check: {BUILD_HOST[0]} is not at {BUILD_HOST[1]} in the account; refusing")
        return
    live = doctl_pairs(["--tag-name", PRODUCER_TAG])
    for n in names:
        if n not in PRODUCERS:
            raise GuardError(f"{n} is not an approved r1006 producer")
        if (n, PRODUCERS[n]) not in live:
            raise GuardError(f"live cross-check: {n} is not tagged {PRODUCER_TAG} at {PRODUCERS[n]}; refusing")
        other = {ip for (nm, ip) in live if nm == n} - {PRODUCERS[n]}
        if other:
            raise GuardError(f"live cross-check: {n} also has address(es) {', '.join(sorted(other))}; refusing")


def build_r1006_genesis(build: dict) -> str:
    g = str(build.get("r1006_genesis") or "").lower()
    if not B32.match(g):
        raise GuardError("the recorded build compiles no r1006 genesis (`citrate consensus --json` has no "
                         "r1006_genesis): a node built from it cannot select the r1006 profile. Refusing; "
                         "build a release with the r1006 genesis.")
    if g in RELEASE_GENESIS:
        raise GuardError(f"the recorded build's r1006 genesis {g} is the {RELEASE_GENESIS[g]} genesis; refusing")
    return g


def check_hash(h: str, build: dict) -> list[str]:
    h = str(h).lower()
    if not B32.match(h):
        return [f"{h!r} is not a 32-byte block hash"]
    if h in RELEASE_GENESIS:
        return [f"block 0 {h} is the {RELEASE_GENESIS[h]} genesis: never run it from this bring-up"]
    want = build_r1006_genesis(build)
    if h != want:
        return [f"block 0 {h} is not the r1006 genesis compiled into the recorded build ({want})"]
    return []


def check_genesis(fill: dict, build: dict) -> list[str]:
    out = []
    p = fill.get("genesis_profile")
    if p != R1006_PROFILE:
        out.append(f"genesis_profile is {p!r}: the hosts must select the compiled {R1006_PROFILE!r} profile")
    if fill.get("genesis_file"):
        out.append("genesis_file is set: the node never reads a genesis file; the genesis must be the "
                   "compiled r1006 profile")
    try:
        out += check_hash(str(fill.get("genesis_hash", "")), build)
    except GuardError as e:
        out.append(str(e))
    return out


def find_leak(stdout: bytes, stderr: bytes) -> str | None:
    """Which stream matched a key/password pattern (never the match itself)."""
    for name, data in (("stdout", stdout), ("stderr", stderr)):
        if any(rx.search(data) for rx in SECRET_ANY):
            return name
    if HEX32.search(stderr) or not_text(stderr):
        return "stderr"
    if not_text(stdout):
        return "stdout"
    return None


def relay(host: str, cmd: list[str], identity_out: Path | None) -> int:
    stdin = sys.stdin.buffer.read()
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"r1006: {host}: agent call failed to run ({type(e).__name__})", file=sys.stderr)
        return 2
    leak = find_leak(r.stdout, r.stderr)
    if leak:
        # Dropped unseen: neither stream is printed, logged or written.
        print(f"r1006: {host}: agent output WITHHELD: its {leak} matched a key/password pattern; "
              f"the step fails and nothing was kept", file=sys.stderr)
        return 3
    if identity_out is not None:
        if r.returncode != 0:
            sys.stderr.write(r.stderr.decode())
            print(f"r1006: {host}: key step failed (rc={r.returncode}); nothing written", file=sys.stderr)
            return r.returncode or 2
        try:
            d = collect.check_identity(host, r.stdout.decode().strip())
        except (collect.CollectError, UnicodeDecodeError) as e:
            msg = str(e) if isinstance(e, collect.CollectError) else "not text"
            # The reason names a field or a shape, never the value.
            print(f"r1006: {host}: public identity refused ({msg.split(':', 1)[-1].strip()}); nothing written",
                  file=sys.stderr)
            return 2
        body = json.dumps({k: d[k] for k in collect.FIELDS}, indent=2) + "\n"
        identity_out.parent.mkdir(parents=True, exist_ok=True)
        tmp = identity_out.with_name(f".{identity_out.name}.{os.getpid()}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(body)
            os.replace(tmp, identity_out)
        finally:
            if tmp.exists():
                tmp.unlink()
        sys.stderr.write(r.stderr.decode())
        return 0
    sys.stdout.write(r.stdout.decode())
    sys.stdout.flush()
    sys.stderr.write(r.stderr.decode())
    return r.returncode


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hosts")
    a = sub.add_parser("check-inventory")
    a.add_argument("--inventory", required=True, type=Path)
    a = sub.add_parser("live-check")
    a.add_argument("--names", default="")
    a.add_argument("--build", action="store_true")
    a = sub.add_parser("check-genesis")
    a.add_argument("--fill", required=True, type=Path)
    a.add_argument("--build", required=True, type=Path)
    a = sub.add_parser("check-hash")
    a.add_argument("--hash", required=True)
    a.add_argument("--build", required=True, type=Path)
    a = sub.add_parser("relay")
    a.add_argument("--host", required=True)
    a.add_argument("--identity-out", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "hosts":
            for n, ip in PRODUCERS.items():
                print(n, ip, "producer")
            print(BUILD_HOST[0], BUILD_HOST[1], "build")
        elif a.cmd == "check-inventory":
            probs = check_inventory(load_json(a.inventory))
            for p in probs:
                print(f"REFUSED  {p}", file=sys.stderr)
            if probs:
                return 2
        elif a.cmd == "live-check":
            live_check([n for n in a.names.split(",") if n], a.build)
        elif a.cmd in ("check-genesis", "check-hash"):
            build = load_json(a.build)
            probs = check_genesis(load_json(a.fill), build) if a.cmd == "check-genesis" else check_hash(a.hash, build)
            for p in probs:
                print(f"REFUSED  {p}", file=sys.stderr)
            if probs:
                return 2
        elif a.cmd == "relay":
            if not cmd:
                raise GuardError("relay needs -- CMD")
            return relay(a.host, cmd, a.identity_out)
        return 0
    except GuardError as e:
        print(f"REFUSED  {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
