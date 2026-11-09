#!/usr/bin/env python3
"""Producer host preflight. Read-only: it inspects the host and changes nothing.

  sudo python3 preflight.py --profile 40204-r1005 --data-dir /var/lib/citrate/data
  sudo python3 preflight.py --profile 40204-r1005 --binary /usr/local/bin/citrate-node \\
      --expect-sha256 <from the release's .sha256> --expect-fingerprint 0x...
  python3 preflight.py --profile 40204-r1005 --dry-run     # list the checks, run nothing

Run it as root so it can read sshd and firewall state; as another user those checks
report UNKNOWN. Key files are checked by stat only (owner, mode, size), never read.

Exit status: 0 no FAIL; 1 at least one FAIL. WARN and UNKNOWN never fail the run,
but every WARN is a runbook item to fix or to explain to the chain team.
Thresholds are in THRESHOLDS below and in docs/ops/PRODUCER_OPERATOR_RUNBOOK.md §1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import producerlib as pl  # noqa: E402

THRESHOLDS = {
    "min_cpus": 4,
    "min_mem_gib": 8,
    "rec_mem_gib": 16,
    "min_disk_free_gib": 100,
    "max_disk_used_pct": 80,
}
SUPPORTED_ARCH = {"x86_64", "aarch64"}


@dataclass
class Host:
    """Everything the checks read, so tests can point it at a fake root."""

    root: Path = Path("/")
    run: Callable[[list[str]], tuple[int, str]] = field(default=None)  # type: ignore[assignment]
    cpu_count: Callable[[], int] = field(default=lambda: os.cpu_count() or 0)
    machine: Callable[[], str] = field(default=platform.machine)
    is_root: Callable[[], bool] = field(default=lambda: os.geteuid() == 0)

    def __post_init__(self) -> None:
        if self.run is None:
            self.run = _run

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def read(self, p: str) -> str | None:
        try:
            return self.path(p).read_text(errors="replace")
        except OSError:
            return None


def _run(cmd: list[str]) -> tuple[int, str]:
    if shutil.which(cmd[0]) is None:
        return 127, f"{cmd[0]} not installed"
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 126, str(e)
    return cp.returncode, (cp.stdout + cp.stderr)


class Report:
    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def add(self, level: str, check: str, msg: str) -> None:
        self.rows.append({"level": level, "check": check, "detail": msg})

    @property
    def failed(self) -> bool:
        return any(r["level"] == "FAIL" for r in self.rows)


# ─────────────────────────────────────────────────────────────────────────────
# Checks. Each takes (host, args, report).
# ─────────────────────────────────────────────────────────────────────────────


def check_os(h: Host, a: argparse.Namespace, r: Report) -> None:
    arch = h.machine()
    if arch in SUPPORTED_ARCH:
        r.add("PASS", "arch", f"{arch} (release builds: x86_64, aarch64 Linux)")
    else:
        r.add("FAIL", "arch", f"{arch}: no Linux release artifact for this architecture")
    osr = h.read("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', osr, re.M)
    name = m.group(1) if m else "unknown"
    if re.search(r"^ID=ubuntu", osr, re.M) and re.search(r'^VERSION_ID="?(22\.04|24\.04)', osr, re.M):
        r.add("PASS", "os", name)
    else:
        r.add("WARN", "os", f"{name}: the runbook is written for Ubuntu 22.04/24.04 LTS")


def check_cpu_mem(h: Host, a: argparse.Namespace, r: Report) -> None:
    n = h.cpu_count()
    lvl = "PASS" if n >= THRESHOLDS["min_cpus"] else "FAIL"
    r.add(lvl, "cpu", f"{n} CPUs (minimum {THRESHOLDS['min_cpus']})")
    mi = h.read("/proc/meminfo") or ""
    m = re.search(r"^MemTotal:\s+(\d+) kB", mi, re.M)
    if not m:
        r.add("UNKNOWN", "memory", "/proc/meminfo unreadable")
        return
    gib = int(m.group(1)) / (1024 * 1024)
    if gib < THRESHOLDS["min_mem_gib"] * 0.95:
        r.add("FAIL", "memory", f"{gib:.1f} GiB (minimum {THRESHOLDS['min_mem_gib']})")
    elif gib < THRESHOLDS["rec_mem_gib"] * 0.95:
        r.add("WARN", "memory", f"{gib:.1f} GiB (recommended {THRESHOLDS['rec_mem_gib']}; replays and rebuilds peak higher)")
    else:
        r.add("PASS", "memory", f"{gib:.1f} GiB")


def check_disk(h: Host, a: argparse.Namespace, r: Report) -> None:
    d = h.path(a.data_dir)
    probe = d
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        st = os.statvfs(probe)
    except OSError as e:
        r.add("UNKNOWN", "disk", f"statvfs {probe}: {e}")
        return
    free = st.f_bavail * st.f_frsize / 2**30
    total = st.f_blocks * st.f_frsize / 2**30
    used_pct = 100 * (1 - st.f_bavail / st.f_blocks) if st.f_blocks else 100
    if free < THRESHOLDS["min_disk_free_gib"]:
        r.add("FAIL", "disk", f"{free:.0f} GiB free on {probe} (minimum {THRESHOLDS['min_disk_free_gib']})")
    elif used_pct > THRESHOLDS["max_disk_used_pct"]:
        r.add("WARN", "disk", f"{used_pct:.0f}% used of {total:.0f} GiB (alarm at {THRESHOLDS['max_disk_used_pct']}%)")
    else:
        r.add("PASS", "disk", f"{free:.0f} GiB free of {total:.0f} GiB on {probe}")
    mounts = h.read("/proc/mounts") or ""
    best = ("", "")
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) >= 3 and str(a.data_dir).startswith(parts[1]) and len(parts[1]) > len(best[0]):
            best = (parts[1], parts[2])
    if best[1] in ("tmpfs", "ramfs", "overlay"):
        r.add("FAIL", "disk-type", f"data dir is on {best[1]} ({best[0]}): chain data would not survive a reboot")
    # Build trees on a producer filled a disk once (chain halt 2026-10-04): never build here.
    for p in ("/root/.cargo", "/home/citrate/.cargo", "/var/lib/citrate/.cargo"):
        try:
            present = h.path(p).exists()
        except OSError:
            present = False
        if present:
            r.add("WARN", "no-builds", f"{p} exists: do not build on a producer; install release artifacts")


def check_clock(h: Host, a: argparse.Namespace, r: Report) -> None:
    rc, out = h.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if rc != 0:
        r.add("UNKNOWN", "clock", f"timedatectl unavailable ({out.strip()[:80]})")
    elif out.strip() == "yes":
        r.add("PASS", "clock", "NTP synchronized")
    else:
        r.add("FAIL", "clock", "NTP not synchronized: block timestamps are checked against the parent")


def check_user(h: Host, a: argparse.Namespace, r: Report) -> None:
    try:
        u = pwd.getpwnam(a.user) if h.root == Path("/") else None
    except KeyError:
        u = None
    if h.root != Path("/"):
        passwd = h.read("/etc/passwd") or ""
        line = next((l for l in passwd.splitlines() if l.startswith(a.user + ":")), None)
        uid = int(line.split(":")[2]) if line else None
    else:
        uid = u.pw_uid if u else None
    if uid is None:
        r.add("FAIL", "user", f"user {a.user!r} does not exist (runbook §2)")
        return
    if uid == 0:
        r.add("FAIL", "user", f"user {a.user!r} is uid 0: the node must not run as root")
    else:
        r.add("PASS", "user", f"{a.user} (uid {uid})")
    d = h.path(a.data_dir)
    try:
        st = d.stat()
    except FileNotFoundError:
        r.add("WARN", "data-dir", f"{a.data_dir} does not exist yet (created before first start, runbook §5)")
        return
    except OSError as e:
        r.add("UNKNOWN", "data-dir", f"cannot stat {a.data_dir}: {e} (run as root)")
        return
    if st.st_uid != uid:
        r.add("FAIL", "data-dir", f"{a.data_dir} owned by uid {st.st_uid}, not {a.user}")
    elif st.st_mode & 0o077:
        r.add("FAIL", "data-dir", f"{a.data_dir} mode {stat.S_IMODE(st.st_mode):o}: must be 0700")
    else:
        r.add("PASS", "data-dir", f"{a.data_dir} owned by {a.user}, 0700")
    for name in ("proposer.key", "noise.key"):
        kp = d / name
        try:
            ks = kp.stat()  # stat only: key material is never read
        except FileNotFoundError:
            r.add("INFO", name, "absent (the node mints it on first start; back it up then, runbook §6)")
            continue
        except OSError as e:
            r.add("UNKNOWN", name, f"cannot stat: {e}")
            continue
        problems = []
        if ks.st_uid != uid:
            problems.append(f"owned by uid {ks.st_uid}")
        if ks.st_mode & 0o077:
            problems.append(f"mode {stat.S_IMODE(ks.st_mode):o}")
        if name == "proposer.key" and ks.st_size != 32:
            problems.append(f"{ks.st_size} bytes, expected 32")
        if problems:
            r.add("FAIL", name, "; ".join(problems))
        else:
            r.add("PASS", name, "present, owner-only (back-up status is yours to confirm)")


def check_ssh_firewall(h: Host, a: argparse.Namespace, r: Report) -> None:
    if not h.is_root():
        r.add("UNKNOWN", "ssh", "run as root to read the effective sshd config")
    else:
        rc, out = h.run(["sshd", "-T"])
        if rc != 0:
            r.add("UNKNOWN", "ssh", f"sshd -T failed ({out.strip()[:80]})")
        else:
            cfg = dict(l.split(None, 1) for l in out.lower().splitlines() if " " in l)
            bad = []
            if cfg.get("passwordauthentication") != "no":
                bad.append("passwordauthentication must be no")
            if cfg.get("permitrootlogin") not in ("no", "prohibit-password", "without-password"):
                bad.append("permitrootlogin must be no or prohibit-password")
            if cfg.get("kbdinteractiveauthentication", "no") != "no":
                bad.append("kbdinteractiveauthentication must be no")
            r.add("FAIL" if bad else "PASS", "ssh", "; ".join(bad) or "key-only, no root password login")
    rc, out = h.run(["ufw", "status"])
    if rc == 0 and "Status: active" in out:
        if re.search(r"^8545\b|^8546\b|^9090\b", out, re.M):
            r.add("FAIL", "firewall", "ufw allows 8545/8546/9090 inbound: RPC and metrics stay local")
        elif re.search(rf"^{a.p2p_port}(/tcp)?\s+ALLOW", out, re.M):
            r.add("PASS", "firewall", f"ufw active; P2P {a.p2p_port}/tcp allowed")
        else:
            r.add("FAIL", "firewall", f"ufw active but P2P {a.p2p_port}/tcp is not allowed inbound")
    elif rc == 0:
        r.add("FAIL", "firewall", "ufw installed but inactive")
    else:
        rc2, out2 = h.run(["nft", "list", "ruleset"])
        if rc2 == 0 and out2.strip():
            r.add("WARN", "firewall", "no ufw; an nftables ruleset exists: confirm P2P open, 8545/8546/9090 closed")
        else:
            r.add("UNKNOWN" if not h.is_root() else "FAIL", "firewall", "no active host firewall found")
    rc, out = h.run(["ss", "-ltnH"])
    if rc == 0:
        exposed = []
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 4:
                local = cols[3]
                port = local.rsplit(":", 1)[-1]
                host_part = local.rsplit(":", 1)[0]
                if port in ("8545", "8546", "9090") and host_part not in ("127.0.0.1", "[::1]", "::1"):
                    exposed.append(local)
        if exposed:
            r.add("FAIL", "listeners", f"RPC/metrics listening beyond localhost: {', '.join(exposed)}")
        else:
            r.add("PASS", "listeners", "RPC/metrics not listening beyond localhost")


def check_journal(h: Host, a: argparse.Namespace, r: Report) -> None:
    main_conf = h.read("/etc/systemd/journald.conf")
    unreadable = []
    if main_conf is None and h.path("/etc/systemd/journald.conf").exists():
        unreadable.append("/etc/systemd/journald.conf")
    conf = main_conf or ""
    dropins = h.path("/etc/systemd/journald.conf.d")
    if dropins.is_dir():
        for p in sorted(dropins.glob("*.conf")):
            try:
                conf += "\n" + p.read_text(errors="replace")
            except OSError:
                unreadable.append(str(p))
    # Drop-ins are applied in order and the last assignment wins; an empty or "infinity"
    # value removes the cap. An unreadable drop-in could hold that last assignment.
    values = re.findall(r"^\s*SystemMaxUse\s*=[ \t]*(\S*)", conf, re.M)
    if unreadable:
        r.add("UNKNOWN", "journald", f"cannot read {', '.join(unreadable)}: SystemMaxUse not determinable")
    elif values and values[-1] and values[-1].lower() != "infinity":
        r.add("PASS", "journald", f"SystemMaxUse is capped ({values[-1]})")
    else:
        r.add("WARN", "journald", "SystemMaxUse not set: cap the journal (runbook §2), a log flood filled a disk once")


def check_binary(h: Host, a: argparse.Namespace, r: Report) -> None:
    b = h.path(a.binary)
    if not b.is_file():
        r.add("WARN" if not a.expect_sha256 else "FAIL", "binary", f"{b} not installed yet")
        return
    digest = hashlib.sha256(b.read_bytes()).hexdigest()
    if a.expect_sha256:
        if digest != a.expect_sha256.lower():
            r.add("FAIL", "binary-sha256", f"{digest} (expected {a.expect_sha256.lower()})")
            # Never execute a binary whose hash was rejected: preflight runs as root, and the
            # binary may be tampered with or truncated. The fingerprint check is skipped.
            r.add("FAIL", "fingerprint", "not checked: the binary was not executed because its sha256 does not match")
            return
        r.add("PASS", "binary-sha256", f"{digest} (expected {a.expect_sha256.lower()})")
    else:
        r.add("INFO", "binary-sha256", f"{digest} (pass --expect-sha256 to compare with the release)")
    rc, out = h.run(["env", "RUST_LOG=error", str(b), "consensus", "--json"])
    fp = None
    if rc == 0:
        lines = out.splitlines()
        try:
            fp = json.loads("\n".join(lines[lines.index("{") :])).get("fingerprint")
        except (ValueError, AttributeError):
            fp = None
    if fp is None:
        r.add("UNKNOWN", "fingerprint", "could not read `citrate-node consensus --json`")
    elif a.expect_fingerprint:
        lvl = "PASS" if str(fp).lower() == a.expect_fingerprint.lower() else "FAIL"
        r.add(lvl, "fingerprint", f"{fp} (expected {a.expect_fingerprint})")
    else:
        r.add("INFO", "fingerprint", f"{fp} (compare with the chain team's announced value)")


def check_network(h: Host, a: argparse.Namespace, r: Report, prof: pl.Profile) -> None:
    for b in prof["bootstrap_nodes"]:
        hostport = b.split("@", 1)[1]
        host, port = hostport.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port)), timeout=5):
                r.add("PASS", "bootnode", f"{hostport} reachable")
        except OSError as e:
            r.add("WARN", "bootnode", f"{hostport} not reachable: {e}")
    try:
        net = pl.check_network(pl.Rpc(prof["public_rpc"], timeout=10), prof)
        r.add("PASS", "public-rpc", f"{prof['public_rpc']} is chain {net['chain_id']}, head {net['head']}")
    except pl.ToolError as e:
        r.add("FAIL", "public-rpc", str(e))


CHECKS: list[tuple[str, Callable[..., None], str]] = [
    ("os", check_os, "architecture and OS release"),
    ("cpu-mem", check_cpu_mem, f">= {THRESHOLDS['min_cpus']} CPUs, >= {THRESHOLDS['min_mem_gib']} GiB RAM"),
    ("disk", check_disk, f">= {THRESHOLDS['min_disk_free_gib']} GiB free, < {THRESHOLDS['max_disk_used_pct']}% used, persistent fs"),
    ("clock", check_clock, "timedatectl: NTP synchronized"),
    ("user", check_user, "non-root service user; data dir 0700; key files stat-only"),
    ("ssh-firewall", check_ssh_firewall, "sshd -T, ufw status / nft, ss -ltn"),
    ("journal", check_journal, "journald SystemMaxUse set"),
    ("binary", check_binary, "sha256 of the binary; `citrate-node consensus --json` fingerprint"),
]


def run(h: Host, a: argparse.Namespace, prof: pl.Profile | None) -> Report:
    r = Report()
    for _, fn, _ in CHECKS:
        fn(h, a, r)
    if prof is not None and not a.offline:
        check_network(h, a, r, prof)
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--data-dir", default="/var/lib/citrate/data")
    ap.add_argument("--user", default="citrate")
    ap.add_argument("--binary", default="/usr/local/bin/citrate-node")
    ap.add_argument("--p2p-port", type=int, default=30303)
    ap.add_argument("--expect-sha256")
    ap.add_argument("--expect-fingerprint")
    ap.add_argument("--offline", action="store_true", help="skip bootnode and public RPC probes")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="list the checks; run nothing")
    args = ap.parse_args(argv)
    try:
        prof = pl.load_profile(args.profile, allow_pending=args.dry_run or args.offline)
    except pl.ToolError as e:
        print(f"preflight: {e}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(f"DRY RUN: preflight for profile {prof.name} ({prof['status']}), data dir {args.data_dir}")
        for name, _, what in CHECKS:
            print(f"  {name:13} {what}")
        if not args.offline:
            print(f"  {'network':13} TCP connect to {len(prof['bootstrap_nodes'])} bootnodes; chain id + genesis on {prof['public_rpc']}")
        return 0
    rep = run(Host(), args, prof)
    if args.json:
        print(json.dumps(rep.rows, indent=2))
    else:
        for row in rep.rows:
            print(f"[{row['level']:7}] {row['check']:14} {row['detail']}")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
