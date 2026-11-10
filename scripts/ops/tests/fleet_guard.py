"""fleet_guard: keep ops tests off the real fleet (fed #467 round 3).

install() for a whole test module (setUpModule), uninstall() in tearDownModule:
- subprocess.Popen (so run, call, check_call, check_output) raises FleetCallBlocked
  for any argv whose program is ssh, scp, sftp, rsync, doctl, tailscale or nsenter
  wrapping one of these, or that names a committed fleet alias;
- os.system raises for anything;
- socket connections to anything but loopback or a Unix socket raise;
- a temp dir with `ssh`, `scp`, `sftp`, `rsync` and `doctl` shims that exit 97 goes first
  on PATH, so a child process (a bash script under test) cannot reach a host either.
Local subprocesses (python3, sh, bash, fake binaries) still run.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

BLOCKED = {"ssh", "scp", "sftp", "rsync", "doctl", "tailscale"}
_REAL = {}
_SHIM_DIR: str | None = None
_ALIASES: set[str] = set()


class FleetCallBlocked(AssertionError):
    pass


def _fleet_aliases() -> set[str]:
    f = Path(__file__).resolve().parents[1] / "r1007" / "fleet.r1007.json"
    try:
        hosts = json.loads(f.read_text())["hosts"]
    except (OSError, ValueError, KeyError):
        return set()
    out = set()
    for h in hosts:
        for k in ("ssh", "name", "p2p_host"):
            if h.get(k):
                out.add(str(h[k]))
    return out


def _check_argv(args) -> None:
    argv = [args] if isinstance(args, (str, bytes, os.PathLike)) else list(args)
    words = []
    for a in argv:
        a = os.fsdecode(a) if isinstance(a, (bytes, os.PathLike)) else str(a)
        words.extend(a.split())
    if not words:
        return
    prog = os.path.basename(words[0])
    if prog in BLOCKED or (prog == "nsenter" and any(os.path.basename(w) in BLOCKED for w in words)):
        raise FleetCallBlocked(f"a test tried to run {prog}: {' '.join(words)[:200]}")
    hit = [w for w in words if w in _ALIASES]
    if hit:
        raise FleetCallBlocked(f"a test command names a fleet host {hit[0]}: {' '.join(words)[:200]}")


class _GuardedPopen(subprocess.Popen):
    def __init__(self, args, *a, **kw):
        _check_argv(args)
        super().__init__(args, *a, **kw)


def _system(cmd):
    raise FleetCallBlocked(f"a test called os.system: {str(cmd)[:200]}")


def _loopback(address) -> bool:
    if isinstance(address, (str, bytes)):
        return True  # AF_UNIX path
    host = str(address[0])
    return host in ("localhost", "::1") or host.startswith("127.")


def _connect(self, address):
    if self.family != socket.AF_UNIX and not _loopback(address):
        raise FleetCallBlocked(f"a test opened a non-loopback connection to {address}")
    return _REAL["connect"](self, address)


def _connect_ex(self, address):
    if self.family != socket.AF_UNIX and not _loopback(address):
        raise FleetCallBlocked(f"a test opened a non-loopback connection to {address}")
    return _REAL["connect_ex"](self, address)


def _create_connection(address, *a, **kw):
    if not _loopback(address):
        raise FleetCallBlocked(f"a test opened a non-loopback connection to {address}")
    return _REAL["create_connection"](address, *a, **kw)


def installed() -> bool:
    return bool(_REAL)


def install() -> None:
    global _SHIM_DIR, _ALIASES
    if _REAL:
        return
    _ALIASES = _fleet_aliases()
    _REAL.update(popen=subprocess.Popen, system=os.system, connect=socket.socket.connect,
                 connect_ex=socket.socket.connect_ex, create_connection=socket.create_connection,
                 path=os.environ.get("PATH", ""))
    subprocess.Popen = _GuardedPopen
    os.system = _system
    socket.socket.connect = _connect
    socket.socket.connect_ex = _connect_ex
    socket.create_connection = _create_connection
    _SHIM_DIR = tempfile.mkdtemp(prefix="fleet-guard-")
    for prog in sorted(BLOCKED - {"tailscale"}):
        p = Path(_SHIM_DIR) / prog
        p.write_text(f"#!/bin/sh\necho 'fleet_guard: {prog} is blocked in ops tests' >&2\nexit 97\n")
        p.chmod(0o755)
    os.environ["PATH"] = _SHIM_DIR + os.pathsep + _REAL["path"]


def uninstall() -> None:
    global _SHIM_DIR
    if not _REAL:
        return
    subprocess.Popen = _REAL["popen"]
    os.system = _REAL["system"]
    socket.socket.connect = _REAL["connect"]
    socket.socket.connect_ex = _REAL["connect_ex"]
    socket.create_connection = _REAL["create_connection"]
    os.environ["PATH"] = _REAL["path"]
    _REAL.clear()
    if _SHIM_DIR:
        shutil.rmtree(_SHIM_DIR, ignore_errors=True)
        _SHIM_DIR = None
