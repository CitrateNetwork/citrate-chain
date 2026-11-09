#!/usr/bin/env python3
"""r1007 ceremony host agent: runs ON one node host (or inside one devnet namespace).

Generation slots. Every chain generation a host runs lives in its own slot, and
nothing in one slot is ever moved or deleted by a switch:

  <root>/etc/citrate/gen/<gen>/        node.toml, node.mine.toml, node.sync.toml,
                                       citrate-node.env, citrate-node.service, launch.json
  <root>/var/lib/citrate/gen/<gen>/    the generation's data dir (keys copied in host-locally)
  <root>/usr/local/lib/citrate-gen/<gen>/citrate-node
  <root>/etc/citrate/active            the generation this host runs (one line)

r1006 on the live fleet predates slots: `park-r1006` records its unit and the files it
references in slot `r1006` WITHOUT moving them (its data stays at /var/lib/citrate/data),
so a rollback is: stop, install the r1006 unit again, start. Data of both generations
is kept.

Modes: `systemd` (fleet; the unit is installed on switch) or `proc` (devnet; the node is
a child process with a pid file). Keys: `seed-keys` copies the host's own noise.key (and
proposer.key for producers) from the r1006 data dir into the new slot's data dir, 0600,
on this host. No key byte is ever printed, returned or sent.

Output: one JSON object per command on stdout. Exit 0 ok, 1 a check failed, 2 refused.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

GEN_OK = ("r1006", "r1007")
SLOT_FILES = ("node.toml", "node.mine.toml", "node.sync.toml", "citrate-node.env", "citrate-node.service", "launch.json")
SECRET_NAMES = ("noise.key", "proposer.key")


class Refused(Exception):
    pass


def out(obj: dict, rc: int = 0) -> int:
    print(json.dumps(obj, sort_keys=True))
    return rc


class Host:
    def __init__(self, a: argparse.Namespace):
        self.root = Path(a.root)
        self.mode = a.mode
        self.run_as = a.run_as or None
        self.rpc = a.rpc

    def p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def slot_etc(self, gen: str) -> Path:
        return self.p(f"/etc/citrate/gen/{gen}")

    def slot_data(self, gen: str) -> Path:
        return self.p(f"/var/lib/citrate/gen/{gen}")

    def slot_bin(self, gen: str) -> Path:
        return self.p(f"/usr/local/lib/citrate-gen/{gen}/citrate-node")

    @property
    def active_file(self) -> Path:
        return self.p("/etc/citrate/active")

    @property
    def state_dir(self) -> Path:
        return self.p("/var/lib/citrate/ceremony")

    @property
    def pidfile(self) -> Path:
        return self.state_dir / "node.pid"

    def active(self) -> str | None:
        try:
            g = self.active_file.read_text().strip()
        except OSError:
            return None
        return g or None

    def own(self, path: Path, mode: int) -> None:
        if self.run_as:
            shutil.chown(path, self.run_as, self.run_as)
        os.chmod(path, mode)

    # ---- process control -------------------------------------------------
    def pid(self) -> int | None:
        try:
            p = int(self.pidfile.read_text().strip())
        except (OSError, ValueError):
            return None
        return p if alive(p) else None

    def running(self) -> bool:
        if self.mode == "systemd":
            return subprocess.run(["systemctl", "is-active", "--quiet", "citrate-node"]).returncode == 0
        return self.pid() is not None

    def start(self) -> None:
        if self.running():
            return
        gen = self.active()
        if gen is None:
            raise Refused("no active generation; switch first")
        if self.mode == "systemd":
            subprocess.run(["systemctl", "enable", "--now", "citrate-node"], check=True)
            return
        spec = json.loads((self.slot_etc(gen) / "launch.json").read_text())
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        for line in Path(self.p(spec["env_file"])).read_text().splitlines():
            if "=" in line and line.split("=", 1)[0].startswith("CITRATE_"):
                k, v = line.split("=", 1)
                env[k] = v
        for kv in os.environ.get("R1007_NODE_ENV_PASSTHRU", "").split():
            k, _, v = kv.partition("=")
            if k.startswith("CITRATE_"):
                env[k] = v
        self.state_dir.mkdir(parents=True, exist_ok=True)
        log = open(self.state_dir / f"node-{gen}.log", "ab")
        data = self.p(spec["data_dir"])
        wait_db_unlocked(data)
        proc = subprocess.Popen(
            [str(self.p(spec["binary"])), "--config", str(self.p(spec["config"]))],
            cwd=data, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
        )
        self.pidfile.write_text(str(proc.pid))
        time.sleep(3)
        if proc.poll() is not None:
            self.pidfile.unlink(missing_ok=True)
            raise RuntimeError(f"the node exited at start-up (rc {proc.returncode}); see node-{gen}.log")

    def stop(self) -> None:
        if self.mode == "systemd":
            if self.running():
                subprocess.run(["systemctl", "stop", "citrate-node"], check=True)
            if self.running():
                raise Refused("citrate-node still active")
            return
        p = self.pid()
        if p is None:
            self.pidfile.unlink(missing_ok=True)
            return
        # The node shuts down on SIGINT (tokio ctrl_c); on the 2026-11-09 rehearsal it did
        # not exit on SIGTERM. SIGINT first, then SIGTERM, then SIGKILL.
        for sig, secs in ((signal.SIGINT, 60), (signal.SIGTERM, 10), (signal.SIGKILL, 30)):
            try:
                os.kill(p, sig)
            except OSError:
                break
            if wait_gone(p, secs):
                break
        else:
            raise Refused(f"node pid {p} did not exit after SIGKILL")
        self.pidfile.unlink(missing_ok=True)
        gen = self.active()
        if gen:
            spec = json.loads((self.slot_etc(gen) / "launch.json").read_text())
            wait_db_unlocked(self.p(spec["data_dir"]))

    # ---- rpc (loopback only) ---------------------------------------------
    def call(self, method: str, params: list) -> object:
        req = urllib.request.Request(
            self.rpc,
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
        if "error" in d:
            raise RuntimeError(f"{method}: {d['error']}")
        return d["result"]


def alive(pid: int) -> bool:
    """A running process (a zombie counts as gone: it holds no files)."""
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return True


def wait_gone(pid: int, seconds: float) -> bool:
    until = time.time() + seconds
    while time.time() < until:
        if not alive(pid):
            return True
        time.sleep(0.25)
    return not alive(pid)


def wait_db_unlocked(data: Path, seconds: float = 60) -> None:
    """Wait until no process holds the data dir's RocksDB LOCK (fcntl), so a restart never
    races the previous process's exit."""
    import fcntl

    lock = data / "LOCK"
    if not lock.exists():
        return
    until = time.time() + seconds
    while True:
        try:
            with open(lock, "r+") as f:
                fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(f, fcntl.LOCK_UN)
            return
        except OSError:
            if time.time() > until:
                raise Refused(f"{lock} is still held by another process")
            time.sleep(0.5)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_status(h: Host, a) -> int:
    slots = {}
    for g in GEN_OK:
        if h.slot_etc(g).is_dir():
            slots[g] = {"etc": True, "data": h.slot_data(g).is_dir(), "bin": h.slot_bin(g).is_file()}
    return out({"active": h.active(), "running": h.running(), "slots": slots})


def cmd_park_r1006(h: Host, a) -> int:
    """Record the live (pre-slot) r1006 install as slot r1006 without moving anything."""
    etc = h.slot_etc("r1006")
    if etc.is_dir() and (etc / "citrate-node.service").is_file():
        return out({"parked": "r1006", "already": True})
    unit = h.p("/etc/systemd/system/citrate-node.service")
    if not unit.is_file():
        raise Refused("no live citrate-node unit to park")
    etc.mkdir(parents=True, exist_ok=True)
    shutil.copy2(unit, etc / "citrate-node.service")
    refs = {}
    for f in ("/etc/citrate/node.toml", "/etc/citrate/citrate-node.env", "/usr/local/bin/citrate-node"):
        if h.p(f).is_file():
            refs[f] = sha(h.p(f))
    (etc / "parked.json").write_text(json.dumps({"files": refs, "data_dir": "/var/lib/citrate/data"}, indent=2))
    if h.active() is None:
        h.active_file.write_text("r1006\n")
    return out({"parked": "r1006", "already": False, "files": sorted(refs)})


def cmd_snapshot(h: Host, a) -> int:
    """The service state before the cut, written once: what a rollback restores."""
    h.state_dir.mkdir(parents=True, exist_ok=True)
    f = h.state_dir / "pre-cut.json"
    if f.exists():
        return out({"snapshot": json.loads(f.read_text()), "already": True})
    snap = {"active": h.active(), "running": h.running(), "ts": int(time.time()), "head": None}
    if snap["running"]:
        try:
            snap["head"] = int(str(h.call("eth_blockNumber", [])), 16)
        except Exception:  # noqa: BLE001 - a node that does not answer has no recorded head
            pass
    if h.mode == "systemd":
        snap["enabled"] = subprocess.run(["systemctl", "is-enabled", "--quiet", "citrate-node"]).returncode == 0
    f.write_text(json.dumps(snap))
    return out({"snapshot": snap, "already": False})


def cmd_stage(h: Host, a) -> int:
    """Install a rendered generation (binary + configs) into its slot, hash-checked."""
    gen, src = a.gen, Path(a.incoming)
    man = json.loads((src / "manifest.json").read_text())
    if man.get("network") != gen:
        raise Refused(f"incoming bundle is for {man.get('network')}, not {gen}")
    for name, digest in man["files"].items():
        if sha(src / name) != digest:
            raise Refused(f"{name} does not match its manifest hash")
    etc, data, binp = h.slot_etc(gen), h.slot_data(gen), h.slot_bin(gen)
    if h.active() == gen and h.running():
        raise Refused(f"{gen} is running; stop it before restaging")
    etc.mkdir(parents=True, exist_ok=True)
    binp.parent.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    h.own(data, 0o700)
    for name in SLOT_FILES:
        if (src / name).is_file():
            shutil.copy2(src / name, etc / name)
            os.chmod(etc / name, 0o644)
    shutil.copy2(src / "citrate-node", binp)
    os.chmod(binp, 0o755)
    shutil.copy2(src / "node.sync.toml", etc / "node.toml")  # every start begins mining off
    (etc / "manifest.json").write_text(json.dumps(man))
    return out({"staged": gen, "files": sorted(man["files"])})


def cmd_seed_keys(h: Host, a) -> int:
    """Copy this host's own keys from the source generation's data dir, host-locally, 0600."""
    keys = [k for k in a.keys.split(",") if k]
    for k in keys:
        if k not in ("noise", "proposer"):
            raise Refused(f"unknown key {k}")
    src_dir = h.p("/var/lib/citrate/data") if a.from_gen == "r1006" and not h.slot_data("r1006").is_dir() else h.slot_data(a.from_gen)
    dst_dir = h.slot_data(a.to_gen)
    if not dst_dir.is_dir():
        raise Refused(f"slot {a.to_gen} has no data dir; stage first")
    done = []
    for k in keys:
        s, d = src_dir / f"{k}.key", dst_dir / f"{k}.key"
        if not s.is_file():
            raise Refused(f"{k}.key is missing in the {a.from_gen} data dir")
        if d.exists():
            if not filecmp.cmp(s, d, shallow=False):
                raise Refused(f"{k}.key in slot {a.to_gen} differs from {a.from_gen}'s; refusing to overwrite")
            done.append(f"{k}:present")
            continue
        tmp = d.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(s.read_bytes())
            f.flush()
            os.fsync(f.fileno())
        h.own(tmp, 0o600)
        os.replace(tmp, d)
        done.append(f"{k}:copied")
    return out({"seeded": done, "from": a.from_gen, "to": a.to_gen})


def cmd_switch(h: Host, a) -> int:
    gen = a.gen
    etc = h.slot_etc(gen)
    if not (etc / "citrate-node.service").is_file() and h.mode == "systemd":
        raise Refused(f"slot {gen} has no unit")
    if h.mode == "proc" and not (etc / "launch.json").is_file():
        raise Refused(f"slot {gen} has no launch spec")
    if h.running():
        raise Refused("the node is running; stop it before switching generation")
    if h.mode == "systemd":
        shutil.copy2(etc / "citrate-node.service", h.p("/etc/systemd/system/citrate-node.service"))
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    h.active_file.parent.mkdir(parents=True, exist_ok=True)
    h.active_file.write_text(gen + "\n")
    return out({"active": gen})


def cmd_start(h: Host, a) -> int:
    h.start()
    return out({"started": h.active()})


def cmd_stop(h: Host, a) -> int:
    h.stop()
    return out({"stopped": h.active()})


def cmd_mining(h: Host, a) -> int:
    gen = h.active()
    if gen is None:
        raise Refused("no active generation")
    etc = h.slot_etc(gen)
    want = a.state
    srcf = etc / ("node.mine.toml" if want == "on" else "node.sync.toml")
    if not srcf.is_file():
        raise Refused(f"slot {gen} has no {srcf.name} (mining is not configured for this role)")
    if want == "on" and a.expect_genesis:
        got = str(h.call("eth_getBlockByNumber", ["0x0", False])["hash"]).lower()  # type: ignore[index]
        if got != a.expect_genesis.lower():
            raise Refused(f"block 0 is {got}, not {a.expect_genesis}; mining stays off")
    if filecmp.cmp(srcf, etc / "node.toml", shallow=False) and h.running():
        return out({"mining": want, "changed": False})
    was = h.running()
    h.stop()
    shutil.copy2(srcf, etc / "node.toml")
    if was or want == "on":
        h.start()
    return out({"mining": want, "changed": True})


def cmd_head(h: Host, a) -> int:
    b0 = h.call("eth_getBlockByNumber", ["0x0", False])
    head = int(str(h.call("eth_blockNumber", [])), 16)
    hb = h.call("eth_getBlockByNumber", [hex(head), False])
    peers = int(str(h.call("net_peerCount", [])), 16)
    res = {"block0": str(b0["hash"]).lower(), "head": head, "head_hash": str(hb["hash"]).lower(), "peers": peers}  # type: ignore[index]
    if a.at is not None:
        blk = h.call("eth_getBlockByNumber", [hex(a.at), False])
        res["at"] = a.at
        res["hash_at"] = str(blk["hash"]).lower() if blk else None  # type: ignore[index]
    return out(res)


def cmd_miners(h: Host, a) -> int:
    """Coinbases of the last N blocks of the selected chain AND of the blocks each one
    merges (`mergeParentHashes`): in a GHOSTDAG DAG a producer's block is often merged
    rather than selected, so the selected chain alone under-counts sealing."""
    head = int(str(h.call("eth_blockNumber", [])), 16)
    seen: dict[str, int] = {}
    done: set[str] = set()

    def count(blk: dict) -> None:
        bh = str(blk.get("hash", "")).lower()
        if bh in done:
            return
        done.add(bh)
        m = str(blk.get("miner", "")).lower()
        seen[m] = seen.get(m, 0) + 1

    for n in range(max(1, head - a.last + 1), head + 1):
        blk = h.call("eth_getBlockByNumber", [hex(n), False])
        if not blk:
            continue
        count(blk)  # type: ignore[arg-type]
        for mh in blk.get("mergeParentHashes") or []:  # type: ignore[union-attr]
            mb = h.call("eth_getBlockByHash", [mh, False])
            if mb:
                count(mb)  # type: ignore[arg-type]
    return out({"head": head, "miners": seen, "blocks": len(done)})


def cmd_rollback_target(h: Host, a) -> int:
    f = h.state_dir / "pre-cut.json"
    if not f.exists():
        raise Refused("no pre-cut snapshot on this host")
    return out(json.loads(f.read_text()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default="/")
    ap.add_argument("--mode", choices=("systemd", "proc"), default="systemd")
    ap.add_argument("--run-as", default="citrate")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("park-r1006")
    sub.add_parser("snapshot")
    s = sub.add_parser("stage")
    s.add_argument("--gen", choices=GEN_OK, required=True)
    s.add_argument("--incoming", required=True)
    s = sub.add_parser("seed-keys")
    s.add_argument("--from-gen", choices=GEN_OK, default="r1006")
    s.add_argument("--to-gen", choices=GEN_OK, default="r1007")
    s.add_argument("--keys", required=True)
    s = sub.add_parser("switch")
    s.add_argument("--gen", choices=GEN_OK, required=True)
    sub.add_parser("start")
    sub.add_parser("stop")
    s = sub.add_parser("mining")
    s.add_argument("state", choices=("on", "off"))
    s.add_argument("--expect-genesis")
    s = sub.add_parser("head")
    s.add_argument("--at", type=int)
    s = sub.add_parser("miners")
    s.add_argument("--last", type=int, default=30)
    sub.add_parser("rollback-target")
    a = ap.parse_args(argv)
    h = Host(a)
    try:
        return {
            "status": cmd_status, "park-r1006": cmd_park_r1006, "snapshot": cmd_snapshot, "stage": cmd_stage,
            "seed-keys": cmd_seed_keys, "switch": cmd_switch, "start": cmd_start, "stop": cmd_stop,
            "mining": cmd_mining, "head": cmd_head, "miners": cmd_miners, "rollback-target": cmd_rollback_target,
        }[a.cmd](h, a)
    except Refused as e:
        return out({"refused": str(e)}, 2)
    except Exception as e:  # noqa: BLE001 - one JSON error line, never a traceback with paths/keys
        return out({"error": f"{type(e).__name__}: {e}"}, 1)


if __name__ == "__main__":
    sys.exit(main())
