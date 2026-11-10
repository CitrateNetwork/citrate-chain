#!/usr/bin/env python3
"""r1007 network ceremony: render, check, plan, bring up, health-check and roll back.

  ceremony.py collect  --fleet F --state DIR [--mint]          public host identities -> DIR/identities.json
  ceremony.py render   --fleet F --state DIR --network r1007|r1006 --binary PATH
                                                               per-host bundles -> DIR/render/<network>/<host>/
  ceremony.py check    --fleet F --state DIR --network r1007 [--binary PATH]
                                                               every rendered config vs R1007_CHAIN_PARAMS
                                                               (static, and with --binary the node's own
                                                               consensus fingerprint for each config)
  ceremony.py plan     --fleet F [--json]                      the ordered bring-up, owner approval points marked
  ceremony.py run STEP --fleet F --state DIR [--owner-go FILE] execute one step (see plan): prepare, cut, boots,
                                                               producers, rpc, indexer, health, rollback
  ceremony.py health   --fleet F --state DIR --network r1007|r1006 [--min-peers N] [--last N]

Every consensus value is read from this checkout (params.py); the fleet file holds only
public host data. Rendered files hold no secret: keys are referenced by their path on the
host (and their 1Password backup item names in the fleet file), and `check` scans every
rendered file for key material.

Transports. `local` (the devnet: each host is a directory + network namespace, the agent
runs under nsenter) and `ssh` (the fleet). The ssh transport refuses to run any step
that changes a host unless --owner-go names a file recording the owner's go for THAT step
and THIS genesis (see RUNBOOK). This lane never ran it against a host.

Exit: 0 ok, 1 a check or gate failed, 2 usage or refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
AGENT = HERE / "node_agent.py"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "scripts" / "producers"))
import params as P  # noqa: E402
import gen_node_config as G  # noqa: E402
import producerlib as PL  # noqa: E402

TEMPLATES = {"r1007": REPO / "scripts/producers/profiles/r1007.json", "r1006": REPO / "scripts/producers/profiles/r1006.json"}
ROLES = ("boot", "producer", "rpc")
PEER_RE = re.compile(r"^noise_[0-9a-f]{64}$")
ZERO_COINBASE = "0" * 40
# Anything that looks like key material in a rendered file (a 32-byte hex outside a known
# public context, a PEM block, a keystore field). Public 32-byte values are allowlisted.
SECRET_RES = (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), re.compile(r"\"(ciphertext|crypto|kdfparams)\""),
              re.compile(r"(?i)(private[_ ]?key|secret|password)\s*="))
HEX64 = re.compile(r"(?<![0-9a-fA-Fx_])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")


class Fail(Exception):
    """A gate or check failed (exit 1)."""


class Refuse(Exception):
    """Usage or a refused action (exit 2)."""


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S', time.gmtime())} {msg}", flush=True)


def load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise Refuse(f"cannot read {p}: {e}") from None


def write_json(p: Path, d: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    t = p.with_suffix(p.suffix + ".tmp")
    t.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
    t.replace(p)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ─── fleet ───────────────────────────────────────────────────────────────────


class Fleet:
    def __init__(self, path: Path):
        self.path = path
        self.d = load_json(path)
        if self.d.get("schema") != "r1007-fleet/1":
            raise Refuse(f"{path} is not an r1007-fleet/1 file")
        self.transport = self.d.get("transport", "ssh")
        if self.transport not in ("ssh", "local"):
            raise Refuse("transport is ssh or local")
        names = [h["name"] for h in self.d["hosts"]]
        if len(set(names)) != len(names):
            raise Refuse("duplicate host names in the fleet file")
        for h in self.d["hosts"]:
            if h.get("role") not in ROLES:
                raise Refuse(f"{h.get('name')}: role must be one of {ROLES}")
        self.port = int(self.d.get("p2p_port", 30303))

    def hosts(self, role: str | None = None) -> list[dict]:
        return [h for h in self.d["hosts"] if role is None or h["role"] == role]

    def root(self, h: dict) -> str:
        return h.get("root", "") if self.transport == "local" else ""


def committed_fleet() -> dict:
    return load_json(HERE / "fleet.r1007.json")


# ─── transport ───────────────────────────────────────────────────────────────


class Transport:
    """Runs node_agent.py on a host and returns its one JSON line."""

    def __init__(self, fleet: Fleet, owner_go: dict | None):
        self.f = fleet
        self.go = owner_go

    def _base(self, h: dict) -> list[str]:
        if self.f.transport == "local":
            pre = ["nsenter", f"--net=/proc/{h['netns_pid']}/ns/net"] if h.get("netns_pid") else []
            return pre + [sys.executable, str(AGENT), "--root", h["root"], "--mode", "proc", "--run-as", ""]
        return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", h["ssh"], "python3", "-", "--mode", "systemd"]

    def agent(self, h: dict, *args: str, mutating: bool = True, step: str = "") -> dict:
        if self.f.transport == "ssh" and mutating:
            self.require_go(step, h)
        cmd = self._base(h) + list(args)
        stdin = AGENT.read_bytes() if self.f.transport == "ssh" else None
        env = dict(os.environ)
        r = subprocess.run(cmd, input=stdin, capture_output=True, env=env, timeout=600)
        line = (r.stdout.decode().strip().splitlines() or ["{}"])[-1]
        try:
            res = json.loads(line)
        except json.JSONDecodeError:
            res = {"error": f"agent output was not JSON (rc {r.returncode})"}
        if r.returncode != 0 or "refused" in res or "error" in res:
            raise Fail(f"{h['name']} {' '.join(args)}: {res.get('refused') or res.get('error') or r.returncode}")
        return res

    def put(self, h: dict, src: Path, dest_rel: str, step: str) -> None:
        if self.f.transport == "local":
            d = Path(h["root"]) / dest_rel.lstrip("/")
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, d)
            return
        self.require_go(step, h)
        subprocess.run(["ssh", h["ssh"], "mkdir", "-p", str(Path(dest_rel).parent)], check=True)
        subprocess.run(["scp", "-q", str(src), f"{h['ssh']}:{dest_rel}"], check=True)

    def require_go(self, step: str, h: dict) -> None:
        if self.go is None:
            raise Refuse(f"step {step} changes {h['name']}: the ssh transport needs --owner-go (the owner's recorded go)")
        allowed = {x["name"] for x in committed_fleet()["hosts"]}
        if h["name"] not in allowed or self.f.path.resolve() != (HERE / "fleet.r1007.json").resolve():
            raise Refuse(f"{h['name']} is not in the committed fleet file; refusing")
        if step not in self.go.get("steps", []):
            raise Refuse(f"the owner go does not cover step {step}")


def load_go(path: str | None, genesis: str) -> dict | None:
    if not path:
        return None
    go = load_json(Path(path))
    if go.get("ceremony") != "r1007" or str(go.get("genesis", "")).lower() != genesis:
        raise Refuse("the owner-go file is not for this ceremony and genesis")
    for k in ("approved_by", "approved_at", "steps"):
        if not go.get(k):
            raise Refuse(f"the owner-go file has no {k}")
    return go


# ─── collect ─────────────────────────────────────────────────────────────────


def cmd_collect(a, fleet: Fleet, src: dict) -> int:
    """Public identities. Fleet: read-only host-identity on each producer (its r1006 keys).
    Devnet (--mint): mint each host's keys into its r1006 slot, as a real host has them."""
    if a.mint and fleet.transport != "local":
        raise Refuse("--mint is for the devnet only")
    ids: dict[str, dict] = {}
    want = {p["name"]: p for p in src["producers"]}
    for h in fleet.hosts():
        if fleet.transport == "ssh" and h["role"] != "producer":
            continue  # boots and rpc-1 keep their published noise identities (fleet file)
        root = Path(fleet.root(h))
        data = root / ("var/lib/citrate/gen/r1006" if a.mint else "var/lib/citrate/data")
        keys = root / "etc/citrate/keys"
        if a.mint:
            data.mkdir(parents=True, exist_ok=True)
            keys.mkdir(parents=True, exist_ok=True)
            os.chmod(data, 0o700)
            os.chmod(keys, 0o700)
        args = ["host-identity", "--identity-dir", str(data), "--staker-keystore", str(keys / "staker.keystore.json"),
                "--staker-password-file", str(keys / "staker.password")]
        if a.mint:
            args.append("--mint")
        # The node logs to stdout as well, so the public identity is read from --out (0644,
        # public parts only), never parsed out of the log stream.
        if fleet.transport == "local":
            out_f = Path(a.state) / "identity-pub" / f"{h['name']}.json"
            out_f.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run([a.binary, *args, "--out", str(out_f)], capture_output=True, text=True, timeout=300)
            text = out_f.read_text() if r.returncode == 0 and out_f.exists() else ""
        else:
            remote = "/var/lib/citrate/ceremony/identity.pub.json"
            r = subprocess.run(["ssh", h["ssh"], "mkdir -p /var/lib/citrate/ceremony && /usr/local/bin/citrate-node "
                                + " ".join(args) + f" --out {remote} >/dev/null 2>&1 && cat {remote}"],
                               capture_output=True, text=True, timeout=300)
            text = r.stdout
        if r.returncode != 0:
            raise Fail(f"{h['name']}: host-identity failed (rc {r.returncode})")
        try:
            pub = json.loads(text)
        except json.JSONDecodeError:
            raise Fail(f"{h['name']}: host-identity wrote no public identity") from None
        if set(pub) != {"schema", "peer_id", "noise_pubkey", "proposer_pubkey", "vrf_pubkey", "staker_address", "coinbase_address"}:
            raise Fail(f"{h['name']}: host-identity printed something other than a public identity")
        if fleet.transport == "ssh":
            exp = want.get(h["name"])
            if not exp or exp["proposer_pubkey"] != pub["proposer_pubkey"].lower() or exp["staker"] != pub["staker_address"].lower():
                raise Fail(f"{h['name']}: its proposer key or staker is not the one validators.json registers")
        ids[h["name"]] = {k: pub[k] for k in ("peer_id", "proposer_pubkey", "staker_address")}
    write_json(Path(a.state) / "identities.json", {"schema": "r1007-identities/1", "hosts": ids})
    log(f"identities -> {a.state}/identities.json ({len(ids)} hosts)")
    return 0


# ─── render ──────────────────────────────────────────────────────────────────


def identities(a, fleet: Fleet) -> dict[str, dict]:
    p = Path(a.state) / "identities.json"
    got = load_json(p)["hosts"] if p.exists() else {}
    out = {}
    for h in fleet.hosts():
        i = dict(got.get(h["name"], {}))
        if h.get("peer_id"):
            if i.get("peer_id") and i["peer_id"] != h["peer_id"]:
                raise Fail(f"{h['name']}: collected peer id differs from the fleet file's")
            i["peer_id"] = h["peer_id"]
        if not PEER_RE.match(str(i.get("peer_id", ""))):
            raise Refuse(f"{h['name']} has no peer id: run collect first")
        out[h["name"]] = i
    return out


def stakers(fleet: Fleet, ids: dict, src: dict) -> dict[str, str]:
    """Producer coinbase = its registered staker: validators.json on the fleet, the minted one on a devnet."""
    reg = {p["name"]: p["staker"] for p in src["producers"]}
    out = {}
    for h in fleet.hosts("producer"):
        s = reg.get(h["name"]) if fleet.transport == "ssh" else ids[h["name"]].get("staker_address")
        if not s:
            raise Refuse(f"{h['name']}: no staker")
        out[h["name"]] = s.lower()
    return out


def bootnode(fleet: Fleet, h: dict, ids: dict) -> str:
    return f"{ids[h['name']]['peer_id']}@{h['p2p_host']}:{fleet.port}"


def bootnodes_for(fleet: Fleet, h: dict, ids: dict) -> list[str]:
    """boots: the other boots + producers; producers: boots + other producers; rpc: boots + producers."""
    peers = [x for x in fleet.hosts() if x["name"] != h["name"] and x["role"] in ("boot", "producer")]
    return [bootnode(fleet, x, ids) for x in peers]


def render_host(fleet: Fleet, h: dict, net: str, src: dict, ids: dict, stk: dict, bin_sha: str) -> dict[str, str]:
    root = fleet.root(h)
    etc = f"/etc/citrate/gen/{net}"
    data = f"/var/lib/citrate/gen/{net}"
    binp = f"/usr/local/lib/citrate-gen/{net}/citrate-node"
    raw = json.loads(TEMPLATES[net].read_text())
    raw.update({
        "name": f"{net}-{h['name']}",
        "status": "ready",
        "chain_id": int(fleet.d["chain_id"]),
        "genesis_hash": src[f"{net}_genesis"],
        "genesis_profile": net,
        "validator_registry": src["validator_registry"],
        "validator_activation_height": int(src["validator_activation_height"]),
        "bootstrap_nodes": bootnodes_for(fleet, h, ids),
    })
    if net == "r1007":
        p = src["params"]
        raw["checkpoint"] = {**raw["checkpoint"], "interval": p["checkpoint_interval"], "committee_size": p["committee_size"]}
        raw["ghostdag_k"] = p["ghostdag_k"]
        raw["env"] = {**raw["env"], "CITRATE_DAG_PRUNE_RETAIN": str(p["pruning_depth"])}
    raw.pop("rpc", None)
    if h.get("serve_recent_state_tags"):
        raw["rpc"] = {"serve_recent_state_tags": int(h["serve_recent_state_tags"])}
    prof = PL.Profile(raw)
    probs = PL.profile_problems(prof)
    if probs:
        raise Fail(f"{h['name']}: rendered profile is not usable: {'; '.join(probs)}")
    real = lambda p: (root.rstrip("/") + p) if root else p  # noqa: E731
    files: dict[str, str] = {}
    if h["role"] == "producer":
        staker = stk[h["name"]]
        files["node.mine.toml"] = G.render_node_toml(prof, staker, real(data), fleet.port, True)
        files["node.sync.toml"] = G.render_node_toml(prof, staker, real(data), fleet.port, False)
    else:
        # Not a producer: mining stays off and the coinbase is unused, so it is zero.
        t = G.render_node_toml(prof, "0x" + "00" * 19 + "01", real(data), fleet.port, False)
        t = re.sub(r'^coinbase = "[0-9a-fA-F]{40}"$', f'# {h["role"]}: never mines; coinbase unused\ncoinbase = "{ZERO_COINBASE}"', t, flags=re.M)
        files["node.sync.toml"] = t
    files["citrate-node.env"] = G.render_env(prof)
    # The node stops cleanly on SIGINT (tokio ctrl_c) and did not exit on SIGTERM on the
    # 2026-11-09 rehearsal, so systemd's default stop would wait out its timeout and kill.
    unit = G.render_unit(real(etc), real(data), real(binp))
    unit = unit.replace("RestartSec=5s\n", "RestartSec=5s\nKillSignal=SIGINT\nTimeoutStopSec=90s\n", 1)
    files["citrate-node.service"] = unit
    files["launch.json"] = json.dumps({"binary": binp, "config": f"{etc}/node.toml", "env_file": f"{etc}/citrate-node.env", "data_dir": data}, indent=2) + "\n"
    return files


def cmd_render(a, fleet: Fleet, src: dict) -> int:
    net = a.network
    if net == "r1006" and fleet.transport != "local":
        raise Refuse("rendering r1006 is for the devnet's stand-in r1006 only; the fleet's r1006 is parked as it is")
    ids = identities(a, fleet)
    stk = stakers(fleet, ids, src)
    binary = Path(a.binary)
    if not binary.is_file():
        raise Refuse(f"no binary at {binary}")
    bin_sha = sha256(binary)
    out = Path(a.state) / "render" / net
    if out.exists():
        shutil.rmtree(out)
    hosts = {}
    for h in fleet.hosts():
        files = render_host(fleet, h, net, src, ids, stk, bin_sha)
        d = out / h["name"]
        d.mkdir(parents=True)
        man = {}
        for name, content in files.items():
            (d / name).write_text(content)
            man[name] = sha256(d / name)
        man["citrate-node"] = bin_sha
        write_json(d / "manifest.json", {"network": net, "host": h["name"], "role": h["role"], "files": man})
        hosts[h["name"]] = {"role": h["role"], "files": man}
    write_json(out / "render-manifest.json", {
        "schema": "r1007-render/1", "network": net, "genesis": src[f"{net}_genesis"],
        "params_render": src["params_render"] if net == "r1007" else None,
        "source_commit": git_head(), "binary_sha256": bin_sha, "hosts": hosts,
    })
    log(f"rendered {len(hosts)} hosts for {net} -> {out}")
    return 0


def git_head() -> str:
    r = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


# ─── check (the fingerprint check) ───────────────────────────────────────────


def parse_toml(text: str) -> dict:
    try:
        import tomllib  # Python 3.11+
    except ImportError:  # 3.10 hosts: the same parser, packaged as tomli
        import tomli as tomllib  # type: ignore[no-redef]

    return tomllib.loads(text)


def parse_env(text: str) -> dict[str, str]:
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


def secret_scan(name: str, text: str, allowed: set[str]) -> list[str]:
    out = []
    for rx in SECRET_RES:
        if rx.search(text):
            out.append(f"{name}: matches a key-material pattern ({rx.pattern})")
    for m in HEX64.finditer(text):
        v = m.group(1).lower()
        if v not in allowed:
            out.append(f"{name}: an unexplained 32-byte hex value {v[:8]}… (key material?)")
    return out


def check_static(fleet: Fleet, net: str, src: dict, rdir: Path, ids: dict, stk: dict) -> list[str]:
    """Problems with the rendered set (empty = every config matches the compiled genesis)."""
    probs: list[str] = []
    man = load_json(rdir / "render-manifest.json")
    if man.get("genesis") != src[f"{net}_genesis"]:
        probs.append(f"render manifest genesis {man.get('genesis')} is not this checkout's {src[f'{net}_genesis']}")
    if net == "r1007" and man.get("params_render") != src["params_render"]:
        probs.append("render manifest params differ from this checkout's R1007_CHAIN_PARAMS (re-render)")
    p = src["params"]
    allowed = {src["r1007_genesis"][2:], src["r1006_genesis"][2:]} | {i["peer_id"][6:] for i in ids.values()}
    consensus_envs: dict[str, dict] = {}
    for h in fleet.hosts():
        d = rdir / h["name"]
        name = h["name"]
        hm = load_json(d / "manifest.json")
        for f, digest in hm["files"].items():
            if f != "citrate-node" and sha256(d / f) != digest:
                probs.append(f"{name}/{f}: changed after render")
        for f in hm["files"]:
            if f != "citrate-node":
                probs += secret_scan(f"{name}/{f}", (d / f).read_text(), allowed)
        tomls = {"node.sync.toml": False}
        if h["role"] == "producer":
            tomls["node.mine.toml"] = True
        elif (d / "node.mine.toml").exists():
            probs.append(f"{name}: a {h['role']} must not have a mining config")
        for f, mining in tomls.items():
            try:
                t = parse_toml((d / f).read_text())
            except Exception as e:  # noqa: BLE001
                probs.append(f"{name}/{f}: not TOML ({e})")
                continue
            c, ck, mn, rpc, st, nw = t["chain"], t.get("checkpoint", {}), t["mining"], t["rpc"], t["storage"], t["network"]
            if c.get("chain_id") != fleet.d["chain_id"]:
                probs.append(f"{name}/{f}: chain_id {c.get('chain_id')}")
            if c.get("genesis_profile") != net:
                probs.append(f"{name}/{f}: genesis_profile {c.get('genesis_profile')!r}, not {net!r}")
            if net == "r1007":
                if ck.get("interval") != p["checkpoint_interval"]:
                    probs.append(f"{name}/{f}: [checkpoint] interval {ck.get('interval')} != {p['checkpoint_interval']}")
                if ck.get("committee_size") != p["committee_size"]:
                    probs.append(f"{name}/{f}: [checkpoint] committee_size {ck.get('committee_size')} != {p['committee_size']}")
                vd = ck.get("vote_depth", src["default_vote_depth"])
                if vd != p["checkpoint_vote_depth"]:
                    probs.append(f"{name}/{f}: [checkpoint] vote_depth {vd} != {p['checkpoint_vote_depth']}")
                if c.get("ghostdag_k") != p["ghostdag_k"]:
                    probs.append(f"{name}/{f}: ghostdag_k {c.get('ghostdag_k')} != {p['ghostdag_k']}")
            if not str(rpc.get("listen_addr", "")).startswith("127.0.0.1:") or not str(rpc.get("ws_addr", "127.0.0.1:")).startswith("127.0.0.1:"):
                probs.append(f"{name}/{f}: RPC is not loopback-only")
            if mn.get("enabled") is not mining:
                probs.append(f"{name}/{f}: mining enabled = {mn.get('enabled')}, expected {mining}")
            if h["role"] == "producer" and mn.get("coinbase", "").lower() != stk[name][2:]:
                probs.append(f"{name}/{f}: coinbase is not the registered staker")
            if h["role"] != "producer" and mn.get("coinbase") != ZERO_COINBASE:
                probs.append(f"{name}/{f}: a {h['role']} carries a coinbase")
            if not str(st.get("data_dir", "")).endswith(f"/var/lib/citrate/gen/{net}"):
                probs.append(f"{name}/{f}: data_dir {st.get('data_dir')} is not the {net} slot")
            boots = set(nw.get("bootstrap_nodes", []))
            me = bootnode(fleet, h, ids)
            if me in boots:
                probs.append(f"{name}/{f}: lists itself as a bootnode")
            for b in fleet.hosts("boot"):
                if b["name"] != name and bootnode(fleet, b, ids) not in boots:
                    probs.append(f"{name}/{f}: does not list {b['name']} as a bootnode")
        env = parse_env((d / "citrate-node.env").read_text())
        if env.get("CITRATE_VALIDATOR_REGISTRY", "").lower() != src["validator_registry"]:
            probs.append(f"{name}: CITRATE_VALIDATOR_REGISTRY is not the compiled registry {src['validator_registry']}")
        if env.get("CITRATE_VALIDATOR_ACTIVATION_HEIGHT") != str(src["validator_activation_height"]):
            probs.append(f"{name}: CITRATE_VALIDATOR_ACTIVATION_HEIGHT is not {src['validator_activation_height']}")
        if net == "r1007" and env.get("CITRATE_DAG_PRUNE_RETAIN", str(p["pruning_depth"])) != str(p["pruning_depth"]):
            probs.append(f"{name}: CITRATE_DAG_PRUNE_RETAIN {env.get('CITRATE_DAG_PRUNE_RETAIN')} != pruning_depth {p['pruning_depth']}")
        consensus_envs[name] = {k: v for k, v in env.items() if k != "CITRATE_METRICS"}
    if len({json.dumps(e, sort_keys=True) for e in consensus_envs.values()}) > 1:
        probs.append("the consensus environment differs between hosts (a fork risk)")
    return probs


def manifest_json(stdout: str) -> dict | None:
    """The JSON manifest `consensus --json` prints after the node's log lines: the text from
    the first line that is exactly `{`."""
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "{":
            try:
                return json.loads("\n".join(lines[i:]))
            except json.JSONDecodeError:
                return None
    return None


def check_binary(fleet: Fleet, net: str, src: dict, rdir: Path, binary: Path) -> list[str]:
    """Run the binary's own `consensus --json` on every rendered config: the node must bind the
    r1007 genesis with exactly R1007_CHAIN_PARAMS, and every node must print one fingerprint."""
    probs: list[str] = []
    fps: dict[str, str] = {}
    for h in fleet.hosts():
        for f in ["node.sync.toml"] + (["node.mine.toml"] if h["role"] == "producer" else []):
            text = (rdir / h["name"] / f).read_text()
            with tempfile.TemporaryDirectory(prefix="r1007-check.") as tmp:
                # A throwaway data dir: the check never opens a host's real one.
                text = re.sub(r'^data_dir = ".*"$', f'data_dir = "{tmp}/data"', text, flags=re.M)
                cfg = Path(tmp) / "node.toml"
                cfg.write_text(text)
                r = subprocess.run([str(binary), "--config", str(cfg), "consensus", "--json"], capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                probs.append(f"{h['name']}/{f}: consensus --json failed: {r.stderr.strip()[-200:]}")
                continue
            m = manifest_json(r.stdout)
            if m is None:
                probs.append(f"{h['name']}/{f}: consensus --json printed no manifest")
                continue
            if str(m.get("genesis_hash", "")).lower() != src[f"{net}_genesis"]:
                probs.append(f"{h['name']}/{f}: the binary binds genesis {m.get('genesis_hash')}, not {src[f'{net}_genesis']}")
            if net == "r1007":
                rules = str(m.get("genesis_rules", ""))
                want = "|params:" + src["params_render"]
                if not rules.endswith(want):
                    probs.append(f"{h['name']}/{f}: the binary's genesis binding does not end in {want!r}: {rules[-160:]!r}")
                if str(m.get("r1007_genesis", "")).lower() != src["r1007_genesis"]:
                    probs.append(f"{h['name']}/{f}: the binary compiles R1007_GENESIS {m.get('r1007_genesis')}, not this checkout's")
            fps[f"{h['name']}/{f}"] = str(m.get("fingerprint"))
    if len(set(fps.values())) > 1:
        probs.append(f"consensus fingerprints differ across rendered configs: {sorted(set(fps.values()))}")
    elif fps:
        log(f"every rendered config gives fingerprint {next(iter(fps.values()))}")
    return probs


def cmd_check(a, fleet: Fleet, src: dict) -> int:
    rdir = Path(a.state) / "render" / a.network
    ids = identities(a, fleet)
    probs = check_static(fleet, a.network, src, rdir, ids, stakers(fleet, ids, src))
    if a.binary:
        probs += check_binary(fleet, a.network, src, rdir, Path(a.binary))
    for p in probs:
        print(f"FAIL  {p}")
    if probs:
        return 1
    log(f"check: {len(fleet.hosts())} rendered nodes match the compiled {a.network} genesis"
        + (f" and R1007_CHAIN_PARAMS ({src['params_render']})" if a.network == "r1007" else "")
        + ("; binary fingerprints agree" if a.binary else ""))
    return 0


# ─── plan ────────────────────────────────────────────────────────────────────


def plan_steps(fleet: Fleet) -> list[dict]:
    b = [h["name"] for h in fleet.hosts("boot")]
    pr = [h["name"] for h in fleet.hosts("producer")]
    rp = [h["name"] for h in fleet.hosts("rpc")]
    return [
        {"step": "prepare", "owner_go": "GO-1 (stage)", "hosts": b + pr + rp, "reversible": True,
         "does": "park r1006 as slot r1006 (nothing moved), record the pre-cut service state, stage the r1007 bundle "
                 "(binary + configs, hash-checked), copy each host's own noise.key (+ proposer.key on producers) into the "
                 "r1007 slot on the host. r1006 keeps running."},
        {"step": "cut", "owner_go": "GO-2 (cut)", "hosts": rp + pr + b, "reversible": True,
         "does": "stop the explorer indexer, then r1006 on rpc-1, the producers and the boots (reverse of bring-up). Data kept."},
        {"step": "boots", "owner_go": "GO-2", "hosts": b, "reversible": True,
         "does": "switch to r1007 and start, mining off. Gate: each serves the r1007 block 0."},
        {"step": "producers", "owner_go": "GO-2", "hosts": pr, "reversible": True,
         "does": "staggered: the first producer starts mining; each next one starts mining off, must reach the same tip "
                 "(same hash at a common height), then mines. Gate per producer: its staker appears as a block miner."},
        {"step": "rpc", "owner_go": "GO-2", "hosts": rp, "reversible": True,
         "does": "switch rpc-1 to r1007, start (mining off). Gate: synced to the producers' tip."},
        {"step": "indexer", "owner_go": "GO-3 (indexer reset)", "hosts": [h["name"] for h in fleet.hosts() if h.get("indexer")], "reversible": "from the fork",
         "does": "confirm citratescan-indexer is stopped; from the operator machine, fork the explorer DB's managed cluster "
                 "(doctl databases fork, --db-cluster-id) and give the fork one trusted source (--db-fork-rule); then on the "
                 "indexer host pnpm indexer:reset --genesis R1007 (dry run), --confirm (citrate-explorer DEPLOY.md §4a), start "
                 "citratescan-indexer. Nothing is written to the host's disk. Gate: /api/health reports the r1007 genesis."},
        {"step": "health", "owner_go": None, "hosts": b + pr + rp, "reversible": True,
         "does": "every node serves the r1007 block 0; every producer's staker is sealing; peer counts at or above the "
                 "floor; the same hash at a common height on every node."},
        {"step": "rollback", "owner_go": "GO-R (rollback, any time before G5)", "hosts": rp + pr + b, "reversible": True,
         "does": "stop r1007 everywhere, switch every host back to slot r1006, start exactly the services the pre-cut "
                 "snapshot recorded as running. The explorer DB is restored from the indexer-step fork by hand (runbook 3.1); "
                 "this step does not do it. Gate: r1006 health, heads at or above the pre-cut heads."},
    ]


def cmd_plan(a, fleet: Fleet, src: dict) -> int:
    steps = plan_steps(fleet)
    if a.json:
        print(json.dumps({"genesis": src["r1007_genesis"], "params": src["params_render"], "steps": steps}, indent=2))
        return 0
    print(f"r1007 bring-up: block 0 {src['r1007_genesis']}\nparams {src['params_render']}\n")
    for i, s in enumerate(steps, 1):
        go = f"  [owner: {s['owner_go']}]" if s["owner_go"] else ""
        print(f"{i}. {s['step']}{go}\n   hosts: {', '.join(s['hosts']) or '-'}\n   {s['does']}\n")
    return 0


# ─── run ─────────────────────────────────────────────────────────────────────


def wait_until(what: str, fn, minutes: float) -> object:
    until = time.time() + minutes * 60
    last = None
    while time.time() < until:
        try:
            v = fn()
            if v:
                return v
        except Fail as e:
            last = e
        time.sleep(3)
    raise Fail(f"gate timed out ({minutes} min): {what}" + (f" (last: {last})" if last else ""))


def head(t: Transport, h: dict, at: int | None = None) -> dict:
    args = ["head"] + (["--at", str(at)] if at is not None else [])
    return t.agent(h, *args, mutating=False)


def same_tip(t: Transport, hosts: list[dict], lag: int) -> dict:
    heads = {h["name"]: head(t, h) for h in hosts}
    common = min(x["head"] for x in heads.values()) - lag
    if common < 1:
        raise Fail(f"heads too low for a common block ({heads})")
    hashes = {h["name"]: head(t, h, common)["hash_at"] for h in hosts}
    if len(set(hashes.values())) != 1:
        raise Fail(f"different blocks at height {common}: {hashes}")
    return {"common": common, "hash": next(iter(hashes.values())), "heads": {k: v["head"] for k, v in heads.items()}}


def gate_block0(t: Transport, h: dict, genesis: str) -> bool:
    return head(t, h)["block0"] == genesis


def run_health(a, fleet: Fleet, t: Transport, src: dict, net: str) -> dict:
    genesis = src[f"{net}_genesis"]
    hosts = fleet.hosts()
    report: dict = {"network": net, "nodes": {}}
    for h in hosts:
        x = head(t, h)
        report["nodes"][h["name"]] = x
        if x["block0"] != genesis:
            raise Fail(f"{h['name']} serves block 0 {x['block0']}, not {genesis}")
        if x["peers"] < a.min_peers:
            raise Fail(f"{h['name']} has {x['peers']} peers (< {a.min_peers})")
    tip = same_tip(t, hosts, a.lag)
    report["tip"] = tip
    if net == "r1007" or a.require_sealing:
        ids = identities(a, fleet)
        stk = stakers(fleet, ids, src)
        miners = t.agent(fleet.hosts("producer")[0], "miners", "--last", str(a.last), mutating=False)["miners"]
        missing = [n for n, s in stk.items() if s not in miners]
        report["miners"] = miners
        if missing:
            raise Fail(f"not sealing in the last {a.last} blocks: {', '.join(missing)}")
    log(f"health {net}: {len(hosts)} nodes on block 0 {genesis[:10]}…, same block at {tip['common']}, peers >= {a.min_peers}"
        + (", every producer sealing" if "miners" in report else ""))
    return report


def step_prepare(a, fleet: Fleet, t: Transport, src: dict) -> None:
    rdir = Path(a.state) / "render" / "r1007"
    if check_static(fleet, "r1007", src, rdir, identities(a, fleet), stakers(fleet, identities(a, fleet), src)):
        raise Fail("the rendered r1007 set does not pass check; run check")
    binary = Path(a.binary)
    want = load_json(rdir / "render-manifest.json")["binary_sha256"]
    if sha256(binary) != want:
        raise Fail("the binary is not the one the render recorded")
    for h in fleet.hosts():
        if fleet.transport == "ssh":
            t.agent(h, "park-r1006", step="prepare")
        t.agent(h, "snapshot", step="prepare")
        inc = "/var/lib/citrate/ceremony/incoming/r1007"
        for f in list((rdir / h["name"]).iterdir()) + [binary]:
            t.put(h, f, f"{inc}/{f.name if f != binary else 'citrate-node'}", "prepare")
        real_inc = (fleet.root(h).rstrip("/") + inc) if fleet.transport == "local" else inc
        t.agent(h, "stage", "--gen", "r1007", "--incoming", real_inc, step="prepare")
        keys = "noise,proposer" if h["role"] == "producer" else "noise"
        t.agent(h, "seed-keys", "--from-gen", "r1006", "--to-gen", "r1007", "--keys", keys, step="prepare")
        log(f"prepare {h['name']}: staged r1007, keys seeded on the host ({keys})")


INDEXER_UNIT = "citratescan-indexer"
INDEXER_FORK_NAME = "citratescan-r1007-precut"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# A DO managed-database trusted source: one IP, one droplet, one tag or one app. Never a CIDR.
FORK_RULE_RE = re.compile(r"^(ip_addr:(\d{1,3}\.){3}\d{1,3}|droplet:\d+|tag:[A-Za-z0-9_.:-]+|app:[0-9a-f-]{36})$")


def ssh_run(t: Transport, h: dict, cmd: str, step: str) -> None:
    """One shell command on a fleet host, under the owner's go for this step."""
    t.require_go(step, h)
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", h["ssh"], cmd], check=True)


def operator_run(argv: list[str]) -> str:
    """One command on the operator machine (doctl). Returns stdout."""
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def stop_indexer(fleet: Fleet, t: Transport, step: str) -> None:
    """Stop the explorer indexer and confirm it is stopped, so it never writes another
    chain's blocks into the explorer DB."""
    cmd = f"systemctl stop {INDEXER_UNIT} && ! systemctl is-active --quiet {INDEXER_UNIT}"
    for h in [h for h in fleet.hosts() if h.get("indexer")]:
        if fleet.transport == "local":
            log(f"{step}: would run on {h['name']}: {cmd}")
            continue
        ssh_run(t, h, cmd, step)
        log(f"{step} {h['name']}: {INDEXER_UNIT} stopped")


def step_cut(a, fleet: Fleet, t: Transport, src: dict) -> None:
    stop_indexer(fleet, t, "cut")  # first: before rpc-1 changes chain under it
    for h in fleet.hosts("rpc") + fleet.hosts("producer") + fleet.hosts("boot"):
        t.agent(h, "stop", step="cut")
        log(f"cut {h['name']}: r1006 stopped (data kept)")


def step_boots(a, fleet: Fleet, t: Transport, src: dict) -> None:
    g = src["r1007_genesis"]
    for h in fleet.hosts("boot"):
        t.agent(h, "switch", "--gen", "r1007", step="boots")
        t.agent(h, "start", step="boots")
        wait_until(f"{h['name']} serves the r1007 block 0", lambda h=h: gate_block0(t, h, g), a.gate_minutes)
        log(f"boots {h['name']}: up on r1007")


def step_producers(a, fleet: Fleet, t: Transport, src: dict) -> None:
    g = src["r1007_genesis"]
    prods = fleet.hosts("producer")
    stk = stakers(fleet, identities(a, fleet), src)
    up: list[dict] = []
    for i, h in enumerate(prods):
        t.agent(h, "switch", "--gen", "r1007", step="producers")
        t.agent(h, "start", step="producers")
        wait_until(f"{h['name']} serves the r1007 block 0", lambda h=h: gate_block0(t, h, g), a.gate_minutes)
        if up:
            # Join by sync: the same block as the producers already up, at a common height.
            wait_until(f"{h['name']} reaches the producers' tip", lambda h=h: same_tip(t, up + [h], a.lag), a.gate_minutes)
        t.agent(h, "mining", "on", "--expect-genesis", g, step="producers")
        up.append(h)
        wait_until(f"{h['name']} seals a block",
                   lambda h=h: stk[h["name"]] in t.agent(h, "miners", "--last", str(a.last), mutating=False)["miners"],
                   a.gate_minutes)
        log(f"producers {h['name']}: sealing ({i + 1}/{len(prods)})")
        if i + 1 < len(prods):
            time.sleep(a.stagger_seconds)


def step_rpc(a, fleet: Fleet, t: Transport, src: dict) -> None:
    g = src["r1007_genesis"]
    prods = fleet.hosts("producer")
    for h in fleet.hosts("rpc"):
        t.agent(h, "switch", "--gen", "r1007", step="rpc")
        t.agent(h, "start", step="rpc")
        wait_until(f"{h['name']} serves the r1007 block 0", lambda h=h: gate_block0(t, h, g), a.gate_minutes)
        wait_until(f"{h['name']} reaches the producers' tip", lambda h=h: same_tip(t, prods + [h], a.lag), a.gate_minutes)
        log(f"rpc {h['name']}: synced on r1007")


def fork_explorer_db(a) -> str:
    """Back up the explorer DB as a fork of its DO managed cluster, from the operator
    machine (citrate-explorer docs/ops/VERIFY_V2_MIGRATION_RUNBOOK.md 2.1-2.2). Nothing is
    written to the indexer host's disk. Returns the fork id."""
    listed = json.loads(operator_run(["doctl", "databases", "list", "-o", "json"]) or "[]")
    if any(d.get("name") == INDEXER_FORK_NAME for d in listed):
        raise Refuse(f"a database named {INDEXER_FORK_NAME} already exists; check and delete it before a new backup")
    operator_run(["doctl", "databases", "fork", INDEXER_FORK_NAME, "--restore-from-cluster-id", a.db_cluster_id, "--wait"])
    listed = json.loads(operator_run(["doctl", "databases", "list", "-o", "json"]) or "[]")
    fork = [d for d in listed if d.get("name") == INDEXER_FORK_NAME]
    if len(fork) != 1 or fork[0].get("status") != "online":
        raise Fail(f"the fork {INDEXER_FORK_NAME} is not online: {fork}")
    fid = fork[0]["id"]
    # A new DO database has no trusted sources, which means any IP may connect. If the rule
    # cannot be added, delete the fork we just made: an open copy of production data must not
    # stay, and a re-run would otherwise refuse on the existing name.
    try:
        operator_run(["doctl", "databases", "firewalls", "append", fid, "--rule", a.db_fork_rule])
    except subprocess.CalledProcessError as e:
        try:
            operator_run(["doctl", "databases", "delete", fid, "--force"])
        except subprocess.CalledProcessError:
            raise Fail(f"the fork {INDEXER_FORK_NAME} ({fid}) has no trusted source and could not be deleted; "
                       f"delete it now: doctl databases delete {fid}") from e
        raise Fail(f"could not add the trusted source to {INDEXER_FORK_NAME}; the fork was deleted. "
                   f"Fix --db-fork-rule and re-run") from e
    log(f"indexer: explorer DB forked to {INDEXER_FORK_NAME} ({fid}), trusted source {a.db_fork_rule}")
    return fid


def step_indexer(a, fleet: Fleet, t: Transport, src: dict) -> None:
    hosts = [h for h in fleet.hosts() if h.get("indexer")]
    g = src["r1007_genesis"]
    host_cmds = [
        f"systemctl stop {INDEXER_UNIT} && ! systemctl is-active --quiet {INDEXER_UNIT}",
        f"cd /opt/citrate-explorer && pnpm indexer:reset --genesis {g}",
        f"cd /opt/citrate-explorer && pnpm indexer:reset --genesis {g} --confirm",
        f"systemctl start {INDEXER_UNIT}",
    ]
    if fleet.transport == "local":
        log("indexer: SKIP on the devnet (no explorer); on the fleet this step runs:")
        log(f"  operator: doctl databases fork {INDEXER_FORK_NAME} --restore-from-cluster-id <--db-cluster-id> --wait,"
            f" then doctl databases firewalls append <fork> --rule <--db-fork-rule>")
        for h in hosts:
            for c in host_cmds:
                log(f"  would run on {h['name']}: {c}")
        return
    cid = getattr(a, "db_cluster_id", None)
    rule = getattr(a, "db_fork_rule", None)
    if not cid or not UUID_RE.match(cid):
        raise Refuse("the indexer step needs --db-cluster-id <the explorer DB's DO cluster id> (a UUID)")
    if not rule or not FORK_RULE_RE.match(rule):
        raise Refuse("the indexer step needs --db-fork-rule ip_addr:<ip> | droplet:<id> | tag:<t> | app:<id>"
                     " (the fork's only trusted source)")
    for h in hosts:
        t.require_go("indexer", h)
    for h in hosts:
        ssh_run(t, h, host_cmds[0], "indexer")
    fork_explorer_db(a)
    for h in hosts:
        for c in host_cmds[1:]:
            ssh_run(t, h, c, "indexer")
        log(f"indexer {h['name']}: reset to {g} and started")


def step_rollback(a, fleet: Fleet, t: Transport, src: dict) -> None:
    order = fleet.hosts("rpc") + fleet.hosts("producer") + fleet.hosts("boot")
    for h in order:
        t.agent(h, "stop", step="rollback")
    for h in reversed(order):  # boots first, as r1006 came up
        snap = t.agent(h, "rollback-target", mutating=False)
        t.agent(h, "switch", "--gen", snap.get("active") or "r1006", step="rollback")
        if snap.get("running"):
            t.agent(h, "start", step="rollback")
            if (snap.get("active") or "r1006") == "r1006":
                g = src["r1006_genesis"]
                wait_until(f"{h['name']} serves the r1006 block 0 again", lambda h=h: gate_block0(t, h, g), a.gate_minutes)
        log(f"rollback {h['name']}: slot {snap.get('active') or 'r1006'}, {'started' if snap.get('running') else 'left stopped (as before the cut)'}")


def step_devnet_r1006(a, fleet: Fleet, t: Transport, src: dict) -> None:
    """Devnet only: bring up the stand-in r1006 the ceremony then cuts over (and rolls back to)."""
    if fleet.transport != "local":
        raise Refuse("devnet-r1006 is for the devnet only")
    rdir = Path(a.state) / "render" / "r1006"
    binary = Path(a.binary)
    for h in fleet.hosts():
        inc = Path(fleet.root(h)) / "var/lib/citrate/ceremony/incoming/r1006"
        inc.mkdir(parents=True, exist_ok=True)
        for f in (rdir / h["name"]).iterdir():
            shutil.copy2(f, inc / f.name)
        shutil.copy2(binary, inc / "citrate-node")
        t.agent(h, "stage", "--gen", "r1006", "--incoming", str(inc))
        t.agent(h, "switch", "--gen", "r1006")
        t.agent(h, "start")
    g = src["r1006_genesis"]
    for h in fleet.hosts():
        wait_until(f"{h['name']} serves the r1006 block 0", lambda h=h: gate_block0(t, h, g), a.gate_minutes)
    for h in fleet.hosts("producer"):
        t.agent(h, "mining", "on", "--expect-genesis", g)
    log(f"devnet-r1006: {len(fleet.hosts())} hosts up on the stand-in r1006")


def health_kept(fleet: Fleet, t: Transport) -> None:
    """After a rollback: every node is back at or above the head it had at the cut (data kept)."""
    for h in fleet.hosts():
        snap = t.agent(h, "rollback-target", mutating=False)
        now = head(t, h)["head"]
        if snap.get("head") is not None and now < int(snap["head"]):
            raise Fail(f"{h['name']} is at {now}, below its pre-cut head {snap['head']}: data was not kept")
    log("rollback: every node is at or above its pre-cut head (data kept)")


STEPS = {"devnet-r1006": step_devnet_r1006, "prepare": step_prepare, "cut": step_cut, "boots": step_boots, "producers": step_producers,
         "rpc": step_rpc, "indexer": step_indexer, "rollback": step_rollback}


def cmd_run(a, fleet: Fleet, src: dict) -> int:
    go = load_go(a.owner_go, src["r1007_genesis"])
    t = Transport(fleet, go)
    if a.step == "health":
        rep = run_health(a, fleet, t, src, a.network)
        if a.expect_kept:
            health_kept(fleet, t)
        write_json(Path(a.state) / f"health-{a.network}.json", rep)
        return 0
    if a.step not in STEPS:
        raise Refuse(f"unknown step {a.step}; one of {', '.join(list(STEPS) + ['health'])}")
    t0 = time.time()
    STEPS[a.step](a, fleet, t, src)
    with open(Path(a.state) / "timings.log", "a") as f:
        f.write(f"{a.step} {time.time() - t0:.1f}s\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("collect", "render", "check", "plan", "run", "health"))
    ap.add_argument("step", nargs="?")
    ap.add_argument("--fleet", type=Path, default=HERE / "fleet.r1007.json")
    ap.add_argument("--state", default=str(Path.home() / "r1007-state"))
    ap.add_argument("--network", choices=("r1007", "r1006"), default="r1007")
    ap.add_argument("--binary")
    ap.add_argument("--mint", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--owner-go")
    ap.add_argument("--gate-minutes", type=float, default=10)
    ap.add_argument("--stagger-seconds", type=float, default=30)
    ap.add_argument("--min-peers", type=int, default=2)
    ap.add_argument("--last", type=int, default=60)
    ap.add_argument("--lag", type=int, default=3)
    ap.add_argument("--db-cluster-id", help="indexer step: the explorer DB's DO managed-cluster id")
    ap.add_argument("--db-fork-rule", help="indexer step: the fork's one trusted source, e.g. ip_addr:<ip>")
    ap.add_argument("--require-sealing", action="store_true")
    ap.add_argument("--expect-kept", action="store_true", help="health after a rollback: heads at or above the pre-cut heads")
    a = ap.parse_args(argv)
    try:
        fleet = Fleet(a.fleet)
        src = P.load(REPO)
        if a.cmd == "health":
            a.step = "health"
            a.cmd = "run"
        if a.cmd in ("collect", "render") and not a.binary and a.cmd == "render":
            raise Refuse("render needs --binary (its sha256 goes into every bundle's manifest)")
        if a.cmd == "collect" and fleet.transport == "local" and not a.binary:
            raise Refuse("collect on the devnet needs --binary (host-identity)")
        return {"collect": cmd_collect, "render": cmd_render, "check": cmd_check, "plan": cmd_plan, "run": cmd_run}[a.cmd](a, fleet, src)
    except Refuse as e:
        print(f"ceremony: refused: {e}", file=sys.stderr)
        return 2
    except (Fail, P.ParamsError, PL.ToolError) as e:
        print(f"ceremony: FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
