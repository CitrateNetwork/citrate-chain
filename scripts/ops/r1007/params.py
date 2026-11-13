#!/usr/bin/env python3
"""The r1007 genesis identity and chain parameters, read from this checkout's source.

Rule 9: nothing here restates a consensus value. Every value is parsed at run time from
the file that compiles it, so the ceremony tooling and the node binary built from the
same commit cannot disagree without one of the checks failing:

  R1007_GENESIS, R1006_GENESIS   core/consensus/src/hardening.rs
  R1007_CHAIN_PARAMS             core/consensus/src/genesis_params.rs
  DEFAULT_VOTE_DEPTH             core/consensus/src/checkpoint.rs (the node's [checkpoint] default)
  ValidatorRegistry + producers  core/economics/assets/r1006/validators.json (r1007 shares it)

`render_params` reproduces `GenesisChainParams::render()` (field order, `name=value`,
joined by `,`). The node appends exactly that string after `|params:` in the genesis
binding of its consensus fingerprint, which `ceremony.py check --binary` compares.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HARDENING = Path("core/consensus/src/hardening.rs")
GENESIS_PARAMS = Path("core/consensus/src/genesis_params.rs")
CHECKPOINT = Path("core/consensus/src/checkpoint.rs")
VALIDATORS = Path("core/economics/assets/r1006/validators.json")

# The field order of `GenesisChainParams` and of its `render()`.
PARAM_FIELDS = (
    "slot_duration_secs",
    "max_future_drift_secs",
    "pruning_depth",
    "undo_window",
    "ghostdag_k",
    "max_parents",
    "merge_depth",
    "checkpoint_interval",
    "committee_size",
    "checkpoint_vote_depth",
    "include_gas_limit",
    "accept_gas_limit",
    "validator_activation_height",
)


class ParamsError(Exception):
    pass


def _read(repo: Path, rel: Path) -> str:
    try:
        return (repo / rel).read_text()
    except OSError as e:
        raise ParamsError(f"cannot read {rel}: {e}") from None


def genesis_const(repo: Path, name: str) -> str:
    """`pub const <name>: [u8; 32] = hex32("…");` -> "0x…" (lower case)."""
    src = _read(repo, HARDENING)
    m = re.search(rf"pub const {re.escape(name)}: \[u8; 32\] =\s*hex32\(\"([0-9a-f]{{64}})\"\);", src)
    if not m:
        raise ParamsError(f"{name} is not a hex32 constant in {HARDENING}")
    return "0x" + m.group(1)


def chain_params(repo: Path, name: str = "R1007_CHAIN_PARAMS") -> dict[str, int]:
    """The struct literal `pub const <name>: GenesisChainParams = GenesisChainParams { … };`."""
    src = _read(repo, GENESIS_PARAMS)
    m = re.search(rf"pub const {re.escape(name)}: GenesisChainParams = GenesisChainParams \{{(.*?)\}};", src, re.S)
    if not m:
        raise ParamsError(f"{name} is not a GenesisChainParams literal in {GENESIS_PARAMS}")
    body = re.sub(r"//[^\n]*", "", m.group(1))
    got: dict[str, int] = {}
    for k, v in re.findall(r"(\w+)\s*:\s*([0-9_]+)\s*,", body):
        got[k] = int(v.replace("_", ""))
    if tuple(got) != PARAM_FIELDS:
        raise ParamsError(
            f"{name} fields {tuple(got)} are not the expected {PARAM_FIELDS}: the struct changed, update params.py"
        )
    return got


def render_params(p: dict[str, int]) -> str:
    """`GenesisChainParams::render()`: name=value in field order, joined by `,`."""
    return ",".join(f"{k}={p[k]}" for k in PARAM_FIELDS)


def default_vote_depth(repo: Path) -> int:
    src = _read(repo, CHECKPOINT)
    m = re.search(r"pub const DEFAULT_VOTE_DEPTH: u64 = ([0-9_]+);", src)
    if not m:
        raise ParamsError(f"DEFAULT_VOTE_DEPTH not found in {CHECKPOINT}")
    return int(m.group(1).replace("_", ""))


def validators(repo: Path) -> dict:
    try:
        d = json.loads(_read(repo, VALIDATORS))
    except json.JSONDecodeError as e:
        raise ParamsError(f"{VALIDATORS}: {e}") from None
    if d.get("status") != "final":
        raise ParamsError(f"{VALIDATORS} status is {d.get('status')!r}, not final")
    return d


# D-K3 (owner 2026-11-10): the r1007 block 0 needs fresh non-producer keys. The
# genesis is pending until an r1007 alloc built from fresh role inputs exists
# with final inputs (docs/consensus/R1007_GENESIS.md §1.1). The roles come from
# the Rust table the node's own refusal uses (core/economics/src/r1007.rs).
R1007_ALLOC = Path("core/economics/assets/r1007/alloc.json")
R1007_RS = Path("core/economics/src/r1007.rs")


def r1007_pending(repo: Path) -> list[str]:
    """Why the r1007 genesis cannot be rendered for the fleet yet; [] when ready."""
    alloc = repo / R1007_ALLOC
    if alloc.is_file():
        try:
            status = json.loads(alloc.read_text()).get("inputsStatus")
        except json.JSONDecodeError as e:
            raise ParamsError(f"{R1007_ALLOC}: {e}") from None
        if status == "final":
            return []
        why = f"{R1007_ALLOC} inputsStatus is {status!r}, not final"
    else:
        why = f"no {R1007_ALLOC} (built from fresh role inputs) yet"
    table = _read(repo, R1007_RS)
    start = table.find("pub const ROTATED_R1006_KEYS")
    roles = re.findall(r'role: "([A-Z0-9_]+)"', table[start:]) if start >= 0 else []
    if not roles:
        raise ParamsError(f"{R1007_RS}: ROTATED_R1006_KEYS not found")
    return [f"D-K3: r1007 is pending fresh non-producer keys ({why}); roles: {', '.join(roles)}"]


def genesis_timestamp(repo: Path) -> int:
    """`pub const GENESIS_TIMESTAMP: u64 = <unix seconds>;` in core/economics/src/r1007.rs
    (stamped at ceremony time by scripts/genesis/r1007/stamp_genesis.py)."""
    m = re.search(r"pub const GENESIS_TIMESTAMP: u64 = ([0-9_]+);", _read(repo, R1007_RS))
    if not m:
        raise ParamsError(f"{R1007_RS}: GENESIS_TIMESTAMP not found")
    return int(m.group(1).replace("_", ""))


def load(repo: Path) -> dict:
    """Everything the ceremony renders and checks against, from this checkout."""
    p = chain_params(repo)
    v = validators(repo)
    return {
        "r1007_genesis": genesis_const(repo, "R1007_GENESIS"),
        "r1006_genesis": genesis_const(repo, "R1006_GENESIS"),
        "params": p,
        "params_render": render_params(p),
        "default_vote_depth": default_vote_depth(repo),
        "validator_registry": v["validatorRegistry"].lower(),
        "validator_activation_height": p["validator_activation_height"],
        "r1007_pending": r1007_pending(repo),
        "r1007_genesis_timestamp": genesis_timestamp(repo),
        "producers": [
            {"name": x["name"], "staker": x["staker"].lower(), "proposer_pubkey": x["proposer_pubkey"].lower()}
            for x in v["validators"]
        ],
    }


if __name__ == "__main__":
    import sys

    print(json.dumps(load(Path(sys.argv[1] if len(sys.argv) > 1 else ".")), indent=2))
