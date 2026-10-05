#!/usr/bin/env python3
"""panic_inventory.py — aggregate clippy panic-lint JSON into the PANIC-S1 inventory.

Reads `cargo clippy --message-format=json` output (stdin or a file) produced by
scripts/ci/panic-inventory.sh, and writes:

  --summary <path>   per-crate x per-lint counts (the ratchet baseline shape)
  --sites <path>     one record per production panic site (for the ledger)

Only PRODUCTION code is counted: the clippy run covers `--lib --bins`, so
`#[cfg(test)]` modules are not compiled, and files under tests/ benches/
examples/ are dropped defensively. Spans outside the workspace (dependencies,
absolute paths) are ignored. Each site is de-duplicated by (lint, file, line, col)
because clippy reports a span once per target that compiles it.
"""
import argparse
import collections
import json
import sys

LINTS = [
    "unwrap_used", "expect_used", "panic", "unreachable",
    "indexing_slicing", "arithmetic_side_effects", "string_slice",
]
TEST_DIRS = ("tests", "benches", "examples")


def crate_of(path: str) -> str:
    parts = path.split("/")
    return "/".join(parts[:2]) if parts[0] in ("core", "crates") else parts[0]


def load_sites(stream):
    seen, sites = set(), []
    for line in stream:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg["message"]
        code = ((m.get("code") or {}).get("code") or "")
        if not code.startswith("clippy::"):
            continue
        lint = code[len("clippy::"):]
        if lint not in LINTS:
            continue
        spans = [s for s in m.get("spans", []) if s.get("is_primary")]
        if not spans:
            continue
        f = spans[0]["file_name"]
        if f.startswith("/") or any(p in TEST_DIRS for p in f.split("/")):
            continue
        key = (lint, f, spans[0]["line_start"], spans[0]["column_start"])
        if key in seen:
            continue
        seen.add(key)
        sites.append({"crate": crate_of(f), "file": f, "line": key[2], "col": key[3], "lint": lint})
    sites.sort(key=lambda s: (s["crate"], s["file"], s["line"], s["col"], s["lint"]))
    return sites


def summarize(sites):
    per = collections.defaultdict(collections.Counter)
    for s in sites:
        per[s["crate"]][s["lint"]] += 1
    crates = {c: {l: per[c][l] for l in LINTS if per[c][l]} for c in sorted(per)}
    return {"lints": LINTS, "total": len(sites), "crates": crates}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", help="clippy JSON (default: stdin)")
    ap.add_argument("--summary")
    ap.add_argument("--sites")
    a = ap.parse_args()
    sites = load_sites(open(a.input) if a.input else sys.stdin)
    summary = summarize(sites)
    if a.summary:
        with open(a.summary, "w") as fh:
            json.dump(summary, fh, indent=1, sort_keys=True)
            fh.write("\n")
    if a.sites:
        with open(a.sites, "w") as fh:
            json.dump(sites, fh, indent=0)
            fh.write("\n")
    print(f"production panic sites: {summary['total']} across {len(summary['crates'])} crates")


if __name__ == "__main__":
    main()
