#!/usr/bin/env python3
"""sequencer_devnet_tripwire.py: keep citrate-sequencer's `devnet` feature out
of every in-repo build.

`devnet` compiles out the production signature gate in the mempool. No non-dev
dependency edge in this repo may turn it on. The check parses every Cargo.toml
as TOML and runs a small Cargo-style feature resolver over the in-repo crates:

  * roots: every crate's `default` feature, and every non-dev dependency spec
    (inline `{ ... }` or table `[dependencies.x]`, plain or under
    `[target.*.dependencies]` / build-dependencies), with `workspace = true`
    merged against the nearest ancestor `[workspace.dependencies]`;
  * a dependency spec activates the target crate's `features` and, unless
    `default-features = false`, its `default`;
  * a feature activates its entries: own features (transitively), `dep:x`,
    `x/f` and `x?/f` forwards into in-repo dependencies (renames via
    `package = "..."` are resolved).

Flagged: any path that reaches (citrate-sequencer, devnet). dev-dependencies
are ignored on purpose (test-only builds may opt in). Unparseable manifests,
or a tree where citrate-sequencer no longer declares `devnet`, fail closed.

Usage: sequencer_devnet_tripwire.py              # scan the tree
       sequencer_devnet_tripwire.py --self-test  # prove each spelling is flagged
Env:   SEQ_DEVNET_TRIPWIRE_ROOT overrides the scanned root.
"""

from __future__ import annotations

import os
import sys
import tempfile
import tomllib
from pathlib import Path

TARGET_PKG = "citrate-sequencer"
TARGET_FEATURE = "devnet"
SKIP_PARTS = {"target", "node_modules", ".git"}
DEP_TABLES = ("dependencies", "build-dependencies")


class ManifestError(Exception):
    pass


def find_manifests(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_PARTS and (rel / d).as_posix() != "contracts/lib"
        )
        if "Cargo.toml" in filenames:
            out.append(Path(dirpath) / "Cargo.toml")
    return out


def load(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ManifestError(f"{path}: cannot parse as TOML: {e}") from e


def nearest_workspace(path: Path, root: Path, docs: dict[Path, dict]) -> dict:
    d = path.parent
    while True:
        m = d / "Cargo.toml"
        doc = docs.get(m)
        if doc is not None and "workspace" in doc:
            return doc["workspace"]
        if d == root or d == d.parent:
            return {}
        d = d.parent


def normalize_spec(alias: str, spec, ws: dict, where: str) -> dict:
    """Return {package, features, default, optional} for one dependency entry."""
    if isinstance(spec, str):
        return {"package": alias, "features": [], "default": True, "optional": False}
    if not isinstance(spec, dict):
        raise ManifestError(f"{where}: dependency {alias!r} has an unexpected form")
    features = list(spec.get("features", []))
    package = spec.get("package", alias)
    default = spec.get("default-features", spec.get("default_features", True))
    if spec.get("workspace") is True:
        wspec = ws.get("dependencies", {}).get(alias)
        if wspec is None:
            raise ManifestError(
                f"{where}: {alias!r} uses workspace = true but the workspace "
                "does not declare it"
            )
        if isinstance(wspec, dict):
            features = list(wspec.get("features", [])) + features
            package = wspec.get("package", package)
            wdefault = wspec.get("default-features", wspec.get("default_features", True))
            # Cargo: the member can only re-enable defaults the workspace turned off.
            default = wdefault or spec.get("default-features", False) is True
    return {
        "package": package,
        "features": features,
        "default": bool(default),
        "optional": bool(spec.get("optional", False)),
    }


def crate_deps(doc: dict, ws: dict, where: str) -> dict[str, dict]:
    """Non-dev dependencies of one manifest, keyed by alias."""
    tables = [doc.get(t, {}) for t in DEP_TABLES]
    for tgt in doc.get("target", {}).values():
        tables += [tgt.get(t, {}) for t in DEP_TABLES]
    deps: dict[str, dict] = {}
    for table in tables:
        for alias, spec in table.items():
            n = normalize_spec(alias, spec, ws, where)
            prev = deps.get(alias)
            if prev:  # same alias in several tables: union the activations
                prev["features"] += n["features"]
                prev["default"] |= n["default"]
                prev["optional"] &= n["optional"]
            else:
                deps[alias] = n
    return deps


def scan(root: Path) -> list[str]:
    root = root.resolve()
    paths = find_manifests(root)
    docs = {p: load(p) for p in paths}
    crates: dict[str, dict] = {}
    for p, doc in docs.items():
        name = doc.get("package", {}).get("name")
        if not name:
            continue
        where = p.relative_to(root).as_posix()
        crates[name] = {
            "where": where,
            "features": doc.get("features", {}),
            "deps": crate_deps(doc, nearest_workspace(p, root, docs), where),
        }

    seq = crates.get(TARGET_PKG)
    if seq is None or TARGET_FEATURE not in seq["features"]:
        # A renamed crate or feature would make this check vacuous.
        raise ManifestError(
            f"{TARGET_PKG} with a `{TARGET_FEATURE}` feature not found under {root}"
        )

    # Feature resolution over (package, feature) nodes, remembering how each
    # node was first reached so a violation prints its chain.
    Node = tuple[str, str]
    reached: dict[Node, tuple[str, Node | None]] = {}
    queue: list[Node] = []

    def activate(pkg: str, feat: str, why: str, parent: Node | None) -> None:
        if pkg not in crates or (pkg, feat) in reached:
            return
        reached[(pkg, feat)] = (why, parent)
        queue.append((pkg, feat))

    def enable_dep(owner: str, alias: str, why: str, parent: Node | None,
                   extra: str | None = None) -> None:
        spec = crates[owner]["deps"].get(alias)
        if spec is None:
            return
        pkg = spec["package"]
        if spec["default"]:
            activate(pkg, "default", why, parent)
        for f in spec["features"]:
            activate(pkg, f, why, parent)
        if extra is not None:
            activate(pkg, extra, why, parent)

    for name, c in sorted(crates.items()):
        activate(name, "default", f"{c['where']}: [features] default", None)
        for alias, spec in sorted(c["deps"].items()):
            if not spec["optional"]:
                enable_dep(name, alias, f"{c['where']}: dependency {alias!r}", None)

    while queue:
        node = queue.pop()
        pkg, feat = node
        c = crates[pkg]
        here = f"{c['where']}: feature {feat!r}"
        for entry in c["features"].get(feat, []):
            if not isinstance(entry, str):
                continue
            if entry.startswith("dep:"):
                enable_dep(pkg, entry[4:], here, node)
            elif "/" in entry:
                # `x/f` and the weak `x?/f` both count: the weak form only
                # needs x enabled some other way, so treat it as on (fail closed).
                alias, sub = entry.split("/", 1)
                enable_dep(pkg, alias.rstrip("?"), f"{here} -> {entry!r}", node, extra=sub)
            elif entry in c["features"]:
                activate(pkg, entry, here, node)
            else:
                enable_dep(pkg, entry, here, node)

    hit: Node = (TARGET_PKG, TARGET_FEATURE)
    if hit not in reached:
        return []
    chain = []
    cur: Node | None = hit
    while cur is not None:
        why, parent = reached[cur]
        chain.append(f"{cur[0]}/{cur[1]}  <=  {why}")
        cur = parent
    return [f"{TARGET_PKG}/{TARGET_FEATURE} is enabled in an in-repo build:"] + [
        "  " + line for line in chain
    ]


# ── self-test ───────────────────────────────────────────────────────────────
WS_ROOT = '[workspace]\nmembers = ["seq", "app"]\n'
SEQ = '[package]\nname = "citrate-sequencer"\nversion = "0.1.0"\n\n[features]\ndefault = []\ndevnet = []\n'
APP = '[package]\nname = "app"\nversion = "0.1.0"\n\n'

CASES: list[tuple[str, bool, dict[str, str]]] = [
    ("clean control", False, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ + 'other = []\n',
        "app/Cargo.toml": APP + '[dependencies]\ncitrate-sequencer = { path = "../seq" }\n\n'
        '[features]\ndefault = []\nopt-in = ["citrate-sequencer/devnet"]\n',
    }),
    ("dev-dependency only (allowed)", False, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dev-dependencies]\ncitrate-sequencer = { path = "../seq", features = ["devnet"] }\n',
    }),
    ("single-line default", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ.replace("default = []", 'default = ["devnet"]'),
        "app/Cargo.toml": APP,
    }),
    ("multi-line default", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ.replace("default = []", 'default = [\n    "devnet",\n]'),
        "app/Cargo.toml": APP,
    }),
    ("default forwarded through own feature", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ.replace("default = []", 'default = ["dev"]\ndev = ["devnet"]'),
        "app/Cargo.toml": APP,
    }),
    ("inline dependency features", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dependencies]\ncitrate-sequencer = { path = "../seq", features = ["devnet"] }\n',
    }),
    ("table-form dependency features", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dependencies.citrate-sequencer]\npath = "../seq"\nfeatures = [\n  "devnet",\n]\n',
    }),
    ("target-specific dependency", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + "[target.'cfg(unix)'.dependencies]\ncitrate-sequencer = { path = \"../seq\", features = [\"devnet\"] }\n",
    }),
    ("workspace-inherited features", True, {
        "Cargo.toml": WS_ROOT + '\n[workspace.dependencies]\ncitrate-sequencer = { path = "seq", features = ["devnet"] }\n',
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dependencies]\ncitrate-sequencer = { workspace = true }\n',
    }),
    ("renamed dependency", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dependencies]\nseq = { package = "citrate-sequencer", path = "../seq", features = ["devnet"] }\n',
    }),
    ("forwarded alias in default", True, {
        "Cargo.toml": WS_ROOT,
        "seq/Cargo.toml": SEQ,
        "app/Cargo.toml": APP + '[dependencies]\ncitrate-sequencer = { path = "../seq" }\n\n'
        '[features]\ndefault = ["dev"]\ndev = ["citrate-sequencer/devnet"]\n',
    }),
    ("forwarded through an intermediate crate", True, {
        "Cargo.toml": '[workspace]\nmembers = ["seq", "mid", "app"]\n',
        "seq/Cargo.toml": SEQ,
        "mid/Cargo.toml": '[package]\nname = "mid"\nversion = "0.1.0"\n\n[dependencies]\n'
        'citrate-sequencer = { path = "../seq" }\n\n[features]\nloose = ["citrate-sequencer?/devnet"]\n',
        "app/Cargo.toml": APP + '[dependencies]\nmid = { path = "../mid", features = ["loose"] }\n',
    }),
]


def self_test() -> int:
    rc = 0
    with tempfile.TemporaryDirectory(prefix="seq-devnet-selftest-") as d:
        for i, (label, expect_flag, files) in enumerate(CASES):
            root = Path(d) / f"case{i}"
            for rel, text in files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            flagged = bool(scan(root))
            if flagged != expect_flag:
                rc = 1
                want = "flagged" if expect_flag else "clean"
                print(f"self-test FAILED: {label}: expected {want}")
        gone = Path(d) / "undeclared"
        (gone / "seq").mkdir(parents=True)
        (gone / "seq" / "Cargo.toml").write_text(SEQ.replace("devnet = []", "dev-net = []"))
        try:
            scan(gone)
            print("self-test FAILED: missing devnet feature did not fail closed")
            rc = 1
        except ManifestError:
            pass
        bad = Path(d) / "unparseable"
        bad.mkdir()
        (bad / "Cargo.toml").write_text('[package\nname = "x"\n')
        try:
            scan(bad)
            print("self-test FAILED: unparseable manifest did not fail closed")
            rc = 1
        except ManifestError:
            pass
    if rc == 0:
        print(f"self-test ok: {len(CASES)} cases + 2 fail-closed checks")
    return rc


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(__doc__)
        return 2
    root = Path(
        os.environ.get("SEQ_DEVNET_TRIPWIRE_ROOT")
        or Path(__file__).resolve().parent.parent.parent
    )
    try:
        violations = scan(root)
    except ManifestError as e:
        print(f"sequencer devnet tripwire: {e}")
        return 1
    if violations:
        print("\n".join(violations))
        return 1
    print("sequencer devnet tripwire: ok (no in-repo build enables citrate-sequencer/devnet)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
