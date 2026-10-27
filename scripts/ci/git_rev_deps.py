#!/usr/bin/env python3
"""git_rev_deps.py: every git dependency pin in the tree must resolve on its remote.

A Cargo git dependency pinned by `rev` is only reproducible while the remote
still serves that commit. When the dependency's history is rewritten, the old
commit stops being reachable from any ref, and GitHub then refuses to serve it
("upload-pack: not our ref"). Builds that already have the commit in
~/.cargo/git keep working, and a clean checkout can't build. Nothing in the
consumer changed, so no path-filtered CI notices.

This check reads every tracked Cargo.toml and Cargo.lock and collects:
  * Cargo.toml: every table that has a `git = "..."` key, at any depth. That
    covers [dependencies], [dev-dependencies], [build-dependencies],
    [target.*.dependencies], [workspace.dependencies] and [patch.*]. It
    records the `rev`, `tag` or `branch` with it.
  * Cargo.lock: every `source = "git+URL?...#SHA"`, i.e. the exact commit a
    --locked build fetches.

Then, per remote:
  * `git ls-remote URL` must succeed, so the remote exists and is readable.
  * a `rev` or lockfile SHA must be fetchable by SHA into a scratch bare repo
    and must be a commit (a short rev is checked against a full fetch);
  * a `tag` or `branch` must exist as a ref.

Usage:
  git_rev_deps.py [ROOT]       # scan ROOT (default: the repo root)
  git_rev_deps.py --self-test  # negative control against local fixture remotes

Exit: 0 = every pin resolves; 1 = a pin does not resolve, or the tree could not
be read (fail closed).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import parse_qs, urlsplit

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
HEX = re.compile(r"^[0-9a-f]{4,40}$")
TIMEOUT = int(os.environ.get("GIT_REV_DEPS_TIMEOUT", "120"))


# `git rev-parse --local-env-vars`: the variables that pick a repository. git exports
# GIT_DIR (and, from a worktree, GIT_INDEX_FILE and more) to hooks, so under the pre-push
# hook an inherited one would aim every git call here, fixture init/commit/gc included, at
# the developer's own repository. Every call locates its repository by -C/cwd instead.
LOCAL_GIT_ENV = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE", "GIT_COMMON_DIR",
)


def git_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in LOCAL_GIT_ENV and not k.startswith("GIT_CONFIG_KEY_")
           and not k.startswith("GIT_CONFIG_VALUE_")}
    env["GIT_TERMINAL_PROMPT"] = "0"  # never hang on a credential prompt
    return env


def run_git(args, cwd=None):
    try:
        return subprocess.run(["git", *args], cwd=cwd, env=git_env(),
                              capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", f"timed out after {TIMEOUT}s")


# ── collection ─────────────────────────────────────────────────────────────

def tracked_manifests(root):
    r = run_git(["-C", root, "ls-files", "-z", "--", "*Cargo.toml", "*Cargo.lock"])
    if r.returncode != 0:
        raise RuntimeError(f"git ls-files failed in {root}: {r.stderr.strip()}")
    out = []
    for p in r.stdout.split("\0"):
        if os.path.basename(p) in ("Cargo.toml", "Cargo.lock"):
            out.append(p)
    return sorted(out)


def walk_git_specs(node, path, found):
    if isinstance(node, dict):
        if isinstance(node.get("git"), str):
            found.append((".".join(path), node))
            return
        for k, v in node.items():
            walk_git_specs(v, path + [str(k)], found)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk_git_specs(v, path + [str(i)], found)


def collect(root):
    """Returns a list of pins: dict(where, url, kind in {rev,tag,branch,lock}, value)."""
    pins = []
    for rel in tracked_manifests(root):
        full = os.path.join(root, rel)
        with open(full, "rb") as f:
            data = tomllib.load(f)  # a parse error propagates: fail closed
        if rel.endswith("Cargo.toml"):
            specs = []
            walk_git_specs(data, [], specs)
            for where, spec in specs:
                for kind in ("rev", "tag", "branch"):
                    if kind in spec:
                        pins.append(dict(where=f"{rel}: {where}", url=spec["git"],
                                         kind=kind, value=str(spec[kind])))
                        break
                else:
                    # No rev/tag/branch means the remote's default branch. That
                    # only has to resolve; the lockfile carries the SHA.
                    pins.append(dict(where=f"{rel}: {where}", url=spec["git"],
                                     kind="default", value="HEAD"))
        else:
            for pkg in data.get("package", []):
                src = pkg.get("source", "")
                if not src.startswith("git+"):
                    continue
                body = src[len("git+"):]
                url_q, _, sha = body.partition("#")
                parts = urlsplit(url_q)
                url = parts._replace(query="").geturl()
                q = parse_qs(parts.query)
                where = f"{rel}: {pkg.get('name')} {pkg.get('version')}"
                if not sha:
                    pins.append(dict(where=where, url=url, kind="lock-malformed", value=src))
                    continue
                pins.append(dict(where=where, url=url, kind="lock", value=sha))
                if "tag" in q:
                    pins.append(dict(where=where, url=url, kind="tag", value=q["tag"][0]))
                elif "branch" in q:
                    pins.append(dict(where=where, url=url, kind="branch", value=q["branch"][0]))
    return pins


# ── resolution ─────────────────────────────────────────────────────────────

class Remote:
    def __init__(self, url, scratch):
        self.url = url
        self.dir = tempfile.mkdtemp(prefix="remote-", dir=scratch)
        self.refs = None
        self.error = None
        self.full_fetched = False
        r = run_git(["init", "--quiet", "--bare", self.dir])
        if r.returncode != 0:
            self.error = f"git init failed: {r.stderr.strip()}"
            return
        r = run_git(["ls-remote", url])
        if r.returncode != 0:
            self.error = f"ls-remote failed: {(r.stderr or r.stdout).strip()[:300]}"
            return
        self.refs = {}
        for line in r.stdout.splitlines():
            sha, _, ref = line.partition("\t")
            self.refs[ref] = sha

    def has_commit(self, rev):
        r = run_git(["-C", self.dir, "cat-file", "-t", rev])
        return r.returncode == 0 and r.stdout.strip() == "commit"

    def resolve_rev(self, rev):
        if not HEX.match(rev):
            return False, f"rev {rev!r} is not a hex commit id"
        if FULL_SHA.match(rev):
            if not self.has_commit(rev):
                r = run_git(["-C", self.dir, "fetch", "--quiet", "--depth=1",
                             "--no-tags", self.url, rev])
                if r.returncode != 0:
                    return False, ("remote does not serve this commit (no ref reaches it?): "
                                   + (r.stderr or r.stdout).strip()[:300])
            if not self.has_commit(rev):
                return False, "fetched, but the object is not a commit"
            return True, "fetchable"
        # Short rev: it can't be fetched by id, so fetch every ref and look.
        if not self.full_fetched:
            r = run_git(["-C", self.dir, "fetch", "--quiet", self.url,
                         "+refs/heads/*:refs/remotes/r/*", "+refs/tags/*:refs/tags/*"])
            if r.returncode != 0:
                return False, f"full fetch failed: {(r.stderr or r.stdout).strip()[:300]}"
            self.full_fetched = True
        r = run_git(["-C", self.dir, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])
        if r.returncode != 0:
            return False, "short rev not found on any branch or tag"
        return True, f"fetchable ({r.stdout.strip()[:12]})"

    def resolve_ref(self, kind, value):
        if kind == "default":
            return ("HEAD" in self.refs), "default branch (HEAD)"
        want = [f"refs/tags/{value}"] if kind == "tag" else [f"refs/heads/{value}"]
        for ref in want:
            if ref in self.refs:
                return True, f"{ref} -> {self.refs[ref][:12]}"
        return False, f"{kind} {value!r} is not a ref on the remote"


def check(root, out=sys.stdout):
    """Returns (ok, n_pins, failures)."""
    try:
        pins = collect(root)
    except Exception as e:  # unreadable tree, bad TOML: fail closed
        print(f"git-rev-deps: cannot read the tree: {e}", file=out)
        return False, 0, [str(e)]
    scratch = tempfile.mkdtemp(prefix="git-rev-deps-")
    failures = []
    try:
        remotes = {}
        for p in pins:
            if p["url"] not in remotes:
                remotes[p["url"]] = Remote(p["url"], scratch)
        for p in pins:
            rem = remotes[p["url"]]
            label = f"{p['where']}  {p['url']}  {p['kind']}={p['value'][:40]}"
            if p["kind"] == "lock-malformed":
                ok, why = False, "lockfile git source has no #SHA"
            elif rem.error:
                ok, why = False, rem.error
            elif p["kind"] in ("rev", "lock"):
                ok, why = rem.resolve_rev(p["value"])
            else:
                ok, why = rem.resolve_ref(p["kind"], p["value"])
            print(f"  {'ok  ' if ok else 'FAIL'} {label}  [{why}]", file=out)
            if not ok:
                failures.append(f"{label}: {why}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return not failures, len(pins), failures


# ── negative control ────────────────────────────────────────────────────────

def self_test():
    """Builds local remotes, pins them, rewrites history, and checks the verdicts."""
    base = tempfile.mkdtemp(prefix="git-rev-deps-selftest-")
    # Fixture git runs must not read the developer's config, hooks or signing.
    saved = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")}
    os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    ident = ["-c", "user.name=fixture", "-c", "user.email=fixture@invalid",
             "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
    rc = 0

    def g(*args, cwd=None):
        r = subprocess.run(["git", *ident, *args], cwd=cwd, env=git_env(),
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"fixture git {args} failed: {r.stderr}")
        return r.stdout.strip()

    def commit(repo, name, text):
        with open(os.path.join(repo, name), "w") as f:
            f.write(text)
        g("add", name, cwd=repo)
        g("commit", "--quiet", "-m", text, cwd=repo)
        return g("rev-parse", "HEAD", cwd=repo)

    def tree(name, toml, lock=None):
        d = os.path.join(base, name)
        os.makedirs(os.path.join(d, "sub"))
        g("init", "--quiet", d)
        with open(os.path.join(d, "sub", "Cargo.toml"), "w") as f:
            f.write(toml)
        if lock is not None:
            with open(os.path.join(d, "sub", "Cargo.lock"), "w") as f:
                f.write(lock)
        g("add", "-A", cwd=d)
        return d

    def expect(name, root, want_ok, want_pins=None, must_mention=None):
        nonlocal rc
        import io
        buf = io.StringIO()
        ok, n, failures = check(root, out=buf)
        good = (ok == want_ok)
        if want_pins is not None and n != want_pins:
            good = False
        if must_mention and not any(must_mention in f for f in failures):
            good = False
        print(f"  self-test {'ok  ' if good else 'FAIL'} {name}: "
              f"verdict={'pass' if ok else 'fail'} pins={n}")
        if not good:
            print(buf.getvalue())
            rc = 1

    try:
        # The dependency repository. old_mid is reachable but not a tip, so a
        # pass on it proves fetch-by-SHA works and not just "is a tip".
        dep = os.path.join(base, "dep")
        g("init", "--quiet", dep)
        commit(dep, "lib.rs", "one")
        old_mid = commit(dep, "lib.rs", "two")
        commit(dep, "lib.rs", "three")
        g("tag", "v1", cwd=dep)
        url = "file://" + dep

        def toml_for(rev, extra=""):
            return (f'[package]\nname = "x"\nversion = "0.1.0"\n\n'
                    f'[dependencies]\nk = {{ git = "{url}", rev = "{rev}" }}\n'
                    f"[target.'cfg(unix)'.dev-dependencies]\n"
                    f'k2 = {{ git = "{url}", tag = "v1" }}\n{extra}')

        def lock_for(sha):
            return ('version = 3\n\n[[package]]\nname = "k"\nversion = "0.1.0"\n'
                    f'source = "git+{url}?rev={sha}#{sha}"\n')

        # 1. Reachable pins (rev, tag, lock) pass. Three pins: the walk found
        #    the target-specific table as well as [dependencies].
        expect("reachable rev+tag+lock passes",
               tree("t1", toml_for(old_mid), lock_for(old_mid)), True, want_pins=3)

        # 2. Short rev that exists passes.
        expect("short reachable rev passes", tree("t2", toml_for(old_mid[:10])), True)

        # 3. Rewrite the dependency's history: old_mid stops being reachable and
        #    is pruned, the way a force-pushed rewrite leaves GitHub.
        g("checkout", "--quiet", "--orphan", "rewritten", cwd=dep)
        commit(dep, "lib.rs", "one (rewritten)")
        new_mid = commit(dep, "lib.rs", "two (rewritten)")
        g("branch", "-D", "main", cwd=dep)
        g("branch", "-m", "main", cwd=dep)
        g("tag", "-f", "v1", cwd=dep)
        g("reflog", "expire", "--expire=now", "--all", cwd=dep)
        g("gc", "--quiet", "--prune=now", cwd=dep)

        expect("stranded rev fails (the negative control)",
               tree("t3", toml_for(old_mid)), False, must_mention=old_mid[:40])
        expect("stranded short rev fails", tree("t4", toml_for(old_mid[:10])), False)
        expect("stranded lockfile SHA fails although Cargo.toml uses a tag",
               tree("t5", f'[dependencies]\nk = {{ git = "{url}", tag = "v1" }}\n',
                    lock_for(old_mid)), False, must_mention="lock=")
        expect("missing tag fails",
               tree("t6", f'[dependencies]\nk = {{ git = "{url}", tag = "v9" }}\n'), False)
        expect("missing remote fails",
               tree("t7", f'[dependencies]\nk = {{ git = "file://{base}/nope", rev = "{new_mid}" }}\n'),
               False, must_mention="ls-remote failed")
        expect("unparseable Cargo.toml fails closed", tree("t8", "[dependencies\n"), False)

        # 4. Re-pinned to the rewritten equivalent: passes again.
        expect("re-pinned rev passes", tree("t9", toml_for(new_mid), lock_for(new_mid)), True,
               want_pins=3)
    except Exception as e:
        print(f"  self-test FAIL: fixture error: {e}")
        rc = 1
    finally:
        shutil.rmtree(base, ignore_errors=True)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    print("git-rev-deps self-test: " + ("ok" if rc == 0 else "FAILED"))
    return rc


def main(argv):
    if argv[1:2] == ["--self-test"]:
        return self_test()
    root = argv[1] if len(argv) > 1 else os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".."))
    ok, n, failures = check(root)
    if not ok:
        print(f"git-rev-deps: FAILED, {len(failures)} of {n} git pin(s) do not resolve on "
              "their remote. Re-pin to a commit the remote serves (for a rewritten "
              "history, the rewritten equivalent) and record it in the federation "
              "[[drift]] map first.")
        return 1
    print(f"git-rev-deps: all {n} git pin(s) resolve on their remote")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
