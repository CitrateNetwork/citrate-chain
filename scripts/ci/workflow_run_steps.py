#!/usr/bin/env python3
"""Print the shell commands GitHub Actions workflows actually run.

Walks jobs.<id>.steps[].run in each workflow file and prints every line of
every run script, with shell comments removed. Text anywhere else in the file
(a `paths:` filter, a YAML comment, a commented-out step, a step name) is not
printed, so a caller that greps this output sees only real invocations.

PyYAML is used when it is installed. Without it, a small parser reads the
subset of YAML that step `run:` keys use (plain, quoted and block scalars);
--self-test checks that both readers agree.

Usage: workflow_run_steps.py <workflow.yml>...                # run-step lines
       workflow_run_steps.py --invocations <workflow.yml>...  # scripts/ci/*.sh
                                     # a step executes (not only --self-test)
       workflow_run_steps.py --self-test
Env:   WORKFLOW_RUN_STEPS_NO_YAML=1 forces the built-in parser.
"""
import os
import re
import sys

try:
    if os.environ.get("WORKFLOW_RUN_STEPS_NO_YAML") == "1":
        raise ImportError
    import yaml  # type: ignore
except ImportError:
    yaml = None


def runs_pyyaml(text: str) -> list[str]:
    doc = yaml.safe_load(text) or {}
    out = []
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    for job in (jobs or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                out.append(step["run"])
    return out


_RUN_KEY = re.compile(r"^(?P<ind>\s*)(?:-\s+)?run:\s*(?P<val>.*)$")


def _unquote(v: str) -> str:
    v = v.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    # A plain scalar ends at " #" (YAML comment).
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def runs_builtin(text: str) -> list[str]:
    lines = text.splitlines()
    out = []
    in_jobs = False
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if re.match(r"^jobs:\s*(#.*)?$", line):
            in_jobs = True
            continue
        if re.match(r"^\S", line) and not line.startswith("#"):
            in_jobs = False
        if not in_jobs or line.lstrip().startswith("#"):
            continue
        m = _RUN_KEY.match(line)
        if not m:
            continue
        val = m.group("val")
        key_col = line.index("run:")
        if re.match(r"^[|>][-+]?\s*(#.*)?$", val):
            block = []
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= key_col:
                    break
                block.append(nxt)
                i += 1
            nonblank = [b for b in block if b.strip()]
            ind = min((len(b) - len(b.lstrip()) for b in nonblank), default=0)
            out.append("\n".join(b[ind:] for b in block).strip("\n"))
        else:
            out.append(_unquote(val))
    return out


def strip_shell_comments(script: str) -> list[str]:
    kept = []
    for ln in script.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        # Trailing comment: " #" outside quotes is close enough for CI scripts.
        kept.append(re.split(r"\s+#", s, maxsplit=1)[0])
    return kept


# A repo script in command position: line start, or after ; & | ( && ||,
# optionally behind `bash`/`sh`, then the path, then end or whitespace.
_INVOKE = re.compile(
    r"(?:^|[;&|(]|\bthen\b|\bdo\b)\s*(?:(?:bash|sh)\s+)?(?:\./)?"
    r"(?P<script>scripts/ci/[A-Za-z0-9_.-]+\.sh)(?P<rest>(?:\s[^;&|]*)?)(?=$|[;&|])"
)


def invocations(lines: list[str]) -> list[str]:
    """Scripts a run step executes for real (not only their --self-test)."""
    found = []
    for ln in lines:
        for m in _INVOKE.finditer(ln):
            if m.group("rest").split()[:1] == ["--self-test"]:
                continue
            found.append(m.group("script"))
    return found


def run_lines(path: str, use_yaml: bool = True) -> list[str]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    runs = runs_pyyaml(text) if (use_yaml and yaml is not None) else runs_builtin(text)
    return [ln for r in runs for ln in strip_shell_comments(r)]


_FIXTURE = """\
on:
  pull_request:
    paths:
      - 'scripts/ci/a.sh'
# scripts/ci/b.sh
jobs:
  one:
    steps:
      - uses: actions/checkout@v4
      - name: plain
        run: scripts/ci/a.sh --self-test
      # - run: scripts/ci/c.sh
      - name: quoted
        run: "cargo test --manifest-path x/Cargo.toml"  # trailing
      - name: block
        run: |
          # scripts/ci/d.sh
          scripts/ci/a.sh
          echo ok # scripts/ci/e.sh
      - name: folded
        run: >-
          cargo test
          --locked
  two:
    steps:
      - run: scripts/ci/f.sh
"""
_EXPECT = [
    "scripts/ci/a.sh --self-test",
    "cargo test --manifest-path x/Cargo.toml",
    "scripts/ci/a.sh",
    "echo ok",
    "cargo test",
    "--locked",
    "scripts/ci/f.sh",
]


def self_test() -> int:
    import tempfile

    rc = 0
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "wf.yml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(_FIXTURE)
        got_builtin = run_lines(p, use_yaml=False)
        if got_builtin != _EXPECT:
            print(f"self-test: built-in reader got {got_builtin}"); rc = 1
        if yaml is not None:
            got_yaml = run_lines(p, use_yaml=True)
            # A folded scalar joins its lines with spaces under a real YAML
            # parser; the built-in reader keeps them apart. Compare on tokens.
            if " ".join(got_yaml).split() != " ".join(_EXPECT).split():
                print(f"self-test: PyYAML reader got {got_yaml}"); rc = 1
    inv = invocations(_EXPECT + ["echo scripts/ci/g.sh", "x && sh scripts/ci/h.sh arg; true"])
    if inv != ["scripts/ci/a.sh", "scripts/ci/f.sh", "scripts/ci/h.sh"]:
        print(f"self-test: invocations got {inv}"); rc = 1
    # Both readers must agree on every real workflow in this repo.
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    wf_dir = os.path.join(root, ".github", "workflows")
    if yaml is not None and os.path.isdir(wf_dir):
        for name in sorted(os.listdir(wf_dir)):
            if not name.endswith((".yml", ".yaml")):
                continue
            p = os.path.join(wf_dir, name)
            a = " ".join(run_lines(p, use_yaml=True)).split()
            b = " ".join(run_lines(p, use_yaml=False)).split()
            if a != b:
                print(f"self-test: readers disagree on .github/workflows/{name}"); rc = 1
    if rc == 0:
        print("workflow_run_steps self-test OK" + ("" if yaml else " (PyYAML not installed)"))
    return rc


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    mode_inv = len(argv) > 1 and argv[1] == "--invocations"
    files = argv[2:] if mode_inv else argv[1:]
    if not files:
        print(__doc__, file=sys.stderr)
        return 2
    lines = [ln for p in files for ln in run_lines(p)]
    for ln in sorted(set(invocations(lines))) if mode_inv else lines:
        print(ln)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
