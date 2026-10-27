#!/usr/bin/env python3
"""phase_inputs.py: the inputs every genesis-ceremony phase reads, and P0's check of them.

A ceremony phase that broadcasts part-way and then stops on a missing input cannot be re-run
(P2 has no partial resume, C10), so P0 must refuse every input a later phase reads before
anything is sent. The list of those inputs is not kept by hand:

  derive      reads the ceremony (genesis_ceremony.sh), regenesis.sh and every forge script
              each phase runs, with their local imports, and prints each environment key
              each phase reads. A read is a vm.env*() call, or a call of a helper that
              reaches one, with a literal key, a key built with string.concat(prefix,
              "_SUFFIX"), or the helper's own parameter; anything else is reported as a
              dynamic read that cannot be checked.
  check-spec  the tripwire: the derived reads and phase_inputs.json must agree. A key a phase
              reads that the spec does not classify fails, so does a spec entry no phase
              reads, a phase list that differs from the derived one, a dynamic read, a
              script a phase runs that is missing, and a "p0-bash" key that P0 does not name
              or a "set" key the ceremony scripts never assign.
  preflight   P0's check (the ceremony calls it): for the phases this invocation runs, every
              "p0" input is present and well formed, every "late" input is present once the
              phase that produces it is behind this run, every "unset" input is unset, and
              the "distinct" groups hold. Prints the problems and exits 3.

An entry may name a "pending_reader": the script that will read it once a change that is not
in this tree yet lands. Until then the unread entry is not stale; once the scripts read the key
the field itself is flagged, so it is dropped.

Spec classes (phase_inputs.json, one entry per key):
  p0       P0 checks it here (presence, type, not the deployer).
  p0-bash  P0 checks it in genesis_ceremony.sh (governance councils, deployer, books).
  late     produced by an earlier phase (available_after); P0 checks it when the run starts
           after that phase, and the reading phase checks it before it sends.
  set      the ceremony or regenesis.sh sets it for the phase.
  default  optional: the script falls back to a safe default or refuses a bad value itself.
  unset    must not be set in a ceremony.

Exit: 0 ok · 1 tripwire failed · 2 usage or unreadable input · 3 preflight refused
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
ENV_FNS = r"env(?:Address|Uint|Int|String|Bool|Bytes32|Bytes|Or|Exists)?"
PHASE_MARK = re.compile(r"^# -{8,} (P[0-9]L?)\s*$", re.M)


def die(msg, code=2):
    print(f"phase_inputs: {msg}", file=sys.stderr)
    sys.exit(code)


# ------------------------------------------------------------------ solidity reads
def strip_comments(src):
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i : j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def split_args(s, start):
    """Arguments of the call whose '(' is at s[start]; returns (args, end index)."""
    depth, i, cur, args, q = 0, start, [], [], None
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == "\\":
                cur.append(s[i + 1])
                i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            if depth > 1:
                cur.append(c)
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return [a for a in args if a != ""] if args != [""] else [], i
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    raise ValueError("unbalanced call")


def functions(src):
    """(name, [param names], body) for every function/constructor/modifier in src."""
    out = []
    for m in re.finditer(r"\b(function\s+(\w+)|constructor|modifier\s+(\w+))\s*\(", src):
        name = m.group(2) or m.group(3) or "constructor"
        params, end = split_args(src, m.end() - 1)
        names = []
        for p in params:
            toks = p.split()
            names.append(toks[-1] if len(toks) >= 2 else "")
        k = end + 1
        while k < len(src) and src[k] not in "{;":
            k += 1
        if k >= len(src) or src[k] == ";":
            continue
        depth, j = 0, k
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((name, names, src[k + 1 : j]))
    return out


LIT = re.compile(r'^"([^"\\]*)"$')


def resolve(expr, params, locals_):
    """A key expression -> ("lit", text) | ("param", index, suffix) | None (dynamic)."""
    expr = expr.strip()
    m = LIT.match(expr)
    if m:
        return ("lit", m.group(1))
    if re.fullmatch(r"\w+", expr):
        if expr in params:
            return ("param", params.index(expr), "")
        if expr in locals_:
            return resolve(locals_[expr], params, {})
        return None
    m = re.fullmatch(r"string\.concat\s*\((.*)\)", expr, re.S)
    if m:
        parts, _ = split_args("(" + m.group(1) + ")", 0)
        if not parts:
            return None
        head = resolve(parts[0], params, locals_)
        tail = ""
        for p in parts[1:]:
            lm = LIT.match(p.strip())
            if not lm:
                return None
            tail += lm.group(1)
        if head is None:
            return None
        if head[0] == "lit":
            return ("lit", head[1] + tail)
        return ("param", head[1], head[2] + tail)
    return None


def solidity_reads(files):
    """files: {path: source}. Returns (reads {key: set(path)}, dynamic [(path, fn, expr)])."""
    funcs = []
    for path, src in files.items():
        s = strip_comments(src)
        for name, params, body in functions(s):
            locals_ = {
                m.group(1): m.group(2)
                for m in re.finditer(r"\bstring\s+memory\s+(\w+)\s*=\s*([^;]+);", body)
            }
            funcs.append((path, name, params, body, locals_))
    wrappers = {}  # name -> set((param index, suffix))
    while True:
        reads, dynamic, grew = {}, [], False
        for path, name, params, body, locals_ in funcs:
            sites = []
            for m in re.finditer(r"\b(?:vm|[A-Z_]*VM)\s*\.\s*" + ENV_FNS + r"\s*\(", body):
                sites.append((m.end() - 1, [(0, "")]))
            for w, uses in wrappers.items():
                for m in re.finditer(r"(?<![\w.])" + re.escape(w) + r"\s*\(", body):
                    if body[: m.start()].rstrip().endswith("function"):
                        continue
                    sites.append((m.end() - 1, sorted(uses)))
            for at, uses in sites:
                try:
                    args, _ = split_args(body, at)
                except ValueError:
                    dynamic.append((path, name, body[at : at + 60]))
                    continue
                for idx, suffix in uses:
                    if idx >= len(args):
                        continue
                    r = resolve(args[idx], params, locals_)
                    if r is None:
                        dynamic.append((path, name, args[idx]))
                    elif r[0] == "lit":
                        reads.setdefault(r[1] + suffix, set()).add(path)
                    else:
                        u = (r[1], r[2] + suffix)
                        if u not in wrappers.setdefault(name, set()):
                            wrappers[name].add(u)
                            grew = True
        if not grew:
            return reads, dynamic


def import_closure(contracts, scripts):
    """Every file under contracts/script/ the given scripts import, transitively."""
    root = os.path.join(contracts, "script")
    todo = [os.path.join(root, s) for s in scripts]
    seen = {}
    while todo:
        f = os.path.normpath(todo.pop())
        if f in seen:
            continue
        try:
            with open(f) as fh:
                seen[f] = fh.read()
        except OSError as e:
            die(f"cannot read {f}: {e}", 1)
        for m in re.finditer(r'^\s*import\s+(?:[^"\';]*\bfrom\s+)?"(\.{1,2}/[^"]+)"', seen[f], re.M):
            dep = os.path.normpath(os.path.join(os.path.dirname(f), m.group(1)))
            if dep.startswith(root + os.sep) and dep not in seen:
                todo.append(dep)
    return seen


# ------------------------------------------------------------------ phases -> scripts
def phase_scripts(repo):
    """{phase: [forge script paths relative to contracts/script]} and regenesis's own reads."""
    ce_path = os.path.join(repo, "scripts", "genesis", "genesis_ceremony.sh")
    rg_path = os.path.join(repo, "scripts", "ops", "regenesis.sh")
    try:
        ce = open(ce_path).read()
        rg = open(rg_path).read()
    except OSError as e:
        die(f"cannot read the ceremony scripts: {e}", 1)
    marks = list(PHASE_MARK.finditer(ce))
    if [m.group(1) for m in marks] != ["P0", "P1", "P2", "P3", "P3L", "P4", "P5", "P6", "P7"]:
        die(f"{ce_path}: expected one '# ---- Pn' section marker per phase P0..P7 (and P3L after P3)", 1)
    gm = re.search(r'^GENESIS_MEMBERSHIP_SCRIPT=([\w./]+)\s*$', ce, re.M)
    out, problems, rg_phases = {}, [], []
    for i, m in enumerate(marks):
        sec = ce[m.end() : marks[i + 1].start() if i + 1 < len(marks) else len(ce)]
        sec = "\n".join(l for l in sec.splitlines() if not l.lstrip().startswith("#"))
        found = re.findall(r"forge_phase\s+P[0-9]L?\s+([\w/]+\.s\.sol)", sec)
        found += re.findall(r"\bscript/([\w/]+\.s\.sol)", sec)
        if re.search(r'\bbash\s+"\$REGENESIS"', sec):
            rg_phases.append(m.group(1))
            rcode = "\n".join(l for l in rg.splitlines() if not l.lstrip().startswith("#"))
            for step in re.findall(r'^\s*run_step\s+"([^"]+)"', rcode, re.M):
                if step.startswith("$"):
                    var = step.strip("${}")
                    vals = re.findall(r'^\s*' + re.escape(var) + r'="([\w./]+)"', rcode, re.M)
                    if var == "MEMBERSHIP_SCRIPT" and gm and gm.group(1) in vals:
                        found.append(gm.group(1))  # the ceremony passes --genesis-membership
                    else:
                        problems.append(f"regenesis.sh: run_step {step} cannot be resolved to a script")
                else:
                    found.append(step)
        out[m.group(1)] = list(dict.fromkeys(found))
    rg_reads = sorted(set(re.findall(r'\$\{([A-Z][A-Z0-9_]*):\?', rg)))
    return out, {k: rg_phases for k in rg_reads}, problems, ce, marks


def derive(repo):
    """Phases, reads, dynamic reads, problems, pending phases, ceremony text, phase markers.

    A phase script that is missing is a problem, unless P0 itself refuses to run without it
    (the P0 section names it): then the ceremony cannot run in this tree at all, and the
    phase is "pending" (its reads cannot be derived until that script is merged)."""
    contracts = os.path.join(repo, "contracts")
    phases, rg_reads, problems, ce, marks = phase_scripts(repo)
    p0 = ce[marks[0].end() : marks[1].start()]
    p0_required = set(re.findall(r"[\w/]+\.s\.sol", p0))
    gm = re.search(r'^GENESIS_MEMBERSHIP_SCRIPT=([\w./]+)\s*$', ce, re.M)
    if gm and "$GENESIS_MEMBERSHIP_SCRIPT" in p0:
        p0_required.add(gm.group(1))
    reads, dynamic, pending = {}, [], set()
    for ph, scripts in phases.items():
        missing = [s for s in scripts if not os.path.isfile(os.path.join(contracts, "script", s))]
        for s in missing:
            if s in p0_required:
                pending.add(ph)
            else:
                problems.append(f"{ph} runs contracts/script/{s}, which is missing")
        files = import_closure(contracts, [s for s in scripts if s not in missing])
        r, d = solidity_reads(files)
        for k, where in r.items():
            reads.setdefault(k, {}).setdefault(ph, set()).update(os.path.relpath(w, repo) for w in where)
        dynamic += [(ph,) + x for x in d]
    for k, phs in rg_reads.items():  # regenesis.sh's own required inputs (${X:?...})
        for ph in phs:
            reads.setdefault(k, {}).setdefault(ph, set()).add("scripts/ops/regenesis.sh")
    return phases, reads, dynamic, problems, pending, ce, marks


# ------------------------------------------------------------------ spec + tripwire
def load_spec(path):
    try:
        with open(path) as fh:
            spec = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"cannot read the spec {path}: {e}")
    if not isinstance(spec.get("inputs"), dict):
        die(f"{path}: no inputs map")
    return spec


CLASSES = {"p0", "p0-bash", "late", "set", "default", "unset"}


def check_spec(repo, spec):
    phases, reads, dynamic, problems, pending, ce, marks = derive(repo)
    inputs = spec["inputs"]
    p0 = ce[marks[0].end() : marks[1].start()]
    rg = open(os.path.join(repo, "scripts", "ops", "regenesis.sh")).read()
    for ph, path, fn, expr in dynamic:
        problems.append(f"{ph}: {path} {fn}() reads an environment key P0 cannot check: {expr}")
    for k in sorted(reads):
        want = sorted(reads[k])
        e = inputs.get(k)
        if e is None:
            where = "; ".join(f"{ph}: {', '.join(sorted(reads[k][ph]))}" for ph in want)
            problems.append(f"{k} is read ({where}) but phase_inputs.json does not classify it")
            continue
        if sorted(set(e.get("phases", [])) - pending) != sorted(set(want) - pending):
            problems.append(f"{k}: phase_inputs.json says phases {sorted(e.get('phases', []))}, the scripts read it in {want}")
    for k, e in sorted(inputs.items()):
        c = e.get("class")
        if c not in CLASSES:
            problems.append(f"{k}: unknown class {c!r}")
        if k in reads and e.get("pending_reader"):
            problems.append(f"{k}: pending_reader {e['pending_reader']!r} is set, but the scripts now read it; drop the field")
        elif k not in reads and not set(e.get("phases", [])) <= pending and not e.get("pending_reader"):
            problems.append(f"{k} is in phase_inputs.json but no phase reads it (stale entry)")
        if not e.get("why"):
            problems.append(f"{k}: no 'why'")
        if c == "p0-bash":
            fn = e.get("checked_by")
            if fn:
                body = re.search(r"^" + re.escape(fn) + r"\(\)\s*\{(.*?)^\}", ce, re.M | re.S)
                if not re.search(r"\b" + re.escape(fn) + r"\b", p0) or not body or ("_" + k.split("_", 1)[-1]) not in body.group(1):
                    problems.append(f"{k} is classed p0-bash, checked by {fn}, but P0 does not call {fn} or {fn} does not read it")
            elif not re.search(r"\b" + re.escape(k) + r"\b", p0):
                problems.append(f"{k} is classed p0-bash but the P0 section of genesis_ceremony.sh never names it")
        if c == "set" and not re.search(r"(?:^|[\s;(])(?:export\s+)?(?:[A-Z_]+=\S*\s+)*" + re.escape(k) + r"=", ce + "\n" + rg, re.M):
            problems.append(f"{k} is classed set but neither genesis_ceremony.sh nor regenesis.sh assigns it")
        if c == "late" and e.get("available_after") not in ("P1", "P2", "P3", "P3L"):
            problems.append(f"{k}: a late input needs available_after P1..P3")
        if c == "p0" and e.get("type") not in ("address", "uint", "path"):
            problems.append(f"{k}: a p0 input needs a type")
    for g in spec.get("distinct", []):
        for k in g:
            if k not in inputs:
                problems.append(f"distinct group {g} names {k}, which is not an input")
    return phases, reads, problems, pending


# ------------------------------------------------------------------ preflight
def preflight(spec, run_phases, started_after, deployer):
    """Problems with the environment for the phases this invocation runs."""
    inputs, env, problems = spec["inputs"], os.environ, []
    order = ["P0", "P1", "P2", "P3", "P3L", "P4", "P5", "P6", "P7"]
    dep = (deployer or "").lower()
    seen_vals = {}
    for k, e in sorted(inputs.items()):
        if not set(e.get("phases", [])) & set(run_phases):
            continue
        c, v = e.get("class"), env.get(k)
        need = c == "p0" or (c == "late" and started_after is not None and order.index(started_after) >= order.index(e["available_after"]))
        if c == "unset":
            if k in env:
                problems.append(f"{k} is set; a genesis ceremony runs without it ({e['why']})")
            continue
        if c == "default" and v not in (None, "") and e.get("type") == "uint" and not re.fullmatch(r"[0-9]+", v):
            problems.append(f"{k} ({v}) is not an unsigned integer ({e['why']})")
            continue
        if c not in ("p0", "late"):
            continue
        if v is None or v == "":
            if need:
                problems.append(f"{k} is not set ({e['why']})")
            continue
        t = e.get("type", "address")
        if t == "address":
            if not ADDR.fullmatch(v):
                problems.append(f"{k} ({v}) is not an address")
                continue
            if int(v, 16) == 0:
                problems.append(f"{k} is the zero address")
                continue
            if e.get("not_deployer", True) and dep and v.lower() == dep:
                problems.append(f"{k} ({v}) is the deployer; it must be a separate account")
            seen_vals[k] = v.lower()
        elif t == "uint" and not re.fullmatch(r"[0-9]+", v):
            problems.append(f"{k} ({v}) is not an unsigned integer")
    for g in spec.get("distinct", []):
        vals = [(k, seen_vals[k]) for k in g if k in seen_vals]
        if len({x for _, x in vals}) != len(vals):
            problems.append(f"{', '.join(g)} must be distinct addresses (got {', '.join(f'{k}={x}' for k, x in vals)})")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("derive", "check-spec"):
        p = sub.add_parser(name)
        p.add_argument("--repo", default=os.path.normpath(os.path.join(HERE, "..", "..")))
        p.add_argument("--spec", default=os.path.join(HERE, "phase_inputs.json"))
    p = sub.add_parser("preflight")
    p.add_argument("--spec", default=os.path.join(HERE, "phase_inputs.json"))
    p.add_argument("--phases", required=True, help="comma-separated phases this invocation runs")
    p.add_argument("--started-after", default="", help="the last phase before this invocation's first (empty: a fresh run)")
    p.add_argument("--deployer", default="")
    a = ap.parse_args()
    if a.cmd == "derive":
        phases, reads, dynamic, problems, pending, _, _ = derive(a.repo)
        print(json.dumps({"phases": phases, "pending": sorted(pending), "reads": {k: {p: sorted(v) for p, v in ph.items()} for k, ph in sorted(reads.items())},
                          "dynamic": [list(x) for x in dynamic], "problems": problems}, indent=1))
        return 0
    if a.cmd == "check-spec":
        phases, reads, problems, pending = check_spec(a.repo, load_spec(a.spec))
        for p in problems:
            print(f"PHASE-INPUTS-FAIL {p}")
        if problems:
            print(f"phase_inputs: {len(problems)} problem(s): every environment key a ceremony phase reads must be classified in {a.spec} (and P0 must check it)")
            return 1
        note = f"; pending until merged (P0 refuses without their scripts): {', '.join(sorted(pending))}" if pending else ""
        print(f"phase_inputs: OK ({len(reads)} keys over {sum(len(v) for v in phases.values())} phase scripts, all classified{note})")
        return 0
    run = [x for x in a.phases.split(",") if x]
    problems = preflight(load_spec(a.spec), run, a.started_after or None, a.deployer)
    for p in problems:
        print(p)
    return 3 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
