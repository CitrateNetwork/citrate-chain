#!/usr/bin/env python3
"""Frame-condition lint for TLA+ modules (citrate-chain: specs/tla/**/*.tla).

Ported from citrate-core src-tauri/formal/tla_frame_lint.py (core#345, head 59cecef). Changes
from that source: string literals are blanked before matching (a string such as "Open" that
equals an operator name is not a reference to that operator), findings carry the module path
and absolute line number as "path:line: ..." for the shared tripwire allowlist, the CLI takes
file paths, and the self-tests gained the string-literal case.

Flags a variable that one conjunct of an action assigns (`x' = ...`, or through a helper operator
such as `FailStep`) while a sibling conjunct of the same conjunction list keeps it `UNCHANGED`.
The conjunction `x' = e /\\ x' = x` only holds when `e = x`, so the action silently fires on a
subset of the states it was written for (example: an action that set
`sinceMember' = 0` beside `UNCHANGED << ..., sinceMember >>` never fired after a failure).

Branches are respected: the THEN and ELSE arms of an IF are separate conjunction lists, and `\\/`
disjuncts are alternatives, never siblings. Tuple aliases (`vars == << ... >>`) are expanded.

Usage: python3 scripts/ci/tla_frame_lint.py <file.tla> [<file.tla> ...]
       python3 scripts/ci/tla_frame_lint.py --self-test
Normally run through scripts/ci/tla_frame_tripwire.sh (scope, allowlist, fixtures).
Exit status is non-zero on any finding (or a failing self-test).
"""
import os, re, sys

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def strip_comments(text):
    text = re.sub(r"\(\*.*?\*\)", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    text = "\n".join(l.split("\\*", 1)[0] for l in text.splitlines())
    # String literals are data: blank their contents so "Open" is not read as operator Open.
    return re.sub(r'"(?:[^"\\\n]|\\.)*"', lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', text)


def parse(text):
    """Return (variables, definitions{name: body_lines}) for one module."""
    text = strip_comments(text)
    variables = set()
    for m in re.finditer(r"^VARIABLES?\b(.*?)(?=^\S)", text, flags=re.S | re.M):
        variables |= set(re.findall(IDENT, m.group(1)))
    defs, name, body = {}, None, []
    starts = {}
    for n, line in enumerate(text.splitlines()):
        m = re.match(rf"^({IDENT})(\([^)]*\))?\s*==(.*)$", line)
        if m:
            if name:
                defs[name] = body
            name, body = m.group(1), [" " * (len(line) - len(m.group(3))) + m.group(3)]
            starts[name] = n + 1
        elif name and (line.startswith((" ", "\t")) or not line.strip()):
            body.append(line)
        elif name:
            defs[name], name, body = body, None, []
    if name:
        defs[name] = body
    return variables, defs, starts


class Module:
    def __init__(self, text):
        self.vars, self.defs, self.starts = parse(text)
        self.aliases = {}
        for n, b in self.defs.items():
            m = re.fullmatch(r"\s*<<(.*)>>\s*", " ".join(b), flags=re.S)
            if m:
                self.aliases[n] = [t for t in re.findall(IDENT, m.group(1))]
        self._primes = {}

    def expand(self, names, seen=()):
        out = set()
        for n in names:
            if n in self.vars:
                out.add(n)
            elif n in self.aliases and n not in seen:
                out |= self.expand(self.aliases[n], seen + (n,))
        return out

    def unchanged(self, text):
        out = set()
        for m in re.finditer(rf"UNCHANGED\s*(<<.*?>>|{IDENT})", text, flags=re.S):
            out |= self.expand(re.findall(IDENT, m.group(1)))
        return out

    def primes(self, text, seen=()):
        out = {v for v in re.findall(rf"({IDENT})'", text) if v in self.vars}
        for ref in set(re.findall(IDENT, text)):
            if ref in self.defs and ref not in seen and ref not in self.aliases:
                out |= self.def_primes(ref, seen + (ref,))
        return out

    def def_primes(self, name, seen):
        if name not in self._primes:
            self._primes[name] = self.primes("\n".join(self.defs[name]), seen)
        return self._primes[name]


def bullets(lines):
    """Yield (line_index, column, kind) for every /\\ or \\/ bullet that starts a list item:
    first token of a line, or right after a leading THEN / ELSE / IN / LET keyword."""
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)((?:THEN|ELSE|IN|LET)\s+)?(/\\|\\/)", l)
        if m:
            yield i, len(m.group(1)) + len(m.group(2) or ""), m.group(3)


def raw_col(line):
    return len(line) - len(line.lstrip()) if line.strip() else None


def lint_definition(mod, name, lines):
    findings = []
    bl = list(bullets(lines))
    groups = {}
    for i, col, kind in bl:
        if kind != "/\\":
            continue
        # The list a bullet belongs to: its own line if a keyword precedes it on that line,
        # otherwise the nearest earlier line that starts left of it.
        if raw_col(lines[i]) < col:
            parent = i
        else:
            parent = next((j for j in range(i - 1, -1, -1)
                           if raw_col(lines[j]) is not None and raw_col(lines[j]) < col), -1)
        # The item runs until the next line that starts at or left of the bullet column.
        end = next((j for j in range(i + 1, len(lines))
                    if raw_col(lines[j]) is not None and raw_col(lines[j]) <= col), len(lines))
        item = lines[i][col + 2:] + "\n" + "\n".join(lines[i + 1:end])
        groups.setdefault((parent, col), []).append((i, item))
    for (parent, col), items in groups.items():
        for a, (ia, ta) in enumerate(items):
            pa = mod.primes(ta)
            for b, (ib, tb) in enumerate(items):
                if a == b:
                    continue
                clash = pa & mod.unchanged(tb)
                base = mod.starts.get(name, 1)
                for v in sorted(clash):
                    findings.append((base + ib, f"[{name}] `{v}` is assigned (line {base + ia}) "
                                     f"and kept UNCHANGED by a sibling conjunct (line {base + ib})"))
    return findings


def lint_text(text):
    mod = Module(text)
    out = []
    for name, lines in mod.defs.items():
        out += lint_definition(mod, name, lines)
    return sorted(set(out))


SELF_TESTS = [
    # (name, module text, expected number of findings)
    ("assign beside UNCHANGED", """VARIABLES x, y
A ==
    /\\ x' = 0
    /\\ UNCHANGED << x, y >>
""", 1),
    ("alias expansion", """VARIABLES x, y
pair == << x, y >>
A ==
    /\\ y' = 1
    /\\ UNCHANGED pair
""", 1),
    ("through a helper", """VARIABLES x, y
Helper == x' = x + 1
A ==
    /\\ Helper
    /\\ UNCHANGED << x >>
    /\\ y' = 0
""", 1),
    ("IF branches are separate lists", """VARIABLES x, y
A ==
    /\\ IF x = 0
       THEN /\\ x' = 1
            /\\ UNCHANGED y
       ELSE /\\ y' = 1
            /\\ UNCHANGED x
""", 0),
    ("THEN and ELSE without bullets", """VARIABLES x
A ==
    IF x = 0
    THEN x' = 1
    ELSE UNCHANGED x
""", 0),
    ("disjuncts are alternatives", """VARIABLES x
A ==
    \\/ x' = 1
    \\/ UNCHANGED x
""", 0),
    ("a nested branch clashing with an outer sibling", """VARIABLES x, y
A ==
    /\\ x' = 1
    /\\ IF y = 0
       THEN UNCHANGED << x, y >>
       ELSE y' = 1
""", 1),
    ("clean frame", """VARIABLES x, y
A ==
    /\\ x' = 1
    /\\ UNCHANGED << y >>
""", 0),
    ("a string literal naming an operator is not a reference", """VARIABLES st, t
Open == /\\ st' = "Open" /\\ t' = 1
B ==
    /\\ st = "Open"
    /\\ UNCHANGED << st, t >>
""", 0),
]


def self_test():
    ok = True
    for name, text, want in SELF_TESTS:
        got = lint_text(text)
        good = len(got) == want
        ok = ok and good
        print(f"{'ok  ' if good else 'FAIL'} {name}: {len(got)} finding(s), expected {want}")
    return ok


def main(argv):
    if argv == ["--self-test"]:
        return 0 if self_test() else 1
    if not argv:
        print(__doc__)
        return 2
    total = 0
    for path in argv:
        with open(path, encoding="utf-8") as fh:
            found = lint_text(fh.read())
        for line, msg in found:
            print(f"{path}:{line}: {msg}")
        total += len(found)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
