#!/usr/bin/env python3
"""privileged_slots_tripwire.py: every privileged slot of a ceremony-deployed
contract is either read by the post-deploy deployer check or exempt for a
stated reason.

The deployer/factory sweep in contracts/script/lib/AdminChecks.sol reads a
fixed list of getters (address slots, address-set memberships, roles) on every
deployed contract. A slot it does not read is a slot the deploy account could
be left holding without the gate noticing. This tripwire walks the sources of
every contract the scanned deploy scripts construct (and every contract they
inherit from) and finds:

  address   a state variable of type address / address payable / a contract or
            interface type (constants excluded: they are fixed in the bytecode)
  set       a state variable `mapping(address => bool)`
  list      a state variable `address[]` (or a contract-typed array)
  role      a `bytes32 ... constant <NAME>_ROLE`

Each must have an entry in contracts/script/lib/privileged_slots.json:

  "Contract.name": "checked"                 the getter name() / name(address)
                                             is in AdminChecks' probe list
  "Contract.name": "checked:<getter>"        read through another getter
                                             (e.g. a private slot behind a function)
  "Contract.name": "exempt: <reason>"        not a privilege, with the reason

and the file must not list anything that no longer exists. A checked entry
whose getter is not in the probe list fails, so removing a probe fails too.

Usage: privileged_slots_tripwire.py [--root DIR] [--self-test]
"""
import json
import os
import re
import shutil
import sys
import tempfile

SCRIPTS = ["contracts/script/DeployAll.s.sol"]
ADMIN_CHECKS = "contracts/script/lib/AdminChecks.sol"
CLASSIFICATION = "contracts/script/lib/privileged_slots.json"
SRC = "contracts/src"
ELEMENTARY = re.compile(r"^(u?int\d*|bytes\d*|bool|string|bytes)$")
MIN_REASON = 12


def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), t, flags=re.S)
    return re.sub(r"//[^\n]*", "", t)


def contracts_in(path):
    """{name: (kind, bases, body)} for every contract/interface/library in a file."""
    t = strip_comments(open(path, encoding="utf-8").read())
    out = {}
    for m in re.finditer(r"\b(abstract\s+contract|contract|interface|library)\s+(\w+)([^{;]*)\{", t):
        kind, name, head = m.group(1), m.group(2), m.group(3)
        bases = []
        hm = re.match(r"\s*is\s+(.*)$", head, re.S)
        if hm:
            depth, cur = 0, ""
            for c in hm.group(1):
                depth += c == "("
                depth -= c == ")"
                if c == "," and depth == 0:
                    bases.append(cur)
                    cur = ""
                else:
                    cur += c
            bases.append(cur)
            bases = [re.match(r"\s*([\w.]+)", b).group(1).split(".")[-1] for b in bases if b.strip()]
        i, depth = m.end(), 1
        while i < len(t) and depth:
            depth += t[i] == "{"
            depth -= t[i] == "}"
            i += 1
        out[name] = (kind, bases, t[m.end():i - 1])
    return out


def top_level_statements(body):
    """Statements at the contract's own level (function/modifier bodies skipped)."""
    stmts, cur, depth = [], "", 0
    for c in body:
        if c == "{":
            if depth == 0:
                cur = ""  # a function/struct/modifier header, not a state variable
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                cur = ""
        elif depth == 0:
            if c == ";":
                stmts.append(" ".join(cur.split()))
                cur = ""
            else:
                cur += c
    return stmts


def index_sources(root):
    defs = {}
    for d in [os.path.join(root, SRC)]:
        for dp, _, fs in os.walk(d):
            for f in sorted(fs):
                if f.endswith(".sol"):
                    p = os.path.join(dp, f)
                    for n, v in contracts_in(p).items():
                        defs[n] = (os.path.relpath(p, root),) + v
    return defs


def deployed_names(root):
    names = set()
    for s in SCRIPTS:
        t = strip_comments(open(os.path.join(root, s), encoding="utf-8").read())
        names.update(re.findall(r"\bnew\s+(\w+)\s*\{\s*salt\s*:", t))
        names.update(re.findall(r"\btype\(\s*(\w+)\s*\)\.creationCode", t))
    return names


MODS = r"(?:public|internal|private|external|immutable|constant|override(?:\([^)]*\))?|transient)"


def slots_of(name, defs):
    """[(kind, var, public)] declared directly in `name`."""
    _, kind_, _, body = defs[name]
    types = {n for n, v in defs.items() if v[1] in ("contract", "abstract contract", "interface")}
    out = []
    for s in top_level_statements(body):
        s = re.split(r"(?<![=!<>])=(?![=>])", s, maxsplit=1)[0].strip()
        if re.match(r"^(using|event|error|struct|enum|function|modifier|constructor|fallback|receive)\b", s):
            continue
        m = re.match(r"^bytes32\s+((?:" + MODS + r"\s+)*)(\w+_ROLE)$", s)
        if m and "constant" in m.group(1):
            out.append(("role", m.group(2), True))
            continue
        m = re.match(r"^mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+((?:" + MODS + r"\s+)*)(\w+)$", s)
        if m:
            out.append(("set", m.group(2), "public" in m.group(1)))
            continue
        m = re.match(r"^(address(?:\s+payable)?|[A-Za-z_]\w*)\s*(\[\s*\d*\s*\])?\s+((?:" + MODS + r"\s+)*)(\w+)$", s)
        if not m:
            continue
        ty, arr, mods, var = m.group(1), m.group(2), m.group(3), m.group(4)
        if "constant" in mods:
            continue
        if not (ty.startswith("address") or ty in types or re.match(r"^I[A-Z]\w*$", ty)):
            continue
        if ELEMENTARY.match(ty):
            continue
        out.append(("list" if arr else "address", var, "public" in mods))
    return out


def probes(root):
    t = strip_comments(open(os.path.join(root, ADMIN_CHECKS), encoding="utf-8").read())

    def body(fn):
        m = re.search(r"function\s+" + fn + r"\s*\([^)]*\)[^{]*\{(.*?)\n\s*\}", t, re.S)
        if not m:
            raise SystemExit(f"privileged-slots tripwire: {ADMIN_CHECKS} has no {fn}()")
        return m.group(1)

    addr = set(re.findall(r'"(\w+\(\))"', body("_addressSlotGetters")))
    sets = set(re.findall(r'"(\w+\(address\))"', body("_addressSetGetters")))
    roles = set(re.findall(r'"(\w+_ROLE)"', body("_probedRoleNames")))
    return addr, sets, roles


def scan(root):
    defs = index_sources(root)
    addr_p, set_p, role_p = probes(root)
    with open(os.path.join(root, CLASSIFICATION), encoding="utf-8") as f:
        cls = json.load(f)["slots"]
    found, problems, missing = {}, [], []
    seen = set()
    todo = sorted(deployed_names(root))
    while todo:
        n = todo.pop(0)
        if n in seen:
            continue
        seen.add(n)
        if n not in defs:
            missing.append(n)
            continue
        for kind, var, public in slots_of(n, defs):
            found[f"{n}.{var}"] = (kind, public, defs[n][0])
        todo.extend(b for b in defs[n][2] if b not in seen)
    for n in missing:
        problems.append(f"{n}: deployed by {', '.join(SCRIPTS)} but its source was not found")
    for key, (kind, public, path) in sorted(found.items()):
        v = cls.get(key)
        var = key.split(".", 1)[1]
        if v is None:
            problems.append(f"{key} ({kind}, {path}) is not classified in {CLASSIFICATION}: "
                            f"add \"checked\" (and its getter to AdminChecks) or \"exempt: <reason>\"")
            continue
        if not isinstance(v, str):
            problems.append(f"{key}: classification must be a string")
            continue
        if v.startswith("exempt"):
            reason = v[len("exempt"):].lstrip(":").strip()
            if len(reason) < MIN_REASON:
                problems.append(f"{key}: an exemption needs a reason (\"exempt: <why this is not a privilege>\")")
            continue
        if v == "checked" or v.startswith("checked:"):
            getter = v.split(":", 1)[1].strip() if ":" in v else None
            if kind == "role":
                g = getter or var
                if g not in role_p:
                    problems.append(f"{key}: classified checked but {g} is not in AdminChecks._probedRoleNames()")
                continue
            if getter is None:
                if not public:
                    problems.append(f"{key}: not public, so \"checked\" must name its getter (\"checked:<fn>()\")")
                    continue
                getter = f"{var}()" if kind == "address" else f"{var}(address)"
            if kind in ("address",) and getter not in addr_p:
                problems.append(f"{key}: classified checked but {getter} is not in AdminChecks._addressSlotGetters()")
            elif kind in ("set", "list") and getter not in set_p and getter not in addr_p:
                problems.append(f"{key}: classified checked but {getter} is not in AdminChecks._addressSetGetters()")
            continue
        problems.append(f"{key}: unknown classification {v!r} (use checked, checked:<getter> or exempt: <reason>)")
    for key in sorted(set(cls) - set(found)):
        problems.append(f"{key} is classified in {CLASSIFICATION} but no scanned contract declares it (stale entry)")
    return found, problems


def self_test(root):
    rc = 0
    tmp = tempfile.mkdtemp(prefix="privslots-")
    try:
        def fresh():
            d = os.path.join(tmp, "t")
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(os.path.join(root, SRC), os.path.join(d, SRC))
            for rel in [ADMIN_CHECKS, CLASSIFICATION] + SCRIPTS:
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                shutil.copy2(os.path.join(root, rel), os.path.join(d, rel))
            return d

        def edit(d, rel, old, new):
            p = os.path.join(d, rel)
            t = open(p, encoding="utf-8").read()
            assert old in t, f"self-test anchor missing in {rel}: {old!r}"
            open(p, "w", encoding="utf-8").write(t.replace(old, new, 1))

        def reclass(d, key, value):
            p = os.path.join(d, CLASSIFICATION)
            j = json.load(open(p, encoding="utf-8"))
            if value is None:
                j["slots"].pop(key, None)
            else:
                j["slots"][key] = value
            json.dump(j, open(p, "w", encoding="utf-8"), indent=2)

        def expect(label, d, needle):
            nonlocal rc
            _, probs = scan(d)
            hit = any(needle in p for p in probs)
            if needle == "" and probs:
                print(f"self-test: {label}: flagged a clean tree: {probs[:3]}")
                rc = 1
            elif needle and not hit:
                print(f"self-test: {label}: not caught (problems: {probs[:3]})")
                rc = 1

        cm = f"{SRC}/ComputeMarketplace.sol"
        anchor = "    address public treasury;"
        expect("clean copy", fresh(), "")
        d = fresh()
        edit(d, cm, anchor, anchor + "\n    address public feeSink;")
        expect("new address public slot", d, "ComputeMarketplace.feeSink (address")
        reclass(d, "ComputeMarketplace.feeSink", "checked")
        expect("checked slot the sweep does not read", d, "feeSink() is not in AdminChecks._addressSlotGetters()")
        reclass(d, "ComputeMarketplace.feeSink", "exempt:")
        expect("exemption without a reason", d, "an exemption needs a reason")
        d = fresh()
        edit(d, cm, anchor, anchor + "\n    address private feeSink2;\n    function setFeeSink2(address a) external onlyGovernance { feeSink2 = a; }")
        expect("new setter-guarded private slot", d, "ComputeMarketplace.feeSink2 (address")
        d = fresh()
        edit(d, cm, anchor, anchor + "\n    mapping(address => bool) public minters;")
        expect("new address set", d, "ComputeMarketplace.minters (set")
        d = fresh()
        edit(d, cm, anchor, anchor + "\n    IComputePricingOracleMin public backupOracle;")
        expect("new interface-typed slot", d, "ComputeMarketplace.backupOracle (address")
        d = fresh()
        edit(d, cm, anchor, anchor + "\n    bytes32 public constant SETTLER_ROLE = keccak256(\"SETTLER_ROLE\");")
        expect("new role", d, "ComputeMarketplace.SETTLER_ROLE (role")
        d = fresh()
        reclass(d, "ComputeMarketplace.noSuchSlot", "checked")
        expect("stale classification", d, "ComputeMarketplace.noSuchSlot is classified")
        d = fresh()
        edit(d, ADMIN_CHECKS, '"treasury()",', "")
        expect("probe removed from the sweep", d, "treasury() is not in AdminChecks._addressSlotGetters()")
        d = fresh()
        reclass(d, "ComputeVerifier.marketplace", None)
        expect("classification removed", d, "ComputeVerifier.marketplace (address")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if rc == 0:
        print("privileged-slots tripwire self-test: ok")
    return rc


def main(argv):
    root = os.environ.get("PRIVILEGED_SLOTS_ROOT") or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if "--root" in argv:
        root = argv[argv.index("--root") + 1]
    if "--self-test" in argv:
        return self_test(root)
    found, problems = scan(root)
    if problems:
        print("\n".join(problems))
        print(f"privileged-slots tripwire: FAILED ({len(problems)} problem(s) over {len(found)} slots)")
        return 1
    kinds = {}
    for k, _, _ in found.values():
        kinds[k] = kinds.get(k, 0) + 1
    print(f"privileged-slots tripwire: clean ({len(found)} slots classified: "
          + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
