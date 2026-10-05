#!/usr/bin/env python3
"""panic_ratchet.py <baseline.json> <current.json> — the PANIC-S1 G1 gate.

Fails if ANY (crate, lint) production panic count is above the committed
baseline. A crate or lint absent from the baseline counts as a baseline of 0,
so new crates start at zero. When everything is at or below baseline and
something went DOWN, the baseline is rewritten (the ratchet tightens) and the
gate tells you to commit it: tightening is deliberate and reviewable.
"""
import json
import sys


def main():
    base_path, cur_path = sys.argv[1], sys.argv[2]
    base = json.load(open(base_path))
    cur = json.load(open(cur_path))
    rose, fell = [], []
    keys = set()
    for src in (base["crates"], cur["crates"]):
        for crate, lints in src.items():
            keys.update((crate, l) for l in lints)
    for crate, lint in sorted(keys):
        b = base["crates"].get(crate, {}).get(lint, 0)
        c = cur["crates"].get(crate, {}).get(lint, 0)
        if c > b:
            rose.append(f"  {crate:28} {lint:26} {b} -> {c}  (+{c - b})")
        elif c < b:
            fell.append(f"  {crate:28} {lint:26} {b} -> {c}  ({c - b})")
    print(f"production panic sites: baseline={base['total']} current={cur['total']}")
    if rose:
        print("error: production panic sites INCREASED (PANIC-S1 G1):")
        print("\n".join(rose))
        print("fix: return an error (?), use checked_*/get(), or — only for a proven")
        print("invariant — #[allow(clippy::<lint>)] with an `// INVARIANT:` comment naming")
        print("its test (enforced by panic_invariant_tripwire.sh). Re-measure with")
        print("scripts/ci/panic-inventory.sh --summary /tmp/p.json")
        return 1
    if fell:
        json.dump(cur, open(base_path, "w"), indent=1, sort_keys=True)
        open(base_path, "a").write("\n")
        print("ratchet tightened:")
        print("\n".join(fell))
        print(f"commit {base_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
