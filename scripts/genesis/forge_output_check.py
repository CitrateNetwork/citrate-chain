#!/usr/bin/env python3
"""forge_output_check.py: forge records its broadcasts where the genesis scripts read them.

The ceremony's sends-once guard (C10), its book checks and the address-book generator read
forge's broadcast records from contracts/broadcast/. forge takes that directory, and the
directory of its per-run script cache (cache/<script>/<chain>/run-*.json), from its config.
Measured with forge 1.8.3 (`forge config --json` in contracts/), these settings move them:

  setting     environment                            effect
  broadcast   FOUNDRY_BROADCAST, DAPP_BROADCAST      the broadcast records' directory
  cache_path  FOUNDRY_CACHE_PATH, DAPP_CACHE_PATH    the script cache's directory
  cache       FOUNDRY_CACHE, DAPP_CACHE              false: no script cache is written
  (profile)   FOUNDRY_PROFILE                        a profile may set any of the three; the
                                                     repo's own [profile.membership] moves
                                                     cache_path
  (file)      FOUNDRY_CONFIG                         another foundry.toml, which may set any

forge reads these names in any case (foundry_broadcast works), so they are matched that way.
Not on the list, because forge 1.8.3 does not read them: FOUNDRY_ROOT, DAPP_ROOT, DAPP_PROFILE;
nor FOUNDRY_OUT and the other path keys, which move compiler artifacts, not the records.
A global ~/.foundry/foundry.toml can set the same keys and no variable names it, so `config`
checks what forge actually resolves.

  env                     exit 1 naming each listed variable that is set (even empty); its
                          value is never printed
  config --contracts DIR  read `forge config --json` (run in DIR) on stdin; exit 1 with the
                          reason unless broadcast is DIR/broadcast, cache_path is DIR/cache and
                          cache is on
"""
import json
import os
import sys

FORGE_OUTPUT_ENV = (
    "FOUNDRY_BROADCAST",
    "DAPP_BROADCAST",
    "FOUNDRY_CACHE_PATH",
    "DAPP_CACHE_PATH",
    "FOUNDRY_CACHE",
    "DAPP_CACHE",
    "FOUNDRY_PROFILE",
    "FOUNDRY_CONFIG",
)


def check_env():
    hits = sorted(n for n in os.environ if n.upper() in FORGE_OUTPUT_ENV)
    if not hits:
        return 0
    for n in hits:
        print(
            f"{n} is set in the environment: forge would take its broadcast or cache output "
            "settings from it, and the sends-once guard reads this run's broadcasts only from "
            "contracts/broadcast/; unset it",
            file=sys.stderr,
        )
    return 1


def check_config(contracts, raw):
    def where(v):
        return os.path.normpath(os.path.join(contracts, v))

    try:
        cfg = json.loads(raw)
    except ValueError:
        return "cannot parse forge's config (forge config --json)"
    if not isinstance(cfg, dict):
        return "cannot parse forge's config (forge config --json): not an object"
    want = os.path.normpath(os.path.join(contracts, "broadcast"))
    b = cfg.get("broadcast")
    if not isinstance(b, str) or not b:
        return "forge's config has no broadcast directory"
    if where(b) != want:
        return f"forge writes its broadcast records to {where(b)}, not {want}, where the sends-once guard reads them"
    if cfg.get("cache") is not True:
        return "forge's cache is off (cache = false): forge script keeps no per-run cache of this run's broadcasts"
    c = cfg.get("cache_path")
    wantc = os.path.normpath(os.path.join(contracts, "cache"))
    if not isinstance(c, str) or not c or where(c) != wantc:
        return f"forge writes its script cache to {where(c) if isinstance(c, str) and c else c!r}, not {wantc}"
    return None


def main(argv):
    if argv[:1] == ["env"] and len(argv) == 1:
        return check_env()
    if argv[:2] == ["config", "--contracts"] and len(argv) == 3:
        why = check_config(os.path.abspath(argv[2]), sys.stdin.read())
        if why:
            print(why, file=sys.stderr)
            return 1
        return 0
    print("usage: forge_output_check.py env | config --contracts DIR < forge-config.json", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
