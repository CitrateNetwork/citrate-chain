---
title: "Faucet policy for the betanet genesis (C2 G4) and the deploy runbook"
created: 2026-10-19T00:00:00Z
branch: ops/genesis-g4-faucet-policy
author: Larry Klosowski + Claude Opus 5.5 (DGX lane)
status: active. Code side implemented and tested; NOT deployed. The amounts marked OPEN wait for the owner (C2 decisions D2, D3 and D6, due 2026-10-30).
chain: 40204
---

# Faucet policy (betanet genesis) and deploy runbook

This is the policy the faucet runs under from the betanet genesis until the 1.0 activation, and
the steps the DGX lead follows to put it live. It covers C2 genesis-spec item **G4** ("deploy the
current binary, turn on the cap and the SBT gate, document the policy").

Where things stand:

| Piece | State |
|---|---|
| Per-address window, per-IP window, global hourly cap, membership-SBT gate, CAPTCHA | **Implemented and tested** in `faucet/src/` (unit tests plus one real drip against a local anvil). |
| Configurable windows (`FAUCET_ADDRESS_COOLDOWN_SECS`, `FAUCET_IP_COOLDOWN_SECS`) and the `FAUCET_REQUIRE_GATES` switch | **Implemented and tested** in this change. |
| Live faucet on 40204 | **Not changed.** The running binary predates the global cap and the SBT gate, so both are off on the live faucet today. Section 4 is the runbook to change that. |
| Faucet funding at genesis | Belongs to the genesis profile (C2 G1). Amount is OPEN (section 3). |

## 1. Policy

1. **One drip per address per window.** 10 SALT per drip (the compiled `DRIP_AMOUNT`). The
   window defaults to 24 h, which makes the per-address cap 10 SALT per address per day.
2. **One drip per client IP per window.** Defaults to 1 h.
3. **A faucet-wide cap.** At most `FAUCET_MAX_DRIPS_PER_HOUR` drips in any sliding hour, over all
   callers. This bounds the outflow when many fresh addresses arrive from many IPs:
   at most `cap × 24 × 10 SALT` per day.
4. **Members only.** A drip goes only to an address holding a `CitrateMemberSBT` token
   (`balanceOf(recipient) > 0`, read with `eth_call` on the faucet's own RPC). If that read
   fails, the drip is refused; the check never falls back to "allow".
5. **Persistent windows.** The windows are kept in `FAUCET_COOLDOWN_FILE`, so a restart or a
   redeploy doesn't reset them.
6. **All of the above or nothing.** The deploy sets `FAUCET_REQUIRE_GATES=true`. The faucet then
   refuses to start if the global cap, the SBT gate or the cooldown file is missing, and names
   each missing variable. `/status` reports `"gates_required": true`. In this mode the cooldown
   file must also load cleanly (a missing file is a fresh start; a directory, an unreadable file
   or unparseable content stops startup) and must be writable at startup. If a later write
   fails, new drips are refused with `"code": "cooldown_store_unavailable"` until a write
   succeeds again.
7. **A fixed budget.** The faucet signer is funded once, at genesis, with a capped amount. There
   is no separate reserve and no top-up without a governance vote. The funded balance is the hard
   upper bound on everything the faucet can ever send.
8. **It stops at 1.0.** At the 1.0 activation height the faucet service is stopped and disabled.
   The unused balance goes back to the treasury multisig in one transfer signed with the faucet
   signer key (a ceremony-held key). That transfer is an owner/DGX-lead action, not something the
   faucet does by itself.
9. **CAPTCHA is optional.** Turnstile stays available (`FAUCET_TURNSTILE_SECRET` plus
   `FAUCET_TURNSTILE_SITE_KEY`) and is not required by `FAUCET_REQUIRE_GATES`.

### Carry-over (C2 D3)

The betanet genesis is the mainnet genesis, so **faucet SALT is ordinary SALT and carries into
mainnet** like every other balance. Nothing in the protocol resets it or marks it. The controls
that bound it are the funded budget (point 7), the member-only gate (point 4) and the rate limits
(points 1 to 3). If the owner decides on a different carry-over rule (D3), this section and
point 7 change with it; the faucet code doesn't need to.

## 2. Configuration

Every variable below is read at startup. A malformed value stops the faucet with an error; none
is silently replaced by a default.

| Variable | Meaning | Default when unset | Betanet setting |
|---|---|---|---|
| `FAUCET_ADDRESS_COOLDOWN_SECS` | Per-address window, 60 to 2,592,000 s | 86,400 (24 h) | OPEN-1 (recommended: unset, 24 h) |
| `FAUCET_IP_COOLDOWN_SECS` | Per-IP window, 60 to 2,592,000 s | 3,600 (1 h) | OPEN-2 (recommended: unset, 1 h) |
| `FAUCET_MAX_DRIPS_PER_HOUR` | Faucet-wide sliding-hour cap, 1 to 100,000 | off | OPEN-3 (the `.env.example` placeholder is 60) |
| `FAUCET_MEMBER_SBT` | `CitrateMemberSBT` address on this chain | off | The address from the frozen address book (`contracts/addresses/40204.json`, key `CitrateMemberSBT`). It changes when the genesis contract set is deployed, so set it again after that deploy. |
| `FAUCET_COOLDOWN_FILE` | Path of the persisted windows (written mode 0600) | in memory | A path on the faucet host outside any build directory |
| `FAUCET_REQUIRE_GATES` | `true`/`1` makes the three settings above mandatory | off | `true` |
| `FAUCET_TRUSTED_PROXIES` | Reverse proxies whose `X-Forwarded-For` is trusted | none | The proxy in front of the faucet, if any (see 4.4) |
| `FAUCET_TURNSTILE_SECRET`, `FAUCET_TURNSTILE_SITE_KEY` | CAPTCHA | off | OPEN-6 |

The per-drip amount is compiled in (`DRIP_AMOUNT`, 10 SALT). Changing it is a code change, not a
setting.

## 3. Open parameters (owner)

These are not decided. Nothing in this document or the code picks them.

| Id | Parameter | Decision it belongs to | What is known today |
|---|---|---|---|
| OPEN-1 | Per-address window | D6 | Code default 24 h. |
| OPEN-2 | Per-IP window | D6 | Code default 1 h. |
| OPEN-3 | `FAUCET_MAX_DRIPS_PER_HOUR` | D6 | Placeholder 60 from the core faucet ADR (O-1), not signed off. |
| OPEN-4 | Faucet budget funded at genesis | D2 / D6 | The spec recommends a small fixed cap and no separate reserve. The current `testnet_beta` profile in `core/economics/src/genesis.rs` funds a signer and a separate reserve; the final profile (G1) replaces both with the one capped amount. |
| OPEN-5 | Does quarantine or term expiry of a membership also block the drip? | core faucet ADR O-2 | Today only a burned (revoked) token blocks; quarantine and expiry keep the token, so they pass. |
| OPEN-6 | CAPTCHA on or off at genesis | D6 | Optional in the spec. The desktop app's in-app window path is core ADR O-3. |
| OPEN-7 | Carry-over rule for faucet SALT | D3 | Recommended: carries over like everything else (section 1). |

Owner sign-off fills these in the C2 spec §4 ("Faucet cap") and in the env file at deploy time.

## 4. Deploy runbook (DGX lead)

Not run. Nothing here has been executed against the live faucet. These steps assume the faucet
host's existing systemd unit `citrate-faucet` and its env file `/etc/citrate-faucet.env`.

### 4.0 Preconditions

- This change is merged, and you build from `origin/main` only. Record the SHA.
- OPEN-1 to OPEN-3 and OPEN-6 are decided. For a deploy before the final genesis, the
  `CitrateMemberSBT` address is the one in the current address book.
- **The env file holds the faucet signer key. Never `cat`, `less`, `grep` without `-c`, or copy
  it anywhere it can be read back.** Edit it only by filtering lines out and appending new ones,
  as below.

### 4.1 Build

1. Check free disk on the build host first (`df -h`). A build target filling the RPC host's disk
   has halted the chain before. Build where there is room, never under the node's data directory,
   and delete the target directory afterwards.
2. Build for the faucet host's architecture from a clean `origin/main` checkout:
   ```bash
   git fetch origin && git checkout --detach origin/main && git rev-parse HEAD
   cargo build --release -p citrate-faucet
   sha256sum target/release/citrate-faucet
   ```
3. Optional local check before touching the host: `cargo test -p citrate-faucet` (it runs one real
   drip against a throwaway local anvil when Foundry is installed; nothing reaches a public chain).

### 4.2 Install, keeping the old binary

```bash
systemctl cat citrate-faucet          # read ExecStart; use that path below as $BIN
# Rollback copy, taken once: a second run must not replace it with the G4 binary.
[ -e "$BIN.pre-g4" ] || cp -a "$BIN" "$BIN.pre-g4"
sha256sum "$BIN.pre-g4"               # record it (on a rerun, check it still matches the first record)
install -m 0755 citrate-faucet "$BIN"
```

### 4.3 Set the policy in the env file

Only non-secret lines are written. The key line is never read, printed, or passed on a command
line. Run this block as root in one shell. It refuses to continue unless the env file is already
private, every file it creates is mode 0600 from the moment it exists (`umask 077` plus `mktemp`
in the same directory), the temporary file is removed on any failure, and the env file is replaced
by one atomic `mv` that keeps its owner and group.

The block stops at the first failed step. The subshell runs on its own (never as the left side of
`&&` or `||`, which would switch `set -e` off inside it), and every step that comes before the
`mv` also carries an explicit `|| exit 1`, so a failed backup, filter, append, key check, `chown`
or `chmod` can never reach the `mv`. The result is read from the subshell's exit status
afterwards.

The rollback copy `$E.pre-g4` is written once. If it already exists (for example the block ran
before and you are rerunning it to change a value), it is kept as it is and the block says so;
it is never overwritten, so §4.6 always restores the env from before the first run. If it exists
but is a symlink or not a regular file, the block refuses. Remove it only as §4.6 says, after
the new config is confirmed.

The two `<...>` values below are placeholders: replace them before running. If one is left
as is, the faucet refuses to start (strict parsing), so the mistake shows at 4.5 and the faucet
does not run with a wrong value.

`FAUCET_ENV` and `FAUCET_STATE_DIR` default to the production paths; the faucet's
test suite (`faucet/tests/runbook_env_block.rs`) runs this exact block against a throwaway env
file, including each failure path.

```bash
(
set -euo pipefail
umask 077
E=${FAUCET_ENV:-/etc/citrate-faucet.env}
D=${FAUCET_STATE_DIR:-/var/lib/citrate-faucet}
# The env file must already be private (0600 or 0400) before anything is copied from it.
case "$(stat -c '%a' "$E")" in 600|400) ;; *) echo "refusing: $E is not mode 0600" >&2; exit 1 ;; esac
install -d -m 0700 "$D"                     || exit 1   # match the unit's User= if it is not root
# Rollback copy, taken on the first run only. A rerun keeps it, so it always holds the pre-G4 env.
if [ -L "$E.pre-g4" ] || { [ -e "$E.pre-g4" ] && [ ! -f "$E.pre-g4" ]; }; then
  echo "refusing: $E.pre-g4 exists and is not a regular file" >&2; exit 1
fi
if [ -e "$E.pre-g4" ]; then
  echo "keeping the existing rollback copy $E.pre-g4 (not overwritten)"
else
  cp -a "$E" "$E.pre-g4"                    || exit 1   # -a keeps the 0600 mode and owner
fi
T=$(mktemp "$E.new.XXXXXX")                 || exit 1   # created 0600 under umask 077, same filesystem as $E
trap 'rm -f "$T"' EXIT
grep -v -E '^(FAUCET_MAX_DRIPS_PER_HOUR|FAUCET_MEMBER_SBT|FAUCET_COOLDOWN_FILE|FAUCET_REQUIRE_GATES|FAUCET_ADDRESS_COOLDOWN_SECS|FAUCET_IP_COOLDOWN_SECS)=' "$E" > "$T" || exit 1
cat >> "$T" <<'ENV' || exit 1
FAUCET_REQUIRE_GATES=true
FAUCET_MAX_DRIPS_PER_HOUR=<OPEN-3>
FAUCET_MEMBER_SBT=<CitrateMemberSBT from contracts/addresses/40204.json>
FAUCET_COOLDOWN_FILE=/var/lib/citrate-faucet/cooldowns.json
ENV
# Add FAUCET_ADDRESS_COOLDOWN_SECS / FAUCET_IP_COOLDOWN_SECS only if OPEN-1 / OPEN-2 differ from the defaults.
n=$(grep -c '^FAUCET_PRIVATE_KEY=' "$T" || true)   # a count only; the line itself is never printed
[ "$n" = 1 ] || { echo "refusing: expected exactly one key line after filtering, found $n" >&2; exit 1; }
chown --reference="$E" "$T"                 || exit 1
chmod 600 "$T"                              || exit 1
mv -f "$T" "$E"                             || exit 1
trap - EXIT
stat -c '%a %U:%G' "$E" || true             # expect 600 and the original owner (report only)
)
rc=$?
if [ "$rc" -eq 0 ]; then echo "env updated"; else echo "env NOT changed (exit $rc); fix the error above and rerun" >&2; fi
```

Do not use `sudo -E`, `env`, `printenv`, `set -x`, `bash -x` or `systemctl show -p Environment`
on this host while doing this; none of the steps above needs them. If the block stops with an
error, the env file is unchanged and the temporary file is already removed.

### 4.4 Check the proxy setting

If a reverse proxy on the same host forwards to the faucet and `FAUCET_TRUSTED_PROXIES` is not
set, the faucet sees every caller as the proxy's address, so all callers share one per-IP window.
Check with `grep -c '^FAUCET_TRUSTED_PROXIES=' /etc/citrate-faucet.env` and the proxy config. If the proxy is on
loopback, set `FAUCET_TRUSTED_PROXIES=127.0.0.1` with the same block as 4.3 (umask 077, `mktemp`, filter, append, atomic `mv`).

### 4.5 Restart and verify

```bash
systemctl restart citrate-faucet
journalctl -u citrate-faucet -n 40 --no-pager   # expect "FAUCET_REQUIRE_GATES on", the cap, and "Membership check on"
curl -s localhost:<port>/health
curl -s localhost:<port>/ready                   # 200, or 503 with a reason
curl -s localhost:<port>/status
```

`/status` must show `"gates_required": true`, `"membership_check": true`,
`"global_cap_per_hour": <OPEN-3>`, and the two cooldown values you intended.

Refusal checks (these send nothing on chain):

- `POST /faucet` for an address that holds no membership token returns `"code": "not_member"`.
- `GET /eligibility?address=<a member address>` answers without reserving anything.

A real drip to a member address broadcasts a transfer from the faucet signer. Whether to do one
as a smoke test is the DGX lead's call; if done, a second request for the same address must
return `"code": "rate_limited"` with `"limit": "address"`.

### 4.6 Rollback

```bash
cp -a "$BIN.pre-g4" "$BIN"
cp -a /etc/citrate-faucet.env.pre-g4 /etc/citrate-faucet.env
systemctl restart citrate-faucet
```

Then shred the `.pre-g4` env copy once the new config is confirmed, since it also holds the key:
`shred -u /etc/citrate-faucet.env.pre-g4`.

### 4.7 At the final genesis and at 1.0

- **After the genesis contract set is deployed:** replace `FAUCET_MEMBER_SBT` with the new
  `CitrateMemberSBT` address from the frozen address book, then restart and repeat 4.5. Put the
  new faucet signer key in the env file by the ceremony runbook's procedure (key handled only on
  the ceremony machine; never printed).
- **At the 1.0 activation:** `systemctl disable --now citrate-faucet`, then the owner-approved
  return of the remaining balance to the treasury multisig (point 8). Record the transfer hash in
  the activation log.

## 5. Where the code is

| What | File |
|---|---|
| Per-address and per-IP windows, persistence, `FAUCET_*_COOLDOWN_SECS` | `faucet/src/cooldowns.rs` |
| Global hourly cap | `faucet/src/limits.rs` |
| Membership-SBT gate (fails closed) | `faucet/src/membership.rs` |
| `FAUCET_REQUIRE_GATES` | `faucet/src/policy.rs` |
| Startup wiring, `/status`, the drip path | `faucet/src/main.rs` |
| Endpoints and refusal codes | `faucet/README.md` |
