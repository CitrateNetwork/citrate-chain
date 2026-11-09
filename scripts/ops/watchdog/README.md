# citrate-height-watchdog

External anti-wedge auto-recovery for a block producer. The node has no
`sd_notify`, so this systemd timer (every 30s) polls the local RPC and restarts
`citrate-node` if the producer is genuinely wedged. Producer operators: see
`docs/ops/PRODUCER_OPERATOR_RUNBOOK.md` §9.

## Install (per producer host)
```
install -m0755 citrate-height-watchdog.sh citrate-watchdog-ctl.sh /usr/local/bin/
cp citrate-height-watchdog.service citrate-height-watchdog.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now citrate-height-watchdog.timer
citrate-watchdog-ctl.sh resume     # arm it: a fresh install restarts nothing until this
```
The watchdog fails closed: it restarts the node only while `$STATE_DIR/ARMED` holds
`armed=1` and no `PAUSE` or `CONTAIN` exists. Without a valid `ARMED` record it restarts
nothing and alerts hourly ("watchdog disarmed"). Needs `flock`, `pgrep` (procps) and `/proc`.
Alerts go to `/usr/local/bin/citrate-alert.sh "<title>" "<body>"` (override with
`ALERT=`); they name the host by `NODE_LABEL` (default: the short hostname).

## Pause during replays (2026-10 producer runbook)
Before a replay, a drain after a rollback, a state copy, a data reset or a planned
rebuild:
```
citrate-watchdog-ctl.sh pause <1-48 hours> "<reason>"
citrate-watchdog-ctl.sh status
citrate-watchdog-ctl.sh resume        # once eth_syncing is false and the head is caught up
```
While `$STATE_DIR/PAUSE` exists the watchdog restarts nothing. A pause does not lift
itself: past its deadline the watchdog alerts hourly, still without restarting, until
someone resumes. `resume` clears the stall baseline so the first poll after a long
pause cannot restart a node that is only catching up. The sync-aware check below does
not cover every replay: a drain holds the head without reporting `eth_syncing`
progress (2026-10-15), which is why the pause is explicit.

If `pause` prints "NOT confirmed" and exits non-zero, do not start the maintenance until a
re-run succeeds. A poll that finds the poll lock taken by a control command restarts nothing
that round.

### Invariants (what `pause` exiting 0 guarantees, and where it is enforced)
After `pause` exits 0, the node is not restarted by the watchdog until `resume`, whatever
happens in between: a timer firing, a poll already in flight, a restart of the watchdog
service, or the marker or lock files being removed, replaced or unreadable.

| # | Invariant | Enforced by | Proved by (`test_height_watchdog.sh`) |
|---|-----------|-------------|---------------------------------------|
| W1 | Control commands never interleave: a running `resume` cannot delete the `PAUSE` of a `pause` that started after it, and `pause` exits 0 only if its own `PAUSE` (by nonce) is present and `ARMED` absent after the drain. | ctl `take_ctl_lock` (`.ctl.lock`) before any marker change in pause/resume/release and contain step 2; pause's nonce check after `drain_polls` | "control race: pause waits for the running resume before writing", "...successful pause leaves PAUSE present and ARMED absent", "resume waits for the pause in progress", "pause confirms before the queued resume runs", "pause is NOT confirmed if its marker vanished during the drain" |
| W2 | When `pause`/`contain` succeed, no poll that read the markers before they changed is still running, even if the poll lock file was deleted meanwhile. | ctl `drain_polls`: holds the poll lock on the file currently at `.poll.lock` (inode checked, re-locks if replaced) and waits until `pgrep` finds no `citrate-height-watchdog.sh` process; timeout means NOT confirmed | race(a) held before its gate, race(b) held inside `systemctl restart`, race(c) lock file deleted under a running poll, "a stuck poll makes pause fail", contain race |
| W3 | Fail closed: a restart needs a valid `ARMED` record, no `PAUSE`/`CONTAIN` in any form (file, directory, dangling link, unreadable) and the poll still holding the current lock file, checked at poll start and again immediately before every `systemctl restart`. | watchdog `restart_permitted`, `guarded_restart`, `is_armed`, section 0c; setup failures (state dir or lock unusable) exit without restarting | section 12 "fail closed: ..." (PAUSE deleted / directory / dangling link / garbled, ARMED garbled or a directory, poll lock deleted or a directory, control lock deleted, state dir wiped or replaced by a file), race(a) "re-checks its gate" |
| W4 | State survives the watchdog's own restarts: a new poll (timer firing, `systemctl restart citrate-height-watchdog.service`, reboot) reads the on-disk markers in `/var/lib`, not memory. | markers live in `$STATE_DIR` (persistent); every poll starts from them | tests 4–5 (polls after pause), race(d) (in-flight poll's process group killed, then fresh polls) |
| W5 | Only `resume` arms. `pause` and `contain` delete `ARMED`; `release` and a fresh install leave it absent. | ctl: the only `write_marker "$ARMED_FILE"` is in `resume` | "fresh install (no ARMED) restarts nothing", "resume arms a fresh install", "release leaves the watchdog disarmed until resume", test 6 |
| W6 | `contain` stops the node only after the marker, the drain and the watchdog timer and service are off; `resume` is refused while contained. | ctl `contain` steps 1–5, each checked | tests 8–9, contain race |

Out of scope: someone who writes `ARMED` by hand, or restarts `citrate-node` themselves.

## Incident containment
For a suspected key compromise, never `pause` and `systemctl stop citrate-node`: a
stopped node's RPC goes quiet and an active watchdog restarts it after `STALL_SECS`.
```
citrate-watchdog-ctl.sh contain "<reason>"   # marker, running poll drained, watchdog timer off, THEN node stopped+disabled
citrate-watchdog-ctl.sh status               # CONTAINED
citrate-watchdog-ctl.sh release "<reason>"   # after the security response; starts nothing, stays disarmed
```
While `$STATE_DIR/CONTAIN` exists the watchdog restarts nothing, with no deadline, and
`resume` is refused. Each step is checked; the first failure stops the command.

Tests: `unshare --user --map-root-user --pid --fork --mount-proc bash scripts/ops/tests/test_height_watchdog.sh`
(hermetic: shimmed curl, systemctl, logger and alert hook; the private PID namespace keeps
the process drain from seeing watchdogs outside the test).

## 2026-09-27 fix — sync-aware liveness (CRITICAL)
The original script used `eth_blockNumber` (the canonical head) as its liveness
signal. **While the node is syncing / replaying state after a restart, the
canonical head legitimately stays frozen until the replay completes.** The old
watchdog read that frozen head as a wedged producer and restarted the node every
`STALL_SECS`, resetting the replay to the last durable state snapshot — turning a
recoverable state-rebuild into a *permanent halt* (chain halt 2026-09-27, block
254941).

Fix: when `eth_syncing != false`, use `eth_syncing.currentBlock` as the progress
signal instead of the head. The node is only "wedged" if its progress signal
(currentBlock while syncing, else the canonical head) is frozen for `STALL_SECS`.
A healthy replay advances `currentBlock` every poll and is never restarted.

## Deeper follow-up (tracked separately)
The incident's root trigger was that the node's *committed* state lagged far
behind the header tip (an unclean restart fell back to a ~14–20k durable
snapshot while the chain was at ~255k), forcing a full ~240k-block replay. That
state-persistence cadence ("pre-K.6" state-root persistence) should be made
durable/frequent so a restart never requires a multi-hour replay.
