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
```
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

`pause` returns only once no poll that started before the marker can still act: every
poll holds an exclusive flock on `$STATE_DIR/.poll.lock` from its marker check through any
restart, and `pause` writes `PAUSE` and then waits (up to `LOCK_WAIT_SECS`, default 300 s)
for that lock. If the wait times out it exits non-zero with "NOT confirmed": the marker is
in place, but do not start the maintenance until a re-run of `pause` succeeds. A poll that
finds the lock taken by a control command restarts nothing that round.

## Incident containment
For a suspected key compromise, never `pause` and `systemctl stop citrate-node`: a
stopped node's RPC goes quiet and an active watchdog restarts it after `STALL_SECS`.
```
citrate-watchdog-ctl.sh contain "<reason>"   # marker, running poll drained, watchdog timer off, THEN node stopped+disabled
citrate-watchdog-ctl.sh status               # CONTAINED
citrate-watchdog-ctl.sh release "<reason>"   # after the security response; starts nothing
```
While `$STATE_DIR/CONTAIN` exists the watchdog restarts nothing, with no deadline, and
`resume` is refused. Each step is checked; the first failure stops the command.

Tests: `bash scripts/ops/tests/test_height_watchdog.sh` (hermetic: shimmed curl,
systemctl, logger and alert hook).

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
