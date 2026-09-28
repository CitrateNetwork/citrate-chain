# citrate-height-watchdog

External anti-wedge auto-recovery for the block producer (rpc-1). The node has no
`sd_notify`, so this systemd timer (every 30s) polls the local RPC and restarts
`citrate-node` if the producer is genuinely wedged.

## Install (per producer host)
```
install -m0755 citrate-height-watchdog.sh /usr/local/bin/citrate-height-watchdog.sh
cp citrate-height-watchdog.service citrate-height-watchdog.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now citrate-height-watchdog.timer
```

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
