---
created: 2026-07-18
branch: fix/ghostdag-select-tip-determinism
author: Claude Opus 4.8 (1M), directed by @SaulBuilds
status: journal
---

# Journal — reroll day

## Morning: the ceremony
It started calm and procedural. The build side was already done and reviewed; today was the
execution — turn verified branches into a live rerolled chain and reconnect everything. I picked up
mid-swing on Phase B, deploying `ValidatorRegistry`. It reverted immediately: `set
CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS`. Small thing — the deploy script wanted the
deployer's *public* address in the env. Set it, and the registry landed at `0x3Bf6C5bb…`, exactly
its frozen address. That first byte-for-byte match sets the tone: the freeze is real, CREATE2 is
holding, and the rest of the deploys are a matter of feeding each script the right constructor args.

The AA stack was the one place that made me slow down. The factory and paymaster addresses depend
on their constructor args, so I couldn't guess — a wrong signer address and the frozen address
walks. I found the canonical args by reading the determinism *test* that asserts the frozen pins,
fed them in, and the whole stack reproduced: EntryPoint, factory, paymaster, walletImpl, guardian —
all matching. Membership needed the pool first (a `require(code.length > 0)`), so I ran the business
stack, then the SBT and vault. Nine contracts, all frozen, all verified.

Then the validators. I built the ceremony binary on the DGX so the keys never left the box, derived
the four stakers from the deployer key, confirmed each was funded @40k, and registered all four.
`activeCount() = 4`. The satisfying part: watching the node log *"synced validator set for epoch 1
at snapshot height 800 (4 validators)."* The machinery I couldn't fully see was working.

## Midday: the crossing, and the fork
The activation crossing at height 2000 was the real gate — the moment §R' enforcement turns on and
rpc-1 has to keep producing under it. I set a monitor and watched. It sailed through: 45 blocks
produced in 90 seconds, zero rejects. The chain was live under the new consensus rules.

Then I got greedy in a useful way. I enabled a second producer to make the four-validator set
*real* — and the fleet forked instantly. Both nodes at the same height, different state roots. My
stomach dropped a little, then the engineer took over. rpc-1 was untouched and canonical; I reverted
the second producer and spun up a subagent to root-cause it. The answer was almost elegant: the
receive-side fork choice iterated a `HashSet` with no tie-break, so two equal-score sibling tips
resolved to whatever the hash-set surfaced first — different on every node, never converging. The
producer path already tie-broke by hash. One function, one asymmetry. I wrote the fix and a
determinism test, and it went green. A practice ceremony had done exactly what a practice ceremony
is for: it found the landmine before it mattered.

## Afternoon: the reconnect, and a long descent into sync
Reconnecting the services was steady work with one nice bonus — fixing the long-standing "paymaster
registerWallet gap" turned out to be a one-line compose change (a key that was never mapped
through). The money path came together and I proved it end to end: a real grant minted SBT #0, and
`tokenURI(0)` rendered a fully on-chain SVG emblem. Seeing the ciphertext-free art come straight off
the chain — that was the payoff of the whole WS-2 thread.

And then the boots wouldn't sync, and the day turned into a long descent.

I want to be honest about this part, because it's where I spent the most and learned the most. Every
production log was ambiguous — asymmetric connections, self-dials, ids that looked like they were
talking to themselves. I chased hypothesis after hypothesis: duplicate connections, peer selection,
stale state. Each one felt right and each one was wrong or incomplete. The turning point was
building a **local two-node harness** — a real producer and a real follower on the box — which
reproduced the stall deterministically and, crucially, *without* any of the fleet's confounders.
That's when it stopped being guesswork.

The bugs came out in a stack. The follower advertised a *static* head captured at startup — genesis,
height zero — so no one ever knew it was behind. It anchored sync on its stored height index instead
of its applied tip, so it asked for the wrong blocks. Its pending requests never retired on empty or
sibling responses, so it timed itself out and dropped its only source. Five distinct bugs, and four
of them were the same conceptual mistake — applied-tip vs stored-height — wearing different clothes.
Each fix, validated in ninety seconds against the harness, then rebuilt and redeployed to the fleet.

The last one had a twist I didn't expect: the near node (same datacenter as rpc-1) caught up cleanly,
but the two distant boots hit a real cross-region wrinkle, and past that, a still-open architectural
issue — two competing sync mechanisms, one of which declares "complete" at a stale target. I could
have kept peeling, but I'd been at it a very long time, and the honest engineering call was to name
it precisely, prove one node converges, and queue the reconciliation as its own focused piece rather
than keep hot-patching a live fleet at 2am-brain.

## Evening: the database, clean
The session closed on something satisfyingly bounded. core-membership needed its Neon database
provisioned; the user set it up, we hit a secret-in-plaintext snag, they rotated it (correctly),
and I ran the migration clean — six tables, field-encrypted with keys outside Neon, the app
redeployed and connecting. A stray ops script broke the build; I pulled it out, the build passed,
and I scrubbed the secret off disk. In and out, no rabbit hole. A good note to end on after the
sync marathon.

## What I'll carry forward
The chain came through this without a hiccup, and the two hard problems it exposed are exactly the
kind you want to find in a practice run. The frozen book held. The money path is real. And I have a
harness now that turns the next sync bug from a séance into a debugger.
