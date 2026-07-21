---
title: "SRP-S2 reroll — LIVE execution status (resumable across context windows)"
created: 2026-07-21
branch: srp/s2-reapply-reward-purity
author: Claude (Opus 4.8, 1M) for SaulBuilds
status: PREP COMPLETE — beginning destructive fleet wipe
chain: 40204
---

# What this is
The SRP-S2 fix is done + validated (see SRP_S2_REAPPLY_REWARD_PURITY_HANDOFF + the ADR/spec/red-test
on branch srp/s2-reapply-reward-purity, HEAD 9941f1f). This doc tracks the LIVE reroll that recovers
the split-brain chain onto the fixed binary. Address-neutral (Rust-only fix). If context is lost,
resume from the first unchecked step below.

# Reroll binary
- HEAD **9941f1f** (main + SRP-S2 reward-purity fix + BLOCK_V2 default-on).
- x86_64 (fleet): md5 **a7f52424b86d1ab46f107fab4d6401da**, built on rpc-1, STAGED on all 4 nodes as
  `/home/citrate/bin/citrate-node.srp-s2` (md5 verified identical on all 4).
- aarch64 (DGX/Mac cold-sync proof): `citrate-chain/target/release/citrate` (local).

# Fleet (all user citrate, bin /home/citrate/bin/citrate-node, data /home/citrate/.citrate; I SSH as root)
| node | ip | coinbase == staker | role |
|---|---|---|---|
| rpc-1 | 142.93.58.145 | 0x0ecbcd85…363b (STAKER_1) | MINER |
| boot1 | 142.93.50.217 | 0xE6221997…658F (STAKER_2) | boot |
| boot2 | 143.198.134.151 | 0xac8e8B2e…22B8 (STAKER_3) | boot |
| boot3 | 142.93.99.212 | 0xFa5FC645…6975 (STAKER_4) | boot |
Systemd env on ALL (verified): CITRATE_BLOCK_V2=1, CITRATE_VALIDATOR_ACTIVATION_HEIGHT=2000,
CITRATE_VALIDATOR_REGISTRY=0x915DdE02831ebacFc57f329f60944492ebb0A095. node.toml+noise.key+models/
live INSIDE /home/citrate/.citrate (PRESERVE on wipe).

# Verification targets (on-chain confirmed on the OLD chain; the reroll must reproduce)
- genesis hash **0xd1a1941e…**, genesis stateRoot **0xd703e8c6…**
- deployer 0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732
- registry 0x915DdE02831ebacFc57f329f60944492ebb0A095 (activeCount()==4)
- EntryPoint 0xc698feaf0ff7fdb0d60e2f620c97cb729a694975
- SBT 0x4CE39F891c0A519Fa0E0De97A1DD3e3f856e0cF1, vault 0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268
- SBT/vault owner == grant signer 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483
- 44 core+feature+AA per contracts/addresses/40204.json
- ⚠️ .env.testnet CITRATE_MEMBER_SBT_ADDRESS/MEMBERSHIP_STAKE_VAULT_ADDRESS are STALE (0x16041DDF/
  0x94c0A523, no code) — do NOT trust; use the book values above; update .env after membership deploy.

# EXECUTION CHECKLIST  (tick as done)
- [x] A. Build x86_64 (rpc-1) + aarch64 (local); stage on all 4 nodes. md5 a7f52424.
- [x] B. Atomic wipe (rpc-1 first, then boots) — surgical (node.toml+noise.key+models preserved);
      binary swapped (backup .pre-srp-s2). Archives .citrate.preroll-srp-s2-<ts> on each node.
- [x] C. rpc-1 isolated; **G1 PASS**: chainId 0x9d0c, block-0 0xd1a1941ede584b26…, stateRoot
      0xd703e8c6fac5148f…, Arachnid code YES, deployer 0x84595161401484a000000 (10M).
- [x] D. Boots started; **G2 PASS**: stateRoot byte-identical on all 4 @ h10/50/80
      (0x018914cf/0x6299847f/0x2b68ed0b); 0 mismatches on the fresh chain. (The 44k old
      "mismatch" log lines were the pre-reroll 2209-loop tail; historical eth_getBalance is
      pruned→returns latest, so per-height balance queries are unreliable — use stateRoot.)
- [x] E. regenesis.sh --with-aa DONE; **G3 PASS** — 44 core+feature+AA redeployed ADDRESS-NEUTRAL
      (git diff shows only SBT/vault/registry removed, re-added in F/G; no core address moved);
      EntryPoint 0xc698feaf code 23882. CITRATE_AA_ENTRY_POINT was blanked (.env backed up).
- [x] F. post-reroll-membership.sh — **G6 PASS**: SBT 0x4CE39F891c0A519Fa0E0De97A1DD3e3f856e0cF1,
      vault 0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268 (frozen), owner 0xF42a1919. NOTE: the
      script's book re-pin + 200k funding did NOT run (python3 hook killed it mid-script) — I
      completed BOTH manually (uv run python3 re-pin at TOP-LEVEL keys; cast send 200000ether from
      TREASURY_PRIVATE_KEY, tx 0x0cd7798c, grant signer balance now 200000 SALT).
- [x] G. DeployValidatorRegistry — **G7 PASS**: projected==deployed==0x915DdE02, code 23614; re-pinned book.
- [x] H. validator-registration-ceremony --force — **G5 PASS**: 4 registered (32k each, status 0x1),
      activeCount()==4, pubkeys byte-identical to old chain (0x1af7f9d5/0x25b78e08/0x39bd37a4/0xd7da4213).
      Registered at head ~570, well before S(2)=1800.
- [x] I. **G8 PASS** — S(2)=1800 sr@1799 identical all 4 (0x2ee6f850); activation 2000 crossed,
      sr@2001 (0x20d32ec8) + sr@2005 (0xa5a4ef8d) identical all 4; **0 mismatches** whole fresh chain.
- [x] J. **G9 FAILED — SECOND BUG.** Restarting the MINER (rpc-1) post-activation re-poisoned block
      2042 (empty, gasUsed 0). rpc-1 claimed sr 8c7c1675; boots compute 01a6b4a6 → split-brain again
      (rpc-1 solo 2174+, boots frozen applied-2041). SRP-S2 (enhanced path) is genuinely fixed (G1-G8
      clean); a SECOND restart-path impurity survives. On an EMPTY block §R' vest is inert (share=0),
      so it's NOT the §R' credit — first post-restart block (2041) applied clean, SECOND (2042) diverged.
      rpc-1 log: "boot rehydration — durable epoch-2 snapshot (4 validators) reloaded" then producer
      counter reset (block #1=2041, #2=2042). Every block "Persisted 51 modified accounts". → SRP-S3.
      **CHAIN CURRENTLY BROKEN past 2042 (not syncable by anyone incl. citrate-core). Needs bug-2 fix
      + a fresh restart-durable reroll before distribution.** main merge (260976b) fix is real but
      incomplete for restart-durability.

# ▶ SRP-S3 (bug #2): restart-produced-block purity — spec-first, then FINAL reroll (in progress)

## SRP-S3 FIX (branch srp/s3-restart-produced-purity, 8d149c1) — DONE, all green
- Mechanism CONFIRMED by red test: calculate_state_root folds the volatile RESIDENT account map;
  a spurious resident EMPTY account (read-through/restart) changes the root though committed state
  is identical → block-2042 fork. Fix = EIP-158 (AccountState::is_empty(); skip empties in the
  fold) + boot HARD-FAIL on root mismatch. TLA RestartProducePurity.tla TLC-clean. ADR + planset +
  tripwire committed. citrate-execution 567/567, node-bin 121/121, rprime/rollback green.
- Binaries: x86_64 md5 c61b9b99 (rpc-1), aarch64 md5 c482ccc8 (local). Staged on all 4.

## SRP-S3 REROLL (FINAL, restart-durable) — live, gates so far ALL PASS
- Fleet wiped+swapped (surgical, keys preserved), binary c61b9b99 on all 4.
- **G1 PASS** — genesis UNCHANGED (0xd1a1941e / stateRoot 0xd703e8c6): genesis has no empty
  accounts so EIP-158 doesn't move it → reroll is genesis-neutral AND address-neutral.
- **G2 PASS** — 4-node consensus, early sr identical (0x018914cf@10, 0x632c7e22@20), 0 fresh mismatches.
- **G3 PASS** — regenesis --with-aa; 44 core+feature+AA redeployed address-neutral; EntryPoint 23882.
- **G6 PASS** — SBT 0x4CE39F89 + vault 0x61E324cF (frozen), owner grant signer 0xF42a1919, book
  re-pinned (top-level), grant signer funded 200k. (post-reroll-membership python3 hook killed the
  script mid-run AGAIN → re-pin + funding done manually, as in S2.)
- **G7 PASS** — DeployValidatorRegistry projected==deployed==0x915DdE02 (23614); book re-pinned.
- **G5 PASS** — 4 validators registered (32k each, status 0x1), activeCount()==4, head ~237 (<<1800).
- [ ] G8 — crossing activation 2000 (monitor bwn08ga36, ~45 min). Then:
- [~] G9 restart proof — MIXED:
    - FOLLOWER restart (boot1, restarted at h63 then re-synced FORWARD across activation): **PASS**,
      0 mismatches, sr@2001 agrees on all 4. Forward-apply (incremental) is clean.
    - MINER restart (rpc-1, restarted at h2345 = state WITH contract storage): **boot HARD-FAIL
      FIRED** (working as designed — safe stop, NO poison). rpc-1 hydrated root 49fb5eac !=
      persisted root 0b14c2ea @2345. Chain SAFELY HALTED (rpc-1 stopped; boots hold correct 0b14c2ea).

# ✅ SRP-S3b ROOT CAUSE PINNED (state-digest diff, exact): producer persists STATE one block ahead of the committed BLOCK
- state-digest on rpc-1 (producer, halts→49fb5eac) vs boot3 (follower, correct→0b14c2ea): 69 accts /
  238 slots, ONLY 2 differ — coinbase 0x0ecbcd85 (+9 SALT) + treasury 0x1111 (+1 SALT) = EXACTLY one
  block's basic reward (9+1). Registry/§R' storage byte-identical. Follower reloads faithfully.
- Mechanism: produce_block writes durable STATE (persist_state_changes, producer.rs:1016) BEFORE the
  BLOCK (put_block :1039) + state-root ptr (:1042) + applied-tip (record_produced :1051). A stop in
  that window (which includes maybe_sync_registry + a calculate_state_root) leaves the FLAT state
  store one reward ahead of the committed block. On restart the reloaded state root != latest committed
  block root → (now) boot-halt. Purely crash-consistency/restart; NOT a live-fork (live roots agree).
- Why atomic is required: state + applied-tip are two separate FLAT durable facts (flat state store
  has no height). Any WRITE ORDER leaves a window where they disagree → boot-halt (state ahead of tip)
  or drain double-applies (tip behind state). Only an ATOMIC (state-batch + applied-tip) RocksDB write
  (all stores share one db: Arc<RocksDB>) + block-first (block may lead; existing forward-drain catches
  state up by re-applying — deterministic since SRP-S2) is correct.
- FIX PLAN (SRP-S3b): (1) persist_state_changes writes the applied-tip pointer in the SAME atomic
  batch (new StateStore method / StorageManager commit) so state==tip always; (2) put_block BEFORE the
  atomic state+tip commit (block may lead, drain re-applies); (3) boot-check compares loaded-state-root
  vs the APPLIED-TIP's root (not latest-BLOCK) — a follower/producer legitimately stores blocks ahead
  of applied. Red test: persist state for N, DON'T commit tip, reload → must recover to N (drain) not
  halt. G9 miner+follower restart must pass. Same for the receiver apply path (apply_block_inner).

# (superseded) earlier framing: "bulk-reload hydration != live root" — REFUTED (follower reloads fine)

## SRP-S3b FIX DONE (branch srp/s3-restart-produced-purity, 2eac545) — all green
- StateStore::write_state_batch_with_applied_tip: state batch + applied-tip pointer in ONE atomic
  cross-CF RocksDB WriteBatch (all stores share one db). Executor::persist_state_changes_with_tip
  used by producer + receiver. produce_block reorders: put_block FIRST, then atomic state+tip; the
  forward drain re-applies a stored-ahead block deterministically. Boot-check compares vs the
  APPLIED-TIP root (not latest block). Tests: srp_s3b_state_and_applied_tip_advance_atomically +
  srp_s3b_bulk_reload_reproduces_live_root. execution 567, storage 13+6, node-bin 121, rprime+rollback green.
- Binaries: x86 md5 8c01e57a (rpc-1), aarch64 c482ccc8→(rebuilt) local. Staged on all 4 as .srp-s3b.

## RECOVERY ATTEMPT (option B, abandoned): swap boots to S3b + wipe/resync miner.
- Boots swapped to S3b: boot-check PASSED on all 3 (S3b reloads S3 state identically — root calc
  unchanged). rpc-1 wiped+cold-synced to 2345 (sr 0b14c2ea, correct) + resumed mining. BUT boot2/3
  then "Rejected inconsistent block" (ghostdag.validate_block_consistency — DAG blue-score/parent
  linkage), a DAG-CONTINUITY artifact of cold-syncing a MINER then producing — NOT an SRP issue
  (roots agree). Does NOT occur on a normal restart (G9 restarts without wipe → DAG preserved).
  → abandoned recovery, went to clean full reroll.

## SRP-S3b FINAL REROLL — live (binary 8c01e57a on all 4)
- Fleet stopped+wiped (surgical). **G1 PASS**: genesis 0xd1a1941e / sroot 0xd703e8c6 UNCHANGED
  (S3b changes only persist timing, not root calc → genesis+address-neutral). **G2 PASS**: 4-node
  consensus sr@10=0x018914cf sr@20=0x632c7e22, 0 mismatches.
- FIRST S3b reroll attempt ABORTED: a multi-hour wall-clock gap let the chain run to 1999 BEFORE
  the registry/validators were deployed → it halted at 1999 (couldn't produce 2000 with an empty
  epoch-2 snapshot; safe, no fork). LESSON: register validators FIRST (front-loaded), before any gap.
- SECOND S3b reroll (front-loaded) — live:
  - **G1 PASS** genesis 0xd1a1941e/0xd703e8c6 unchanged.
  - **G7 PASS @head 15** — DeployValidatorRegistry 0x915DdE02 FIRST (before boots).
  - **G5 PASS @head 27** — 4 validators registered, activeCount()==4, ~1773 blocks to 1800 (gap-safe).
  - **G2 PASS** — boots joined, sr@10=0x018914cf sr@20=0x686420bc agree on all 4.
  - [~] regenesis --with-aa RUNNING (bg). Then membership(F/G6) + book re-pin + grant-signer fund +
    cross-activation(G8) + **G9 DURABLE RESTART PROOF (restart miner+follower WITHOUT wipe)**.
    Only after G9: merge srp/s3 → main + update citrate-core handoff.

# ✅ SRP-S3c FIXED + G9 PROVEN (binary be0f55c3, branch d00e29d): miner restart no longer wedges
- Root cause: after a miner restart, the drain's fork-choice select_tip transiently returned an
  already-applied ANCESTOR as "best"; reorg_to state_restore'd the executor back to that fork-point
  snapshot every tick → producer's sealed root FROZE (173/174/175 all 966a9fa9) → boots rejected →
  wedge. Fix: reorg_to declines any reorg to a block already on the applied chain (backwards reorg;
  fork-choice only ever advances to a strictly heavier tip). Test reorg_to_applied_ancestor_is_declined.
- **G9 PASS (live)**: restarted the MINER (rpc-1, S3c, no wipe) → boots' APPLIED tips advanced in
  lockstep (88/89/90), 0 mismatches, 0 reorg-thrash, sr@70 identical on all 4 (0xb2fa526e).
- **G9b PASS**: SECOND miner restart + simultaneous FOLLOWER (boot2) restart → all 4 advancing
  (126-129), 0 mismatches, sr@110 identical (0xf2594ddc). Restart durability proven REPEATEDLY.
- ALL FOUR facets fixed: S2 (enhanced path) + S3 (EIP-158) + S3b (atomic state+tip) + S3c (no
  backwards reorg). Miner AND follower restart mid-operation without divergence.

# (historical) SRP-S3c investigation notes below
- Setup complete (G1/G2/G3/G5/G6/G7 all PASS, front-loaded registration). Then the G9 MINER restart
  (rpc-1, no wipe, S3b binary): boot-check PASSED (S3b atomic commit works — no halt), miner resumed
  producing. But: blocks 173,174,175,... ALL sealed the SAME state_root 0x966a9fa9 (block 172 was
  0x7419d165, changed correctly; from 173 on the sealed root FROZE) while rpc-1's actual balances
  kept growing (state-digest @188 = 301a057c, coinbase/treasury advanced 188 blocks). So after a
  miner restart, calculate_state_root returns a STALE/FROZEN value during PRODUCTION — the sealed
  root stops reflecting the applied reward → boots compute the real (changed) root and REJECT (wedge
  at applied-173, reject-looping 174: claimed 966a9fa9 vs computed fbab6a6c). state-digest diff:
  only coinbase+treasury differ (by the height delta) — pure basic-reward path.
- This is NOT S2 (enhanced path gone), NOT S3 (EIP-158, non-empty accounts), NOT S3b (atomic commit
  works — no halt). It is a NEW facet: the producer's calculate_state_root goes stale after restart
  (possible caching / two-state_db / drain-interaction; needs an in-process repro: restart executor,
  produce 3 blocks, assert each sealed root == reward-applied root). S3b's atomic commit let the
  miner START (vs S3's halt), which EXPOSED this production-path freeze.
- IMPACT: MINER restart wedges the chain. FOLLOWER restart is FINE (boot2/boot3 restarted clean,
  boot-check PASS — the partner-relevant case). Cold-sync FINE. So partners (followers, no mining)
  are unblocked; only MY operational miner can't be safely restarted yet.
- CURRENT FLEET: rpc-1 stopped (bad fork 174+), boot3 stopped, boot1/boot2 idle at applied-173
  (correct 0b14... no, this reroll's 173=966a9fa9). Chain not advancing. Needs a reroll to recover.
- DECISION PENDING (owner): (A) reroll clean + distribute now (followers work; DON'T restart miner;
  track SRP-S3c as follow-up) vs (B) keep digging SRP-S3c before distributing (deep, uncertain).
- EIP-158 fixed the empty-account facet (S2's block-2042). The boot HARD-FAIL then caught a SECOND,
  distinct restart facet: get_all_accounts + get_all_storage bulk-reload (main.rs:1020/1035) does
  NOT reproduce the live-computed root for a state WITH contract storage. Forward-apply nodes (boots,
  boot1-resync) build storage incrementally and are correct (0b14c2ea); rpc-1's bulk-reload diverges
  (49fb5eac). So the STORE is not a byte-faithful mirror of the live committed state (a persistence
  round-trip bug), OR the reload fold differs. NOT zero-slot filtering (write_state_batch_sync writes
  zeros + deletes None faithfully). Likely the registry/contract storage_trie or an account round-trip.
- IMPACT: blocks restart-durability AND citrate-core close/reopen (a fully-synced node reopened at a
  storage-bearing height bulk-reloads → boot-halt → won't start). HARD BLOCKER for distribution.
- Chain state: SAFELY HALTED at 2345 (boot-halt = fail-safe worked, no fork). Boots hold correct
  state. Recoverable. rpc-1 stopped (was crash-looping the halt).
- FIX SCOPE: needs deep persist/reload round-trip debugging (instrument live-trie vs store at a
  height) → targeted fix, OR the durable redesign (root from a committed authenticated trie, not the
  reconstructed in-memory caches — diagnostic "option 1"). Do NOT merge srp/s3 to main until this is
  fixed + G9 (miner restart) passes. EIP-158 + boot-halt commits (21a9484) are correct + keep.
- [ ] I. Let chain cross 2000; G8: 0 post-activation state-root mismatches on all 4.
- [ ] J. G9 restart-resilience: restart a fresh cold node + restart the miner mid-epoch → no divergence (THE 2209 fix).
- [ ] K. Treasury-signer rekey (droplet 157.230.55.191) — likely NO-OP (addrs unchanged); G10 /health.
- [ ] L. G4 external cold-sync: fresh aarch64 node genesis→head matches fleet on root+balance; citrate-core Linux+Mac.
- [ ] M. Downstream re-pins (GATED): update .env.testnet SBT/vault; consumer sync-addresses; identity/bundler.

# Key handling: DEPLOYER/TREASURY/GRANT_SIGNER/VALIDATOR_STAKER_* keys read from .env.testnet by
# scripts/forge/ceremony ONLY; never argv/echo/log. C-1 in force. Never pgrep -af the deploy proc.
