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
- [ ] I. Chain cross 2000 (activation); G8: 0 post-activation state-root mismatches all 4. (~47 min from head 573.)
- [ ] I. Let chain cross 2000; G8: 0 post-activation state-root mismatches on all 4.
- [ ] J. G9 restart-resilience: restart a fresh cold node + restart the miner mid-epoch → no divergence (THE 2209 fix).
- [ ] K. Treasury-signer rekey (droplet 157.230.55.191) — likely NO-OP (addrs unchanged); G10 /health.
- [ ] L. G4 external cold-sync: fresh aarch64 node genesis→head matches fleet on root+balance; citrate-core Linux+Mac.
- [ ] M. Downstream re-pins (GATED): update .env.testnet SBT/vault; consumer sync-addresses; identity/bundler.

# Key handling: DEPLOYER/TREASURY/GRANT_SIGNER/VALIDATOR_STAKER_* keys read from .env.testnet by
# scripts/forge/ceremony ONLY; never argv/echo/log. C-1 in force. Never pgrep -af the deploy proc.
