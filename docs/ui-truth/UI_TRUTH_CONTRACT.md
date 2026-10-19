---
created: 2026-10-19T02:00:00Z
branch: docs/c1-ui-truth-contract
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
version: v1 (2026-10-19). Re-issued at each rehearsal and at genesis
applies_to: citrate-core, the design prototype (design/CitrateCore.dc.html), citrate.ai and docs copy
verified_against: citrate-chain c384fc98, address book 40204.json (deployedAt 2026-10-06), live 40204 at block ~499,000
---

# UI truth contract v1 (betanet workstream C1)

This is the chain team's contract with everyone who draws or ships a screen. It defines the words the app may use for chain state, every on-chain number it may show and where that number comes from, what is live and what is dormant, and how we talk about money. **The chain team has the final say.** If a screen and this file disagree, the screen is wrong. If this file and the chain disagree, tell the chain team; this file gets corrected, not worked around.

It refines `verification/claims.json` (public claims) for in-app state. It does not replace it. The address source is `contracts/addresses/40204.json` only.

## 0. The five rules

1. **Every number names its source.** A screen may show an on-chain number only if it is in the catalog (§2), read from the source named there. If a number is not in the catalog, it can't be shown. Ask for it (§10), and the chain team adds a real source first.
2. **Unknown is not zero.** When a read fails, times out or isn't available, show the unavailable state ("—" plus a reason). Never show 0. Several RPCs return a plausible value on error (§3), so the app must not treat their 0 as data.
3. **Not running means not shown as running.** Finality, multiple producers, pin rewards and group rounds are not live on 40204 (§4). Don't draw them as working, and don't describe them in tooltips, coach marks or agent replies as current.
4. **Fixtures are labelled.** Anything that isn't a live read is labelled "fixture" on screen, and comes only from a chain-team export (§7).
5. **No copy ahead of the chain.** Copy, tooltips, onboarding text and agent prompts follow the same rules as numbers. Money copy follows §5.

## 1. State vocabulary

Use these words exactly. Each has one meaning and one condition. If a state isn't listed, add it here before using it.

### Network and node

| Word | Means | Condition (source) |
|---|---|---|
| **Off** | The node process isn't running | Supervisor reports stopped |
| **Starting** | The process started but isn't answering RPC yet | Supervisor starting; local RPC not answering |
| **Syncing · N blocks behind** | Applying blocks to catch up | `eth_syncing` returns an object; N = `highestBlock − currentBlock`. Don't show a "% from start": `startingBlock` always equals `currentBlock` |
| **Synced** | Caught up with the network | `eth_syncing` = `false` **and** local `eth_blockNumber` is within 5 blocks of the public RPC head |
| **Sync stalled** | Peers exist but the applied height isn't moving | Local height unchanged for ≥ 60 s with `net_peerCount` > 0 |
| **No peers** | Can't reach the network | `net_peerCount` = 0 for ≥ 60 s. If the genesis check fails too, show *Update required* instead |
| **Update required** | This build is for a different genesis | Genesis hash ≠ the release genesis the app ships with (§6) |
| **Resync required** | Local data is on a withdrawn branch | A canonical checkpoint hash doesn't match (§6) |
| **Error** | The node failed to start or crashed | Supervisor failed or start blocked |

### Blocks and transactions

| Word | Condition |
|---|---|
| **Pending** | Transaction is in the mempool, with no receipt |
| **Included in block N** | Receipt exists (`eth_getTransactionReceipt`) |
| **N confirmations** | Head − N. This is a depth count, not finality |
| ~~Final, Finalized, Settled, Irreversible~~ | **Banned** until checkpoint finality runs and the `finalized` tag returns a height above 0. Today the `finalized` tag returns the genesis block |

### Validators

| Word | Means | Condition (source) |
|---|---|---|
| **Not a validator** | No stake in the registry for this key | `ValidatorRegistry.validatorInfo(pubkey).status` = None |
| **Bond locked · not staked** | Membership grant sits in the member's bond, not in the registry | `MemberBond.activated()` = false |
| **Staked · active from next epoch** | Stake is registered but the validator isn't in the set yet | Registered stake, `isActive(pubkey)` = false. The set changes at epoch snapshots (every 1,000 blocks, with a lag) |
| **Validator active** | In the active set | `ValidatorRegistry.isActive(pubkey)` = true |
| **Producing blocks** | This node actually proposed blocks recently | A block in the last 1,000 has `proposerPubkey` = this node's key. *Active* does not imply this: today only one validator produces |
| **Exiting** / **Slashed** | Registry status 2 / 3 | `validatorInfo.status` |
| ~~Validating~~ (for stake ≥ 32k), ~~building blocks~~, ~~producing again~~ | **Banned.** Use the words above. Self-stake in LiquidStakingPool never makes a validator; only the registry does |

### Membership and bond

| Word | Condition (source) |
|---|---|
| **Member** / **Membership lapsed** | `CitrateMemberSBT.isActive(tokenId)` true / false. `isActive` does not include KYC |
| **Locked until ⟨date⟩ (block N)** | `MemberBond.unlockTimestamp()` and `unlockBlock()`. Show both: the lock opens when either is reached |
| **Unlocked · verify identity to withdraw** | `isUnlocked()` = true and `isKycVerified()` = false |
| **Unlocked** | `isUnlocked()` = true and `isKycVerified()` = true |

### Rewards

| Word | Condition (source) |
|---|---|
| **Validator rewards** | `ValidatorRegistry.rewardsOf(pubkey).total` |
| **Claimable now** | `rewardsOf(pubkey).claimableNow` |
| **Maturing** | `total − claimableNow` (slashable for 4 epochs) |
| ~~Earning~~, ~~income~~, ~~projected~~, ~~estimate~~, ~~today~~ | **Banned.** No projections and no "per month at current demand". "Today" needs a per-day source, and none exists |

### Pins and group rounds (not live, see §4)

| Word | Condition (source: `IPFSIncentivesV3.getPin` / `getChallenge`) |
|---|---|
| **Pinned** | status Active, no challenger |
| **Challenged** | status Active, `getChallenge.challenger` ≠ 0 |
| **Complete · bond claimable** | status Done, `bondHeld` > 0 |
| **Released** | status Done, `bondHeld` = 0 |
| **Slashed** | status Slashed |
| **Pin bonds not live yet** | Required wording until V3 is funded at genesis |
| **Group rounds not live yet** | Required wording until FederatedRoundLedger and PatronageLedger are deployed. Today neither exists on 40204 |

Service states (Alive, Ready, Stopping, Quarantined) belong to the K1 services contract (SPEC-001), owned by core. They aren't chain state and are out of scope here.

## 2. Number catalog

Amounts are SALT with 18 decimals (wei), so divide by 1e18. Addresses come from `contracts/addresses/40204.json`. "Today" was read live on 40204 at block ~499,000 (fixture `docs/ui-truth/fixtures/40204-2026-10-19.json`).

| Number | Source | Display | Today |
|---|---|---|---|
| Network | `eth_chainId` **and** genesis hash (§6) | "Citrate betanet". Chain id alone is not enough: three profiles share 40204 | `0x9d0c`, genesis `0x1dcfc490…75f1` |
| Head height | Public `eth_blockNumber` (network). Local `eth_blockNumber` (this node) | Integer. If the call errors it returns `0x0`, so show unknown | 499,058 |
| Behind by | `eth_syncing.highestBlock − currentBlock` | "N blocks behind". `highestBlock` includes unverified peer claims, so it is a ceiling | `false` (synced) |
| Block time | Timestamp delta over the last 100 blocks | "~2 s". Never the 1 s config value | 2 s |
| Peers | Local `net_peerCount` | "N direct peers", not "the network" | 3 (public RPC) |
| Base fee / gas price | `baseFeePerGas` of the latest block | "1 gwei (fixed)". It is a consensus constant | 1 gwei |
| Active validators | `ValidatorRegistry.activeCount()` | Integer | 5 |
| Producing validators | Distinct `proposerPubkey` over the last 1,000 blocks | Integer. Show it next to *active* so the gap is visible | 1 |
| Minimum stake | `ValidatorRegistry.minStake()` | SALT. Read it; don't hard-code 32,000 | 32,000 |
| Block reward | `ValidatorRegistry.blockSubsidy()` | "N SALT per block, to the producer". It is governance-set, so read it, never hard-code it | 10 SALT |
| Epoch | `ValidatorRegistry.currentEpoch()`; `EPOCH()` = 1,000 blocks | Integer | 499 |
| Your stake | `ValidatorRegistry.stakeOf(pubkey)` | SALT. This is the **only** "staked" figure. Consensus weight (`activeSet().effStakes`) is capped at 1/3, so label it separately if shown | — |
| Validator rewards / claimable | `ValidatorRegistry.rewardsOf(pubkey)` | SALT, with the words in §1 | 1 of 5 validators has rewards |
| Bond principal | `MemberBond.principal()`; staked/locked state from `activated()` | SALT, plus the bond state word | 32,000 |
| Bond lock end | `MemberBond.unlockTimestamp()`, `unlockBlock()` | Date and block | ~2027-10 |
| Grants issued / members | `MembershipStakeVault.nextGrantId()`, `CitrateMemberSBT.nextTokenId()` | Integer. `totalSupply()` reverts, so don't call it | 5 / 5 |
| Balance | `eth_getBalance(addr, "latest")` | SALT, "latest". Errors return `0x0`, so show unknown | — |
| Max supply | `TOTAL_SUPPLY` (`core/economics/src/lib.rs:75`) | "Max supply 1,000,000,000,000 SALT". This is a cap, not circulating supply | 1T |
| Pin bond / pin reward | `IPFSIncentivesV3.BOND()`, `REWARD()`, `ROUNDS()` | Parameters only, until pins are live | 10 SALT / 4 SALT over 4 rounds |
| Skills / models listed | `SkillRegistry.totalSkills()`, `ModelRegistry.totalModels()` (the contract at `0x086F…75eF`, not a precompile) | Integer | 0 / 1 |
| Governance delay | `minDelay()` on GOVERNANCE / GUARDIAN | Hours | 2 h / 2 h |
| Durations given in blocks | Blocks × measured block time | Show both, e.g. "50,400 blocks (~28 h)". Never assume 12 s blocks | — |

Not in the catalog, so **not shown**: circulating or issued supply (no source exists), TPS (the app has no reason to show it; claims.json covers public copy), SALT price, any USD value of SALT, APY or yield, "finalized height", node version (no RPC serves it yet, see §9).

## 3. Never show (fabricated or misleading RPC values)

| Value | Why |
|---|---|
| `finalized` / `safe` block | Returns genesis: finality isn't running |
| `web3_clientVersion` | Hard-coded "citrate/v0.1.0" |
| `citrate_getDagStats` blue/red counts, `ghostdagParams`; `maxBlueScore` as a maximum | Blue/red counts are estimated as height × 0.95. The params are defaults, not the running config. `maxBlueScore` is the first tip's score |
| `citrate_getMempoolStats.avgGasPrice`, `aiOperations` | The first is average gas *limit*; the second is a heuristic |
| `mempool_getStatus.queued`, `max_size` | Hard-coded |
| `citrate_getToken.totalMinted`, `citrate_getEconomicState`, `citrate_getStakedBalance` | 0 / error object / in-memory state, not the registry |
| `eth_mining`, `eth_hashrate`, `eth_protocolVersion`, `net_listening` | Constants. `net_listening` returns `true` on error |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas` as market signals | Fixed at 1 gwei. Show the base fee instead |
| `NetworkApi::get_node_info` | Hard-coded zeros (not registered as an RPC) |

These return a believable value on error. Treat their 0 or `true` as "unknown" unless the call succeeded: `eth_blockNumber`, `eth_getBalance`, nonce, `net_peerCount`, `mempool_getStatus`, `chain_getTips`.

## 4. Live and dormant

| Feature | Today on 40204 (r1005) | At betanet genesis (final in the C2 genesis spec) |
|---|---|---|
| Block production | **One producer.** 5 validators are in the active set, but only 1 proposes | ≥ 4 producers on separate hosts and operators (C3) |
| Checkpoint finality | **Specified, not running.** The `finalized` tag returns genesis | Running if rehearsal 1 finalizes cleanly; otherwise turned on at an audited activation height before mainnet. Until then, rule 3 applies |
| Validator rewards | **Live** (`rewardsOf`), paid only to the producer | Live |
| Membership (Track M) | **Deployed.** Grants go into locked MemberBond clones; 4 of 5 bonds are locked but not staked | Staked, ~1-year locked bond (C4; decision pending) |
| Pin bonds (IPFSIncentivesV3) | **Deployed, dormant**: unfunded, no pins | Real bonds on the genesis contract |
| Group rounds (FederatedRoundLedger, PatronageLedger) | **Not deployed** | Deployed dormant (audit phase A). Rounds go live after mainnet |
| SkillRegistry / ModelRegistry | Deployed. 0 skills / 1 model | Populated for Store v1 (first-party) |
| LiquidStakingPool | Deployed, empty | The plan retires the liquid path; pending the money-path decision |
| Governance | 2-of-3 multisig, 2 h delay (GOVERNANCE and GUARDIAN) | 3-of-5 hardware governance, separate 2-of-3 hardware guardian; timelock set in C2 |
| Liquidity | None | None until the 1.0 soft fork |

## 5. Money copy (provisional until counsel review)

1. **No investment language for SALT**: not invest, investment, return, yield, APY, APR, profit, passive income, appreciation, or "price".
2. **No price or USD value for SALT** anywhere, and no exchange, listing or trading talk before 1.0.
3. **Membership price**: "$48 a year" comes from the membership service, not a hard-coded string. It buys membership; it does not buy SALT.
4. **Grant**: say exactly what the contracts do. "Your membership comes with a 32,000 SALT grant, locked in your bond until ⟨date⟩." Say "staked" only after `activated()`. Use one explanation everywhere: onboarding, Wallet, Node and the Hermes context.
5. **Rewards**: only on-chain reads (§2), named as rewards for producing blocks. No projections, formulas or "at current demand". If a member's node isn't producing, don't say it earns.
6. **Betanet balances**: don't promise that SALT carries over to mainnet. Until the C2 genesis spec decides, say: "Betanet. What carries over to mainnet is set in the genesis spec."
7. **Disclaimers**: the existing "not purchased, not an investment" line appears anywhere the grant is mentioned, not only in one onboarding step.

## 6. Network identity check (the app runs this before trusting any read)

1. `eth_chainId` = `0x9d0c`.
2. `eth_getBlockByNumber("0x0").hash` = the release genesis the app ships with. Today that is `0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1`. A new genesis ships with 0.5.2. A mismatch means **Update required**.
3. Canonical checkpoints: block 365,784 = `0x63dcd4a8c7cd701080e242e5949402da93143bfd0659b3012e57998da4aa2c56` and 365,785 = `0x51482ff9724a2f0cbf4fe678f3ce556f6222334d5b2a3f5eba8a2b52af0cf3d2`. A mismatch means **Resync required**. The list grows with each release; read it from the bundled release, not from this file.

A node on a stale genesis usually shows up first as `net_peerCount` stuck at 0, because peers reject the handshake.

## 7. Fixtures and rehearsal exports

- `scripts/ui-truth/export-fixtures.sh [rpc] [out]` reads every catalog value at one block and writes `docs/ui-truth/fixtures/<chain>-<date>.json`. Each read records its source and the block number. The file carries `"fixture": true` and a label that must appear on screen.
- **Now**: `fixtures/40204-2026-10-19.json` (live 40204) is the prototype's data until rehearsal 1.
- **Rehearsal 1** and **rehearsal 2**: the chain team exports from the rehearsal network and re-issues this contract. Design v2 uses the R1 export.
- States that need data the chain doesn't have yet (Challenged pin, Exiting validator, an open round) are drawn from the state tables in §1, labelled "fixture", with values from the parameter reads.

## 8. Known violations in citrate-core main (b521d98)

These are for the core lane to fix against this contract. Each is a board item on Project #5.

| # | Where | Problem | Rule |
|---|---|---|---|
| V1 | `Dashboard.tsx:109`, `data/seed.ts:146`, `agent/harness.ts:1014` | Finality described as running: "BFT checkpoint every ~50 blocks", "finality" in the coach, "last BFT checkpoint settled" in the fallback agent | 3 |
| V2 | `Node.tsx:160-164, 495-502`; `store.ts:561-562` | Heartbeat "last ack 4s ago" is stuck at its seed value in the app and presented as slashing protection | 2, 3 |
| V3 | `Node.tsx:179-185, 513-537` | Pin projections (bonded × 0.0075 "per month at current demand") and "challenges passed" (pins × 9 + 4) are made-up formulas labelled live | 1, 3, §5.5 |
| V4 | `store.ts:405, 1394, 1424`; `Onboarding.tsx:864` | "validating" from stake ≥ 32k (including LiquidStakingPool self-stake); "producing again" toast; "every full node builds blocks" | §1 Validators |
| V5 | `Onboarding.tsx:740-742, 798, 824`; `Wallet.tsx:383`; `store.ts:2042` | Three different explanations of grant custody | §5.4 |
| V6 | `Wallet.tsx:411, 426-433` | Withdrawal time assumes 12 s blocks: "~7 days (50,400 blocks)" is ~28 h at 2 s | §2 durations |
| V7 | `Dashboard.tsx:72-79`, `Wallet.tsx:46-55`, `Node.tsx:70`, `store.ts:2026-2034` | Four definitions of "staked" (one hard-codes 32,000) | §2 Your stake |
| V8 | `Wallet.tsx:271`; `Node.tsx:144-147, 466-479`; `Dashboard.tsx:117-124` | Liquid balance captioned "earned rewards"; real `rewardsOf` labelled "off-chain estimate"; Claimable caption names the wrong source; "Today" has no writer | 1, §1 Rewards |
| V9 | `Wallet.tsx:54, 257`; `Onboarding.tsx:836` | "source · local node" when reads go to rpc.citrate.ai; stale vault and SBT addresses in a live caption | 1 |
| V10 | `state.ts:756-759, 988-1002` | Seeded height 131,204 and persisted node state show before the first poll | 2, 4 |
| V11 | `Train.tsx`; `src-tauri/src/addresses.rs:55, 200` | Reads PatronageLedger, which isn't deployed on 40204. It must show "Group rounds not live yet" | 2, 3 |
| V12 | `Onboarding.tsx:572, 613`; `Settings.tsx:439` | "$48" hard-coded | §5.3 |

## 9. Chain-side follow-ups (DGX lane)

- **claims.json errata**: precompile set (agent precompiles 0x0112, 0x0113, 0x0121, 0x0122 are live; 0x0104 retired), ModelRegistry precompile flag (fixed in G, set agrees = true), the `finalized` tag note (the tag is served since #250 and returns genesis), the supply pointer (`lib.rs:75`), the `deployed_contracts` verification date, and re-run test counts.
- **RPC honesty**: real node version and consensus fingerprint over RPC, a genesis-hash method, errors instead of silent defaults (§3), drop the DAG-stats estimates, and fix the `eth_feeHistory` reward shape and `citrate_getToken.totalMinted`.
- **Mainnet profile**: `GenesisConfig::mainnet()` uses chain ID 1 and placeholder addresses; `node/config/mainnet.toml` is a skeleton. Resolved in C2.

## 10. Changing this contract

- To show a new number or state, add a board item (Project #5, Workstream C1, Lane DGX). The chain team names a real source first (Rule 7), then adds it here. Until then, the screen shows the unavailable state.
- Version bumps at each rehearsal and at genesis. Each version notes what changed.
- Sign-off: the chain team checks each prototype screen against this file. Core checks that every bridge call it needs exists.
