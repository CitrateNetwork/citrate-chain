---
created: 2026-10-19T02:00:00Z
updated: 2026-10-22T12:00:00Z
branch: docs/c1-ui-truth-v1.2
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
version: v1.2 (2026-10-22). Re-issued at each rehearsal and at genesis. What changed is in §12 (v1.1) and §13 (v1.2)
applies_to: citrate-core, the design prototype (design/CitrateCore.dc.html), citrate.ai and docs copy
verified_against: citrate-chain c384fc98 (origin/main; contracts/src/ValidatorRegistry.sol, core_membership/MemberBond.sol, LiquidStakingPool.sol); v1.2 rules against citrate-chain b4dc3b1b (origin/main; core_membership/MemberBond.sol, core/execution/src/executor.rs, core/api/src/eth_rpc.rs), address book 40204.json (deployedAt 2026-10-06), live 40204 at heads 510,030–510,047 (committed fixture) and ~512,250 (v1.1 spot check), latest state
---

# UI truth contract v1.2 (betanet workstream C1)

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
| **Syncing · N blocks behind** | Applying blocks to catch up | `eth_syncing` returns an object; N = `highestBlock − currentBlock`. Show the block count, not a percentage ("syncing N%" is not a §1 word). `startingBlock` always equals `currentBlock`, so there is no "% from start" either |
| **Synced** | Caught up with the network | `eth_syncing` = `false` **and** local `eth_blockNumber` is within 5 blocks of a public RPC head read in the last 60 s |
| **Sync unknown · network head unavailable** | The node says it isn't syncing, but the app can't check that against the network | `eth_syncing` = `false` and the public RPC head can't be read (error, timeout, `0x0`, or the last good read is older than 60 s). Never fall back to "Synced" on the local `eth_syncing` alone: a node far behind can report `false` (the 2026-08-06 case at 67,824 vs ~84,000). Show the local height labelled "this node", or "—" with this reason. Block production stays unarmed in this state |
| **Sync stalled** | Peers exist but the applied height isn't moving | Local height unchanged for ≥ 60 s with `net_peerCount` > 0 |
| **No peers** | Can't reach the network | `net_peerCount` = 0 for ≥ 60 s. If the genesis check fails too, show *Update required* instead |
| **Update required** | This build is for a different genesis | Genesis hash ≠ the release genesis the app ships with (§6) |
| **Resync required** | Local data is on a withdrawn branch | The local node has applied the checkpoint height, returns **that** block (its `number` is the checkpoint height) with a well-formed hash, and the hash differs from the canonical checkpoint (§6). Anything else (a null, an error response, a block without a `number`, a block for another height, a missing or malformed hash) means "not yet", never "Resync required" |
| **Error** | The node failed to start or crashed | Supervisor failed or start blocked |

### Blocks and transactions

| Word | Condition |
|---|---|
| **Pending** | Transaction is in the mempool, with no receipt |
| **Included in block N** | Receipt exists (`eth_getTransactionReceipt`) with `status` = `0x1` |
| **Included in block N · reverted** | Receipt exists with `status` = `0x0`. The transaction is in block N, its call didn't take effect, and **the fee was charged**. Required sub-line: "receipt status 0: the transfer didn't happen; the fee was charged", with the fee stated as SALT = receipt `gasUsed` × `effectiveGasPrice` (`eth_rpc.rs:779, 797`). On 40204 a reverted transaction pays its full gas limit with no refund, and the receipt's `gasUsed` equals that gas limit (`executor.rs:2121, 2229, 2255-2258` at b4dc3b1b), so the receipt alone gives the exact fee. If the receipt read fails, show the fee as "—", never 0 |
| **Sent, outcome unknown — check tx ⟨hash⟩** | The signed transaction may have reached the node, but the app can't prove it wasn't accepted. This is the state for every `eth_sendRawTransaction` outcome that isn't on the definitive list below: a transport failure, timeout or unreadable response; any error code or message not on the list (including `-32603` internal errors); the ambiguous errors (already known, nonce in use); any error at all on a re-submission of signed bytes the app has sent before; and a failed receipt poll after the node returned a hash. ⟨hash⟩ is keccak256 of the signed raw transaction, which is the hash the node assigns. Reconcile by that hash (`eth_getTransactionByHash`, then `eth_getTransactionReceipt`), and tell the member to check it (for example on the explorer) before trying again. Never show "Not sent" here, never re-send automatically, and never sign a new transaction for the same payment while this state holds |
| **Not sent** | Only when the node provably didn't accept this transaction: the flow failed before submission (locked vault, signing, nonce or gas-price read), or the node answered the **first** submission of these signed bytes with one of the definitive errors listed below. Any other error means "Sent, outcome unknown" |
| **N confirmations** | Head − N. This is a depth count, not finality |
| ~~Final, Finalized, Settled, Irreversible~~ | **Banned** until checkpoint finality runs and the `finalized` tag returns a height above 0. Today the `finalized` tag returns the genesis block |
| ~~nothing moved~~, ~~no fee~~, ~~Failed · reverted~~, ~~Failed~~ (for a mined transaction) | **Banned.** A reverted transaction moved its fee from the sender. Use "Included in block N · reverted" with the fee. "Failed" alone is not a §1 word: before submission the state is "Not sent", after it "Sent, outcome unknown" or one of the Included words |

#### Which `eth_sendRawTransaction` errors mean "Not sent"

Verified against `core/api/src/server.rs:1213-1278` (the handler the node serves; it replaces the `eth_rpc.rs:1024` registration, last registration wins), `core/sequencer/src/mempool.rs:549-787` (`add_transaction`) and `:790-1019` (`validate_transaction`), and `core/api/src/rate_limit.rs:457-470`, all at c384fc98. The handler checks the request, decodes, checks the balance, then calls `mempool.add_transaction`. Every error returned before or by `add_transaction` leaves the pool without this transaction: the insert (`mempool.rs:748`) is the last fallible step, and nothing after it returns an error. Every handler error uses code `-32602` (Invalid params), so **match on the message, not the code**.

**Definitive (show "Not sent")**, only on the first submission of these signed bytes, to any node. Messages are listed exactly; `…` is variable text.

| Code | Message | Source |
|---|---|---|
| HTTP 429, `-32099` | `Rate limit exceeded. Try again later.` | Request middleware; the handler never ran |
| `-32602` | `Missing transaction data`, `Invalid tx hex`, `Invalid hex`, or a params-parse message | Request checks |
| `-32602` | `Failed to parse transaction: …` | Decoder (malformed RLP or signature values, high-s signature, wrong `v`) |
| `-32602` | `Insufficient funds: account balance … < required …` | Committed-balance check before the mempool |
| `-32602` | `Failed to submit transaction: Full` | Pool full of better-priced transactions |
| `-32602` | `Failed to submit transaction: SenderLimitExceeded` | Per-sender pool limit |
| `-32602` | `Failed to submit transaction: InvalidSignature` | Signature gates |
| `-32602` | `Failed to submit transaction: GasPriceTooLow { …` | Minimum gas price |
| `-32602` | `Failed to submit transaction: InsufficientBalance { …` | Balance covers neither this nor the sender's pooled transactions |
| `-32602` | `Failed to submit transaction: InvalidTransaction(…` | Size, payload, gas limit, chain ID, nonce too far ahead, sender refused, signature verification |
| `-32602` | `Failed to submit transaction: NonceTooLow { …` | The account's committed nonce is past this transaction's nonce, so it can never be included. Say "nonce already used", and reconcile the account's recent transactions before offering a new one |

**Ambiguous (show "Sent, outcome unknown — check tx ⟨hash⟩")**:

| Message | Why it doesn't prove non-acceptance |
|---|---|
| `Failed to submit transaction: DuplicateTransaction(…` | The node already holds this transaction (`mempool.rs:592-595`) or accepted and later evicted it (`:598-600`). This is what a re-send returns after an earlier submission succeeded and its response was lost. It means "previously submitted": reconcile by hash |
| `Failed to submit transaction: DuplicateNonce { …` | Another transaction from this account with the same nonce is pending, which can be an earlier signing of the same payment (`:627-635`). The same message is also used for a nonce gap (`:637-643`), so the app can't tell the two apart. Reconcile the account's pending transactions |
| Any error on a **re-submission** of bytes already sent once | If the first submission was accepted and mined, the re-send fails at the balance check (the balance already paid for it) or with `NonceTooLow` (`:820-825`), both of which look definitive. Only the first submission's error counts |
| Any other code or message, including `-32603` (Internal error) and a dropped connection | Not proven to come before the mempool insert |

The node doesn't yet return a distinct "already known" code; core matches on these messages until it does (§9 Already-known error).

### Validators

| Word | Means | Condition (source) |
|---|---|---|
| **Not a validator** | This key was never registered | `ValidatorRegistry.validatorInfo(pubkey).status` = None (0) |
| **Bond locked · not staked** | Membership grant sits in the member's bond, not in the registry | `MemberBond.activated()` = false and `isUnlocked()` = false. Once the lock has ended and the bond was never activated, use **Unlocked · not activated** (Membership and bond, below) |
| **Registered · active from epoch N** | Registered in the registry; consensus activation is pending | `validatorInfo(pubkey).status` = Active (1) and `actEpoch` (= N) > `currentEpoch()`. Show the actual N; never promise "next epoch". Registration sets `actEpoch = (block + SNAPSHOT_LAG) / EPOCH + 1` with `SNAPSHOT_LAG` = 200 (`firstEpochAfterSnapshot`), so a registration in the last 200 blocks of an epoch activates two epochs later. `isActive(pubkey)` is already true at registration and can't tell these apart |
| **Validator active** | Active in the live registry, activation epoch reached | `isActive(pubkey)` = true **and** `validatorInfo(pubkey).status` = Active (1) **and** `actEpoch` ≤ `currentEpoch()`. Only then. Consensus follows the epoch snapshot, so it can lag by up to an epoch after a change; show the note "consensus can lag by up to an epoch; Producing blocks is the evidence of participation" |
| **Producing blocks** | This node actually proposed blocks recently | A block in the sampled window has `proposerPubkey` = this node's key (§2 Producing validators: N ≥ 100 blocks, N stated). *Active* does not imply this: today only one validator produces. An absent key reads "Not seen producing in the last N blocks", never "not producing" |
| **Exiting** | The validator left the active set; its bond is in escrow and still slashable | `validatorInfo(pubkey).status` = Exiting (2). Optional detail: "escrow withdrawable from epoch N" with N = `validatorInfo.escrowUnlock` |
| **Slashed** | Removed for equivocation | `validatorInfo(pubkey).status` = Slashed (3) |
| **— · registry state inconsistent** | The reads succeeded but disagree | For example status Active with `actEpoch` reached but `isActive` false, or status None with a nonzero `stakeOf`. Distinct from "— · registry not read yet", which is only for reads that haven't landed or failed |
| ~~Validating~~ (for stake ≥ 32k), ~~building blocks~~, ~~producing again~~ | **Banned.** Use the words above. Self-stake in LiquidStakingPool never makes a validator; only the registry does |

**Exiting and Slashed are reachable states, and the UI must derive them from status, not from stake.** Verified against `ValidatorRegistry.sol` at c384fc98:

- A validator becomes **Exiting** three ways: a full unbond (`initiateUnbond` for the whole bond, `:311-316`), eviction by a larger registration when the set is full (`registerValidator` → `_beginExit`, `:254-263`), and a non-Byzantine slash that leaves the bond below its admission minimum (demotion, `:450-455`). Each path sets `bondedStake` to 0 (the principal moves to `escrow`), removes the key from `activeSet()` (so `isActive` = false and `activeCount()` drops), and clears `pubkeyOfStaker[staker]` (`_beginExit`, `:727-736`).
- A validator becomes **Slashed** only through a Byzantine (equivocation) slash (`_slash`, `:440-449`). That penalty is 100% of bond + escrow + unmatured rewards, so `stakeOf` is 0 as well; the key leaves the set, `pubkeyOfStaker` is cleared, and the key and staker are banned from registering again. Latency and Inconsistency slashes never set Slashed: they leave the validator Active or demote it to Exiting.
- So **never gate the validator word on `stakeOf(pubkey)` > 0**, and never look the key up through `pubkeyOfStaker(bond)` after registration. Read `validatorInfo(pubkey)` whenever the key is known (this node's own proposer key, or `MemberBond.pubkey()`, which the bond keeps after exit) and branch on `status` first: None → Not a validator (or the bond words below), Slashed, Exiting, then Active → the `actEpoch` and `isActive` checks.
- Rewards survive both states. `rewardsOf(pubkey)` still reads, `claimRewards` pays matured rewards in any status (including Slashed, `:521-536`), and a fully exited (not slashed) validator's remaining rewards are released by `withdraw` from epoch `exitEpoch + EXIT_LOCK_EPOCHS` (6 epochs); a slashed key can't `withdraw`, so only its matured rewards remain claimable. Keep showing the Rewards figures for an exited or slashed key.

### Membership and bond

| Word | Condition (source) |
|---|---|
| **Member** / **Membership lapsed** | `CitrateMemberSBT.isActive(tokenId)` true / false. `isActive` does not include KYC |
| **Locked until ⟨date⟩ (block N)** | `MemberBond.unlockTimestamp()` and `unlockBlock()`. Show both: the lock opens when either is reached |
| **Unlocked · not activated** | `isUnlocked()` = true and `activated()` = false. The member can't withdraw this principal: `requestRelease()` and `withdrawToMember()` both revert `NotActivated()` for a bond that was never activated (`MemberBond.sol:225-241` at b4dc3b1b). Required detail: "Only an activated bond can be withdrawn." No identity or KYC prompt in this state, and no withdraw action. Don't say where the principal goes (see "Unactivated grants" below) |
| **Unlocked · verify identity to withdraw** | `activated()` = true **and** `isUnlocked()` = true **and** `isKycVerified()` = false |
| **Unlocked** | `activated()` = true **and** `isUnlocked()` = true **and** `isKycVerified()` = true. This makes the release *available*, not paid: `requestRelease()` starts the unbond, and `withdrawToMember()` pays once the registry's exit lock has run (§1 Exiting) |

**Withdrawable wording needs `activated()`.** Any word, row, tooltip or agent phrase that says or implies the member can withdraw the principal ("withdraw after the lock", "withdrawable", "verify identity to withdraw", "Needed to withdraw after the lock end") requires `MemberBond.activated()` = true. For a bond that isn't activated, the Withdraw row reads "only an activated bond can be withdrawn" (source: `withdrawToMember` requires `activated()`), before and after the lock. The identity requirement applies to activated bonds only. Its source is the on-chain gate the bond checks, `CitrateMemberSBT.isKycVerified(tokenId)` via `MemberBond.isKycVerified()` (`MemberBond.sol:266`); the `kyc_status` userinfo claim is not what the bond checks and is never the source for a withdraw or rewards gate. `claimRewards()` needs `activated()` and `isKycVerified()` as well (`:207`).

**Unactivated grants: what to say today.** The owner decision of 2026-10-19 (activation open only inside the lock; after the lock the treasury may reclaim a never-activated grant) is implemented in chain #331, which is not merged and not deployed on 40204. On the bonds the app reads today, `activate()` has no lock-end check and there is no reclaim path. So, until a MemberBond with `reclaimUnactivated()` is deployed on the network the app reads (expected with the betanet genesis set; this contract is re-issued then and says so):

- No copy says an unactivated grant "returns to the treasury", "is reclaimed" or "is lost", and none says activation closes at the lock end.
- The grant copy says only what holds today: "Only an activated bond can be withdrawn."
- The app doesn't infer the new behaviour from a merge, a release note or a runtime probe; it follows the version of this contract for the network it shows.

On a network where that contract is deployed, the chain team adds these words here (draft, not usable yet): **Unlocked · not activated** gets the detail "Not activated before the lock ended. Only the treasury can reclaim it", the Activate action is drawn off once `isUnlocked()` is true, and **Returned to the treasury** (`reclaimed()` = true) is the word after the reclaim.

### Rewards

The Node tab and any section that holds these figures is called **Rewards**.

| Word | Condition (source) |
|---|---|
| **Validator rewards** | `ValidatorRegistry.rewardsOf(pubkey).total` |
| **Claimable now** | `rewardsOf(pubkey).claimableNow`. The Claim action must check this same read (not ContributionAccounting) for a validator key, including an exited one |
| **Maturing** | `total − claimableNow` (slashable for 4 epochs) |
| ~~Earning~~, ~~Earnings~~ (as a tab, heading, label, toast or agent phrase), ~~income~~, ~~projected~~, ~~estimate~~, ~~today~~ | **Banned.** No projections and no "per month at current demand". "Today" needs a per-day source, and no chain or SALT figure has one. "Today" is allowed only for local per-day sources (daemon run and token counts, the gateway escalation budget that resets at local midnight), and never next to a chain or SALT figure |

### Pins and group rounds (not live, see §4)

| Word | Condition (source: `IPFSIncentivesV3.getPin` / `getChallenge`) |
|---|---|
| **Pinned** | status Active, no challenger |
| **Challenged** | status Active, `getChallenge.challenger` ≠ 0 |
| **Complete · bond claimable** | status Done, `bondHeld` > 0 |
| **Released** | status Done, `bondHeld` = 0 |
| **Slashed** | status Slashed |
| **Pin bonds not live yet** | Required wording until V3 is funded at genesis |
| **Group rounds not live yet** | Required wording while rounds can't run, in **both** ledger states: FederatedRoundLedger and PatronageLedger absent (today on 40204), or deployed with no rounds (the genesis plan, §4). In the deployed state the detail may say "Both ledgers are deployed and hold no rounds", with row values "deployed, no rounds (code at the pinned address)" |
| ~~Deployed · dormant~~ (as a state word, lead, round-card word or chip) | **Banned as a word.** It is not a contract state: neither ledger has a dormant flag, and "deployed dormant" in §4 describes the rollout, not something a read returns. Use "Group rounds not live yet" (rounds) or "Pin bonds not live yet" (pins), with "deployed, no rounds" or "deployed, not funded" as row values |

Service states (Alive, Ready, Stopping, Quarantined) belong to the K1 services contract (SPEC-001), owned by core. They aren't chain state and are out of scope here.

## 2. Number catalog

Amounts are SALT with 18 decimals (wei), so divide by 1e18. Addresses come from `contracts/addresses/40204.json`. "Today" is latest state on live 40204 at heads 510,030–510,047 (fixture `docs/ui-truth/fixtures/40204-2026-10-19.json`; per-read heads inside it). A v1.1 spot check at ~512,250 gave the same values.

| Number | Source | Display | Today |
|---|---|---|---|
| Network | `eth_chainId` **and** genesis hash (§6) | "Citrate betanet". Chain id alone is not enough: three profiles share 40204 | `0x9d0c`, genesis `0x1dcfc490…75f1` |
| Head height | Public `eth_blockNumber` (network). Local `eth_blockNumber` (this node) | Integer. If the call errors it returns `0x0`, so show unknown | 510,030 |
| Behind by | `eth_syncing.highestBlock − currentBlock` | "N blocks behind". `highestBlock` includes unverified peer claims, so it is a ceiling | `false` (synced) |
| Block time | Timestamp delta over the last 100 blocks | "~2 s". Never the 1 s config value | 2 s |
| Peers (this node) | Local `net_peerCount` | "N direct peers", not "the network" | — (a member's node; not in the fixture) |
| Peers of the public RPC node | `net_peerCount` on rpc.citrate.ai (fixture `rpc_node_peer_count`; the 2026-10-19 file names it `peer_count`) | Only as the RPC node's own peers, e.g. on a status page. Never shown as a member's peers or as the size of the network | 3 |
| Base fee / gas price | `baseFeePerGas` of the latest block | "1 gwei (fixed)". It is a consensus constant | 1 gwei |
| Registered validators | `ValidatorRegistry.activeCount()` (fixture `registered_validators`). `activeCount()` = `activeSet().pubkeys.length`, so it can come from the same `activeSet()` call as the eligible count | Tile label "Registered validators", with the sub-line "N eligible (live registry)". It **includes** registrations still pending activation, so never call it "active". Exited and slashed keys are not in it | 5 |
| Eligible validators (live registry) | Live `activeSet()` members with `validatorInfo(pubkey).actEpoch` ≤ `currentEpoch()` (fixture `eligible_validators`, which also reports `pending_activation`) | "N eligible (live registry)", or "eligible: —" while unread or if any read fails; never the registered count in its place. It is the live registry, **not** consensus membership: consensus uses the governing epoch snapshot, so a validator that registered or exited after that snapshot differs for up to an epoch. Read it on the same cadence as the registered count (or from the same `activeSet()` call), so eligible never exceeds registered on screen. Example: right after a registration, registered = 6, eligible = 5, pending = 1 | 5 |
| Consensus validator set | The governing epoch snapshot S(E) (node-internal) | **Unavailable**: no RPC exposes it yet (§9). Don't show a consensus-set number anywhere, and don't present registered or eligible as one. A tip may say "unavailable until a snapshot RPC exists" | — |
| Producing validators | Distinct `proposerPubkey` over the last 1,000 blocks (fixture `producing_validators`, with its window) | Integer, with the window stated ("over the last N blocks"). A sample of N ≥ 100 is allowed if N is the number of blocks that actually came back. Show it next to the validator counts so the gap is visible. A validator absent from the window is "not seen producing in the last N blocks", not "not producing". If fewer blocks came back than were requested, or fewer than 100, the sample backs neither word: show "— · producer sample incomplete: only N of M blocks came back" | 1 (blocks 509,033–510,032) |
| Minimum stake | `ValidatorRegistry.minStake()` | SALT. Read it; don't hard-code 32,000 | 32,000 |
| Block reward | `ValidatorRegistry.blockSubsidy()` | "N SALT per block, to the producer". It is governance-set, so read it, never hard-code it | 10 SALT |
| Epoch | `ValidatorRegistry.currentEpoch()`; `EPOCH()` = 1,000 blocks | Integer | 510 |
| Your stake | `ValidatorRegistry.stakeOf(pubkey)` | SALT. This is the **only** "staked" figure. Consensus weight (`activeSet().effStakes`) is capped at 1/3, so label it separately if shown | — |
| Validator rewards / claimable | `ValidatorRegistry.rewardsOf(pubkey)` | SALT, with the words in §1 | 1 of 5 validators has rewards |
| Bond principal | `MemberBond.principal()`; staked/locked state from `activated()` | SALT, plus the bond state word | 32,000 |
| Bond lock end | `MemberBond.unlockTimestamp()`, `unlockBlock()` | Date and block, both (the lock opens at whichever comes first). While unread: "until block — (not read yet)", never "for about a year" for a member who has a grant | ~2027-10 |
| Grants issued / members | `MembershipStakeVault.nextGrantId()`, `CitrateMemberSBT.nextTokenId()` | Integer. `totalSupply()` reverts, so don't call it | 5 / 5 |
| Balance | `eth_getBalance(addr, "latest")` | SALT, "latest". Errors return `0x0`, so show unknown | — |
| Max supply | `TOTAL_SUPPLY` (`core/economics/src/lib.rs:75`) | "Max supply 1,000,000,000,000 SALT". This is a cap, not circulating supply | 1T |
| Pin bond / pin reward | `IPFSIncentivesV3.BOND()`, `REWARD()`, `ROUNDS()` | Parameters only, until pins are live | 10 SALT / 4 SALT over 4 rounds |
| Skills / models listed | `SkillRegistry.totalSkills()`, `ModelRegistry.totalModels()` (the contract at `0x086F…75eF`, not a precompile) | Integer | 0 / 1 |
| Governance delay | `minDelay()` on GOVERNANCE / GUARDIAN | Hours | 2 h / 2 h |
| LiquidStakingPool deposit | `LiquidStakingPool.balanceOf(addr)` | SALT, labelled "LiquidStakingPool deposit · not validator stake". It never counts toward "staked" or any validator word | — |
| LiquidStakingPool withdrawal delay | `LiquidStakingPool.WITHDRAWAL_DELAY()` (a contract constant, so a bundled constant matching it is acceptable) | As a duration (row below): "50,400 blocks (~28 h)" | 50,400 blocks |
| Durations given in blocks | Blocks × block time measured over the last 100 blocks | Show both, e.g. "50,400 blocks (~28 h)". With no measurement, show the block count only. Never assume 12 s blocks | — |

Not in the catalog, so **not shown**: circulating or issued supply (no source exists), TPS (the app has no reason to show it; claims.json covers public copy), SALT price, any USD value of SALT, APY or yield, "finalized height", any finality time (claims.json publishes none while checkpoint finality isn't running), node version (no RPC serves it yet, see §9).

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
| Liquidity (needs counsel; provisional until counsel review, C2 D3/D4 decided by 2026-10-30) | No protocol gate: SALT transfers work on 40204. No trading venue | No protocol gate: SALT and wSALT are transferable from genesis. Any trading venue is a market event (C2 D4), not a chain state; the app never shows it |

"Deployed, dormant" and "Deployed dormant" in this table describe the rollout. They are not §1 words and never appear on screen as a state (§1 Pins and group rounds).

## 5. Money copy (provisional until counsel review)

1. **No investment language for SALT**: not invest, investment, return, yield, APY, APR, profit, passive income, appreciation, or "price".
2. **No price or USD value for SALT** anywhere, and no exchange, listing or trading talk before 1.0. USD is allowed only for the member's own third-party provider keys (gateway escalation, model APIs): label it as the provider's list price ("at OpenAI's list price"), and never put it next to a SALT amount. Prefer "cost" to "price" in that copy.
3. **Membership price**: comes only from the membership service, never a constant in the app (no waiver). Until core-membership serves a public price route (board item C1-P), the app shows no price at all: it links "See membership pricing" to membership.citrate.ai, where Stripe checkout shows the exact charge. Membership buys membership; it does not buy SALT.
4. **Grant**: say exactly what the contracts do. "Your membership comes with a 32,000 SALT grant, locked in your bond until ⟨date⟩." Say "staked" only after `activated()`, and "withdraw" only for an activated bond (§1 Membership and bond). Say nothing about what happens to a grant that is never activated beyond "Only an activated bond can be withdrawn" until the reclaim path is deployed (§1 Unactivated grants). Use one explanation everywhere: onboarding, Wallet, Node and the Hermes context.
5. **Rewards**: only on-chain reads (§2), named as rewards for producing blocks. No projections, formulas or "at current demand". If a member's node isn't producing, don't say it earns.
6. **Betanet balances** (C2 D3; provisional until counsel review, C2 D3/D4 decided by 2026-10-30). Before 2026-12-01 the app is on the current testnet. Say: "Testnet. This network may be reset before betanet launches on 1 December 2026." From the betanet genesis (2026-12-01, shipped with 0.5.2) the chain is the mainnet chain: no reset is planned, and balances, SBTs, bonds and contracts carry into mainnet when the 1.0 soft fork activates (targeted 2027-02-01). Approved string: "Betanet. This is the chain mainnet keeps: balances carry into mainnet when the 1.0 upgrade activates, targeted for February 2027." Never say "guaranteed". Never attach a value, price or venue to carried-over SALT (§5.1, §5.2). Never describe 1.0 as turning on transfers or liquidity (D4): 1.0 is an upgrade that carries hardening and anything not ready at genesis.
7. **Disclaimers**: the existing "not purchased, not an investment" line appears anywhere the grant is mentioned, not only in one onboarding step.
8. **Daemons and SALT**: daemons can't spend SALT. Write "Daemons can't spend SALT"; never show "0 SALT spend", which reads like a balance that could grow. Gateway escalation spend is shown in its own unit, with its daily cap.

## 6. Network identity check (the app runs this before trusting any read)

1. `eth_chainId` = `0x9d0c`.
2. `eth_getBlockByNumber("0x0").hash` = the release genesis the app ships with. Today that is `0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1`. A new genesis ships with 0.5.2. A mismatch means **Update required**.
3. Canonical checkpoints: block 365,784 = `0x63dcd4a8c7cd701080e242e5949402da93143bfd0659b3012e57998da4aa2c56` and 365,785 = `0x51482ff9724a2f0cbf4fe678f3ce556f6222334d5b2a3f5eba8a2b52af0cf3d2`. The list grows with each release; read it from the bundled release, not from this file.

   **Checkpoint availability rule.** Compare hashes only when all of these hold:
   - the local node's applied height has reached the checkpoint height;
   - `eth_getBlockByNumber(<checkpoint height>)` returned a block object (not null, not an error);
   - that object **is** the checkpoint block: its `number` field is present and equals the checkpoint height;
   - its `hash` is well-formed (`0x` plus 64 hex digits).

   If any of these fails (below the height, null, an error response, a missing `number`, a block for a different height, a missing or malformed hash), the verdict is **"not yet"**: the state stays **Syncing** or the unavailable state, and no local data is moved aside. Only a returned checkpoint block whose well-formed hash differs from the canonical one means **Resync required**.

A node on a stale genesis usually shows up first as `net_peerCount` stuck at 0, because peers reject the handshake.

## 7. Fixtures and rehearsal exports

- `scripts/ui-truth/export-fixtures.sh [rpc] [out]` reads every catalog value and writes `docs/ui-truth/fixtures/<chain>-<date>.json`. The file carries `"fixture": true` and a label that must appear on screen.
- **An export is not a snapshot, and its reads are not mutually consistent.** The node serves *latest* committed state for every block tag; there are no historical state reads. Registry state (validator registrations, stake changes, executed parameters) can change in any block, not only at epoch boundaries. So each read records its source, `state: "latest"`, and the head it was observed at (`observed_head`), and the file says `consistency: "none: …"`. `head_at_start`, `head_at_end`, `head_moved` and `single_epoch` are indicators only. `single_epoch: false` means the validator-set snapshot changed during the export, and the exporter warns.
- `producing_validators` is exported with its window (`from_block`, `to_block`). If any block in the window didn't come back (an RPC error, a null block or a missing proposer key), it is exported as `unavailable` with `blocks_returned`/`blocks_requested`, never as a count. Show it next to active validators, or show the unavailable state.
- The exporter refuses values it can't use safely. A head that is malformed, `0x0` or longer than 13 hex digits aborts the export with no file written (13 digits keeps it exact in Bash and jq); the abort message carries only a short printable excerpt of what the RPC sent. Epoch values wider than 15 digits make `eligible_validators` unavailable rather than counting validators as pending. RPC values never reach shell arithmetic unvalidated.
- `scripts/ui-truth/test-export-fixtures.sh` tests this offline against a stub RPC whose head moves during the export, plus malformed, oversized, zero and hostile heads, an out-of-range epoch, and hostile timestamps.
- **v1.1 id change**: the peers read is exported as `rpc_node_peer_count` (the public RPC node's own peers). The committed 2026-10-19 file predates this and carries it as `peer_count`; it is not re-exported, because screens cite that file as committed.
- **On screen**: every group of fixture numbers carries the "fixture" pill, not one pill per screen, and a footnote with the verbatim `label`, the file name and the head range it was read over (for example "FIXTURE — captured from 40204, not live · fixtures/40204-2026-10-19.json · latest state at heads 510,030–510,047"). Don't write "read at block N": an export is not a snapshot. A number without a visible pill is a violation, even when a footnote exists elsewhere on the screen.
- **Now**: `fixtures/40204-2026-10-19.json` (live 40204) is the prototype's data until rehearsal 1.
- **Rehearsal 1** and **rehearsal 2**: the chain team exports from the rehearsal network and re-issues this contract. Design v2 uses the R1 export. The R1 export adds one sample rehearsal member bond, labelled as a rehearsal fixture: `principal`, `activated`, `unlockBlock`, `unlockTimestamp`, `isKycVerified`, and the validator state (`validatorInfo`) for its `pubkey`.
- States that need data the chain doesn't have yet (Challenged pin, Exiting validator, an open round) are drawn from the state tables in §1, labelled "fixture", with values from the parameter reads.

## 8. Known violations in citrate-core main (b521d98)

These are for the core lane to fix against this contract. Each is a board item on Project #5. Status at this writing: V1–V13 are addressed in the open, stacked core PRs #347, #348 and #349, and the v1.1 §1/§2/§6 rules in #358 (stacked on #349). None of them is merged yet, so main still has every row below.

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
| V13 | `Community.tsx:23-27` | Referral rewards with no on-chain source ("founding-roster SALT grant", "growth reward", "the full 2,000-run reward, settled to every member"), and "settled" used for SALT | 1, §1 banned words, §5.5 |

Open follow-ups from the DGX reviews of the stack (not in main or in any open PR yet; v1.1 rules apply):

| # | Where (at #358 head c023c0e unless noted) | Problem | Rule |
|---|---|---|---|
| V14 | `store.ts:1323`, `chainTruth.ts:280` | The validator word is gated on `stakeOf > 0`, so Exiting and Slashed (stake 0) read "Not a validator" or "Bond locked · not staked". The test at `truthContractV11.test.tsx:85-88` uses stake 32,000 with status 2, which the chain can't produce | §1 Validators (status first) |
| V15 | `src-tauri/src/node_withdrawn.rs:134` | A block with no `number` field is still compared | §6 availability rule |
| V16 | `Node.tsx:376`, `Onboarding.tsx:971` | "— · registry not read yet" is also shown when reads succeeded but disagree | §1 "registry state inconsistent" |
| V17 | Dashboard counts | Registered refreshes every 60 s and eligible every 5 min, so eligible can briefly exceed registered | §2 Registered / Eligible |
| V18 | `store.ts:5010`, `node_mcp.rs:495` (#347 head 5618ba6) | An agent- or MCP-originated payment with an unknown outcome resolves as rejected or error, so it may be proposed again | §1 "Sent, outcome unknown" |
| V19 | `grantCopy.ts`, `grant_status.rs` | The lock end shows the block only; `unlockTimestamp()` isn't read | §1 Membership, §2 Bond lock end |
| V20 | `grantCopy.ts`, `describeBond` | "Staked" keys off `bondedStake > 0` / `hasValidator` instead of `MemberBond.activated()` | §5.4 |

## 9. Chain-side follow-ups (DGX lane)

- **claims.json errata**: precompile set (agent precompiles 0x0112, 0x0113, 0x0121, 0x0122 are live; 0x0104 retired), ModelRegistry precompile flag (fixed in G, set agrees = true), the `finalized` tag note (the tag is served since #250 and returns genesis), the supply pointer (`lib.rs:75`), the `deployed_contracts` verification date, and re-run test counts.
- **Consensus set RPC**: expose the governing epoch snapshot (membership and effective stake for the epoch governing a height) so the app can show consensus membership, not just live-registry eligibility.
- **Producers RPC** (optimisation, not a prerequisite): distinct proposers over a stated window in one call. The sampled source in §2 (batched `eth_getBlockByNumber` → `proposerPubkey`) already works and stays the reference until this exists.
- **Already-known error**: give `eth_sendRawTransaction` distinct, stable error codes for "already known" (`DuplicateTransaction`) and "nonce in use" (`DuplicateNonce`), and separate the nonce-gap case from `DuplicateNonce`, so core doesn't have to match on Debug-formatted messages (§1).
- **R1 export**: add the sample member bond (§7) to `export-fixtures.sh`.
- **RPC honesty**: real node version and consensus fingerprint over RPC, a genesis-hash method, errors instead of silent defaults (§3), drop the DAG-stats estimates, and fix the `eth_feeHistory` reward shape and `citrate_getToken.totalMinted`.
- **Mainnet profile**: `GenesisConfig::mainnet()` uses chain ID 1 and placeholder addresses; `node/config/mainnet.toml` is a skeleton. Resolved in C2.

## 10. Changing this contract

- To show a new number or state, add a board item (Project #5, Workstream C1, Lane DGX). The chain team names a real source first (Rule 7), then adds it here. Until then, the screen shows the unavailable state.
- Version bumps at each rehearsal and at genesis. Each version notes what changed.
- Sign-off: the chain team checks each prototype screen against this file. Core checks that every bridge call it needs exists.

## 11. Hermes and prototype rulings (design slice 1, binding for 0.5.2)

The chain team's answers to the design slice-1 questions (citrate-core #350). The ones that change a rule above are folded in there; this is the full list.

1. **Producing validators in the export: yes.** Done: `producing_validators`, with its window (§2, §7).
2. **Fixture pill and footnote** on every group of fixture numbers, naming the file and the head range (§7).
3. **Hermes and chain numbers.** In the shipped app, Hermes states a chain number only from a live §2 read and names the source ("ValidatorRegistry says 5 registered validators"). If the read fails, it says it can't read that right now. It never estimates or remembers chain numbers. In the prototype, it may quote fixture numbers only when they are labelled "fixture" inline.
4. **USD** only for the member's own provider keys, at the provider's list price, never next to SALT (§5.2).
5. **No "0 SALT spend"**: "Daemons can't spend SALT" (§5.8).
6. **Where chain numbers appear in Hermes**: only where a Hermes action needs them: approvals that move SALT, the member's own bond or reward state when they ask, and network status in the composer. Everything else lives in Node and Wallet; Hermes home doesn't repeat Node's numbers.
7. **A sample member bond in the R1 export: yes** (§7, §9).

## 12. Changes in v1.1

- §1 Network: "Synced" needs a public head read in the last 60 s; new **Sync unknown · network head unavailable**; no sync percentage; "Resync required" uses the §6 availability rule.
- §1 Transactions: new **Sent, outcome unknown — check tx ⟨hash⟩** and a narrow **Not sent**, which only the listed definitive `eth_sendRawTransaction` errors on a first submission can produce. Already-known and nonce-in-use errors, and any error on a re-send, are "outcome unknown".
- §1 Validators: "Registered · active from epoch N" and "Validator active" conditions include `status`; Exiting and Slashed are reachable and derived from `status`, not stake; new "— · registry state inconsistent".
- §1 Rewards: the tab is "Rewards"; "Earnings" banned in every form; "today" only for local per-day sources.
- §2: "Registered validators" with "N eligible (live registry)" on one cadence, no consensus number; peers split into this node vs the public RPC node (`rpc_node_peer_count`); producer sample shortfall rule; LiquidStakingPool deposit and withdrawal delay rows; unread lock end wording; "Today" values from the committed fixture.
- §5: USD for own provider keys (2), no in-app membership price until C1-P (3), betanet balances per C2 D3 (6, provisional until counsel review), "Daemons can't spend SALT" (8).
- §4: the Liquidity row per C2 D4 option A (no protocol gate; needs counsel). No finality time is introduced anywhere.
- §6: the checkpoint availability rule.
- §7: exporter range checks, the `rpc_node_peer_count` id, on-screen pill and footnote, R1 sample bond.
- §8: V13 and follow-ups V14–V20. §9: producers RPC, R1 export bond. §11: slice-1 rulings.

## 13. Changes in v1.2

From the chain-team review of design slice 3 (citrate-core #387 at 2fa84955).

- §1 Membership and bond: new **Unlocked · not activated**. "Unlocked · verify identity to withdraw" and "Unlocked" now require `MemberBond.activated()`; any withdrawable wording requires it too. The identity gate's source is `CitrateMemberSBT.isKycVerified(tokenId)` via `MemberBond.isKycVerified()`, not the `kyc_status` claim. No "returns to the treasury" or activation-window copy until the reclaim path (chain #331) is deployed on the network shown; the words for that are drafted, not usable.
- §1 Validators: "Bond locked · not staked" holds only while the lock runs.
- §1 Pins and group rounds: "Group rounds not live yet" in both ledger states (absent, or deployed with no rounds). "Deployed · dormant" is not a contract state and is banned as a word. §4 says its "dormant" entries are rollout descriptions.
- §1 Transactions: new **Included in block N · reverted**, with the fee (receipt `gasUsed` × `effectiveGasPrice`; a reverted transaction pays its full gas limit). "Included in block N" now needs receipt status `0x1`. Banned: "nothing moved", "no fee", "Failed · reverted", and "Failed" for a mined transaction.
- §1 Validators: "Validator active" already required `status` = Active alongside `actEpoch` ≤ `currentEpoch()` in v1.1; unchanged.
- §5.4: withdraw wording and unactivated grants as above.
- No catalog (§2) or exporter change: the bond rules read `activated`, `isUnlocked` and `isKycVerified`, which the R1 sample bond (§7) already lists, and the reverted rule reads the receipt the app already polls for the Included words.
