---
created: 2026-11-09
branch: r1007/s3-6-genesis
author: Claude Opus 5.5 (lane S3-6 GENESIS WIRING) for Larry Klosowski
status: draft for second-reviewer review (Matr0xshka, kurtatwork); owner parameters decided 2026-11-09; PENDING under D-K3 (owner 2026-11-10): the rotated non-producer keys (§1.1); the block-0 hash is the candidate of the r1006-keys layout
amended: 2026-11-10 on r1007/genesis-candidate-2 (lane CHAIN-INTEG): D-K3 pending parameters §1.1, integration items §5.1-§5.3 done
adr: ADR-2026-11-03-chain-convergence-r1007 CV-2, CV-7a, CV-8, CV-12, CV-13, CV-14
planset: 2026-11-03-r1007-v060 05 S3-6, 06 §1.2
---

# The r1007 genesis

r1007 is the new-genesis rehearsal of chain 40204 (ADR Q-1). It runs every r1007
consensus rule from block 0 (CV-2). This page lists every parameter the r1007 profile
fixes, where each one comes from, and its status. The owner decided every pending
parameter on 2026-11-09. On 2026-11-10 the owner decided D-K3: every non-producer EVM key
is rotated at the r1007 ceremony. The keys of §1.1 are therefore pending again, and the
builder refuses to build r1007 until fresh keys replace them. It also
gives the plan for re-issuing grants after genesis.

Code:
- `core/consensus/src/hardening.rs`: `R1007_GENESIS`, `R1007_ACTIVATIONS`, and the
  `RELEASE_GENESIS` and `GENESIS_ACTIVATIONS` entries.
- `core/consensus/src/genesis_params.rs`: `R1007_CHAIN_PARAMS` and `GENESIS_CHAIN_PARAMS`.
- `core/economics/src/r1007.rs`: `GenesisConfig::r1007()`, the note, and the validator binding.
- `node/src/genesis.rs`: profile `r1007`, `compiled_genesis_for_profile`,
  `compiled_validator_set`, `r1007_boot_guard` and `check_checkpoint_params`.

## 1. What block 0 holds (owner decisions 2026-11-03 Q-1, Q-3)

| Item | r1007 | Source |
|---|---|---|
| Chain id | 40204 | Q-6 ("the stable chain-ID-40204 release") |
| Contract set | **the r1006 block-0 contract set**: every account of `GenesisConfig::r1006()` except the r1006 note, at the same addresses. Byte for byte only in the r1006-keys layout (`r1007::candidate_layout_with_r1006_role_keys`); the storage words and balances that name a rotated key change under D-K3 (§1.1) | owner: r1007 keeps today's contract set; the 0.6.0 contracts go in the later ceremony genesis |
| Validator set | the 7 r1006 producers, the same registry state, the same stakes | Q-3 ("fresh genesis from the same validator set") |
| Source files | `core/economics/assets/r1006/alloc.json` (sha256 `ac969bda…43db`) and `validators.json` (sha256 `26f14840…d0ca`), read in place, not copied (Rule 9) | `GenesisConfig::r1007()` |
| Genesis note | "Citrate r1007: rehearsal genesis for chain 40204" at `0x000000000000000000000000000000C17A7E1007`, replacing r1006's note at `…C17A7E1006` | Decided (owner 2026-11-09) |
| State root of block 0 | standard MPT root (CV-14), with activation 0 covering block 0 itself | STATE_ROOT_MPT.md §1 |
| Genesis header | the shared canonical genesis block (`create_canonical_genesis_block`, version 1, timestamp `CANONICAL_GENESIS_TIMESTAMP` = 1,767,225,600 = 2026-01-01T00:00:00Z) | unchanged from r1006 |
| Supply split | unchanged: mining pool = 1T SALT − pre-allocations (the note holds no balance) | `GenesisConfig::r1006` |
| Block-0 hash | `0xd245a960a616896a2b80f9aa8e92417b44a4fb451640efdb9c75dda5abc1ba7f` | **candidate of the r1006-keys layout**, never built by a node under D-K3; re-pinned from the fresh-keys alloc, see §2 |

**Every block-0 contract address is unchanged from r1006.** That includes `CitrateMemberSBT`
`0x8831…060d`, `MembershipStakeVault` `0xd663…555e` and `ValidatorRegistry` `0xf511…31cd`,
because they are in the r1006 block-0 state. The r1005-era drift (SBT and vault deployed
by nonce CREATE after genesis, so they moved on every reroll) does not apply to these
three. `scripts/genesis/r1006/emit_book.py --check contracts/addresses/r1006/40204.json
--alloc core/economics/assets/r1006/alloc.json` passes: all 84 book addresses have code.
The r1006 block-0 book is therefore also r1007's. Anything deployed *after* r1006's
genesis is not in r1007 (§4).

The 7 producers (public identities from `validators.json`; no key material anywhere in
this repo):

| Name | Proposer key (ed25519) | Staker | Stake (SALT) | Liquid (SALT) |
|---|---|---|---|---|
| citrate-prod-1 | `0x0a44ba01…ba0d10` | `0xfc0305a20a46c791ea40e72bbf80582fdd5fe0ab` | 32,000 | 100 |
| citrate-prod-2 | `0xd51c32a9…cbc33c` | `0x618164fecfe4468dc4162e9f7c61f1e3995c46b9` | 32,000 | 100 |
| citrate-prod-3 | `0xf99cf9fe…4111eb` | `0xaf68e45518c01b9484321f471b153d321197b238` | 32,000 | 100 |
| citrate-prod-4 | `0x778f3c12…2aaa3d` | `0x96b82a070ca2615eef29d8c67b86c21fd0ba474b` | 32,000 | 100 |
| citrate-prod-5 | `0x0f2e42ae…b6f362` | `0xe1fa687d4684fdebb06f513ce2f5674812668cd2` | 32,000 | 100 |
| citrate-prod-6 | `0xcece36ef…70d0b8` | `0x78fc4dee8c40be8786c6b4e98482fdaa60435542` | 32,000 | 100 |
| citrate-prod-7 | `0x15d1f3c5…befc40` | `0xbb7316ece2325e76cc66a61a01a1f307e67fd89c` | 32,000 | 100 |

Producer keys stay on their hosts. **Decided (owner 2026-11-09): r1007 uses the same
producer keys as r1006**, so the validators file is r1006's and nothing is refilled. (Fresh
keys, D-K3, would mean refilling it with `scripts/genesis/r1006/fill_producers.py` and
re-pinning the hash; that is for the ceremony genesis, not r1007.)

### 1.1 Pending genesis parameters: the rotated non-producer keys (D-K3, owner 2026-11-10)

Every non-producer EVM key touched at the r1007 ceremony is rotated. Producer keys (the
proposer keys and the staker accounts of `validators.json`) stay. The r1006 block-0 state
names the r1006 keys below, so "r1007 keeps r1006's block-0 state byte for byte" no longer
holds for them. They are compiled as `r1007::ROTATED_R1006_KEYS` (public addresses only),
bound to `scripts/genesis/r1006/inputs.r1006.env` and the alloc deployer by
`the_rotated_keys_are_every_r1006_non_producer_key`.

`GenesisConfig::r1007()` refuses while they are pending. It names every role, with its
plain occurrences in the layout (`r1007::rotated_key_locations`). The node (profile
`r1007`), the GUI and the light node all build through it, so none of them can start a
block 0 that names a rotated key. `r1007::readiness()` reports `inputs_final = false`.

| Role (inputs.r1006.env) | Where the r1006 block 0 uses it (plain occurrences, `the_r1006_layout_shows_where_r1007_must_replace_each_rotated_key`) |
|---|---|
| `GOV_OWNER_1`..`GOV_OWNER_5` (`GOV_OWNERS`) | GovernanceMultisig `0x3975…2c5c` owner set |
| `GRD_OWNER_1`..`GRD_OWNER_3` (`GRD_OWNERS`) | GuardianMultisig `0xc6ed…af1d` owner set |
| `MEMBERSHIP_GRANTOR` | CitrateMemberSBT `0x8831…060d` and MembershipStakeVault `0xd663…555e` |
| `SIGNER_1`..`SIGNER_3` | InstitutionalVault `0x9fea…7938` signers |
| `RELAYER` | not found in a plain storage word: held under a hashed mapping slot, or off chain only. Check against DeployAll before the fresh alloc is accepted |
| `CITRATE_AA_OWNER` | CitratePaymaster `0x5a1e…ff56` and CitrateWalletFactory `0x6ee3…434c` |
| `CITRATE_AA_IDENTITY_SIGNER` | CitrateWalletFactory |
| `CITRATE_AA_SPONSOR_SIGNER` | CitratePaymaster |
| `TREASURY` (`TREASURY`, `BASE_TREASURY`) | base allocation (its own balance) and the fee recipient of X402Facilitator, ComputeMarketplace and ModelMarketplace |
| `FAUCET` (`BASE_FAUCET`) | base allocation |
| `TEAM` (`BASE_TEAM`, `TEAM_VESTING_BENEFICIARY`) | base allocation and the TeamVesting beneficiary |
| `DEPLOYER` (alloc `deployer`) | the ceremony deployer account itself (nonce 92) |

The scan sees an account's own address and any storage word that holds the address. A
key held only under a hashed mapping slot (an AccessControl role member, for example) is
invisible to it, so the fresh alloc must come from fresh inputs, not from editing these
words. To unblock r1007:
1. generate the fresh role keys (`scripts/genesis/r1006/new_role_keys.sh` pattern), and
   write r1007 inputs (public addresses only);
2. re-run the ceremony build from those inputs into an r1007 alloc;
3. point `GenesisConfig::r1007()` at it, keep `rotated_key_locations` empty as its guard,
   and re-pin `R1007_GENESIS` (§2);
4. re-render the canonical book and the ops profile from the new hash.

Open with the owner: whether the producer **staker** accounts count as producer keys
(this page assumes they do and keeps them).

## 2. The block-0 hash: how it is computed and when it moves

The ceremony step (STATE_ROOT_MPT.md §1, step 3) is:

```
cargo run -p citrate-economics --example r1007_genesis_hash
```

It turns the MPT rule on from 0 for that process and builds the profile with the shared
genesis function, `initialize_shared_genesis_state`. It then prints the hash and the
pinned value. Three tests keep the hash honest:
- `r1007_genesis_hash_is_pinned_and_reproducible_under_the_mpt_rule` (economics) builds
  it twice, checks it equals `R1007_GENESIS`, and checks the root equals the
  from-scratch MPT reference.
- `r1007_profile_builds_the_pinned_block_0_under_the_published_rule` (node, in a child
  process) runs the node's own path: `publish_mpt_rule_for_genesis_build` for profile
  `r1007`, which resolves `Some(0)` from the genesis table, and then
  `initialize_genesis_state_with_profile`. Under D-K3 that build is refused (it checks the
  refusal names D-K3); the layout tests above read the r1006-keys layout directly.
- `r1007_genesis_state_refuses_to_build_without_the_mpt_rule` and
  `r1007_profile_build_refuses_without_the_published_rule`: with the rule unset, or
  active only from a later height, the build is refused. It never silently builds a
  different block 0.

**The hash is a candidate, not final.** It is the hash of the r1006-keys layout, which
no node builds under D-K3 (§1.1); it keys the r1007 tables until the fresh-keys alloc
re-pins it. It is a function of the allocation, the genesis block encoding and the root
rule. It moves when any of them changes:
- **D-K3: the fresh role keys change the allocation, so it moves;**
- a lane changes the genesis header or its hash pre-image (for example a v3 genesis
  header with `accepted_root` from mergeset execution);
- a lane changes the MPT leaf encoding;
- the owner changes the note or the producer set.

The integration step runs the example, re-pins `R1007_GENESIS`, and the economics test
confirms it. Every table keyed by the hash follows automatically: activations, chain
params, the release genesis list and the manifest binding. The genesis commit that
builds the real block 0 is the audit freeze (CV-13, `audit-freeze/r1007`).

## 3. Parameters

Status key:
- **Decided**: accepted by the owner or ADR, and enforced in this branch.
- **Recorded**: compiled in `R1007_CHAIN_PARAMS` and bound into the consensus
  fingerprint. The constant it must equal lives on another lane's branch, and the
  integration binds it (§5).
- **Decided 2026-11-09**: was PENDING OWNER in the first draft; the owner approved the
  value on 2026-11-09.

### 3.1 Genesis-keyed activations (`R1007_ACTIVATIONS`)

| Rule | r1007 | Source | Status |
|---|---|---|---|
| `mpt_state_root` | `Some(0)`, block 0 included | CV-14 (a)+(b), owner 2026-11-07; lead decision 2026-11-09 (block 0 under the rule); storage lane `r1007/s3-storage-cow` 8c7742ce | Decided |
| `pba_hardening` | `Some(0)` | r1006 schedule (owner 2026-10-26) carried over | Decided |
| `vrf_canonical_encoding` | `Some(0)` | as r1006 | Decided |
| `storage_root_hardening` | `Some(0)` | as r1006 | Decided |
| `supply_hardening` | `Some(0)`: on at block 0 (block 0 has no transactions, so it governs every executed tx) | mergeset lane recommendation: no 1 SALT deployment bonus for a *failed* deployment, and a deployment's `value` is transferred, not only checked | Decided 2026-11-09 |
| `exact_create_code` | `Some(0)`: on at block 0 | mergeset lane recommendation: contract-created code is stored exactly, not zero-padded (REVM's analysed form) | Decided 2026-11-09 |

The owner took the recommendation for both on 2026-11-09. `None` would have kept the
legacy behaviours on r1007, and removing them later needs a fork, which the soft-fork rule
(06 §11) does not allow after the audit freeze.

Checkpoint finality voting is on from genesis on the finality lane
(`CHECKPOINT_VOTING_FROM_GENESIS = true`, `r1007/s3-finality-voting-v2`), and enforcement
stays off (CV-8). That lane keys enforcement by `(chain id, genesis)` in
`CHECKPOINT_ENFORCEMENT_GENESES`, which is empty. After G5, governance adds
`(40204, R1007_GENESIS)` to it. The genesis lane needs to add nothing at launch.

### 3.2 Chain parameters (`R1007_CHAIN_PARAMS`)

| Parameter | Value | Source | Where it is enforced | Status |
|---|---|---|---|---|
| `slot_duration_secs` | 1 | 06 §1.2, owner question O2 (1 s = r1006's live cadence, vs 2 s or 5 s); time-slots lane `SLOT_DURATION_SECS = 1` | fingerprint; bind to `slots::SLOT_DURATION_SECS` at integration | Decided 2026-11-09 (O2: 1 s) |
| slot origin | genesis timestamp 1,767,225,600 | time-slots lane: `DagStore::set_slot_origin(genesis header)` | the genesis header | Decided (shared genesis block) |
| `max_future_drift_secs` | 15 | 06 G9 / reviewer R12; time-slots lane `MAX_FUTURE_SLOT_DRIFT_SECS = 15` (120 s hold horizon in v2) | fingerprint; bind at integration | Recorded (review R12) |
| `pruning_depth` | 10,000 chain blocks | 06 §1.2 D12; `dag_prune::MIN_RETAIN_BLOCKS` = `DEFAULT_RETAIN_BLOCKS` | test `r1007_undo_window_is_the_compiled_retention` | Decided (CV-7a, owner O7) |
| `undo_window` | 10,000 (= pruning depth) | CV-7a, owner 2026-11-07; `canonical_apply::MAX_REORG_DEPTH`, `state_store::REORG_UNDO_DEPTH` (S3-4) | same test | Decided |
| `ghostdag_k` | 18 | 06 D2 (valid while 2·D·λ ≤ 10; S1 measures D) | `GhostDagParams::default().k`, test | Decided, conditional on S1 (§1.3) |
| `max_parents` | 10 | 06 §1.2 | `GhostDagParams::default()` | Decided |
| `merge_depth` | 100 | 06 §1.2 | `ghostdag::MERGE_PARENT_MAX_DEPTH` | Decided |
| `checkpoint_interval` | 50 | 06 §1.2; finality lane `CHECKPOINT_INTERVAL = 50` | node start-up refuses another `[checkpoint] interval` on r1007 | Decided |
| `committee_size` | 100 (with 7 producers, all 7 are the committee) | finality lane `CHECKPOINT_COMMITTEE_SIZE = 100` | node start-up refuses another `[checkpoint] committee_size` on r1007 | Decided (reviewer R8 open on count vs stake) |
| `checkpoint_vote_depth` | 3 | `checkpoint::DEFAULT_VOTE_DEPTH` | node start-up refuses another `[checkpoint] vote_depth` on r1007 | Decided |
| `include_gas_limit` | 30,000,000 | 06 D9; `producer::PRODUCER_BLOCK_GAS_LIMIT`; mergeset lane `INCLUDE_GAS_LIMIT` | test | Decided 2026-11-09 (O5: 30M) |
| `accept_gas_limit` | 60,000,000 | 06 D9; mergeset lane `ACCEPT_GAS_LIMIT` | fingerprint; bind at integration | Decided 2026-11-09 (O5: 60M) |
| `validator_activation_height` | 1,000 (start of epoch 1; above S(1) = 800) | `R1006_VALIDATOR_ACTIVATION_HEIGHT` | the compiled registry binding (§3.3) | Decided |

The parameter rendering is appended to the genesis binding of the consensus fingerprint
(`|params:…`). A binary that disagrees on any value therefore prints a different
fingerprint on r1007. r1006's binding is byte-identical to before.

### 3.3 Validator registry and the finality committee

- **Registry binding.** `compiled_validator_set(Some(R1007_GENESIS))` returns
  (`0xf511327ef586908bc34990621e3624d5de4131cd`, 1,000), which is r1006's. Start-up
  uses it in place of the r1006-only branch. `CITRATE_VALIDATOR_REGISTRY` and
  `CITRATE_VALIDATOR_ACTIVATION_HEIGHT` may only repeat it, as on r1006, so registry
  snapshots and committees come from one set on every node.
- **Epoch-0 committee.** The finality-fixes lane adds `genesis_committee_set` (node) and
  `r1006::genesis_validator_set` (economics). r1007 needs one more arm in
  `genesis_committee_set`: `Some(g) if *g == R1007_GENESIS` gives the same set as r1006,
  because the validators file is shared. That arm is an integration item (§5), because
  this branch does not merge finality-fixes. Without it, r1007 votes form only from the
  first registry snapshot S(1) = 800. (Done on `r1007/genesis-candidate-2`,
  `r1007_genesis_committee_is_the_shared_validator_set`.)

## 4. Grants: what must run after genesis (plan only; nothing run)

Block 0 carries the r1006 *block-0* state. Everything that happened on r1006 after its
genesis is absent on r1007:
- membership grants (SBT mints and vault stakes);
- the grantor's funding;
- the post-genesis deploys (forwarder and relayer, Radar, the 32 unpinned post-genesis
  contracts noted on fed#331);
- the AA paymaster `setPaymaster`;
- the team-vesting and every other post-genesis transaction.

No step below may run before the owner's S4 go. Every step names its tool.

| # | Step | Tool (existing) | Notes |
|---|---|---|---|
| G0 | Record `R1007_GENESIS` (final, after integration) | this doc, gates.yaml `genesis_hash` | every pin below uses it |
| G1 | Canonical book: regenerate `contracts/addresses/40204.json` *in the genesis commit* from the r1006 block-0 book, with the r1007 genesis hash (CV-12) | `scripts/genesis/r1006/emit_book.py --check` against the shared alloc (passes today) | the addresses are unchanged; only the genesis identity changes. Consumers must refuse a book whose genesis differs from block 0 |
| G2 | Treasury signer reset to the new generation: signer `/health` reports `genesis` = `R1007_GENESIS`, so its ledger key `<genesis>/<orderId>` starts empty | identity#43 signer (genesis pin); core-membership#80 client (`CITRATE_GENESIS_HASH`) | the client refuses to POST unless `/health` echoes the pin (#80) |
| G3 | Fund the grantor `MEMBERSHIP_GRANTOR` `0x57b06e5d…ba2a` from the treasury (32,000 SALT per member to re-grant, plus gas). It holds no balance in block 0 | a treasury transfer (GOVERNANCE or treasury key, 1Password item names only) | **[OWNER]** money movement |
| G4 | Set `CITRATE_GENESIS_HASH` = `R1007_GENESIS` on core-membership (Vercel, server-side), then `vercel --prod` | core-membership#80 deploy order | until set, every grant is refused, with nothing sent (`genesis_unpinned`) |
| G5 | Re-issue: one full reconcile sweep. `sweepRerollReissues` returns each `granted`/`active`/`renewed` order whose SBT is absent and whose sub is unbound (`isRerollPhantom`) to `paid`; the stranded-order loop then re-grants it through the triple-proof, single-writer and KYC path (mint the SBT, then `vault.grant(member, 32000e18, tokenId)`) | core-membership#70 (`fix/reroll-reissue`, OPEN; moved to 0.5.3) | needs #70 merged first, **and #70 changed for the term (below)**: as written it opens a fresh one-year term. Each re-issue is audited `grant.reissue` and gets no dunning, SLA refund or welcome email. The member's wallet must be on record (the identity → members bridge) |
| G5′ | Fallback if #70 is not merged: per member with an active order and on-chain SBT = 0, call `mintMember(member, keccak256(sub), now, <remaining-term end>)` and then `grant(member, 32000e18, tokenId)` with `--value 32000e18` through the droplet signer | the droplet `/_ops/treasury/grant` (3-argument grant, SBT first). This is the 2026-09-20 manual procedure, with the term end changed | the app's `staging-grant.mjs` still uses the stale 2-argument grant and must not be used |
| G6 | Verify: for every re-granted member, `SBT.balanceOf = 1`, `vault.attributedStake = 32,000e18` and the SBT expiry = the member's r1006 term end on r1007, and the explorer shows the grant txs | `eth_call` read-only | the success gate for S4-3 / g5-apps |
| G7 | Re-deploy the post-genesis contracts that r1006 had outside block 0 (forwarder/relayer, Radar, the 32 unpinned deploys), and re-run `setPaymaster`. **Their addresses move**: they are nonce-CREATE from post-genesis deployers. Re-pin every consumer after an `eth_getCode` check | the per-app deploy scripts listed on fed#331; the stale-pin scan (every repo's default branch) | the drift rule (memory `reroll-membership-contracts-drift`) applies here, not to the block-0 SBT and vault |

### 4.1 The re-grant term (owner decision 2026-11-09)

A re-issued grant carries the **remaining r1006 term**, not a fresh year:
- The SBT is minted with `start = now` and `expiry` = the member's r1006 term end. The
  term end comes from the order's `expires_at` in core-membership (the member's paid
  coverage), which is the same end the r1006 SBT was minted with.
- An order whose `expires_at` is past is not re-issued. That is #70's existing "coverage
  remains" guard.
- An order with a NULL `expires_at` has no recorded end in the database. Its end is read
  from that member's r1006 SBT (`expiry` of `tokenIdForSub(subHash)`) on the final r1006
  snapshot, **before r1006 is retired (S4-5)**. If neither source has an end, the order is
  left for an operator and not granted.
- Change needed in core-membership#70: re-issue grants pass the order's remaining term to
  the mint, instead of `now + 1 year`. Add a test that a re-issued order's SBT expiry
  equals the order's `expires_at`. This lands before G5 runs.

**r1006-only grantees (owner decision 2026-11-09).** A member who held an r1006 SBT but
has no paid order **is** re-granted on r1007, with the remaining term of that r1006 SBT.

Where this is implemented (core-membership#83, stacked on #70):
- **`scripts/r1007-reissue.ts`:**
  - The end is the order's `expires_at`, else the r1006 SBT's `termEnd` from the final
    snapshot export. With neither, the member goes to `term_unknown_operator_queue` and is
    not granted.
  - r1006-only grantees are re-granted by default (`--r1006-only regrant`, the owner's
    decision). `skip` only lists them.
  - `verify` checks each SBT's term end against the plan.
- **#70's reconcile:**
  - A re-issue with no recorded expiry is queued for an operator once (`grant.reissue`,
    denied, `reissue_term_unknown`). It is never granted a fresh year.
  - A re-issue with an expiry is minted to that expiry, as before.

The final r1006 snapshot is taken at the ceremony's grant freeze, before the cut
(federation `ops/r1007-ceremony/RUNBOOK.md`, T0). Slot r1006 stays on every host until
S4-5, so the snapshot can be taken again until then.

### 4.2 Ceremony decisions (owner 2026-11-09)

The procedures are in the federation `ops/r1007-ceremony/RUNBOOK.md` (fed#467).
- **Treasury signer daily cap:** 20 grants a day for the re-grant window only, then
  restored to 3 a day. The restore is mandatory, and both changes are verified from the
  signer's `/health` (`r1007-reissue.ts cap-check`). Each grant counts 32,000.05 SALT against
  the cap (the bond plus the gas top-up). That is why today's default of 96,000 SALT admits
  only 2 grants, and why both values are set explicitly.
- **Developer notice:** pencilled in for 2026-11-25. It is confirmed only after G4 passes on
  the integrated candidate. Only at confirmation is the date set, in one change, in
  `NEXT_PUBLIC_TESTNET_RESET_DATE` (docs), `CITRATE_TESTNET_RESET_DATE` (explorer) and the
  email and X drafts.
- **KYC attestations:** members verified on r1006 get the SBT attestation back right after
  the re-issue, from the stored verification record (identity `/kyc/status`). Nobody redoes
  KYC. The `setKycVerified` write is `onlyOwner`, and the treasury signer has no endpoint
  for it, so the lead picks a write path before the ceremony (runbook §5.2).
- **DPF timelock wiring (G7/D3):** queued right after the post-genesis deploys, so the 48 h
  delay runs during the soak. It is executed at about T0+50 h and checked before the G5
  sign-off.

## 5. Integration checklist (for the step that combines the r1007 lanes)

**Status on `r1007/genesis-candidate-2` (2026-11-10):** items 1 to 3 are done there
(item 1 with the merge order in its merge commits, the finality fallback fix in `eb486a44`
and `cca762ce`; item 2 in `cca762ce`; item 3 as `r1007_chain_params_bind_the_lane_constants`).
Item 4 waits for D-K3 (§1.1): the hash cannot be final until the fresh-keys alloc exists.
Item 6 is open: the ops tooling renders `R1007_GENESIS` and should refuse while r1007 is
pending (a node it starts refuses anyway, at its genesis build).


1. Merge order: storage-cow is already in this branch. Then mergeset-execution,
   time-slots-v2 (not v1), finality-fixes (which contains voting-v2), and rpc-explorer.
   rpc-explorer's `finality_status_json` calls `checkpoint_voting_pinned(chain_id)` and
   `checkpoint_enforcement_pinned(chain_id)`, which voting-v2 removes or changes, so it
   needs a hand fix.
2. `genesis_committee_set`: add the `R1007_GENESIS` arm (§3.3).
3. Bind the lane constants to `R1007_CHAIN_PARAMS`. The constants do not exist on this
   branch, so the binding test can only compile after the merges in step 1:
   - `slots::SLOT_DURATION_SECS` (time-slots-v2), and `MAX_FUTURE_SLOT_DRIFT_SECS`;
   - `acceptance::INCLUDE_GAS_LIMIT` and `ACCEPT_GAS_LIMIT` (mergeset-execution);
   - `checkpoint::CHECKPOINT_INTERVAL` and `CHECKPOINT_COMMITTEE_SIZE` (finality-fixes).

   The test is `r1007_chain_params_bind_the_lane_constants` in
   `core/consensus/tests/r1007_chain_params.rs`, one `assert_eq!` per constant. On
   2026-11-09 the lane branches carry exactly the compiled values (1, 15, 30M, 60M, 50,
   100). The constants that exist here are bound already: `GhostDagParams::default()`,
   `MERGE_PARENT_MAX_DEPTH`, `CheckpointConfig::default()`, `DEFAULT_VOTE_DEPTH`,
   `producer::PRODUCER_BLOCK_GAS_LIMIT`, the undo-window and retention constants.
4. Re-run `cargo run -p citrate-economics --example r1007_genesis_hash`, re-pin
   `R1007_GENESIS`, and run `cargo test --workspace`.
5. Every genesis builder publishes the MPT rule first:
   - **node** (this repo): every build in `main.rs` calls
     `publish_mpt_rule_for_genesis_build`. The tripwire is
     `every_genesis_build_publishes_the_mpt_rule_first`.
   - **GUI** (citrate-core `src-tauri`): it spawns this node binary with a network
     profile, so it builds through the node path. It needs an r1007 entry in its network
     profiles (`genesis_profile = "r1007"`, `genesis_hash = R1007_GENESIS`) at its next
     chain pin bump.
   - **Light node** (citrate-native, `gui/citrate_desktop_app/src/services/node_service.rs`,
     which calls `initialize_shared_genesis_state` directly): before building r1007 it
     must call `citrate_execution::mpt_state_root::init_for_genesis(40204,
     Some(&R1007_GENESIS), None)`.
   - If any of them forgets, the shared function refuses to build the r1007 config. It
     names the rule, so the failure is loud and closed.
6. Ops: the r1006 node-config renderer (`scripts/ops/r1006/render_profile.py`) and the
   bring-up script name profile `r1006`. The S4 bring-up needs r1007 variants. No
   `[checkpoint]` override may differ from §3.2, or the node refuses to start.

## 6. Not verified here

- No network was touched. The hash has not been produced by a node binary on a host,
  only by the tests and the example on the build host.
- The GUI and light-node paths are in other repos. Here, only the fail-closed guard they
  will hit is tested.
- The grant plan is a plan. #70 is open and #80 is open. Neither has been exercised
  against r1007.
