---
created: 2026-10-19T12:00:00Z
branch: ops/genesis-g5-ceremony
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active (draft for rehearsal 1; owner parameters OPEN)
supersedes: scripts/ceremony/REROLL_2026-09-28_RUNBOOK.md
workstream: C2 genesis spec, item G5
---

# Genesis ceremony runbook (betanet = mainnet genesis)

The betanet genesis on 2026-12-01 is the mainnet genesis. Mainnet is the same chain at a later activation height. Everything this runbook creates is permanent unless a later fork changes it.

This runbook covers the cut, the contract ceremony and the governance handover. The tooling it calls lives in [`scripts/genesis/`](.) and is tested offline by [`tests/test_genesis_scripts.sh`](tests/test_genesis_scripts.sh). It replaces [`REROLL_2026-09-28_RUNBOOK.md`](../ceremony/REROLL_2026-09-28_RUNBOOK.md), which still names the pre-r1005 deployer, governance and genesis and must not be followed.

**No key material appears in this runbook, in the scripts, or in their logs.** Signing uses Foundry keystore accounts (`--account`). The scripts refuse `--private-key` and refuse to run when a raw key variable (`PRIVATE_KEY`, `DEPLOYER_PRIVATE_KEY`, …) is set. Key handling follows [`keystore_protocol.md`](../ceremony/keystore_protocol.md).

## 0. Status of what this runbook depends on

"Implemented" means merged code. "Pending" means an open PR. Nothing here is runtime-proven until rehearsal 1.

| Dependency | State | Effect on this runbook |
|---|---|---|
| Genesis contract set: `DeployGenesisGovernance`, `DeployTeamVesting`, `DeployDormantLedgers`, `MultisigProposer`, `CheckDeployedAdmins` covering genesis seats | **Pending chain#320** | `genesis_ceremony.sh` P0 refuses to start until these scripts exist on the branch it runs from |
| Governance hardening: guardian CANCELLER-only on GOVERNANCE, production floors (3-of-≥5 / 48 h, guardian 2-of-≥3), guardian delay < governance delay, 14-day proposal TTL fixed on 40204, refusal of the weak-governance override on the genesis profile | **Pending chain#324** (stacked on #320) | P0 checks the same floors before anything is sent. The on-chain refusal is #324's |
| **The guardian can't cancel its own removal** (owner decision 2026-10-19) | **Pending chain#324** (fix in progress; not on the branch yet) | Until it lands, two compromised guardian keys could veto their own removal. Rehearsal 1 must run with it. §7.3 describes the intended behaviour |
| Final genesis profile (`citrate`), allocations, chain id + genesis hash in the fingerprint | Pending G1 | §6.1 builds the binary from it |
| Initial `blockSubsidy` | `BLOCK_SUBSIDY` is a constant in `contracts/script/DeployValidatorRegistry.s.sol` (today 10 SALT). Changing it is a code change that moves the ValidatorRegistry CREATE2 address | Must be merged **before** rehearsal 1, or the freeze pins the wrong address |
| Ceremony outputs folded into the book; `regenesis.sh` taking GOVERNANCE/GUARDIAN from the genesis output | Follow-up to #320 | `genesis_ceremony.sh` exports them from P1's output itself |

## 1. Dates

| Date | Event | This runbook |
|---|---|---|
| 2026-10-30 | Owner decisions (C2 §2) | Fills §2 |
| 2026-11-06 | Code freeze, audit phase A | #320, #324 and the subsidy value merged |
| 2026-11-13 | **Rehearsal 1**, address book freeze | §5 |
| 2026-11-23 | **Key ceremony** | §3 |
| 2026-11-24 | Rehearsal 2 (with the 0.5.2 RC) | §5 again, with the real holder addresses |
| 2026-12-01 | **Genesis** | §6 |

## 2. Parameters

Values not yet decided are **OPEN**. Nothing in this repo carries allocation amounts or holder identities; those stay in the private genesis spec until the genesis commit is public.

| Parameter | Value | Where it goes |
|---|---|---|
| Chain id | 40204 | `EXPECTED_CHAIN_ID` (default) |
| GOVERNANCE | **3-of-5**, 48 h delay (owner, 2026-10-19) | `GOV_OWNERS` (5 addresses, **OPEN: holders**), `GOV_THRESHOLD=3`, `GOV_MIN_DELAY=172800` |
| GUARDIAN | **2-of-3**, cancel only (owner, 2026-10-19) | `GRD_OWNERS` (3 addresses, **OPEN: holders**), `GRD_THRESHOLD=2`, `GRD_MIN_DELAY` (**OPEN**: ≥ 3600, < 172800; recommendation 3600) |
| Proposal TTL | **14 days, fixed on 40204** | `GOV_PROPOSAL_TTL` / `GRD_PROPOSAL_TTL` = 1209600 (the default; P0 refuses other values on 40204) |
| Holder independence | No address on both councils; the deployer on neither | P0 refuses otherwise. A shared seat needs the owner's written approval and `ALLOW_SHARED_HOLDERS=1` |
| Allocations (treasury, ecosystem, team, faucet, stakers, deployer gas) | **OPEN** (C2 D2) | The genesis profile (G1) |
| Team vesting: holders, amounts, cliff, duration, start | **OPEN** (C2 D2) | `TEAM_VESTING_FILE` under `contracts/genesis/` (gitignored) |
| Faucet cap | **OPEN** (C2 D2/D6) | Genesis allocation to the faucet signer; faucet policy is G4 |
| Initial `blockSubsidy` | **OPEN** (C2 D8) | `DeployValidatorRegistry.s.sol` constant (see §0) |
| Producer staker addresses (≥ 4, one per operator, generated by the operator) | **OPEN** (C2 D7, operators not yet named) | Genesis allocations; `reset_node.sh --coinbase` |
| Validator activation height | **OPEN** | `reset_node.sh --activation-height` |
| Genesis timestamp, genesis hash | Set and recorded at the cut | `EXPECTED_GENESIS_HASH` |
| 1.0 activation height | Set at 1.0, not at genesis | n/a |

## 3. Roles and keys

- **Deployer.** A fresh keystore account used only for the ceremony. It pays gas, deploys, and hands every role over in the same runs. After P5 reports `DEPLOYER-ADMIN 0` it holds nothing, and it is retired.
- **GOVERNANCE holders (5) and GUARDIAN holders (3).** Hardware wallets, eight distinct people or devices. The key ceremony on 2026-11-23 produces their **public addresses only**; the chain team never sees a private key. The addresses go into `GOV_OWNERS` / `GRD_OWNERS`.
- **Producer operators (≥ 4).** Each generates its own staker key on its own host and gives the chain team a public address (C2 D7). Each node also mints its own `proposer.key` on first start (§6.3).
- **Faucet signer.** A ceremony-held key, funded at genesis with the capped amount (G4 policy).
- The keystore password is typed at forge's prompt or read from a `--password-file` path. The scripts pass the path and never read or print the file.

## 4. Tooling (`scripts/genesis/`)

| Script | Writes? | What it does |
|---|---|---|
| `genesis_ceremony.sh` | Only with `--confirm` | The contract ceremony P0–P7 with a gate after each phase. Default is an offline dry run. `--simulate` runs against an RPC without broadcasting. `--from Pn` resumes and `--only Pn` runs one phase |
| `keep_check.sh` | No | Address-book freeze gate. `keys` lists book entries, `pin` records code hashes and proxy implementations from a chain, `verify` checks a chain against the pinned list. `--dry-run` needs no RPC |
| `fleet_agree.sh` | No | Every endpoint on the same chain id, the same block-0 hash and the same block hash at a common height |
| `reset_node.sh` | Only with `--confirm` | Per-node reset: watchdog off, node stopped, binary swapped (sha256-checked), data dir **archived**, identity carried, coinbase and registry set. Never starts the node |

Ported from DGX-local tooling of the R2 redeploy (`keep_check.sh`, `sample_height.sh`) and the r1005 reroll (per-node reset, deploy driver). The older `scripts/ops/reroll-orchestrate.sh` and `fleet-surgical-wipe.sh` are not on `main`; this set replaces them for the genesis.

Run the tests: `bash scripts/genesis/tests/test_genesis_scripts.sh` (CI: `.github/workflows/genesis-scripts.yml`).

### 4.1 Ceremony invariants

What a gate's pass guarantees, the code that enforces it, and the tests that prove it (test names as printed by `tests/test_genesis_scripts.sh`; "integration" cases run against a local anvil with the real `CheckDeployedAdmins`). The gates are P0, P5, P6 and P7. P1–P4 are steps, but P1 (`--confirm`), P2 and P4 (`--confirm`) run the same on-chain governance check before they use the councils. Every gate pass therefore means the governance floors (C3, C4) and the no-redeploy rule (C6) hold for the exact contracts and KEEP list recorded in this run's manifest (C2, C5, C6).

| # | Invariant | Enforced by (`genesis_ceremony.sh` unless noted) | Proved by |
|---|-----------|--------------------------------------------------|-----------|
| C1 | Run binding: every `--simulate`/`--confirm` invocation, resumes included, re-proves chain id, block-0 hash and timestamp, deployer, keystore account and mode against `ceremony-run.json` | P0: `manifest_write`, `manifest_check` | "a resume needs the run manifest", "a manifest from another genesis is refused", "a resume with another DEPLOYER_ADDRESS than the manifest is refused", "a simulation's manifest does not serve a --confirm resume" |
| C2 | Governance identity: the four governance contracts every later phase uses are the ones the manifest recorded at their first on-chain verification. A `governance.json` naming others fails, and P0 re-proves the recorded councils on chain on every resume | `load_governance` + `manifest_bind` (key `governance`); P0 calls `load_governance P0 1` once a record exists | "C2: P5 records the verified governance", "C2: the manifest holds the four governance addresses", "C2: a swapped governance.json fails the P0 preflight of a resume", "C2: a swapped governance.json stops P2 before regenesis", "C2: P0 re-proves the recorded governance on chain" |
| C3 | Governance floors on chain: for each council, the multisig's `timelock()` is its timelock and holds `PROPOSER_ROLE` there; `owners()` and `threshold()` equal the P0-validated inputs and are a strict majority; `getMinDelay()` equals the input; on 40204 also ≥ 5 owners / ≥ 3 threshold / ≥ 48 h (GOVERNANCE) and ≥ 3 / ≥ 2 / ≥ 1 h (GUARDIAN); the deployer holds no owner seat and no PROPOSER or DEFAULT_ADMIN role on either timelock; the GUARDIAN delay is shorter than the GOVERNANCE delay | `check_governance_onchain` → `council_onchain`, at P0 (once recorded), P1/P2/P4 (`--confirm`), P5, P6, P7 | "C3: P5 checks the councils on chain", the nine "C3: …" failure cases (2-of-5, other owners, 24 h delay, multisig fronting another timelock, not proposer, deployer proposer, deployer admin, unreadable timelock, guardian delay not shorter), "C3: a rehearsal chain holds the councils to its own inputs", "C3: a rehearsal council matching its inputs passes", "C3: P6 fails a council below its inputs", "C3: P7 fails a council below its inputs"; integration "the real councils pass the on-chain floor check", "a 2-of-5 governance council on chain fails" |
| C4 | No authority override (Codex r6 P1): `VALIDATOR_GOVERNANCE` and `VALIDATOR_SLASHER` are always P1's GOVERNANCE. A preset value that differs (or a conflicting `GOVERNANCE`, `GUARDIAN`, `GOVERNANCE_TIMELOCK`, `GOVERNANCE_MULTISIG`, `GUARDIAN_MULTISIG`) fails before regenesis runs. P5 reads `ValidatorRegistry.governance()` and `slasher()` (must be GOVERNANCE) and `pendingGovernance()` (must be 0) from the chain; on `--confirm` the book must list the registry | `load_governance` (preset check, exports); P5 registry block | "C4: a conflicting VALIDATOR_GOVERNANCE is refused before P2 runs", "C4: a refused P2 runs no regenesis", "C4: a conflicting VALIDATOR_SLASHER is refused", "C4: a conflicting GOVERNANCE preset is refused", "C4: regenesis gets VALIDATOR_GOVERNANCE and VALIDATOR_SLASHER = GOVERNANCE", "C4: P5 fails a registry governed by a stale EOA" (+ other slasher, pending transfer, unreadable, `--confirm` without a registry); integration "the real checker alone passes a registry governed by a stale EOA", "P5 fails a registry governed by a stale EOA", "P5 passes a registry governed by this run's GOVERNANCE" |
| C5 | Handover over the exact outputs: P5 sweeps one merged book; every book names the manifest's deployer; the vesting and dormant-ledger contract maps are the ones the manifest recorded at first use | P5 merge + `manifest_bind` (keys `teamVesting`, `dormantLedgers`) | "C5: P5 records the vesting output", "C5: P5 refuses a vesting output other than the recorded one", "P5 refuses an output from another deployer", "consistent books naming another deployer than the run's fail P5", "P5 fails a deployer role held in the vesting output" |
| C6 | No redeploy over the exact KEEP list (Codex r6 P2): the list's sha256 is recorded at P0 of a fresh run (or at first use) and any other list fails P0/P6. Each row's `contract_name` is the broadcast's Solidity name at the pinned address (`keys` derives it, `pin` refuses a mismatch); `verify` fails a deployment at a pinned address under another name, and a named row with no in-scope deployment at its pin | `manifest_bind` (key `keepListSha256`); `keep_check.sh`: `broadcast_names`, `pin` name check, scanner `rows_at` / `anchored` | "keys names EduForwarder by its broadcast name, Forwarder", "pin refuses a book-key name the broadcasts never deployed", "pin refuses - where the broadcasts show a deployment", "a Forwarder redeployed elsewhere fails under the EduForwarder alias", "a KEEP row named by the book key fails (pinned address deployed as Forwarder)", "a KEEP row name with no deployment at its pin fails", "a deployment at a - row's pinned address fails", "C6: P6 records the KEEP list", "C6: a resume's P0 refuses another KEEP list", plus the redeploy and scanner-failure cases |
| C7 | Fleet on this run's block 0 | P7 passes the manifest's block-0 hash to `fleet_agree.sh` | "P7 fails a fleet that agrees on another genesis than the run's" |

Limits, stated plainly. In `--simulate`, P1 deploys nothing, so P2 and P4 check the manifest record but not the chain; the gates still read the chain. The C3 getters are read after two cross-links (the multisig names the timelock and is its proposer); proving that the multisig is the exact `MultisigProposer` code is #320's `CheckDeployedAdmins` (CREATE2 provenance), which P5 runs once #320 is merged. A row whose contract has no broadcast deployment (a vendored or genesis-allocated contract) keeps `contract_name -` with a warning, so only its code, address and implementation are checked.

## 5. Rehearsal (1 on 2026-11-13, 2 on 2026-11-24)

Run the whole of §6 against a rehearsal network built from the release candidate, with rehearsal holder addresses (rehearsal 1) or the real holder addresses (rehearsal 2). In addition:

1. **Dry run** offline with the final inputs: `bash scripts/genesis/genesis_ceremony.sh`. It must print the full plan with no gate failure.
2. **Simulate** against a fork of the rehearsal chain at block 0, or a fresh local node from the release binary: `RPC_URL=http://127.0.0.1:8545 bash scripts/genesis/genesis_ceremony.sh --simulate`.
3. Run §6 for real on the rehearsal network.
4. **Freeze the address book** (rehearsal 1 only):
   ```bash
   ADDRESS_BOOK=contracts/addresses/40204.json BROADCAST_DIR=contracts/broadcast \
     bash scripts/genesis/keep_check.sh keys contracts,aaStack > KEEP_KEYS.tsv
   # mark ERC-1967 proxies "yes" in column 4; review every row, and every WARNING
   # (a row with no broadcast deployment gets contract_name "-": redeploy detection is off for it)
   RPC=<rehearsal rpc> ADDRESS_BOOK=contracts/addresses/40204.json BROADCAST_DIR=contracts/broadcast \
     bash scripts/genesis/keep_check.sh pin KEEP_KEYS.tsv > scripts/genesis/KEEP_LIST.genesis.tsv
   ```
   `contract_name` is the Solidity name the broadcasts recorded at the address, not the book key: the book's `EduForwarder` is the contract `Forwarder` (renamed by `emit-address-table.sh`), and an ERC-1967 proxy row is `ERC1967Proxy`. `keys` writes those names; `pin` refuses a row whose name differs from the broadcasts, and a `-` where they show a deployment.
   Commit `KEEP_LIST.genesis.tsv` in a reviewed PR. Contracts whose constructor takes holder addresses (the P1 governance pair, and every contract governed by it) move when rehearsal holders are replaced by the real ones, so **re-pin at rehearsal 2** with the real holder addresses and review the diff: only those expected entries may change. From this point an address change needs an explicit, reviewed re-pin. Addresses that depend on the deployer nonce (PatronageLedger, plain-CREATE deploys) only match if the genesis replays the exact same transaction sequence; the rehearsal shows which ones do.
5. **Governance drills** (rehearsal only, never on the genesis chain):
   - a GOVERNANCE proposal approved 3-of-5, queued, executed after 48 h (shorten nothing: run it across the rehearsal window, or use a rehearsal-profile delay and record that you did);
   - a GUARDIAN veto of a queued GOVERNANCE operation;
   - a proposal left unexecuted past 14 days reverts `ProposalExpired`;
   - **pending #324:** a GUARDIAN attempt to cancel a GOVERNANCE operation that removes the guardian's own role is refused.
6. Record the evidence (commands, outputs, block numbers) in the C2 sprint's EVIDENCE file.

## 6. Genesis cut (2026-12-01)

Coordinate on the federation tracking issue with the MAC lane. Each step is announced before it runs. Abort criteria are in §8.

### 6.1 Pre-cut gates

- [ ] #320 and #324 merged, including the guardian self-removal guard. The subsidy value merged.
- [ ] G1 merged: the final genesis profile, selected explicitly by `genesis_profile` in the release config; chain id and genesis hash in the consensus fingerprint.
- [ ] Release binary built from `main` at the release tag. Record its sha256; every node checks it (`EXPECTED_BIN_SHA256`).
- [ ] Rehearsal 2 passed end to end; `KEEP_LIST.genesis.tsv` committed.
- [ ] Key ceremony done: 5 + 3 holder addresses, ≥ 4 operator staker addresses, the faucet signer address. All in the genesis profile and the ceremony env.
- [ ] Offline dry run of `genesis_ceremony.sh` with the final env passes.

### 6.2 Reset the nodes

On each fleet node, as root, after staging the release binary at `$BIN.new`:

```bash
EXPECTED_BIN_SHA256=<release sha256> bash scripts/genesis/reset_node.sh \
  --coinbase <this operator's staker address> \
  --validator-registry <ValidatorRegistry address from the frozen book> \
  --activation-height <OPEN>            # dry run: prints the plan
# then the same command with --confirm
```

The script aborts before touching the binary or the data dir unless the watchdog timer, the watchdog service and the node all report inactive after the stop. The old data dir is moved to `.citrate.pregenesis-<ts>`, never deleted. `proposer.key` is not carried: each node mints a fresh consensus key on first start. New operator hosts that were never on a previous chain start from their own provisioning instead (producer runbook, C3).

### 6.3 Start the chain

1. Start the first producer **alone**. Read block 0 and record the genesis hash. Compare it to the hash computed from the genesis profile at the release commit. They must match.
2. Start the remaining producers and RPC nodes, one at a time.
3. Each operator copies its node's `proposer.key` **public key** to the chain team for registration. The private key stays on the node.
4. `FLEET_RPCS=<all endpoints> EXPECTED_GENESIS_HASH=<hash> bash scripts/genesis/fleet_agree.sh` must report `FLEET AGREE`.

### 6.4 Contract ceremony

From a clean checkout of the release tag, on the ceremony host, with the ceremony env loaded (no raw keys in it):

```bash
bash scripts/genesis/genesis_ceremony.sh                                  # offline plan
RPC_URL=<loopback rpc> bash scripts/genesis/genesis_ceremony.sh --simulate
RPC_URL=<loopback rpc> bash scripts/genesis/genesis_ceremony.sh --confirm --account <deployer keystore name>
```

| Phase | Does | Gate |
|---|---|---|
| P0 | Inputs, floors, tools, scripts present; chain id, block-0 hash and timestamp, remote-RPC authorization, deployer seat; deployer nonce 0 on a fresh start. A fresh run then writes the run manifest `GENESIS_OUT_DIR/ceremony-run.json` (run id, mode, chain id, block-0 hash and timestamp, deployer address, keystore account name) and refuses to start over an existing one; every resume re-reads it and stops unless chain, block 0, deployer, account and mode all match. Runs on **every** `--simulate`/`--confirm` invocation, including `--from` and `--only` resumes (only the nonce-0 check is skipped on a resume). A fresh run records the KEEP list's sha256; once the manifest records them, a resume also re-checks the KEEP list hash and re-proves the recorded councils on chain (§4.1 C2, C3, C6) | Any failure stops before a transaction. A missing or malformed manifest on a resume is a failure |
| P1 | GOVERNANCE and GUARDIAN: each a TimelockController fronted by a MultisigProposer. The GUARDIAN timelock gets CANCELLER only on GOVERNANCE (pending #324). The deployer renounces in the same run | The deploy script's own postconditions |
| P2 | The contract stack via `scripts/ops/regenesis.sh --reroll --with-aa`, with GOVERNANCE, GUARDIAN, VALIDATOR_GOVERNANCE and VALIDATOR_SLASHER set from P1's output. A different preset value in the environment stops the phase (§4.1 C4); on `--confirm` the councils are first checked on chain (C3) | regenesis exit status |
| P3 | Team vesting wallets from `TEAM_VESTING_FILE` | The deploy script's checks |
| P4 | FederatedRoundLedger and PatronageLedger, dormant, admin = GOVERNANCE timelock | The deploy script's governance check |
| P5 | `CheckDeployedAdmins` over one merged book, `p5-admin-book.json` in `GENESIS_OUT_DIR`: the address book plus the `contracts` of every P1/P3/P4 output (all three on `--confirm`). Every book (the address book and each output) must name the run manifest's deployer, so stale books that agree on another deployer are refused before the checker runs; the merge also refuses an output with no contracts or a reused name, so the checker sweeps every ceremony contract through the one book it always reads. The report must carry exactly one summary line per class. Before the checker: both councils on chain (§4.1 C3), the outputs bound to the manifest (C5), and `ValidatorRegistry.governance()`/`slasher()` = GOVERNANCE with nothing pending (C4) | **`FACTORY-ADMIN 0` and `DEPLOYER-ADMIN 0`**, councils at the floors, registry governed by GOVERNANCE |
| P6 | Councils on chain (C3); the KEEP list must be the one the manifest recorded (C6). Then `keep_check.sh verify` against `KEEP_LIST.genesis.tsv`, reading every broadcast record of this chain id (`run-latest.json` and every timestamped `run-<ts>.json`) recorded since the manifest's block-0 timestamp; no in-scope record at all, or a `broadcast/multi/` record, fails | Every frozen address has the frozen code; a kept contract deployed anywhere but its pinned address fails; a pinned address deployed under another contract name than its row's, or a named row with no deployment at its pin, fails; a broadcast that cannot be scanned, or a scanner that crashes, fails the gate |
| P7 | Councils on chain (C3); `fleet_agree.sh`, with the run manifest's block-0 hash as the expected genesis | All endpoints are on this run's block 0 and agree on the tip |

The phase outputs (`governance.json`, `team-vesting.json`, `dormant-ledgers.json`) live in one directory, `GENESIS_OUT_DIR` (default `contracts/genesis`; it must be that directory or one below it). A phase that writes one of them refuses to start while the file already exists, so move an earlier run's or a simulation's output aside first.

A failed phase prints the exact `--from Pn` to resume with. A phase that failed after broadcasting part of its transactions is never re-run blindly: read `contracts/broadcast/` and the chain first.

### 6.5 Validators and finality

1. Register the ≥ 4 producers into ValidatorRegistry with their stake (C2 D7) before the go/no-go check.
2. The go/no-go needs ≥ 4 producers and finality running (C3).

### 6.6 After the cut

1. Regenerate the address book from the ceremony outputs; diff it against the frozen book (P6 already proved the addresses). Fan out per [`REROLL_FANOUT.md`](../ceremony/REROLL_FANOUT.md).
2. Record the genesis hash, the release sha256 and the ceremony evidence in the genesis spec §4 and the sprint EVIDENCE file.
3. Re-enable the height watchdog on each node once the chain is past the activation height and every node is at the tip.
4. Retire the deployer keystore.

## 7. Governance after the handover

### 7.1 A change

1. A GOVERNANCE holder proposes an operation on the GOVERNANCE MultisigProposer. Two more approve (3-of-5).
2. The multisig schedules it on the GOVERNANCE TimelockController. It waits at least 48 h.
3. The multisig executes it. An approved proposal that isn't executed within **14 days** expires, and re-proposing starts a new id.

### 7.2 A veto

The GUARDIAN 2-of-3 schedules `cancel(id)` on its own timelock and executes it after the guardian delay, which is shorter than the 48 h governance delay, so the veto lands in time. The guardian can only cancel; it can't propose or execute on GOVERNANCE.

### 7.3 Removing the guardian (pending #324)

GOVERNANCE can always replace a compromised or hostile guardian after its 48 h delay. Owner decision 2026-10-19: the guardian's veto covers every GOVERNANCE operation **except** one that revokes or replaces the guardian's own role. Until that guard is merged, this guarantee does not hold, and the genesis must not proceed without it.

## 8. Abort and rollback

Abort, and announce it, if any of these happens:

- the block-0 hash differs from the one computed at the release commit, or `fleet_agree.sh` fails;
- any P0–P7 gate fails and the fix isn't a resumable input correction;
- `DEPLOYER-ADMIN` or `FACTORY-ADMIN` is not 0;
- a frozen address has different code (P6), unless the owner approves a re-pin in writing.

Before the public announcement, the chain can be cut again: every node keeps its archived data dir, and `reset_node.sh` runs again with the same inputs. After the announcement, a fix is a governance operation or a soft fork, not a re-cut.

## 9. Older runbooks

- [`REROLL_2026-09-28_RUNBOOK.md`](../ceremony/REROLL_2026-09-28_RUNBOOK.md): superseded by this runbook.
- [`I64S1_REROLL_RUNBOOK.md`](../ceremony/I64S1_REROLL_RUNBOOK.md), [`CEREMONY_CHECKLIST.md`](../ceremony/CEREMONY_CHECKLIST.md), [`GUIDED_OPERATOR_FLOW.md`](../ceremony/GUIDED_OPERATOR_FLOW.md): historical; read for context only.
