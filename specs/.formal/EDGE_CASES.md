# Edge Cases & Race Conditions Registry

**Date**: 2026-03-14
**Purpose**: Catalog identified edge cases, race conditions, and concurrency bugs across the Citrate codebase that require formal verification or hardening.

---

## Critical Race Conditions

### RC-1: GUI Block Producer State Commit Race
**Location**: `gui/citrate_gui_v2/src-tauri/src/block_producer.rs`
**Severity**: P0 — Data Loss
**Description**: If the GUI block producer crashes between transaction execution (line ~140) and state commit (line ~374), executed transactions are lost but may have already been reported to the user as confirmed.
**Current Mitigation**: Fixed in recent audit — state commit now happens immediately after execution.
**Formal Verification Need**: TLA+ spec for `GUIBlockProducerLifecycle` modeling the execute→commit→receipt-store sequence with crash recovery.
**Invariant**: `\A tx \in executed : tx \in committed \/ tx \in rollback_set`

### RC-2: Mempool Nonce Gap Under Concurrent Submission
**Location**: `core/sequencer/src/mempool.rs`
**Severity**: P0 — Transaction Ordering
**Description**: When two transactions from the same sender arrive nearly simultaneously, nonce validation races against mempool insertion. Transaction B (nonce=2) may be validated before Transaction A (nonce=1) is inserted, causing B to be rejected as "nonce too high."
**Current Mitigation**: `MempoolSequencer.tla` verifies `NoncesAboveState` but doesn't model concurrent insertion.
**Formal Verification Need**: Extend `MempoolSequencer.tla` with a `ConcurrentSubmit` action that models two simultaneous insertions.
**Invariant**: `NoncesContiguous == \A s \in Senders : \A n1, n2 \in senderNonces(s) : n2 = n1 + 1 \/ n2 = n1`

### RC-3: Environment Switch During Active RPC Call
**Location**: `gui/citrate_gui_v2/src/features/settings/EnvironmentContext.tsx`
**Severity**: P1 — Data Corruption
**Description**: If the user switches from devnet to testnet while an RPC call (balance check, tx submission) is in flight, the response may be attributed to the wrong network. Balances from devnet could overwrite testnet state in the UI.
**Current Mitigation**: `EnvironmentSwitch.tla` exists but has no `.cfg` file — never model-checked.
**Formal Verification Need**: Create `.cfg`, add invariant that no RPC response is processed if its source network differs from current active network.
**Invariant**: `NoStaleNetworkResponse == \A resp \in pendingResponses : resp.network = activeNetwork`

### RC-4: VRF Output Chaining Under Reorg
**Location**: `node/src/producer.rs` (lines 515-525)
**Severity**: P0 — Consensus Safety
**Description**: VRF alpha binding includes `prev_vrf_output` from the selected parent. During a DAG reorg (tip switch), the producer may use a VRF output from a block that is no longer in the canonical chain, creating an invalid VRF chain.
**Current Mitigation**: `VRFElection.tla` models single-slot election but not multi-slot chaining with reorgs.
**Formal Verification Need**: New spec `VRFChainContinuity.tla` modeling VRF output chaining across reorgs.
**Invariant**: `VRFChainValid == \A b \in blocks : b.vrf_alpha = Hash(b.parent.vrf_output || b.proposer || b.slot)`

### RC-5: Checkpoint Finality vs DAG Tip Race
**Location**: `core/consensus/src/checkpoint.rs`
**Severity**: P0 — Consensus Safety
**Description**: A checkpoint can finalize a block while a concurrent tip switch makes that block no longer the selected parent chain head. The depth-based finality and checkpoint-based finality may disagree.
**Current Mitigation**: `CheckpointSafety.tla` verifies quorum but doesn't model interaction with tip selection.
**Formal Verification Need**: Combined spec `FinalityInteraction.tla` modeling both finality mechanisms.
**Invariant**: `FinalityAgreement == checkpointFinalized \subseteq depthFinalized \/ depthFinalized \subseteq checkpointFinalized`

### RC-6: Wallet Session Expiry During Transaction Signing
**Location**: `gui/citrate_gui_v2/src/features/wallet/WalletContext.tsx`
**Severity**: P1 — UX / Security
**Description**: If a wallet session expires while a transaction is being signed (multi-step process: construct → sign → submit), the signing key may be cleared mid-operation, causing a partial failure or, worse, the signed transaction may be submitted after re-authentication with different wallet state.
**Current Mitigation**: `WalletSession.tla` exists but has no `.cfg` file.
**Formal Verification Need**: Model the sign→submit flow with session expiry as a concurrent event.
**Invariant**: `NoSignAfterExpiry == \A tx \in signed : sessionActive(tx.signer)`

### RC-7: IPC Message Ordering in Tauri Bridge
**Location**: `gui/citrate_gui_v2/src/adapters/ipc.ts`
**Severity**: P2 — Data Consistency
**Description**: Tauri IPC calls are async. If the GUI sends `getBalance` then `sendTransaction` then `getBalance`, the second `getBalance` may return before the `sendTransaction` completes, showing stale data.
**Current Mitigation**: None — raw `invoke()` calls with no sequencing.
**Formal Verification Need**: `IPCBridge.tla` spec modeling message ordering and response attribution.
**Invariant**: `ResponseOrdering == \A req1, req2 \in requests : req1.seq < req2.seq /\ causal(req1, req2) => resp(req1).time < resp(req2).time`

### RC-8: State DB Concurrent Read/Write During Block Execution
**Location**: `core/execution/src/state/state_db.rs`
**Severity**: P1 — State Corruption
**Description**: The state DB uses `RwLock` for concurrent access. During block execution, if an RPC `eth_call` reads state while a block is being executed, it may see partially-applied state (some transactions executed, others not yet).
**Current Mitigation**: Execution holds write lock during full block execution.
**Formal Verification Need**: `StateDatabaseConcurrency.tla` modeling read/write lock semantics with block execution.
**Invariant**: `NoPartialState == \A read \in rpcReads : read.state \in {preBlock, postBlock}` (snapshot isolation)

---

## Concurrency Edge Cases

### CE-1: IPFS Upload Timeout During Model Deployment
**Location**: `node/src/artifact.rs`, `core/api/src/eth_rpc.rs`
**Description**: `citrate_deployModel` uploads to IPFS then registers on-chain. If IPFS times out after partial upload, the model is registered with an incomplete CID.
**Required Invariant**: Model registration only succeeds if IPFS CID is verified complete.

### CE-2: Peer Discovery During Network Partition
**Location**: `core/network/src/`
**Description**: During a network partition, peer discovery may add peers from the other partition. When the partition heals, stale peer lists could cause connection storms.
**Required Invariant**: Peer list size bounded, stale peers evicted before reconnection.

### CE-3: Genesis Block Race in Multi-Node Startup
**Location**: `node/src/genesis.rs`
**Description**: If multiple nodes start simultaneously, each may create a slightly different genesis block if timestamps differ or if genesis parameters are not exactly identical.
**Required Invariant**: All nodes produce identical genesis block regardless of startup timing.

### CE-4: Faucet Double-Drip
**Location**: `faucet/`
**Description**: If a user submits multiple faucet requests before the first transaction confirms, rate limiting based on on-chain state won't catch duplicates.
**Required Invariant**: Per-address rate limit enforced across pending+confirmed transactions.

### CE-5: SDK Connection Pool Exhaustion
**Location**: `sdk/javascript/src/`
**Description**: If the SDK opens connections faster than they're closed (e.g., rapid retry loop), the connection pool may exhaust, blocking all SDK operations.
**Required Invariant**: Connection count bounded, oldest idle connections reclaimed.

---

## Boundary Conditions

### BC-1: Maximum DAG Width
**Description**: GhostDAG with 100+ parallel tips. Blue set calculation becomes O(n^2) with merge parents.
**Question**: Does `MaxParents=10` constraint prevent pathological DAG shapes?
**Verification Need**: Model GhostDAG with `MaxParents=10, Blocks=20` to explore maximum fan-out.

### BC-2: Mempool at Full Capacity
**Description**: What happens when mempool is at `MaxCapacity` and a higher-priority transaction arrives?
**Verification**: `MempoolSequencer.tla` verifies `CapacityRespected` but doesn't model priority eviction ordering.
**Extension**: Add `EvictAndInsert` action to spec.

### BC-3: Zero-Validator Committee
**Description**: If all validators go offline, can a checkpoint still be created? Should the system halt or continue with depth-based finality only?
**Verification**: `CheckpointSafety.tla` has `Quorum=3` but doesn't model the degraded mode.
**Extension**: Add `DegradedMode` action where committee size drops below quorum.

### BC-4: Chain ID Mismatch
**Description**: Transaction signed with chain ID 40204 submitted to node with different chain ID (misconfiguration).
**Verification Need**: Spec for transaction validation that includes chain ID check.

### BC-5: Maximum Block Size / Gas Limit
**Description**: Block stuffed with maximum-gas transactions. Does execution timeout? Does the gas limit correctly prevent overfill?
**Verification Need**: `BlockExecution.tla` with gas accounting.

---

## Missing Error Recovery Paths

### ER-1: Node Crash During State Root Computation
**Location**: `core/storage/src/state_db.rs`
**Risk**: State trie left in inconsistent state after crash. On restart, state root may not match expected value.
**Mitigation**: Write-ahead log or atomic commit.

### ER-2: GUI Wallet Key Export During Signing
**Location**: `gui/citrate_gui_v2/src-tauri/src/wallet_manager.rs`
**Risk**: If user initiates key export while a background transaction is being signed, the key material access may conflict.
**Mitigation**: Mutex on key access with signing priority.

### ER-3: Explorer WebSocket Disconnect During Block Subscription
**Location**: `explorer/`
**Risk**: If the WebSocket drops, the explorer may miss blocks and show gaps in the chain visualization.
**Mitigation**: Reconnect with gap-fill from last known block number.

### ER-4: SDK Retry After Network Partition Heal
**Location**: `sdk/javascript/`, `sdks/python/`
**Risk**: Retried transactions may now succeed (network is back) but the original also eventually succeeds — double execution.
**Mitigation**: Nonce-based idempotency check before retry.

---

## Priority Matrix for Formal Verification

| ID | Description | Severity | Effort | Priority |
|----|-------------|----------|--------|----------|
| RC-1 | GUI producer commit race | P0 | 3 pts | Immediate |
| RC-2 | Mempool nonce gap | P0 | 5 pts | Phase 2 |
| RC-4 | VRF chaining under reorg | P0 | 8 pts | Phase 2 |
| RC-5 | Checkpoint vs DAG tip race | P0 | 8 pts | Phase 2 |
| RC-3 | Environment switch race | P1 | 3 pts | Phase 3 |
| RC-6 | Wallet session expiry | P1 | 3 pts | Phase 3 |
| RC-8 | State DB concurrency | P1 | 5 pts | Phase 2 |
| RC-7 | IPC message ordering | P2 | 5 pts | Phase 3 |
| CE-4 | Faucet double-drip | P2 | 3 pts | Phase 4 |
| BC-2 | Mempool eviction ordering | P1 | 3 pts | Phase 2 |
| BC-3 | Zero-validator degraded mode | P1 | 5 pts | Phase 2 |
