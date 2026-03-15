# GUI & SDK Formal Verification Plan

**Date**: 2026-03-14
**Scope**: GUI state machines (Tauri + React), JavaScript SDK, Python SDK, CLI wallet

---

## Part 1: GUI State Machines

### 1.1 Existing Specs (Need .cfg Files + TLC Runs)

Four TLA+ specs exist in `gui/citrate_gui_v2/specs/` but have never been model-checked because they lack `.cfg` configuration files.

#### AuthStateMachine.tla
**Models**: Authentication flow — locked → authenticating → authenticated → session_expired
**React Implementation**: `features/auth/AuthGate.tsx`, `core/auth.ts`
**Action**: Create `AuthStateMachine.cfg` with:
```
CONSTANTS
  Users = {u1, u2}
  AuthMethods = {password, biometric, privy}
  SessionTimeout = 3
```
**Target Invariants**:
- `NoWalletAccessWithoutAuth` — wallet operations blocked in locked/expired states
- `SessionExpiryEnforced` — expired sessions cannot perform privileged operations
- `NoParallelSessions` — single active session per user

#### WalletSession.tla
**Models**: Wallet lifecycle — create → load → unlock → sign → lock
**React Implementation**: `features/wallet/WalletContext.tsx`, `services/walletService.ts`
**Action**: Create `WalletSession.cfg` with:
```
CONSTANTS
  Accounts = {acc1, acc2, acc3}
  MaxPendingTx = 3
```
**Target Invariants**:
- `NoSignWhenLocked` — transaction signing impossible in locked state
- `BalanceConsistency` — displayed balance matches state DB after tx confirmation
- `NoPendingTxOverflow` — pending transaction queue respects bounds

#### AgentChat.tla
**Models**: AI agent chat — idle → user_input → agent_thinking → tool_call → approval → executing → response
**React Implementation**: `features/chat/ChatInterface.tsx`, `features/chat/ChatContext.tsx`
**Action**: Create `AgentChat.cfg` with:
```
CONSTANTS
  Tools = {read_file, write_file, execute_cmd, send_tx, deploy_contract}
  HighRiskTools = {execute_cmd, send_tx, deploy_contract}
  MaxToolCalls = 3
```
**Target Invariants**:
- `NoHighRiskWithoutApproval` — mirrors AgentToolAuthorization spec
- `NoToolCallDuringInput` — agent doesn't execute tools while user is typing
- `ResponseAfterThinking` — every agent_thinking state eventually reaches response or error

#### EnvironmentSwitch.tla
**Models**: Network switching — current_env → switching → confirming → new_env
**React Implementation**: `features/settings/EnvironmentContext.tsx`, `config/environments.ts`
**Action**: Create `EnvironmentSwitch.cfg` with:
```
CONSTANTS
  Environments = {devnet, testnet, mainnet}
  RPCEndpoints = {rpc_devnet, rpc_testnet, rpc_mainnet}
```
**Target Invariants**:
- `NoStaleNetworkData` — no RPC response processed from previous environment
- `ConfigConsistency` — chain_id matches active environment
- `NoPartialSwitch` — switch is atomic (all state updated or none)

### 1.2 New GUI Specs Needed

#### OnboardingStateMachine.tla
**Purpose**: Model the 12-step onboarding flow
**React Implementation**: `features/onboarding/steps/` (12 step components)
**States**: `welcome → accept_terms → create_wallet → backup_seed → verify_seed → configure_node → start_node → fund_wallet → deploy_contract → verify_deployment → explore_features → complete`
**Key Invariants**:
- `NoSkipRequiredSteps` — cannot jump to step N without completing steps 1..N-1
- `NoRegression` — completed steps cannot revert to incomplete
- `BackupBeforeFund` — wallet funding blocked until seed backup verified

#### NodeLifecycleStateMachine.tla
**Purpose**: Model embedded node start/stop/restart
**Tauri Implementation**: `src-tauri/src/lib.rs`, `src-tauri/src/block_producer.rs`
**States**: `stopped → starting → syncing → running → stopping → stopped` (also: `crashed → recovering`)
**Key Invariants**:
- `NoOrphanedProcesses` — stopping always terminates all child processes
- `NoBlockProductionWhenStopped` — block producer inactive in stopped/stopping states
- `DataIntegrityOnCrash` — RocksDB consistent after crash→recovery transition

#### TransactionSubmissionFlow.tla
**Purpose**: Model GUI transaction lifecycle end-to-end
**Implementation**: `services/walletService.ts` → `adapters/ipc.ts` → `src-tauri/src/wallet_manager.rs`
**States**: `constructing → signing → submitting → pending → confirming → confirmed | failed`
**Key Invariants**:
- `NoDoubleSubmit` — same signed transaction never submitted twice
- `ConfirmationImpliesExecution` — confirmed status only after block inclusion
- `FailureRecovery` — failed transactions allow retry with incremented nonce

---

## Part 2: SDK Formal Verification

### 2.1 JavaScript SDK (`sdk/javascript/`)

#### SDKConnectionLifecycle.tla
**Purpose**: Model connection state machine
**Implementation**: `src/client.ts` (CitrateClient class)
**States**: `disconnected → connecting → connected → authenticated → disconnected`
**Constants**: `MaxRetries = 3, Endpoints = {primary, fallback}`
**Invariants**:
- `NoRPCWhenDisconnected` — RPC calls blocked in disconnected state
- `RetryBounded` — retry count never exceeds MaxRetries
- `FallbackOnFailure` — primary failure triggers fallback endpoint attempt

#### SDKTransactionLifecycle.tla
**Purpose**: Model transaction creation through confirmation
**Implementation**: `src/transaction.ts`, `src/wallet.ts`
**States**: `created → signed → submitted → pending → confirmed | reverted | dropped`
**Constants**: `MaxPendingPerAccount = 5, ConfirmationBlocks = 1`
**Invariants**:
- `NonceMonotonicity` — each account's nonces are strictly increasing
- `NoSignWithoutKey` — signing requires loaded private key
- `NoPendingOverflow` — pending count per account respects limit
- `DropImpliesTimeout` — dropped only after timeout, not arbitrary

#### SDKModelDeployment.tla
**Purpose**: Model AI model deployment lifecycle
**Implementation**: `src/model.ts`
**States**: `uploading → registering → verifying → deployed | failed`
**Invariants**:
- `NoRegisterWithoutUpload` — on-chain registration only after IPFS upload confirmed
- `CIDIntegrity` — registered CID matches uploaded content hash
- `MetadataComplete` — all required fields populated before registration

### 2.2 Alternative JS SDK (`sdks/javascript/citrate-js/`)

Same spec structure as official SDK but with implementation-specific constants matching `citrate-js` API surface.

### 2.3 Python SDK (`sdks/python/`)

#### PythonSDKLifecycle.tla
**Purpose**: Model Python SDK connection and transaction lifecycle
**Implementation**: `citrate_sdk/client.py`, `citrate_sdk/transaction.py`
**States**: Same as JavaScript SDK
**Additional Invariant**:
- `GILSafety` — concurrent SDK calls from multiple threads don't corrupt shared state (model with interleaving)

---

## Part 3: CLI & Tools Verification

### 3.1 CLI Wallet (`wallet/`)

#### WalletCLIStateMachine.tla
**Purpose**: Model CLI wallet command flow
**Implementation**: `wallet/src/main.rs`, `wallet/src/wallet.rs`, `wallet/src/transaction.rs`
**States**: `init → load_keystore | create_keystore → ready → {sign, send, balance, export} → ready`
**Invariants**:
- `KeystoreIntegrity` — keystore file consistent after any operation
- `NoSignWithoutLoad` — signing requires keystore loaded and unlocked
- `TransactionAtomicity` — sign+submit is atomic (no partial state on failure)

### 3.2 Faucet (`faucet/`)

#### FaucetRateLimiting.tla
**Purpose**: Model faucet request processing with rate limits
**States**: `idle → validating → checking_rate_limit → funding → cooldown`
**Constants**: `CooldownPeriod = 24h, MaxPerAddress = 1, FaucetBalance = 1000`
**Invariants**:
- `RateLimitEnforced` — no address receives more than MaxPerAddress per CooldownPeriod
- `BalanceNonNegative` — faucet balance never goes below 0
- `NoDuplicateFunding` — concurrent requests for same address don't both succeed

### 3.3 Explorer (`explorer/`)

#### ExplorerDataConsistency.tla
**Purpose**: Model explorer's data synchronization with RPC
**States**: `syncing → up_to_date → stale → resyncing`
**Invariants**:
- `NoMissingBlocks` — displayed block range is contiguous
- `TransactionInBlock` — every displayed transaction belongs to a displayed block
- `BalanceMatchesRPC` — displayed account balance matches `eth_getBalance` result

---

## Part 4: Implementation Roadmap

### Sprint Allocation

| Sprint | Specs | Points | Dependencies |
|--------|-------|--------|-------------|
| **Z+2** | Auth, Wallet, Environment, Node Lifecycle (GUI) | 13 pts | Phase 1 complete |
| **Z+3** | AgentChat, Onboarding, TransactionSubmission (GUI) | 13 pts | Z+2 |
| **Z+3** | SDKConnection, SDKTransaction (JS) | 8 pts | None |
| **Z+4** | PythonSDK, WalletCLI, FaucetRateLimit | 13 pts | None |
| **Z+4** | ModelDeployment, ExplorerConsistency | 8 pts | Z+3 |

### Per-Spec Checklist

For each new specification:
- [ ] Write `.tla` file with TypeInv + domain invariants
- [ ] Write `.cfg` file with small-but-representative constants
- [ ] Run TLC locally — verify 0 violations
- [ ] Record state count and search depth in verification report
- [ ] Add to `run_all.sh` script
- [ ] Add to CI workflow trigger paths
- [ ] Cross-reference with implementation code (file + line numbers)
- [ ] Document any bugs found during specification

### Tooling Requirements

| Tool | Purpose | Status |
|------|---------|--------|
| TLC (tla2tools.jar) | Model checker | Installed (v1.8.0) |
| OpenJDK 17 | TLC runtime | Installed (Homebrew) |
| `run_all.sh` | Batch runner | Exists for core specs |
| CI workflow | Automated checking | `.github/workflows/tla-check.yml` |
| **NEEDED**: `gui/specs/run_all.sh` | GUI spec batch runner | To be created |
| **NEEDED**: `specs/.formal/run_coverage.sh` | Coverage report generator | To be created |

---

## Part 5: Mapping Specs to Code

### Traceability Matrix (GUI)

| Spec | React Component | Tauri Backend | Context Provider |
|------|----------------|---------------|-----------------|
| AuthStateMachine | `AuthGate.tsx` | `lib.rs` | `core/auth.ts` |
| WalletSession | `WalletView.tsx` | `wallet_manager.rs` | `WalletContext.tsx` |
| AgentChat | `ChatInterface.tsx` | — | `ChatContext.tsx` |
| EnvironmentSwitch | `EnvironmentSwitcher.tsx` | — | `EnvironmentContext.tsx` |
| OnboardingFlow | `steps/*.tsx` | — | `OnboardingContext.tsx` |
| NodeLifecycle | `NodeControl.tsx` | `block_producer.rs` | `SettingsView.tsx` |
| TransactionSubmission | `AccountDetails.tsx` | `wallet_manager.rs` | `WalletContext.tsx` |

### Traceability Matrix (SDK)

| Spec | JS SDK File | Python SDK File | CLI File |
|------|------------|----------------|----------|
| ConnectionLifecycle | `src/client.ts` | `citrate_sdk/client.py` | — |
| TransactionLifecycle | `src/transaction.ts` | `citrate_sdk/transaction.py` | `wallet/src/transaction.rs` |
| ModelDeployment | `src/model.ts` | `citrate_sdk/model.py` | — |
| WalletCLI | — | — | `wallet/src/main.rs` |
| FaucetRateLimit | — | — | `faucet/src/main.rs` |
