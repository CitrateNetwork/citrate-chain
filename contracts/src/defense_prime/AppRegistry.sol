// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IMultiSigEnvelope} from "../quorum/ThresholdApproval.sol";
import {QuorumIdentity} from "../quorum/QuorumIdentity.sol";

/// @notice Legacy minimal interface (kept for ABI consumers). PBA-L2-012:
///         AppRegistry NO LONGER trusts `isSignedThresholdMet`, which reads
///         the envelope's own caller-chosen threshold/signers.
interface IEnvelopeOracle {
    function isSignedThresholdMet(bytes32 envelope_id) external view returns (bool);
}

/// @title AppRegistry — DefensePrime app + contract registry (DPF-09)
/// @notice Tracks deployed apps per tenant scope. Each app references
///         one or more already-deployed contract addresses; each
///         contract carries an audit-grade source ↔ bytecode binding
///         (`bytecode_hash == keccak256(eth_getCode(contract_addr))`).
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/AppRegistryLifecycle.tla`
///
/// Cited invariants:
///   - DeployedRequiresEnvelopeThresholdMet — load-bearing multi-sig
///     gate: an app cannot reach `Deployed` unless the referenced
///     envelope carries signatures from at least `threshold` members of
///     the approver set governance configured (snapshotted per app at
///     proposal), was drafted by the recorder that proposed the app, and
///     is bound to this registry + app (`corr_id == envelopeCorrId`).
///     PBA-L2-012 (pre-bounty audit 2026-09-24): this used to be
///     `isSignedThresholdMet`, i.e. the envelope's OWN threshold and
///     signer list, which anyone could self-draft as 1-of-1.
///   - RetiredIsAbsorbing — no transition out of Retired.
///   - BytecodeHashStableOnceDeployed — once an app is Deployed, the
///     recorded `bytecode_hash` for each contract in its `contracts[]`
///     list is immutable.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § entity-to-contract mapping
///      (APPS + CONTRACTS rows) + `07_DATA_SOURCES.md` § Panel 7.
///
/// @dev Per WP-3 design decisions (sprint scaffold):
///   - D-1: storage model approved; bytecode_hash is the load-bearing
///     audit field.
///   - D-2: `deploy(envelope_id)` registers an already-deployed
///     address, gated by the envelope's threshold. It does NOT
///     CREATE2-deploy in-contract — the heavy constructor call is a
///     separate operator action via wallet-core tx-builder.
contract AppRegistry {
    // ── Errors ─────────────────────────────────────────────────────

    error ZeroGovernance();
    error ZeroEnvelopeOracle();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AppAlreadyExists(bytes32 app_id);
    error AppDoesNotExist(bytes32 app_id);
    error AppNotInState(bytes32 app_id, AppState expected, AppState actual);
    error EnvelopeThresholdNotMet(bytes32 envelope_id);
    error EmptyContractsList();
    error EmptyName();
    error ZeroContractAddress();
    error ContractAlreadyRegistered(address contract_addr);
    error BytecodeMismatch(address contract_addr, bytes32 expected, bytes32 actual);
    // PBA-L2-012
    error NoApproverPolicy();
    error BadApproverPolicy(uint256 approvers, uint8 threshold);
    error DuplicateApprover(bytes32 approver);
    error NotProposerOrGovernance(address caller);

    // ── Types ──────────────────────────────────────────────────────

    /// @notice App lifecycle state. Matches AppRegistryLifecycle.tla
    ///         `States` enum minus Draft (Draft is the off-chain
    ///         pre-storage state).
    enum AppState {
        NotExist, // 0 — sentinel; an unset app
        Pending,  // 1 — proposed but envelope not yet met
        Deployed, // 2 — envelope met, app + contracts recorded
        Retired,  // 3 — terminal: deprecated by operator
        Failed    // 4 — terminal: envelope rejected
    }

    /// @notice An on-chain app record.
    struct AppEntry {
        bytes32 app_id;
        bytes32 scope;
        string name;
        string version;
        address owner;
        bytes32 deploy_envelope;
        address[] contracts;
        bytes32 source_cid; // IPFS CID for source bundle
        AppState state;
        uint256 deployed_at_block;
    }

    /// @notice A contract-library entry. The load-bearing audit field
    ///         is `bytecode_hash`, which a verifier can cross-check
    ///         against `keccak256(eth_getCode(contract_addr))`.
    struct ContractEntry {
        address contract_addr;
        bytes32 source_cid;
        bytes32 bytecode_hash;
        address compiler_oracle; // attestor that source ↔ bytecode
        bytes32 deploy_envelope;
        bytes32 deployed_by_app;
        uint256 deployed_at_block;
    }

    // ── Storage ────────────────────────────────────────────────────

    /// @notice Governance EOA / multi-sig that authorizes recorder
    ///         management + retirement.
    address public governance;

    /// @notice Address of the MultiSigEnvelope contract (DPF-02).
    ///         Used solely for the threshold-met check in `deploy`.
    IMultiSigEnvelope public envelope_oracle;

    /// @notice PBA-L2-012: registry-wide approver policy set by governance.
    ///         Snapshotted into each app at `proposeApp`.
    bytes32[] private _approvers;
    uint8 public approverThreshold;

    /// @notice Per-app snapshot of the policy + the proposing recorder's key.
    mapping(bytes32 => bytes32[]) private _appApprovers;
    mapping(bytes32 => uint8) public appThreshold;
    mapping(bytes32 => bytes32) public appProposerKey;

    /// @notice Recorder allowlist (write-gate for proposeApp,
    ///         registerContract).
    mapping(address => bool) public is_recorder;

    /// @notice app_id → AppEntry.
    mapping(bytes32 => AppEntry) public apps;

    /// @notice contract_addr → ContractEntry.
    mapping(address => ContractEntry) public contracts;

    /// @notice scope → app_ids in that scope.
    mapping(bytes32 => bytes32[]) public appsByScope;

    /// @notice All contracts ever registered, for the `defense_prime-contracts-list`
    ///         IPC. Append-only.
    address[] public allContractsList;

    // ── Events ─────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event ApproverPolicySet(uint256 approvers, uint8 threshold);
    event DeployEnvelopeRepointed(bytes32 indexed app_id, bytes32 indexed old_envelope, bytes32 indexed new_envelope);
    event AppProposed(
        bytes32 indexed app_id,
        bytes32 indexed scope,
        bytes32 indexed deploy_envelope,
        string name,
        string version,
        address owner
    );
    event AppDeployed(
        bytes32 indexed app_id,
        bytes32 indexed deploy_envelope,
        uint256 contracts_count,
        uint256 deployed_at_block
    );
    event AppRetired(bytes32 indexed app_id, uint256 retired_at_block);
    event AppFailed(bytes32 indexed app_id, bytes32 indexed deploy_envelope);
    event ContractRegistered(
        address indexed contract_addr,
        bytes32 indexed deployed_by_app,
        bytes32 indexed bytecode_hash,
        bytes32 source_cid
    );

    // ── Constructor ────────────────────────────────────────────────

    constructor(address initialGovernance, address envelopeOracle) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        if (envelopeOracle == address(0)) revert ZeroEnvelopeOracle();
        governance = initialGovernance;
        envelope_oracle = IMultiSigEnvelope(envelopeOracle);
    }

    // ── Governance ─────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    /// @notice PBA-L2-012: set the approver set (QuorumIdentity subject keys)
    ///         and threshold that a deploy envelope must satisfy. Applies to
    ///         apps proposed AFTER the call (each app snapshots it).
    function setApproverPolicy(bytes32[] calldata approvers, uint8 threshold) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        if (approvers.length == 0 || approvers.length > 64 || threshold == 0 || threshold > approvers.length) {
            revert BadApproverPolicy(approvers.length, threshold);
        }
        for (uint256 i = 0; i < approvers.length; ++i) {
            for (uint256 j = i + 1; j < approvers.length; ++j) {
                if (approvers[i] == approvers[j]) revert DuplicateApprover(approvers[i]);
            }
        }
        _approvers = approvers;
        approverThreshold = threshold;
        emit ApproverPolicySet(approvers.length, threshold);
    }

    function approverPolicy() external view returns (bytes32[] memory approvers, uint8 threshold) {
        return (_approvers, approverThreshold);
    }

    function appApprovers(bytes32 app_id) external view returns (bytes32[] memory) {
        return _appApprovers[app_id];
    }

    /// @notice The `corr_id` a deploy envelope for `app_id` must carry: binds
    ///         the approval to THIS registry and THIS app (PBA-L2-012).
    function envelopeCorrId(bytes32 app_id) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), app_id));
    }

    // ── Mutators ───────────────────────────────────────────────────

    /// @notice Propose a new app for deployment. Moves the app to
    ///         `Pending` state, bound to the given multi-sig envelope.
    /// @dev Cited transition: AppRegistryLifecycle.tla::Propose
    function proposeApp(
        bytes32 app_id,
        bytes32 scope,
        string calldata name,
        string calldata version,
        address owner,
        bytes32 deploy_envelope,
        address[] calldata initial_contracts,
        bytes32 source_cid
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (apps[app_id].state != AppState.NotExist) revert AppAlreadyExists(app_id);
        if (bytes(name).length == 0) revert EmptyName();
        // PBA-L2-012: an app cannot be proposed before an approver policy exists.
        if (approverThreshold == 0) revert NoApproverPolicy();
        _appApprovers[app_id] = _approvers;
        appThreshold[app_id] = approverThreshold;
        appProposerKey[app_id] = QuorumIdentity.subjectKey(msg.sender);

        // Note: initial_contracts may be empty if the app is registering
        // a logical group before its contracts are deployed. The
        // Deployed transition checks `contracts.length` against the
        // expected set if needed; we don't gate proposeApp on it.

        AppEntry storage a = apps[app_id];
        a.app_id = app_id;
        a.scope = scope;
        a.name = name;
        a.version = version;
        a.owner = owner;
        a.deploy_envelope = deploy_envelope;
        a.source_cid = source_cid;
        a.state = AppState.Pending;
        // Copy initial_contracts into storage.
        for (uint256 i = 0; i < initial_contracts.length; i++) {
            a.contracts.push(initial_contracts[i]);
        }

        appsByScope[scope].push(app_id);

        emit AppProposed(app_id, scope, deploy_envelope, name, version, owner);
    }

    /// @notice Register a deployed contract address into the contracts
    ///         library, with the source ↔ bytecode binding. The
    ///         bytecode_hash MUST match `keccak256(extcodecopy(addr))`;
    ///         we verify on-chain so the registry's audit guarantee
    ///         is enforced, not just claimed.
    /// @dev Cited invariant: BytecodeHashStableOnceDeployed.
    function registerContract(
        address contract_addr,
        bytes32 source_cid,
        bytes32 bytecode_hash,
        address compiler_oracle,
        bytes32 deploy_envelope,
        bytes32 deployed_by_app
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (contract_addr == address(0)) revert ZeroContractAddress();
        if (contracts[contract_addr].contract_addr != address(0)) {
            revert ContractAlreadyRegistered(contract_addr);
        }

        // Audit-grade gate: compute keccak256 of the runtime bytecode
        // and require it matches the claimed hash. Without this check,
        // the registry is a glorified address book.
        bytes32 actual = keccak256(_codeAt(contract_addr));
        if (actual != bytecode_hash) {
            revert BytecodeMismatch(contract_addr, bytecode_hash, actual);
        }

        contracts[contract_addr] = ContractEntry({
            contract_addr: contract_addr,
            source_cid: source_cid,
            bytecode_hash: bytecode_hash,
            compiler_oracle: compiler_oracle,
            deploy_envelope: deploy_envelope,
            deployed_by_app: deployed_by_app,
            deployed_at_block: block.number
        });
        allContractsList.push(contract_addr);

        emit ContractRegistered(contract_addr, deployed_by_app, bytecode_hash, source_cid);
    }

    /// @notice Mark an app as Deployed. Requires the referenced
    ///         envelope to have reached threshold (load-bearing
    ///         multi-sig gate per AppRegistryLifecycle.tla::INV1).
    /// @dev Cited transition: AppRegistryLifecycle.tla::Deploy
    /// @dev Cited invariant: DeployedRequiresEnvelopeThresholdMet
    function deploy(bytes32 app_id) external {
        AppEntry storage a = apps[app_id];
        if (a.state == AppState.NotExist) revert AppDoesNotExist(app_id);
        if (a.state != AppState.Pending) {
            revert AppNotInState(app_id, AppState.Pending, a.state);
        }
        if (!_envelopeApproves(app_id, a.deploy_envelope)) {
            revert EnvelopeThresholdNotMet(a.deploy_envelope);
        }

        a.state = AppState.Deployed;
        a.deployed_at_block = block.number;

        emit AppDeployed(app_id, a.deploy_envelope, a.contracts.length, block.number);
    }

    /// @notice Mark an app as Failed (envelope rejected). Anyone can
    ///         call once the envelope's terminal state is observable
    ///         off-chain; the contract validates the precondition by
    ///         checking the envelope is NOT met.
    function recordFailureOnEnvelopeReject(bytes32 app_id) external {
        // CHAIN-B-C025: gate the absorbing Failed transition. Previously
        // permissionless — any anonymous caller could watch for
        // `AppProposed` and immediately burn the app id forever (the
        // envelope has no signatures yet, so `isSignedThresholdMet` is
        // false and the caller's claim was accepted). Only an authorized
        // recorder or governance may record an envelope rejection.
        if (!is_recorder[msg.sender] && msg.sender != governance) {
            revert NotRecorder(msg.sender);
        }
        AppEntry storage a = apps[app_id];
        if (a.state == AppState.NotExist) revert AppDoesNotExist(app_id);
        if (a.state != AppState.Pending) {
            revert AppNotInState(app_id, AppState.Pending, a.state);
        }
        // Envelope is "rejected" if it is NOT met. Caller is implicitly
        // attesting that further state changes on the envelope are
        // impossible (e.g., expired or all signers revoked); for v1
        // we accept the caller's claim and rely on the off-chain
        // monitor to invoke this only when truly absorbing.
        if (_envelopeApproves(app_id, a.deploy_envelope)) {
            // Envelope is met → caller's claim is wrong; revert so the
            // happy-path Deploy is still reachable.
            revert EnvelopeThresholdNotMet(a.deploy_envelope);
        }
        a.state = AppState.Failed;
        emit AppFailed(app_id, a.deploy_envelope);
    }

    /// @notice Retire a deployed app. Owner OR governance can call.
    function retire(bytes32 app_id) external {
        AppEntry storage a = apps[app_id];
        if (a.state == AppState.NotExist) revert AppDoesNotExist(app_id);
        if (a.state != AppState.Deployed) {
            revert AppNotInState(app_id, AppState.Deployed, a.state);
        }
        if (msg.sender != a.owner && msg.sender != governance) {
            revert NotGovernance(msg.sender);
        }
        a.state = AppState.Retired;
        emit AppRetired(app_id, block.number);
    }

    /// @notice PBA-L2-012: re-point a Pending app at a fresh envelope id.
    ///         `MultiSigEnvelope.draft` is first-writer-wins, so an outsider
    ///         can occupy a published envelope id; the proposing recorder (or
    ///         governance) moves the app to a new id instead of losing it.
    function repointDeployEnvelope(bytes32 app_id, bytes32 new_envelope) external {
        AppEntry storage a = apps[app_id];
        if (a.state == AppState.NotExist) revert AppDoesNotExist(app_id);
        if (a.state != AppState.Pending) revert AppNotInState(app_id, AppState.Pending, a.state);
        if (
            msg.sender != governance
                && !(is_recorder[msg.sender] && QuorumIdentity.subjectKey(msg.sender) == appProposerKey[app_id])
        ) revert NotProposerOrGovernance(msg.sender);
        bytes32 old = a.deploy_envelope;
        a.deploy_envelope = new_envelope;
        emit DeployEnvelopeRepointed(app_id, old, new_envelope);
    }

    /// @notice True iff `envelope_id` is a live approval for `app_id` under
    ///         the app's snapshotted policy (PBA-L2-012). Never consults the
    ///         envelope's own `threshold`/`required_signers`.
    function isDeployApproved(bytes32 app_id) external view returns (bool) {
        AppEntry storage a = apps[app_id];
        if (a.state == AppState.NotExist) return false;
        return _envelopeApproves(app_id, a.deploy_envelope);
    }

    function _envelopeApproves(bytes32 app_id, bytes32 envelope_id) internal view returns (bool) {
        IMultiSigEnvelope.EnvelopeState st = envelope_oracle.getState(envelope_id);
        if (
            st == IMultiSigEnvelope.EnvelopeState.NotExist || st == IMultiSigEnvelope.EnvelopeState.Rejected
                || st == IMultiSigEnvelope.EnvelopeState.Closed
        ) return false;
        IMultiSigEnvelope.Envelope memory e = envelope_oracle.getEnvelope(envelope_id);
        // Drafted by the recorder that proposed this app ("bound to proposer").
        if (e.initiator != appProposerKey[app_id]) return false;
        // Bound to this registry and this app.
        if (e.corr_id != envelopeCorrId(app_id)) return false;
        if (e.expires_at != 0 && block.timestamp >= e.expires_at) return false;
        bytes32[] storage set = _appApprovers[app_id];
        uint256 counted;
        for (uint256 i = 0; i < set.length; ++i) {
            for (uint256 j = 0; j < e.signed_by.length; ++j) {
                if (e.signed_by[j] != set[i]) continue;
                if (envelope_oracle.signatureOf(envelope_id, set[i]).length != 0) ++counted;
                break;
            }
        }
        uint8 th = appThreshold[app_id];
        return th != 0 && counted >= th;
    }

    // ── Views ──────────────────────────────────────────────────────

    /// @notice All app_ids registered under a scope. Maps to
    ///         IPC `defense_prime-apps-list(scope)`.
    function byScope(bytes32 scope) external view returns (bytes32[] memory) {
        return appsByScope[scope];
    }

    /// @notice Number of contracts ever registered.
    function contractCount() external view returns (uint256) {
        return allContractsList.length;
    }

    /// @notice Returns the full app entry (storage struct).
    /// @dev For Solidity 0.8.26 auto-getters of structs containing
    ///      dynamic types (string, array) only return scalar fields;
    ///      we expose a typed getter for the full record.
    function getApp(bytes32 app_id) external view returns (AppEntry memory) {
        return apps[app_id];
    }

    /// @notice Returns the full contract entry.
    function getContract(address contract_addr) external view returns (ContractEntry memory) {
        return contracts[contract_addr];
    }

    /// @notice Returns the list of all contract addresses (for the
    ///         contracts-library page).
    function allContracts() external view returns (address[] memory) {
        return allContractsList;
    }

    // ── Internal ───────────────────────────────────────────────────

    /// @dev Read the runtime bytecode at an address into memory.
    function _codeAt(address target) internal view returns (bytes memory code) {
        uint256 size;
        assembly {
            size := extcodesize(target)
        }
        code = new bytes(size);
        assembly {
            extcodecopy(target, add(code, 0x20), 0, size)
        }
    }
}
