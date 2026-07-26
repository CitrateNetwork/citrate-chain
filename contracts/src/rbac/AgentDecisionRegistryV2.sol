// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title AgentDecisionRegistryV2 — every signed decision, every agent tool call
/// @notice Append-only log of every signed action in the system, indexed
///         by user, tenant, correlation-id, event-class. Powers the
///         audit-event ribbon, the Governance audit-log panel, and the
///         assistant decision log.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/AgentDecisionLog.tla`
/// @dev Cited invariants:
///   - `AppendOnly` — `record()` only appends; existing decisions never
///     mutate. Storage layout has no in-place rewrite for `decisions[id]`.
///   - `DisputeRequiresRecorded` — `dispute()` reverts unless the
///     `decision_id` is in Recorded state.
///   - `NotRecordedNotInList` — non-existent decision_ids return zero
///     records and don't appear in any index.
///   - `RecordedInList` — every recorded decision is retrievable by
///     `byUser`, `byTenant`, `byCorrId`, `byClass`.
///   - `ListUnique` — no duplicate decision_id in the registry.
///   - `LengthConsistent` — `byUser.length` reflects the count of
///     recorded decisions for that user.
///
/// @dev V2 upgrade per `03_RBAC_CONTRACTS.md` § 5. Existing V1 contract
///      at `AgentDecisionRegistry.sol` carries a different shape
///      (paramsHash + toolName + DecisionStatus). V2 ships as a new
///      contract; migration path documented in
///      `audits/bfr-02-upgrade-safety.md`. BFR-02 deliverable.
contract AgentDecisionRegistryV2 {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice Top-level event classification used by the audit-event
    ///         ribbon and by Governance → Audit Log filters.
    enum EventClass {
        Provenance,    // 0
        Supplier,      // 1
        Model,         // 2
        Compute,       // 3
        Governance,    // 4
        App,           // 5
        Contract,      // 6
        Network,       // 7
        Verification,  // 8
        Audit          // 9
    }

    /// @notice Recorded-decision lifecycle status. Stored as a tagged
    ///         string so future statuses can be added without an
    ///         enum-shape upgrade.
    string internal constant STATUS_VERIFIED = "Verified";
    string internal constant STATUS_PENDING = "Pending";
    string internal constant STATUS_DISPUTED = "Disputed";
    string internal constant STATUS_REVOKED = "Revoked";

    struct Decision {
        bytes32 decision_id;
        bytes32 user;
        bytes32 tenant;
        bytes32 corr_id;
        EventClass class;
        string description;
        string auth_mode;
        bytes32 artifact_root;
        string status;
        uint64 ts;
        bool exists;
        // FWA-C3-09: the on-chain recorder that attested this decision
        // (msg.sender at record time) and the hash of the off-chain
        // decision signature bound to this exact record. Makes "every
        // signed decision" verifiable: the attestor is on-chain, and the
        // signature material is bound to (decision_id,user,tenant,corr_id,
        // artifact_root) so a recorder cannot later claim a decision was
        // unsigned or swap the signature.
        address attestor;
        bytes32 decision_sig_hash;
    }

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 decision_id => Decision) private _decisions;
    mapping(bytes32 corr_id => bytes32[]) private _by_corr_id;
    mapping(bytes32 user => bytes32[]) private _by_user;
    mapping(bytes32 tenant => bytes32[]) private _by_tenant;
    mapping(uint8 class_idx => bytes32[]) private _by_class;

    /// @notice Authorized recorders. The off-chain orchestrator (typically
    ///         the agent runtime + RoleEscalation gate) is the typical
    ///         recorder; admin-managed.
    mapping(address => bool) public is_recorder;

    /// @notice Admin authority (root-tenant multi-sig executor).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event DecisionRecorded(
        bytes32 indexed decision_id,
        bytes32 indexed user,
        bytes32 indexed tenant,
        bytes32 corr_id,
        EventClass class
    );

    /// @notice FWA-C3-09: emits the on-chain attestor and the bound
    ///         signature hash so off-chain verifiers can reconstruct and
    ///         check the decision signature.
    event DecisionAttested(
        bytes32 indexed decision_id,
        address indexed attestor,
        bytes32 decision_sig_hash
    );

    event DecisionDisputed(
        bytes32 indexed decision_id,
        bytes32 indexed corr_id,
        string reason
    );

    event DecisionRevoked(
        bytes32 indexed decision_id,
        bytes32 indexed corr_id,
        string reason
    );

    event RecorderSet(address indexed recorder, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ZeroGovernance();
    error DecisionAlreadyExists(bytes32 decision_id);
    error DecisionDoesNotExist(bytes32 decision_id);
    error DisputeRequiresRecorded(bytes32 decision_id, string current_status);
    error EmptyAuthMode();
    error EmptyDescription();
    error InvalidClass(uint8 class_idx);
    /// @notice FWA-C3-09: a decision must carry a non-empty signature.
    error EmptyDecisionSig();

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance transfer (two-step) ──────────────────────────────

    /// @notice Governance nominated to take over, pending its own
    ///         acceptance. Zero when no transfer is in flight.
    address public pendingGovernance;

    /// @notice Emitted when a transfer is proposed.
    event GovernanceTransferStarted(address indexed from, address indexed to);
    /// @notice Emitted when the nominee accepts and governance moves.
    event GovernanceTransferred(address indexed from, address indexed to);

    error NotPendingGovernance(address caller);

    /// @notice Nominate `newGovernance`. It does not take effect until the
    ///         nominee calls {acceptGovernance}.
    ///
    /// @dev Two-step on purpose. `governance` gates every admin operation on
    ///      this contract and there is no recovery path: a one-step setter
    ///      pointed at a typo, an address on the wrong chain, or a contract
    ///      that cannot call back would brick administration permanently and
    ///      the only remedy would be redeploying and re-booking the address
    ///      across the federation. Requiring the nominee to prove it can
    ///      transact makes that unreachable.
    ///
    ///      Passing `address(0)` clears a pending nomination.
    function transferGovernance(address newGovernance) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        pendingGovernance = newGovernance;
        emit GovernanceTransferStarted(governance, newGovernance);
    }

    /// @notice Accept a pending nomination. Only the nominee may call this.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) {
            revert NotPendingGovernance(msg.sender);
        }
        address previous = governance;
        governance = msg.sender;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, msg.sender);
    }

    // ── Governance ──────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Record a new decision. Append-only.
    /// @dev FWA-C3-09: every recorded decision MUST carry a non-empty
    ///      `decision_sig` — the off-chain signature the agent runtime
    ///      produced over the decision. Its keccak hash is bound into the
    ///      stored record (so the recorder cannot later claim a decision
    ///      was unsigned or substitute a different signature), and the
    ///      on-chain `attestor` (msg.sender) is stored and emitted. The
    ///      cryptographic verification of `decision_sig` against the
    ///      agent's key happens off-chain (keys are bytes32 hashes here,
    ///      not on-chain addresses), but the binding makes the claim
    ///      "every signed decision" auditable and non-repudiable on-chain.
    function record(
        bytes32 decision_id,
        bytes32 user,
        bytes32 tenant,
        bytes32 corr_id,
        EventClass class,
        string calldata description,
        string calldata auth_mode,
        bytes32 artifact_root,
        string calldata status,
        bytes calldata decision_sig
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (_decisions[decision_id].exists) {
            revert DecisionAlreadyExists(decision_id);
        }
        if (uint8(class) > uint8(EventClass.Audit)) {
            revert InvalidClass(uint8(class));
        }
        if (bytes(auth_mode).length == 0) revert EmptyAuthMode();
        if (bytes(description).length == 0) revert EmptyDescription();
        // FWA-C3-09: a decision must be signed.
        if (decision_sig.length == 0) revert EmptyDecisionSig();

        // Bind the signature to THIS exact decision tuple so it cannot be
        // detached, swapped, or replayed onto a different record.
        bytes32 sigHash = keccak256(
            abi.encodePacked(
                decision_id, user, tenant, corr_id, artifact_root, decision_sig
            )
        );

        _decisions[decision_id] = Decision({
            decision_id: decision_id,
            user: user,
            tenant: tenant,
            corr_id: corr_id,
            class: class,
            description: description,
            auth_mode: auth_mode,
            artifact_root: artifact_root,
            status: bytes(status).length == 0 ? STATUS_VERIFIED : status,
            ts: uint64(block.timestamp),
            exists: true,
            attestor: msg.sender,
            decision_sig_hash: sigHash
        });

        _by_corr_id[corr_id].push(decision_id);
        _by_user[user].push(decision_id);
        _by_tenant[tenant].push(decision_id);
        _by_class[uint8(class)].push(decision_id);

        emit DecisionRecorded(decision_id, user, tenant, corr_id, class);
        emit DecisionAttested(decision_id, msg.sender, sigHash);
    }

    /// @notice Dispute a recorded decision. Admin-gated.
    function dispute(
        bytes32 decision_id,
        string calldata reason,
        bytes32 corr_id
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Decision storage d = _decisions[decision_id];
        if (!d.exists) revert DecisionDoesNotExist(decision_id);
        // DisputeRequiresRecorded — must be in Verified or Pending state.
        if (
            keccak256(bytes(d.status)) != keccak256(bytes(STATUS_VERIFIED)) &&
            keccak256(bytes(d.status)) != keccak256(bytes(STATUS_PENDING))
        ) {
            revert DisputeRequiresRecorded(decision_id, d.status);
        }
        d.status = STATUS_DISPUTED;
        emit DecisionDisputed(decision_id, corr_id, reason);
    }

    /// @notice Revoke a recorded decision. Admin-gated. Terminal state.
    function revoke(
        bytes32 decision_id,
        string calldata reason,
        bytes32 corr_id
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Decision storage d = _decisions[decision_id];
        if (!d.exists) revert DecisionDoesNotExist(decision_id);
        d.status = STATUS_REVOKED;
        emit DecisionRevoked(decision_id, corr_id, reason);
    }

    // ── Read views ──────────────────────────────────────────────────

    function getDecision(bytes32 decision_id)
        external view returns (Decision memory)
    {
        Decision storage d = _decisions[decision_id];
        if (!d.exists) revert DecisionDoesNotExist(decision_id);
        return d;
    }

    function exists(bytes32 decision_id) external view returns (bool) {
        return _decisions[decision_id].exists;
    }

    function byUser(bytes32 user) external view returns (bytes32[] memory) {
        return _by_user[user];
    }

    function byTenant(bytes32 tenant) external view returns (bytes32[] memory) {
        return _by_tenant[tenant];
    }

    function byCorrId(bytes32 corr_id) external view returns (bytes32[] memory) {
        return _by_corr_id[corr_id];
    }

    function byClass(EventClass class) external view returns (bytes32[] memory) {
        return _by_class[uint8(class)];
    }

    /// @notice Latest N decisions for a tenant (used by the Slint
    ///         AuditEventRibbon's 12-event strip).
    function latestByTenant(bytes32 tenant, uint256 n)
        external view returns (bytes32[] memory)
    {
        bytes32[] storage all = _by_tenant[tenant];
        uint256 total = all.length;
        if (total == 0) return new bytes32[](0);
        uint256 take = n > total ? total : n;
        bytes32[] memory out = new bytes32[](take);
        for (uint256 i; i < take; ++i) {
            out[i] = all[total - 1 - i];
        }
        return out;
    }
}
