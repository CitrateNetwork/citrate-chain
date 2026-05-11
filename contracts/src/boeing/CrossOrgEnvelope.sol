// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Minimal read interface for ClassificationRegistry.
///         Mirrors `rbac/ClassificationRegistry.sol::clearanceOrdinal`.
///         0=Public, 1=Proprietary, 2=CUI, 3=ITAR.
interface IClassificationOracle {
    function clearanceOrdinal(bytes32 user) external view returns (uint8);
}

/// @title CrossOrgEnvelope — Multi-org envelope flow for BFR-14.
/// @notice Per planset 09_INTER_ORG_TRANSFER.md § Architecture +
///         InterOrgEnvelopeChain.tla. Generalizes the single-org
///         envelope to span multiple tenant roots (Boeing → Tier-1 →
///         DOD → federal sponsor) with per-org signature thresholds.
///
/// @dev 7-state lifecycle (mirrors InterOrgEnvelopeChain.tla):
///        0 = NotStarted (sentinel)
///        1 = Drafted    (operator drafted; sig collection open)
///        2 = Signing    (≥1 org has reached its threshold)
///        3 = Signed     (all orgs have reached their thresholds)
///        4 = Delivered  (artifact handed to target org)
///        5 = Accepted   (target org accepted; co-anchored on chain)
///        6 = Rejected   (any org rejected; terminal)
///        7 = Closed     (terminal-positive after Accepted)
///
/// @dev Allowed transitions (per InterOrgEnvelopeChain.tla):
///        Drafted    → Signing | Rejected | Withdrawn
///        Signing    → Signed | Rejected
///        Signed     → Delivered | Rejected
///        Delivered  → Accepted | Rejected
///        Accepted   → Closed | Rejected
///
/// @dev Invariants enforced contract-side:
///        - signed_state ⇔ ∀ org: signed_count[org] ≥ threshold[org]
///        - rejected_by_any_org ⇒ terminal (no further transitions)
///        - expired ⇒ no further signing
///        - threshold > 0 per org
///
/// Source: .agentile/sprints/active/2026-05-11-bfr-14-inter-org-transfer/SPRINT.md D-1
contract CrossOrgEnvelope {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AlreadyDrafted(bytes32 envelope_id);
    error NotInState(bytes32 envelope_id, uint8 expected, uint8 actual);
    error UnknownOrg(bytes32 envelope_id, bytes32 org_root);
    error NotRequiredSigner(bytes32 envelope_id, bytes32 org_root, bytes32 signer);
    error AlreadySigned(bytes32 envelope_id, bytes32 signer);
    error ThresholdNotMet();
    error EmptyOrgRoots();
    error MismatchedThresholdLength();
    error ZeroThreshold();
    error Expired(uint256 expires_at, uint256 block_number);
    /// @notice Raised when a required signer's max clearance is below
    ///         the artifact's classification level. Enforced when
    ///         `classification_oracle` is set and `artifact_max_class > 0`.
    error InsufficientClearance(bytes32 signer, uint8 required, uint8 actual);

    // ── Types ──────────────────────────────────────────────────────────

    struct CrossOrgEnvelopeRecord {
        bytes32 envelope_id;
        bytes32 artifact_root;
        bytes32 artifact_cid;       // IPFS CID
        uint8   state;
        uint256 drafted_at_block;
        uint256 expires_at_block;
        uint256 delivered_at_block;
        uint256 accepted_at_block;
        bytes32 rejected_by_org;    // bytes32(0) until rejected
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;
    mapping(address => bool) public is_recorder;

    /// @notice Optional classification oracle (typically the deployed
    ///         `ClassificationRegistry`). When set, `draft(...)` reads
    ///         each required signer's clearance and enforces
    ///         `clearanceOrdinal(signer) >= artifact_max_class`.
    ///         Zero address disables the gate (pre-migration default).
    address public classification_oracle;

    /// @notice envelope_id → recorded artifact classification level
    ///         that was enforced at draft time (0..3). Surfaced for
    ///         downstream audit + replay.
    mapping(bytes32 => uint8) public artifactClassOf;

    mapping(bytes32 => CrossOrgEnvelopeRecord) public envelopes;
    mapping(bytes32 => bool) public exists;

    /// @notice envelope_id → org_roots[]
    mapping(bytes32 => bytes32[]) public orgRootsOf;

    /// @notice envelope_id → org_root → threshold
    mapping(bytes32 => mapping(bytes32 => uint8)) public thresholdOf;

    /// @notice envelope_id → org_root → required signers
    mapping(bytes32 => mapping(bytes32 => bytes32[])) public requiredSignersOf;

    /// @notice envelope_id → org_root → set membership for required signers
    mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => bool))) public isRequiredSigner;

    /// @notice envelope_id → org_root → signed count
    mapping(bytes32 => mapping(bytes32 => uint8)) public signedCountOf;

    /// @notice envelope_id → signer → has signed (any org)
    mapping(bytes32 => mapping(bytes32 => bool)) public hasSigned;

    /// @notice scope → envelope_ids (append-only).
    mapping(bytes32 => bytes32[]) public envelopesByScope;

    /// @notice All envelope_ids drafted.
    bytes32[] public allEnvelopeIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Drafted(
        bytes32 indexed envelope_id,
        bytes32 indexed artifact_root,
        bytes32 artifact_cid,
        uint256 expires_at_block
    );
    event Signed(
        bytes32 indexed envelope_id,
        bytes32 indexed org_root,
        bytes32 signer,
        uint8 org_signed_count
    );
    event StateChanged(bytes32 indexed envelope_id, uint8 from_state, uint8 to_state);
    event Rejected(bytes32 indexed envelope_id, bytes32 indexed org_root, string reason);
    event ClassificationOracleSet(address indexed oracle);

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    /// @notice Governance-only. Set or clear the classification oracle.
    ///         Pass `address(0)` to disable the gate.
    function setClassificationOracle(address oracle) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        classification_oracle = oracle;
        emit ClassificationOracleSet(oracle);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Draft a new cross-org envelope.
    /// @param artifact_max_class Classification level of the artifact
    ///        being transferred (0=Public..3=ITAR). When the
    ///        `classification_oracle` is set and `artifact_max_class > 0`,
    ///        every required signer in every org must have
    ///        `clearanceOrdinal(signer) >= artifact_max_class`, or the
    ///        call reverts with `InsufficientClearance`. Pass `0` (and
    ///        leave the oracle unset) to disable the gate.
    function draft(
        bytes32 envelope_id,
        bytes32 artifact_root,
        bytes32 artifact_cid,
        bytes32[] calldata org_roots,
        uint8[] calldata thresholds,
        bytes32[][] calldata signers_per_org,
        uint256 expires_at_block,
        bytes32 scope,
        uint8 artifact_max_class
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (exists[envelope_id]) revert AlreadyDrafted(envelope_id);
        uint256 n = org_roots.length;
        if (n == 0) revert EmptyOrgRoots();
        if (thresholds.length != n || signers_per_org.length != n) {
            revert MismatchedThresholdLength();
        }

        envelopes[envelope_id] = CrossOrgEnvelopeRecord({
            envelope_id: envelope_id,
            artifact_root: artifact_root,
            artifact_cid: artifact_cid,
            state: 1, // Drafted
            drafted_at_block: block.number,
            expires_at_block: expires_at_block,
            delivered_at_block: 0,
            accepted_at_block: 0,
            rejected_by_org: bytes32(0)
        });
        exists[envelope_id] = true;
        artifactClassOf[envelope_id] = artifact_max_class;
        envelopesByScope[scope].push(envelope_id);
        allEnvelopeIds.push(envelope_id);

        // The gate is active only when both (a) governance has wired
        // an oracle and (b) the artifact has a non-zero classification.
        // Reading the oracle once before the loop avoids repeated
        // SLOAD of the storage variable.
        address oracle = classification_oracle;
        bool enforceGate = oracle != address(0) && artifact_max_class > 0;

        for (uint256 i = 0; i < n; i++) {
            if (thresholds[i] == 0) revert ZeroThreshold();
            bytes32 org = org_roots[i];
            orgRootsOf[envelope_id].push(org);
            thresholdOf[envelope_id][org] = thresholds[i];
            for (uint256 j = 0; j < signers_per_org[i].length; j++) {
                bytes32 s = signers_per_org[i][j];
                if (enforceGate) {
                    uint8 ord = IClassificationOracle(oracle).clearanceOrdinal(s);
                    if (ord < artifact_max_class) {
                        revert InsufficientClearance(s, artifact_max_class, ord);
                    }
                }
                requiredSignersOf[envelope_id][org].push(s);
                isRequiredSigner[envelope_id][org][s] = true;
            }
        }

        emit Drafted(envelope_id, artifact_root, artifact_cid, expires_at_block);
    }

    /// @notice Sign on behalf of an org. Increments `signedCountOf`.
    function sign(bytes32 envelope_id, bytes32 org_root, bytes32 signer) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        CrossOrgEnvelopeRecord storage e = envelopes[envelope_id];
        if (e.state != 1 && e.state != 2) revert NotInState(envelope_id, 1, e.state);
        if (e.expires_at_block != 0 && block.number > e.expires_at_block) {
            revert Expired(e.expires_at_block, block.number);
        }
        if (thresholdOf[envelope_id][org_root] == 0) revert UnknownOrg(envelope_id, org_root);
        if (!isRequiredSigner[envelope_id][org_root][signer]) {
            revert NotRequiredSigner(envelope_id, org_root, signer);
        }
        if (hasSigned[envelope_id][signer]) revert AlreadySigned(envelope_id, signer);

        hasSigned[envelope_id][signer] = true;
        signedCountOf[envelope_id][org_root] = signedCountOf[envelope_id][org_root] + 1;
        emit Signed(envelope_id, org_root, signer, signedCountOf[envelope_id][org_root]);

        uint8 prev = e.state;
        if (prev == 1) {
            e.state = 2; // Drafted → Signing
            emit StateChanged(envelope_id, prev, 2);
        }
        if (_allOrgsMet(envelope_id)) {
            uint8 was = e.state;
            e.state = 3;
            emit StateChanged(envelope_id, was, 3);
        }
    }

    /// @notice Mark Signed → Delivered. Permissionless (any caller).
    function markDelivered(bytes32 envelope_id) external {
        CrossOrgEnvelopeRecord storage e = envelopes[envelope_id];
        if (e.state != 3) revert NotInState(envelope_id, 3, e.state);
        e.state = 4;
        e.delivered_at_block = block.number;
        emit StateChanged(envelope_id, 3, 4);
    }

    /// @notice Mark Delivered → Accepted. Permissionless.
    function accept(bytes32 envelope_id) external {
        CrossOrgEnvelopeRecord storage e = envelopes[envelope_id];
        if (e.state != 4) revert NotInState(envelope_id, 4, e.state);
        e.state = 5;
        e.accepted_at_block = block.number;
        emit StateChanged(envelope_id, 4, 5);
    }

    /// @notice Close an Accepted envelope. Terminal-positive.
    function close(bytes32 envelope_id) external {
        CrossOrgEnvelopeRecord storage e = envelopes[envelope_id];
        if (e.state != 5) revert NotInState(envelope_id, 5, e.state);
        e.state = 7;
        emit StateChanged(envelope_id, 5, 7);
    }

    /// @notice Reject from any org. Terminal. Requires recorder.
    function reject(
        bytes32 envelope_id,
        bytes32 org_root,
        string calldata reason
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        CrossOrgEnvelopeRecord storage e = envelopes[envelope_id];
        // Reject is allowed from any non-terminal state (1..5).
        if (e.state == 0 || e.state >= 6) revert NotInState(envelope_id, 1, e.state);
        if (thresholdOf[envelope_id][org_root] == 0) revert UnknownOrg(envelope_id, org_root);
        uint8 prev = e.state;
        e.state = 6;
        e.rejected_by_org = org_root;
        emit StateChanged(envelope_id, prev, 6);
        emit Rejected(envelope_id, org_root, reason);
    }

    // ── Internal ───────────────────────────────────────────────────────

    function _allOrgsMet(bytes32 envelope_id) internal view returns (bool) {
        bytes32[] storage orgs = orgRootsOf[envelope_id];
        for (uint256 i = 0; i < orgs.length; i++) {
            if (signedCountOf[envelope_id][orgs[i]] < thresholdOf[envelope_id][orgs[i]]) {
                return false;
            }
        }
        return true;
    }

    // ── Views ──────────────────────────────────────────────────────────

    function getEnvelope(bytes32 envelope_id)
        external
        view
        returns (CrossOrgEnvelopeRecord memory)
    {
        return envelopes[envelope_id];
    }

    function orgRoots(bytes32 envelope_id) external view returns (bytes32[] memory) {
        return orgRootsOf[envelope_id];
    }

    function requiredSigners(bytes32 envelope_id, bytes32 org_root)
        external
        view
        returns (bytes32[] memory)
    {
        return requiredSignersOf[envelope_id][org_root];
    }

    function isOrgThresholdMet(bytes32 envelope_id, bytes32 org_root)
        external
        view
        returns (bool)
    {
        return signedCountOf[envelope_id][org_root] >= thresholdOf[envelope_id][org_root];
    }

    function isAllOrgsMet(bytes32 envelope_id) external view returns (bool) {
        return _allOrgsMet(envelope_id);
    }

    function byScope(bytes32 scope) external view returns (bytes32[] memory) {
        return envelopesByScope[scope];
    }

    function allEnvelopes() external view returns (bytes32[] memory) {
        return allEnvelopeIds;
    }

    function envelopeCount() external view returns (uint256) {
        return allEnvelopeIds.length;
    }

    function countByScope(bytes32 scope) external view returns (uint256) {
        return envelopesByScope[scope].length;
    }
}
