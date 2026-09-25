// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

import {IInstitutionTreeV1} from "./interfaces/IInstitutionTreeV1.sol";

/// @title ComplianceRegistry
/// @notice On-chain home for the 9 compliance gates that gate every school
///         in a CMO's portfolio. Federal gates apply to every school;
///         state-specific gates apply only when the school's NCES state
///         matches. Each (school, gate) pair has a state machine that
///         transitions: NotApplicable / Untouched → Signed → {Expired ∪ Revoked}.
///
/// @dev    The 9 gates (matching the GUI's CmoCompliance panel — WP-E6.5):
///
///           Federal (apply to every school):
///             0. DPA   — Data Processing Agreement
///             1. FERPA — Family Educational Rights and Privacy Act
///             2. COPPA — Children's Online Privacy Protection Act
///             3. CIPA  — Children's Internet Protection Act (E-rate)
///
///           State-specific (apply only when school.state matches gate.state):
///             4. CA_AB1584    — California: AB 1584 + SOPIPA          (state idx 0)
///             5. NY_EDLAW2D   — New York: Education Law § 2-d         (state idx 1)
///             6. IL_SOPPA     — Illinois: SOPPA                       (state idx 2)
///             7. TX_TEC32_151 — Texas: TEC § 32.151                   (state idx 3)
///             8. CO_CRS22     — Colorado: C.R.S. § 22-16-104          (state idx 4)
///
///         Privacy property: only the SHA-256 hash of the Docusign envelope
///         ID is stored on-chain. The raw envelope ID lives in the school's
///         off-chain compliance_storage filesystem QSSP envelope and never
///         appears on-chain. An observer of `GateSigned` learns: a school
///         signed a gate, with this envelope-hash, expiring at this date.
///         They cannot fetch the envelope or learn the signers' identities.
///
///         Coupling to InstitutionTreeV1: the contract reads the school's
///         tree node to (a) verify the school is registered and active,
///         (b) authorize the school admin as the signer, and (c) determine
///         the school's state for state-specific gate applicability. The
///         tree address is set in the constructor and immutable thereafter.
///
///         CEI compliance: every state-mutating function follows
///         Checks-Effects-Interactions strictly. Checks first (auth +
///         state-validity), then storage writes, then events. No external
///         calls outside `view`/`pure` cross-contract reads to the tree.
///
///         Re-entrancy: not a concern because no `call`/`delegatecall`/
///         `transfer`/`send` to untrusted addresses. The only external
///         dependency is the tree, which is a known governance-controlled
///         contract whose `view` functions cannot re-enter.
///
///         Two-step governance: matches InstitutionTreeV1's pattern.
///         Governance can revoke any gate-signing record; institutional
///         admins can self-record signing but cannot revoke (prevents
///         self-erasure under audit pressure).
contract ComplianceRegistry {
    // ──────────────────────────────────────────────────────────────
    // Types
    // ──────────────────────────────────────────────────────────────

    /// @notice Per-(school × gate) lifecycle state.
    /// @dev `Untouched` is the implicit default returned for a never-recorded
    ///      slot. We DO NOT distinguish `NotApplicable` from `Untouched` in
    ///      storage — applicability is computed from the tree's school state
    ///      at read time. Storing it would be redundant and could go stale
    ///      if the school's state were ever amended. The read functions
    ///      surface `NotApplicable` for state-mismatched gates.
    enum Status {
        Untouched,    // never recorded (default zero state)
        Signed,       // currently signed and within validity window
        Expired,      // past expiresAt; cleared by anyone calling expireGate
        Revoked,      // revoked by governance — terminal until next sign
        NotApplicable // synthetic (read-only) — gate doesn't apply to this school's state
    }

    struct Record {
        Status status;          // packed alongside u64s for storage efficiency
        bytes32 envelopeIdHash; // SHA-256 of Docusign envelope ID
        address signer;         // who signed (typically school admin)
        uint64 signedAt;        // block.timestamp at signing
        uint64 expiresAt;       // hard expiry deadline
    }

    // ──────────────────────────────────────────────────────────────
    // Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Total gate count. Every school's matrix has exactly this
    ///         many cells (some rendered NotApplicable based on state).
    uint8 public constant GATE_COUNT = 9;

    /// @notice First gate index that is state-specific. Gates [0, 4) are
    ///         federal (apply to every school); gates [4, 9) are state-
    ///         specific. Maps to the planset's gate ordering.
    uint8 public constant FIRST_STATE_GATE = 4;

    /// @notice Maximum signing-validity window: 365 days from `signedAt`.
    ///         Signing with `expiresAt > signedAt + MAX_VALIDITY_WINDOW`
    ///         reverts. Most compliance regimes require annual re-signing,
    ///         so this is the natural cap. Operators can sign for shorter
    ///         windows; the contract just enforces the upper bound.
    uint64 public constant MAX_VALIDITY_WINDOW = 365 days;

    // ──────────────────────────────────────────────────────────────
    // Immutables
    // ──────────────────────────────────────────────────────────────

    /// @notice The institution-tree this registry is coupled to. Set once
    ///         at deploy; never changes. Migrating to a new tree requires
    ///         deploying a new ComplianceRegistry.
    IInstitutionTreeV1 public immutable tree;

    // ──────────────────────────────────────────────────────────────
    // Storage
    // ──────────────────────────────────────────────────────────────

    address public governance;
    address public pendingGovernance;

    /// @dev schoolIdHash => gateIdx => Record
    mapping(bytes32 => mapping(uint8 => Record)) private _records;

    /// @notice Total signing events ever recorded (monotonic). Useful for
    ///         off-chain analytics and audit traces.
    uint256 public totalSignings;

    /// @notice Total revocation events ever recorded (monotonic).
    uint256 public totalRevocations;

    // ──────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────

    error NotGovernance();
    error NotSchoolAdmin();
    error InvalidGovernanceTransfer();
    error InvalidGate(uint8 gateIdx);
    error InvalidSchool(bytes32 schoolIdHash);
    error SchoolRevoked(bytes32 schoolIdHash);
    error GateNotApplicable(bytes32 schoolIdHash, uint8 gateIdx);
    error InvalidEnvelopeHash();
    error InvalidExpiry();
    error ValidityWindowTooLong();
    error CannotRecordSigned(Status currentStatus);
    error CannotExpire(Status currentStatus);
    error NotYetExpired(uint64 expiresAt, uint64 nowTs);
    error CannotRevoke(Status currentStatus);

    // ──────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────

    event GateSigned(
        bytes32 indexed schoolIdHash,
        uint8 indexed gateIdx,
        address indexed signer,
        bytes32 envelopeIdHash,
        uint64 signedAt,
        uint64 expiresAt
    );
    event GateExpired(bytes32 indexed schoolIdHash, uint8 indexed gateIdx, uint64 at);
    event GateRevoked(
        bytes32 indexed schoolIdHash,
        uint8 indexed gateIdx,
        address indexed by,
        bytes32 reasonHash,
        uint64 at
    );
    event GovernanceTransferProposed(address indexed from, address indexed to);
    event GovernanceTransferAccepted(address indexed from, address indexed to);
    event GovernanceTransferCancelled(address indexed by);

    // ──────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(address _governance, address _tree) {
        if (_governance == address(0)) revert InvalidGovernanceTransfer();
        if (_tree == address(0)) revert InvalidSchool(bytes32(0));
        governance = InitialAdmin.check(_governance); // PBA-L2-002: never the CREATE2 factory
        tree = IInstitutionTreeV1(_tree);
    }

    // ──────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    // Governance transfer (two-step) — mirrors InstitutionTreeV1
    // ──────────────────────────────────────────────────────────────

    function transferGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert InvalidGovernanceTransfer();
        pendingGovernance = newGovernance;
        emit GovernanceTransferProposed(governance, newGovernance);
    }

    function acceptGovernance() external {
        if (msg.sender != pendingGovernance || pendingGovernance == address(0)) {
            revert InvalidGovernanceTransfer();
        }
        address oldGov = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferAccepted(oldGov, governance);
    }

    function cancelGovernanceTransfer() external onlyGovernance {
        pendingGovernance = address(0);
        emit GovernanceTransferCancelled(msg.sender);
    }

    // ──────────────────────────────────────────────────────────────
    // Mutations
    // ──────────────────────────────────────────────────────────────

    /// @notice Record that a school has signed a compliance gate.
    /// @dev    Authorization: only the school's `admin` (per the tree). The
    ///         school must be registered AND not revoked. The gate must be
    ///         applicable (federal, OR state matches). Validity window
    ///         capped at MAX_VALIDITY_WINDOW.
    ///
    ///         Permitted prior states: Untouched, Expired, Revoked. A
    ///         currently-Signed gate cannot be re-signed without first
    ///         expiring or being revoked — prevents accidental overwrite
    ///         of a current-signed envelope's metadata.
    /// @param schoolIdHash    Pseudonymous school hash from InstitutionTreeV1.
    /// @param gateIdx         0..8 — which gate is being signed.
    /// @param envelopeIdHash  SHA-256 of the Docusign envelope ID. Reverts on zero.
    /// @param expiresAt       Hard expiry deadline. Must be in the future
    ///                        and within MAX_VALIDITY_WINDOW from now.
    function recordSigned(
        bytes32 schoolIdHash,
        uint8 gateIdx,
        bytes32 envelopeIdHash,
        uint64 expiresAt
    ) external {
        // ── Checks ──
        if (gateIdx >= GATE_COUNT) revert InvalidGate(gateIdx);
        if (envelopeIdHash == bytes32(0)) revert InvalidEnvelopeHash();

        IInstitutionTreeV1.InstitutionNode memory node = tree.getNode(schoolIdHash);
        if (node.level != 3) revert InvalidSchool(schoolIdHash);
        if (node.revoked) revert SchoolRevoked(schoolIdHash);
        if (msg.sender != node.admin) revert NotSchoolAdmin();
        if (!_isApplicable(gateIdx, node.state)) revert GateNotApplicable(schoolIdHash, gateIdx);

        uint64 nowTs = uint64(block.timestamp);
        if (expiresAt <= nowTs) revert InvalidExpiry();
        if (expiresAt - nowTs > MAX_VALIDITY_WINDOW) revert ValidityWindowTooLong();

        Status prior = _records[schoolIdHash][gateIdx].status;
        if (prior == Status.Signed) revert CannotRecordSigned(prior);

        // ── Effects ──
        _records[schoolIdHash][gateIdx] = Record({
            status: Status.Signed,
            envelopeIdHash: envelopeIdHash,
            signer: msg.sender,
            signedAt: nowTs,
            expiresAt: expiresAt
        });
        unchecked { totalSignings += 1; }

        // ── Interactions ──
        emit GateSigned(schoolIdHash, gateIdx, msg.sender, envelopeIdHash, nowTs, expiresAt);
    }

    /// @notice Mark a Signed gate as Expired once `block.timestamp > expiresAt`.
    /// @dev    Permissionless — any caller can sweep. This is a keeper-style
    ///         function: anyone can call to clean up state. The economic
    ///         incentive is implicit (cleaner matrix renders for downstream
    ///         readers), no on-chain reward.
    function expireGate(bytes32 schoolIdHash, uint8 gateIdx) external {
        // ── Checks ──
        if (gateIdx >= GATE_COUNT) revert InvalidGate(gateIdx);

        Record storage rec = _records[schoolIdHash][gateIdx];
        if (rec.status != Status.Signed) revert CannotExpire(rec.status);

        uint64 nowTs = uint64(block.timestamp);
        if (nowTs <= rec.expiresAt) revert NotYetExpired(rec.expiresAt, nowTs);

        // ── Effects ──
        rec.status = Status.Expired;

        // ── Interactions ──
        emit GateExpired(schoolIdHash, gateIdx, nowTs);
    }

    /// @notice Revoke a (school, gate) pair. Governance-only — institutional
    ///         admins cannot self-revoke (audit-resilience property: a
    ///         school cannot erase its own non-compliance under pressure).
    /// @param schoolIdHash The school whose gate is being revoked.
    /// @param gateIdx      The gate index being revoked.
    /// @param reasonHash   Off-chain reason (e.g., audit finding) hash.
    ///                     Stored only in the event for traceability.
    function revokeGate(
        bytes32 schoolIdHash,
        uint8 gateIdx,
        bytes32 reasonHash
    ) external onlyGovernance {
        // ── Checks ──
        if (gateIdx >= GATE_COUNT) revert InvalidGate(gateIdx);

        Record storage rec = _records[schoolIdHash][gateIdx];
        // Cannot revoke an Untouched record — there's nothing to revoke.
        // Cannot re-revoke an already-Revoked record.
        if (rec.status == Status.Untouched || rec.status == Status.Revoked) {
            revert CannotRevoke(rec.status);
        }

        // ── Effects ──
        rec.status = Status.Revoked;
        unchecked { totalRevocations += 1; }

        // ── Interactions ──
        emit GateRevoked(schoolIdHash, gateIdx, msg.sender, reasonHash, uint64(block.timestamp));
    }

    // ──────────────────────────────────────────────────────────────
    // Reads
    // ──────────────────────────────────────────────────────────────

    /// @notice Fetch the raw record for a (school, gate) pair. Returns the
    ///         zero-Record struct (Status.Untouched) if never recorded.
    /// @dev    Does NOT surface NotApplicable — use `getEffectiveStatus` for
    ///         the applicability-aware view. This raw read is what off-chain
    ///         keepers (e.g., the expireGate sweeper) need.
    function getRecord(bytes32 schoolIdHash, uint8 gateIdx) external view returns (Record memory) {
        if (gateIdx >= GATE_COUNT) revert InvalidGate(gateIdx);
        return _records[schoolIdHash][gateIdx];
    }

    /// @notice Returns the effective status for a (school, gate) pair,
    ///         accounting for applicability based on the school's tree state.
    ///         Returns NotApplicable for state-specific gates whose state
    ///         doesn't match the school. Reverts on unknown schools.
    function getEffectiveStatus(bytes32 schoolIdHash, uint8 gateIdx) external view returns (Status) {
        if (gateIdx >= GATE_COUNT) revert InvalidGate(gateIdx);
        IInstitutionTreeV1.InstitutionNode memory node = tree.getNode(schoolIdHash);
        if (node.level != 3) revert InvalidSchool(schoolIdHash);
        if (!_isApplicable(gateIdx, node.state)) return Status.NotApplicable;
        return _records[schoolIdHash][gateIdx].status;
    }

    /// @notice Returns the full 9-cell matrix for a school. State-specific
    ///         gates that don't match the school's state are returned with
    ///         status = NotApplicable and zero metadata.
    /// @dev    The GUI's CmoCompliance panel calls this once per school per
    ///         render. The fixed-size return array keeps gas predictable.
    function getSchoolMatrix(bytes32 schoolIdHash) external view returns (Record[9] memory matrix) {
        IInstitutionTreeV1.InstitutionNode memory node = tree.getNode(schoolIdHash);
        if (node.level != 3) revert InvalidSchool(schoolIdHash);
        for (uint8 i = 0; i < GATE_COUNT; i++) {
            if (!_isApplicable(i, node.state)) {
                matrix[i] = Record({
                    status: Status.NotApplicable,
                    envelopeIdHash: bytes32(0),
                    signer: address(0),
                    signedAt: 0,
                    expiresAt: 0
                });
            } else {
                matrix[i] = _records[schoolIdHash][i];
            }
        }
    }

    /// @notice True iff the gate is currently Signed AND not past its expiry.
    ///         Useful as a one-call gate predicate by other contracts that
    ///         need to short-circuit on compliance status.
    function isCompliant(bytes32 schoolIdHash, uint8 gateIdx) external view returns (bool) {
        if (gateIdx >= GATE_COUNT) return false;
        IInstitutionTreeV1.InstitutionNode memory node = tree.getNode(schoolIdHash);
        if (node.level != 3 || node.revoked) return false;
        if (!_isApplicable(gateIdx, node.state)) return false; // NotApplicable is not "compliant"
        Record memory rec = _records[schoolIdHash][gateIdx];
        if (rec.status != Status.Signed) return false;
        return block.timestamp <= rec.expiresAt;
    }

    // ──────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────

    /// @dev Federal gates [0..4) apply to every school. State-specific
    ///      gates [4..9) apply iff `gateIdx - FIRST_STATE_GATE == schoolState`.
    ///      Mapping (planset / gate enum):
    ///        gate 4 = CA → state idx 0
    ///        gate 5 = NY → state idx 1
    ///        gate 6 = IL → state idx 2
    ///        gate 7 = TX → state idx 3
    ///        gate 8 = CO → state idx 4
    function _isApplicable(uint8 gateIdx, uint8 schoolState) internal pure returns (bool) {
        if (gateIdx < FIRST_STATE_GATE) return true;
        // State-specific: gate's expected state = gateIdx - FIRST_STATE_GATE
        return uint8(gateIdx - FIRST_STATE_GATE) == schoolState;
    }
}
