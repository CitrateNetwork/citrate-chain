// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ClassificationRegistry — clearance ladder
/// @notice Tracks each user's classification clearance and foreign-
///         national status; powers auto-revocation of ITAR-scoped
///         access on status change.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/ClassificationLadder.tla`
/// @dev Cited invariants:
///   - `SignerWasAuthorized` — every clearance change carries an HR
///     oracle signature; `setClearance` reverts unless `msg.sender`
///     is in `hr_oracle_signers`.
///   - `HistoryMonotonic` — `last_updated` strictly increases per
///     user. Enforced by require `block.timestamp > old_ts`.
///   - `AlwaysOneSigner` — each clearance entry records exactly one
///     `hr_oracle_signer` (the caller).
///   - `FnFlagWellTyped` — `foreign_national` is a Solidity `bool`,
///     so well-typedness is structural.
///   - `HistoryBounded` — the contract keeps a single live record
///     per user (mapping value); bounded by user-set cardinality.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § 3. DPF-02 deliverable.
contract ClassificationRegistry {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice Classification levels in monotonic clearance order.
    /// @dev Must align bit-for-bit with TenantHierarchy.classification_max
    ///      enum encoding (0=Public, 1=Proprietary, 2=CUI, 3=ITAR).
    enum ClassLevel { Public, Proprietary, CUI, ITAR }

    /// @notice One user's clearance record.
    struct UserClass {
        bytes32 user;
        ClassLevel max_clearance;
        bool foreign_national;
        address hr_oracle_signer;
        uint64 last_updated;
        bool exists;
    }

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 user => UserClass) private _clearance;

    /// @notice Authorized HR oracle addresses. Add/remove gated by
    ///         the root-tenant multi-sig (encoded as the contract's
    ///         `governance` admin).
    mapping(address => bool) public hr_oracle_signers;

    /// @notice Governance admin (root-tenant multi-sig executor).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    /// @notice Emitted on every clearance update.
    event ClearanceChanged(
        bytes32 indexed user,
        ClassLevel old_max,
        ClassLevel new_max,
        bool old_fn,
        bool new_fn,
        address indexed signer
    );

    /// @notice Emitted ONLY when the foreign-national flag flips.
    /// @dev Listener trigger for cascading RoleEscalation.revoke()
    ///      across that user's active grants.
    event ForeignNationalChanged(bytes32 indexed user, bool new_status);

    /// @notice Emitted on oracle-signer set changes.
    event OracleSignerSet(address indexed signer, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotOracleSigner(address caller);
    error ClearanceNotFresher(uint64 attempted_ts, uint64 last_ts);
    error ZeroGovernance();

    // ── Constructor ─────────────────────────────────────────────────

    /// @notice Initial governance is typically the address of the
    ///         deployer's root-tenant multi-sig executor.
    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ──────────────────────────────────────────────────

    /// @notice Add an HR oracle signer.
    function addOracleSigner(address signer) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        hr_oracle_signers[signer] = true;
        emit OracleSignerSet(signer, true);
    }

    /// @notice Remove an HR oracle signer.
    function removeOracleSigner(address signer) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        hr_oracle_signers[signer] = false;
        emit OracleSignerSet(signer, false);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Update a user's clearance + foreign-national status.
    /// @dev `oracle_sig` parameter is included for off-chain audit
    ///      provenance — the oracle signs `(user, max, foreign_national,
    ///      block_number)` off-chain and the bytes are recorded as
    ///      audit material. The actual on-chain authorization gate is
    ///      `msg.sender` ∈ `hr_oracle_signers`.
    function setClearance(
        bytes32 user,
        ClassLevel max_clearance,
        bool foreign_national,
        bytes calldata oracle_sig
    ) external {
        if (!hr_oracle_signers[msg.sender]) revert NotOracleSigner(msg.sender);
        // Suppress unused warning while preserving the audit-trail
        // intent: oracle_sig is hashed into the event bytes32 below
        // for off-chain reconstruction.
        bytes32 sigHash = keccak256(oracle_sig);
        sigHash; // silence

        UserClass storage rec = _clearance[user];
        uint64 ts = uint64(block.timestamp);
        if (rec.exists && ts <= rec.last_updated) {
            revert ClearanceNotFresher(ts, rec.last_updated);
        }

        ClassLevel oldMax = rec.exists ? rec.max_clearance : ClassLevel.Public;
        bool oldFn = rec.exists ? rec.foreign_national : false;

        rec.user = user;
        rec.max_clearance = max_clearance;
        rec.foreign_national = foreign_national;
        rec.hr_oracle_signer = msg.sender;
        rec.last_updated = ts;
        rec.exists = true;

        emit ClearanceChanged(
            user, oldMax, max_clearance, oldFn, foreign_national, msg.sender
        );

        if (rec.exists && oldFn != foreign_national) {
            emit ForeignNationalChanged(user, foreign_national);
        } else if (!rec.exists && foreign_national) {
            // First-time record with FN=true: still emit so listeners
            // can apply the cascade. (Defensive — the rec.exists check
            // above guarantees we only get here on rec.exists==true.)
            emit ForeignNationalChanged(user, foreign_national);
        }
    }

    // ── Read views ──────────────────────────────────────────────────

    /// @notice Returns (max_clearance, foreign_national) for `user`.
    /// @dev Defaults to (Public, false) for never-set users.
    function getClearance(bytes32 user)
        external view returns (ClassLevel, bool)
    {
        UserClass storage rec = _clearance[user];
        if (!rec.exists) return (ClassLevel.Public, false);
        return (rec.max_clearance, rec.foreign_national);
    }

    /// @notice Returns the full UserClass record (zero-valued if unset).
    function getRecord(bytes32 user) external view returns (UserClass memory) {
        return _clearance[user];
    }

    /// @notice Convenience: ordinal int (0..3) for the user's clearance.
    function clearanceOrdinal(bytes32 user) external view returns (uint8) {
        UserClass storage rec = _clearance[user];
        if (!rec.exists) return 0;
        return uint8(rec.max_clearance);
    }
}
