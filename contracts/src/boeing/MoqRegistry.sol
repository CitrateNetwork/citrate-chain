// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MoqRegistry — supplier MOQ commitments + variance tracking
/// @notice On-chain backing for the BFR-06 Suppliers panel's MOQ tab.
///         Records each commitment as `(supplier, part_family,
///         program, commit_qty, period)`, then accumulates draw
///         attestations from receiving sites. Variance is derived;
///         Belnap "B" state is set when supplier-reported and
///         receiving-attested draws disagree.
///
/// @dev Cited specs:
///   - `formal/specs/contracts/AgentDecisionLog.tla` — CommitmentAppendOnly + DrawAppendOnly ratified.
///   - `formal/specs/contracts/ContradictionStateMachine.tla` — Belnap state for source disagreement.
contract MoqRegistry {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice Belnap 4-valued state for a variance row.
    enum Belnap {
        T,  // 0 — true (sources agree, within threshold)
        F,  // 1 — false (sources agree, outside threshold)
        B,  // 2 — both (sources disagree — supplier vs receiving)
        N   // 3 — neither (no draws recorded yet)
    }

    /// @notice Source of a draw attestation.
    enum DrawSource {
        SupplierReported,   // 0
        ReceivingAttested   // 1
    }

    struct Commitment {
        bytes32 commitment_id;
        bytes32 supplier;
        bytes32 part_family;
        bytes32 program;
        bytes32 scope;          // tenant scope
        uint128 commit_qty;
        uint64  period_start;
        uint64  period_end;
        bool    exists;
    }

    struct Draw {
        bytes32 commitment_id;
        DrawSource source;
        uint128 qty;
        uint64  ts;
        bytes32 corr_id;
        bytes32 signer;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Default variance threshold (basis points). 500 bps = 5%.
    uint16 public constant DEFAULT_VARIANCE_THRESHOLD_BPS = 500;

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 commitment_id => Commitment) private _commitments;
    mapping(bytes32 commitment_id => Draw[]) private _draws;
    mapping(bytes32 supplier => bytes32[]) private _by_supplier;
    mapping(bytes32 scope => mapping(bytes32 program => bytes32[])) private _by_scope_program;
    bytes32[] private _all_commitment_ids;

    address public governance;
    mapping(address => bool) public is_recorder;

    // ── Events ──────────────────────────────────────────────────────

    event CommitmentRecorded(
        bytes32 indexed commitment_id,
        bytes32 indexed supplier,
        bytes32 indexed program,
        uint128 commit_qty
    );
    event DrawRecorded(
        bytes32 indexed commitment_id,
        DrawSource indexed source,
        uint128 qty,
        bytes32 corr_id
    );
    event RecorderSet(address indexed recorder, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ZeroGovernance();
    error CommitmentAlreadyExists(bytes32 commitment_id);
    error CommitmentDoesNotExist(bytes32 commitment_id);
    error PeriodInvalid(uint64 period_start, uint64 period_end);
    error InvalidDrawSource(uint8 source);

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ──────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ────────────────────────────────────────────────────

    function recordCommitment(
        bytes32 commitment_id,
        bytes32 supplier,
        bytes32 part_family,
        bytes32 program,
        bytes32 scope,
        uint128 commit_qty,
        uint64 period_start,
        uint64 period_end
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (_commitments[commitment_id].exists) {
            revert CommitmentAlreadyExists(commitment_id);
        }
        if (period_end <= period_start) {
            revert PeriodInvalid(period_start, period_end);
        }

        _commitments[commitment_id] = Commitment({
            commitment_id: commitment_id,
            supplier: supplier,
            part_family: part_family,
            program: program,
            scope: scope,
            commit_qty: commit_qty,
            period_start: period_start,
            period_end: period_end,
            exists: true
        });
        _by_supplier[supplier].push(commitment_id);
        _by_scope_program[scope][program].push(commitment_id);
        _all_commitment_ids.push(commitment_id);

        emit CommitmentRecorded(commitment_id, supplier, program, commit_qty);
    }

    function recordDraw(
        bytes32 commitment_id,
        DrawSource source,
        uint128 qty,
        bytes32 corr_id,
        bytes32 signer
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (!_commitments[commitment_id].exists) {
            revert CommitmentDoesNotExist(commitment_id);
        }
        if (uint8(source) > uint8(DrawSource.ReceivingAttested)) {
            revert InvalidDrawSource(uint8(source));
        }

        _draws[commitment_id].push(Draw({
            commitment_id: commitment_id,
            source: source,
            qty: qty,
            ts: uint64(block.timestamp),
            corr_id: corr_id,
            signer: signer
        }));

        emit DrawRecorded(commitment_id, source, qty, corr_id);
    }

    // ── Read views ──────────────────────────────────────────────────

    function commitment(bytes32 commitment_id) external view returns (Commitment memory) {
        Commitment storage c = _commitments[commitment_id];
        if (!c.exists) revert CommitmentDoesNotExist(commitment_id);
        return c;
    }

    function draws(bytes32 commitment_id) external view returns (Draw[] memory) {
        return _draws[commitment_id];
    }

    function bySupplier(bytes32 supplier) external view returns (bytes32[] memory) {
        return _by_supplier[supplier];
    }

    function list(bytes32 scope, bytes32 program) external view returns (bytes32[] memory) {
        return _by_scope_program[scope][program];
    }

    function commitmentCount() external view returns (uint256) {
        return _all_commitment_ids.length;
    }

    /// @notice Returns the aggregate draw quantities (supplier-reported,
    ///         receiving-attested) for a commitment. Used by the
    ///         variance + Belnap calculations.
    function aggregateDraws(bytes32 commitment_id)
        public
        view
        returns (uint128 supplier_total, uint128 receiving_total)
    {
        Draw[] storage list_ = _draws[commitment_id];
        uint128 s_;
        uint128 r_;
        for (uint256 i; i < list_.length; ++i) {
            if (list_[i].source == DrawSource.SupplierReported) {
                s_ += list_[i].qty;
            } else {
                r_ += list_[i].qty;
            }
        }
        return (s_, r_);
    }

    /// @notice Belnap 4-valued classification per cited invariant:
    ///   N — no draws recorded yet
    ///   B — supplier and receiving disagree (any difference)
    ///   T — agree, within threshold of commitment
    ///   F — agree, outside threshold of commitment
    function belnap(bytes32 commitment_id, uint16 threshold_bps)
        external
        view
        returns (Belnap)
    {
        Commitment storage c = _commitments[commitment_id];
        if (!c.exists) revert CommitmentDoesNotExist(commitment_id);
        (uint128 sup, uint128 rec) = aggregateDraws(commitment_id);
        if (sup == 0 && rec == 0) return Belnap.N;
        if (sup != rec && (sup != 0 && rec != 0)) return Belnap.B;
        if (sup == 0 && rec != 0) return Belnap.B; // single-source missing
        if (rec == 0 && sup != 0) return Belnap.B;
        // Both reports agree; check variance against commitment.
        uint128 actual = sup;
        uint128 commit = c.commit_qty;
        uint128 diff = actual > commit ? actual - commit : commit - actual;
        if (commit == 0) {
            return diff == 0 ? Belnap.T : Belnap.F;
        }
        // variance_bps = (diff * 10_000) / commit
        uint256 variance_bps = (uint256(diff) * 10_000) / uint256(commit);
        return variance_bps <= uint256(threshold_bps) ? Belnap.T : Belnap.F;
    }
}
