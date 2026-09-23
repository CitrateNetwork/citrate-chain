// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title PartProvenanceRegistry — append-only part lineage + counterfeit verifier
/// @notice The on-chain backing store for the DPF-05 Provenance panel.
///         Records every lineage step a part takes from raw material
///         through manufacture, inspection, and acceptance. Enables:
///           1. `lineage(part_hash)` — render the chain root-to-leaf in
///              the Provenance panel's lineage tree
///           2. `searchTails(query_prefix, max_results)` — tail-number
///              autocomplete in the panel's search bar
///           3. `verifyChain(part_hash)` — the counterfeit verifier:
///              returns true iff every step is recorded, no step is
///              orphaned, and no step's subject has an open
///              contradiction in the ContradictionLedger
///           4. `byTail(tail_id)` — parts produced under a tail-number
///
/// @dev Formal specs (cited, not introduced):
///   - `formal/specs/contracts/AgentDecisionLog.tla` — every lineage
///     step IS an audit decision; this contract enforces the same
///     `AppendOnly` and `RecordedInList` invariants on its lineage
///     storage.
///   - `formal/specs/contracts/ContradictionStateMachine.tla` —
///     `verifyChain` consults `ContradictionLedger.hasOpenContradiction`
///     for each step's subject, ratifying
///     `OpenContradictionImpliesDoubt`.
///
/// @dev Cited invariants (per `tla_to_solidity.md`):
///   - **AppendOnly** — `recordStep` only appends; existing steps never
///     mutate. There is no setter; the storage layout is write-once
///     per `(step_id)` slot.
///   - **StepIndexedByPart** — every recorded step is retrievable via
///     `lineage(part_hash)` AND `_steps[step_id].exists == true`.
///   - **VerifyChainConsistent** — `verifyChain(part_hash)` returns
///     `(true, [step_id...])` iff:
///       (a) the chain has at least one step,
///       (b) every step exists,
///       (c) every step's `prev_step_id` is either zero (root) or
///           also exists for the same part,
///       (d) for every step, `ContradictionLedger.hasOpenContradiction(
///           step.artifact_root) == false`.
///   - **TailIndexConsistent** — `linkPartToTail(part, tail)` adds the
///     part to `_by_tail[tail]`, and once added it is retrievable.
///   - **SearchTailsBounded** — `searchTails` truncates the result at
///     `max_results` (caller-supplied; capped at `MAX_SEARCH_RESULTS`)
///     to keep gas O(N) over registered tails.
///
/// @dev DPF-05 deliverable. Composes
///      `citrate_v0.01.1/contracts/src/rbac/AgentDecisionRegistryV2.sol`
///      (each `LineageStep.decision_id` references a recorded decision)
///      and `ContradictionLedger.sol` (consulted by `verifyChain`).

interface IContradictionLedger {
    function hasOpenContradiction(bytes32 subject) external view returns (bool);
}

contract PartProvenanceRegistry {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice Top-level lineage step kind. Mirrors prototype's
    ///         `mock-data.jsx` step types one-for-one.
    enum StepKind {
        RawMaterial,    // 0 — raw stock pulled from inventory
        Manufacture,    // 1 — machined / formed
        Inspection,     // 2 — NDT / visual / dimensional inspection
        Assembly,       // 3 — installed into a sub-assembly
        Acceptance,     // 4 — DefensePrime acceptance signoff
        Rework,         // 5 — pulled and reworked
        Disposition     // 6 — final acceptance / scrap / quarantine
    }

    /// @notice One step in a part's lineage. Append-only.
    struct LineageStep {
        bytes32 step_id;
        bytes32 part_hash;
        bytes32 prev_step_id;     // zero for root
        bytes32 agent;            // user/agent who attested
        bytes32 corr_id;
        bytes32 decision_id;      // reference into AgentDecisionRegistryV2
        bytes32 artifact_root;    // subject for ContradictionLedger lookup
        StepKind kind;
        string  description;
        uint64  ts;
        bool    exists;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Hard ceiling on `searchTails` results to bound gas.
    /// @dev Per planset row 7: ~25 tails. Cap at 32 for headroom.
    uint8 public constant MAX_SEARCH_RESULTS = 32;

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 step_id => LineageStep) private _steps;

    /// @notice For each part, the chronologically-ordered list of step ids.
    mapping(bytes32 part_hash => bytes32[]) private _by_part;

    /// @notice Tails registered with the system (e.g., "N1234" hashed).
    bytes32[] private _tails;
    mapping(bytes32 tail_id => bool) public tail_exists;

    /// @notice Parts produced under each tail.
    mapping(bytes32 tail_id => bytes32[]) private _by_tail;

    /// @notice Reverse: a part may be associated with at most one tail
    ///         (per planset's mental model — a part traces to one airframe).
    mapping(bytes32 part_hash => bytes32) private _part_to_tail;

    /// @notice External contradiction-ledger consulted by `verifyChain`.
    IContradictionLedger public contradiction_ledger;

    /// @notice Authorized step recorders (typically agents + QA stations).
    mapping(address => bool) public is_recorder;

    /// @notice Admin authority (root-tenant multi-sig executor).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event StepRecorded(
        bytes32 indexed step_id,
        bytes32 indexed part_hash,
        bytes32 indexed corr_id,
        StepKind kind
    );
    event TailRegistered(bytes32 indexed tail_id);
    event PartLinkedToTail(bytes32 indexed part_hash, bytes32 indexed tail_id);
    event RecorderSet(address indexed recorder, bool authorized);
    event ContradictionLedgerSet(address indexed ledger);

    // ── Errors ──────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ZeroGovernance();
    error StepAlreadyExists(bytes32 step_id);
    error StepDoesNotExist(bytes32 step_id);
    error PartHashMismatch(bytes32 expected, bytes32 got);
    error PrevStepNotForSamePart(bytes32 prev, bytes32 part);
    error EmptyDescription();
    error InvalidStepKind(uint8 kind);
    error TailDoesNotExist(bytes32 tail_id);
    error PartAlreadyLinkedToTail(bytes32 part_hash, bytes32 existing_tail);
    error MaxResultsZero();
    error MaxResultsTooLarge(uint8 requested, uint8 cap);

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

    function setContradictionLedger(address ledger) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        contradiction_ledger = IContradictionLedger(ledger);
        emit ContradictionLedgerSet(ledger);
    }

    function registerTail(bytes32 tail_id) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        if (!tail_exists[tail_id]) {
            tail_exists[tail_id] = true;
            _tails.push(tail_id);
            emit TailRegistered(tail_id);
        }
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Record a new lineage step. Append-only.
    /// @dev Cited invariants: AppendOnly, StepIndexedByPart.
    function recordStep(
        bytes32 step_id,
        bytes32 part_hash,
        bytes32 prev_step_id,
        bytes32 agent,
        bytes32 corr_id,
        bytes32 decision_id,
        bytes32 artifact_root,
        StepKind kind,
        string calldata description
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (_steps[step_id].exists) revert StepAlreadyExists(step_id);
        if (uint8(kind) > uint8(StepKind.Disposition)) {
            revert InvalidStepKind(uint8(kind));
        }
        if (bytes(description).length == 0) revert EmptyDescription();

        // If prev_step_id is non-zero, it must be a recorded step for
        // the SAME part — otherwise the chain is malformed.
        if (prev_step_id != bytes32(0)) {
            LineageStep storage prev = _steps[prev_step_id];
            if (!prev.exists) revert StepDoesNotExist(prev_step_id);
            if (prev.part_hash != part_hash) {
                revert PrevStepNotForSamePart(prev_step_id, part_hash);
            }
        }

        _steps[step_id] = LineageStep({
            step_id: step_id,
            part_hash: part_hash,
            prev_step_id: prev_step_id,
            agent: agent,
            corr_id: corr_id,
            decision_id: decision_id,
            artifact_root: artifact_root,
            kind: kind,
            description: description,
            ts: uint64(block.timestamp),
            exists: true
        });

        _by_part[part_hash].push(step_id);

        emit StepRecorded(step_id, part_hash, corr_id, kind);
    }

    /// @notice Associate a part with a tail-number. One-shot — a part
    ///         can be linked to a tail only once.
    /// @dev Cited invariant: TailIndexConsistent.
    function linkPartToTail(bytes32 part_hash, bytes32 tail_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (!tail_exists[tail_id]) revert TailDoesNotExist(tail_id);
        bytes32 existing = _part_to_tail[part_hash];
        if (existing != bytes32(0)) {
            revert PartAlreadyLinkedToTail(part_hash, existing);
        }
        _part_to_tail[part_hash] = tail_id;
        _by_tail[tail_id].push(part_hash);
        emit PartLinkedToTail(part_hash, tail_id);
    }

    // ── Read views ──────────────────────────────────────────────────

    /// @notice Returns the chronologically-ordered list of step ids for
    ///         a part. The first entry is the root step (typically
    ///         RawMaterial); the last is the most recent.
    /// @dev Cited invariant: StepIndexedByPart.
    function lineage(bytes32 part_hash) external view returns (bytes32[] memory) {
        return _by_part[part_hash];
    }

    /// @notice Returns the full struct for a step.
    function getStep(bytes32 step_id) external view returns (LineageStep memory) {
        LineageStep storage s = _steps[step_id];
        if (!s.exists) revert StepDoesNotExist(step_id);
        return s;
    }

    /// @notice Counterfeit verifier. Returns whether the chain is intact
    ///         AND consistent with the ContradictionLedger.
    /// @dev Cited invariant: VerifyChainConsistent.
    /// @return ok True iff (a) ≥1 step recorded, (b) every step exists,
    ///         (c) every prev pointer resolves to a step for the same
    ///         part, and (d) no step's `artifact_root` has an open
    ///         contradiction in the ledger (if a ledger is wired).
    /// @return chain The full chain step ids in chronological order.
    function verifyChain(bytes32 part_hash)
        external
        view
        returns (bool ok, bytes32[] memory chain)
    {
        bytes32[] storage ids = _by_part[part_hash];
        chain = new bytes32[](ids.length);

        if (ids.length == 0) {
            return (false, chain);
        }

        bool ledger_present = address(contradiction_ledger) != address(0);

        for (uint256 i; i < ids.length; ++i) {
            bytes32 sid = ids[i];
            chain[i] = sid;
            LineageStep storage s = _steps[sid];
            if (!s.exists) {
                return (false, chain);
            }
            // Chain integrity: prev must resolve to a step for same part.
            if (s.prev_step_id != bytes32(0)) {
                LineageStep storage p = _steps[s.prev_step_id];
                if (!p.exists || p.part_hash != part_hash) {
                    return (false, chain);
                }
            }
            // Contradiction integrity: any open contradiction on the
            // step's subject invalidates the chain.
            if (ledger_present) {
                if (contradiction_ledger.hasOpenContradiction(s.artifact_root)) {
                    return (false, chain);
                }
            }
        }
        return (true, chain);
    }

    /// @notice Returns parts produced under a tail.
    /// @dev Cited invariant: TailIndexConsistent.
    function byTail(bytes32 tail_id) external view returns (bytes32[] memory) {
        return _by_tail[tail_id];
    }

    /// @notice Returns the tail a part is linked to (zero if unlinked).
    function partTail(bytes32 part_hash) external view returns (bytes32) {
        return _part_to_tail[part_hash];
    }

    /// @notice Linear scan over registered tails matching the prefix.
    /// @dev Cited invariant: SearchTailsBounded. The query is a
    ///      bytes32 prefix; `prefix_len` (in bytes, 1..32) controls
    ///      how many bytes of `query` are compared. `max_results` is
    ///      caller-supplied and capped at MAX_SEARCH_RESULTS.
    /// @dev Per planset row 7, ≤25 tails register, so the linear scan
    ///      is acceptable on-chain. If the tail set grows past
    ///      MAX_SEARCH_RESULTS × 4, an off-chain index becomes the
    ///      better path (DPF-13 deliverable).
    function searchTails(
        bytes32 query,
        uint8 prefix_len,
        uint8 max_results
    ) external view returns (bytes32[] memory) {
        if (max_results == 0) revert MaxResultsZero();
        if (max_results > MAX_SEARCH_RESULTS) {
            revert MaxResultsTooLarge(max_results, MAX_SEARCH_RESULTS);
        }
        if (prefix_len == 0 || prefix_len > 32) {
            // prefix_len out of range → treat as "match all".
            prefix_len = 0;
        }

        uint256 n = _tails.length;
        // Scratch full-size buffer; trim at the end.
        bytes32[] memory tmp = new bytes32[](max_results);
        uint256 found;
        for (uint256 i; i < n && found < max_results; ++i) {
            bytes32 t = _tails[i];
            if (prefix_len == 0 || _prefixMatch(t, query, prefix_len)) {
                tmp[found++] = t;
            }
        }
        bytes32[] memory out = new bytes32[](found);
        for (uint256 i; i < found; ++i) {
            out[i] = tmp[i];
        }
        return out;
    }

    /// @notice Number of registered tails. Cheap read for UI pagination.
    function tailCount() external view returns (uint256) {
        return _tails.length;
    }

    /// @notice Number of steps recorded for a part. O(1).
    function stepCount(bytes32 part_hash) external view returns (uint256) {
        return _by_part[part_hash].length;
    }

    // ── Internal ────────────────────────────────────────────────────

    function _prefixMatch(bytes32 a, bytes32 b, uint8 len) internal pure returns (bool) {
        for (uint8 i; i < len; ++i) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
