// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title FederatedRoundLedger: the on-chain record of a cluster-scoped federated round
/// @notice HUP-S9.2 (FL_ROUND_V1). A cluster coordinator aggregates its devices' LoRA deltas
///         off chain, chunk by chunk, through the 0x0110 Belnap-FOUR precompile, and commits
///         four roots here: the participants (worker, delta root), the precompile inputs, the
///         precompile outputs, and the merged adapter's hash. The round is accepted after a
///         challenge window unless someone proves, on chain, that it is wrong:
///
///         * `challengeOutput`: the ledger re-runs 0x0110 on a committed input; an output
///           that differs from the committed one rejects the round.
///         * `challengeRow`: a participant's row inside a committed input is not the row its
///           committed delta root holds.
///         * `challengeRules`: a committed input breaks the cluster's rules (shape, weights,
///           confidences, thresholds).
///         * `challengeOrder`: participants are not strictly ascending (a repeated worker).
///
///         A failed challenge reverts and changes nothing, so no bond is needed; a successful
///         one rejects the round permanently. Settlement reads `isAccepted` and anchors
///         `recordDigest` (citrate-settlement `fl` gate), so a rejected round never pays.
///
///         Holds no value and calls nothing but the 0x0110 precompile (static). It changes no
///         consensus rule: 0x0110 is already a live precompile, and on a chain without it every
///         path that needs it reverts with `PrecompileUnavailable` instead of passing.
/// @dev Leaves: keccak256(0x00 ‖ uint32 index ‖ payload); nodes: keccak256(0x01 ‖ l ‖ r); leaf
///      lists are padded with zero words to a power of two. See docs/fl/FL_ROUND_V1.md.
contract FederatedRoundLedger {
    // ── constants ───────────────────────────────────────────────────

    /// @notice The Belnap-FOUR aggregation precompile.
    address public constant BELNAP_AGGREGATE = address(0x0110);
    /// @notice 0x0110's per-call caps.
    uint256 public constant MAX_CHUNK_DIM = 1024;
    uint256 public constant MAX_PARTICIPANTS = 1024;
    /// @notice A challenge carries one chunk's whole input in calldata; this bounds it.
    uint256 public constant MAX_CHUNK_CELLS = 4096;
    uint16 public constant MIN_PARTICIPANTS_FLOOR = 3;
    uint8 public constant MAX_SCALE_LOG2 = 16;
    uint8 public constant CONFIDENCE_NONZERO = 1;
    uint8 public constant WEIGHT_UNIFORM = 1;
    /// @dev One unit on the Q16 grid, as raw bits.
    uint256 internal constant Q16_ONE = 65536;

    // ── types ───────────────────────────────────────────────────────

    enum Status {
        None,
        Committed,
        Rejected,
        Accepted
    }

    enum Fault {
        None,
        OutputMismatch,
        RowMismatch,
        RuleViolation,
        ParticipantOrder
    }

    /// @notice Fixed for the life of a cluster. The off-chain round config repeats them and its
    ///         hash is committed per round; the replay checks the two agree.
    struct ClusterRules {
        uint16 minParticipants;
        uint32 chunkDim;
        uint8 valueScaleLog2;
        int64 thresholdPos;
        int64 thresholdNeg;
        uint8 confidenceRule;
        uint8 weightRule;
        uint64 challengeWindow;
    }

    struct Cluster {
        address coordinator;
        uint64 nextOrdinal;
        ClusterRules rules;
    }

    struct RoundCommit {
        bytes32 clusterId;
        uint64 ordinal;
        bytes32 configHash;
        bytes32 participantsRoot;
        uint16 participants;
        uint64 nValues;
        bytes32 inputRoot;
        bytes32 outputRoot;
        uint32 chunks;
        bytes32 adapterHash;
    }

    struct Round {
        bytes32 clusterId;
        uint64 ordinal;
        bytes32 configHash;
        bytes32 participantsRoot;
        uint16 participants;
        uint64 nValues;
        bytes32 inputRoot;
        bytes32 outputRoot;
        uint32 chunks;
        bytes32 adapterHash;
        uint64 deadline;
        Status status;
        Fault fault;
        uint32 faultChunk;
    }

    /// @notice A participant opened from `participantsRoot`, and (for row challenges) its row for
    ///         one chunk opened from its delta root.
    struct RowClaim {
        uint16 participant;
        address worker;
        bytes32 deltaRoot;
        bytes32[] participantProof;
        bytes32 rowHash;
        bytes32[] rowProof;
    }

    // ── state ───────────────────────────────────────────────────────

    mapping(bytes32 => Cluster) internal clusters;
    mapping(bytes32 => Round) internal rounds;

    // ── events ──────────────────────────────────────────────────────

    event ClusterRegistered(bytes32 indexed clusterId, address indexed coordinator, ClusterRules rules);
    event RoundCommitted(
        bytes32 indexed roundId, bytes32 indexed clusterId, uint64 ordinal, uint64 deadline, bytes32 recordDigest
    );
    event RoundRejected(bytes32 indexed roundId, Fault fault, uint32 chunk, address indexed challenger);
    event RoundAccepted(bytes32 indexed roundId, bytes32 recordDigest);

    // ── errors ──────────────────────────────────────────────────────

    error BadRules();
    error ClusterExists();
    error NotCoordinator();
    error BadOrdinal();
    error BadShape();
    error UnknownRound();
    error NotCommitted();
    error WindowOpen();
    error WindowClosed();
    error BadProof();
    error ChallengeFailed();
    error PrecompileUnavailable();

    // ── ids ─────────────────────────────────────────────────────────

    function clusterIdOf(address coordinator, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encodePacked("citrate-fl-cluster/1", uint64(block.chainid), address(this), coordinator, salt));
    }

    /// @notice The round id the off-chain config computes (`RoundConfig::round_id`).
    function roundIdOf(bytes32 clusterId, uint64 ordinal) public view returns (bytes32) {
        return keccak256(abi.encodePacked("citrate-fl-round-key/1", uint64(block.chainid), address(this), clusterId, ordinal));
    }

    // ── clusters ────────────────────────────────────────────────────

    function registerCluster(bytes32 salt, ClusterRules calldata rules) external returns (bytes32 clusterId) {
        if (
            rules.minParticipants < MIN_PARTICIPANTS_FLOOR || rules.minParticipants > MAX_PARTICIPANTS
                || rules.chunkDim == 0 || rules.chunkDim > MAX_CHUNK_DIM
                || uint256(rules.minParticipants) * rules.chunkDim > MAX_CHUNK_CELLS
                || rules.valueScaleLog2 > MAX_SCALE_LOG2 || rules.thresholdPos <= 0 || rules.thresholdNeg >= 0
                || rules.confidenceRule != CONFIDENCE_NONZERO || rules.weightRule != WEIGHT_UNIFORM
                || rules.challengeWindow == 0
        ) revert BadRules();
        clusterId = clusterIdOf(msg.sender, salt);
        if (clusters[clusterId].coordinator != address(0)) revert ClusterExists();
        clusters[clusterId] = Cluster({coordinator: msg.sender, nextOrdinal: 0, rules: rules});
        emit ClusterRegistered(clusterId, msg.sender, rules);
    }

    // ── rounds ──────────────────────────────────────────────────────

    function commitRound(RoundCommit calldata c) external returns (bytes32 roundId) {
        Cluster storage cl = clusters[c.clusterId];
        if (cl.coordinator == address(0) || msg.sender != cl.coordinator) revert NotCoordinator();
        if (c.ordinal != cl.nextOrdinal) revert BadOrdinal();
        ClusterRules memory r = cl.rules;
        if (
            c.participants < r.minParticipants || uint256(c.participants) * r.chunkDim > MAX_CHUNK_CELLS
                || c.nValues == 0 || uint256(c.chunks) != (uint256(c.nValues) + r.chunkDim - 1) / r.chunkDim
                || c.configHash == bytes32(0) || c.participantsRoot == bytes32(0) || c.inputRoot == bytes32(0)
                || c.outputRoot == bytes32(0) || c.adapterHash == bytes32(0)
        ) revert BadShape();
        roundId = roundIdOf(c.clusterId, c.ordinal);
        cl.nextOrdinal = c.ordinal + 1;
        uint64 deadline = uint64(block.number) + r.challengeWindow;
        rounds[roundId] = Round({
            clusterId: c.clusterId,
            ordinal: c.ordinal,
            configHash: c.configHash,
            participantsRoot: c.participantsRoot,
            participants: c.participants,
            nValues: c.nValues,
            inputRoot: c.inputRoot,
            outputRoot: c.outputRoot,
            chunks: c.chunks,
            adapterHash: c.adapterHash,
            deadline: deadline,
            status: Status.Committed,
            fault: Fault.None,
            faultChunk: 0
        });
        emit RoundCommitted(roundId, c.clusterId, c.ordinal, deadline, recordDigest(roundId));
    }

    /// @notice After the window, an unchallenged (or unsuccessfully challenged) round is accepted.
    function finalize(bytes32 roundId) external {
        Round storage r = rounds[roundId];
        if (r.status != Status.Committed) revert NotCommitted();
        if (block.number <= r.deadline) revert WindowOpen();
        r.status = Status.Accepted;
        emit RoundAccepted(roundId, recordDigest(roundId));
    }

    // ── challenges ──────────────────────────────────────────────────

    function _open(bytes32 roundId) internal view returns (Round storage r) {
        r = rounds[roundId];
        if (r.status != Status.Committed) revert NotCommitted();
        if (block.number > r.deadline) revert WindowClosed();
    }

    function _reject(bytes32 roundId, Round storage r, Fault f, uint32 chunk) internal {
        r.status = Status.Rejected;
        r.fault = f;
        r.faultChunk = chunk;
        emit RoundRejected(roundId, f, chunk, msg.sender);
    }

    /// @dev Open the committed input of `chunk`.
    function _openInput(Round storage r, uint32 chunk, bytes calldata input, bytes32[] calldata proof) internal view {
        if (chunk >= r.chunks) revert BadProof();
        if (!_verify(r.inputRoot, chunk, keccak256(input), proof)) revert BadProof();
    }

    /// @notice Re-run 0x0110 on a committed input; reject if it disagrees with the committed output.
    function challengeOutput(
        bytes32 roundId,
        uint32 chunk,
        bytes calldata input,
        bytes32[] calldata inputProof,
        bytes32 committedOutputHash,
        bytes32[] calldata outputProof
    ) external {
        Round storage r = _open(roundId);
        _openInput(r, chunk, input, inputProof);
        if (!_verify(r.outputRoot, chunk, committedOutputHash, outputProof)) revert BadProof();
        bytes memory out = _aggregate(input);
        if (keccak256(out) == committedOutputHash) revert ChallengeFailed();
        _reject(roundId, r, Fault.OutputMismatch, chunk);
    }

    /// @notice Reject if participant `rc.participant`'s row inside a committed input is not the
    ///         row its committed delta root holds for this chunk.
    function challengeRow(
        bytes32 roundId,
        uint32 chunk,
        bytes calldata input,
        bytes32[] calldata inputProof,
        RowClaim calldata rc
    ) external {
        Round storage r = _open(roundId);
        _openInput(r, chunk, input, inputProof);
        _openParticipant(r, rc);
        if (!_verify(rc.deltaRoot, chunk, rc.rowHash, rc.rowProof)) revert BadProof();
        (uint256 dim, uint256 n) = _header(input);
        // An input whose shape is off is a rules fault; prove it with challengeRules.
        if (n != r.participants || input.length != 24 + 16 * n * dim + 8 * n) revert ChallengeFailed();
        uint256 off = 8 + uint256(rc.participant) * dim * 8;
        if (keccak256(input[off:off + dim * 8]) == rc.rowHash) revert ChallengeFailed();
        _reject(roundId, r, Fault.RowMismatch, chunk);
    }

    /// @notice Reject if a committed input breaks the cluster's rules.
    function challengeRules(bytes32 roundId, uint32 chunk, bytes calldata input, bytes32[] calldata inputProof)
        external
    {
        Round storage r = _open(roundId);
        _openInput(r, chunk, input, inputProof);
        if (_rulesHold(r, chunk, input)) revert ChallengeFailed();
        _reject(roundId, r, Fault.RuleViolation, chunk);
    }

    /// @notice Reject if two committed participants are not in strictly ascending worker order.
    function challengeOrder(bytes32 roundId, RowClaim calldata a, RowClaim calldata b) external {
        Round storage r = _open(roundId);
        if (a.participant >= b.participant) revert BadProof();
        _openParticipant(r, a);
        _openParticipant(r, b);
        if (a.worker < b.worker) revert ChallengeFailed();
        _reject(roundId, r, Fault.ParticipantOrder, 0);
    }

    function _openParticipant(Round storage r, RowClaim calldata rc) internal view {
        if (rc.participant >= r.participants) revert BadProof();
        bytes32 payload = keccak256(abi.encodePacked(rc.worker, rc.deltaRoot));
        if (!_verify(r.participantsRoot, rc.participant, payload, rc.participantProof)) revert BadProof();
    }

    // ── rules ───────────────────────────────────────────────────────

    function _header(bytes calldata input) internal pure returns (uint256 dim, uint256 n) {
        if (input.length < 8) return (0, 0);
        dim = uint32(bytes4(input[0:4]));
        n = uint32(bytes4(input[4:8]));
    }

    function _word(bytes calldata input, uint256 off) internal pure returns (int64) {
        return int64(uint64(bytes8(input[off:off + 8])));
    }

    /// @dev The same word as raw bits, widened (no sign): equality against a non-negative
    ///      constant is then exact without a narrowing cast.
    function _uword(bytes calldata input, uint256 off) internal pure returns (uint256) {
        return uint256(uint64(bytes8(input[off:off + 8])));
    }

    function _rulesHold(Round storage r, uint32 chunk, bytes calldata input) internal view returns (bool) {
        ClusterRules memory rules = clusters[r.clusterId].rules;
        if (input.length < 24) return false;
        (uint256 dim, uint256 n) = _header(input);
        uint256 expectDim = rules.chunkDim;
        if (chunk == r.chunks - 1) {
            expectDim = uint256(r.nValues) - uint256(r.chunks - 1) * rules.chunkDim;
        }
        if (dim != expectDim || n != r.participants) return false;
        if (input.length != 24 + 16 * n * dim + 8 * n) return false;
        uint256 conf = 8 + 8 * n * dim;
        uint256 w = conf + 8 * n * dim;
        // CONFIDENCE_NONZERO: 1.0 where the participant moved the coordinate, else 0.
        for (uint256 k = 0; k < n * dim; k++) {
            uint256 want = _uword(input, 8 + 8 * k) == 0 ? 0 : Q16_ONE;
            if (_uword(input, conf + 8 * k) != want) return false;
        }
        // WEIGHT_UNIFORM: floor(1.0 / n) each (n >= 3 here, so the weight is positive).
        uint256 weight = Q16_ONE / n;
        for (uint256 i = 0; i < n; i++) {
            if (_uword(input, w + 8 * i) != weight) return false;
        }
        uint256 t = w + 8 * n;
        return _word(input, t) == rules.thresholdPos && _word(input, t + 8) == rules.thresholdNeg;
    }

    // ── the precompile ──────────────────────────────────────────────

    /// @dev Static call to 0x0110 that fails closed: a chain without the precompile answers a
    ///      call to a codeless address with success and no data, which is never an aggregate.
    function _aggregate(bytes calldata input) internal view returns (bytes memory out) {
        (uint256 dim,) = _header(input);
        bool ok;
        (ok, out) = BELNAP_AGGREGATE.staticcall(input);
        if (!ok || dim == 0 || out.length != 9 * dim) revert PrecompileUnavailable();
    }

    /// @notice 0x0110 through a contract, so a coordinator can aggregate with `eth_call` on any
    ///         node build (a direct `eth_call` to a precompile address is not served by all).
    function belnapAggregate(bytes calldata input) external view returns (bytes memory) {
        return _aggregate(input);
    }

    // ── views ───────────────────────────────────────────────────────

    function getCluster(bytes32 clusterId) external view returns (Cluster memory) {
        return clusters[clusterId];
    }

    function getRound(bytes32 roundId) external view returns (Round memory) {
        return rounds[roundId];
    }

    function isAccepted(bytes32 roundId) external view returns (bool) {
        return rounds[roundId].status == Status.Accepted;
    }

    /// @notice What settlement anchors as the round's merged hash (PatronageLedger.commitRound).
    function recordDigest(bytes32 roundId) public view returns (bytes32) {
        Round storage r = rounds[roundId];
        if (r.status == Status.None) revert UnknownRound();
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                roundId,
                r.configHash,
                r.participantsRoot,
                r.inputRoot,
                r.outputRoot,
                r.adapterHash,
                uint256(r.nValues),
                uint256(r.chunks),
                uint256(r.participants)
            )
        );
    }

    // ── the tree ────────────────────────────────────────────────────

    function _verify(bytes32 root, uint32 index, bytes32 payload, bytes32[] calldata path)
        internal
        pure
        returns (bool)
    {
        // The index is inside the leaf preimage, so a path cannot be replayed at another index.
        bytes32 h = keccak256(abi.encodePacked(bytes1(0x00), index, payload));
        for (uint256 i = 0; i < path.length; i++) {
            h = (index & 1) == 0
                ? keccak256(abi.encodePacked(bytes1(0x01), h, path[i]))
                : keccak256(abi.encodePacked(bytes1(0x01), path[i], h));
            index >>= 1;
        }
        return h == root;
    }
}
