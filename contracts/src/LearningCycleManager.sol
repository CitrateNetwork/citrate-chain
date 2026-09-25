// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title LearningCycleManager — On-Chain Learning Cycle Orchestration
/// @notice Manages the full lifecycle of collaborative learning cycles:
///         Open → Collecting → Aggregating → AdapterGen → Finalized.
///         Reward distribution: 40% participants, 35% mentors, 15% improved mentees, 10% aggregator.
/// @dev WP-F.11
contract LearningCycleManager is ReentrancyGuard, Governable {
    // ── Types ───────────────────────────────────────────────────────

    enum CycleState { Open, Collecting, Aggregating, AdapterGen, Finalized }

    struct CycleInfo {
        uint256 cycleId;
        uint256 checkpointHeight;
        CycleState state;
        uint256 participantCount;
        uint256 mentorCount;
        uint256 totalRewards;
        bool rewardsDistributed;
        address aggregator;
        uint256 phaseStartBlock;
    }

    // ── Constants ────────────────────────────────────────────────────

    /// @notice Reward share: 40% to all participants who submitted embeddings.
    uint256 public constant PARTICIPANT_SHARE_BPS = 4000;

    /// @notice Reward share: 35% to mentors who generated adapters.
    uint256 public constant MENTOR_SHARE_BPS = 3500;

    /// @notice Reward share: 15% to mentees who showed improvement.
    uint256 public constant MENTEE_SHARE_BPS = 1500;

    /// @notice Reward share: 10% to the aggregator that ran paraconsensus.
    uint256 public constant AGGREGATOR_SHARE_BPS = 1000;

    uint256 private constant BPS = 10000;

    // ── State ────────────────────────────────────────────────────────

    /// @notice Current (latest) cycle ID. Incremented on each `openCycle`.
    uint256 public currentCycleId;

    // Governance state lives in Governable mixin (audit SOL-21).

    // ── Per-Cycle Storage ────────────────────────────────────────────

    /// @dev Core metadata per cycle (everything except nested mappings).
    mapping(uint256 => CycleInfo) private _cycleInfo;

    /// @dev Participants list per cycle.
    mapping(uint256 => address[]) private _participants;

    /// @dev Whether an address has registered for a cycle.
    mapping(uint256 => mapping(address => bool)) private _isParticipant;

    /// @notice Governance-managed participant allowlist. Registration is
    ///         gated on eligibility to close CHAIN-B-C029: previously any
    ///         address could self-register, letting a sybil both dilute
    ///         the participant reward pool arbitrarily and — past the
    ///         block gas limit on the `finalizeCycle` participant loop —
    ///         permanently brick the contract (openCycle requires the
    ///         prior cycle to be Finalized).
    mapping(address => bool) public eligibleParticipant;

    /// @dev Embedding commitment hashes per cycle.
    mapping(uint256 => mapping(address => bytes32)) public embeddingCommitments;

    /// @dev Mentor assignments: mentee => mentor.
    mapping(uint256 => mapping(address => address)) public mentorAssignments;

    /// @dev Whether an address has been assigned as mentor in a cycle.
    mapping(uint256 => mapping(address => bool)) private _isMentor;

    /// @dev List of mentors per cycle.
    mapping(uint256 => address[]) private _mentors;

    /// @dev Adapter hashes submitted by mentors.
    mapping(uint256 => mapping(address => bytes32)) public adapterHashes;

    /// @dev Mentees list per mentor per cycle.
    mapping(uint256 => mapping(address => address[])) private _mentorMentees;

    /// @dev Whether rewards have been claimed by a participant.
    mapping(uint256 => mapping(address => bool)) private _claimed;

    /// @dev Per-address reward allocation for a cycle (set during finalization).
    mapping(uint256 => mapping(address => uint256)) private _rewards;

    // ── Events ───────────────────────────────────────────────────────

    event CycleOpened(uint256 indexed cycleId, uint256 checkpointHeight);
    event ParticipantRegistered(uint256 indexed cycleId, address indexed participant);
    event ParticipantEligibilitySet(address indexed participant, bool eligible);
    event EmbeddingCommitted(uint256 indexed cycleId, address indexed participant, bytes32 commitment);
    event StateAdvanced(uint256 indexed cycleId, CycleState oldState, CycleState newState);
    event MentorAssigned(uint256 indexed cycleId, address indexed mentor, address indexed mentee);
    event AdapterRecorded(uint256 indexed cycleId, address indexed mentor, bytes32 adapterHash);
    event CycleFinalized(uint256 indexed cycleId, uint256 totalRewards);
    event CycleCancelled(uint256 indexed cycleId);
    event RewardClaimed(uint256 indexed cycleId, address indexed participant, uint256 amount);
    // GovernanceTransferred event provided by Governable mixin.

    // ── Modifiers ────────────────────────────────────────────────────

    // `onlyGovernance` is inherited from Governable.

    // ── Constructor ──────────────────────────────────────────────────

    /// @param initialGovernance Explicit governance (PBA-L2-002: never msg.sender,
    ///        which is the CREATE2 factory under a salted ceremony deploy).
    constructor(address initialGovernance) Governable(initialGovernance) {}

    // ── Participant eligibility (CHAIN-B-C029) ───────────────────────

    /// @notice Authorize (or revoke) an address permitted to register as
    ///         a participant. Governance-only.
    function setParticipantEligibility(address participant, bool eligible)
        external
        onlyGovernance
    {
        eligibleParticipant[participant] = eligible;
        emit ParticipantEligibilitySet(participant, eligible);
    }

    /// @notice Batch variant of `setParticipantEligibility`.
    function setParticipantEligibilityBatch(address[] calldata participants, bool eligible)
        external
        onlyGovernance
    {
        for (uint256 i = 0; i < participants.length; i++) {
            eligibleParticipant[participants[i]] = eligible;
            emit ParticipantEligibilitySet(participants[i], eligible);
        }
    }

    // ── Cycle Lifecycle ──────────────────────────────────────────────

    /// @notice Open a new learning cycle anchored to a BFT checkpoint height.
    /// @param checkpointHeight The block height of the BFT checkpoint.
    function openCycle(uint256 checkpointHeight) external onlyGovernance {
        // If a cycle already exists, it must be finalized before opening a new one
        if (currentCycleId > 0) {
            require(
                _cycleInfo[currentCycleId].state == CycleState.Finalized,
                "Previous cycle not finalized"
            );
        }

        currentCycleId++;
        uint256 cid = currentCycleId;

        _cycleInfo[cid] = CycleInfo({
            cycleId: cid,
            checkpointHeight: checkpointHeight,
            state: CycleState.Open,
            participantCount: 0,
            mentorCount: 0,
            totalRewards: 0,
            rewardsDistributed: false,
            aggregator: address(0),
            phaseStartBlock: block.number
        });

        emit CycleOpened(cid, checkpointHeight);
    }

    /// @notice PBA-L2-047: governance escape hatch for a cycle that cannot
    ///         progress. Marks the CURRENT, not-yet-finalized cycle Finalized
    ///         with no rewards (nothing was ever escrowed before finalize), so
    ///         `openCycle` is reachable again.
    function cancelCycle(uint256 cycleId) external onlyGovernance {
        require(cycleId == currentCycleId && cycleId > 0, "Not the current cycle");
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state != CycleState.Finalized, "Already finalized");
        CycleState old = ci.state;
        ci.state = CycleState.Finalized;
        ci.phaseStartBlock = block.number;
        emit StateAdvanced(cycleId, old, CycleState.Finalized);
        emit CycleCancelled(cycleId);
    }

    /// @notice Register as a participant in an open cycle.
    /// @param cycleId The cycle to join.
    function registerParticipant(uint256 cycleId) external {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.cycleId > 0, "Cycle does not exist");
        require(
            ci.state == CycleState.Open || ci.state == CycleState.Collecting,
            "Registration closed"
        );
        // CHAIN-B-C029: registration is gated on a governance allowlist so
        // sybils cannot dilute the reward pool or grow the finalize loop
        // past the block gas limit. Placed after the state check so a
        // closed-cycle registration still reports "Registration closed".
        require(eligibleParticipant[msg.sender], "Not eligible participant");
        require(!_isParticipant[cycleId][msg.sender], "Already registered");

        _isParticipant[cycleId][msg.sender] = true;
        _participants[cycleId].push(msg.sender);
        ci.participantCount++;

        // Auto-transition from Open to Collecting on first registration
        if (ci.state == CycleState.Open) {
            CycleState old = ci.state;
            ci.state = CycleState.Collecting;
            ci.phaseStartBlock = block.number;
            emit StateAdvanced(cycleId, old, CycleState.Collecting);
        }

        emit ParticipantRegistered(cycleId, msg.sender);
    }

    /// @notice Submit an embedding commitment hash for a cycle.
    /// @param cycleId The cycle.
    /// @param commitment keccak256 hash of the embedding data.
    function submitEmbeddingCommitment(uint256 cycleId, bytes32 commitment) external {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state == CycleState.Collecting, "Not in Collecting state");
        require(_isParticipant[cycleId][msg.sender], "Not a participant");
        require(commitment != bytes32(0), "Empty commitment");
        require(embeddingCommitments[cycleId][msg.sender] == bytes32(0), "Already committed");

        embeddingCommitments[cycleId][msg.sender] = commitment;

        emit EmbeddingCommitted(cycleId, msg.sender, commitment);
    }

    /// @notice Advance the cycle from Collecting to Aggregating (governance only).
    /// @param cycleId The cycle to advance.
    function advanceToAggregating(uint256 cycleId) external onlyGovernance {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state == CycleState.Collecting, "Not in Collecting state");
        // PBA-L2-047: AdapterGen needs a mentor assignment between TWO distinct
        // participants; advancing with one made finalize (and so every future
        // openCycle) unreachable forever.
        require(ci.participantCount >= 2, "Need at least 2 participants");

        CycleState old = ci.state;
        ci.state = CycleState.Aggregating;
        ci.phaseStartBlock = block.number;
        emit StateAdvanced(cycleId, old, CycleState.Aggregating);
    }

    /// @notice Record a mentor-mentee assignment (governance or aggregator).
    /// @param cycleId The cycle.
    /// @param mentor The mentor address.
    /// @param mentee The mentee address.
    function recordMentorAssignment(
        uint256 cycleId,
        address mentor,
        address mentee
    ) external onlyGovernance {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(
            ci.state == CycleState.Aggregating || ci.state == CycleState.AdapterGen,
            "Wrong state for assignments"
        );
        require(_isParticipant[cycleId][mentor], "Mentor not a participant");
        require(_isParticipant[cycleId][mentee], "Mentee not a participant");
        require(mentor != mentee, "Cannot self-mentor");
        require(mentorAssignments[cycleId][mentee] == address(0), "Mentee already assigned");

        mentorAssignments[cycleId][mentee] = mentor;
        _mentorMentees[cycleId][mentor].push(mentee);

        if (!_isMentor[cycleId][mentor]) {
            _isMentor[cycleId][mentor] = true;
            _mentors[cycleId].push(mentor);
            ci.mentorCount++;
        }

        // Auto-transition from Aggregating to AdapterGen on first mentor assignment
        if (ci.state == CycleState.Aggregating) {
            CycleState old = ci.state;
            ci.state = CycleState.AdapterGen;
            ci.phaseStartBlock = block.number;
            emit StateAdvanced(cycleId, old, CycleState.AdapterGen);
        }

        emit MentorAssigned(cycleId, mentor, mentee);
    }

    /// @notice Record an adapter hash submitted by a mentor.
    /// @param cycleId The cycle.
    /// @param mentor The mentor submitting the adapter.
    /// @param adapterHash IPFS CID hash of the adapter weights.
    function recordAdapter(
        uint256 cycleId,
        address mentor,
        bytes32 adapterHash
    ) external onlyGovernance {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state == CycleState.AdapterGen, "Not in AdapterGen state");
        require(_isMentor[cycleId][mentor], "Not a mentor");
        require(adapterHash != bytes32(0), "Empty adapter hash");
        require(adapterHashes[cycleId][mentor] == bytes32(0), "Adapter already recorded");

        adapterHashes[cycleId][mentor] = adapterHash;

        emit AdapterRecorded(cycleId, mentor, adapterHash);
    }

    /// @notice Finalize a cycle, distributing rewards according to the 40/35/15/10 split.
    /// @param cycleId The cycle to finalize.
    function finalizeCycle(uint256 cycleId) external payable onlyGovernance nonReentrant {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state == CycleState.AdapterGen, "Not in AdapterGen state");
        require(msg.value > 0, "No rewards sent");

        ci.totalRewards = msg.value;
        ci.aggregator = msg.sender;

        // Calculate reward pool allocations
        uint256 participantPool = (msg.value * PARTICIPANT_SHARE_BPS) / BPS;
        uint256 mentorPool = (msg.value * MENTOR_SHARE_BPS) / BPS;
        uint256 menteePool = (msg.value * MENTEE_SHARE_BPS) / BPS;
        uint256 aggregatorPool = msg.value - participantPool - mentorPool - menteePool;

        // Distribute participant rewards equally among all participants
        uint256 pCount = ci.participantCount;
        if (pCount > 0) {
            uint256 perParticipant = participantPool / pCount;
            address[] storage parts = _participants[cycleId];
            for (uint256 i = 0; i < parts.length; i++) {
                _rewards[cycleId][parts[i]] += perParticipant;
            }
        }

        // Distribute mentor rewards equally among mentors
        uint256 mCount = ci.mentorCount;
        if (mCount > 0) {
            uint256 perMentor = mentorPool / mCount;
            address[] storage mts = _mentors[cycleId];
            for (uint256 i = 0; i < mts.length; i++) {
                _rewards[cycleId][mts[i]] += perMentor;
            }

            // Distribute mentee rewards equally among all mentees (those with a mentor)
            // Count total mentees
            uint256 totalMentees = 0;
            for (uint256 i = 0; i < mts.length; i++) {
                totalMentees += _mentorMentees[cycleId][mts[i]].length;
            }
            if (totalMentees > 0) {
                uint256 perMentee = menteePool / totalMentees;
                for (uint256 i = 0; i < mts.length; i++) {
                    address[] storage mentees = _mentorMentees[cycleId][mts[i]];
                    for (uint256 j = 0; j < mentees.length; j++) {
                        _rewards[cycleId][mentees[j]] += perMentee;
                    }
                }
            }
        }

        // Aggregator reward
        _rewards[cycleId][ci.aggregator] += aggregatorPool;

        ci.rewardsDistributed = true;

        CycleState old = ci.state;
        ci.state = CycleState.Finalized;
        ci.phaseStartBlock = block.number;
        emit StateAdvanced(cycleId, old, CycleState.Finalized);
        emit CycleFinalized(cycleId, msg.value);
    }

    /// @notice Claim rewards for a finalized cycle.
    /// @param cycleId The cycle to claim from.
    function claimCycleReward(uint256 cycleId) external nonReentrant {
        CycleInfo storage ci = _cycleInfo[cycleId];
        require(ci.state == CycleState.Finalized, "Cycle not finalized");
        require(!_claimed[cycleId][msg.sender], "Already claimed");

        uint256 reward = _rewards[cycleId][msg.sender];
        require(reward > 0, "No reward");

        _claimed[cycleId][msg.sender] = true;

        (bool success, ) = payable(msg.sender).call{value: reward}("");
        require(success, "Transfer failed");

        emit RewardClaimed(cycleId, msg.sender, reward);
    }

    // ── View Functions ───────────────────────────────────────────────

    /// @notice Get the state of a cycle.
    function getCycleState(uint256 cycleId) external view returns (CycleState) {
        require(_cycleInfo[cycleId].cycleId > 0, "Cycle does not exist");
        return _cycleInfo[cycleId].state;
    }

    /// @notice Get core info for a cycle.
    function getCycleInfo(uint256 cycleId) external view returns (
        uint256 checkpointHeight,
        CycleState state,
        uint256 participantCount,
        uint256 mentorCount,
        uint256 totalRewards,
        bool rewardsDistributed,
        address aggregator,
        uint256 phaseStartBlock
    ) {
        CycleInfo storage ci = _cycleInfo[cycleId];
        return (
            ci.checkpointHeight,
            ci.state,
            ci.participantCount,
            ci.mentorCount,
            ci.totalRewards,
            ci.rewardsDistributed,
            ci.aggregator,
            ci.phaseStartBlock
        );
    }

    /// @notice Get participants for a cycle.
    function getParticipants(uint256 cycleId) external view returns (address[] memory) {
        return _participants[cycleId];
    }

    /// @notice Get mentors for a cycle.
    function getMentors(uint256 cycleId) external view returns (address[] memory) {
        return _mentors[cycleId];
    }

    /// @notice Get the reward allocation for a participant in a cycle.
    function getReward(uint256 cycleId, address participant) external view returns (uint256) {
        return _rewards[cycleId][participant];
    }

    /// @notice Check if a participant has claimed their reward.
    function hasClaimed(uint256 cycleId, address participant) external view returns (bool) {
        return _claimed[cycleId][participant];
    }

    /// @notice Check if an address is a participant in a cycle.
    function isParticipant(uint256 cycleId, address addr) external view returns (bool) {
        return _isParticipant[cycleId][addr];
    }

    /// @notice Check if an address is a mentor in a cycle.
    function isMentor(uint256 cycleId, address addr) external view returns (bool) {
        return _isMentor[cycleId][addr];
    }

    // ── Governance ───────────────────────────────────────────────────

    // transferGovernance / acceptGovernance are inherited from Governable.

    // ── Receive ──────────────────────────────────────────────────────

    /// @notice Accept SALT transfers.
    receive() external payable {}
}
