// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MentorMatcher — RM-FL-4 / WP-4.5
/// @notice On-chain mentor-mentee assignment for the federated
///         learning network. Pairs higher-accuracy mentors with
///         lower-accuracy mentees subject to capacity bounds and
///         a configurable trust floor. Each committed pairing
///         records the mentor's accuracy AT PAIRING TIME so a
///         subsequent score update does not retroactively
///         invalidate the pairing — see MentorAdversarial.tla
///         (PairingAccuracyGapPreservedAtCommit) and the
///         RM-FL-3 essay THE_TRAINING_DAEMON_BET (chain is
///         canonical; rollback is not an option).
///
/// @dev Spec sources:
///        - specs/tla/learning/MentorSelection.tla    (7 inv, 112K states)
///        - specs/tla/learning/MentorAdversarial.tla  (7 inv, 13.5M states)
///      Tripwire enforcement (WP-4.4):
///        - check_matcher_capacity_bounded.py        (paginated views)
///        - check_matcher_no_unbounded_loops.py      (no storage-array .length loops)
contract MentorMatcher {
    // ============================================================
    // Constants & types
    // ============================================================

    /// Q16.16 fixed-point representation of 1.0.
    uint32 internal constant Q16_ONE = 65536;

    /// Pairing record. `mentorAccAtPair` is the mentor's accuracy
    /// (Q16.16, 0..Q16_ONE) at the moment the pairing was
    /// committed. It is NOT updated when the mentor's overall
    /// accuracy later changes.
    struct Pairing {
        address mentor;
        address mentee;
        bytes32 dimension;       // application-defined dimension key
        uint32 mentorAccAtPair;  // Q16.16
        uint32 menteeAccAtPair;  // Q16.16
        uint64 pairedAt;         // block.timestamp
    }

    // ============================================================
    // Storage
    // ============================================================

    /// Governance-mutable per-mentor capacity (M_max). Default 3.
    uint256 public mentorCap = 3;

    /// Trust floor: minimum mentor accuracy to be assigned a
    /// mentee, in Q16.16. Default 0.30 = 19661.
    uint32 public trustFloor = 19661;

    /// Minimum accuracy gap (Q16.16) between mentor and mentee.
    /// Default 0.05 = 3277.
    uint32 public minAccuracyGap = 3277;

    /// Governance role (the address allowed to mutate cap/floor/gap).
    address public governance;

    /// Per-mentor mentee count.
    mapping(address => uint256) public mentorLoad;

    /// Lookup: (mentor, mentee) → pairing index in `pairings`+1.
    /// Zero means "no pairing." Storing index+1 lets us treat
    /// 0 as "absent" without conflating with index 0.
    mapping(address => mapping(address => uint256)) public pairingIndexPlusOne;

    /// All pairings, append-only. Removed pairings are zero'd in
    /// place; the index does not get reused. Bounded growth is
    /// the caller's responsibility — production usage is one
    /// pairing per mentee per cycle, and the matcher prunes
    /// completed cycles via `unassignMentee`.
    Pairing[] public pairings;

    /// Per-mentee → currently-assigned mentor (or zero if none).
    /// MentorSelection.tla::MenteeHasAtMostOneMentor enforces
    /// this is at-most-one.
    mapping(address => address) public menteeMentor;

    // ============================================================
    // Events
    // ============================================================

    /// Emitted when a pairing is committed.
    event MentorAssigned(
        address indexed mentor,
        address indexed mentee,
        bytes32 indexed dimension,
        uint32 mentorAccAtPair,
        uint32 menteeAccAtPair,
        uint256 pairingIndex
    );

    /// Emitted when a pairing is removed (mentee leaves or
    /// mentor freed).
    event MentorUnassigned(
        address indexed mentor,
        address indexed mentee,
        uint256 pairingIndex
    );

    /// Emitted when a candidate batch is evaluated and no
    /// qualifying mentor was found.
    event NoQualifiedMentor(address indexed mentee, uint256 cycleId);

    /// Emitted when governance changes the per-mentor cap.
    event MentorCapUpdated(uint256 oldCap, uint256 newCap);

    /// Emitted when governance changes the trust floor.
    event TrustFloorUpdated(uint32 oldFloor, uint32 newFloor);

    /// Emitted when governance changes the minimum accuracy gap.
    event MinAccuracyGapUpdated(uint32 oldGap, uint32 newGap);

    // ============================================================
    // Errors
    // ============================================================

    error NotGovernance();
    error MentorAtCapacity(address mentor);
    error AccuracyGapTooSmall(uint32 mentorAcc, uint32 menteeAcc);
    error MentorBelowTrustFloor(address mentor, uint32 mentorAcc);
    error SelfMentor(address who);
    error MenteeAlreadyAssigned(address mentee, address currentMentor);
    error PairingNotFound(address mentor, address mentee);
    error InvalidGovernance(address proposed);
    error PaginationOutOfRange(uint256 from_, uint256 to_, uint256 length);

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    /// @param governance_ Address allowed to mutate cap/floor/gap.
    constructor(address governance_) {
        if (governance_ == address(0)) revert InvalidGovernance(governance_);
        governance = governance_;
    }

    // ============================================================
    // Governance — mutate cap, trust floor, accuracy gap
    // ============================================================

    /// Set the per-mentor cap. Existing pairings above the new cap
    /// are NOT unwound; only future `assignMentees` calls see the
    /// new bound. This mirrors the chain-canonical principle: state
    /// already on chain is not retroactively invalidated.
    function setMentorCap(uint256 newCap) external onlyGovernance {
        uint256 oldCap = mentorCap;
        mentorCap = newCap;
        emit MentorCapUpdated(oldCap, newCap);
    }

    /// Set the trust floor (Q16.16, 0..Q16_ONE).
    function setTrustFloor(uint32 newFloor) external onlyGovernance {
        require(newFloor <= Q16_ONE, "MentorMatcher: floor > 1.0");
        uint32 oldFloor = trustFloor;
        trustFloor = newFloor;
        emit TrustFloorUpdated(oldFloor, newFloor);
    }

    /// Set the minimum accuracy gap (Q16.16).
    function setMinAccuracyGap(uint32 newGap) external onlyGovernance {
        require(newGap <= Q16_ONE, "MentorMatcher: gap > 1.0");
        uint32 oldGap = minAccuracyGap;
        minAccuracyGap = newGap;
        emit MinAccuracyGapUpdated(oldGap, newGap);
    }

    /// Transfer governance to a new address.
    function setGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) {
            revert InvalidGovernance(newGovernance);
        }
        governance = newGovernance;
    }

    // ============================================================
    // Assignment — write
    // ============================================================

    /// Batch-assign mentees to a single mentor. Each mentee in the
    /// batch is checked independently against the accuracy gap,
    /// trust floor, and capacity. Mentors that fail any check
    /// cause the relevant tx to revert (atomic batch — either all
    /// pairings commit or none do, by design, so the caller can
    /// retry with a smaller batch).
    ///
    /// `mentorAcc` and `menteeAccs` are the accuracies AT THE TIME
    /// of the call. The matcher records them with the pairing so
    /// subsequent score updates don't retroactively void it.
    function assignMentees(
        address mentor,
        address[] calldata mentees,
        uint32 mentorAcc,
        uint32[] calldata menteeAccs,
        bytes32 dimension
    ) external {
        require(
            mentees.length == menteeAccs.length,
            "MentorMatcher: length mismatch"
        );
        // Trust floor first — this catches sybil mentors regardless
        // of their relative gap claims.
        if (mentorAcc < trustFloor) {
            revert MentorBelowTrustFloor(mentor, mentorAcc);
        }
        // Bounded by `mentees.length` (caller-supplied; tripwire
        // permits this — caller controls the bound, gas pays for
        // the iteration).
        for (uint256 i = 0; i < mentees.length; i++) {
            address mentee = mentees[i];
            uint32 menteeAcc = menteeAccs[i];

            if (mentor == mentee) revert SelfMentor(mentor);

            // Capacity check — must not exceed mentorCap.
            if (mentorLoad[mentor] >= mentorCap) {
                revert MentorAtCapacity(mentor);
            }

            // Accuracy gap check.
            if (mentorAcc <= menteeAcc + minAccuracyGap) {
                revert AccuracyGapTooSmall(mentorAcc, menteeAcc);
            }

            // Mentee at-most-one check.
            address existing = menteeMentor[mentee];
            if (existing != address(0)) {
                revert MenteeAlreadyAssigned(mentee, existing);
            }

            // Commit pairing.
            pairings.push(
                Pairing({
                    mentor: mentor,
                    mentee: mentee,
                    dimension: dimension,
                    mentorAccAtPair: mentorAcc,
                    menteeAccAtPair: menteeAcc,
                    pairedAt: uint64(block.timestamp)
                })
            );
            uint256 idx = pairings.length - 1;
            pairingIndexPlusOne[mentor][mentee] = idx + 1;
            menteeMentor[mentee] = mentor;
            mentorLoad[mentor] += 1;

            emit MentorAssigned(
                mentor, mentee, dimension, mentorAcc, menteeAcc, idx
            );
        }
    }

    /// Remove a single pairing. Either party (or governance) can
    /// trigger this — application-defined access control should
    /// wrap this in the calling contract if needed.
    function unassignMentee(address mentor, address mentee) external {
        require(
            msg.sender == mentor
                || msg.sender == mentee
                || msg.sender == governance,
            "MentorMatcher: unauthorized"
        );
        uint256 idxPlusOne = pairingIndexPlusOne[mentor][mentee];
        if (idxPlusOne == 0) revert PairingNotFound(mentor, mentee);
        uint256 idx = idxPlusOne - 1;

        delete pairingIndexPlusOne[mentor][mentee];
        delete menteeMentor[mentee];
        mentorLoad[mentor] -= 1;
        // Zero the pairing in place (do not shrink the array — keeps
        // existing indices stable). The index becomes a tombstone
        // (mentor == address(0) signals "removed").
        delete pairings[idx];

        emit MentorUnassigned(mentor, mentee, idx);
    }

    /// Signal that a candidate mentee has no qualifying mentor in
    /// the current cycle. Off-chain matchers call this after their
    /// pairing pass exhausts options. Pure observability — no
    /// state change.
    function recordNoQualifiedMentor(
        address mentee,
        uint256 cycleId
    ) external {
        emit NoQualifiedMentor(mentee, cycleId);
    }

    // ============================================================
    // Views — read (paginated)
    // ============================================================

    /// Total pairings ever created (including removed tombstones).
    function pairingCount() external view returns (uint256) {
        return pairings.length;
    }

    /// Read a window of pairings. `from` is inclusive, `to` is
    /// exclusive. Reverts if the window is out of bounds. The
    /// returned array's length is bounded by `to - from`.
    function getPairings(
        uint256 from_,
        uint256 to_
    ) external view returns (Pairing[] memory window) {
        if (to_ < from_ || to_ > pairings.length) {
            revert PaginationOutOfRange(from_, to_, pairings.length);
        }
        uint256 n = to_ - from_;
        window = new Pairing[](n);
        // Caller-supplied length bound — tripwire permits.
        for (uint256 i = 0; i < n; i++) {
            window[i] = pairings[from_ + i];
        }
    }

    /// Get the pairing record for a (mentor, mentee). Reverts if
    /// no pairing exists. Returns the pair-time accuracies; do
    /// NOT use this view to query "current" mentor accuracy —
    /// that lives in ContributionAccounting.
    function getPairing(
        address mentor,
        address mentee
    ) external view returns (Pairing memory) {
        uint256 idxPlusOne = pairingIndexPlusOne[mentor][mentee];
        if (idxPlusOne == 0) revert PairingNotFound(mentor, mentee);
        return pairings[idxPlusOne - 1];
    }

    /// Whether a (mentor, mentee) pair currently exists.
    function isPaired(
        address mentor,
        address mentee
    ) external view returns (bool) {
        return pairingIndexPlusOne[mentor][mentee] != 0;
    }
}
