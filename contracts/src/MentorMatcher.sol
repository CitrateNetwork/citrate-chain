// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Minimal slice of the ContributionAccounting interface used by
/// the matcher's lazy-profile views (WP-4.9). The matcher does NOT
/// mirror the per-(addr, dim) score in its own storage; instead it
/// `staticcall`s the live total on demand. This trades O(N×D)
/// per-cycle write cost for O(D) per-query read cost, paid by the
/// matcher caller (the off-chain daemon or a dashboard view).
interface IContributionAccountingDimRead {
    function getDimensionScore(
        address contributor,
        bytes32 dimension
    ) external view returns (uint256);
}

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

    /// Validity codes returned by `validatePairing` (WP-4.8). The
    /// enum is the contract↔daemon contract: an off-chain matcher
    /// can call `validatePairing` via `eth_call` to ask "would this
    /// pairing be accepted?" without submitting a tx, and parse the
    /// answer the same way the daemon does. Adding a new variant
    /// is a contract upgrade (the daemon must learn the new code);
    /// reordering existing variants is FORBIDDEN.
    enum PairingValidity {
        OK,
        SELF_MENTOR,
        MENTOR_BELOW_TRUST_FLOOR,
        ACCURACY_GAP_TOO_SMALL,
        MENTOR_AT_CAPACITY,
        MENTEE_ALREADY_ASSIGNED
    }

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

    /// Address of the ContributionAccounting contract used by the
    /// lazy-profile views (WP-4.9). Zero until wired by governance —
    /// the matcher otherwise functions normally; only the lazy
    /// profile views revert when this is unset.
    address public contributionAccounting;

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

    /// Emitted when governance wires (or rewires) the
    /// ContributionAccounting source contract used by the lazy
    /// profile views.
    event ContributionAccountingSet(address oldAddr, address newAddr);

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
    error ContributionAccountingNotSet();
    error EmptyDimensionWindow();

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

    // ============================================================
    // Pure helper — pairing validity (WP-4.8)
    //
    // The matching algorithm is the same logic on chain and off
    // chain. Extracting it into a pure function gives the daemon
    // a way to call `eth_call validatePairing(...)` and get the
    // exact same answer as the contract's internal write path
    // would. This eliminates a class of "the daemon thought it
    // was a valid pairing but the contract rejected it" desync
    // bugs without a round-trip to chain.
    //
    // Pure: no state reads, no events, no side effects. The
    // function takes the entire context as arguments — the
    // caller (whether the contract or the daemon) is responsible
    // for sourcing those values.
    // ============================================================

    /// Internal pure variant — returns the validity code.
    function _validatePairing(
        address mentor,
        address mentee,
        uint32 mentorAcc,
        uint32 menteeAcc,
        uint256 mentorLoad_,
        uint256 mentorCap_,
        uint32 trustFloor_,
        uint32 minAccuracyGap_,
        bool menteeAlreadyAssigned
    ) internal pure returns (PairingValidity) {
        if (mentor == mentee) return PairingValidity.SELF_MENTOR;
        if (mentorAcc < trustFloor_) {
            return PairingValidity.MENTOR_BELOW_TRUST_FLOOR;
        }
        if (mentorAcc <= menteeAcc + minAccuracyGap_) {
            return PairingValidity.ACCURACY_GAP_TOO_SMALL;
        }
        if (mentorLoad_ >= mentorCap_) {
            return PairingValidity.MENTOR_AT_CAPACITY;
        }
        if (menteeAlreadyAssigned) {
            return PairingValidity.MENTEE_ALREADY_ASSIGNED;
        }
        return PairingValidity.OK;
    }

    /// Public read-only preview. The off-chain daemon calls this
    /// via `eth_call` to ask "would this pairing be accepted right
    /// now?" — the contract sources `mentorLoad`, the cap, the
    /// trust floor, the gap, and the mentee's existing assignment
    /// from its own state, so the daemon does not need to mirror
    /// every storage variable.
    function validatePairing(
        address mentor,
        address mentee,
        uint32 mentorAcc,
        uint32 menteeAcc
    ) external view returns (PairingValidity) {
        return
            _validatePairing(
                mentor,
                mentee,
                mentorAcc,
                menteeAcc,
                mentorLoad[mentor],
                mentorCap,
                trustFloor,
                minAccuracyGap,
                menteeMentor[mentee] != address(0)
            );
    }

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

    /// Wire (or rewire) the ContributionAccounting contract used by
    /// the lazy-profile views. Setting to address(0) intentionally
    /// disables those views. Idempotent.
    function setContributionAccounting(
        address newAddr
    ) external onlyGovernance {
        address old = contributionAccounting;
        contributionAccounting = newAddr;
        emit ContributionAccountingSet(old, newAddr);
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
        // Bounded by `mentees.length` (caller-supplied; tripwire
        // permits this — caller controls the bound, gas pays for
        // the iteration). Each mentee runs through the same pure
        // helper that the daemon uses — see WP-4.8.
        for (uint256 i = 0; i < mentees.length; i++) {
            address mentee = mentees[i];
            uint32 menteeAcc = menteeAccs[i];
            address existing = menteeMentor[mentee];

            PairingValidity v = _validatePairing(
                mentor,
                mentee,
                mentorAcc,
                menteeAcc,
                mentorLoad[mentor],
                mentorCap,
                trustFloor,
                minAccuracyGap,
                existing != address(0)
            );

            if (v == PairingValidity.SELF_MENTOR) {
                revert SelfMentor(mentor);
            } else if (v == PairingValidity.MENTOR_BELOW_TRUST_FLOOR) {
                revert MentorBelowTrustFloor(mentor, mentorAcc);
            } else if (v == PairingValidity.ACCURACY_GAP_TOO_SMALL) {
                revert AccuracyGapTooSmall(mentorAcc, menteeAcc);
            } else if (v == PairingValidity.MENTOR_AT_CAPACITY) {
                revert MentorAtCapacity(mentor);
            } else if (v == PairingValidity.MENTEE_ALREADY_ASSIGNED) {
                revert MenteeAlreadyAssigned(mentee, existing);
            }
            // PairingValidity.OK — fall through to commit.

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
    // Lazy mentee profile (WP-4.9)
    //
    // The matcher does NOT precompute and cache per-(addr, dim)
    // profiles inside its own storage. Doing so would cost
    // O(N participants × D dimensions) state writes every cycle,
    // most of which would never be read. Instead, profiles are
    // sourced on demand from `ContributionAccounting`: the matcher
    // is a window onto the live total, not a duplicate of it.
    //
    // The cost model inverts: write-heavy → read-heavy. The reader
    // (the daemon, a dashboard, a wallet) pays the staticcall gas
    // for the dimensions they actually want, and the contract pays
    // nothing per cycle to keep mirrored state in sync.
    //
    // Both views are paginated over the caller-supplied
    // `dimensions[]` calldata array via `from_/to_` (capacity-
    // bounded tripwire enforces this on dynamic-return views).
    // Empty windows revert because they have no useful semantic.
    // ============================================================

    /// Read a window of a mentee's per-dimension scores. The
    /// returned array is `to_ - from_` long. Reverts if the
    /// ContributionAccounting source is unset, the window is empty,
    /// or the window is out of bounds. The matcher pays no per-
    /// cycle gas to keep this in sync — the data is the live total
    /// in `ContributionAccounting.dimensionContributions`.
    function getMenteeProfile(
        address mentee,
        bytes32[] calldata dimensions,
        uint256 from_,
        uint256 to_
    ) external view returns (uint256[] memory profile) {
        address ca = contributionAccounting;
        if (ca == address(0)) revert ContributionAccountingNotSet();
        if (to_ < from_ || to_ > dimensions.length) {
            revert PaginationOutOfRange(from_, to_, dimensions.length);
        }
        uint256 n = to_ - from_;
        if (n == 0) revert EmptyDimensionWindow();
        profile = new uint256[](n);
        // Caller-bounded by `n = to_ - from_`; both tripwires permit.
        for (uint256 i = 0; i < n; i++) {
            profile[i] = IContributionAccountingDimRead(ca)
                .getDimensionScore(mentee, dimensions[from_ + i]);
        }
    }

    /// Pick the dimension within `dimensions[from_:to_]` where the
    /// (mentor, mentee) score gap is largest. Returns the dimension
    /// key, both scores, and the index within the supplied window.
    /// Ties resolve to the lower-index dimension (deterministic).
    /// Reverts under the same conditions as `getMenteeProfile`. A
    /// gap of zero is a valid result — caller decides whether that's
    /// useful (typically: it isn't, and the caller falls back to
    /// `recordNoQualifiedMentor`).
    function selectBestDimension(
        address mentor,
        address mentee,
        bytes32[] calldata dimensions,
        uint256 from_,
        uint256 to_
    )
        external
        view
        returns (
            bytes32 bestDimension,
            uint256 mentorScore,
            uint256 menteeScore,
            uint256 windowIndex
        )
    {
        address ca = contributionAccounting;
        if (ca == address(0)) revert ContributionAccountingNotSet();
        if (to_ < from_ || to_ > dimensions.length) {
            revert PaginationOutOfRange(from_, to_, dimensions.length);
        }
        uint256 n = to_ - from_;
        if (n == 0) revert EmptyDimensionWindow();

        IContributionAccountingDimRead src =
            IContributionAccountingDimRead(ca);
        uint256 bestGap = 0;
        bool anyGap = false;
        // Caller-bounded by `n = to_ - from_`.
        for (uint256 i = 0; i < n; i++) {
            bytes32 dim = dimensions[from_ + i];
            uint256 mScore = src.getDimensionScore(mentor, dim);
            uint256 eScore = src.getDimensionScore(mentee, dim);
            // Gap is positive only when mentor outscores mentee on
            // this dimension; otherwise treat as zero so we never
            // suggest a "negative-gap" dimension as best.
            uint256 gap = mScore > eScore ? mScore - eScore : 0;
            if (!anyGap || gap > bestGap) {
                anyGap = true;
                bestGap = gap;
                bestDimension = dim;
                mentorScore = mScore;
                menteeScore = eScore;
                windowIndex = i;
            }
        }
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
