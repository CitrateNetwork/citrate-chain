// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MentorMatcher} from "../src/MentorMatcher.sol";

/// @title MentorMatcherTest — RM-FL-4 / WP-4.3
/// @notice Maps the 8 Gherkin scenarios in
///         specs/gherkin/mentor_matching.feature to Forge tests.
///         Acceptance per planset: 100% passing.
contract MentorMatcherTest is Test {
    MentorMatcher public mm;

    address public gov;
    address public mentorA;       // accuracy 0.85 in scenarios
    address public mentorC;       // accuracy 0.78 in scenarios
    address public menteeB;       // accuracy 0.40 in scenarios
    address public menteeD;
    address public sybil1;
    address public sybil2;
    address public sybil3;

    bytes32 public constant DIM_FINANCE = keccak256("finance");
    bytes32 public constant DIM_TECH = keccak256("tech");

    // Q16.16 helpers
    uint32 internal constant Q16_ONE = 65536;
    function q16(uint256 cents) internal pure returns (uint32) {
        // cents = hundredths, e.g. 85 → 0.85 → Q16(0.85) = 55706
        return uint32((cents * Q16_ONE) / 100);
    }

    function setUp() public {
        gov = address(this);  // test contract is governance
        mm = new MentorMatcher(gov);

        mentorA = address(0xA11CE);
        mentorC = address(0xC44E);
        menteeB = address(0xB055);
        menteeD = address(0xD00D);
        sybil1 = address(0x51B11);
        sybil2 = address(0x51B12);
        sybil3 = address(0x51B13);
    }

    // ====================================================================
    // Defaults
    // ====================================================================

    function test_defaults_match_planset() public view {
        assertEq(mm.mentorCap(), 3, "default M_max = 3");
        assertEq(mm.trustFloor(), 19661, "default trust floor 0.30 (Q16)");
        assertEq(mm.minAccuracyGap(), 3277, "default gap 0.05 (Q16)");
    }

    // ====================================================================
    // Scenario 1 — Standard mentor match with adequate accuracy gap
    // ====================================================================

    function test_scenario1_standard_match_with_adequate_gap() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);

        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);

        assertEq(mm.mentorLoad(mentorA), 1, "load incremented to 1");
        assertTrue(mm.isPaired(mentorA, menteeB), "pair recorded");
        MentorMatcher.Pairing memory p = mm.getPairing(mentorA, menteeB);
        assertEq(p.mentor, mentorA);
        assertEq(p.mentee, menteeB);
        assertEq(p.dimension, DIM_FINANCE);
        assertEq(p.mentorAccAtPair, q16(85), "mentor acc recorded at 0.85");
        assertEq(p.menteeAccAtPair, q16(40), "mentee acc recorded at 0.40");
    }

    // ====================================================================
    // Scenario 2 — No qualified mentor (trust floor)
    // ====================================================================

    function test_scenario2_mentor_below_trust_floor_reverts() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(10);

        // Mentor accuracy 0.20 < trust floor 0.30 → revert.
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.MentorBelowTrustFloor.selector,
                mentorA,
                q16(20)
            )
        );
        mm.assignMentees(mentorA, mentees, q16(20), accs, DIM_FINANCE);
        assertEq(mm.mentorLoad(mentorA), 0, "no pairing recorded");
    }

    function test_scenario2_no_qualified_mentor_event_via_observer_call() public {
        // The off-chain matcher signals "no qualified mentor" by
        // calling recordNoQualifiedMentor — this is pure observability,
        // does not modify state.
        vm.expectEmit(true, false, false, true);
        emit MentorMatcher.NoQualifiedMentor(menteeB, 42);
        mm.recordNoQualifiedMentor(menteeB, 42);
    }

    // ====================================================================
    // Scenario 3 — Mentor at capacity is skipped
    // ====================================================================

    function test_scenario3_mentor_at_capacity_reverts() public {
        // Pair mentorA up to cap (3 mentees).
        address[] memory three = new address[](3);
        three[0] = address(0x1);
        three[1] = address(0x2);
        three[2] = address(0x3);
        uint32[] memory accs = new uint32[](3);
        accs[0] = q16(40);
        accs[1] = q16(40);
        accs[2] = q16(40);
        mm.assignMentees(mentorA, three, q16(85), accs, DIM_FINANCE);
        assertEq(mm.mentorLoad(mentorA), 3, "at cap");

        // Fourth mentee → revert.
        address[] memory fourth = new address[](1);
        fourth[0] = menteeB;
        uint32[] memory acc4 = new uint32[](1);
        acc4[0] = q16(40);
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.MentorAtCapacity.selector,
                mentorA
            )
        );
        mm.assignMentees(mentorA, fourth, q16(85), acc4, DIM_FINANCE);
        assertEq(mm.mentorLoad(mentorA), 3, "still at cap");
    }

    function test_scenario3_governance_can_raise_cap() public {
        mm.setMentorCap(5);
        assertEq(mm.mentorCap(), 5);
    }

    function test_scenario3_non_governance_cannot_raise_cap() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(MentorMatcher.NotGovernance.selector);
        mm.setMentorCap(5);
    }

    // ====================================================================
    // Scenario 4 — Sybil mentor below trust floor cannot capture mentee
    // ====================================================================

    function test_scenario4_sybil_below_trust_floor_blocked() public {
        // All three sybils are at 0.20 — below the 0.30 trust floor.
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);

        for (uint256 i = 0; i < 3; i++) {
            address sybil = i == 0 ? sybil1 : (i == 1 ? sybil2 : sybil3);
            vm.expectRevert(
                abi.encodeWithSelector(
                    MentorMatcher.MentorBelowTrustFloor.selector,
                    sybil,
                    q16(20)
                )
            );
            mm.assignMentees(sybil, mentees, q16(20), accs, DIM_FINANCE);
        }
        assertFalse(mm.isPaired(sybil1, menteeB));
        assertFalse(mm.isPaired(sybil2, menteeB));
        assertFalse(mm.isPaired(sybil3, menteeB));
    }

    // ====================================================================
    // Scenario 5 — Mentor accuracy drop after pairing leaves record intact
    // ====================================================================

    function test_scenario5_acc_drop_post_pair_does_not_invalidate() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);

        // Mentor's overall accuracy "drops" off-chain (we don't model
        // an on-chain accuracy oracle here). The contract's pair
        // record retains the 0.85 baseline.
        MentorMatcher.Pairing memory p = mm.getPairing(mentorA, menteeB);
        assertEq(p.mentorAccAtPair, q16(85), "pair-time acc preserved");
        assertTrue(mm.isPaired(mentorA, menteeB), "pair still active");
    }

    // ====================================================================
    // Scenario 6 + 7 — Adapter verification (deferred to WP-4.7)
    // ====================================================================
    // These scenarios are exercised on LoRAFactory at WP-4.7;
    // MentorMatcher itself does not orchestrate adapter verification.

    // ====================================================================
    // Scenario 8 — Per-dimension scoring (deferred to WP-4.6)
    // ====================================================================
    // Exercised on ContributionAccounting at WP-4.6.

    // ====================================================================
    // Additional: invariant-mapped tests
    // ====================================================================

    function test_inv_no_self_mentor() public {
        address[] memory mentees = new address[](1);
        mentees[0] = mentorA;  // self-pair attempt
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.SelfMentor.selector,
                mentorA
            )
        );
        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);
    }

    function test_inv_mentee_at_most_one_mentor() public {
        address[] memory m1 = new address[](1);
        m1[0] = menteeB;
        uint32[] memory acc1 = new uint32[](1);
        acc1[0] = q16(40);
        mm.assignMentees(mentorA, m1, q16(85), acc1, DIM_FINANCE);

        // Second mentor tries to claim same mentee → revert.
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.MenteeAlreadyAssigned.selector,
                menteeB,
                mentorA
            )
        );
        mm.assignMentees(mentorC, m1, q16(78), acc1, DIM_FINANCE);
    }

    function test_inv_accuracy_gap_enforced() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        // Mentor at 0.42, mentee at 0.40 → gap = 0.02 < 0.05 threshold.
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.AccuracyGapTooSmall.selector,
                q16(42),
                q16(40)
            )
        );
        mm.assignMentees(mentorA, mentees, q16(42), accs, DIM_FINANCE);
    }

    // ====================================================================
    // Pagination (WP-4.4 tripwire pair)
    // ====================================================================

    function test_pagination_get_pairings_window() public {
        // Create 5 pairings on mentorA (raise cap first).
        mm.setMentorCap(10);
        address[] memory five = new address[](5);
        uint32[] memory accs = new uint32[](5);
        for (uint256 i = 0; i < 5; i++) {
            five[i] = address(uint160(0x1000 + i));
            accs[i] = q16(40);
        }
        mm.assignMentees(mentorA, five, q16(85), accs, DIM_FINANCE);

        assertEq(mm.pairingCount(), 5);

        // Window [1, 4) — expect 3 pairings.
        MentorMatcher.Pairing[] memory window = mm.getPairings(1, 4);
        assertEq(window.length, 3, "window of 3");
        assertEq(window[0].mentee, address(uint160(0x1001)));
        assertEq(window[2].mentee, address(uint160(0x1003)));
    }

    function test_pagination_out_of_range_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.PaginationOutOfRange.selector,
                0,
                10,
                0
            )
        );
        mm.getPairings(0, 10);
    }

    // ====================================================================
    // Unassign
    // ====================================================================

    function test_unassign_by_mentor() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);

        vm.prank(mentorA);
        mm.unassignMentee(mentorA, menteeB);

        assertFalse(mm.isPaired(mentorA, menteeB));
        assertEq(mm.mentorLoad(mentorA), 0);
        assertEq(mm.menteeMentor(menteeB), address(0));
    }

    function test_unassign_unauthorized_reverts() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);

        vm.prank(address(0xDEAD));
        vm.expectRevert("MentorMatcher: unauthorized");
        mm.unassignMentee(mentorA, menteeB);
    }

    // ====================================================================
    // WP-4.8 — Pure helper: validatePairing
    //
    // The contract↔daemon contract. The off-chain matcher should be
    // able to call validatePairing via eth_call and get the same
    // answer the on-chain assignMentees write path would produce.
    // ====================================================================

    function test_helper_returns_OK_for_valid_pairing() public view {
        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorA, menteeB, q16(85), q16(40));
        assertEq(uint256(v), uint256(MentorMatcher.PairingValidity.OK));
    }

    function test_helper_self_mentor_code() public view {
        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorA, mentorA, q16(85), q16(40));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.SELF_MENTOR)
        );
    }

    function test_helper_below_trust_floor_code() public view {
        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorA, menteeB, q16(20), q16(15));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.MENTOR_BELOW_TRUST_FLOOR)
        );
    }

    function test_helper_gap_too_small_code() public view {
        // Mentor 0.42, mentee 0.40 — gap 0.02 < 0.05 floor.
        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorA, menteeB, q16(42), q16(40));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.ACCURACY_GAP_TOO_SMALL)
        );
    }

    function test_helper_at_capacity_code() public {
        // Saturate mentorA at cap.
        address[] memory three = new address[](3);
        three[0] = address(0x1);
        three[1] = address(0x2);
        three[2] = address(0x3);
        uint32[] memory accs = new uint32[](3);
        accs[0] = q16(40);
        accs[1] = q16(40);
        accs[2] = q16(40);
        mm.assignMentees(mentorA, three, q16(85), accs, DIM_FINANCE);

        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorA, menteeB, q16(85), q16(40));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.MENTOR_AT_CAPACITY)
        );
    }

    function test_helper_mentee_already_assigned_code() public {
        address[] memory mentees = new address[](1);
        mentees[0] = menteeB;
        uint32[] memory accs = new uint32[](1);
        accs[0] = q16(40);
        mm.assignMentees(mentorA, mentees, q16(85), accs, DIM_FINANCE);

        // Different mentor checks the same mentee.
        MentorMatcher.PairingValidity v =
            mm.validatePairing(mentorC, menteeB, q16(78), q16(40));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.MENTEE_ALREADY_ASSIGNED)
        );
    }

    function test_helper_agrees_with_assignMentees_path() public {
        // Property test: every code the helper returns must match
        // the actual revert (or success) of assignMentees. This
        // pins the contract↔daemon agreement.
        MentorMatcher.PairingValidity v;
        address[] memory single = new address[](1);
        uint32[] memory acc = new uint32[](1);

        // OK case → assignMentees succeeds.
        single[0] = menteeB;
        acc[0] = q16(40);
        v = mm.validatePairing(mentorA, menteeB, q16(85), q16(40));
        assertEq(uint256(v), uint256(MentorMatcher.PairingValidity.OK));
        mm.assignMentees(mentorA, single, q16(85), acc, DIM_FINANCE);
        assertTrue(mm.isPaired(mentorA, menteeB));

        // SELF_MENTOR case → assignMentees reverts SelfMentor.
        single[0] = mentorC;
        acc[0] = q16(40);
        v = mm.validatePairing(mentorC, mentorC, q16(85), q16(40));
        assertEq(
            uint256(v),
            uint256(MentorMatcher.PairingValidity.SELF_MENTOR)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.SelfMentor.selector,
                mentorC
            )
        );
        mm.assignMentees(mentorC, single, q16(85), acc, DIM_FINANCE);
    }

    // ====================================================================
    // WP-4.9 — Lazy mentee profile (sourced from ContributionAccounting)
    //
    // The matcher does NOT mirror per-(addr, dim) scores in its own
    // storage; it staticcalls a wired ContributionAccounting source
    // on demand. Tests use a minimal in-memory stub that implements
    // `getDimensionScore` so we exercise the cross-contract path
    // without booting the real ContributionAccounting (which has its
    // own much larger test surface).
    // ====================================================================

    function _setCAFromGov(address ca) internal {
        // gov is `address(this)` per setUp().
        mm.setContributionAccounting(ca);
    }

    function _makeStubCA(
        address[] memory addrs,
        bytes32[] memory dims,
        uint256[] memory scores
    ) internal returns (StubContributionAccounting) {
        StubContributionAccounting stub = new StubContributionAccounting();
        require(
            addrs.length == dims.length
                && dims.length == scores.length,
            "stub: length mismatch"
        );
        for (uint256 i = 0; i < addrs.length; i++) {
            stub.set(addrs[i], dims[i], scores[i]);
        }
        return stub;
    }

    function test_lazy_setContributionAccounting_authz_and_event() public {
        // Non-governance cannot set.
        vm.prank(address(0xBAD));
        vm.expectRevert(MentorMatcher.NotGovernance.selector);
        mm.setContributionAccounting(address(0xC0FFEE));

        // Governance can; event fires; storage updates.
        vm.expectEmit(false, false, false, true, address(mm));
        emit MentorMatcher.ContributionAccountingSet(
            address(0),
            address(0xC0FFEE)
        );
        mm.setContributionAccounting(address(0xC0FFEE));
        assertEq(mm.contributionAccounting(), address(0xC0FFEE));
    }

    function test_lazy_getMenteeProfile_reverts_if_CA_unset() public {
        bytes32[] memory dims = new bytes32[](1);
        dims[0] = DIM_FINANCE;
        vm.expectRevert(
            MentorMatcher.ContributionAccountingNotSet.selector
        );
        mm.getMenteeProfile(menteeB, dims, 0, 1);
    }

    function test_lazy_getMenteeProfile_returns_window_from_CA() public {
        // Stub CA with menteeB scoring 100, 250, 30 across three dims.
        address[] memory addrs = new address[](3);
        bytes32[] memory dims = new bytes32[](3);
        uint256[] memory scores = new uint256[](3);
        addrs[0] = menteeB; dims[0] = DIM_FINANCE; scores[0] = 100;
        addrs[1] = menteeB; dims[1] = DIM_TECH;    scores[1] = 250;
        addrs[2] = menteeB; dims[2] = keccak256("ops"); scores[2] = 30;
        StubContributionAccounting ca = _makeStubCA(addrs, dims, scores);
        _setCAFromGov(address(ca));

        bytes32[] memory window = new bytes32[](3);
        window[0] = DIM_FINANCE;
        window[1] = DIM_TECH;
        window[2] = keccak256("ops");

        // Full window.
        uint256[] memory profile = mm.getMenteeProfile(menteeB, window, 0, 3);
        assertEq(profile.length, 3);
        assertEq(profile[0], 100);
        assertEq(profile[1], 250);
        assertEq(profile[2], 30);

        // Partial window [1,3): 250, 30.
        uint256[] memory tail = mm.getMenteeProfile(menteeB, window, 1, 3);
        assertEq(tail.length, 2);
        assertEq(tail[0], 250);
        assertEq(tail[1], 30);
    }

    function test_lazy_getMenteeProfile_empty_or_oob_reverts() public {
        StubContributionAccounting ca = new StubContributionAccounting();
        _setCAFromGov(address(ca));

        bytes32[] memory window = new bytes32[](2);
        window[0] = DIM_FINANCE;
        window[1] = DIM_TECH;

        // Empty window.
        vm.expectRevert(MentorMatcher.EmptyDimensionWindow.selector);
        mm.getMenteeProfile(menteeB, window, 1, 1);

        // Out-of-bounds window.
        vm.expectRevert(
            abi.encodeWithSelector(
                MentorMatcher.PaginationOutOfRange.selector,
                uint256(0), uint256(3), uint256(2)
            )
        );
        mm.getMenteeProfile(menteeB, window, 0, 3);
    }

    function test_lazy_selectBestDimension_picks_largest_gap() public {
        // mentorA stronger than menteeB across 3 dims with gaps
        // (finance: 800-100=700), (tech: 400-250=150), (ops: 90-30=60).
        // Best dim = finance.
        StubContributionAccounting ca = new StubContributionAccounting();
        ca.set(mentorA, DIM_FINANCE, 800);
        ca.set(mentorA, DIM_TECH, 400);
        ca.set(mentorA, keccak256("ops"), 90);
        ca.set(menteeB, DIM_FINANCE, 100);
        ca.set(menteeB, DIM_TECH, 250);
        ca.set(menteeB, keccak256("ops"), 30);
        _setCAFromGov(address(ca));

        bytes32[] memory window = new bytes32[](3);
        window[0] = DIM_FINANCE;
        window[1] = DIM_TECH;
        window[2] = keccak256("ops");

        (
            bytes32 bestDim,
            uint256 mScore,
            uint256 eScore,
            uint256 idx
        ) = mm.selectBestDimension(mentorA, menteeB, window, 0, 3);
        assertEq(bestDim, DIM_FINANCE);
        assertEq(mScore, 800);
        assertEq(eScore, 100);
        assertEq(idx, 0);
    }

    function test_lazy_selectBestDimension_negative_gap_treated_as_zero()
        public
    {
        // mentor LOSES to mentee on every dim: gaps clamp to 0.
        // The function still returns the first dim (deterministic
        // tie-break to lowest index when all gaps are zero).
        StubContributionAccounting ca = new StubContributionAccounting();
        ca.set(mentorA, DIM_FINANCE, 10);
        ca.set(mentorA, DIM_TECH, 20);
        ca.set(menteeB, DIM_FINANCE, 100);
        ca.set(menteeB, DIM_TECH, 200);
        _setCAFromGov(address(ca));

        bytes32[] memory window = new bytes32[](2);
        window[0] = DIM_FINANCE;
        window[1] = DIM_TECH;

        (bytes32 bestDim, uint256 mScore, uint256 eScore, uint256 idx) =
            mm.selectBestDimension(mentorA, menteeB, window, 0, 2);
        // Tie at gap=0: lowest index wins.
        assertEq(bestDim, DIM_FINANCE);
        assertEq(mScore, 10);
        assertEq(eScore, 100);
        assertEq(idx, 0);
    }

    function test_lazy_selectBestDimension_reverts_if_CA_unset() public {
        bytes32[] memory window = new bytes32[](1);
        window[0] = DIM_FINANCE;
        vm.expectRevert(
            MentorMatcher.ContributionAccountingNotSet.selector
        );
        mm.selectBestDimension(mentorA, menteeB, window, 0, 1);
    }

    function test_lazy_no_per_cycle_storage_writes() public {
        // The matcher's lazy views must not mutate matcher state.
        // Snapshot mentorLoad + pairings.length before & after a
        // sequence of profile reads and assert no change.
        StubContributionAccounting ca = new StubContributionAccounting();
        ca.set(mentorA, DIM_FINANCE, 800);
        ca.set(menteeB, DIM_FINANCE, 100);
        _setCAFromGov(address(ca));

        uint256 loadBefore = mm.mentorLoad(mentorA);
        uint256 countBefore = mm.pairingCount();

        bytes32[] memory window = new bytes32[](1);
        window[0] = DIM_FINANCE;
        mm.getMenteeProfile(menteeB, window, 0, 1);
        mm.selectBestDimension(mentorA, menteeB, window, 0, 1);

        assertEq(mm.mentorLoad(mentorA), loadBefore);
        assertEq(mm.pairingCount(), countBefore);
    }
}

/// Minimal in-memory ContributionAccounting stub for WP-4.9 tests.
/// Implements only `getDimensionScore` — the slice the matcher
/// actually consumes. NOT a production type; lives in this test
/// file only.
contract StubContributionAccounting {
    mapping(address => mapping(bytes32 => uint256)) internal _score;

    function set(address who, bytes32 dim, uint256 v) external {
        _score[who][dim] = v;
    }

    function getDimensionScore(
        address contributor,
        bytes32 dimension
    ) external view returns (uint256) {
        return _score[contributor][dimension];
    }
}
