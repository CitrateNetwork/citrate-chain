// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";

/// @notice Foundry fuzz tests for ComplianceRegistry. Probes the time- and
///         value-boundary spaces that unit tests can only sample. Every
///         fuzz target either: (a) bounds inputs to the legal range and
///         asserts an invariant holds, or (b) asserts that out-of-range
///         inputs revert with the expected error.
///
///         IR-optimizer note: foundry.toml has `via_ir = true`. We avoid
///         repeated `block.timestamp + delta` patterns (which the IR
///         optimizer can fold across vm.warp boundaries) by anchoring on
///         absolute timestamps via vm.warp.
contract ComplianceRegistryFuzzTest is Test {
    InstitutionTreeV1 internal tree;
    ComplianceRegistry internal reg;

    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);
    address internal schoolAdmin = address(0x5C0CA);
    address internal stranger = address(0xBEEF);

    bytes32 internal constant CMO_HASH = keccak256("FUZZ-CMO");
    bytes32 internal constant DIST_HASH = keccak256("FUZZ-DIST");
    bytes32 internal constant SCHOOL_HASH = keccak256("FUZZ-SCHOOL");

    uint64 internal constant SETUP_TIMESTAMP = 1_700_000_000;
    uint8 internal constant STATE_CA = 0;

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
        reg = new ComplianceRegistry(governance, address(tree));

        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DIST_HASH, districtAdmin, STATE_CA);
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_HASH, SCHOOL_HASH, schoolAdmin, STATE_CA);

        vm.warp(SETUP_TIMESTAMP);
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: federal gate signing accepts any (envelope, expiry) within bounds
    // ──────────────────────────────────────────────────────────────

    function testFuzz_recordSigned_federalGate_acceptsValidExpiry(
        bytes32 envHash,
        uint32 deltaSeconds
    ) public {
        // Bound: envelope must be non-zero, expiry must be > now AND
        // within MAX_VALIDITY_WINDOW.
        vm.assume(envHash != bytes32(0));
        uint64 deltaBounded = uint64(bound(uint256(deltaSeconds), 1, reg.MAX_VALIDITY_WINDOW()));
        uint64 expiresAt = SETUP_TIMESTAMP + deltaBounded;

        vm.prank(schoolAdmin);
        reg.recordSigned(SCHOOL_HASH, 0 /* DPA */, envHash, expiresAt);

        ComplianceRegistry.Record memory r = reg.getRecord(SCHOOL_HASH, 0);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, envHash);
        assertEq(r.signer, schoolAdmin);
        assertEq(r.expiresAt, expiresAt);
        assertTrue(reg.isCompliant(SCHOOL_HASH, 0));
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: out-of-range expiry deltas always revert
    // ──────────────────────────────────────────────────────────────

    function testFuzz_recordSigned_revertsOnExpiryAtOrBeforeNow(uint64 expiresAt) public {
        vm.assume(expiresAt <= SETUP_TIMESTAMP);
        vm.prank(schoolAdmin);
        vm.expectRevert(ComplianceRegistry.InvalidExpiry.selector);
        reg.recordSigned(SCHOOL_HASH, 0, keccak256("env"), expiresAt);
    }

    function testFuzz_recordSigned_revertsOnExpiryBeyondMaxWindow(uint64 deltaSeconds) public {
        // Bound: delta strictly greater than MAX_VALIDITY_WINDOW so the
        // window check fires (the InvalidExpiry check passes because expiresAt > now).
        uint64 maxWindow = reg.MAX_VALIDITY_WINDOW();
        uint64 boundedDelta = uint64(bound(uint256(deltaSeconds), uint256(maxWindow) + 1, type(uint32).max));
        uint64 expiresAt = SETUP_TIMESTAMP + boundedDelta;

        vm.prank(schoolAdmin);
        vm.expectRevert(ComplianceRegistry.ValidityWindowTooLong.selector);
        reg.recordSigned(SCHOOL_HASH, 0, keccak256("env"), expiresAt);
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: invalid gate indices always revert
    // ──────────────────────────────────────────────────────────────

    function testFuzz_recordSigned_revertsOnInvalidGateIdx(uint8 gateIdx) public {
        vm.assume(gateIdx >= reg.GATE_COUNT());
        vm.prank(schoolAdmin);
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, gateIdx));
        reg.recordSigned(SCHOOL_HASH, gateIdx, keccak256("env"), SETUP_TIMESTAMP + 30 days);
    }

    function testFuzz_expireGate_revertsOnInvalidGateIdx(uint8 gateIdx) public {
        vm.assume(gateIdx >= reg.GATE_COUNT());
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, gateIdx));
        reg.expireGate(SCHOOL_HASH, gateIdx);
    }

    function testFuzz_revokeGate_revertsOnInvalidGateIdx(uint8 gateIdx) public {
        vm.assume(gateIdx >= reg.GATE_COUNT());
        vm.prank(governance);
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.InvalidGate.selector, gateIdx));
        reg.revokeGate(SCHOOL_HASH, gateIdx, keccak256("reason"));
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: applicability is symmetric with school state
    // ──────────────────────────────────────────────────────────────

    function testFuzz_applicability_stateGate_onlyMatchesSchoolState(
        uint8 schoolState,
        uint8 gateOffset
    ) public {
        // Map fuzzed schoolState to a known state index and gateOffset to one
        // of the 5 state-specific gates. Then verify only matching pairs are
        // applicable; all others revert with GateNotApplicable.
        schoolState = uint8(bound(uint256(schoolState), 0, 4));
        gateOffset = uint8(bound(uint256(gateOffset), 0, 4));
        uint8 gateIdx = reg.FIRST_STATE_GATE() + gateOffset;

        // Register a fresh school with this fuzzed state
        bytes32 fuzzSchool = keccak256(abi.encodePacked("fuzz-school", schoolState, gateOffset));
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_HASH, fuzzSchool, schoolAdmin, schoolState);

        bool shouldMatch = (schoolState == gateOffset);
        if (shouldMatch) {
            // Should succeed
            vm.prank(schoolAdmin);
            reg.recordSigned(fuzzSchool, gateIdx, keccak256("env"), SETUP_TIMESTAMP + 30 days);
            assertEq(
                uint8(reg.getRecord(fuzzSchool, gateIdx).status),
                uint8(ComplianceRegistry.Status.Signed)
            );
        } else {
            // Should refuse
            vm.prank(schoolAdmin);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ComplianceRegistry.GateNotApplicable.selector, fuzzSchool, gateIdx
                )
            );
            reg.recordSigned(fuzzSchool, gateIdx, keccak256("env"), SETUP_TIMESTAMP + 30 days);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: federal gates always applicable regardless of state
    // ──────────────────────────────────────────────────────────────

    function testFuzz_federalGate_alwaysApplicable(uint8 schoolState, uint8 federalGateIdx)
        public
    {
        federalGateIdx = uint8(bound(uint256(federalGateIdx), 0, reg.FIRST_STATE_GATE() - 1));
        // Bound state to 0..4 OR 255 (Other)
        if (schoolState >= 5) schoolState = 255;
        else schoolState = uint8(bound(uint256(schoolState), 0, 4));

        bytes32 sch = keccak256(abi.encodePacked("fed", schoolState, federalGateIdx));
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_HASH, sch, schoolAdmin, schoolState);

        // Federal gates apply to all schools regardless of state. Sign should succeed.
        vm.prank(schoolAdmin);
        reg.recordSigned(sch, federalGateIdx, keccak256("env"), SETUP_TIMESTAMP + 30 days);
        assertTrue(reg.isCompliant(sch, federalGateIdx));
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: state-other (255) schools cannot sign any state gate
    // ──────────────────────────────────────────────────────────────

    function testFuzz_stateOther_rejectsAllStateGates(uint8 gateOffset) public {
        gateOffset = uint8(bound(uint256(gateOffset), 0, 4));
        uint8 gateIdx = reg.FIRST_STATE_GATE() + gateOffset;

        bytes32 schOther = keccak256(abi.encodePacked("other-state", gateOffset));
        vm.prank(districtAdmin);
        tree.registerSchool(DIST_HASH, schOther, schoolAdmin, 255);

        vm.prank(schoolAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.GateNotApplicable.selector, schOther, gateIdx
            )
        );
        reg.recordSigned(schOther, gateIdx, keccak256("env"), SETUP_TIMESTAMP + 30 days);
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: expireGate timing — only succeeds after expiry, regardless of caller
    // ──────────────────────────────────────────────────────────────

    function testFuzz_expireGate_onlyAfterExpiry(uint32 deltaToExpiry, address caller) public {
        // Bound delta well within the validity window
        uint64 delta = uint64(bound(uint256(deltaToExpiry), 60, 30 days));
        uint64 expiresAt = SETUP_TIMESTAMP + delta;

        vm.prank(schoolAdmin);
        reg.recordSigned(SCHOOL_HASH, 0, keccak256("env"), expiresAt);

        // Anyone can call expireGate, but only after expiresAt
        if (caller == address(0)) caller = address(0xDEAD); // vm.prank rejects address(0)

        // Before expiry — refuse
        vm.warp(uint256(expiresAt));
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceRegistry.NotYetExpired.selector, expiresAt, uint64(expiresAt)
            )
        );
        reg.expireGate(SCHOOL_HASH, 0);

        // 1 second after — succeed
        vm.warp(uint256(expiresAt) + 1);
        vm.prank(caller);
        reg.expireGate(SCHOOL_HASH, 0);
        assertEq(
            uint8(reg.getRecord(SCHOOL_HASH, 0).status),
            uint8(ComplianceRegistry.Status.Expired)
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: revokeGate is governance-monopoly across the caller space
    // ──────────────────────────────────────────────────────────────

    function testFuzz_revokeGate_onlyGovernance(address caller) public {
        vm.assume(caller != governance);
        // Sign first so there's something to revoke
        vm.prank(schoolAdmin);
        reg.recordSigned(SCHOOL_HASH, 0, keccak256("env"), SETUP_TIMESTAMP + 30 days);

        // For non-zero callers (vm.prank rejects address(0))
        if (caller == address(0)) caller = address(0xCAFE);
        vm.prank(caller);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCHOOL_HASH, 0, keccak256("reason"));
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: recordSigned only by school admin
    // ──────────────────────────────────────────────────────────────

    function testFuzz_recordSigned_onlySchoolAdmin(address caller) public {
        vm.assume(caller != schoolAdmin);
        if (caller == address(0)) caller = address(0xDEAD);
        vm.prank(caller);
        vm.expectRevert(ComplianceRegistry.NotSchoolAdmin.selector);
        reg.recordSigned(SCHOOL_HASH, 0, keccak256("env"), SETUP_TIMESTAMP + 30 days);
    }

    // ──────────────────────────────────────────────────────────────
    // Fuzz: total counters are monotonic
    // ──────────────────────────────────────────────────────────────

    function testFuzz_totalCounters_monotonic(uint8 nSigns, uint8 nRevokes) public {
        nSigns = uint8(bound(uint256(nSigns), 0, 8));
        nRevokes = uint8(bound(uint256(nRevokes), 0, nSigns));

        uint256 expectedSignings = 0;
        uint256 expectedRevocations = 0;

        // Sign federal gates 0..nSigns-1
        for (uint8 g = 0; g < nSigns; g++) {
            uint8 gateIdx = uint8(bound(uint256(g), 0, reg.FIRST_STATE_GATE() - 1));
            // Skip if same gate index used twice (would conflict)
            if (
                reg.getRecord(SCHOOL_HASH, gateIdx).status == ComplianceRegistry.Status.Signed
            ) continue;

            vm.prank(schoolAdmin);
            reg.recordSigned(
                SCHOOL_HASH, gateIdx, keccak256(abi.encode("env", g)), SETUP_TIMESTAMP + 30 days
            );
            expectedSignings++;
        }
        assertEq(reg.totalSignings(), expectedSignings);

        // Revoke a subset
        for (uint8 g = 0; g < nRevokes; g++) {
            uint8 gateIdx = uint8(bound(uint256(g), 0, reg.FIRST_STATE_GATE() - 1));
            ComplianceRegistry.Status s = reg.getRecord(SCHOOL_HASH, gateIdx).status;
            if (s == ComplianceRegistry.Status.Signed) {
                vm.prank(governance);
                reg.revokeGate(SCHOOL_HASH, gateIdx, keccak256("reason"));
                expectedRevocations++;
            }
        }
        assertEq(reg.totalRevocations(), expectedRevocations);
    }
}
