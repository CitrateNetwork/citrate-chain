// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";

/// @notice End-to-end integration test for the InstitutionTreeV1 +
///         ComplianceRegistry pair. Models a realistic multi-state CMO
///         operating across all 5 state-specific compliance regimes, with
///         schools signing some gates, expiring some, revoking some, and
///         re-signing. Verifies that the matrix view the GUI consumes
///         matches the expected end-state.
///
///         The test is deliberately long-form rather than parameterized
///         because each signing decision is policy-meaningful and we want
///         the assertion sequence to read like an audit log.
contract ComplianceIntegrationTest is Test {
    InstitutionTreeV1 internal tree;
    ComplianceRegistry internal reg;

    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);

    // 5 schools, one per state-specific gate
    address internal caAdmin = address(0x5C0AAA);
    address internal nyAdmin = address(0x5C0BBB);
    address internal ilAdmin = address(0x5C0CCC);
    address internal txAdmin = address(0x5C0DDD);
    address internal coAdmin = address(0x5C0EEE);

    bytes32 internal constant CMO_HASH = keccak256("INTG-CMO");
    bytes32 internal constant DIST_HASH = keccak256("INTG-DIST");

    bytes32 internal constant SCH_CA = keccak256("INTG-CA");
    bytes32 internal constant SCH_NY = keccak256("INTG-NY");
    bytes32 internal constant SCH_IL = keccak256("INTG-IL");
    bytes32 internal constant SCH_TX = keccak256("INTG-TX");
    bytes32 internal constant SCH_CO = keccak256("INTG-CO");

    uint8 internal constant STATE_CA = 0;
    uint8 internal constant STATE_NY = 1;
    uint8 internal constant STATE_IL = 2;
    uint8 internal constant STATE_TX = 3;
    uint8 internal constant STATE_CO = 4;

    uint8 internal constant G_DPA = 0;
    uint8 internal constant G_FERPA = 1;
    uint8 internal constant G_COPPA = 2;
    uint8 internal constant G_CIPA = 3;
    uint8 internal constant G_CA = 4;
    uint8 internal constant G_NY = 5;
    uint8 internal constant G_IL = 6;
    uint8 internal constant G_TX = 7;
    uint8 internal constant G_CO = 8;

    uint64 internal constant T0 = 1_700_000_000;

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
        reg = new ComplianceRegistry(governance, address(tree));

        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DIST_HASH, districtAdmin, STATE_CA);
        // 5 schools, each in a different state — exercises all state-gate paths
        vm.startPrank(districtAdmin);
        tree.registerSchool(DIST_HASH, SCH_CA, caAdmin, STATE_CA);
        tree.registerSchool(DIST_HASH, SCH_NY, nyAdmin, STATE_NY);
        tree.registerSchool(DIST_HASH, SCH_IL, ilAdmin, STATE_IL);
        tree.registerSchool(DIST_HASH, SCH_TX, txAdmin, STATE_TX);
        tree.registerSchool(DIST_HASH, SCH_CO, coAdmin, STATE_CO);
        vm.stopPrank();

        vm.warp(T0);
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: a healthy CMO with all schools fully compliant
    // ──────────────────────────────────────────────────────────────

    function test_e2e_allSchoolsFullyCompliant() public {
        // Each school signs its 4 federal gates + 1 state-specific gate
        _signFullCompliance(SCH_CA, caAdmin, G_CA);
        _signFullCompliance(SCH_NY, nyAdmin, G_NY);
        _signFullCompliance(SCH_IL, ilAdmin, G_IL);
        _signFullCompliance(SCH_TX, txAdmin, G_TX);
        _signFullCompliance(SCH_CO, coAdmin, G_CO);

        // 5 schools × 5 active gates each = 25 signings
        assertEq(reg.totalSignings(), 25);
        assertEq(reg.totalRevocations(), 0);

        // Each school's matrix has exactly 5 Signed cells + 4 NotApplicable cells
        _assertMatrixForState(SCH_CA, G_CA);
        _assertMatrixForState(SCH_NY, G_NY);
        _assertMatrixForState(SCH_IL, G_IL);
        _assertMatrixForState(SCH_TX, G_TX);
        _assertMatrixForState(SCH_CO, G_CO);

        // isCompliant returns true for every applicable gate
        for (uint8 g = 0; g < reg.GATE_COUNT(); g++) {
            if (g < reg.FIRST_STATE_GATE() || g == G_CA) {
                assertTrue(reg.isCompliant(SCH_CA, g));
            } else {
                assertFalse(reg.isCompliant(SCH_CA, g));
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: realistic time-slip — DPA expires, CIPA revoked under audit
    // ──────────────────────────────────────────────────────────────

    function test_e2e_realisticTimeSlipAndRecovery() public {
        // CA school signs full compliance with 30-day DPA, 1-yr others
        vm.startPrank(caAdmin);
        reg.recordSigned(SCH_CA, G_DPA, keccak256("env-dpa"), T0 + 30 days);
        reg.recordSigned(SCH_CA, G_FERPA, keccak256("env-ferpa"), T0 + 365 days);
        reg.recordSigned(SCH_CA, G_COPPA, keccak256("env-coppa"), T0 + 365 days);
        reg.recordSigned(SCH_CA, G_CIPA, keccak256("env-cipa"), T0 + 365 days);
        reg.recordSigned(SCH_CA, G_CA, keccak256("env-ca"), T0 + 365 days);
        vm.stopPrank();

        // Walk forward 31 days — DPA expires
        vm.warp(T0 + 31 days);

        // The matrix already shows Signed for DPA but isCompliant=false (timestamp-aware)
        assertFalse(reg.isCompliant(SCH_CA, G_DPA));
        // Other gates still compliant
        assertTrue(reg.isCompliant(SCH_CA, G_FERPA));
        assertTrue(reg.isCompliant(SCH_CA, G_CIPA));

        // Keeper sweeps the expired DPA
        reg.expireGate(SCH_CA, G_DPA);
        assertEq(
            uint8(reg.getRecord(SCH_CA, G_DPA).status),
            uint8(ComplianceRegistry.Status.Expired)
        );

        // Now the audit hits — governance revokes CIPA after a finding
        bytes32 reasonHash = keccak256("audit:CIPA-non-compliance-2026-Q2");
        vm.prank(governance);
        reg.revokeGate(SCH_CA, G_CIPA, reasonHash);
        assertEq(
            uint8(reg.getRecord(SCH_CA, G_CIPA).status),
            uint8(ComplianceRegistry.Status.Revoked)
        );
        assertFalse(reg.isCompliant(SCH_CA, G_CIPA));

        // School re-signs DPA (post-expire) and CIPA (post-revoke)
        uint64 t1 = T0 + 31 days;
        vm.startPrank(caAdmin);
        reg.recordSigned(SCH_CA, G_DPA, keccak256("env-dpa-v2"), t1 + 30 days);
        reg.recordSigned(SCH_CA, G_CIPA, keccak256("env-cipa-v2"), t1 + 365 days);
        vm.stopPrank();

        // Both back to compliant
        assertTrue(reg.isCompliant(SCH_CA, G_DPA));
        assertTrue(reg.isCompliant(SCH_CA, G_CIPA));

        // Counters: 5 initial signings + 2 re-signings = 7 total; 1 revocation
        assertEq(reg.totalSignings(), 7);
        assertEq(reg.totalRevocations(), 1);

        // Envelope hashes were updated, not appended (single record per cell)
        assertEq(reg.getRecord(SCH_CA, G_DPA).envelopeIdHash, keccak256("env-dpa-v2"));
        assertEq(reg.getRecord(SCH_CA, G_CIPA).envelopeIdHash, keccak256("env-cipa-v2"));
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: GUI matrix-render scenario (worst-cell-wins per E6.3)
    // ──────────────────────────────────────────────────────────────

    function test_e2e_guiMatrixRender_worstCellComputedOffChain() public {
        // 3-school portfolio with mixed compliance:
        //   - CA: all green
        //   - NY: DPA pending (untouched in v1), others green
        //   - IL: CIPA expired

        // CA: full compliance
        _signFullCompliance(SCH_CA, caAdmin, G_CA);

        // NY: only sign 3 of 4 federal + 1 state — DPA stays Untouched
        vm.startPrank(nyAdmin);
        reg.recordSigned(SCH_NY, G_FERPA, keccak256("env"), T0 + 365 days);
        reg.recordSigned(SCH_NY, G_COPPA, keccak256("env"), T0 + 365 days);
        reg.recordSigned(SCH_NY, G_CIPA, keccak256("env"), T0 + 365 days);
        reg.recordSigned(SCH_NY, G_NY, keccak256("env"), T0 + 365 days);
        vm.stopPrank();

        // IL: full compliance, then CIPA expires
        _signFullCompliance(SCH_IL, ilAdmin, G_IL);
        // Don't expire yet — we'll do that after time advances

        // Walk to T0 + 366 days (post the 365-day expiry of all 1-yr signings)
        vm.warp(T0 + 366 days);

        // IL's CIPA is now past expiry. Sweep it.
        reg.expireGate(SCH_IL, G_CIPA);

        // The "worst-cell-wins" semantic the GUI computes off-chain:
        //   CA matrix: 5 Signed (but all expired now since 1yr+ has passed) + 4 NotApplicable
        //   NY matrix: DPA Untouched + 3 Signed (expired) + NY Signed (expired) + 4 NotApplicable
        //   IL matrix: 4 federal Signed (3 still valid? no — 365 days passed, all expired) + IL Signed (expired) + CIPA Expired + others NotApplicable
        //
        // For simplicity here we just verify the cells exist with the right
        // statuses; the GUI's color-coding is its job.
        ComplianceRegistry.Record[9] memory caMx = reg.getSchoolMatrix(SCH_CA);
        ComplianceRegistry.Record[9] memory nyMx = reg.getSchoolMatrix(SCH_NY);
        ComplianceRegistry.Record[9] memory ilMx = reg.getSchoolMatrix(SCH_IL);

        // Spot checks
        assertEq(uint8(caMx[G_DPA].status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(uint8(nyMx[G_DPA].status), uint8(ComplianceRegistry.Status.Untouched));
        assertEq(uint8(ilMx[G_CIPA].status), uint8(ComplianceRegistry.Status.Expired));

        // Cross-school applicability invariant: CA cell on NY school is N/A
        assertEq(uint8(nyMx[G_CA].status), uint8(ComplianceRegistry.Status.NotApplicable));
        // NY cell on CA school is N/A
        assertEq(uint8(caMx[G_NY].status), uint8(ComplianceRegistry.Status.NotApplicable));
        // IL cell on CA school is N/A
        assertEq(uint8(caMx[G_IL].status), uint8(ComplianceRegistry.Status.NotApplicable));
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: school is removed mid-flight at the tree level
    // ──────────────────────────────────────────────────────────────

    function test_e2e_schoolTreeRevocation_disablesFurtherSigning() public {
        _signFullCompliance(SCH_NY, nyAdmin, G_NY);
        // NY closes mid-year — governance revokes at tree level
        vm.prank(governance);
        tree.revokeInstitution(SCH_NY);

        // Records remain in storage for forensic visibility
        ComplianceRegistry.Record memory r = reg.getRecord(SCH_NY, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        // But isCompliant returns false because school is revoked
        assertFalse(reg.isCompliant(SCH_NY, G_DPA));
        assertFalse(reg.isCompliant(SCH_NY, G_NY));

        // Admin cannot sign new gates for the revoked school
        vm.prank(nyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(ComplianceRegistry.SchoolRevoked.selector, SCH_NY)
        );
        reg.recordSigned(SCH_NY, G_FERPA, keccak256("env"), T0 + 30 days);

        // Other schools unaffected
        assertEq(
            uint8(reg.getRecord(SCH_CA, G_DPA).status),
            uint8(ComplianceRegistry.Status.Untouched)
        );
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: governance hand-off mid-portfolio
    // ──────────────────────────────────────────────────────────────

    function test_e2e_governanceHandoff_mid_portfolio() public {
        _signFullCompliance(SCH_CA, caAdmin, G_CA);
        _signFullCompliance(SCH_NY, nyAdmin, G_NY);

        // Hand off governance
        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        reg.transferGovernance(newGov);
        vm.prank(newGov);
        reg.acceptGovernance();

        // Old governance is now powerless
        vm.prank(governance);
        vm.expectRevert(ComplianceRegistry.NotGovernance.selector);
        reg.revokeGate(SCH_CA, G_DPA, keccak256("reason"));

        // New governance can revoke
        vm.prank(newGov);
        reg.revokeGate(SCH_CA, G_DPA, keccak256("reason"));
        assertEq(reg.totalRevocations(), 1);

        // Pre-handoff signings still in counters (monotonic)
        assertEq(reg.totalSignings(), 10);

        // School's other gates still valid (handoff doesn't touch records)
        assertTrue(reg.isCompliant(SCH_CA, G_FERPA));
        assertTrue(reg.isCompliant(SCH_NY, G_NY));
    }

    // ──────────────────────────────────────────────────────────────
    // E2E: full re-cycle of a single gate (sign → expire → sign → revoke → sign)
    // ──────────────────────────────────────────────────────────────

    function test_e2e_fullRecycleOfOneGate() public {
        // Initial sign
        vm.prank(caAdmin);
        reg.recordSigned(SCH_CA, G_DPA, keccak256("env-1"), T0 + 30 days);

        // Expire after 30 days
        vm.warp(T0 + 30 days + 1);
        reg.expireGate(SCH_CA, G_DPA);

        // Re-sign
        uint64 t1 = uint64(block.timestamp);
        vm.prank(caAdmin);
        reg.recordSigned(SCH_CA, G_DPA, keccak256("env-2"), t1 + 60 days);

        // Governance revokes (audit)
        vm.prank(governance);
        reg.revokeGate(SCH_CA, G_DPA, keccak256("audit-finding"));

        // Re-sign post-revoke
        vm.prank(caAdmin);
        reg.recordSigned(SCH_CA, G_DPA, keccak256("env-3"), t1 + 30 days);

        ComplianceRegistry.Record memory r = reg.getRecord(SCH_CA, G_DPA);
        assertEq(uint8(r.status), uint8(ComplianceRegistry.Status.Signed));
        assertEq(r.envelopeIdHash, keccak256("env-3"));
        assertTrue(reg.isCompliant(SCH_CA, G_DPA));

        // Counters: 3 signings, 1 revocation
        assertEq(reg.totalSignings(), 3);
        assertEq(reg.totalRevocations(), 1);
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    function _signFullCompliance(bytes32 schoolHash, address admin, uint8 stateGateIdx) internal {
        vm.startPrank(admin);
        reg.recordSigned(schoolHash, G_DPA, keccak256(abi.encode(schoolHash, "dpa")), T0 + 365 days);
        reg.recordSigned(schoolHash, G_FERPA, keccak256(abi.encode(schoolHash, "ferpa")), T0 + 365 days);
        reg.recordSigned(schoolHash, G_COPPA, keccak256(abi.encode(schoolHash, "coppa")), T0 + 365 days);
        reg.recordSigned(schoolHash, G_CIPA, keccak256(abi.encode(schoolHash, "cipa")), T0 + 365 days);
        reg.recordSigned(schoolHash, stateGateIdx, keccak256(abi.encode(schoolHash, "state")), T0 + 365 days);
        vm.stopPrank();
    }

    function _assertMatrixForState(bytes32 schoolHash, uint8 stateGateIdx) internal view {
        ComplianceRegistry.Record[9] memory mx = reg.getSchoolMatrix(schoolHash);
        // 4 federal gates: Signed
        for (uint8 g = 0; g < reg.FIRST_STATE_GATE(); g++) {
            assertEq(uint8(mx[g].status), uint8(ComplianceRegistry.Status.Signed));
        }
        // State gates: stateGateIdx Signed, others NotApplicable
        for (uint8 g = reg.FIRST_STATE_GATE(); g < reg.GATE_COUNT(); g++) {
            if (g == stateGateIdx) {
                assertEq(uint8(mx[g].status), uint8(ComplianceRegistry.Status.Signed));
            } else {
                assertEq(uint8(mx[g].status), uint8(ComplianceRegistry.Status.NotApplicable));
            }
        }
    }
}
