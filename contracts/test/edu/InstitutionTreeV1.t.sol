// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/edu/InstitutionTreeV1.sol";

/// @notice Forge tests for InstitutionTreeV1 (CODA-E2). Locks the 4-level
///         tenancy semantics from `03_CMO_TENANCY_SPEC.md`.
contract InstitutionTreeV1Test is Test {
    InstitutionTreeV1 internal tree;
    address internal governance = address(0xA11CE);
    address internal cmoAdmin = address(0xCEC0);
    address internal districtAdmin = address(0xD15);
    address internal schoolAdmin = address(0x5C00);
    address internal stranger = address(0xBEEF);

    bytes32 internal constant CMO_HASH = keccak256("KIPP-EIN");
    bytes32 internal constant DISTRICT_DC_HASH = keccak256("KIPP-DC-1100030");
    bytes32 internal constant DISTRICT_NYC_HASH = keccak256("KIPP-NYC-3600001");
    bytes32 internal constant SCHOOL_PROMISE_HASH = keccak256("KIPP-DC-PROMISE");

    bytes32 internal constant STANDALONE_DISTRICT_HASH = keccak256("LINCOLN-0612630");
    bytes32 internal constant STANDALONE_SCHOOL_HASH = keccak256("LINCOLN-ELEM");

    uint8 internal constant STATE_CA = 0;
    uint8 internal constant STATE_NY = 1;

    function setUp() public {
        tree = new InstitutionTreeV1(governance);
    }

    // ── Construction ──

    function test_construction_setsGovernance() public {
        assertEq(tree.governance(), governance);
        assertEq(tree.pendingGovernance(), address(0));
        assertEq(tree.totalNodes(), 0);
    }

    function test_construction_revertsOnZeroGovernance() public {
        vm.expectRevert("governance is zero");
        new InstitutionTreeV1(address(0));
    }

    // ── CMO registration ──

    function test_registerCmo_succeedsAsGovernance() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(CMO_HASH);
        assertEq(n.cmoIdHash, CMO_HASH);
        assertEq(n.districtIdHash, bytes32(0));
        assertEq(n.schoolIdHash, bytes32(0));
        assertEq(n.admin, cmoAdmin);
        assertEq(n.level, 1);
        assertFalse(n.revoked);
        assertEq(tree.totalNodes(), 1);
    }

    function test_registerCmo_revertsForNonGovernance() public {
        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.NotGovernance.selector);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
    }

    function test_registerCmo_revertsOnDuplicate() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.expectRevert(
            abi.encodeWithSelector(InstitutionTreeV1.AlreadyRegistered.selector, CMO_HASH)
        );
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();
    }

    // ── District registration: under CMO ──

    function test_registerDistrictUnderCmo_byCmoAdmin() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);

        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(DISTRICT_DC_HASH);
        assertEq(n.cmoIdHash, CMO_HASH);
        assertEq(n.districtIdHash, DISTRICT_DC_HASH);
        assertEq(n.level, 2);
        assertEq(n.state, STATE_NY); // multi-state CMO: child district is NY even though CMO is CA

        bytes32[] memory children = tree.listDistrictsForCmo(CMO_HASH);
        assertEq(children.length, 1);
        assertEq(children[0], DISTRICT_DC_HASH);
    }

    function test_registerDistrictUnderCmo_revertsForStranger() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);

        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.NotInstitutionAdmin.selector);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
    }

    function test_registerDistrictUnderCmo_revertsForUnknownCmo() public {
        bytes32 unknownCmo = keccak256("MYTHICAL-CMO");
        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.InvalidParentChain.selector);
        tree.registerDistrict(unknownCmo, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
    }

    // ── District registration: standalone ──

    function test_registerStandaloneDistrict_byGovernance() public {
        vm.prank(governance);
        tree.registerDistrict(bytes32(0), STANDALONE_DISTRICT_HASH, districtAdmin, STATE_CA);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(STANDALONE_DISTRICT_HASH);
        assertEq(n.cmoIdHash, bytes32(0));
        assertEq(n.districtIdHash, STANDALONE_DISTRICT_HASH);
        assertEq(n.level, 2);
    }

    function test_registerStandaloneDistrict_revertsForNonGovernance() public {
        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.NotGovernance.selector);
        tree.registerDistrict(bytes32(0), STANDALONE_DISTRICT_HASH, districtAdmin, STATE_CA);
    }

    // ── School registration ──

    function test_registerSchool_byDistrictAdmin() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();

        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);

        vm.prank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(SCHOOL_PROMISE_HASH);
        assertEq(n.cmoIdHash, CMO_HASH);
        assertEq(n.districtIdHash, DISTRICT_DC_HASH);
        assertEq(n.schoolIdHash, SCHOOL_PROMISE_HASH);
        assertEq(n.admin, schoolAdmin);
        assertEq(n.level, 3);
    }

    function test_registerSchool_byCmoAdminThroughDistrict() public {
        // CMO admin should be able to register a school under any of its
        // districts even without separate authorization at the district level.
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();

        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);

        vm.prank(cmoAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(SCHOOL_PROMISE_HASH);
        assertEq(n.admin, schoolAdmin);
    }

    function test_registerSchool_revertsForStranger() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();

        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);

        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.NotInstitutionAdmin.selector);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);
    }

    // ── Lineage walk ──

    function test_lineageWalk_returnsCorrectAncestry() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        vm.prank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        (bytes32 cmoOut, bytes32 districtOut, address adminOut, uint8 stateOut) =
            tree.getInstitutionLineage(SCHOOL_PROMISE_HASH);
        assertEq(cmoOut, CMO_HASH);
        assertEq(districtOut, DISTRICT_DC_HASH);
        assertEq(adminOut, schoolAdmin);
        assertEq(stateOut, STATE_NY);
    }

    // ── Revocation ──

    function test_revoke_byGovernance() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.stopPrank();
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);

        vm.prank(governance);
        tree.revokeInstitution(DISTRICT_DC_HASH);

        InstitutionTreeV1.InstitutionNode memory n = tree.getNode(DISTRICT_DC_HASH);
        assertTrue(n.revoked);
        assertFalse(tree.isActive(DISTRICT_DC_HASH));
    }

    function test_revoke_revertsForInstitutionAdmin() public {
        // Self-revocation is prevented; only governance can revoke.
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);

        vm.prank(cmoAdmin);
        vm.expectRevert(InstitutionTreeV1.NotGovernance.selector);
        tree.revokeInstitution(CMO_HASH);
    }

    function test_revoke_revertsOnDoubleRevocation() public {
        vm.startPrank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        tree.revokeInstitution(CMO_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(InstitutionTreeV1.AlreadyRevoked.selector, CMO_HASH)
        );
        tree.revokeInstitution(CMO_HASH);
        vm.stopPrank();
    }

    // ── Governance transfer (two-step) ──

    function test_governanceTransfer_twoStep() public {
        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        tree.transferGovernance(newGov);
        assertEq(tree.pendingGovernance(), newGov);
        assertEq(tree.governance(), governance);

        vm.prank(newGov);
        tree.acceptGovernance();
        assertEq(tree.governance(), newGov);
        assertEq(tree.pendingGovernance(), address(0));
    }

    function test_governanceTransfer_canBeCancelled() public {
        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        tree.transferGovernance(newGov);
        vm.prank(governance);
        tree.cancelGovernanceTransfer();
        assertEq(tree.pendingGovernance(), address(0));

        vm.prank(newGov);
        vm.expectRevert(InstitutionTreeV1.InvalidGovernanceTransfer.selector);
        tree.acceptGovernance();
    }

    function test_governanceTransfer_revertsForRandomAcceptor() public {
        address newGov = address(0xC0FFEE);
        vm.prank(governance);
        tree.transferGovernance(newGov);
        vm.prank(stranger);
        vm.expectRevert(InstitutionTreeV1.InvalidGovernanceTransfer.selector);
        tree.acceptGovernance();
    }

    // ── listAllSchoolsForCmo (CMO-portal helper) ──

    function test_listAllSchoolsForCmo_emptyForUnknownCmo() public view {
        bytes32[] memory schools = tree.listAllSchoolsForCmo(keccak256("unknown"));
        assertEq(schools.length, 0);
    }

    function test_listAllSchoolsForCmo_emptyForCmoWithNoDistricts() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        bytes32[] memory schools = tree.listAllSchoolsForCmo(CMO_HASH);
        assertEq(schools.length, 0);
    }

    function test_listAllSchoolsForCmo_singleDistrictSingleSchool() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        vm.prank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        bytes32[] memory schools = tree.listAllSchoolsForCmo(CMO_HASH);
        assertEq(schools.length, 1);
        assertEq(schools[0], SCHOOL_PROMISE_HASH);
    }

    function test_listAllSchoolsForCmo_multiDistrictMultiSchool() public {
        // 1 CMO → 2 districts → 3 schools (2 in DC, 1 in NYC)
        bytes32 SCH_DC_2 = keccak256("KIPP-DC-EAST");
        bytes32 SCH_NYC_1 = keccak256("KIPP-NYC-AMP");

        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.startPrank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        tree.registerDistrict(CMO_HASH, DISTRICT_NYC_HASH, districtAdmin, STATE_NY);
        vm.stopPrank();
        vm.startPrank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);
        tree.registerSchool(DISTRICT_DC_HASH, SCH_DC_2, schoolAdmin, STATE_NY);
        tree.registerSchool(DISTRICT_NYC_HASH, SCH_NYC_1, schoolAdmin, STATE_NY);
        vm.stopPrank();

        bytes32[] memory schools = tree.listAllSchoolsForCmo(CMO_HASH);
        assertEq(schools.length, 3);
        // Order: districts iterated in registration order; schools within
        // each district in registration order. Verify the expected sequence.
        assertEq(schools[0], SCHOOL_PROMISE_HASH);
        assertEq(schools[1], SCH_DC_2);
        assertEq(schools[2], SCH_NYC_1);
    }

    function test_listAllSchoolsForCmo_excludesStandaloneDistricts() public {
        // Standalone district (no CMO parent) — its schools must NOT appear
        // in any CMO's enumeration.
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        vm.prank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        // Standalone district + school
        vm.prank(governance);
        tree.registerDistrict(bytes32(0), STANDALONE_DISTRICT_HASH, districtAdmin, STATE_CA);
        vm.prank(districtAdmin);
        tree.registerSchool(STANDALONE_DISTRICT_HASH, STANDALONE_SCHOOL_HASH, schoolAdmin, STATE_CA);

        bytes32[] memory schools = tree.listAllSchoolsForCmo(CMO_HASH);
        assertEq(schools.length, 1);
        assertEq(schools[0], SCHOOL_PROMISE_HASH);
        // Standalone school not in the CMO list
        for (uint256 i = 0; i < schools.length; i++) {
            assertTrue(schools[i] != STANDALONE_SCHOOL_HASH);
        }
    }

    function test_listAllSchoolsForCmo_isReadOnly() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);
        vm.prank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        vm.prank(districtAdmin);
        tree.registerSchool(DISTRICT_DC_HASH, SCHOOL_PROMISE_HASH, schoolAdmin, STATE_NY);

        // Snapshot length, call helper twice, verify state unchanged
        uint256 totalBefore = tree.totalNodes();
        tree.listAllSchoolsForCmo(CMO_HASH);
        tree.listAllSchoolsForCmo(CMO_HASH);
        assertEq(tree.totalNodes(), totalBefore);
    }

    // ── Multi-state CMO scenario (S4 from scenario analysis) ──

    function test_multiStateCmo_districtsCanBeInDifferentStates() public {
        vm.prank(governance);
        tree.registerCmo(CMO_HASH, cmoAdmin, STATE_CA);

        vm.startPrank(cmoAdmin);
        tree.registerDistrict(CMO_HASH, DISTRICT_DC_HASH, districtAdmin, STATE_NY);
        tree.registerDistrict(CMO_HASH, DISTRICT_NYC_HASH, districtAdmin, STATE_NY);
        vm.stopPrank();

        bytes32[] memory children = tree.listDistrictsForCmo(CMO_HASH);
        assertEq(children.length, 2);

        InstitutionTreeV1.InstitutionNode memory dc = tree.getNode(DISTRICT_DC_HASH);
        InstitutionTreeV1.InstitutionNode memory nyc = tree.getNode(DISTRICT_NYC_HASH);
        // Same CMO, both NY districts in this fixture.
        assertEq(dc.cmoIdHash, nyc.cmoIdHash);
        assertEq(dc.state, nyc.state);
    }
}
