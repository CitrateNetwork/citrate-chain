// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {DefensePrimeComplianceRegistry} from "../../src/defense_prime/DefensePrimeComplianceRegistry.sol";

contract DefensePrimeComplianceRegistryTest is Test {
    DefensePrimeComplianceRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant SCOPE_UNIT = keccak256("scope-unit");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 internal constant FW_FEDRAMP = keccak256("FedRAMP-Moderate");
    bytes32 internal constant FW_CMMC = keccak256("CMMC L2");
    bytes32 internal constant CID = keccak256("ipfs-cid");

    uint8 internal constant POSTURE_IN_PROGRESS = 1;
    uint8 internal constant POSTURE_ATTESTED = 2;
    uint8 internal constant POSTURE_EXCEPTION = 3;
    uint8 internal constant POSTURE_FAILED = 4;

    event RecorderSet(address indexed recorder, bool authorized);
    event Attested(
        bytes32 indexed row_id,
        bytes32 indexed framework,
        bytes32 indexed scope,
        uint8 posture,
        bytes32 evidence_cid,
        uint256 expires_at_block
    );
    event Expired(bytes32 indexed row_id);

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new DefensePrimeComplianceRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    // ── Constructor / governance ────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(DefensePrimeComplianceRegistry.ZeroGovernance.selector);
        new DefensePrimeComplianceRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(DefensePrimeComplianceRegistry.NotGovernance.selector, nobody)
        );
        reg.setRecorder(nobody, true);
    }

    function test_setRecorder_can_revoke() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        assertFalse(reg.is_recorder(recorder));
    }

    // ── attest input validation ─────────────────────────────────────

    function test_attest_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(DefensePrimeComplianceRegistry.NotRecorder.selector, nobody)
        );
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 0);
    }

    function test_attest_rejects_zero_framework() public {
        vm.prank(recorder);
        vm.expectRevert(DefensePrimeComplianceRegistry.ZeroFramework.selector);
        reg.attest(bytes32(0), SCOPE_UNIT, POSTURE_ATTESTED, CID, 0);
    }

    function test_attest_rejects_zero_scope() public {
        vm.prank(recorder);
        vm.expectRevert(DefensePrimeComplianceRegistry.ZeroScope.selector);
        reg.attest(FW_FEDRAMP, bytes32(0), POSTURE_ATTESTED, CID, 0);
    }

    function test_attest_rejects_invalid_posture_zero() public {
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(DefensePrimeComplianceRegistry.InvalidPosture.selector, 0));
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, 0, CID, 0);
    }

    function test_attest_rejects_invalid_posture_five() public {
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(DefensePrimeComplianceRegistry.InvalidPosture.selector, 5));
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, 5, CID, 0);
    }

    // ── Initial attest (NotAttempted → x) ──────────────────────────

    function test_attest_first_time_in_progress_succeeds() public {
        vm.prank(recorder);
        bytes32 row_id = reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        assertEq(reg.getRow(row_id).posture, POSTURE_IN_PROGRESS);
    }

    function test_attest_first_time_attested_fast_path_succeeds() public {
        vm.prank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_ATTESTED);
    }

    function test_attest_first_time_exception_disallowed() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeComplianceRegistry.DisallowedTransition.selector,
                0,
                POSTURE_EXCEPTION
            )
        );
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_EXCEPTION, CID, 0);
    }

    function test_attest_first_time_failed_disallowed() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeComplianceRegistry.DisallowedTransition.selector,
                0,
                POSTURE_FAILED
            )
        );
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
    }

    // ── Allowed-transition graph (canonical TLA+ paths) ────────────

    function test_in_progress_to_attested_allowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_ATTESTED);
    }

    function test_in_progress_to_failed_allowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_FAILED);
    }

    function test_attested_to_exception_allowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_EXCEPTION, CID, 1000);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_EXCEPTION);
    }

    function test_attested_to_in_progress_allowed_recertification() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_IN_PROGRESS);
    }

    function test_failed_to_in_progress_allowed_corrective() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_IN_PROGRESS);
    }

    function test_failed_to_attested_disallowed_no_corrective() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeComplianceRegistry.DisallowedTransition.selector,
                POSTURE_FAILED,
                POSTURE_ATTESTED
            )
        );
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        vm.stopPrank();
    }

    function test_exception_to_failed_allowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_EXCEPTION, CID, 1000);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
        vm.stopPrank();
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(reg.getRow(row_id).posture, POSTURE_FAILED);
    }

    // ── Append-only indices ─────────────────────────────────────────

    function test_indices_grow_per_attest() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        reg.attest(FW_CMMC, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        vm.stopPrank();

        assertEq(reg.rowCount(), 3);
        assertEq(reg.rowCountByScope(SCOPE_UNIT), 3);
        bytes32[] memory ids = reg.rowsByScopeList(SCOPE_UNIT);
        assertEq(ids.length, 3);
    }

    function test_indices_isolated_per_scope() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_BDS, POSTURE_ATTESTED, CID, 0);
        vm.stopPrank();
        assertEq(reg.rowCountByScope(SCOPE_UNIT), 1);
        assertEq(reg.rowCountByScope(SCOPE_BDS), 1);
        assertEq(reg.rowCount(), 2);
    }

    function test_rowsByFrameworkList_populates() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_BDS, POSTURE_ATTESTED, CID, 0);
        reg.attest(FW_CMMC, SCOPE_UNIT, POSTURE_ATTESTED, CID, 0);
        vm.stopPrank();
        assertEq(reg.rowsByFrameworkList(FW_FEDRAMP).length, 2);
        assertEq(reg.rowsByFrameworkList(FW_CMMC).length, 1);
    }

    function test_framework_returns_latest_row() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        vm.stopPrank();
        DefensePrimeComplianceRegistry.Row memory row = reg.framework(FW_FEDRAMP, SCOPE_UNIT);
        assertEq(row.posture, POSTURE_ATTESTED);
        assertEq(row.expires_at_block, 1000);
    }

    function test_attested_emits_event() public {
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        vm.expectEmit(true, true, true, true);
        emit Attested(row_id, FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        vm.prank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
    }

    function test_attest_records_block_number_and_attestor() public {
        vm.roll(98765);
        vm.prank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 100000);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        DefensePrimeComplianceRegistry.Row memory r = reg.getRow(row_id);
        assertEq(r.attested_at_block, 98765);
        assertEq(r.attestor, bytes32(uint256(uint160(recorder))));
    }

    // ── Expire ──────────────────────────────────────────────────────

    function test_expire_only_recorder() public {
        vm.prank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(DefensePrimeComplianceRegistry.NotRecorder.selector, nobody)
        );
        reg.expire(row_id);
    }

    function test_expire_marks_row() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        reg.expire(row_id);
        vm.stopPrank();
        assertTrue(reg.getRow(row_id).expired);
        assertEq(reg.getRow(row_id).posture, POSTURE_ATTESTED); // unchanged
    }

    function test_expire_exception_allowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_ATTESTED, CID, 1000);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_EXCEPTION, CID, 1000);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        reg.expire(row_id);
        vm.stopPrank();
        assertTrue(reg.getRow(row_id).expired);
    }

    function test_expire_in_progress_disallowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeComplianceRegistry.DisallowedTransition.selector,
                POSTURE_IN_PROGRESS,
                POSTURE_IN_PROGRESS
            )
        );
        reg.expire(row_id);
        vm.stopPrank();
    }

    function test_expire_failed_disallowed() public {
        vm.startPrank(recorder);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_IN_PROGRESS, CID, 0);
        reg.attest(FW_FEDRAMP, SCOPE_UNIT, POSTURE_FAILED, CID, 0);
        bytes32 row_id = reg.rowIdFor(FW_FEDRAMP, SCOPE_UNIT);
        vm.expectRevert(
            abi.encodeWithSelector(
                DefensePrimeComplianceRegistry.DisallowedTransition.selector,
                POSTURE_FAILED,
                POSTURE_FAILED
            )
        );
        reg.expire(row_id);
        vm.stopPrank();
    }
}
