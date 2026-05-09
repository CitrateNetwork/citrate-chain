// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MoqRegistry} from "../../src/boeing/MoqRegistry.sol";

contract MoqRegistryTest is Test {
    MoqRegistry internal r;

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    bytes32 constant COMM_A = keccak256("commitment-A");
    bytes32 constant COMM_B = keccak256("commitment-B");
    bytes32 constant SUP_A = keccak256("supplier-A");
    bytes32 constant SUP_B = keccak256("supplier-B");
    bytes32 constant FAMILY = keccak256("family-fasteners");
    bytes32 constant PROG_777X = keccak256("777x");
    bytes32 constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 constant USER = keccak256("user-1");
    bytes32 constant CORR = keccak256("corr-1");

    function setUp() public {
        r = new MoqRegistry(governance);
        vm.prank(governance);
        r.setRecorder(recorder, true);
    }

    function _commit(bytes32 cid, bytes32 sup, uint128 qty) internal {
        vm.prank(recorder);
        r.recordCommitment(cid, sup, FAMILY, PROG_777X, SCOPE_BCA, qty, 100, 200);
    }

    // ── Constructor ──────────────────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(MoqRegistry.ZeroGovernance.selector);
        new MoqRegistry(address(0));
    }

    // ── recordCommitment ─────────────────────────────────────────────

    function test_recordCommitment_basic_flow() public {
        _commit(COMM_A, SUP_A, 1000);
        MoqRegistry.Commitment memory c = r.commitment(COMM_A);
        assertEq(c.commit_qty, 1000);
        assertTrue(c.exists);
    }

    function test_recordCommitment_rejects_non_recorder() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(MoqRegistry.NotRecorder.selector, stranger)
        );
        r.recordCommitment(COMM_A, SUP_A, FAMILY, PROG_777X, SCOPE_BCA, 1000, 100, 200);
    }

    function test_recordCommitment_rejects_duplicate() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                MoqRegistry.CommitmentAlreadyExists.selector,
                COMM_A
            )
        );
        r.recordCommitment(COMM_A, SUP_A, FAMILY, PROG_777X, SCOPE_BCA, 999, 100, 200);
    }

    function test_recordCommitment_rejects_invalid_period() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(MoqRegistry.PeriodInvalid.selector, 200, 100)
        );
        r.recordCommitment(COMM_A, SUP_A, FAMILY, PROG_777X, SCOPE_BCA, 1000, 200, 100);
    }

    function test_recordCommitment_indexes_by_supplier() public {
        _commit(COMM_A, SUP_A, 1000);
        _commit(COMM_B, SUP_A, 2000);
        assertEq(r.bySupplier(SUP_A).length, 2);
    }

    function test_recordCommitment_indexes_by_scope_program() public {
        _commit(COMM_A, SUP_A, 1000);
        bytes32[] memory list = r.list(SCOPE_BCA, PROG_777X);
        assertEq(list.length, 1);
    }

    // ── recordDraw ───────────────────────────────────────────────────

    function test_recordDraw_basic_flow() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.prank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 500, CORR, USER);
        MoqRegistry.Draw[] memory ds = r.draws(COMM_A);
        assertEq(ds.length, 1);
        assertEq(ds[0].qty, 500);
    }

    function test_recordDraw_rejects_unknown_commitment() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                MoqRegistry.CommitmentDoesNotExist.selector,
                COMM_A
            )
        );
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 500, CORR, USER);
    }

    function test_recordDraw_appendonly_no_mutation() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.prank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 500, CORR, USER);
        MoqRegistry.Draw[] memory before_ = r.draws(COMM_A);

        // Record another draw — first one untouched.
        vm.prank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, 480, CORR, USER);
        MoqRegistry.Draw[] memory after_ = r.draws(COMM_A);
        assertEq(after_.length, 2);
        assertEq(after_[0].qty, before_[0].qty);
        assertEq(after_[0].ts, before_[0].ts);
    }

    // ── aggregateDraws + Belnap ──────────────────────────────────────

    function test_aggregateDraws_sums_per_source() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.startPrank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 300, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 200, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, 500, CORR, USER);
        vm.stopPrank();
        (uint128 sup, uint128 rec) = r.aggregateDraws(COMM_A);
        assertEq(sup, 500);
        assertEq(rec, 500);
    }

    function test_belnap_n_when_no_draws() public {
        _commit(COMM_A, SUP_A, 1000);
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.N));
    }

    function test_belnap_b_when_sources_disagree() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.startPrank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 1000, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, 800, CORR, USER);
        vm.stopPrank();
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.B));
    }

    function test_belnap_b_when_one_source_missing() public {
        _commit(COMM_A, SUP_A, 1000);
        vm.prank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 1000, CORR, USER);
        // Receiving never reported → B (single-source disagreement).
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.B));
    }

    function test_belnap_t_when_within_threshold() public {
        _commit(COMM_A, SUP_A, 1000);
        // Both sources report 980 → variance 2% = 200bps; threshold 500bps → T.
        vm.startPrank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 980, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, 980, CORR, USER);
        vm.stopPrank();
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.T));
    }

    function test_belnap_f_when_outside_threshold() public {
        _commit(COMM_A, SUP_A, 1000);
        // Both report 800 → variance 20% = 2000bps; threshold 500bps → F.
        vm.startPrank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, 800, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, 800, CORR, USER);
        vm.stopPrank();
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.F));
    }

    function test_belnap_default_threshold_is_500_bps() public {
        assertEq(r.DEFAULT_VARIANCE_THRESHOLD_BPS(), 500);
    }

    function test_belnap_unknown_commitment_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                MoqRegistry.CommitmentDoesNotExist.selector,
                COMM_A
            )
        );
        r.belnap(COMM_A, 500);
    }

    // ── List views ───────────────────────────────────────────────────

    function test_list_by_scope_program() public {
        _commit(COMM_A, SUP_A, 1000);
        _commit(COMM_B, SUP_B, 2000);
        bytes32[] memory list = r.list(SCOPE_BCA, PROG_777X);
        assertEq(list.length, 2);
    }

    function test_commitmentCount_grows() public {
        assertEq(r.commitmentCount(), 0);
        _commit(COMM_A, SUP_A, 1000);
        assertEq(r.commitmentCount(), 1);
    }

    // ── Fuzz ─────────────────────────────────────────────────────────

    function testFuzz_recordCommitment_indexes_by_supplier(bytes32 cid, bytes32 sup) public {
        vm.assume(cid != bytes32(0));
        uint256 before_ = r.bySupplier(sup).length;
        vm.prank(recorder);
        r.recordCommitment(cid, sup, FAMILY, PROG_777X, SCOPE_BCA, 1000, 100, 200);
        assertEq(r.bySupplier(sup).length, before_ + 1);
    }

    function testFuzz_belnap_b_when_sup_ne_rec(uint64 sup_qty, uint64 rec_qty) public {
        vm.assume(sup_qty > 0 && rec_qty > 0 && sup_qty != rec_qty);
        _commit(COMM_A, SUP_A, 1000);
        vm.startPrank(recorder);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.SupplierReported, sup_qty, CORR, USER);
        r.recordDraw(COMM_A, MoqRegistry.DrawSource.ReceivingAttested, rec_qty, CORR, USER);
        vm.stopPrank();
        assertEq(uint8(r.belnap(COMM_A, 500)), uint8(MoqRegistry.Belnap.B));
    }
}
