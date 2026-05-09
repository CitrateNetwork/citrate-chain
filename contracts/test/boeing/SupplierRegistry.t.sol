// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {SupplierRegistry} from "../../src/boeing/SupplierRegistry.sol";

contract SupplierRegistryTest is Test {
    SupplierRegistry internal r;

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    bytes32 constant SUP_A = keccak256("supplier-A");
    bytes32 constant SUP_B = keccak256("supplier-B");
    bytes32 constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 constant USER = keccak256("user-1");
    bytes32 constant CORR = keccak256("corr-1");

    function setUp() public {
        r = new SupplierRegistry(governance);
        vm.prank(governance);
        r.setRecorder(recorder, true);
    }

    function _register(bytes32 sup, bytes32 scope) internal {
        vm.prank(recorder);
        r.register(sup, scope, 365, CORR, USER);
    }

    function _setState(bytes32 sup, SupplierRegistry.State to_, address caller) internal {
        vm.prank(caller);
        r.setState(sup, to_, CORR, USER, "transition");
    }

    // ── Constructor / governance ─────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(SupplierRegistry.ZeroGovernance.selector);
        new SupplierRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SupplierRegistry.NotGovernance.selector, stranger)
        );
        r.setRecorder(stranger, true);
    }

    // ── register ─────────────────────────────────────────────────────

    function test_register_basic_flow() public {
        _register(SUP_A, SCOPE_BCA);
        SupplierRegistry.Supplier memory s = r.get(SUP_A);
        assertEq(s.supplier_id, SUP_A);
        assertEq(s.scope, SCOPE_BCA);
        assertEq(uint8(s.state), uint8(SupplierRegistry.State.Pending));
        assertTrue(s.exists);
    }

    function test_register_rejects_non_recorder() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SupplierRegistry.NotRecorder.selector, stranger)
        );
        r.register(SUP_A, SCOPE_BCA, 365, CORR, USER);
    }

    function test_register_rejects_duplicate() public {
        _register(SUP_A, SCOPE_BCA);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.SupplierAlreadyExists.selector,
                SUP_A
            )
        );
        r.register(SUP_A, SCOPE_BCA, 365, CORR, USER);
    }

    function test_register_appends_history() public {
        _register(SUP_A, SCOPE_BCA);
        assertEq(r.historyLength(SUP_A), 1);
        SupplierRegistry.StateRecord[] memory h = r.history(SUP_A);
        assertEq(uint8(h[0].state), uint8(SupplierRegistry.State.Pending));
    }

    function test_register_indexes_by_scope() public {
        _register(SUP_A, SCOPE_BCA);
        _register(SUP_B, SCOPE_BCA);
        bytes32[] memory ids = r.byScope(SCOPE_BCA);
        assertEq(ids.length, 2);
    }

    function test_register_indexes_by_state_pending() public {
        _register(SUP_A, SCOPE_BCA);
        bytes32[] memory pending = r.byState(SupplierRegistry.State.Pending);
        assertEq(pending.length, 1);
        assertEq(pending[0], SUP_A);
    }

    // ── State machine — happy paths ──────────────────────────────────

    function test_setState_pending_to_inreview() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.InReview));
    }

    function test_setState_inreview_to_requalified() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        _setState(SUP_A, SupplierRegistry.State.ReQualified, recorder);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.ReQualified));
    }

    function test_setState_inreview_to_probationary() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        _setState(SUP_A, SupplierRegistry.State.Probationary, recorder);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.Probationary));
    }

    // ── State machine — terminal-state governance gate ───────────────

    function test_setState_inreview_to_suspended_requires_governance() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.TerminalStateRequiresGovernance.selector,
                SupplierRegistry.State.Suspended
            )
        );
        r.setState(SUP_A, SupplierRegistry.State.Suspended, CORR, USER, "ops fail");
    }

    function test_setState_inreview_to_suspended_governance_allowed() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        // Governance must also be a recorder.
        vm.prank(governance);
        r.setRecorder(governance, true);
        _setState(SUP_A, SupplierRegistry.State.Suspended, governance);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.Suspended));
    }

    function test_setState_inreview_to_rejected_requires_governance() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.TerminalStateRequiresGovernance.selector,
                SupplierRegistry.State.Rejected
            )
        );
        r.setState(SUP_A, SupplierRegistry.State.Rejected, CORR, USER, "fraud");
    }

    // ── State machine — invalid transitions ──────────────────────────

    function test_setState_pending_to_requalified_rejected() public {
        _register(SUP_A, SCOPE_BCA);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.InvalidTransition.selector,
                SupplierRegistry.State.Pending,
                SupplierRegistry.State.ReQualified
            )
        );
        r.setState(SUP_A, SupplierRegistry.State.ReQualified, CORR, USER, "skip review");
    }

    function test_setState_suspended_is_terminal() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        vm.prank(governance);
        r.setRecorder(governance, true);
        _setState(SUP_A, SupplierRegistry.State.Suspended, governance);
        // No outbound transitions allowed.
        vm.prank(governance);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.InvalidTransition.selector,
                SupplierRegistry.State.Suspended,
                SupplierRegistry.State.InReview
            )
        );
        r.setState(SUP_A, SupplierRegistry.State.InReview, CORR, USER, "appeal");
    }

    function test_setState_empty_reason_rejected() public {
        _register(SUP_A, SCOPE_BCA);
        vm.prank(recorder);
        vm.expectRevert(SupplierRegistry.EmptyReason.selector);
        r.setState(SUP_A, SupplierRegistry.State.InReview, CORR, USER, "");
    }

    function test_setState_unknown_supplier_rejected() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.SupplierDoesNotExist.selector,
                SUP_A
            )
        );
        r.setState(SUP_A, SupplierRegistry.State.InReview, CORR, USER, "nope");
    }

    // ── requestRequalification ───────────────────────────────────────

    function test_requestRequalification_from_requalified() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        _setState(SUP_A, SupplierRegistry.State.ReQualified, recorder);
        vm.prank(recorder);
        r.requestRequalification(SUP_A, CORR, USER);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.InReview));
    }

    function test_requestRequalification_from_probationary() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        _setState(SUP_A, SupplierRegistry.State.Probationary, recorder);
        vm.prank(recorder);
        r.requestRequalification(SUP_A, CORR, USER);
        assertEq(uint8(r.get(SUP_A).state), uint8(SupplierRegistry.State.InReview));
    }

    function test_requestRequalification_from_pending_rejected() public {
        _register(SUP_A, SCOPE_BCA);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                SupplierRegistry.InvalidTransition.selector,
                SupplierRegistry.State.Pending,
                SupplierRegistry.State.InReview
            )
        );
        r.requestRequalification(SUP_A, CORR, USER);
    }

    // ── AppendOnlyHistory ────────────────────────────────────────────

    function test_history_grows_per_state_change() public {
        _register(SUP_A, SCOPE_BCA);
        assertEq(r.historyLength(SUP_A), 1);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        assertEq(r.historyLength(SUP_A), 2);
        _setState(SUP_A, SupplierRegistry.State.ReQualified, recorder);
        assertEq(r.historyLength(SUP_A), 3);
    }

    function test_history_records_metadata() public {
        _register(SUP_A, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        SupplierRegistry.StateRecord[] memory h = r.history(SUP_A);
        assertEq(h[1].corr_id, CORR);
        assertEq(h[1].signer, USER);
    }

    // ── byScope / byState ────────────────────────────────────────────

    function test_byState_tracks_transitions() public {
        _register(SUP_A, SCOPE_BCA);
        _register(SUP_B, SCOPE_BCA);
        _setState(SUP_A, SupplierRegistry.State.InReview, recorder);
        bytes32[] memory pending = r.byState(SupplierRegistry.State.Pending);
        bytes32[] memory inreview = r.byState(SupplierRegistry.State.InReview);
        // SUP_A appears in both Pending (history) and InReview (current);
        // panel filters by current state via `get`.
        assertEq(pending.length, 2);
        assertEq(inreview.length, 1);
    }

    function test_byScope_separates_scopes() public {
        _register(SUP_A, SCOPE_BCA);
        _register(SUP_B, SCOPE_BDS);
        assertEq(r.byScope(SCOPE_BCA).length, 1);
        assertEq(r.byScope(SCOPE_BDS).length, 1);
    }

    // ── Fuzz ─────────────────────────────────────────────────────────

    function testFuzz_register_appends_one_per_id(bytes32 sup, bytes32 scope) public {
        vm.assume(sup != bytes32(0));
        uint256 before_ = r.byScope(scope).length;
        vm.prank(recorder);
        r.register(sup, scope, 365, CORR, USER);
        assertEq(r.byScope(scope).length, before_ + 1);
    }

    function testFuzz_history_length_monotonic(uint8 transitions) public {
        vm.assume(transitions <= 10);
        _register(SUP_A, SCOPE_BCA);
        SupplierRegistry.State current = SupplierRegistry.State.Pending;
        uint256 expected_len = 1;
        for (uint8 i = 0; i < transitions; ++i) {
            // Always go Pending → InReview → ReQualified → InReview → ...
            SupplierRegistry.State next_;
            if (current == SupplierRegistry.State.Pending) {
                next_ = SupplierRegistry.State.InReview;
            } else if (current == SupplierRegistry.State.InReview) {
                next_ = SupplierRegistry.State.ReQualified;
            } else {
                // ReQualified → InReview via convenience method
                vm.prank(recorder);
                r.requestRequalification(SUP_A, CORR, USER);
                current = SupplierRegistry.State.InReview;
                expected_len++;
                continue;
            }
            _setState(SUP_A, next_, recorder);
            current = next_;
            expected_len++;
        }
        assertEq(r.historyLength(SUP_A), expected_len);
    }
}
