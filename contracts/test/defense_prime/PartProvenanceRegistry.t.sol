// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {PartProvenanceRegistry} from "../../src/defense_prime/PartProvenanceRegistry.sol";

/// @title PartProvenanceRegistry.t — DPF-05-WP2 Forge tests
/// @dev Cites:
///   - `formal/specs/contracts/AgentDecisionLog.tla` (AppendOnly,
///     RecordedInList) — ratified for lineage steps.
///   - `formal/specs/contracts/ContradictionStateMachine.tla`
///     (OpenContradictionImpliesDoubt) — ratified by `verifyChain`.

contract MockContradictionLedger {
    mapping(bytes32 => bool) public flags;

    function setFlag(bytes32 subject, bool flagged) external {
        flags[subject] = flagged;
    }

    function hasOpenContradiction(bytes32 subject) external view returns (bool) {
        return flags[subject];
    }
}

contract PartProvenanceRegistryTest is Test {
    PartProvenanceRegistry internal r;
    MockContradictionLedger internal ledger;

    address internal governance = address(0xA1);
    address internal recorder = address(0xB1);
    address internal stranger = address(0x5);

    bytes32 constant PART_A = keccak256("part-A");
    bytes32 constant PART_B = keccak256("part-B");
    bytes32 constant TAIL_777X = keccak256("N777X");
    bytes32 constant TAIL_787 = keccak256("N787");
    bytes32 constant USER = keccak256("user-1");
    bytes32 constant CORR = keccak256("corr-1");
    bytes32 constant ART_OK = keccak256("artifact-ok");
    bytes32 constant ART_FLAGGED = keccak256("artifact-flagged");

    function setUp() public {
        r = new PartProvenanceRegistry(governance);
        ledger = new MockContradictionLedger();
        vm.prank(governance);
        r.setRecorder(recorder, true);
        vm.prank(governance);
        r.setContradictionLedger(address(ledger));
    }

    // Helper: record a step authored by `recorder`.
    function _record(
        bytes32 step_id,
        bytes32 part,
        bytes32 prev,
        PartProvenanceRegistry.StepKind kind,
        string memory desc
    ) internal {
        vm.prank(recorder);
        r.recordStep(
            step_id,
            part,
            prev,
            USER,
            CORR,
            keccak256(abi.encodePacked("dec-", step_id)),
            ART_OK,
            kind,
            desc
        );
    }

    // ── Constructor / governance ─────────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(PartProvenanceRegistry.ZeroGovernance.selector);
        new PartProvenanceRegistry(address(0));
    }

    function test_governance_set_correctly() public {
        assertEq(r.governance(), governance);
    }

    function test_setRecorder_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.NotGovernance.selector,
                stranger
            )
        );
        r.setRecorder(stranger, true);
    }

    function test_setRecorder_emits_event() public {
        address newRec = address(0xC1);
        vm.prank(governance);
        vm.expectEmit(true, false, false, true);
        emit PartProvenanceRegistry.RecorderSet(newRec, true);
        r.setRecorder(newRec, true);
        assertTrue(r.is_recorder(newRec));
    }

    function test_setContradictionLedger_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.NotGovernance.selector,
                stranger
            )
        );
        r.setContradictionLedger(address(ledger));
    }

    // ── recordStep — happy path + AppendOnly invariant ───────────────

    function test_recordStep_basic_flow() public {
        bytes32 step1 = keccak256("s1");
        _record(step1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw bar stock");

        PartProvenanceRegistry.LineageStep memory s = r.getStep(step1);
        assertEq(s.step_id, step1);
        assertEq(s.part_hash, PART_A);
        assertEq(s.prev_step_id, bytes32(0));
        assertTrue(s.exists);
        assertEq(uint8(s.kind), uint8(PartProvenanceRegistry.StepKind.RawMaterial));
    }

    function test_recordStep_rejects_non_recorder() public {
        bytes32 step1 = keccak256("s1");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.NotRecorder.selector,
                stranger
            )
        );
        r.recordStep(
            step1, PART_A, bytes32(0), USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.RawMaterial, "raw"
        );
    }

    function test_recordStep_rejects_duplicate_step_id() public {
        bytes32 step1 = keccak256("s1");
        _record(step1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");

        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.StepAlreadyExists.selector,
                step1
            )
        );
        r.recordStep(
            step1, PART_A, bytes32(0), USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.RawMaterial, "raw again"
        );
    }

    function test_recordStep_rejects_empty_description() public {
        bytes32 step1 = keccak256("s1");
        vm.prank(recorder);
        vm.expectRevert(PartProvenanceRegistry.EmptyDescription.selector);
        r.recordStep(
            step1, PART_A, bytes32(0), USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.RawMaterial, ""
        );
    }

    function test_recordStep_appendonly_no_mutation() public {
        bytes32 step1 = keccak256("s1");
        _record(step1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");

        PartProvenanceRegistry.LineageStep memory before_ = r.getStep(step1);
        // Try to record a different step — original is untouched.
        bytes32 step2 = keccak256("s2");
        _record(step2, PART_A, step1, PartProvenanceRegistry.StepKind.Manufacture, "machined");

        PartProvenanceRegistry.LineageStep memory after_ = r.getStep(step1);
        assertEq(before_.description, after_.description);
        assertEq(before_.ts, after_.ts);
    }

    function test_recordStep_chain_two_steps() public {
        bytes32 s1 = keccak256("s1");
        bytes32 s2 = keccak256("s2");
        _record(s1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");
        _record(s2, PART_A, s1, PartProvenanceRegistry.StepKind.Manufacture, "milled");

        bytes32[] memory chain = r.lineage(PART_A);
        assertEq(chain.length, 2);
        assertEq(chain[0], s1);
        assertEq(chain[1], s2);
    }

    function test_recordStep_rejects_prev_does_not_exist() public {
        bytes32 phantom = keccak256("phantom");
        bytes32 s1 = keccak256("s1");
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.StepDoesNotExist.selector,
                phantom
            )
        );
        r.recordStep(
            s1, PART_A, phantom, USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.Manufacture, "milled"
        );
    }

    function test_recordStep_rejects_prev_for_different_part() public {
        bytes32 sA = keccak256("sA");
        _record(sA, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw A");

        bytes32 sB = keccak256("sB");
        vm.prank(recorder);
        // prev points to PART_A's step but we're claiming PART_B
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.PrevStepNotForSamePart.selector,
                sA,
                PART_B
            )
        );
        r.recordStep(
            sB, PART_B, sA, USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.Manufacture, "wrong part"
        );
    }

    // ── lineage / getStep / stepCount ────────────────────────────────

    function test_lineage_empty_for_unknown_part() public view {
        bytes32[] memory chain = r.lineage(keccak256("never-recorded"));
        assertEq(chain.length, 0);
    }

    function test_stepCount_tracks_chain_length() public {
        assertEq(r.stepCount(PART_A), 0);
        bytes32 s1 = keccak256("s1");
        _record(s1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");
        assertEq(r.stepCount(PART_A), 1);
        bytes32 s2 = keccak256("s2");
        _record(s2, PART_A, s1, PartProvenanceRegistry.StepKind.Manufacture, "milled");
        assertEq(r.stepCount(PART_A), 2);
    }

    function test_getStep_reverts_for_unknown() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.StepDoesNotExist.selector,
                keccak256("nope")
            )
        );
        r.getStep(keccak256("nope"));
    }

    // ── verifyChain — happy + invalid paths ──────────────────────────

    function test_verifyChain_empty_returns_false() public view {
        (bool ok, bytes32[] memory chain) = r.verifyChain(PART_A);
        assertFalse(ok);
        assertEq(chain.length, 0);
    }

    function test_verifyChain_intact_two_steps() public {
        bytes32 s1 = keccak256("s1");
        bytes32 s2 = keccak256("s2");
        _record(s1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");
        _record(s2, PART_A, s1, PartProvenanceRegistry.StepKind.Acceptance, "accepted");

        (bool ok, bytes32[] memory chain) = r.verifyChain(PART_A);
        assertTrue(ok);
        assertEq(chain.length, 2);
    }

    function test_verifyChain_open_contradiction_invalidates() public {
        bytes32 s1 = keccak256("s1");
        // Record with ART_FLAGGED as the artifact root.
        vm.prank(recorder);
        r.recordStep(
            s1, PART_A, bytes32(0), USER, CORR, bytes32(0), ART_FLAGGED,
            PartProvenanceRegistry.StepKind.Acceptance, "flagged accept"
        );

        // Initially clean.
        (bool ok1, ) = r.verifyChain(PART_A);
        assertTrue(ok1);

        // Flag the artifact root.
        ledger.setFlag(ART_FLAGGED, true);
        (bool ok2, ) = r.verifyChain(PART_A);
        assertFalse(ok2);
    }

    function test_verifyChain_no_ledger_skips_contradiction_check() public {
        // Deploy a fresh registry without setting the ledger.
        PartProvenanceRegistry r2 = new PartProvenanceRegistry(governance);
        vm.prank(governance);
        r2.setRecorder(recorder, true);

        bytes32 s1 = keccak256("s1");
        vm.prank(recorder);
        r2.recordStep(
            s1, PART_A, bytes32(0), USER, CORR, bytes32(0), ART_FLAGGED,
            PartProvenanceRegistry.StepKind.Acceptance, "no ledger"
        );

        (bool ok, ) = r2.verifyChain(PART_A);
        assertTrue(ok);
    }

    // ── Tail registration + linkPartToTail ───────────────────────────

    function test_registerTail_only_governance() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.NotGovernance.selector,
                stranger
            )
        );
        r.registerTail(TAIL_777X);
    }

    function test_registerTail_idempotent() public {
        vm.startPrank(governance);
        r.registerTail(TAIL_777X);
        r.registerTail(TAIL_777X);
        vm.stopPrank();
        assertEq(r.tailCount(), 1);
        assertTrue(r.tail_exists(TAIL_777X));
    }

    function test_registerTail_emits_only_once() public {
        vm.startPrank(governance);
        vm.expectEmit(true, false, false, false);
        emit PartProvenanceRegistry.TailRegistered(TAIL_777X);
        r.registerTail(TAIL_777X);
        // 2nd call shouldn't emit.
        vm.recordLogs();
        r.registerTail(TAIL_777X);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 0);
        vm.stopPrank();
    }

    function test_linkPartToTail_basic_flow() public {
        vm.prank(governance);
        r.registerTail(TAIL_777X);

        vm.prank(recorder);
        r.linkPartToTail(PART_A, TAIL_777X);

        assertEq(r.partTail(PART_A), TAIL_777X);
        bytes32[] memory parts = r.byTail(TAIL_777X);
        assertEq(parts.length, 1);
        assertEq(parts[0], PART_A);
    }

    function test_linkPartToTail_rejects_unregistered_tail() public {
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.TailDoesNotExist.selector,
                TAIL_777X
            )
        );
        r.linkPartToTail(PART_A, TAIL_777X);
    }

    function test_linkPartToTail_rejects_duplicate_link() public {
        vm.prank(governance);
        r.registerTail(TAIL_777X);
        vm.prank(governance);
        r.registerTail(TAIL_787);

        vm.prank(recorder);
        r.linkPartToTail(PART_A, TAIL_777X);

        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.PartAlreadyLinkedToTail.selector,
                PART_A,
                TAIL_777X
            )
        );
        r.linkPartToTail(PART_A, TAIL_787);
    }

    function test_linkPartToTail_only_recorder() public {
        vm.prank(governance);
        r.registerTail(TAIL_777X);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.NotRecorder.selector,
                stranger
            )
        );
        r.linkPartToTail(PART_A, TAIL_777X);
    }

    function test_byTail_multiple_parts() public {
        vm.prank(governance);
        r.registerTail(TAIL_777X);
        vm.startPrank(recorder);
        r.linkPartToTail(PART_A, TAIL_777X);
        r.linkPartToTail(PART_B, TAIL_777X);
        vm.stopPrank();

        bytes32[] memory parts = r.byTail(TAIL_777X);
        assertEq(parts.length, 2);
    }

    // ── searchTails — bounded + prefix-match ─────────────────────────

    function test_searchTails_returns_empty_on_no_matches() public {
        vm.prank(governance);
        r.registerTail(TAIL_777X);
        bytes32[] memory results = r.searchTails(keccak256("XYZ"), 4, 5);
        assertEq(results.length, 0);
    }

    function test_searchTails_match_all_when_prefix_zero() public {
        vm.startPrank(governance);
        r.registerTail(TAIL_777X);
        r.registerTail(TAIL_787);
        vm.stopPrank();
        bytes32[] memory results = r.searchTails(bytes32(0), 0, 5);
        assertEq(results.length, 2);
    }

    function test_searchTails_caps_at_max_results() public {
        // Register 5 tails.
        vm.startPrank(governance);
        for (uint256 i; i < 5; ++i) {
            r.registerTail(keccak256(abi.encodePacked("tail-", i)));
        }
        vm.stopPrank();

        bytes32[] memory results = r.searchTails(bytes32(0), 0, 3);
        assertEq(results.length, 3);
    }

    function test_searchTails_rejects_zero_max_results() public {
        vm.expectRevert(PartProvenanceRegistry.MaxResultsZero.selector);
        r.searchTails(bytes32(0), 0, 0);
    }

    function test_searchTails_rejects_max_results_too_large() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PartProvenanceRegistry.MaxResultsTooLarge.selector,
                33,
                32
            )
        );
        r.searchTails(bytes32(0), 0, 33);
    }

    function test_searchTails_prefix_match_first_byte() public {
        bytes32 ab = bytes32(uint256(0xAB) << 248); // first byte = 0xAB
        bytes32 ac = bytes32(uint256(0xAC) << 248);
        vm.startPrank(governance);
        r.registerTail(ab);
        r.registerTail(ac);
        vm.stopPrank();

        bytes32[] memory results = r.searchTails(bytes32(uint256(0xAB) << 248), 1, 5);
        assertEq(results.length, 1);
        assertEq(results[0], ab);
    }

    // ── Composability: lineage + verify + tail join ──────────────────

    function test_e2e_full_lineage_and_verify_and_tail_link() public {
        // 1. Register a tail
        vm.prank(governance);
        r.registerTail(TAIL_777X);

        // 2. Build a 4-step chain for PART_A
        bytes32 s1 = keccak256("raw");
        bytes32 s2 = keccak256("mfg");
        bytes32 s3 = keccak256("ndt");
        bytes32 s4 = keccak256("acc");
        _record(s1, PART_A, bytes32(0), PartProvenanceRegistry.StepKind.RawMaterial, "raw");
        _record(s2, PART_A, s1, PartProvenanceRegistry.StepKind.Manufacture, "mfg");
        _record(s3, PART_A, s2, PartProvenanceRegistry.StepKind.Inspection, "ndt");
        _record(s4, PART_A, s3, PartProvenanceRegistry.StepKind.Acceptance, "acc");

        // 3. Link to tail
        vm.prank(recorder);
        r.linkPartToTail(PART_A, TAIL_777X);

        // 4. Verify chain
        (bool ok, bytes32[] memory chain) = r.verifyChain(PART_A);
        assertTrue(ok);
        assertEq(chain.length, 4);

        // 5. byTail join
        bytes32[] memory parts = r.byTail(TAIL_777X);
        assertEq(parts.length, 1);
        assertEq(parts[0], PART_A);
    }

    // ── Fuzz tests ───────────────────────────────────────────────────

    function testFuzz_recordStep_appends_one_to_lineage(bytes32 step_id, bytes32 part) public {
        vm.assume(step_id != bytes32(0));
        vm.assume(part != bytes32(0));
        uint256 before_ = r.stepCount(part);
        vm.prank(recorder);
        r.recordStep(
            step_id, part, bytes32(0), USER, CORR, bytes32(0), ART_OK,
            PartProvenanceRegistry.StepKind.RawMaterial, "fuzz"
        );
        assertEq(r.stepCount(part), before_ + 1);
    }

    function testFuzz_searchTails_truncates(uint8 max_results) public {
        vm.assume(max_results > 0 && max_results <= r.MAX_SEARCH_RESULTS());
        // Register 40 tails.
        vm.startPrank(governance);
        for (uint256 i; i < 40; ++i) {
            r.registerTail(keccak256(abi.encodePacked("t", i)));
        }
        vm.stopPrank();
        bytes32[] memory results = r.searchTails(bytes32(0), 0, max_results);
        assertEq(results.length, max_results);
    }

    function testFuzz_verifyChain_returns_consistent_for_intact_chain(uint8 chain_len) public {
        vm.assume(chain_len > 0 && chain_len < 20);
        bytes32 prev = bytes32(0);
        for (uint256 i; i < chain_len; ++i) {
            bytes32 sid = keccak256(abi.encodePacked("step-", i));
            _record(
                sid, PART_A, prev,
                PartProvenanceRegistry.StepKind.Manufacture,
                "fuzz step"
            );
            prev = sid;
        }
        (bool ok, bytes32[] memory chain) = r.verifyChain(PART_A);
        assertTrue(ok);
        assertEq(chain.length, chain_len);
    }
}
