// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MeetingRegistry} from "../src/cit_agent/MeetingRegistry.sol";

/// @title MeetingRegistry.t — QRM-S6
/// @dev The properties that make a registered record evidence: it cannot be
///      amended, it cannot be pre-empted by an empty write, and verification
///      answers the auditor's actual question.
contract MeetingRegistryTest is Test {
    MeetingRegistry internal reg;

    bytes32 constant TENANT = keccak256("acme");
    bytes32 constant TENANT2 = keccak256("other");
    bytes32 constant MEETING = keccak256("m-1");
    bytes32 constant AGENDA = bytes32(uint256(0xA6E7DA));
    bytes32 constant MINUTES = bytes32(uint256(0x111));

    address internal ratifier = address(0xA1);
    address internal stranger = address(0xB2);

    function setUp() public {
        reg = new MeetingRegistry();
    }

    function _register() internal {
        vm.prank(ratifier);
        reg.register(TENANT, MEETING, AGENDA, MINUTES, 1_753_460_000, "");
    }

    // ── the record ──────────────────────────────────────────────────

    function test_registerStoresTheCommitmentAndTheSigningKey() public {
        _register();

        MeetingRegistry.MinutesRecord memory r = reg.getMinutes(TENANT, MEETING);
        assertEq(r.agendaHash, AGENDA);
        assertEq(r.minutesHash, MINUTES);
        assertEq(r.ratifier, ratifier, "the signing key is the on-chain ratifier");
        assertEq(r.ratifiedAt, 1_753_460_000);
        assertEq(r.blockNumber, uint64(block.number));
        assertEq(bytes(r.cid).length, 0, "no pin is the default, not a degraded state");
    }

    function test_blockNumberComesFromTheChainNotTheCaller() public {
        vm.roll(500);
        _register();
        assertEq(reg.getMinutes(TENANT, MEETING).blockNumber, 500);
    }

    // ── append-only ─────────────────────────────────────────────────

    function test_aRegisteredMeetingCannotBeAmended() public {
        _register();
        vm.prank(ratifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                MeetingRegistry.AlreadyRegistered.selector, TENANT, MEETING
            )
        );
        reg.register(TENANT, MEETING, AGENDA, bytes32(uint256(0x222)), 2, "");
    }

    function test_aStrangerCannotOverwriteSomeoneElsesRecord() public {
        _register();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                MeetingRegistry.AlreadyRegistered.selector, TENANT, MEETING
            )
        );
        reg.register(TENANT, MEETING, AGENDA, bytes32(uint256(0x333)), 3, "");

        // and the original survives untouched
        assertEq(reg.getMinutes(TENANT, MEETING).minutesHash, MINUTES);
        assertEq(reg.getMinutes(TENANT, MEETING).ratifier, ratifier);
    }

    function test_anEmptyHashCannotSquatOnAMeetingKey() public {
        // Without this guard a caller could occupy (tenant, meetingId) with a
        // zero record and permanently block the real registration.
        vm.prank(stranger);
        vm.expectRevert(MeetingRegistry.ZeroMinutesHash.selector);
        reg.register(TENANT, MEETING, AGENDA, bytes32(0), 1, "");

        _register();
        assertTrue(reg.isRegistered(TENANT, MEETING));
    }

    // ── tenant isolation ────────────────────────────────────────────

    function test_theSameMeetingIdInAnotherTenantIsADifferentRecord() public {
        _register();
        vm.prank(stranger);
        reg.register(TENANT2, MEETING, AGENDA, bytes32(uint256(0x999)), 9, "");

        assertEq(reg.getMinutes(TENANT, MEETING).minutesHash, MINUTES);
        assertEq(reg.getMinutes(TENANT2, MEETING).minutesHash, bytes32(uint256(0x999)));
        assertEq(reg.meetingCount(TENANT), 1);
        assertEq(reg.meetingCount(TENANT2), 1);
    }

    // ── verification, the auditor's question ────────────────────────

    function test_verifyMinutes_trueOnlyForTheExactHash() public {
        _register();
        assertTrue(reg.verifyMinutes(TENANT, MEETING, MINUTES));
        assertFalse(reg.verifyMinutes(TENANT, MEETING, bytes32(uint256(0x222))));
    }

    function test_verifyMinutes_isFalseNotARevertForAnUnknownMeeting() public view {
        // "no record" and "a different record" are both answers to the same
        // question; a verifier wants a boolean, not two error paths.
        assertFalse(reg.verifyMinutes(TENANT, keccak256("never"), MINUTES));
    }

    function test_verifyMinutes_rejectsTheZeroHash() public {
        _register();
        assertFalse(
            reg.verifyMinutes(TENANT, keccak256("never"), bytes32(0)),
            "zero must never verify against an empty slot"
        );
    }

    function test_getMinutes_revertsRatherThanReturningAZeroedStruct() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                MeetingRegistry.NotRegistered.selector, TENANT, MEETING
            )
        );
        reg.getMinutes(TENANT, MEETING);
    }

    // ── enumeration ─────────────────────────────────────────────────

    function test_meetingsByTenant_isPaginatedAndInOrder() public {
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(ratifier);
            reg.register(
                TENANT,
                keccak256(abi.encode("m", i)),
                AGENDA,
                bytes32(uint256(0x100 + i)),
                uint64(i),
                ""
            );
        }
        assertEq(reg.meetingCount(TENANT), 5);

        bytes32[] memory page = reg.meetingsByTenant(TENANT, 1, 2);
        assertEq(page.length, 2);
        assertEq(page[0], keccak256(abi.encode("m", uint256(1))));
        assertEq(page[1], keccak256(abi.encode("m", uint256(2))));

        // over-reading clamps instead of reverting
        assertEq(reg.meetingsByTenant(TENANT, 3, 99).length, 2);
        assertEq(reg.meetingsByTenant(TENANT, 99, 1).length, 0);
    }

    function test_recordKeyIsReproducibleOffChain() public view {
        assertEq(
            reg.recordKey(TENANT, MEETING),
            keccak256(abi.encode(TENANT, MEETING))
        );
    }

    // ── a CID is optional, and stored verbatim when present ─────────

    function test_aPinnedDeploymentCanCarryItsCid() public {
        vm.prank(ratifier);
        reg.register(TENANT, MEETING, AGENDA, MINUTES, 1, "bafy104e");
        assertEq(reg.getMinutes(TENANT, MEETING).cid, "bafy104e");
    }

    // ── fuzz ────────────────────────────────────────────────────────

    function testFuzz_registerThenVerifyRoundTrips(
        bytes32 tenant,
        bytes32 meetingId,
        bytes32 minutesHash
    ) public {
        vm.assume(minutesHash != bytes32(0));
        vm.prank(ratifier);
        reg.register(tenant, meetingId, AGENDA, minutesHash, 1, "");
        assertTrue(reg.verifyMinutes(tenant, meetingId, minutesHash));
        assertTrue(reg.isRegistered(tenant, meetingId));
    }
}
