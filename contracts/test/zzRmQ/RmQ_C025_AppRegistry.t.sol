// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AppRegistry} from "../../src/defense_prime/AppRegistry.sol";
import {MultiSigEnvelope} from "../../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";

/// @title RM-Q · CHAIN-B-C025 — permissionless recordFailureOnEnvelopeReject
/// @notice RED→GREEN tripwire. Before the fix, any anonymous caller could
///         watch for `AppProposed` and immediately drive a pending app to
///         the absorbing `Failed` state (the envelope has no signatures
///         yet, so `isSignedThresholdMet` is false and the caller's claim
///         was accepted) — permanently burning the app id. After the fix
///         the transition is recorder/governance-gated.
contract RmQ_C025 is Test {
    AppRegistry internal reg;
    // PBA-L2-012: the real MultiSigEnvelope (AppRegistry no longer trusts an
    // envelope's self-reported `isSignedThresholdMet`).
    MultiSigEnvelope internal oracle;
    address internal approver = address(0xA99);
    address internal governance = address(0x6025);
    address internal recorder = address(0x8EC);
    address internal attacker = address(0xBAD);
    address internal owner1 = address(0x0E1);

    bytes32 internal constant APP = keccak256("app-1");
    bytes32 internal constant SCOPE = keccak256("scope");
    bytes32 internal constant ENV = keccak256("env-1");

    function setUp() public {
        oracle = new MultiSigEnvelope();
        vm.prank(governance);
        reg = new AppRegistry(governance, address(oracle));
        vm.prank(governance);
        reg.setRecorder(recorder, true);
        bytes32[] memory approvers = new bytes32[](1);
        approvers[0] = QuorumIdentity.subjectKey(approver);
        vm.prank(governance);
        reg.setApproverPolicy(approvers, 1);
        address[] memory empty;
        vm.prank(recorder);
        reg.proposeApp(APP, SCOPE, "app", "1.0", owner1, ENV, empty, keccak256("src"));
    }

    /// RED: an attacker races to burn the pending app id. Pre-fix the call
    /// SUCCEEDED (state → Failed forever); post-fix it reverts NotRecorder
    /// and the app stays Pending → still deployable.
    function test_C025_anon_cannot_burn_pending_app() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotRecorder.selector, attacker));
        reg.recordFailureOnEnvelopeReject(APP);

        assertEq(uint8(reg.getApp(APP).state), uint8(AppRegistry.AppState.Pending));
        // Envelope later reaches threshold → deploy still reachable.
        bytes32[] memory req = new bytes32[](1);
        req[0] = QuorumIdentity.subjectKey(approver);
        bytes32 corr = reg.envelopeCorrId(APP);
        vm.prank(recorder);
        oracle.draft(ENV, QuorumIdentity.subjectKey(recorder), keccak256("art"), "cid", req, 1, 0, corr);
        vm.prank(approver);
        oracle.sign(ENV, req[0], hex"01", "ceremony");
        reg.deploy(APP);
        assertEq(uint8(reg.getApp(APP).state), uint8(AppRegistry.AppState.Deployed));
    }

    /// The recorder can still record a genuine envelope rejection.
    function test_C025_recorder_can_record_failure() public {
        vm.prank(recorder);
        reg.recordFailureOnEnvelopeReject(APP);
        assertEq(uint8(reg.getApp(APP).state), uint8(AppRegistry.AppState.Failed));
    }
}
