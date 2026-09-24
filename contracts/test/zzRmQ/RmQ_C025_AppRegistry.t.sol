// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AppRegistry, IEnvelopeOracle} from "../../src/defense_prime/AppRegistry.sol";

contract RmQMockOracle is IEnvelopeOracle {
    mapping(bytes32 => bool) public met;
    function setMet(bytes32 id, bool v) external { met[id] = v; }
    function isSignedThresholdMet(bytes32 id) external view returns (bool) { return met[id]; }
}

/// @title RM-Q · CHAIN-B-C025 — permissionless recordFailureOnEnvelopeReject
/// @notice RED→GREEN tripwire. Before the fix, any anonymous caller could
///         watch for `AppProposed` and immediately drive a pending app to
///         the absorbing `Failed` state (the envelope has no signatures
///         yet, so `isSignedThresholdMet` is false and the caller's claim
///         was accepted) — permanently burning the app id. After the fix
///         the transition is recorder/governance-gated.
contract RmQ_C025 is Test {
    AppRegistry internal reg;
    RmQMockOracle internal oracle;
    address internal governance = address(0x6025);
    address internal recorder = address(0x8EC);
    address internal attacker = address(0xBAD);
    address internal owner1 = address(0x0E1);

    bytes32 internal constant APP = keccak256("app-1");
    bytes32 internal constant SCOPE = keccak256("scope");
    bytes32 internal constant ENV = keccak256("env-1");

    function setUp() public {
        oracle = new RmQMockOracle();
        vm.prank(governance);
        reg = new AppRegistry(governance, address(oracle));
        vm.prank(governance);
        reg.setRecorder(recorder, true);
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
        oracle.setMet(ENV, true);
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
