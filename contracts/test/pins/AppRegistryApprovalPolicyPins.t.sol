// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";
import {AppRegistry} from "../../src/defense_prime/AppRegistry.sol";

/// @notice Pins two checks in AppRegistry's deploy approval that the existing
///         suite did not reach: the registry's own approver threshold (an
///         envelope that met only its OWN, lower threshold must not count) and
///         the envelope expiry. Every existing envelope test uses a 2-of-2
///         envelope with no expiry, so lowering the counted threshold to one
///         approver, or dropping the expiry check, left it green.
contract AppRegistryApprovalPolicyPinsTest is Test {
    MultiSigEnvelope env;
    AppRegistry reg;
    bytes32 constant TENANT = keccak256("tenant-A");
    address gov = address(0x60);
    address recorder = address(0xEC0);
    address a1 = address(0xA1);
    address a2 = address(0xA2);
    bytes32 appId = keccak256("app");
    bytes32 envId = keccak256("env");

    function setUp() public {
        vm.warp(1_000_000);
        env = new MultiSigEnvelope();
        reg = new AppRegistry(gov, address(env));
        vm.startPrank(gov);
        reg.setRecorder(recorder, true);
        reg.setApproverPolicy(_approvers(), 2); // the registry requires 2 of {a1, a2}
        vm.stopPrank();
        address[] memory none = new address[](0);
        vm.prank(recorder);
        reg.proposeApp(appId, TENANT, "app", "1.0", recorder, envId, none, bytes32(0));
    }

    function _approvers() internal pure returns (bytes32[] memory r) {
        r = new bytes32[](2);
        r[0] = QuorumIdentity.subjectKey(address(0xA1));
        r[1] = QuorumIdentity.subjectKey(address(0xA2));
    }

    function _draft(uint8 envelopeThreshold, uint64 expiresAt) internal {
        bytes32 corr = reg.envelopeCorrId(appId);
        vm.prank(recorder);
        env.draft(
            envId,
            QuorumIdentity.subjectKey(recorder),
            bytes32(uint256(1)),
            "cid",
            _approvers(),
            envelopeThreshold,
            expiresAt,
            corr
        );
    }

    function _sign(address who, uint256 i) internal {
        vm.prank(who);
        env.sign(envId, _approvers()[i], hex"01", "x");
    }

    /// A 1-of-2 envelope reaches its own `Signed` state with one approver, but
    /// the registry's snapshotted policy needs two: deploy is refused.
    function test_envelopeMeetingOnlyItsOwnLowerThresholdIsRefused() public {
        _draft(1, 0);
        _sign(a1, 0);
        assertEq(uint8(env.getState(envId)), uint8(MultiSigEnvelope.EnvelopeState.Signed), "envelope's own 1-of-2 met");

        assertFalse(reg.isDeployApproved(appId), "one approver is below the registry threshold of two");
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, envId));
        reg.deploy(appId);
        assertEq(uint8(reg.getApp(appId).state), uint8(AppRegistry.AppState.Pending));
    }

    /// Control: the same approvers at the registry threshold do deploy.
    function test_bothApproversDeploy() public {
        _draft(2, 0);
        _sign(a1, 0);
        _sign(a2, 1);
        assertTrue(reg.isDeployApproved(appId));
        reg.deploy(appId);
        assertEq(uint8(reg.getApp(appId).state), uint8(AppRegistry.AppState.Deployed));
    }

    /// A fully signed envelope stops counting once it expires.
    function test_expiredEnvelopeNoLongerApproves() public {
        _draft(2, uint64(block.timestamp + 100));
        _sign(a1, 0);
        _sign(a2, 1);
        assertTrue(reg.isDeployApproved(appId), "valid before expiry");

        vm.warp(block.timestamp + 100);
        assertFalse(reg.isDeployApproved(appId), "expired at expires_at");
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, envId));
        reg.deploy(appId);
    }
}
