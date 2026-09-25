// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";
import {IGovernanceProtocol} from "../../src/quorum/IGovernanceProtocol.sol";
import {ThresholdApproval} from "../../src/quorum/ThresholdApproval.sol";
import {SegregationOfDuties} from "../../src/quorum/SegregationOfDuties.sol";
import {AppRegistry} from "../../src/defense_prime/AppRegistry.sol";

/// PBA-L2-012 / -013 / -035 regressions (pre-bounty audit 2026-09-24): the lane
/// PoCs `test_F4_01`, `test_F4_02`, `test_F4_03`, `test_F4_03b`, inverted.
///
/// Written against call shapes that exist before AND after the fix (new entry
/// points via low-level calls, new constructor args appended and deployed from
/// creation code) so the revert check can run this file on the vulnerable
/// source. Attack steps that the fix makes revert are wrapped in try/catch; the
/// assertions are about the OUTCOME the attacker wanted.
contract PBA_L2_Envelope_Regression is Test {
    MultiSigEnvelope env;
    bytes32 constant TENANT = keccak256("tenant-A");
    bytes32 constant ACTION = keccak256("action.deploy");
    bytes32 constant PARAMS = keccak256("params");
    bytes32 constant CORR = keccak256("corr-1");

    address gov = address(0x60);
    address attacker = address(0xA77);
    address s1 = address(0x5111);
    address s2 = address(0x5112);
    address a1 = address(0xA1);
    address a2 = address(0xA2);

    function setUp() public {
        env = new MultiSigEnvelope();
    }

    function _one(bytes32 x) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = x;
    }

    function _create(bytes memory initCode) internal returns (address a) {
        assembly {
            a := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(a != address(0), "create failed");
    }

    function _ctx(address principal) internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 0, principal: principal, classification: 0, cost: 0, paramsHash: PARAMS, correlationId: CORR
        });
    }

    /// F4-01 inverted (PBA-L2-012): a role-less attacker self-drafts the app's
    /// envelope id as 1-of-1 and signs it; `deploy` must NOT succeed.
    function test_L2_012_selfDraftedEnvelope_cannotDeployApp() public {
        AppRegistry reg = AppRegistry(_create(abi.encodePacked(type(AppRegistry).creationCode, abi.encode(gov, address(env)))));
        address recorder = address(0xEC0);
        vm.prank(gov);
        reg.setRecorder(recorder, true);
        bytes32[] memory approvers = new bytes32[](2);
        approvers[0] = QuorumIdentity.subjectKey(a1);
        approvers[1] = QuorumIdentity.subjectKey(a2);
        vm.prank(gov);
        (bool ok,) = address(reg).call(abi.encodeWithSignature("setApproverPolicy(bytes32[],uint8)", approvers, uint8(2)));
        ok; // absent pre-fix

        bytes32 appId = keccak256("app-1");
        bytes32 deployEnvelope = keccak256("deploy-envelope-app-1");
        address[] memory none = new address[](0);
        vm.prank(recorder);
        reg.proposeApp(appId, TENANT, "app", "1.0", recorder, deployEnvelope, none, bytes32(0));

        bytes32 me = QuorumIdentity.subjectKey(attacker);
        vm.startPrank(attacker);
        env.draft(deployEnvelope, me, bytes32(uint256(1)), "cid", _one(me), 1, 0, bytes32(0));
        env.sign(deployEnvelope, me, hex"01", "x");
        try reg.deploy(appId) {} catch {}
        vm.stopPrank();

        assertEq(
            uint8(reg.getApp(appId).state),
            uint8(AppRegistry.AppState.Pending),
            "a self-drafted 1-of-1 envelope must not deploy the app"
        );
    }

    /// F4-02 inverted (PBA-L2-013): the executor drafts SoD's derived id with a
    /// fake initiator and two sybil approvers; SoD must not Allow.
    function test_L2_013_sybilApprovers_cannotSatisfySoD() public {
        bytes32[] memory roster = new bytes32[](3);
        roster[0] = QuorumIdentity.subjectKey(address(0xB0B1));
        roster[1] = QuorumIdentity.subjectKey(address(0xB0B2));
        roster[2] = QuorumIdentity.subjectKey(address(0xB0B3));
        // New trailing `roster` arg; the pre-fix constructor ignores it.
        SegregationOfDuties sod = SegregationOfDuties(
            _create(
                abi.encodePacked(
                    type(SegregationOfDuties).creationCode,
                    abi.encode(TENANT, keccak256("sod"), uint32(1), keccak256("spec"), "cid", address(env), uint8(2), roster)
                )
            )
        );
        bytes32 eid = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        bytes32[] memory req = new bytes32[](2);
        req[0] = QuorumIdentity.subjectKey(s1);
        req[1] = QuorumIdentity.subjectKey(s2);

        vm.prank(attacker);
        try env.draft(eid, keccak256("nobody"), bytes32(uint256(1)), "cid", req, 2, 0, bytes32(0)) {}
        catch {
            // Post-fix the fake initiator is refused; the best the attacker can
            // do is draft under its own (non-roster) identity.
            vm.prank(attacker);
            env.draft(eid, QuorumIdentity.subjectKey(attacker), bytes32(uint256(1)), "cid", req, 2, 0, bytes32(0));
        }
        vm.prank(s1);
        env.sign(eid, req[0], hex"01", "x");
        vm.prank(s2);
        env.sign(eid, req[1], hex"01", "x");

        (IGovernanceProtocol.Verdict v,,) = sod.check(TENANT, ACTION, _ctx(attacker));
        assertTrue(
            uint8(v) != uint8(IGovernanceProtocol.Verdict.Allow), "SoD must not allow a self-proposed, sybil-approved action"
        );
    }

    /// F4-03 inverted (PBA-L2-035): an outsider squats ThresholdApproval's
    /// derived id and closes it; the protocol must NOT answer Deny.
    function test_L2_035_squatAndClose_cannotForceDeny() public {
        bytes32[] memory approvers = new bytes32[](2);
        approvers[0] = QuorumIdentity.subjectKey(a1);
        approvers[1] = QuorumIdentity.subjectKey(a2);
        ThresholdApproval ta =
            new ThresholdApproval(TENANT, keccak256("ta"), 1, keccak256("spec"), "cid", address(env), approvers, 2);
        bytes32 eid = ta.approvalEnvelopeId(ACTION, PARAMS, CORR);

        bytes32 me = QuorumIdentity.subjectKey(attacker);
        vm.prank(attacker);
        env.draft(eid, me, bytes32(uint256(1)), "cid", _one(me), 1, 0, bytes32(0));
        vm.prank(attacker);
        env.close(eid, me);

        (IGovernanceProtocol.Verdict v,,) = ta.check(TENANT, ACTION, _ctx(a1));
        assertTrue(uint8(v) != uint8(IGovernanceProtocol.Verdict.Deny), "an outsider's squat+close must not force Deny");
        assertTrue(uint8(v) != uint8(IGovernanceProtocol.Verdict.Allow), "and it is not an approval either");
    }

    /// F4-03b inverted (PBA-L2-035): an outsider cannot reject a Delivered,
    /// fully-approved envelope; the verdict stays Allow.
    function test_L2_035_outsiderCannotRejectDelivered() public {
        bytes32[] memory approvers = new bytes32[](1);
        approvers[0] = QuorumIdentity.subjectKey(a1);
        ThresholdApproval ta =
            new ThresholdApproval(TENANT, keccak256("ta"), 1, keccak256("spec"), "cid", address(env), approvers, 1);
        bytes32 eid = ta.approvalEnvelopeId(ACTION, PARAMS, CORR);
        vm.startPrank(a1);
        env.draft(eid, approvers[0], bytes32(uint256(1)), "cid", approvers, 1, 0, bytes32(0));
        env.sign(eid, approvers[0], hex"01", "x");
        env.markDelivered(eid);
        vm.stopPrank();

        (IGovernanceProtocol.Verdict v0,,) = ta.check(TENANT, ACTION, _ctx(a1));
        assertEq(uint8(v0), uint8(IGovernanceProtocol.Verdict.Allow));

        vm.prank(attacker);
        try env.reject(eid, "griefed") {} catch {}
        (IGovernanceProtocol.Verdict v1,,) = ta.check(TENANT, ACTION, _ctx(a1));
        assertEq(uint8(v1), uint8(IGovernanceProtocol.Verdict.Allow), "outsider reject must not flip Allow to Deny");
    }
}
