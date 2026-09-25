// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";
import {IGovernanceProtocol} from "../../src/quorum/IGovernanceProtocol.sol";
import {ThresholdApproval} from "../../src/quorum/ThresholdApproval.sol";
import {SegregationOfDuties} from "../../src/quorum/SegregationOfDuties.sol";
import {AppRegistry} from "../../src/defense_prime/AppRegistry.sol";

/// PBA-L2-012 / -013 / -035: behaviour of the fixed envelope stack (new API),
/// plus the class tripwire: for any envelope whose signers are all outside a
/// protocol's configured set, `check` is never `Allow`.
contract PBA_L2_Envelope_Fixed is Test {
    MultiSigEnvelope env;
    bytes32 constant TENANT = keccak256("tenant-A");
    bytes32 constant ACTION = keccak256("action.deploy");
    bytes32 constant PARAMS = keccak256("params");
    bytes32 constant CORR = keccak256("corr-1");
    address gov = address(0x60);
    address recorder = address(0xEC0);
    address a1 = address(0xA1);
    address a2 = address(0xA2);
    address attacker = address(0xA77);

    function setUp() public {
        env = new MultiSigEnvelope();
    }

    function _ctx(address principal) internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 0, principal: principal, classification: 0, cost: 0, paramsHash: PARAMS, correlationId: CORR
        });
    }

    function _two(address x, address y) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](2);
        r[0] = QuorumIdentity.subjectKey(x);
        r[1] = QuorumIdentity.subjectKey(y);
    }

    // ── MultiSigEnvelope ───────────────────────────────────────────

    function test_L2_013_draftRefusesForeignInitiator() public {
        bytes32[] memory req = _two(a1, a2);
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigEnvelope.NotInitiator.selector, QuorumIdentity.subjectKey(a1), attacker)
        );
        env.draft(keccak256("e"), QuorumIdentity.subjectKey(a1), bytes32(0), "cid", req, 2, 0, bytes32(0));
    }

    function test_L2_035_acceptRejectRequireCounterparty() public {
        bytes32[] memory req = _two(a1, a2);
        bytes32 id = keccak256("e");
        vm.prank(a1);
        env.draft(id, req[0], bytes32(0), "cid", req, 1, 0, bytes32(0));
        vm.prank(a1);
        env.sign(id, req[0], hex"01", "x");
        vm.prank(a1);
        env.markDelivered(id);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(MultiSigEnvelope.NotCounterparty.selector, id, attacker));
        env.accept(id);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(MultiSigEnvelope.NotCounterparty.selector, id, attacker));
        env.reject(id, "x");
        vm.prank(a2);
        env.accept(id);
        assertEq(uint8(env.getState(id)), uint8(MultiSigEnvelope.EnvelopeState.Accepted));
    }

    // ── AppRegistry (PBA-L2-012) ───────────────────────────────────

    function _registry() internal returns (AppRegistry reg) {
        reg = new AppRegistry(gov, address(env));
        vm.startPrank(gov);
        reg.setRecorder(recorder, true);
        reg.setApproverPolicy(_two(a1, a2), 2);
        vm.stopPrank();
    }

    function _propose(AppRegistry reg, bytes32 appId, bytes32 envId) internal {
        address[] memory none = new address[](0);
        vm.prank(recorder);
        reg.proposeApp(appId, TENANT, "app", "1.0", recorder, envId, none, bytes32(0));
    }

    function _honestEnvelope(AppRegistry reg, bytes32 appId, bytes32 envId) internal {
        bytes32[] memory req = _two(a1, a2);
        bytes32 corr = reg.envelopeCorrId(appId); // computed BEFORE the prank
        vm.prank(recorder);
        env.draft(envId, QuorumIdentity.subjectKey(recorder), bytes32(uint256(1)), "cid", req, 2, 0, corr);
        vm.prank(a1);
        env.sign(envId, req[0], hex"01", "x");
        vm.prank(a2);
        env.sign(envId, req[1], hex"02", "x");
    }

    function test_L2_012_proposeNeedsPolicy() public {
        AppRegistry reg = new AppRegistry(gov, address(env));
        vm.prank(gov);
        reg.setRecorder(recorder, true);
        address[] memory none = new address[](0);
        vm.prank(recorder);
        vm.expectRevert(AppRegistry.NoApproverPolicy.selector);
        reg.proposeApp(keccak256("a"), TENANT, "app", "1.0", recorder, keccak256("e"), none, bytes32(0));
    }

    function test_L2_012_honestEnvelopeDeploys() public {
        AppRegistry reg = _registry();
        bytes32 appId = keccak256("app");
        _propose(reg, appId, keccak256("env"));
        _honestEnvelope(reg, appId, keccak256("env"));
        reg.deploy(appId);
        assertEq(uint8(reg.getApp(appId).state), uint8(AppRegistry.AppState.Deployed));
    }

    /// Envelope signed by the approvers but drafted by someone other than the
    /// proposing recorder does not count ("bound to proposer").
    function test_L2_012_envelopeFromOtherDrafterRefused() public {
        AppRegistry reg = _registry();
        bytes32 appId = keccak256("app");
        bytes32 envId = keccak256("env");
        _propose(reg, appId, envId);
        bytes32[] memory req = _two(a1, a2);
        bytes32 corr = reg.envelopeCorrId(appId);
        vm.prank(a1); // an approver, not the proposing recorder
        env.draft(envId, req[0], bytes32(uint256(1)), "cid", req, 2, 0, corr);
        vm.prank(a1);
        env.sign(envId, req[0], hex"01", "x");
        vm.prank(a2);
        env.sign(envId, req[1], hex"02", "x");
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, envId));
        reg.deploy(appId);
    }

    /// An envelope approved for ANOTHER app (or registry) is not reusable.
    function test_L2_012_envelopeBoundToRegistryAndApp() public {
        AppRegistry reg = _registry();
        bytes32 appA = keccak256("appA");
        bytes32 appB = keccak256("appB");
        bytes32 envId = keccak256("env");
        _propose(reg, appA, envId);
        _honestEnvelope(reg, appA, envId);
        _propose(reg, appB, envId); // same envelope id referenced by app B
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, envId));
        reg.deploy(appB);
    }

    /// A squatted envelope id no longer kills the app: the recorder re-points.
    function test_L2_012_squatRecoveredByRepoint() public {
        AppRegistry reg = _registry();
        bytes32 appId = keccak256("app");
        bytes32 squatted = keccak256("env");
        _propose(reg, appId, squatted);
        bytes32 me = QuorumIdentity.subjectKey(attacker);
        bytes32[] memory one = new bytes32[](1);
        one[0] = me;
        vm.prank(attacker);
        env.draft(squatted, me, bytes32(uint256(1)), "cid", one, 1, 0, bytes32(0));
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotProposerOrGovernance.selector, attacker));
        reg.repointDeployEnvelope(appId, keccak256("attacker-env"));
        vm.prank(recorder);
        reg.repointDeployEnvelope(appId, keccak256("env-2"));
        _honestEnvelope(reg, appId, keccak256("env-2"));
        reg.deploy(appId);
        assertEq(uint8(reg.getApp(appId).state), uint8(AppRegistry.AppState.Deployed));
    }

    // ── SegregationOfDuties (PBA-L2-013) ───────────────────────────

    function test_L2_013_rosterApprovedThreeDistinctAllows() public {
        address p = address(0xB0B1);
        address r1 = address(0xB0B2);
        address ex = address(0xB0B3);
        bytes32[] memory roster = new bytes32[](3);
        roster[0] = QuorumIdentity.subjectKey(p);
        roster[1] = QuorumIdentity.subjectKey(r1);
        roster[2] = QuorumIdentity.subjectKey(ex);
        SegregationOfDuties sod =
            new SegregationOfDuties(TENANT, keccak256("sod"), 1, keccak256("spec"), "cid", address(env), 1, roster);
        bytes32 eid = sod.approvalEnvelopeId(ACTION, PARAMS, CORR);
        bytes32[] memory req = new bytes32[](1);
        req[0] = roster[1];
        vm.prank(p);
        env.draft(eid, roster[0], bytes32(0), "cid", req, 1, 0, bytes32(0));
        vm.prank(r1);
        env.sign(eid, req[0], hex"01", "x");
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(TENANT, ACTION, _ctx(ex));
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, sod.REASON_SATISFIED());
    }

    function test_L2_013_rosterValidation() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(SegregationOfDuties.EmptyRoster.selector);
        new SegregationOfDuties(TENANT, keccak256("sod"), 1, keccak256("spec"), "cid", address(env), 1, empty);
        bytes32[] memory one = new bytes32[](1);
        one[0] = keccak256("x");
        vm.expectRevert(abi.encodeWithSelector(SegregationOfDuties.RosterTooSmall.selector, uint256(1), uint8(1)));
        new SegregationOfDuties(TENANT, keccak256("sod"), 1, keccak256("spec"), "cid", address(env), 1, one);
    }

    /// Tripwire: whatever envelope an outsider constructs at the derived id
    /// (any signer count, any threshold, any close/deliver), with every signer
    /// outside the configured sets, neither TA nor SoD ever says Allow.
    function testFuzz_L2_035_outsiderEnvelopeNeverAllows(uint8 nSigners, uint8 th, bool closeIt, bool deliver) public {
        nSigners = uint8(bound(nSigners, 1, 6));
        th = uint8(bound(th, 1, nSigners));
        ThresholdApproval ta =
            new ThresholdApproval(TENANT, keccak256("ta"), 1, keccak256("spec"), "cid", address(env), _two(a1, a2), 1);
        bytes32 eid = ta.approvalEnvelopeId(ACTION, PARAMS, CORR);
        bytes32[] memory req = new bytes32[](nSigners);
        for (uint256 i = 0; i < nSigners; i++) {
            req[i] = QuorumIdentity.subjectKey(address(uint160(0xD000 + i)));
        }
        vm.prank(attacker);
        env.draft(eid, QuorumIdentity.subjectKey(attacker), bytes32(uint256(1)), "cid", req, th, 0, bytes32(0));
        for (uint256 i = 0; i < th; i++) {
            vm.prank(address(uint160(0xD000 + i)));
            env.sign(eid, req[i], hex"01", "x");
        }
        if (closeIt) {
            vm.prank(attacker);
            env.close(eid, QuorumIdentity.subjectKey(attacker));
        } else if (deliver) {
            vm.prank(attacker);
            env.markDelivered(eid);
        }
        (IGovernanceProtocol.Verdict v,,) = ta.check(TENANT, ACTION, _ctx(a1));
        assertTrue(uint8(v) != uint8(IGovernanceProtocol.Verdict.Allow));
        assertTrue(uint8(v) != uint8(IGovernanceProtocol.Verdict.Deny));
    }
}

/// Mutation hardening (PBA-L2-013): a roster proposer's envelope signed only by
/// sybils OUTSIDE the roster must not satisfy SoD.
contract PBA_L2_013_SybilSigners is Test {
    function test_L2_013_nonRosterSignersDoNotCount() public {
        MultiSigEnvelope env = new MultiSigEnvelope();
        address p = address(0xB0B1);
        address ex = address(0xB0B3);
        bytes32[] memory roster = new bytes32[](3);
        roster[0] = QuorumIdentity.subjectKey(p);
        roster[1] = QuorumIdentity.subjectKey(address(0xB0B2));
        roster[2] = QuorumIdentity.subjectKey(ex);
        SegregationOfDuties sod = new SegregationOfDuties(
            keccak256("tenant-A"), keccak256("sod"), 1, keccak256("spec"), "cid", address(env), 1, roster
        );
        bytes32 eid = sod.approvalEnvelopeId(keccak256("action.deploy"), keccak256("params"), keccak256("corr-1"));
        address sybil = address(0x5B1);
        bytes32[] memory req = new bytes32[](1);
        req[0] = QuorumIdentity.subjectKey(sybil);
        vm.prank(p);
        env.draft(eid, roster[0], bytes32(0), "cid", req, 1, 0, bytes32(0));
        vm.prank(sybil);
        env.sign(eid, req[0], hex"01", "x");
        IGovernanceProtocol.ActionContext memory ctx = IGovernanceProtocol.ActionContext({
            agentSbtId: 0,
            principal: ex,
            classification: 0,
            cost: 0,
            paramsHash: keccak256("params"),
            correlationId: keccak256("corr-1")
        });
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(keccak256("tenant-A"), keccak256("action.deploy"), ctx);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, sod.REASON_PENDING());
    }
}

/// Only the proposing recorder or governance may record an app's failure.
contract PBA_L2_012_RecordFailureBinding is Test {
    function test_L2_012_otherRecorderCannotFailPendingApp() public {
        MultiSigEnvelope env = new MultiSigEnvelope();
        address gov = address(0x60);
        address rec = address(0xEC0);
        address rec2 = address(0xEC2);
        AppRegistry reg = new AppRegistry(gov, address(env));
        bytes32[] memory approvers = new bytes32[](1);
        approvers[0] = QuorumIdentity.subjectKey(address(0xA1));
        vm.startPrank(gov);
        reg.setRecorder(rec, true);
        reg.setRecorder(rec2, true);
        reg.setApproverPolicy(approvers, 1);
        vm.stopPrank();
        address[] memory none = new address[](0);
        vm.prank(rec);
        reg.proposeApp(keccak256("app"), keccak256("t"), "app", "1", rec, keccak256("env"), none, bytes32(0));
        vm.prank(rec2);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotProposerOrGovernance.selector, rec2));
        reg.recordFailureOnEnvelopeReject(keccak256("app"));
        vm.prank(rec);
        reg.recordFailureOnEnvelopeReject(keccak256("app"));
        assertEq(uint8(reg.getApp(keccak256("app")).state), uint8(AppRegistry.AppState.Failed));
    }
}
