// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {MultiSigEnvelope} from "../../src/rbac/MultiSigEnvelope.sol";
import {QuorumIdentity} from "../../src/quorum/QuorumIdentity.sol";
import {IGovernanceProtocol} from "../../src/quorum/IGovernanceProtocol.sol";
import {SegregationOfDuties} from "../../src/quorum/SegregationOfDuties.sol";

/// `SegregationOfDuties.check` must ignore an envelope that was drafted by an
/// address outside its roster, whatever state that envelope reaches: a roster
/// approval on it does not allow the action, and the drafter closing it does
/// not deny the action.
contract SegregationOfDutiesForeignProposerTest is Test {
    MultiSigEnvelope internal env;
    SegregationOfDuties internal sod;
    bytes32[] internal roster;

    address internal constant P = address(0xB0B1);
    address internal constant APPROVER = address(0xB0B2);
    address internal constant EXEC = address(0xB0B3);
    address internal constant OUTSIDER = address(0x0D7);
    bytes32 internal constant TENANT = keccak256("tenant-A");
    bytes32 internal constant ACTION = keccak256("action.deploy");

    function setUp() public {
        env = new MultiSigEnvelope();
        roster = new bytes32[](3);
        roster[0] = QuorumIdentity.subjectKey(P);
        roster[1] = QuorumIdentity.subjectKey(APPROVER);
        roster[2] = QuorumIdentity.subjectKey(EXEC);
        sod = new SegregationOfDuties(TENANT, keccak256("sod"), 1, keccak256("spec"), "cid", address(env), 1, roster);
    }

    function _ctx() internal pure returns (IGovernanceProtocol.ActionContext memory) {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: 0,
            principal: EXEC,
            classification: 0,
            cost: 0,
            paramsHash: keccak256("params"),
            correlationId: keccak256("corr-1")
        });
    }

    function _draftAs(address drafter) internal returns (bytes32 eid) {
        eid = sod.approvalEnvelopeId(ACTION, keccak256("params"), keccak256("corr-1"));
        bytes32[] memory req = new bytes32[](1);
        req[0] = roster[1];
        vm.prank(drafter);
        env.draft(eid, QuorumIdentity.subjectKey(drafter), bytes32(0), "cid", req, 1, 0, bytes32(0));
    }

    function test_rosterApprovalOnAnOutsiderDraftDoesNotAllow() public {
        bytes32 eid = _draftAs(OUTSIDER);
        vm.prank(APPROVER);
        env.sign(eid, roster[1], hex"01", "x");
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(TENANT, ACTION, _ctx());
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval), "outsider draft must not allow");
        assertEq(reason, sod.REASON_FOREIGN_PROPOSER());
    }

    function test_outsiderClosingItsDraftDoesNotDeny() public {
        bytes32 eid = _draftAs(OUTSIDER);
        vm.prank(OUTSIDER);
        env.close(eid, QuorumIdentity.subjectKey(OUTSIDER));
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(TENANT, ACTION, _ctx());
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval), "outsider close must not deny");
        assertEq(reason, sod.REASON_FOREIGN_PROPOSER());
    }

    function test_rosterProposerWithRosterApprovalAllows() public {
        bytes32 eid = _draftAs(P);
        vm.prank(APPROVER);
        env.sign(eid, roster[1], hex"01", "x");
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = sod.check(TENANT, ACTION, _ctx());
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, sod.REASON_SATISFIED());
    }
}
