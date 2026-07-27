// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IGovernanceProtocol} from "../src/quorum/IGovernanceProtocol.sol";
import {BudgetedAutonomy} from "../src/quorum/BudgetedAutonomy.sol";
import {TimeBoundedElevation, IRoleEscalation} from "../src/quorum/TimeBoundedElevation.sol";
import {IncidentEscalation, IContradictionLedger} from "../src/quorum/IncidentEscalation.sol";
import {QuorumIdentity} from "../src/quorum/QuorumIdentity.sol";
import {RoleEscalation} from "../src/rbac/RoleEscalation.sol";
import {ContradictionLedger} from "../src/rbac/ContradictionLedger.sol";

/// @title The three state-reading seed templates — invariant tests (QRM-S6.7)
///
/// `BudgetedAutonomy`, `TimeBoundedElevation` and `IncidentEscalation`, the last
/// two against the real deployed `RoleEscalation` and `ContradictionLedger`.
contract SeedTemplatesStateTest is Test {
    BudgetedAutonomy ba;
    TimeBoundedElevation tbe;
    IncidentEscalation ie;
    RoleEscalation escalations;
    ContradictionLedger ledger;

    bytes32 constant TENANT = keccak256("Citrate");
    bytes32 constant OTHER = keccak256("Elsewhere");
    bytes32 constant CHEAP = keccak256("repo.write");
    bytes32 constant MONEY = keccak256("treasury.transfer");
    bytes32 constant SPEC_HASH = keccak256("spec");
    string constant SPEC_CID = "bafySpec";

    address constant OPERATOR = address(0xA11CE);
    address constant OUTSIDER = address(0xBEEF);
    bytes32 constant APPROVER = keccak256("approver");
    bytes32 constant RESPONDER = keccak256("responder");
    bytes32 constant ONCALL_ROLE = keccak256("role:sre-oncall");
    bytes32 constant BASE_ROLE = keccak256("role:engineer");

    uint256 constant AGENT = 7;
    uint256 constant CEILING = 100;
    uint64 constant START = 1_700_000_000;
    uint64 constant SLA = 4 hours;

    function setUp() public {
        vm.warp(START);

        bytes32[] memory approvers = new bytes32[](1);
        approvers[0] = APPROVER;
        bytes32[] memory always_ = new bytes32[](1);
        always_[0] = MONEY;
        ba = new BudgetedAutonomy(
            TENANT, keccak256("ba"), 1, SPEC_HASH, SPEC_CID, CEILING, always_, approvers
        );

        escalations = new RoleEscalation(address(this));
        tbe = new TimeBoundedElevation(
            TENANT, keccak256("tbe"), 1, SPEC_HASH, SPEC_CID, address(escalations), ONCALL_ROLE
        );

        ledger = new ContradictionLedger(address(this));
        ledger.setResolver(address(this), true);
        bytes32[] memory responders = new bytes32[](1);
        responders[0] = RESPONDER;
        ie = new IncidentEscalation(
            TENANT, keccak256("ie"), 1, SPEC_HASH, SPEC_CID, address(ledger), responders, SLA, 8
        );
    }

    function _ctx(address principal, uint256 agentSbtId, uint256 cost)
        internal
        pure
        returns (IGovernanceProtocol.ActionContext memory)
    {
        return IGovernanceProtocol.ActionContext({
            agentSbtId: agentSbtId,
            principal: principal,
            classification: 0,
            cost: cost,
            paramsHash: keccak256("params"),
            correlationId: keccak256("corr")
        });
    }

    // ══ BudgetedAutonomy ════════════════════════════════════════════

    /// The line is the whole point: at or below it the agent acts unattended,
    /// above it a human signs. The boundary is inclusive, because "up to 100" is
    /// what an operator means when they write 100.
    function test_BA_theCeilingIsTheLineAndItIsInclusive() public view {
        (IGovernanceProtocol.Verdict at, bytes32 r1,) = ba.check(TENANT, CHEAP, _ctx(OPERATOR, AGENT, CEILING));
        assertEq(uint8(at), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r1, ba.REASON_UNATTENDED());

        (IGovernanceProtocol.Verdict over, bytes32 r2, bytes32[] memory who) =
            ba.check(TENANT, CHEAP, _ctx(OPERATOR, AGENT, CEILING + 1));
        assertEq(uint8(over), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, ba.REASON_OVER_CEILING());
        assertEq(who.length, 1, "and it says who signs");
        assertEq(who[0], APPROVER);
    }

    /// Some classes always need a human however cheap they are — chain, money,
    /// keys, grants, classification (L-1 of the HIC model). Checked BEFORE the
    /// ceiling, so the operator is told which rule applied rather than merely
    /// that one did.
    function test_BA_mandatoryClassesAreNotCheapEnoughable() public view {
        (IGovernanceProtocol.Verdict v, bytes32 reason,) = ba.check(TENANT, MONEY, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, ba.REASON_ALWAYS_SIGNED(), "a zero-cost money action still signs");
        assertTrue(reason != ba.REASON_OVER_CEILING(), "and for a stated reason of its own");
    }

    /// A ceiling of zero means "nothing is unattended" — a legitimate and
    /// legible setting, not a misconfiguration.
    function test_BA_aZeroCeilingMeansNothingIsUnattended() public {
        bytes32[] memory approvers = new bytes32[](1);
        approvers[0] = APPROVER;
        BudgetedAutonomy strict =
            new BudgetedAutonomy(TENANT, keccak256("ba0"), 1, SPEC_HASH, SPEC_CID, 0, new bytes32[](0), approvers);

        (IGovernanceProtocol.Verdict free, bytes32 r1,) = strict.check(TENANT, CHEAP, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(free), uint8(IGovernanceProtocol.Verdict.Allow), "a costless action is still costless");
        assertEq(r1, strict.REASON_UNATTENDED());

        (IGovernanceProtocol.Verdict any, bytes32 r2,) = strict.check(TENANT, CHEAP, _ctx(OPERATOR, AGENT, 1));
        assertEq(uint8(any), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, strict.REASON_OVER_CEILING());
    }

    /// An escalation with nobody to escalate to is a Deny that calls itself an
    /// approval.
    function test_BA_refusesAPolicyWithNobodyToEscalateTo() public {
        vm.expectRevert(BudgetedAutonomy.EmptyApproverSet.selector);
        new BudgetedAutonomy(TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, CEILING, new bytes32[](0), new bytes32[](0));
    }

    // ══ TimeBoundedElevation ════════════════════════════════════════

    function _elevate(address who, bytes32 role, uint32 duration) internal {
        bytes32 user = QuorumIdentity.subjectKey(who);
        escalations.setBaseRole(user, TENANT, BASE_ROLE);
        escalations.requestElevation(user, TENANT, role, duration, keccak256("corr"), hex"5163", "webauthn");
    }

    function _tbeCheck(address who) internal view returns (IGovernanceProtocol.Verdict v, bytes32 reason) {
        (v, reason,) = tbe.check(TENANT, CHEAP, _ctx(who, AGENT, 0));
    }

    /// The capability exists only while the window is open. Nothing has to be
    /// revoked when it closes, because nothing was granted permanently.
    function test_TBE_theCapabilityClosesWithTheWindow() public {
        _elevate(OPERATOR, ONCALL_ROLE, 3600);

        (IGovernanceProtocol.Verdict live, bytes32 r1) = _tbeCheck(OPERATOR);
        assertEq(uint8(live), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r1, tbe.REASON_ELEVATED());

        vm.warp(START + 3601);
        (IGovernanceProtocol.Verdict expired, bytes32 r2) = _tbeCheck(OPERATOR);
        assertEq(uint8(expired), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r2, tbe.REASON_NOT_ELEVATED(), "and the remedy is a ceremony, not despair");
    }

    /// An elevation obtained for one purpose must not authorise a different one.
    /// `isActiveNow` answers "is there an elevation", not "to what" — a protocol
    /// that stopped there would be a confused deputy.
    function test_TBE_anElevationToAnotherRoleDoesNotCount() public {
        _elevate(OPERATOR, keccak256("role:billing-admin"), 3600);

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _tbeCheck(OPERATOR);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, tbe.REASON_WRONG_ROLE());
        assertTrue(escalations.isActiveNow(QuorumIdentity.subjectKey(OPERATOR), TENANT), "an elevation exists");
    }

    /// Someone with no grant history is not a member with a base role, so there
    /// is nothing to elevate. Administrative, not a ceremony — hence `Deny`
    /// rather than `RequireApproval`.
    function test_TBE_aNonMemberIsADifferentProblemFromAnUnelevatedMember() public {
        (IGovernanceProtocol.Verdict v, bytes32 reason) = _tbeCheck(OUTSIDER);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, tbe.REASON_NO_MEMBERSHIP());

        _elevate(OPERATOR, ONCALL_ROLE, 3600);
        escalations.stepDown(QuorumIdentity.subjectKey(OPERATOR), TENANT, keccak256("corr"));
        (IGovernanceProtocol.Verdict member, bytes32 memberReason) = _tbeCheck(OPERATOR);
        assertEq(uint8(member), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(memberReason, tbe.REASON_NOT_ELEVATED());
    }

    /// A protocol that accepted "any role" would be a confused deputy by
    /// construction, so it cannot be deployed.
    function test_TBE_refusesToBeDeployedWithoutARole() public {
        vm.expectRevert(TimeBoundedElevation.ZeroRole.selector);
        new TimeBoundedElevation(
            TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, address(escalations), bytes32(0)
        );
    }

    // ══ IncidentEscalation ══════════════════════════════════════════

    function _report(bytes32 id, uint256 agentSbtId) internal {
        ledger.report(
            id, bytes32(agentSbtId), "output", keccak256("src-a"), keccak256("src-b"), "yes", "no",
            keccak256("detector"), keccak256("corr")
        );
    }

    function _ieCheck(uint256 agentSbtId) internal view returns (IGovernanceProtocol.Verdict v, bytes32 reason) {
        (v, reason,) = ie.check(TENANT, CHEAP, _ctx(OPERATOR, agentSbtId, 0));
    }

    /// The ladder: clear → a human takes it → it stops. The last rung has to be
    /// a stop, because an escalation ladder whose top rung is "escalate harder"
    /// never terminates — it degrades into everything sitting at the top and
    /// being approved by whoever is available.
    function test_IE_theLadderEndsInAStopNotAnotherEscalation() public {
        (IGovernanceProtocol.Verdict clear, bytes32 r0) = _ieCheck(AGENT);
        assertEq(uint8(clear), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(r0, ie.REASON_CLEAR());

        _report(keccak256("c1"), AGENT);

        (IGovernanceProtocol.Verdict open, bytes32 r1, bytes32[] memory who) =
            ie.check(TENANT, CHEAP, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(open), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(r1, ie.REASON_OPEN_INCIDENT());
        assertEq(who[0], RESPONDER);

        vm.warp(START + SLA + 1);
        (IGovernanceProtocol.Verdict breached, bytes32 r2) = _ieCheck(AGENT);
        assertEq(uint8(breached), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r2, ie.REASON_SLA_BREACHED());
    }

    /// Resolving the contradiction is what lifts it. The remedy is fixing the
    /// underlying disagreement, not obtaining a bigger signature.
    function test_IE_resolvingTheContradictionLiftsTheGate() public {
        _report(keccak256("c1"), AGENT);
        vm.warp(START + SLA + 1);
        (IGovernanceProtocol.Verdict breached,) = _ieCheck(AGENT);
        assertEq(uint8(breached), uint8(IGovernanceProtocol.Verdict.Deny));

        ledger.resolve(keccak256("c1"), "Resolved-A", keccak256("decision"), keccak256("corr"));

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ieCheck(AGENT);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, ie.REASON_CLEAR());
    }

    /// The SLA runs from the OLDEST open contradiction, not the newest. A stream
    /// of fresh reports must not keep resetting the clock on an old one that was
    /// never dealt with.
    function test_IE_theSlaRunsFromTheOldestOpenIncident() public {
        _report(keccak256("old"), AGENT);
        vm.warp(START + SLA - 1);
        _report(keccak256("new"), AGENT);

        (IGovernanceProtocol.Verdict within,) = _ieCheck(AGENT);
        assertEq(uint8(within), uint8(IGovernanceProtocol.Verdict.RequireApproval));

        vm.warp(START + SLA + 1);
        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ieCheck(AGENT);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, ie.REASON_SLA_BREACHED(), "a fresh report does not reset an old clock");
    }

    /// An escalated (Investigating) contradiction is still open. Escalating is
    /// how the ladder is climbed, not how it is escaped.
    function test_IE_investigatingIsStillOpen() public {
        _report(keccak256("c1"), AGENT);
        ledger.escalate(keccak256("c1"), keccak256("corr"));

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ieCheck(AGENT);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.RequireApproval));
        assertEq(reason, ie.REASON_OPEN_INCIDENT());
    }

    /// A human acting directly is already the escalation target; gating them
    /// would make the ladder circular.
    function test_IE_aHumanActingDirectlyIsNotGated() public {
        _report(keccak256("c1"), AGENT);
        vm.warp(START + SLA + 1);

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ieCheck(0);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Allow));
        assertEq(reason, ie.REASON_HUMAN_ACTING());
    }

    /// An agent with a long contradiction history must not be able to make its
    /// own actions un-checkable. When the bounded scan cannot reach what the
    /// ledger says is open, it says so instead of quietly reporting "within
    /// SLA" — a truncated read must not become a permissive answer.
    function test_IE_aTruncatedScanFailsClosedAndSaysSo() public {
        // 8 resolved contradictions fill the scan window; the 9th is open and
        // out of reach.
        for (uint256 i = 0; i < 8; ++i) {
            bytes32 id = keccak256(abi.encode("resolved", i));
            _report(id, AGENT);
            ledger.resolve(id, "Resolved-A", keccak256("decision"), keccak256("corr"));
        }
        _report(keccak256("unreachable"), AGENT);

        (IGovernanceProtocol.Verdict v, bytes32 reason) = _ieCheck(AGENT);
        assertEq(uint8(v), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(reason, ie.REASON_SCAN_TRUNCATED());
    }

    /// A zero SLA would make every open contradiction an instant hard stop,
    /// skipping the human rung entirely. That is a different control and should
    /// be configured as one, not arrived at by leaving a field unset.
    function test_IE_refusesAZeroSla() public {
        bytes32[] memory responders = new bytes32[](1);
        responders[0] = RESPONDER;
        vm.expectRevert(IncidentEscalation.ZeroSla.selector);
        new IncidentEscalation(TENANT, keccak256("x"), 1, SPEC_HASH, SPEC_CID, address(ledger), responders, 0, 8);
    }

    // ══ Shared ══════════════════════════════════════════════════════

    /// Every template refuses to answer for a tenant it was not deployed for.
    function test_allThreeRefuseToAnswerForAnotherTenant() public view {
        (IGovernanceProtocol.Verdict v1, bytes32 r1,) = ba.check(OTHER, CHEAP, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(v1), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r1, ba.REASON_WRONG_TENANT());

        (IGovernanceProtocol.Verdict v2, bytes32 r2,) = tbe.check(OTHER, CHEAP, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(v2), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r2, tbe.REASON_WRONG_TENANT());

        (IGovernanceProtocol.Verdict v3, bytes32 r3,) = ie.check(OTHER, CHEAP, _ctx(OPERATOR, AGENT, 0));
        assertEq(uint8(v3), uint8(IGovernanceProtocol.Verdict.Deny));
        assertEq(r3, ie.REASON_WRONG_TENANT());
    }

    /// All eight seed templates carry their provenance: from a live address a
    /// verifier reaches the audited template and the spec it claims to implement.
    function test_provenanceIsReadableFromEachProtocol() public view {
        (bytes32 t1,) = ba.template();
        (bytes32 t2,) = tbe.template();
        (bytes32 t3,) = ie.template();
        assertEq(t1, keccak256("ba"));
        assertEq(t2, keccak256("tbe"));
        assertEq(t3, keccak256("ie"));

        (bytes32 h, string memory cid) = ie.spec();
        assertEq(h, SPEC_HASH);
        assertEq(cid, SPEC_CID);
    }
}
