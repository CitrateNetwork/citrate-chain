// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {InstitutionalVault} from "../../src/edu/InstitutionalVault.sol";
import {ClassroomRegistry} from "../../src/ClassroomRegistry.sol";
import {ClassroomClusterV1} from "../../src/edu/ClassroomClusterV1.sol";
import {Forwarder} from "../../src/edu/Forwarder.sol";
import {IForwarder} from "../../src/edu/interfaces/IForwarder.sol";
import {BudgetAllocation} from "../../src/edu/BudgetAllocation.sol";
import {IClassroomCluster} from "../../src/edu/interfaces/IClassroomCluster.sol";
import {MultisigTimelock2of3} from "../../src/cit_agent/MultisigTimelock2of3.sol";

contract CounterR2 {
    uint256 public count;

    function increment() external {
        count++;
    }
}

/// PBA-R2 CONTRACTS-A: evidence/F3/PBA_F3.t.sol turned into regression tests
/// with INVERTED assertions, plus the F3 medium/low findings in scope.
contract PBA_R2_F3 is Test {
    address A = address(0xA11CE);
    address B = address(0xB0B);
    address C = address(0xC0C);
    address attacker = address(0xBAD);

    function _vault(uint256 threshold) internal returns (InstitutionalVault v) {
        address[] memory s = new address[](3);
        s[0] = A;
        s[1] = B;
        s[2] = C;
        v = new InstitutionalVault(s, threshold);
        vm.deal(address(v), 50 ether);
    }

    // ── PBA-L2-009 ──────────────────────────────────────────────────

    /// F3-01 inverted: pre-approving a not-yet-existing id reverts, so a
    /// threshold-1 vault can no longer be drained by its own proposer.
    function test_L2_009_preapproval_rejected_threshold1() public {
        InstitutionalVault v = _vault(1);
        vm.startPrank(A);
        vm.expectRevert(InstitutionalVault.CashoutNotFound.selector);
        v.approveCashout(0);
        uint256 id = v.proposeCashout(A, 50 ether, bytes32("x"));
        vm.expectRevert(InstitutionalVault.SelfApproval.selector);
        v.approveCashout(id);
        vm.expectRevert(InstitutionalVault.QuorumNotMet.selector);
        v.executeCashout(id);
        vm.stopPrank();
        assertEq(address(v).balance, 50 ether);
    }

    function test_L2_009_preapproval_2of3_needs_two_non_proposers() public {
        InstitutionalVault v = _vault(2);
        vm.prank(A);
        vm.expectRevert(InstitutionalVault.CashoutNotFound.selector);
        v.approveCashout(0);
        vm.prank(A);
        uint256 id = v.proposeCashout(A, 50 ether, bytes32("x"));
        vm.prank(B);
        v.approveCashout(id);
        vm.prank(A);
        vm.expectRevert(InstitutionalVault.QuorumNotMet.selector);
        v.executeCashout(id);
        vm.prank(C);
        v.approveCashout(id);
        vm.prank(A);
        v.executeCashout(id);
        assertEq(A.balance, 50 ether);
    }

    /// Tripwire: approving / rejecting a non-existent id reverts for every
    /// proposal type.
    function test_L2_009_nonexistent_ids_revert() public {
        InstitutionalVault v = _vault(2);
        vm.startPrank(A);
        vm.expectRevert(InstitutionalVault.CashoutNotFound.selector);
        v.rejectCashout(5);
        vm.expectRevert(InstitutionalVault.SignerProposalNotFound.selector);
        v.approveSignerChange(0);
        vm.expectRevert(InstitutionalVault.SignerProposalNotFound.selector);
        v.rejectSignerChange(0);
        vm.expectRevert(InstitutionalVault.ThresholdProposalNotFound.selector);
        v.approveThresholdChange(0);
        vm.expectRevert(InstitutionalVault.ThresholdProposalNotFound.selector);
        v.rejectThresholdChange(0);
        vm.stopPrank();
    }

    /// Tripwire (fuzz): for every executed cashout, the number of live
    /// NON-PROPOSER approvers is at least the threshold.
    function testFuzz_L2_009_executed_cashout_has_threshold_non_proposers(uint8 approverMask, uint8 thr) public {
        uint256 threshold = bound(thr, 1, 3);
        InstitutionalVault v = _vault(threshold);
        address[3] memory s = [A, B, C];
        vm.prank(A);
        uint256 id = v.proposeCashout(A, 1 ether, bytes32("x"));
        uint256 nonProposer;
        for (uint256 i = 0; i < 3; i++) {
            if (approverMask & (1 << i) == 0) continue;
            vm.prank(s[i]);
            try v.approveCashout(id) {
                if (s[i] != A) nonProposer++;
            } catch {}
        }
        vm.prank(A);
        try v.executeCashout(id) {
            assertGe(nonProposer, threshold, "executed without threshold non-proposer approvals");
        } catch {}
    }

    // ── PBA-L2-010 ──────────────────────────────────────────────────

    uint256 constant INVITE_PK = 0xC0DE5EC4E7;

    function _inviteSig(ClassroomRegistry r, address teacher, address student, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        address key = vm.addr(pk);
        bytes32 h = keccak256(abi.encodePacked(key));
        bytes32 d = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", r.enrollmentDigest(teacher, student, h)));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(rr, s, v);
    }

    /// F3-02 inverted: the enrolment proof in a student's calldata cannot be
    /// replayed by anyone else.
    function test_L2_010_invite_proof_not_replayable() public {
        ClassroomRegistry r = new ClassroomRegistry();
        address teacher = address(0x7EAC);
        address key = vm.addr(INVITE_PK);
        vm.prank(teacher);
        r.createClassroom("Algebra", 30, keccak256(abi.encodePacked(key)));

        address student = address(0x5100);
        bytes memory sig = _inviteSig(r, teacher, student, INVITE_PK);
        vm.prank(student);
        r.enrollWithInvite(key, sig);
        assertTrue(r.isEnrolled(teacher, student));

        // Outsider copies (key, sig) from the student's transaction.
        vm.prank(attacker);
        vm.expectRevert(bytes("Invalid invite proof"));
        r.enrollWithInvite(key, sig);
        assertFalse(r.isEnrolled(teacher, attacker));
    }

    /// A proof signed with a different secret (or for a different
    /// classroom's key) is refused.
    function test_L2_010_wrong_secret_rejected() public {
        ClassroomRegistry r = new ClassroomRegistry();
        address teacher = address(0x7EAC);
        address key = vm.addr(INVITE_PK);
        vm.prank(teacher);
        r.createClassroom("Algebra", 30, keccak256(abi.encodePacked(key)));
        address student = address(0x5100);
        bytes memory forged = _inviteSig(r, teacher, student, 0xBADBAD);
        vm.prank(student);
        vm.expectRevert(bytes("Invalid invite proof"));
        r.enrollWithInvite(key, forged);
    }

    // ── PBA-L2-031 ──────────────────────────────────────────────────

    /// F3-03 inverted: the vault can now execute a governance call on a
    /// contract it governs (Forwarder.addRelayer) under quorum.
    function test_L2_031_vault_executes_governance_call() public {
        address[] memory s = new address[](3);
        s[0] = A;
        s[1] = B;
        s[2] = C;
        InstitutionalVault vault = new InstitutionalVault(s, 2);
        ClassroomClusterV1 cluster = new ClassroomClusterV1(address(vault));
        Forwarder fwd = new Forwarder(address(vault), address(cluster), address(vault));
        BudgetAllocation budget = new BudgetAllocation(address(vault));

        vm.prank(A);
        uint256 id = vault.proposeCall(address(fwd), 0, abi.encodeCall(Forwarder.addRelayer, (A)), bytes32("addRelayer"));
        vm.prank(B);
        vault.approveCashout(id);
        vm.prank(C);
        vault.approveCashout(id);
        vm.prank(A);
        vault.executeCashout(id);
        assertTrue(fwd.isAuthorizedRelayer(A));

        vm.prank(A);
        uint256 id2 = vault.proposeCall(address(budget), 0, abi.encodeCall(BudgetAllocation.setSpender, (B, true)), bytes32("sp"));
        vm.prank(B);
        vault.approveCashout(id2);
        vm.prank(C);
        vault.approveCashout(id2);
        vm.prank(B);
        vault.executeCashout(id2);
        assertTrue(budget.authorizedSpender(B));
    }

    function test_L2_031_proposeCall_self_rejected() public {
        InstitutionalVault v = _vault(2);
        vm.prank(A);
        vm.expectRevert(InstitutionalVault.SelfCall.selector);
        v.proposeCall(address(v), 0, hex"", bytes32(0));
    }

    // ── PBA-L2-032 ──────────────────────────────────────────────────

    /// F3-05 inverted: a single rogue owner can no longer cancel the honest
    /// pair's `replaceOwner` of itself.
    function test_L2_032_rogue_owner_cannot_cancel_own_replacement() public {
        address[3] memory o = [A, B, attacker];
        MultisigTimelock2of3 t = new MultisigTimelock2of3(o, 1 hours);
        bytes memory payload = abi.encodeCall(MultisigTimelock2of3.replaceOwner, (uint8(2), C));
        vm.prank(A);
        bytes32 op = t.propose(address(t), payload);
        vm.prank(B);
        t.approve(op);
        vm.prank(attacker);
        t.cancel(op); // one vote, not a veto
        vm.warp(block.timestamp + 2 hours);
        vm.prank(A);
        t.execute(op);
        assertFalse(t.isOwner(attacker));
        assertTrue(t.isOwner(C));
    }

    /// Two owners can still cancel; a proposer can withdraw its own
    /// still-unapproved op.
    function test_L2_032_two_owners_cancel_and_proposer_withdraws() public {
        address[3] memory o = [A, B, C];
        MultisigTimelock2of3 t = new MultisigTimelock2of3(o, 1 hours);
        vm.prank(A);
        bytes32 op = t.propose(address(0x1234), hex"");
        vm.prank(B);
        t.approve(op);
        vm.prank(B);
        t.cancel(op);
        vm.prank(C);
        t.cancel(op);
        (,, MultisigTimelock2of3.OpState st,,,) = t.getOperation(op);
        assertEq(uint256(st), uint256(MultisigTimelock2of3.OpState.Cancelled));

        vm.prank(C);
        bytes32 op2 = t.propose(address(0x1234), hex"01");
        vm.prank(C);
        t.cancel(op2);
        (,, st,,,) = t.getOperation(op2);
        assertEq(uint256(st), uint256(MultisigTimelock2of3.OpState.Cancelled));
    }

    /// Once a second owner approved, the proposer alone cannot cancel it.
    function test_L2_032_proposer_cannot_solo_cancel_approved_op() public {
        address[3] memory o = [A, B, C];
        MultisigTimelock2of3 t = new MultisigTimelock2of3(o, 1 hours);
        vm.prank(A);
        bytes32 op = t.propose(address(0x1234), hex"");
        vm.prank(B);
        t.approve(op);
        vm.prank(A);
        t.cancel(op);
        (,, MultisigTimelock2of3.OpState st,,,) = t.getOperation(op);
        assertEq(uint256(st), uint256(MultisigTimelock2of3.OpState.Approved), "one vote only");
    }

    /// F3-05 (vault) inverted: a rogue signer's reject is one vote; the
    /// honest pair removes it.
    function test_L2_032_rogue_signer_cannot_veto_own_removal() public {
        InstitutionalVault v = _vault(2);
        vm.prank(A);
        uint256 pid = v.proposeSignerChange(C, false);
        vm.prank(C);
        v.rejectSignerChange(pid);
        vm.prank(B);
        v.approveSignerChange(pid);
        vm.prank(A);
        v.executeSignerChange(pid);
        assertFalse(v.isSigner(C));
    }

    /// Blocking minority still rejects (n - t + 1 = 2 of 3).
    function test_L2_032_blocking_minority_rejects() public {
        InstitutionalVault v = _vault(2);
        vm.prank(A);
        uint256 id = v.proposeCashout(A, 1 ether, bytes32("x"));
        vm.prank(B);
        v.rejectCashout(id);
        vm.prank(C);
        v.rejectCashout(id);
        vm.prank(B);
        vm.expectRevert(InstitutionalVault.AlreadyRejected.selector);
        v.approveCashout(id);
    }

    /// Pause re-arm is bounded per signer.
    function test_L2_032_pause_rearm_cooldown() public {
        InstitutionalVault v = _vault(2);
        vm.prank(C);
        v.emergencyPause();
        vm.prank(A);
        v.unpause();
        vm.prank(B);
        v.unpause();
        vm.prank(C);
        vm.expectRevert(InstitutionalVault.PauseCooldown.selector);
        v.emergencyPause();
        vm.warp(block.timestamp + v.PAUSE_COOLDOWN());
        vm.prank(C);
        v.emergencyPause();
    }

    // ── PBA-L2-033 ──────────────────────────────────────────────────

    /// F3-06 inverted: approvals of a since-removed signer no longer count.
    function test_L2_033_stale_signer_approval_does_not_count() public {
        address[] memory s = new address[](4);
        s[0] = A;
        s[1] = B;
        s[2] = C;
        s[3] = attacker;
        InstitutionalVault v = new InstitutionalVault(s, 3);
        vm.prank(attacker);
        uint256 addPid = v.proposeSignerChange(address(0xACC), true);
        vm.prank(C);
        v.approveSignerChange(addPid);
        vm.prank(A);
        uint256 rm = v.proposeSignerChange(attacker, false);
        vm.prank(B);
        v.approveSignerChange(rm);
        vm.prank(C);
        v.approveSignerChange(rm);
        vm.prank(A);
        v.executeSignerChange(rm);
        vm.prank(B);
        v.approveSignerChange(addPid);
        vm.prank(B);
        vm.expectRevert(InstitutionalVault.SignerProposalQuorumNotMet.selector);
        v.executeSignerChange(addPid);
        assertFalse(v.isSigner(address(0xACC)));
    }

    function test_L2_033_stale_threshold_approval_does_not_count() public {
        address[] memory s = new address[](4);
        s[0] = A;
        s[1] = B;
        s[2] = C;
        s[3] = attacker;
        InstitutionalVault v = new InstitutionalVault(s, 3);
        vm.prank(attacker);
        uint256 tp = v.proposeThresholdChange(1);
        vm.prank(C);
        v.approveThresholdChange(tp);
        vm.prank(A);
        uint256 rm = v.proposeSignerChange(attacker, false);
        vm.prank(B);
        v.approveSignerChange(rm);
        vm.prank(C);
        v.approveSignerChange(rm);
        vm.prank(A);
        v.executeSignerChange(rm);
        vm.prank(B);
        v.approveThresholdChange(tp);
        vm.prank(B);
        vm.expectRevert(InstitutionalVault.SignerProposalQuorumNotMet.selector);
        v.executeThresholdChange(tp);
        assertEq(v.getThreshold(), 3);
    }

    // ── PBA-L2-034 ──────────────────────────────────────────────────

    function _cluster() internal returns (ClassroomClusterV1 c, address gov, address sa, address admin, address it) {
        gov = address(0x60F);
        c = new ClassroomClusterV1(gov);
        sa = address(0x5A);
        admin = address(0xAD);
        it = address(0x17);
        vm.startPrank(gov);
        c.grantOrgRole(sa, IClassroomCluster.OrgRole.SuperAdmin);
        c.grantOrgRole(admin, IClassroomCluster.OrgRole.Admin);
        c.grantOrgRole(it, IClassroomCluster.OrgRole.IT);
        vm.stopPrank();
    }

    /// F3-07 inverted: an Admin cannot demote or revoke a SuperAdmin.
    function test_L2_034_admin_cannot_demote_superadmin() public {
        (ClassroomClusterV1 c,, address sa, address admin,) = _cluster();
        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.SuperAdminRequiresGovernance.selector);
        c.grantOrgRole(sa, IClassroomCluster.OrgRole.IT);
        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.InsufficientPrivilege.selector);
        c.revokeOrgRole(sa);
        assertEq(uint8(c.getOrgRole(sa)), uint8(IClassroomCluster.OrgRole.SuperAdmin));
    }

    /// F3-07 inverted: IT cannot lift an Admin-imposed suspension.
    function test_L2_034_it_cannot_lift_suspension() public {
        (ClassroomClusterV1 c,,, address admin, address it) = _cluster();
        address student = address(0x57);
        vm.prank(admin);
        c.setAccountStatus(student, IClassroomCluster.AccountStatus.Suspended);
        vm.prank(it);
        vm.expectRevert(ClassroomClusterV1.InsufficientPrivilege.selector);
        c.setAccountStatus(student, IClassroomCluster.AccountStatus.Active);
        vm.prank(admin);
        c.setAccountStatus(student, IClassroomCluster.AccountStatus.Active);
    }

    /// F3-07 inverted: a Suspended admin has no powers.
    function test_L2_034_suspended_admin_loses_powers() public {
        (ClassroomClusterV1 c, address gov,, address admin,) = _cluster();
        vm.prank(gov);
        c.setAccountStatus(admin, IClassroomCluster.AccountStatus.Suspended);
        vm.prank(admin);
        vm.expectRevert(ClassroomClusterV1.NotAdminOrAbove.selector);
        c.createClassroom("still-works", admin, 5, 2026, "");
    }

    /// Tripwire (fuzz over the role/status matrix): no caller can change the
    /// role or status of an account of equal or higher rank.
    function testFuzz_L2_034_no_equal_or_higher_rank_changes(uint8 callerIdx, uint8 targetIdx, uint8 newRole) public {
        (ClassroomClusterV1 c,, address sa, address admin, address it) = _cluster();
        address plain = address(0x57);
        address[4] memory who = [plain, it, admin, sa];
        uint8[4] memory rank = [0, 1, 2, 3];
        uint256 ci = bound(callerIdx, 0, 3);
        uint256 ti = bound(targetIdx, 0, 3);
        vm.assume(ci != ti);
        IClassroomCluster.OrgRole role = IClassroomCluster.OrgRole(bound(newRole, 0, 2)); // None/Admin/IT
        uint8 roleRank = role == IClassroomCluster.OrgRole.Admin ? 2 : (role == IClassroomCluster.OrgRole.IT ? 1 : 0);
        IClassroomCluster.OrgRole before = c.getOrgRole(who[ti]);
        vm.prank(who[ci]);
        try c.grantOrgRole(who[ti], role) {
            assertGt(rank[ci], rank[ti], "changed an equal/higher-ranked account");
            assertGt(rank[ci], roleRank, "granted a role at/above own rank");
        } catch {
            assertEq(uint8(c.getOrgRole(who[ti])), uint8(before));
        }
        IClassroomCluster.AccountStatus sBefore = c.getAccountStatus(who[ti]);
        vm.prank(who[ci]);
        try c.setAccountStatus(who[ti], IClassroomCluster.AccountStatus.Inactive) {
            assertGt(rank[ci], rank[ti], "status change on equal/higher rank");
        } catch {
            assertEq(uint8(c.getAccountStatus(who[ti])), uint8(sBefore));
        }
    }

    // ── PBA-L2-050 ──────────────────────────────────────────────────

    /// A request signed by device X cannot change the nonce of a principal
    /// not owned by X.
    function test_L2_050_device_cannot_burn_other_principals_nonce() public {
        address gov = address(0x1000);
        address relayer = address(0x2000);
        address[] memory signers = new address[](1);
        signers[0] = gov;
        InstitutionalVault vault = new InstitutionalVault(signers, 1);
        ClassroomClusterV1 cluster = new ClassroomClusterV1(gov);
        Forwarder fwd = new Forwarder(gov, address(cluster), address(vault));
        CounterR2 counter = new CounterR2();
        uint256 attackerKey = 0xB0B;
        address victim = address(0x7777);
        address att = vm.addr(attackerKey);
        vm.startPrank(gov);
        fwd.addRelayer(relayer);
        fwd.setTargetAllowed(address(counter), true);
        cluster.registerDevice(keccak256("dev-att"), att);
        vm.stopPrank();

        bytes32 victimPrincipal = keccak256("victim-principal");
        IForwarder.ForwardRequest memory req = IForwarder.ForwardRequest({
            orgPrincipalId: victimPrincipal,
            classroomId: 0,
            nonce: 0,
            sessionExpiry: block.timestamp + 3600,
            deviceCertHash: keccak256("dev-att"),
            target: address(counter),
            data: abi.encodeCall(CounterR2.increment, ())
        });
        bytes32 digest = fwd.hashForwardRequest(req);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        vm.prank(relayer);
        fwd.execute(req, abi.encodePacked(r, s, v));
        assertEq(fwd.getNonce(victim, victimPrincipal, 0), 0, "victim's counter untouched");
        assertEq(fwd.getNonce(att, victimPrincipal, 0), 1, "only the signer's own namespace advanced");
    }

    // ── PBA-L2-053 ──────────────────────────────────────────────────

    function test_L2_053_monthly_limit_enforced() public {
        address gov = address(0x60F);
        BudgetAllocation b = new BudgetAllocation(gov);
        vm.prank(gov);
        b.allocateBudget(1, 100 ether, 10 ether);
        vm.prank(gov);
        b.spendFromBudget(1, 6 ether);
        vm.prank(gov);
        vm.expectRevert(BudgetAllocation.ExceedsMonthlyLimit.selector);
        b.spendFromBudget(1, 5 ether);
        vm.warp(block.timestamp + b.PERIOD());
        vm.prank(gov);
        b.spendFromBudget(1, 10 ether); // new period
        assertEq(b.getSpentThisPeriod(1), 10 ether);
    }

    /// Spend accumulates across calls within one period.
    function test_L2_053_period_spend_accumulates() public {
        address gov = address(0x60F);
        BudgetAllocation b = new BudgetAllocation(gov);
        vm.prank(gov);
        b.allocateBudget(1, 100 ether, 10 ether);
        vm.startPrank(gov);
        b.spendFromBudget(1, 3 ether);
        b.spendFromBudget(1, 3 ether);
        vm.expectRevert(BudgetAllocation.ExceedsMonthlyLimit.selector);
        b.spendFromBudget(1, 5 ether);
        vm.stopPrank();
        assertEq(b.getSpentThisPeriod(1), 6 ether);
    }

    function test_L2_053_zero_limit_means_uncapped() public {
        address gov = address(0x60F);
        BudgetAllocation b = new BudgetAllocation(gov);
        vm.prank(gov);
        b.allocateBudget(1, 100 ether, 0);
        vm.prank(gov);
        b.spendFromBudget(1, 100 ether);
    }
}
