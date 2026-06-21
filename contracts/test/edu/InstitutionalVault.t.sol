// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {InstitutionalVault} from "../../src/edu/InstitutionalVault.sol";

contract InstitutionalVaultTest is Test {
    InstitutionalVault vault;

    address signer1 = address(0x1);
    address signer2 = address(0x2);
    address signer3 = address(0x3);
    address signer4 = address(0x4);
    address signer5 = address(0x5);
    address nonSigner = address(0xBEEF);
    address recipient = address(0xCAFE);

    function setUp() public {
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        vault = new InstitutionalVault(signers, 2); // 2-of-3
        vm.deal(address(vault), 100 ether);
    }

    // ===================================================================
    // UNIT TESTS — Constructor
    // ===================================================================

    function test_constructor_sets_signers() public view {
        assertTrue(vault.isSigner(signer1));
        assertTrue(vault.isSigner(signer2));
        assertTrue(vault.isSigner(signer3));
        assertFalse(vault.isSigner(nonSigner));
    }

    function test_constructor_sets_threshold() public view {
        assertEq(vault.getThreshold(), 2);
    }

    function test_constructor_sets_signer_count() public view {
        assertEq(vault.getSignerCount(), 3);
    }

    function test_constructor_reverts_zero_threshold() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        vm.expectRevert();
        new InstitutionalVault(signers, 0);
    }

    function test_constructor_reverts_threshold_exceeds_signers() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        vm.expectRevert();
        new InstitutionalVault(signers, 3);
    }

    function test_constructor_reverts_duplicate_signer() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer1;
        vm.expectRevert();
        new InstitutionalVault(signers, 1);
    }

    function test_constructor_reverts_zero_address_signer() public {
        address[] memory signers = new address[](2);
        signers[0] = address(0);
        signers[1] = signer1;
        vm.expectRevert();
        new InstitutionalVault(signers, 1);
    }

    function test_constructor_reverts_empty_signers() public {
        address[] memory signers = new address[](0);
        vm.expectRevert();
        new InstitutionalVault(signers, 1);
    }

    // ===================================================================
    // UNIT TESTS — Deposit
    // ===================================================================

    function test_deposit() public {
        uint256 balBefore = vault.getBalance();
        vm.deal(nonSigner, 10 ether);
        vm.prank(nonSigner);
        vault.deposit{value: 5 ether}();
        assertEq(vault.getBalance(), balBefore + 5 ether);
    }

    function test_receive_ether() public {
        uint256 balBefore = vault.getBalance();
        vm.deal(nonSigner, 10 ether);
        vm.prank(nonSigner);
        (bool ok,) = address(vault).call{value: 3 ether}("");
        assertTrue(ok);
        assertEq(vault.getBalance(), balBefore + 3 ether);
    }

    // ===================================================================
    // UNIT TESTS — Cashout Lifecycle
    // ===================================================================

    function test_propose_cashout() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("supplies"));
        assertEq(txId, 0);
        assertEq(vault.getApprovalCount(txId), 0);
    }

    function test_propose_cashout_increments_id() public {
        vm.prank(signer1);
        uint256 id1 = vault.proposeCashout(recipient, 1 ether, keccak256("a"));
        vm.prank(signer1);
        uint256 id2 = vault.proposeCashout(recipient, 1 ether, keccak256("b"));
        assertEq(id2, id1 + 1);
    }

    function test_propose_reverts_non_signer() public {
        vm.prank(nonSigner);
        vm.expectRevert();
        vault.proposeCashout(recipient, 1 ether, keccak256("x"));
    }

    function test_propose_reverts_zero_address() public {
        vm.prank(signer1);
        vm.expectRevert();
        vault.proposeCashout(address(0), 1 ether, keccak256("x"));
    }

    function test_propose_reverts_insufficient_balance() public {
        vm.prank(signer1);
        vm.expectRevert();
        vault.proposeCashout(recipient, 1000 ether, keccak256("x"));
    }

    function test_approve_cashout() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        vm.prank(signer2);
        vault.approveCashout(txId);

        assertEq(vault.getApprovalCount(txId), 1);
        assertTrue(vault.hasApproved(txId, signer2));
    }

    function test_execute_cashout_after_quorum() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);

        uint256 recipientBalBefore = recipient.balance;
        vm.prank(signer1);
        vault.executeCashout(txId);
        assertEq(recipient.balance, recipientBalBefore + 1 ether);
    }

    function test_reject_cashout() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        vm.prank(signer2);
        vault.rejectCashout(txId);

        // Cannot approve after rejection
        vm.prank(signer3);
        vm.expectRevert();
        vault.approveCashout(txId);
    }

    // ===================================================================
    // INVARIANT TESTS — Q-004 TLA+ Mapping
    // ===================================================================

    // Invariant 1: NoWithdrawalWithoutQuorum
    function test_invariant_no_withdrawal_without_quorum() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        // Only 1 approval (need 2)
        vm.prank(signer2);
        vault.approveCashout(txId);

        vm.prank(signer1);
        vm.expectRevert(); // QuorumNotMet
        vault.executeCashout(txId);
    }

    // Invariant 2: EmergencyPauseStopsOutflows
    function test_invariant_pause_stops_outflows() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));
        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);

        // Pause
        vm.prank(signer1);
        vault.emergencyPause();
        assertTrue(vault.isPaused());

        // Execute should fail while paused
        vm.prank(signer1);
        vm.expectRevert(); // VaultPaused
        vault.executeCashout(txId);
    }

    // Invariant 3: UnpauseRequiresQuorum
    function test_invariant_unpause_requires_quorum() public {
        vm.prank(signer1);
        vault.emergencyPause();

        // Single signer unpause attempt — should NOT unpause
        vm.prank(signer1);
        vault.unpause();
        assertTrue(vault.isPaused()); // Still paused

        // Second signer — now meets 2-of-3 threshold
        vm.prank(signer2);
        vault.unpause();
        assertFalse(vault.isPaused()); // Now unpaused
    }

    // Invariant 4: SignerAddRemoveRequiresQuorum
    // Now enforced via proposal flow — remove requires quorum before execution
    function test_invariant_cannot_remove_below_threshold() public {
        // 3 signers, threshold 2. Propose removing signer3 — both signer1 and signer2 approve.
        vm.prank(signer1);
        uint256 pid = vault.proposeSignerChange(signer3, false);

        vm.prank(signer2);
        vault.approveSignerChange(pid);

        vm.prank(signer1);
        vault.executeSignerChange(pid);
        assertEq(vault.getSignerCount(), 2);

        // Now 2 signers, threshold 2. Proposing removal would leave 1 < 2 — should fail at proposal time.
        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold
        vault.proposeSignerChange(signer2, false);
    }

    // Invariant 5: BudgetCannotExceedVaultBalance
    function test_invariant_propose_exceeds_balance_reverts() public {
        vm.prank(signer1);
        vm.expectRevert(); // InsufficientBalance
        vault.proposeCashout(recipient, 1000 ether, keccak256("x"));
    }

    // Invariant 7: SelfApprovalForbidden
    function test_invariant_self_approval_forbidden() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        // Proposer tries to approve their own cashout
        vm.prank(signer1);
        vm.expectRevert(); // SelfApproval
        vault.approveCashout(txId);
    }

    // Invariant 8: ThresholdBoundsValid
    // FWA-C3-16: threshold changes are now quorum-gated (propose/approve/
    // execute), not a single-signer one-shot. Bounds still enforced at
    // propose time; a single signer can no longer weaken the threshold.
    function test_invariant_threshold_bounds() public {
        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold (0)
        vault.proposeThresholdChange(0);

        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold (>n)
        vault.proposeThresholdChange(10);

        // Valid change requires quorum (2-of-3).
        vm.prank(signer1);
        uint256 pid = vault.proposeThresholdChange(3);
        vm.prank(signer2);
        vault.approveThresholdChange(pid);
        vm.prank(signer1);
        vault.executeThresholdChange(pid);
        assertEq(vault.getThreshold(), 3);
    }

    // FWA-C3-16 regression: a SINGLE signer cannot change the threshold.
    function test_C3_16_single_signer_cannot_change_threshold() public {
        vm.prank(signer1);
        uint256 pid = vault.proposeThresholdChange(1);
        // Only the proposer has approved (1 of required 2). Execute must
        // revert — no unilateral threshold weakening.
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.SignerProposalQuorumNotMet.selector);
        vault.executeThresholdChange(pid);
        assertEq(vault.getThreshold(), 2); // unchanged
    }

    // FWA-C3-17: stale-quorum — a removed signer's approval must NOT count.
    // Pre-fix: executeCashout trusted the cached approvalCount, so a cashout
    // could execute on ex-signer authority across a signer-set change.
    // Post-fix: approvals are recounted over the CURRENT signer set.
    function test_C3_17_removed_signer_approval_does_not_count() public {
        // 2-of-3. signer1 proposes a cashout, signer2 + signer3 approve → 2.
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("c"));
        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);
        // approvalCount is now 2 (signer2, signer3).

        // Now remove signer3 via the quorum flow (signer1 + signer2 approve).
        vm.prank(signer1);
        uint256 pid = vault.proposeSignerChange(signer3, false);
        vm.prank(signer2);
        vault.approveSignerChange(pid);
        vm.prank(signer1);
        vault.executeSignerChange(pid);
        assertFalse(vault.isSigner(signer3));

        // Live approvals are now only signer2 (1) < threshold 2 → execute reverts.
        // (Pre-fix this would have executed on the cached count of 2.)
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.QuorumNotMet.selector);
        vault.executeCashout(txId);
    }

    // FWA-C3-17 positive: with all approvers still signers, the cashout
    // executes — confirming the live recount didn't break the happy path.
    function test_C3_17_live_quorum_still_executes() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("ok"));
        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);

        uint256 balBefore = recipient.balance;
        vm.prank(signer1);
        vault.executeCashout(txId);
        assertEq(recipient.balance, balBefore + 1 ether);
    }

    // ===================================================================
    // ADVERSARIAL TESTS — Q-004 Scenarios
    // ===================================================================

    // Adversarial 1: Single-signer drain attempt
    function test_adversarial_single_signer_drain() public {
        vm.startPrank(signer1);
        uint256 txId = vault.proposeCashout(signer1, 100 ether, keccak256("drain"));
        // Cannot self-approve
        vm.expectRevert();
        vault.approveCashout(txId);
        // Cannot execute without quorum
        vm.expectRevert();
        vault.executeCashout(txId);
        vm.stopPrank();

        // Balance unchanged
        assertEq(vault.getBalance(), 100 ether);
    }

    // Adversarial 2: Signer rotation attack — now requires quorum to add a signer
    function test_adversarial_signer_rotation_attack() public {
        // Attacker (signer1) proposes adding accomplice — alone this is not enough
        vm.prank(signer1);
        uint256 propId = vault.proposeSignerChange(signer4, true);
        // signer4 is NOT a signer yet — proposal has only 1 approval (signer1 auto-approves)
        // threshold is 2, so we need signer2 or signer3 to approve before signer4 is a signer
        // Attacker cannot execute alone
        vm.prank(signer1);
        vm.expectRevert(); // SignerProposalQuorumNotMet
        vault.executeSignerChange(propId);

        // signer4 is still NOT a signer
        assertFalse(vault.isSigner(signer4));
        assertEq(vault.getSignerCount(), 3);

        // Even if signer4 were added via quorum, attacker still can't drain alone:
        // propose cashout, accomplice approves — still can't self-approve
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(signer1, 100 ether, keccak256("steal"));

        vm.prank(signer2);
        vault.approveCashout(txId);

        // Attacker can't self-approve (SelfApproval)
        vm.prank(signer1);
        vm.expectRevert();
        vault.approveCashout(txId);
    }

    // Adversarial 3: Pause-then-unpause by same signer
    function test_adversarial_pause_unpause_same_signer() public {
        vm.prank(signer1);
        vault.emergencyPause();
        assertTrue(vault.isPaused());

        // Same signer tries to immediately unpause
        vm.prank(signer1);
        vault.unpause();
        // Still paused — needs 2 signers
        assertTrue(vault.isPaused());
    }

    // Adversarial 4: Double-approval
    function test_adversarial_double_approval() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        vm.prank(signer2);
        vault.approveCashout(txId);

        // Same signer tries to approve again
        vm.prank(signer2);
        vm.expectRevert(); // AlreadyApproved
        vault.approveCashout(txId);

        // Still only 1 approval
        assertEq(vault.getApprovalCount(txId), 1);
    }

    // Adversarial 5: Non-signer tries everything
    function test_adversarial_non_signer_actions() public {
        vm.startPrank(nonSigner);

        vm.expectRevert();
        vault.proposeCashout(recipient, 1 ether, keccak256("x"));

        vm.expectRevert();
        vault.approveCashout(0);

        vm.expectRevert();
        vault.executeCashout(0);

        vm.expectRevert();
        vault.emergencyPause();

        vm.expectRevert();
        vault.proposeSignerChange(signer4, true);

        vm.expectRevert();
        vault.proposeSignerChange(signer1, false);

        // FWA-C3-16: a non-signer cannot even propose a threshold change.
        vm.expectRevert();
        vault.proposeThresholdChange(1);

        vm.stopPrank();
    }

    // ===================================================================
    // CEI PATTERN TESTS — Checks-Effects-Interactions
    // ===================================================================

    // Reentrancy test: malicious recipient tries to re-enter during cashout
    function test_cei_reentrancy_on_execute() public {
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(vault));
        vm.deal(address(vault), 10 ether);

        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(address(attacker), 1 ether, keccak256("x"));
        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);

        // Execute — attacker's receive() will try to re-enter
        vm.prank(signer1);
        vault.executeCashout(txId);

        // Attacker got exactly 1 ether, not more (executed flag set before transfer)
        assertEq(address(attacker).balance, 1 ether);
    }

    // ===================================================================
    // FUZZ TESTS
    // ===================================================================

    function testFuzz_deposit_any_amount(uint256 amount) public {
        vm.assume(amount > 0 && amount < type(uint128).max);
        vm.deal(nonSigner, amount);
        uint256 balBefore = vault.getBalance();
        vm.prank(nonSigner);
        vault.deposit{value: amount}();
        assertEq(vault.getBalance(), balBefore + amount);
    }

    function testFuzz_propose_within_balance(uint256 amount) public {
        uint256 balance = vault.getBalance();
        vm.assume(amount > 0 && amount <= balance);
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, amount, keccak256("fuzz"));
        assertEq(txId, 0);
    }

    function testFuzz_propose_exceeds_balance_reverts(uint256 amount) public {
        uint256 balance = vault.getBalance();
        vm.assume(amount > balance);
        vm.prank(signer1);
        vm.expectRevert();
        vault.proposeCashout(recipient, amount, keccak256("fuzz"));
    }

    function testFuzz_threshold_bounds(uint256 newThreshold) public {
        uint256 signerCount = vault.getSignerCount();
        if (newThreshold == 0 || newThreshold > signerCount) {
            vm.prank(signer1);
            vm.expectRevert();
            vault.proposeThresholdChange(newThreshold);
        } else {
            // FWA-C3-16: quorum-gated change (2-of-3).
            vm.prank(signer1);
            uint256 pid = vault.proposeThresholdChange(newThreshold);
            vm.prank(signer2);
            vault.approveThresholdChange(pid);
            vm.prank(signer1);
            vault.executeThresholdChange(pid);
            assertEq(vault.getThreshold(), newThreshold);
        }
    }

    // ===================================================================
    // EDGE CASES
    // ===================================================================

    function test_execute_already_executed_reverts() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));
        vm.prank(signer2);
        vault.approveCashout(txId);
        vm.prank(signer3);
        vault.approveCashout(txId);
        vm.prank(signer1);
        vault.executeCashout(txId);

        // Try again
        vm.prank(signer1);
        vm.expectRevert(); // AlreadyExecuted
        vault.executeCashout(txId);
    }

    function test_approve_rejected_cashout_reverts() public {
        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(recipient, 1 ether, keccak256("x"));
        vm.prank(signer2);
        vault.rejectCashout(txId);

        vm.prank(signer3);
        vm.expectRevert(); // AlreadyRejected
        vault.approveCashout(txId);
    }

    function test_propose_while_paused_reverts() public {
        vm.prank(signer1);
        vault.emergencyPause();

        vm.prank(signer2);
        vm.expectRevert(); // VaultPaused
        vault.proposeCashout(recipient, 1 ether, keccak256("x"));
    }

    function test_unpause_resets_approvals() public {
        vm.prank(signer1);
        vault.emergencyPause();

        vm.prank(signer1);
        vault.unpause();
        vm.prank(signer2);
        vault.unpause();
        // Now unpaused

        // Pause again
        vm.prank(signer1);
        vault.emergencyPause();

        // Need fresh approvals — signer1's old approval was reset
        vm.prank(signer1);
        vault.unpause();
        assertTrue(vault.isPaused()); // Still paused, only 1 approval
    }

    // ===================================================================
    // SIGNER CHANGE PROPOSAL TESTS
    // ===================================================================

    /// @dev Proposing alone is not enough — threshold approvals needed to execute.
    function test_add_signer_requires_quorum() public {
        // signer1 proposes adding signer4 — auto-approves (1 approval)
        vm.prank(signer1);
        uint256 propId = vault.proposeSignerChange(signer4, true);
        assertEq(vault.getSignerProposalApprovalCount(propId), 1);

        // threshold is 2, so execution should fail with 1 approval
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.SignerProposalQuorumNotMet.selector);
        vault.executeSignerChange(propId);

        // signer4 is still NOT a signer
        assertFalse(vault.isSigner(signer4));
        assertEq(vault.getSignerCount(), 3);
    }

    /// @dev Full propose→approve→execute flow for adding a signer.
    function test_signer_change_executes_after_quorum() public {
        // signer1 proposes
        vm.prank(signer1);
        uint256 propId = vault.proposeSignerChange(signer4, true);

        // signer2 approves — now at threshold (2-of-3)
        vm.prank(signer2);
        vault.approveSignerChange(propId);
        assertEq(vault.getSignerProposalApprovalCount(propId), 2);

        // Execute
        vm.prank(signer1);
        vault.executeSignerChange(propId);

        assertTrue(vault.isSigner(signer4));
        assertEq(vault.getSignerCount(), 4);
    }

    /// @dev Same quorum requirement for removing a signer.
    function test_remove_signer_requires_quorum() public {
        // Propose removing signer3 — signer1 auto-approves
        vm.prank(signer1);
        uint256 propId = vault.proposeSignerChange(signer3, false);

        // Only 1 approval — cannot execute yet
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.SignerProposalQuorumNotMet.selector);
        vault.executeSignerChange(propId);
        assertEq(vault.getSignerCount(), 3); // Unchanged

        // signer2 approves
        vm.prank(signer2);
        vault.approveSignerChange(propId);

        // Execute
        vm.prank(signer1);
        vault.executeSignerChange(propId);

        assertFalse(vault.isSigner(signer3));
        assertEq(vault.getSignerCount(), 2);
    }

    /// @dev rejectSignerChange marks proposal as rejected; further approvals fail.
    function test_signer_change_rejected() public {
        vm.prank(signer1);
        uint256 propId = vault.proposeSignerChange(signer4, true);

        vm.prank(signer2);
        vault.rejectSignerChange(propId);

        // Approve after rejection should fail
        vm.prank(signer3);
        vm.expectRevert(InstitutionalVault.SignerProposalAlreadyRejected.selector);
        vault.approveSignerChange(propId);

        // Execute after rejection should fail
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.SignerProposalAlreadyRejected.selector);
        vault.executeSignerChange(propId);

        // signer4 was not added
        assertFalse(vault.isSigner(signer4));
    }

    /// @dev proposeSignerChange reverts if target is already a signer.
    function test_cannot_add_existing_signer() public {
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.AlreadySigner.selector);
        vault.proposeSignerChange(signer2, true);
    }

    /// @dev proposeSignerChange reverts if removing would drop below threshold.
    function test_cannot_remove_below_threshold_via_proposal() public {
        // 3 signers, threshold 2. First remove signer3 (leaves 2 >= threshold 2 — ok).
        vm.prank(signer1);
        uint256 p1 = vault.proposeSignerChange(signer3, false);
        vm.prank(signer2);
        vault.approveSignerChange(p1);
        vm.prank(signer1);
        vault.executeSignerChange(p1);
        assertEq(vault.getSignerCount(), 2);

        // Now 2 signers, threshold 2. Proposing removal of signer2 would leave 1 < 2 — revert.
        vm.prank(signer1);
        vm.expectRevert(InstitutionalVault.InvalidThreshold.selector);
        vault.proposeSignerChange(signer2, false);
    }
}

// ===================================================================
// HELPER: Reentrancy Attacker
// ===================================================================

contract ReentrancyAttacker {
    InstitutionalVault private _vault;
    uint256 private _attackCount;

    constructor(address vault_) {
        _vault = InstitutionalVault(payable(vault_));
    }

    receive() external payable {
        // Try to re-enter executeCashout
        if (_attackCount < 3) {
            _attackCount++;
            try _vault.executeCashout(0) {} catch {}
        }
    }
}
