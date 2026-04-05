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
    // (Simplified in v1 — any signer can add, but removal enforces threshold bounds)
    function test_invariant_cannot_remove_below_threshold() public {
        // 3 signers, threshold 2. Removing one leaves 2 signers with threshold 2 — ok.
        vm.prank(signer1);
        vault.removeSigner(signer3);
        assertEq(vault.getSignerCount(), 2);

        // Now 2 signers, threshold 2. Removing another would leave 1 < 2 — should fail.
        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold
        vault.removeSigner(signer2);
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
    function test_invariant_threshold_bounds() public {
        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold (0)
        vault.setThreshold(0);

        vm.prank(signer1);
        vm.expectRevert(); // InvalidThreshold (>n)
        vault.setThreshold(10);

        // Valid change
        vm.prank(signer1);
        vault.setThreshold(3);
        assertEq(vault.getThreshold(), 3);
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

    // Adversarial 2: Signer rotation attack
    function test_adversarial_signer_rotation_attack() public {
        // Attacker (signer1) adds accomplice, then tries to drain
        vm.prank(signer1);
        vault.addSigner(signer4);

        vm.prank(signer1);
        uint256 txId = vault.proposeCashout(signer1, 100 ether, keccak256("steal"));

        // Accomplice approves
        vm.prank(signer4);
        vault.approveCashout(txId);

        // Still needs 2 approvals (threshold=2), accomplice is 1
        // Attacker can't self-approve (SelfApproval)
        vm.prank(signer1);
        vm.expectRevert();
        vault.approveCashout(txId);

        // Only 1 approval — can't execute
        vm.prank(signer1);
        vm.expectRevert();
        vault.executeCashout(txId);
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
        vault.addSigner(nonSigner);

        vm.expectRevert();
        vault.removeSigner(signer1);

        vm.expectRevert();
        vault.setThreshold(1);

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
        vm.prank(signer1);
        if (newThreshold == 0 || newThreshold > signerCount) {
            vm.expectRevert();
            vault.setThreshold(newThreshold);
        } else {
            vault.setThreshold(newThreshold);
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
