// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {InstitutionalVault} from "../../src/edu/InstitutionalVault.sol";

/// Unpause quorum counts only the approvals of the CURRENT signer set, and a
/// signer that is removed and later re-added does not bring back the unpause
/// approval it gave before its removal.
contract InstitutionalVaultReAddedSignerUnpauseTest is Test {
    InstitutionalVault internal vault;
    address internal constant S1 = address(0x1);
    address internal constant S2 = address(0x2);
    address internal constant S3 = address(0x3);

    function setUp() public {
        address[] memory signers = new address[](3);
        signers[0] = S1;
        signers[1] = S2;
        signers[2] = S3;
        vault = new InstitutionalVault(signers, 2); // 2-of-3
        vm.prank(S1);
        vault.emergencyPause();
    }

    function _change(address target, bool isAdd) internal {
        vm.prank(S1);
        uint256 pid = vault.proposeSignerChange(target, isAdd);
        vm.prank(S2);
        vault.approveSignerChange(pid);
        vm.prank(S1);
        vault.executeSignerChange(pid);
    }

    function test_removedSignerUnpauseApprovalDoesNotCount() public {
        vm.prank(S3);
        vault.unpause(); // 1 of 2
        _change(S3, false);
        assertFalse(vault.isSigner(S3));

        vm.prank(S1);
        vault.unpause(); // live approvals: S1 only
        assertTrue(vault.isPaused(), "a removed signer's approval must not complete the quorum");

        vm.prank(S2);
        vault.unpause();
        assertFalse(vault.isPaused(), "two live signers unpause");
    }

    function test_reAddedSignerDoesNotInheritItsOldUnpauseApproval() public {
        vm.prank(S3);
        vault.unpause();
        _change(S3, false);
        _change(S3, true);
        assertTrue(vault.isSigner(S3));

        vm.prank(S1);
        vault.unpause(); // S3's pre-removal approval must be gone
        assertTrue(vault.isPaused(), "re-added signer brought back a stale approval");

        vm.prank(S3);
        vault.unpause();
        assertFalse(vault.isPaused(), "a fresh approval from the re-added signer counts");
    }
}
