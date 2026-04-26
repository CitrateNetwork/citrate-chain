// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SpecRegistry.sol";
import "../src/lib/Governable.sol";

contract SpecRegistryTest is Test {
    SpecRegistry public registry;
    address public governor;
    address public nonGovernor;

    function setUp() public {
        governor = address(this);
        nonGovernor = address(0xBEEF);
        // RM-L / WP-L1.1: SpecRegistry now requires governance address
        // at deploy. Pre-fix the constructor took no args and used
        // msg.sender; now it inherits Governable's two-step transfer.
        registry = new SpecRegistry(governor);
    }

    // ── Registration ────────────────────────────────────────────────

    function test_registerSpec() public {
        registry.registerSpec("contract_deploy", "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        (string memory cid, bool active, uint256 version) = registry.getSpec("contract_deploy");
        assertEq(cid, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        assertTrue(active);
        assertEq(version, 1);
        assertEq(registry.domainCount(), 1);
    }

    function test_registerMultipleDomains() public {
        registry.registerSpec("contract_deploy", "Qm1");
        registry.registerSpec("token_transfer", "Qm2");
        registry.registerSpec("model_inference", "Qm3");
        assertEq(registry.domainCount(), 3);
    }

    function test_cannotRegisterDuplicate() public {
        registry.registerSpec("contract_deploy", "Qm1");
        vm.expectRevert("Domain already registered");
        registry.registerSpec("contract_deploy", "Qm2");
    }

    function test_cannotRegisterEmptyDomain() public {
        vm.expectRevert("Domain cannot be empty");
        registry.registerSpec("", "Qm1");
    }

    function test_cannotRegisterEmptyCid() public {
        vm.expectRevert("CID cannot be empty");
        registry.registerSpec("test", "");
    }

    function test_nonGovernorCannotRegister() public {
        vm.prank(nonGovernor);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        registry.registerSpec("test", "Qm1");
    }

    // ── Updates ─────────────────────────────────────────────────────

    function test_updateSpec() public {
        registry.registerSpec("contract_deploy", "QmOLD");
        registry.updateSpec("contract_deploy", "QmNEW");
        (string memory cid, , uint256 version) = registry.getSpec("contract_deploy");
        assertEq(cid, "QmNEW");
        assertEq(version, 2);
    }

    function test_updateIncreasesVersion() public {
        registry.registerSpec("test", "Qm1");
        registry.updateSpec("test", "Qm2");
        registry.updateSpec("test", "Qm3");
        (, , uint256 version) = registry.getSpec("test");
        assertEq(version, 3);
    }

    function test_cannotUpdateNonexistent() public {
        vm.expectRevert("Domain not registered");
        registry.updateSpec("nonexistent", "Qm1");
    }

    // ── Activation / Deactivation ───────────────────────────────────

    function test_deactivateSpec() public {
        registry.registerSpec("test", "Qm1");
        registry.deactivateSpec("test");
        (, bool active, ) = registry.getSpec("test");
        assertFalse(active);
        assertFalse(registry.hasActiveSpec("test"));
    }

    function test_reactivateSpec() public {
        registry.registerSpec("test", "Qm1");
        registry.deactivateSpec("test");
        registry.reactivateSpec("test");
        (, bool active, ) = registry.getSpec("test");
        assertTrue(active);
    }

    function test_cannotDeactivateInactive() public {
        registry.registerSpec("test", "Qm1");
        registry.deactivateSpec("test");
        vm.expectRevert("Already deactivated");
        registry.deactivateSpec("test");
    }

    function test_cannotReactivateActive() public {
        registry.registerSpec("test", "Qm1");
        vm.expectRevert("Already active");
        registry.reactivateSpec("test");
    }

    // ── Governance (RM-L / WP-L1.1 — two-step transfer) ─────────────

    function test_l1_1_transferGovernance_is_two_step() public {
        address newGov = address(0x1234);
        // Step 1: propose
        registry.transferGovernance(newGov);
        // Old governor still has authority — propose alone does not
        // transfer.
        assertEq(registry.governance(), governor, "L1.1: pre-accept governance unchanged");
        // Old governor can still register specs (still authoritative).
        registry.registerSpec("test", "Qm1");
        assertEq(registry.domainCount(), 1);

        // Step 2: pending governance accepts
        vm.prank(newGov);
        registry.acceptGovernance();
        assertEq(registry.governance(), newGov, "L1.1: post-accept governance moved");

        // Old governor can no longer register.
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        registry.registerSpec("test2", "Qm2");

        // New governor can.
        vm.prank(newGov);
        registry.registerSpec("test2", "Qm2");
    }

    function test_l1_1_pending_only_accept_works() public {
        address newGov = address(0x1234);
        address other = address(0xCAFE);
        registry.transferGovernance(newGov);

        // Random non-pending address cannot accept.
        vm.prank(other);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        registry.acceptGovernance();

        // The pending address can.
        vm.prank(newGov);
        registry.acceptGovernance();
        assertEq(registry.governance(), newGov);
    }

    function test_l1_1_cancel_governance_transfer() public {
        address newGov = address(0x1234);
        registry.transferGovernance(newGov);
        // Current governor can cancel.
        registry.cancelGovernanceTransfer();
        // Now `acceptGovernance` from the proposed address fails.
        vm.prank(newGov);
        vm.expectRevert(Governable.Governable_NotPendingGovernance.selector);
        registry.acceptGovernance();
        // Original governor remains.
        assertEq(registry.governance(), governor);
    }

    function test_l1_1_cannotTransferToZero() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        registry.transferGovernance(address(0));
    }

    function test_l1_1_only_governance_can_propose() public {
        vm.prank(nonGovernor);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        registry.transferGovernance(address(0xBEEF));
    }

    // ── View Functions ──────────────────────────────────────────────

    function test_hasActiveSpec() public {
        assertFalse(registry.hasActiveSpec("nonexistent"));
        registry.registerSpec("test", "Qm1");
        assertTrue(registry.hasActiveSpec("test"));
    }

    function test_getAllDomains() public {
        registry.registerSpec("a", "Qm1");
        registry.registerSpec("b", "Qm2");
        registry.registerSpec("c", "Qm3");
        string[] memory all = registry.getAllDomains();
        assertEq(all.length, 3);
    }

    // ── Events ──────────────────────────────────────────────────────

    function test_emitsSpecRegistered() public {
        vm.expectEmit(false, false, false, true);
        emit SpecRegistry.SpecRegistered("test", "Qm1", 1);
        registry.registerSpec("test", "Qm1");
    }

    function test_emitsSpecUpdated() public {
        registry.registerSpec("test", "QmOLD");
        vm.expectEmit(false, false, false, true);
        emit SpecRegistry.SpecUpdated("test", "QmOLD", "QmNEW", 2);
        registry.updateSpec("test", "QmNEW");
    }
}
