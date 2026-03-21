// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SpecRegistry.sol";

contract SpecRegistryTest is Test {
    SpecRegistry public registry;
    address public governor;
    address public nonGovernor;

    function setUp() public {
        governor = address(this);
        nonGovernor = address(0xBEEF);
        registry = new SpecRegistry();
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
        vm.expectRevert("Only governor can modify specs");
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

    // ── Governance ──────────────────────────────────────────────────

    function test_transferGovernor() public {
        address newGov = address(0x1234);
        registry.transferGovernor(newGov);
        assertEq(registry.governor(), newGov);

        // Old governor can no longer register
        vm.expectRevert("Only governor can modify specs");
        registry.registerSpec("test", "Qm1");

        // New governor can
        vm.prank(newGov);
        registry.registerSpec("test", "Qm1");
    }

    function test_cannotTransferToZero() public {
        vm.expectRevert("Cannot transfer to zero address");
        registry.transferGovernor(address(0));
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
