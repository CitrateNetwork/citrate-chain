// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TenantHierarchy} from "../../src/rbac/TenantHierarchy.sol";
import {CapabilityGrant} from "../../src/quorum/CapabilityGrant.sol";
import {ITenantHierarchy} from "../../src/quorum/GovernanceProtocolFactory.sol";

/// Regression for PBA-L2-056 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_056_Regression is Test {
    function test_L2_056_adminCannotIssuePostHocForAnotherPrincipal() public {
        TenantHierarchy th = new TenantHierarchy();
        address admin = address(0xAD);
        address principal = address(0xB0B);
        address[] memory a = new address[](1);
        a[0] = admin;
        bytes32 tenant = keccak256("t");
        th.initRoot(tenant, "t", keccak256("s"), a, 1, 3);
        CapabilityGrant g = new CapabilityGrant(ITenantHierarchy(address(th)));
        vm.warp(1_700_000_000);
        bytes32[] memory c = new bytes32[](1);
        c[0] = keccak256("write");
        vm.prank(admin);
        try g.issue(1, principal, principal, tenant, c, CapabilityGrant.Hic.PostHoc, 0, 10, uint64(block.timestamp * 1000 + 1e6), bytes32(0))
        returns (bytes32 id) {
            assertTrue(uint8(g.grantOf(id).hic) != uint8(CapabilityGrant.Hic.PostHoc), "admin granted PostHoc autonomy");
        } catch {}
    }
}
