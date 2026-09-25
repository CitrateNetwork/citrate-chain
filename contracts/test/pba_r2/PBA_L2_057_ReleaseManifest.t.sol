// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ReleaseManifestRegistry} from "../../src/defense_prime/ReleaseManifestRegistry.sol";

/// Regression for PBA-L2-057 (pre-bounty audit 2026-09-24, lane CONTRACTS-B): the lane
/// PoC / finding trace, inverted. New entry points are reached via low-level
/// calls and new constructor args are appended, so the "Regression" contract
/// compiles against the pre-fix source and the revert check can replay it.
contract PBA_L2_057_Regression is Test {
    function test_L2_057_publishCannotFrontRunWithdraw() public {
        address gov = address(0x60);
        ReleaseManifestRegistry r = new ReleaseManifestRegistry(gov);
        address rec = address(0xEC);
        vm.prank(gov);
        r.setRecorder(rec, true);
        bytes32 id = keccak256("rel");
        vm.startPrank(rec);
        r.draftRelease(id, keccak256("v1"));
        r.addArtifact(id, keccak256("linux"), keccak256("bin"), keccak256("sig"), 1);
        r.beginBuild(id);
        r.markTested(id);
        r.markNotarized(id);
        vm.stopPrank();
        // A mempool watcher sees the recorder's withdraw and publishes first.
        vm.prank(makeAddr("watcher"));
        try r.publish(id) {} catch {}
        vm.prank(rec);
        r.withdraw(id);
        assertEq(r.getRelease(id).state, 6, "the bad release was withdrawn, not published");
    }
}
