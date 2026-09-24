// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ReleaseManifestRegistry} from "../../src/defense_prime/ReleaseManifestRegistry.sol";

contract ReleaseManifestRegistryTest is Test {
    ReleaseManifestRegistry internal reg;
    address internal governance;
    address internal recorder;
    address internal nobody;

    bytes32 internal constant R_1 = keccak256("release-1");
    bytes32 internal constant R_2 = keccak256("release-2");
    bytes32 internal constant V_050 = keccak256("v0.5.0");
    bytes32 internal constant V_051 = keccak256("v0.5.1");
    bytes32 internal constant PLATFORM_LINUX = keccak256("linux-x86_64-deb");
    bytes32 internal constant PLATFORM_MAC = keccak256("darwin-aarch64-app");
    bytes32 internal constant ART_HASH = keccak256("sha256-binary-1");
    bytes32 internal constant SIG_HASH = keccak256("sha256-codesign-1");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        nobody = makeAddr("nobody");
        vm.prank(governance);
        reg = new ReleaseManifestRegistry(governance);
        vm.prank(governance);
        reg.setRecorder(recorder, true);
    }

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(ReleaseManifestRegistry.ZeroGovernance.selector);
        new ReleaseManifestRegistry(address(0));
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReleaseManifestRegistry.NotGovernance.selector,
                nobody
            )
        );
        reg.setRecorder(nobody, true);
    }

    function test_draft_only_recorder() public {
        vm.prank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotRecorder.selector, nobody)
        );
        reg.draftRelease(R_1, V_050);
    }

    function test_draft_rejects_zero_release_id() public {
        vm.prank(recorder);
        vm.expectRevert(ReleaseManifestRegistry.ZeroReleaseId.selector);
        reg.draftRelease(bytes32(0), V_050);
    }

    function test_draft_creates_release_in_state_1() public {
        vm.roll(98765);
        vm.prank(recorder);
        reg.draftRelease(R_1, V_050);
        ReleaseManifestRegistry.Release memory r = reg.getRelease(R_1);
        assertEq(r.state, 1);
        assertEq(r.artifact_count, 0);
        assertEq(r.version_tag, V_050);
        assertEq(r.drafted_at_block, 98765);
        assertEq(r.published_at_block, 0);
        assertEq(r.drafted_by, bytes32(uint256(uint160(recorder))));
    }

    function test_draft_rejects_duplicate() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReleaseManifestRegistry.ReleaseAlreadyDrafted.selector,
                R_1
            )
        );
        reg.draftRelease(R_1, V_051);
        vm.stopPrank();
    }

    function test_addArtifact_only_in_drafted_or_building() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        // Allowed in Drafted (1)
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 12345);
        // Transition to Building (2)
        reg.beginBuild(R_1);
        // Allowed in Building (2)
        reg.addArtifact(R_1, PLATFORM_MAC, keccak256("art-2"), SIG_HASH, 22222);
        vm.stopPrank();
        assertEq(reg.artifactCount(R_1), 2);
    }

    function test_addArtifact_rejects_in_tested() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 1, 3)
        );
        reg.addArtifact(R_1, PLATFORM_MAC, keccak256("late"), SIG_HASH, 1000);
        vm.stopPrank();
    }

    function test_addArtifact_rejects_zero_hash() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        vm.expectRevert(ReleaseManifestRegistry.ZeroArtifactHash.selector);
        reg.addArtifact(R_1, PLATFORM_LINUX, bytes32(0), SIG_HASH, 1000);
        vm.stopPrank();
    }

    function test_beginBuild_only_from_drafted() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.beginBuild(R_1);
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 1, 2)
        );
        reg.beginBuild(R_1);
        vm.stopPrank();
    }

    function test_markTested_requires_artifacts() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.beginBuild(R_1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReleaseManifestRegistry.TestedRequiresArtifacts.selector,
                R_1
            )
        );
        reg.markTested(R_1);
        vm.stopPrank();
    }

    function test_markTested_succeeds_with_artifacts() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        vm.stopPrank();
        assertEq(reg.getRelease(R_1).state, 3);
    }

    function test_markTested_only_from_building() public {
        vm.prank(recorder);
        reg.draftRelease(R_1, V_050);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 2, 1)
        );
        reg.markTested(R_1);
    }

    function test_markNotarized_only_from_tested() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        reg.markNotarized(R_1);
        vm.stopPrank();
        assertEq(reg.getRelease(R_1).state, 4);
    }

    function test_publish_only_from_notarized() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        reg.markNotarized(R_1);
        vm.stopPrank();
        vm.roll(block.number + 5);
        reg.publish(R_1);
        ReleaseManifestRegistry.Release memory r = reg.getRelease(R_1);
        assertEq(r.state, 5);
        assertEq(r.published_at_block, block.number);
    }

    function test_publish_is_permissionless() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        reg.markNotarized(R_1);
        vm.stopPrank();
        // Nobody can call publish.
        vm.prank(nobody);
        reg.publish(R_1);
        assertEq(reg.getRelease(R_1).state, 5);
    }

    function test_publish_before_notarized_reverts() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        vm.stopPrank();
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 4, 3)
        );
        reg.publish(R_1);
    }

    function test_withdraw_from_drafted() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.withdraw(R_1);
        vm.stopPrank();
        assertEq(reg.getRelease(R_1).state, 6);
    }

    function test_withdraw_from_notarized() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        reg.markNotarized(R_1);
        reg.withdraw(R_1);
        vm.stopPrank();
        assertEq(reg.getRelease(R_1).state, 6);
    }

    function test_cannot_publish_after_withdraw() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.withdraw(R_1);
        vm.stopPrank();
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 4, 6)
        );
        reg.publish(R_1);
    }

    function test_cannot_withdraw_published() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.beginBuild(R_1);
        reg.markTested(R_1);
        reg.markNotarized(R_1);
        vm.stopPrank();
        reg.publish(R_1);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(ReleaseManifestRegistry.NotInState.selector, R_1, 1, 5)
        );
        reg.withdraw(R_1);
    }

    function test_byVersionTag_groups() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.draftRelease(R_2, V_051);
        vm.stopPrank();
        assertEq(reg.byVersionTag(V_050).length, 1);
        assertEq(reg.byVersionTag(V_051).length, 1);
    }

    function test_artifacts_returns_full_list() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.addArtifact(R_1, PLATFORM_LINUX, ART_HASH, SIG_HASH, 1000);
        reg.addArtifact(R_1, PLATFORM_MAC, keccak256("art2"), SIG_HASH, 2000);
        vm.stopPrank();
        ReleaseManifestRegistry.Artifact[] memory arts = reg.artifacts(R_1);
        assertEq(arts.length, 2);
        assertEq(arts[0].platform, PLATFORM_LINUX);
        assertEq(arts[1].platform, PLATFORM_MAC);
    }

    function test_allReleases_in_insertion_order() public {
        vm.startPrank(recorder);
        reg.draftRelease(R_1, V_050);
        reg.draftRelease(R_2, V_051);
        vm.stopPrank();
        bytes32[] memory all = reg.allReleases();
        assertEq(all.length, 2);
        assertEq(all[0], R_1);
        assertEq(all[1], R_2);
        assertEq(reg.releaseCount(), 2);
    }

    function test_revoked_recorder_cannot_draft() public {
        vm.prank(governance);
        reg.setRecorder(recorder, false);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReleaseManifestRegistry.NotRecorder.selector,
                recorder
            )
        );
        reg.draftRelease(R_1, V_050);
    }
}
