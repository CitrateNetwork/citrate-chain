// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../src/cit_agent/AnchorRegistry.sol";
import "../../src/cit_agent/BenchmarkRegistry.sol";
import "../../src/SkillRegistry.sol";

/// HUP-S7.1: the registry versions that ship with the post-reroll redeploy.
///
///  * AnchorRegistry records every (committer, root) pair, so the committer a
///    reader sees is always the sender of that committer's own transaction, and
///    a second committer of the same root is recorded instead of refused.
///  * Paginated reads clamp `count` / `limit` without computing `start + count`,
///    so a caller passing a large page size gets the tail, not a revert.
///  * SkillRegistry derives `skillHash` with `abi.encode`, so (name, version)
///    pairs that concatenate to the same bytes get distinct ids.
contract RegistryNextVersionTest is Test {
    AnchorRegistry internal anchors;
    BenchmarkRegistry internal benchmarks;
    SkillRegistry internal skills;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    AnchorRegistry.AnchorKind internal constant NIGHTLY = AnchorRegistry.AnchorKind.NightlyMerkle;

    function setUp() public {
        anchors = new AnchorRegistry();
        benchmarks = new BenchmarkRegistry();
        skills = new SkillRegistry();
    }

    // ── AnchorRegistry: per-committer records ──────────────────────

    function test_anchor_secondCommitterOfSameRootIsRecorded() public {
        bytes32 root = keccak256("day-2026-10-01");
        vm.prank(bob);
        anchors.anchor(NIGHTLY, root);
        // A later anchor of the same value by another committer succeeds and is
        // recorded under that committer.
        vm.roll(block.number + 1);
        vm.prank(alice);
        anchors.anchor(NIGHTLY, root);

        AnchorRegistry.Anchor memory mine = anchors.getAnchorBy(alice, root);
        assertEq(mine.committer, alice, "alice's record names alice");
        assertEq(mine.root, root);
        assertEq(uint256(mine.kind), uint256(NIGHTLY));
        assertEq(mine.block_number, block.number);

        assertTrue(anchors.isAnchoredBy(alice, root));
        assertTrue(anchors.isAnchoredBy(bob, root));
        // The legacy read keeps returning the first record of the value.
        assertTrue(anchors.isAnchored(root));
        assertEq(anchors.getAnchor(root).committer, bob);
        // The per-kind list stays a list of distinct values.
        assertEq(anchors.rootCountByKind(NIGHTLY), 1);
        assertEq(anchors.rootCountByCommitter(alice, NIGHTLY), 1);
        assertEq(anchors.rootCountByCommitter(bob, NIGHTLY), 1);
    }

    function test_anchor_sameCommitterTwiceReverts() public {
        bytes32 root = keccak256("dup");
        vm.startPrank(alice);
        anchors.anchor(NIGHTLY, root);
        vm.expectRevert(AnchorRegistry.AlreadyAnchored.selector);
        anchors.anchor(NIGHTLY, root);
        // Also under another kind: one record per (committer, root).
        vm.expectRevert(AnchorRegistry.AlreadyAnchored.selector);
        anchors.anchor(AnchorRegistry.AnchorKind.PerApproval, root);
        vm.stopPrank();
    }

    function test_anchor_isAnchoredByIsFalseForOtherCommitters() public {
        bytes32 root = keccak256("only-alice");
        vm.prank(alice);
        anchors.anchor(NIGHTLY, root);
        assertFalse(anchors.isAnchoredBy(bob, root));
        vm.expectRevert(AnchorRegistry.AnchorNotFound.selector);
        anchors.getAnchorBy(bob, root);
    }

    function test_anchor_emitsEventWithSender() public {
        bytes32 root = keccak256("evt");
        vm.expectEmit(true, true, true, true, address(anchors));
        emit AnchorRegistry.Anchored(root, NIGHTLY, alice);
        vm.prank(alice);
        anchors.anchor(NIGHTLY, root);
    }

    // ── AnchorRegistry: pagination never overflows ─────────────────

    function _anchorN(address who, uint256 n) internal {
        for (uint256 i = 0; i < n; i++) {
            vm.prank(who);
            anchors.anchor(NIGHTLY, bytes32(uint256(0xa000) + i));
        }
    }

    function test_rootsByKind_maxCountReturnsTail() public {
        _anchorN(alice, 3);
        bytes32[] memory tail = anchors.rootsByKind(NIGHTLY, 1, type(uint256).max);
        assertEq(tail.length, 2);
        assertEq(tail[0], bytes32(uint256(0xa001)));
        assertEq(tail[1], bytes32(uint256(0xa002)));
    }

    function test_rootsByKind_startPastEndIsEmpty() public {
        _anchorN(alice, 2);
        assertEq(anchors.rootsByKind(NIGHTLY, 2, 1).length, 0);
        assertEq(anchors.rootsByKind(NIGHTLY, type(uint256).max, type(uint256).max).length, 0);
    }

    function test_rootsByCommitter_pagesOnlyThatCommitter() public {
        _anchorN(alice, 3);
        vm.prank(bob);
        anchors.anchor(NIGHTLY, keccak256("bob-only"));
        bytes32[] memory b = anchors.rootsByCommitter(bob, NIGHTLY, 0, type(uint256).max);
        assertEq(b.length, 1);
        assertEq(b[0], keccak256("bob-only"));
        bytes32[] memory a = anchors.rootsByCommitter(alice, NIGHTLY, 2, 10);
        assertEq(a.length, 1);
        assertEq(a[0], bytes32(uint256(0xa002)));
    }

    function testFuzz_rootsByKind_neverReverts(uint8 n, uint256 start, uint256 count) public {
        uint256 total = uint256(n) % 12;
        _anchorN(alice, total);
        bytes32[] memory page = anchors.rootsByKind(NIGHTLY, start, count);
        uint256 expected = start >= total ? 0 : (count < total - start ? count : total - start);
        assertEq(page.length, expected);
        for (uint256 i = 0; i < page.length; i++) {
            assertEq(page[i], bytes32(uint256(0xa000) + start + i));
        }
    }

    // ── BenchmarkRegistry: pagination never overflows ──────────────

    function test_benchmark_getMetricMaxLimitReturnsTail() public {
        bytes32 capsule = keccak256("capsule");
        bytes32 metric = keccak256("latency_p99_ms");
        vm.startPrank(alice);
        benchmarks.record(7, capsule, metric, 10);
        benchmarks.record(7, capsule, metric, 20);
        benchmarks.record(7, capsule, metric, 30);
        vm.stopPrank();
        BenchmarkRegistry.BenchmarkRecord[] memory page =
            benchmarks.getMetric(alice, 7, capsule, metric, 1, type(uint256).max);
        assertEq(page.length, 2);
        assertEq(page[0].value, 20);
        assertEq(page[1].value, 30);
        assertEq(benchmarks.getMetric(alice, 7, capsule, metric, type(uint256).max, 1).length, 0);
    }

    // ── SkillRegistry: unambiguous skillHash ───────────────────────

    function _register(address who, string memory name, string memory version) internal returns (bytes32) {
        string[] memory tags = new string[](0);
        vm.prank(who);
        return skills.registerSkill(name, version, "", "test skill", tags);
    }

    function test_skillHash_isAbiEncodeOfOwnerNameVersion() public {
        bytes32 h = _register(alice, "hf-model-register", "1.0.0");
        assertEq(h, keccak256(abi.encode(alice, "hf-model-register", "1.0.0")));
        assertEq(skills.skillHashOf(alice, "hf-model-register", "1.0.0"), h);
    }

    function test_skillHash_concatenationTwinsAreDistinct() public {
        // "skill1" + ".0" and "skill" + "1.0" concatenate to the same bytes.
        bytes32 a = _register(alice, "skill1", ".0");
        bytes32 b = _register(alice, "skill", "1.0");
        assertTrue(a != b, "distinct (name, version) pairs must get distinct ids");
        assertEq(skills.totalSkills(), 2);
        (, string memory nameA, string memory versionA,,,) = skills.getSkill(a);
        (, string memory nameB, string memory versionB,,,) = skills.getSkill(b);
        assertEq(nameA, "skill1");
        assertEq(versionA, ".0");
        assertEq(nameB, "skill");
        assertEq(versionB, "1.0");
    }

    function test_skillHash_sameTripleTwiceStillReverts() public {
        _register(alice, "dup", "1.0.0");
        string[] memory tags = new string[](0);
        vm.prank(alice);
        vm.expectRevert(bytes("skill exists"));
        skills.registerSkill("dup", "1.0.0", "", "again", tags);
    }

    function testFuzz_skillHashOf_matchesRegister(string memory name, string memory version) public {
        vm.assume(bytes(name).length != 0);
        bytes32 h = _register(bob, name, version);
        assertEq(skills.skillHashOf(bob, name, version), h);
        assertEq(h, keccak256(abi.encode(bob, name, version)));
    }
}
