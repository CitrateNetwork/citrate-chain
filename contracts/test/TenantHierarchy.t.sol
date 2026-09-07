// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TenantHierarchy} from "../src/rbac/TenantHierarchy.sol";

/// @title TenantHierarchy.t — BFR-02-WP2 Forge tests
/// @dev Cites `.agentile/formal/specs/contracts/TenantHierarchyTree.tla`.
///      Coverage spans every cited invariant + happy path + reverts +
///      fuzz invariants. ≥30 tests per WP-2 acceptance.
contract TenantHierarchyTest is Test {
    TenantHierarchy internal th;

    bytes32 constant ROOT = keccak256("Boeing");
    bytes32 constant BCA = keccak256("Boeing.BCA");
    bytes32 constant EVERETT = keccak256("Boeing.BCA.Everett");
    bytes32 constant LINE = keccak256("Boeing.BCA.Everett.787-Line");
    bytes32 constant BDS = keccak256("Boeing.BDS");

    address internal admin1 = address(0xA1);
    address internal admin2 = address(0xA2);
    address internal admin3 = address(0xA3);
    address internal stranger = address(0x5);

    function setUp() public {
        th = new TenantHierarchy();
        address[] memory admins = new address[](2);
        admins[0] = admin1;
        admins[1] = admin2;
        th.initRoot(ROOT, "Boeing", bytes32(uint256(1)), admins, 2, 3);
    }

    // ── init ────────────────────────────────────────────────────────

    function test_initRoot_setsRootAndExists() public view {
        assertEq(th.root(), ROOT);
        assertTrue(th.exists(ROOT));
        TenantHierarchy.TenantNode memory n = th.getNode(ROOT);
        assertEq(n.level, 0);
        assertEq(n.classification_max, 3);
    }

    function test_initRoot_revertsOnDoubleInit() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.expectRevert(TenantHierarchy.AlreadyInitialized.selector);
        th.initRoot(BCA, "x", bytes32(0), admins, 1, 0);
    }

    function test_initRoot_revertsOnEmptyAdmins() public {
        TenantHierarchy fresh = new TenantHierarchy();
        address[] memory empty = new address[](0);
        vm.expectRevert(TenantHierarchy.EmptyAdmins.selector);
        fresh.initRoot(ROOT, "x", bytes32(0), empty, 0, 0);
    }

    function test_initRoot_revertsOnInvalidThreshold() public {
        TenantHierarchy fresh = new TenantHierarchy();
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.InvalidThreshold.selector, 2, 1)
        );
        fresh.initRoot(ROOT, "x", bytes32(0), admins, 2, 0);
    }

    function test_initRoot_revertsOnInvalidClassification() public {
        TenantHierarchy fresh = new TenantHierarchy();
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.InvalidClassification.selector, 4)
        );
        fresh.initRoot(ROOT, "x", bytes32(0), admins, 1, 4);
    }

    // ── createNode happy path ───────────────────────────────────────

    function test_createNode_levelOne() public {
        _createBcaUnderRoot();
        assertTrue(th.exists(BCA));
        TenantHierarchy.TenantNode memory n = th.getNode(BCA);
        assertEq(n.parent, ROOT);
        assertEq(n.level, 1);
    }

    function test_createNode_levelTwo() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        TenantHierarchy.TenantNode memory n = th.getNode(EVERETT);
        assertEq(n.level, 2);
        assertEq(n.parent, BCA);
    }

    function test_createNode_levelThree() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        _createLineUnderEverett();
        TenantHierarchy.TenantNode memory n = th.getNode(LINE);
        assertEq(n.level, 3);
    }

    function test_createNode_emitsNodeCreated() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        vm.expectEmit(true, true, false, true);
        emit TenantHierarchy.NodeCreated(BCA, ROOT, 1);
        th.createNode(ROOT, BCA, "BCA", 1, bytes32(uint256(2)), admins, 1, 3);
    }

    function test_createNode_addsToChildrenList() public {
        _createBcaUnderRoot();
        _createBdsUnderRoot();
        bytes32[] memory kids = th.getChildren(ROOT);
        assertEq(kids.length, 2);
    }

    // ── createNode invariant: ParentExists ──────────────────────────

    function test_createNode_revertsWhenParentMissing() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        bytes32 ghostParent = keccak256("ghost");
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NodeDoesNotExist.selector, ghostParent)
        );
        th.createNode(ghostParent, BCA, "x", 1, bytes32(0), admins, 1, 0);
    }

    function test_createNode_revertsOnDuplicateSelf() public {
        _createBcaUnderRoot();
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NodeAlreadyExists.selector, BCA)
        );
        th.createNode(ROOT, BCA, "x", 1, bytes32(0), admins, 1, 0);
    }

    // ── LevelsRespected ─────────────────────────────────────────────

    function test_createNode_revertsOnLevelMismatch() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        // Try to create level 2 directly under root (which is level 0).
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.LevelMismatch.selector, 1, 2)
        );
        th.createNode(ROOT, BCA, "x", 2, bytes32(0), admins, 1, 0);
    }

    function test_createNode_revertsOnInvalidLevelZero() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.InvalidLevel.selector, 0)
        );
        th.createNode(ROOT, BCA, "x", 0, bytes32(0), admins, 1, 0);
    }

    function test_createNode_revertsOnInvalidLevelTooDeep() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        _createLineUnderEverett();
        // Try to create level 4 under a level-3 leaf.
        bytes32 deeperKid = keccak256("Line.deeper");
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.InvalidLevel.selector, 4)
        );
        th.createNode(LINE, deeperKid, "x", 4, bytes32(0), admins, 1, 0);
    }

    // ── ClearanceMaxMonotonicDownTree ───────────────────────────────

    function test_createNode_revertsWhenChildClearanceExceedsParent() public {
        // Make BCA's max = 1 (Proprietary), then try to create child with max=2.
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        th.createNode(ROOT, BCA, "BCA", 1, bytes32(uint256(2)), admins, 1, 1);

        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TenantHierarchy.ClassificationExceedsParent.selector, 2, 1
            )
        );
        th.createNode(BCA, EVERETT, "E", 2, bytes32(0), admins, 1, 2);
    }

    function test_setClassificationMax_revertsWhenExceedsParent() public {
        _createBcaUnderRoot();
        // C035: a parent may not be lowered below an existing child's ceiling,
        // so first lower BCA to 1 before lowering ROOT to 1 (otherwise the
        // ChildExceedsClassification guard fires — which its own test covers).
        vm.prank(admin1);
        th.setClassificationMax(BCA, 1);
        // Lower root's max to 1.
        vm.prank(admin1);
        th.setClassificationMax(ROOT, 1);
        // Now raising BCA back to 3 exceeds the parent's (root's) max of 1.
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TenantHierarchy.ClassificationExceedsParent.selector, 3, 1
            )
        );
        th.setClassificationMax(BCA, 3);
    }

    function test_setClassificationMax_lowersValue() public {
        _createBcaUnderRoot();
        vm.prank(admin1);
        th.setClassificationMax(BCA, 1);
        TenantHierarchy.TenantNode memory n = th.getNode(BCA);
        assertEq(n.classification_max, 1);
    }

    function test_setClassificationMax_emitsNodeUpdated() public {
        _createBcaUnderRoot();
        vm.prank(admin1);
        vm.expectEmit(true, true, false, true);
        emit TenantHierarchy.NodeUpdated(
            BCA, keccak256("classification_max"), abi.encode(uint8(1))
        );
        th.setClassificationMax(BCA, 1);
    }

    // ── Admin gating ────────────────────────────────────────────────

    function test_createNode_revertsWhenCallerNotParentAdmin() public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NotAdmin.selector, stranger)
        );
        th.createNode(ROOT, BCA, "x", 1, bytes32(0), admins, 1, 0);
    }

    function test_setClassificationMax_revertsWhenNotAdmin() public {
        _createBcaUnderRoot();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NotAdmin.selector, stranger)
        );
        th.setClassificationMax(BCA, 1);
    }

    // ── removeNode ──────────────────────────────────────────────────

    function test_removeNode_succeedsWhenChildless() public {
        _createBcaUnderRoot();
        vm.prank(admin1);
        th.removeNode(BCA);
        assertFalse(th.exists(BCA));
    }

    function test_removeNode_revertsWhenHasChildren() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.HasChildren.selector, BCA)
        );
        th.removeNode(BCA);
    }

    function test_removeNode_removesFromParentChildrenList() public {
        _createBcaUnderRoot();
        _createBdsUnderRoot();
        vm.prank(admin1);
        th.removeNode(BCA);
        bytes32[] memory kids = th.getChildren(ROOT);
        assertEq(kids.length, 1);
        assertEq(kids[0], BDS);
    }

    function test_removeNode_emitsNodeRemoved() public {
        _createBcaUnderRoot();
        vm.prank(admin1);
        vm.expectEmit(true, true, false, true);
        emit TenantHierarchy.NodeRemoved(BCA, admin1);
        th.removeNode(BCA);
    }

    function test_removeNode_revertsOnRoot() public {
        vm.prank(admin1);
        vm.expectRevert();
        th.removeNode(ROOT);
    }

    function test_removeNode_revertsOnGhost() public {
        bytes32 ghost = keccak256("ghost");
        vm.prank(admin1);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NodeDoesNotExist.selector, ghost)
        );
        th.removeNode(ghost);
    }

    function test_removeNode_revertsWhenNotAdmin() public {
        _createBcaUnderRoot();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NotAdmin.selector, stranger)
        );
        th.removeNode(BCA);
    }

    // ── getPath ─────────────────────────────────────────────────────

    function test_getPath_root() public view {
        bytes32[] memory p = th.getPath(ROOT);
        assertEq(p.length, 1);
        assertEq(p[0], ROOT);
    }

    function test_getPath_levelOne() public {
        _createBcaUnderRoot();
        bytes32[] memory p = th.getPath(BCA);
        assertEq(p.length, 2);
        assertEq(p[0], ROOT);
        assertEq(p[1], BCA);
    }

    function test_getPath_levelThree() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        _createLineUnderEverett();
        bytes32[] memory p = th.getPath(LINE);
        assertEq(p.length, 4);
        assertEq(p[0], ROOT);
        assertEq(p[1], BCA);
        assertEq(p[2], EVERETT);
        assertEq(p[3], LINE);
    }

    function test_getPath_revertsOnGhost() public {
        bytes32 ghost = keccak256("ghost");
        vm.expectRevert(
            abi.encodeWithSelector(TenantHierarchy.NodeDoesNotExist.selector, ghost)
        );
        th.getPath(ghost);
    }

    // ── deriveSubSecretSalts ────────────────────────────────────────

    function test_deriveSubSecretSalts_returnsRootToLeafChain() public {
        _createBcaUnderRoot();
        _createEverettUnderBca();
        bytes32[] memory salts = th.deriveSubSecretSalts(EVERETT);
        assertEq(salts.length, 3);
        // ROOT salt was 1 in setUp, BCA was 2, EVERETT was 3.
        assertEq(salts[0], bytes32(uint256(1)));
        assertEq(salts[1], bytes32(uint256(2)));
        assertEq(salts[2], bytes32(uint256(3)));
    }

    // ── Fuzz: ParentImpliesChildListed ──────────────────────────────

    /// @dev Fuzz target: any created node appears in its parent's children list.
    function testFuzz_ParentImpliesChildListed(bytes32 child_id) public {
        vm.assume(child_id != ROOT && child_id != bytes32(0));
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        try th.createNode(ROOT, child_id, "x", 1, bytes32(0), admins, 1, 0) {
            bytes32[] memory kids = th.getChildren(ROOT);
            bool found;
            for (uint256 i; i < kids.length; ++i) {
                if (kids[i] == child_id) { found = true; break; }
            }
            assertTrue(found, "child must be listed in parent's children");
        } catch {}
    }

    /// @dev Fuzz target: classification_max never exceeds parent's after creation.
    function testFuzz_ClearanceMaxMonotonicDownTree(uint8 child_max, uint8 parent_max)
        public
    {
        parent_max = uint8(bound(parent_max, 0, 3));
        child_max = uint8(bound(child_max, 0, 3));
        // Override root's max via setClassificationMax.
        vm.prank(admin1);
        th.setClassificationMax(ROOT, parent_max);
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        if (child_max > parent_max) {
            vm.expectRevert();
            th.createNode(ROOT, BCA, "x", 1, bytes32(0), admins, 1, child_max);
        } else {
            th.createNode(ROOT, BCA, "x", 1, bytes32(0), admins, 1, child_max);
            assertLe(th.getNode(BCA).classification_max, parent_max);
        }
    }

    /// @dev Fuzz target: levels are bounded 0..3.
    function testFuzz_LevelBounded(uint8 level) public {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        if (level == 0 || level > 3) {
            vm.expectRevert(
                abi.encodeWithSelector(TenantHierarchy.InvalidLevel.selector, level)
            );
            th.createNode(ROOT, BCA, "x", level, bytes32(0), admins, 1, 0);
        } else if (level != 1) {
            vm.expectRevert(
                abi.encodeWithSelector(TenantHierarchy.LevelMismatch.selector, 1, level)
            );
            th.createNode(ROOT, BCA, "x", level, bytes32(0), admins, 1, 0);
        } else {
            th.createNode(ROOT, BCA, "x", level, bytes32(0), admins, 1, 0);
            assertEq(th.getNode(BCA).level, 1);
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _createBcaUnderRoot() internal {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        th.createNode(ROOT, BCA, "BCA", 1, bytes32(uint256(2)), admins, 1, 3);
    }

    function _createBdsUnderRoot() internal {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        th.createNode(ROOT, BDS, "BDS", 1, bytes32(uint256(20)), admins, 1, 3);
    }

    function _createEverettUnderBca() internal {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        th.createNode(BCA, EVERETT, "Everett", 2, bytes32(uint256(3)), admins, 1, 3);
    }

    function _createLineUnderEverett() internal {
        address[] memory admins = new address[](1);
        admins[0] = admin1;
        vm.prank(admin1);
        th.createNode(EVERETT, LINE, "787-Line", 3, bytes32(uint256(4)), admins, 1, 3);
    }
}
