// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

import "../../src/cit_agent/OrganizationSBT.sol";
import "../../src/cit_agent/AgentSBT.sol";
import "../../src/cit_agent/CapsuleRegistry.sol";
import "../../src/cit_agent/AnchorRegistry.sol";
import "../../src/cit_agent/BenchmarkRegistry.sol";

/// CIT-AGENT-6a Foundry tests covering happy paths + soulbound
/// transfer rejection + access control reverts for all 5 contracts.
contract CitAgentContractsTest is Test, IERC1155Receiver {
    // Foundry tests that mint ERC-1155 to `address(this)` need the
    // receiver hook to accept the transfer.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }

    OrganizationSBT internal org;
    AgentSBT internal agent;
    CapsuleRegistry internal capsules;
    AnchorRegistry internal anchors;
    BenchmarkRegistry internal benchmarks;

    address internal admin;
    address internal alice;
    address internal bob;

    function setUp() public {
        admin = address(this);
        alice = address(0xA11CE);
        bob = address(0xB0B);

        org = new OrganizationSBT(admin);
        agent = new AgentSBT(admin, org);
        capsules = new CapsuleRegistry(admin);
        anchors = new AnchorRegistry();
        benchmarks = new BenchmarkRegistry();
    }

    // ── OrganizationSBT ────────────────────────────────────────────

    function testOrg_mintHappyPath() public {
        bytes32[] memory overlays = new bytes32[](1);
        overlays[0] = keccak256("FedRAMP-High");
        uint256 id =
            org.mintOrg(alice, keccak256("did:citrate:org:defense_prime"), bob, overlays);
        assertEq(id, 0);
        assertEq(org.ownerOf(id), alice);
        assertTrue(org.isActive(id));
        OrganizationSBT.Org memory o = org.getOrg(id);
        assertEq(o.signing_authority, bob);
        assertEq(o.active_overlays.length, 1);
    }

    function testOrg_mintRequiresAdmin() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(alice);
        vm.expectRevert();
        org.mintOrg(alice, keccak256("did:citrate:org:rogue"), bob, empty);
    }

    function testOrg_transferReverts() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 id =
            org.mintOrg(alice, keccak256("did:citrate:org:defense_prime"), bob, empty);
        vm.prank(alice);
        vm.expectRevert(OrganizationSBT.TransferNotAllowed.selector);
        org.transferFrom(alice, bob, id);
    }

    function testOrg_deactivate() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 id =
            org.mintOrg(alice, keccak256("did:citrate:org:defense_prime"), bob, empty);
        org.deactivate(id);
        assertFalse(org.isActive(id));
    }

    // ── AgentSBT ───────────────────────────────────────────────────

    function testAgent_mintRequiresActiveOrg() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 orgId =
            org.mintOrg(alice, keccak256("did:citrate:org:defense_prime"), bob, empty);
        org.deactivate(orgId);
        vm.expectRevert(AgentSBT.OrgNotActive.selector);
        agent.mintAgent(
            alice,
            orgId,
            keccak256("did:citrate:agent:0xab12"),
            keccak256("pubkey_fingerprint")
        );
    }

    function testAgent_mintHappyPath() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 orgId =
            org.mintOrg(alice, keccak256("did:citrate:org:defense_prime"), bob, empty);
        uint256 agentId = agent.mintAgent(
            alice,
            orgId,
            keccak256("did:citrate:agent:0xab12"),
            keccak256("pubkey_fingerprint")
        );
        assertEq(agentId, 0);
        AgentSBT.Agent memory a = agent.getAgent(agentId);
        assertEq(a.parent_org_id, orgId);
        assertFalse(a.quarantined);
        uint256[] memory list = agent.getAgentsForOrg(orgId);
        assertEq(list.length, 1);
        assertEq(list[0], agentId);
    }

    function testAgent_transferReverts() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 orgId = org.mintOrg(alice, keccak256("did:citrate:org:b"), bob, empty);
        uint256 agentId = agent.mintAgent(
            alice,
            orgId,
            keccak256("did:citrate:agent:0xab12"),
            keccak256("pubkey")
        );
        vm.prank(alice);
        vm.expectRevert(AgentSBT.TransferNotAllowed.selector);
        agent.transferFrom(alice, bob, agentId);
    }

    function testAgent_quarantine() public {
        bytes32[] memory empty = new bytes32[](0);
        uint256 orgId = org.mintOrg(alice, keccak256("did:citrate:org:b"), bob, empty);
        uint256 agentId = agent.mintAgent(
            alice,
            orgId,
            keccak256("did:citrate:agent:0xab12"),
            keccak256("pubkey")
        );
        agent.quarantine(agentId);
        assertTrue(agent.getAgent(agentId).quarantined);
        agent.unquarantine(agentId);
        assertFalse(agent.getAgent(agentId).quarantined);
    }

    // ── CapsuleRegistry ───────────────────────────────────────────

    function testCapsule_bundledRequiresAdmin() public {
        uint256 capsule_id = uint256(keccak256("capsule-1"));
        vm.prank(alice);
        vm.expectRevert(CapsuleRegistry.BundledRequiresAdmin.selector);
        capsules.registerCapsule(
            capsule_id,
            keccak256("manifest-hash"),
            keccak256("did:publisher"),
            CapsuleRegistry.SigningTier.Bundled
        );
    }

    function testCapsule_bundledAdminMints() public {
        uint256 capsule_id = uint256(keccak256("capsule-1"));
        capsules.registerCapsule(
            capsule_id,
            keccak256("manifest-hash"),
            keccak256("did:publisher"),
            CapsuleRegistry.SigningTier.Bundled
        );
        CapsuleRegistry.Capsule memory c = capsules.getCapsule(capsule_id);
        assertEq(uint256(c.tier), uint256(CapsuleRegistry.SigningTier.Bundled));
        assertFalse(c.revoked);
    }

    function testCapsule_managedAnyCallerMints() public {
        uint256 capsule_id = uint256(keccak256("capsule-2"));
        vm.prank(alice);
        capsules.registerCapsule(
            capsule_id,
            keccak256("manifest-hash"),
            keccak256("did:publisher"),
            CapsuleRegistry.SigningTier.Managed
        );
        assertEq(capsules.balanceOf(alice, capsule_id), 1);
    }

    function testCapsule_duplicateRegisterReverts() public {
        uint256 capsule_id = uint256(keccak256("capsule-1"));
        capsules.registerCapsule(
            capsule_id,
            keccak256("m"),
            keccak256("p"),
            CapsuleRegistry.SigningTier.Bundled
        );
        vm.expectRevert(CapsuleRegistry.AlreadyRegistered.selector);
        capsules.registerCapsule(
            capsule_id,
            keccak256("m"),
            keccak256("p"),
            CapsuleRegistry.SigningTier.Bundled
        );
    }

    function testCapsule_revokeMarksRevoked() public {
        uint256 capsule_id = uint256(keccak256("capsule-1"));
        capsules.registerCapsule(
            capsule_id,
            keccak256("m"),
            keccak256("p"),
            CapsuleRegistry.SigningTier.Bundled
        );
        capsules.revokeCapsule(capsule_id);
        assertTrue(capsules.isRevoked(capsule_id));
    }

    function testCapsule_transferReverts() public {
        uint256 capsule_id = uint256(keccak256("capsule-1"));
        capsules.registerCapsule(
            capsule_id,
            keccak256("m"),
            keccak256("p"),
            CapsuleRegistry.SigningTier.Bundled
        );
        vm.expectRevert(CapsuleRegistry.TransferNotAllowed.selector);
        capsules.safeTransferFrom(admin, alice, capsule_id, 1, "");
    }

    // ── AnchorRegistry ────────────────────────────────────────────

    function testAnchor_perCapsuleCommit() public {
        bytes32 root = keccak256("audit-record-hash");
        anchors.anchor(AnchorRegistry.AnchorKind.PerCapsule, root);
        AnchorRegistry.Anchor memory a = anchors.getAnchor(root);
        assertEq(uint256(a.kind), uint256(AnchorRegistry.AnchorKind.PerCapsule));
        assertEq(a.committer, admin);
        assertTrue(anchors.isAnchored(root));
    }

    function testAnchor_nightlyMerkleAndPerApproval() public {
        bytes32 merkle = keccak256("nightly-merkle");
        bytes32 approval = keccak256("approval-decision-hash");
        anchors.anchor(AnchorRegistry.AnchorKind.NightlyMerkle, merkle);
        anchors.anchor(AnchorRegistry.AnchorKind.PerApproval, approval);
        assertEq(anchors.rootCountByKind(AnchorRegistry.AnchorKind.NightlyMerkle), 1);
        assertEq(anchors.rootCountByKind(AnchorRegistry.AnchorKind.PerApproval), 1);
    }

    function testAnchor_duplicateReverts() public {
        bytes32 root = keccak256("dup");
        anchors.anchor(AnchorRegistry.AnchorKind.PerApproval, root);
        vm.expectRevert(AnchorRegistry.AlreadyAnchored.selector);
        anchors.anchor(AnchorRegistry.AnchorKind.PerApproval, root);
    }

    function testAnchor_anyCallerCanAnchor() public {
        bytes32 root = keccak256("alice-commit");
        vm.prank(alice);
        anchors.anchor(AnchorRegistry.AnchorKind.NightlyMerkle, root);
        assertEq(anchors.getAnchor(root).committer, alice);
    }

    function testAnchor_pagination() public {
        for (uint256 i = 0; i < 5; i++) {
            anchors.anchor(
                AnchorRegistry.AnchorKind.PerCapsule,
                bytes32(uint256(0xc0ffee) + i)
            );
        }
        bytes32[] memory first2 = anchors.rootsByKind(AnchorRegistry.AnchorKind.PerCapsule, 0, 2);
        bytes32[] memory last3 = anchors.rootsByKind(AnchorRegistry.AnchorKind.PerCapsule, 2, 5);
        assertEq(first2.length, 2);
        assertEq(last3.length, 3);
    }

    // ── BenchmarkRegistry ─────────────────────────────────────────

    function testBenchmark_recordAndQuery() public {
        bytes32 metric = keccak256("inference_latency_p99_ms");
        bytes32 capsule_id = keccak256("query-capsule");
        benchmarks.record(1, capsule_id, metric, 42);
        benchmarks.record(1, capsule_id, metric, 50);
        BenchmarkRegistry.BenchmarkRecord[] memory records =
            benchmarks.getMetric(1, capsule_id, metric);
        assertEq(records.length, 2);
        assertEq(records[0].value, 42);
        assertEq(records[1].value, 50);
        assertEq(benchmarks.metricCount(1, capsule_id, metric), 2);
    }

    function testBenchmark_metricSeenTracksUnique() public {
        bytes32 m1 = keccak256("latency_p99");
        bytes32 m2 = keccak256("throughput_rps");
        bytes32 capsule_id = keccak256("c");
        benchmarks.record(1, capsule_id, m1, 100);
        benchmarks.record(1, capsule_id, m2, 200);
        benchmarks.record(1, capsule_id, m1, 110);
        assertEq(benchmarks.allMetrics(0), m1);
        assertEq(benchmarks.allMetrics(1), m2);
        // m1 only appears once even though recorded twice.
    }
}
