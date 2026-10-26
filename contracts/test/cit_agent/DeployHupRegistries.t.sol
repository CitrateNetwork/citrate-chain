// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../script/DeployHupRegistries.s.sol";
import "../../script/Salts.sol";
import "../../src/core_membership/CitrateMemberSBT.sol";

/// HUP-S7.1: in-process rehearsal of the registry redeploy script. Calls the env-free
/// `deployWith` (vm.setEnv is process-wide, so env-driven runs race across tests) and
/// then makes one state-changing smoke call per contract, the way the operator's
/// anvil rehearsal does.
contract DeployHupRegistriesTest is Test {
    DeployHupRegistries internal script;
    address internal deployer;
    address internal ownerA;
    address internal ownerB;
    address internal ownerC;
    address internal member;
    CitrateMemberSBT internal memberSbt;

    function setUp() public {
        script = new DeployHupRegistries();
        deployer = makeAddr("deployer");
        ownerA = makeAddr("timelock-owner-a");
        ownerB = makeAddr("timelock-owner-b");
        ownerC = makeAddr("timelock-owner-c");
        member = makeAddr("member");
        memberSbt = new CitrateMemberSBT(address(this));
    }

    function _cfg(address admin) internal view returns (DeployHupRegistries.Config memory c) {
        c.deployer = deployer;
        c.admin = admin;
        c.timelockOwners = [ownerA, ownerB, ownerC];
        c.timelockDelay = 2 days;
        c.bookPath = "";
        c.memberSBT = address(memberSbt);
    }

    /// The live (40204) config: the member SBT is the book's pin.
    function _liveCfg(address admin) internal view returns (DeployHupRegistries.Config memory c) {
        c = _cfg(admin);
        c.bookPath = "addresses/40204.json";
        c.memberSBT = vm.parseJsonAddress(vm.readFile(c.bookPath), ".contracts.CitrateMemberSBT");
    }

    function _assertProjected(DeployHupRegistries.Deployed memory d) internal view {
        DeployHupRegistries.Deployed memory p = script.projectAll(d.admin, d.memberSBT);
        assertEq(d.organizationSBT, p.organizationSBT, "OrganizationSBT off projection");
        assertEq(d.agentSBT, p.agentSBT, "AgentSBT off projection");
        assertEq(d.capsuleRegistry, p.capsuleRegistry, "CapsuleRegistry off projection");
        assertEq(d.anchorRegistry, p.anchorRegistry, "AnchorRegistry off projection");
        assertEq(d.benchmarkRegistry, p.benchmarkRegistry, "BenchmarkRegistry off projection");
        assertEq(d.skillRegistry, p.skillRegistry, "SkillRegistry off projection");
        assertEq(address(AgentSBT(d.agentSBT).memberSbt()), d.memberSBT, "AgentSBT.memberSbt");
        // Independent recomputation with the cheatcode, through the Arachnid factory.
        assertEq(
            d.anchorRegistry,
            vm.computeCreate2Address(
                Salts.salt("AnchorRegistry"), keccak256(script.anchorInitCode()), script.ARACHNID_FACTORY()
            )
        );
    }

    function test_deploy_freshTimelockAdmin_landsOnProjections() public {
        DeployHupRegistries.Deployed memory d = script.deployWith(_cfg(address(0)));
        assertTrue(d.adminDeployedHere, "timelock deployed by the script");
        assertEq(
            d.admin, script.project("CitAgentTimelock", script.timelockInitCode([ownerA, ownerB, ownerC], 2 days))
        );
        MultisigTimelock2of3 tl = MultisigTimelock2of3(payable(d.admin));
        assertTrue(tl.isOwner(ownerA) && tl.isOwner(ownerB) && tl.isOwner(ownerC));
        assertEq(tl.minDelay(), 2 days);
        _assertProjected(d);
        // Admin-gated contracts are born owned by the admin, never the deployer or factory.
        assertEq(OrganizationSBT(d.organizationSBT).owner(), d.admin);
        assertEq(AgentSBT(d.agentSBT).owner(), d.admin);
        assertEq(CapsuleRegistry(d.capsuleRegistry).owner(), d.admin);
        assertTrue(OrganizationSBT(d.organizationSBT).owner() != deployer);
    }

    function test_deploy_isIdempotent() public {
        DeployHupRegistries.Deployed memory first = script.deployWith(_cfg(address(0)));
        DeployHupRegistries.Deployed memory again = script.deployWith(_cfg(address(0)));
        assertFalse(again.adminDeployedHere, "second run reuses the timelock");
        assertEq(again.admin, first.admin);
        assertEq(again.agentSBT, first.agentSBT);
        assertEq(again.skillRegistry, first.skillRegistry);
    }

    /// A rerun over a registry members already use must stay cheap to simulate: verify()
    /// reads the whole root list only while it is short.
    function test_verify_staysBoundedOverABusyAnchorRegistry() public {
        DeployHupRegistries.Deployed memory d = script.deployWith(_cfg(address(0)));
        for (uint256 i = 0; i < 1000; i++) {
            vm.prank(member);
            AnchorRegistry(d.anchorRegistry).anchor(AnchorRegistry.AnchorKind.NightlyMerkle, keccak256(abi.encode(i)));
        }
        vm.cool(d.anchorRegistry); // price the reads as a fresh eth_call would (cold slots)
        uint256 before = gasleft();
        script.verify(d);
        uint256 used = before - gasleft();
        assertLt(used, 1_000_000, "verify reads the whole busy root list");
        // And the rerun itself is still idempotent over the busy registry.
        DeployHupRegistries.Deployed memory again = script.deployWith(_cfg(address(0)));
        assertEq(again.anchorRegistry, d.anchorRegistry);
        assertEq(AnchorRegistry(d.anchorRegistry).rootCountByKind(AnchorRegistry.AnchorKind.NightlyMerkle), 1000);
    }

    function test_deploy_existingAdmin_used_as_owner() public {
        MultisigTimelock2of3 existing = new MultisigTimelock2of3([ownerA, ownerB, ownerC], 2 days);
        DeployHupRegistries.Deployed memory d = script.deployWith(_cfg(address(existing)));
        assertFalse(d.adminDeployedHere);
        assertEq(d.admin, address(existing));
        assertEq(AgentSBT(d.agentSBT).owner(), address(existing));
        _assertProjected(d);
    }

    function test_deploy_refusesFactoryAsAdmin() public {
        address factory = script.ARACHNID_FACTORY();
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        script.deployWith(_cfg(factory));
    }

    function test_deploy_onLiveChainId_refusesDeployerAsAdmin() public {
        vm.chainId(40204);
        DeployHupRegistries.Config memory c = _liveCfg(deployer);
        _plantCeremonySet();
        vm.expectRevert(bytes("admin must not be the deployer on 40204"));
        script.deployWith(c);
    }

    function test_deploy_onLiveChainId_refusesEoaAdmin() public {
        vm.chainId(40204);
        DeployHupRegistries.Config memory c = _liveCfg(makeAddr("some-eoa"));
        _plantCeremonySet();
        vm.expectRevert(bytes("admin must be a deployed multisig on 40204"));
        script.deployWith(c);
    }

    function test_deploy_onLiveChainId_requiresCeremonySet() public {
        vm.chainId(40204);
        DeployHupRegistries.Config memory c = _liveCfg(address(0));
        // No code planted at the book's ceremony-owned addresses.
        vm.expectRevert();
        script.deployWith(c);
    }

    function test_deploy_onLiveChainId_withCeremonySet_succeeds() public {
        vm.chainId(40204);
        DeployHupRegistries.Config memory c = _liveCfg(address(0));
        _plantCeremonySet();
        DeployHupRegistries.Deployed memory d = script.deployWith(c);
        _assertProjected(d);
    }

    function test_deploy_refusesMissingMemberSbt() public {
        DeployHupRegistries.Config memory c = _cfg(address(0));
        c.memberSBT = address(0);
        vm.expectRevert(bytes("set HUP_MEMBER_SBT (the CitrateMemberSBT address)"));
        script.deployWith(c);
    }

    function test_deploy_refusesMemberSbtWithoutCode() public {
        DeployHupRegistries.Config memory c = _cfg(address(0));
        c.memberSBT = makeAddr("no-code");
        vm.expectRevert(bytes("member SBT has no code: run DeployCoreMembership first"));
        script.deployWith(c);
    }

    function test_deploy_onLiveChainId_refusesMemberSbtOffTheBook() public {
        vm.chainId(40204);
        DeployHupRegistries.Config memory c = _liveCfg(address(0));
        _plantCeremonySet();
        c.memberSBT = address(memberSbt); // has code, but is not the book's pin
        vm.expectRevert(bytes("member SBT must be the book's CitrateMemberSBT on 40204"));
        script.deployWith(c);
    }

    function test_memberSbt_movesTheAgentProjection() public {
        address admin = makeAddr("admin");
        DeployHupRegistries.Deployed memory a = script.projectAll(admin, address(0xA));
        DeployHupRegistries.Deployed memory b = script.projectAll(admin, address(0xB));
        assertTrue(a.agentSBT != b.agentSBT, "the member SBT is part of AgentSBT's init code");
        assertEq(a.organizationSBT, b.organizationSBT);
    }

    /// Plants code at the book's ceremony-owned addresses (the check is "has code"; the test
    /// EVM is empty, so the real book's addresses double as fixtures).
    function _plantCeremonySet() internal {
        string memory json = vm.readFile("addresses/40204.json");
        string[6] memory names = script.ceremonyOwnedNames();
        for (uint256 i = 0; i < names.length; i++) {
            vm.etch(vm.parseJsonAddress(json, string.concat(".contracts.", names[i])), hex"00");
        }
        vm.etch(vm.parseJsonAddress(json, ".contracts.CitrateMemberSBT"), hex"00");
    }

    // ── one state-changing smoke call per contract ───────────────────────────

    function test_smoke_everyRegistryAcceptsItsFirstWrite() public {
        DeployHupRegistries.Deployed memory d = script.deployWith(_cfg(address(0)));

        // OrganizationSBT + AgentSBT: admin-only (the timelock executes these on chain).
        bytes32[] memory overlays = new bytes32[](0);
        vm.prank(d.admin);
        uint256 orgId = OrganizationSBT(d.organizationSBT).mintOrg(
            makeAddr("org-holder"), keccak256("did:citrate:org:smoke"), makeAddr("org-signer"), overlays
        );
        assertTrue(OrganizationSBT(d.organizationSBT).isActive(orgId));
        vm.prank(d.admin);
        uint256 agentId = AgentSBT(d.agentSBT).mintAgent(
            member, orgId, keccak256("did:citrate:agent:smoke"), keccak256("fingerprint")
        );
        assertEq(AgentSBT(d.agentSBT).ownerOf(agentId), member);
        vm.prank(member);
        vm.expectRevert();
        AgentSBT(d.agentSBT).mintAgent(member, orgId, keccak256("x"), keccak256("y"));

        // AgentSBT member mint: the admin names the member org, a membership holder mints.
        vm.prank(d.admin);
        AgentSBT(d.agentSBT).setMemberOrg(orgId);
        memberSbt.mintMember(member, keccak256("sub:smoke"), uint64(block.timestamp), uint64(block.timestamp + 365 days));
        vm.prank(member);
        uint256 memberAgentId =
            AgentSBT(d.agentSBT).mintAgentAsMember(keccak256("did:citrate:agent:member-smoke"), keccak256("fp-2"));
        assertEq(AgentSBT(d.agentSBT).ownerOf(memberAgentId), member);
        assertEq(AgentSBT(d.agentSBT).getAgent(memberAgentId).parent_org_id, orgId);

        // CapsuleRegistry: Workspace tier is open; Bundled needs the admin.
        vm.prank(member);
        CapsuleRegistry(d.capsuleRegistry).registerCapsule(
            uint256(keccak256("capsule")), keccak256("manifest"), keccak256("did"), CapsuleRegistry.SigningTier.Workspace
        );
        assertFalse(CapsuleRegistry(d.capsuleRegistry).isRevoked(uint256(keccak256("capsule"))));

        // AnchorRegistry.
        vm.prank(member);
        AnchorRegistry(d.anchorRegistry).anchor(AnchorRegistry.AnchorKind.NightlyMerkle, keccak256("day"));
        assertTrue(AnchorRegistry(d.anchorRegistry).isAnchoredBy(member, keccak256("day")));

        // BenchmarkRegistry.
        vm.prank(member);
        BenchmarkRegistry(d.benchmarkRegistry).record(agentId, keccak256("capsule"), keccak256("toolcall_pass"), 87);
        assertEq(
            BenchmarkRegistry(d.benchmarkRegistry).metricCount(member, agentId, keccak256("capsule"), keccak256("toolcall_pass")),
            1
        );

        // SkillRegistry.
        string[] memory tags = new string[](1);
        tags[0] = "hermes-learned";
        vm.prank(member);
        bytes32 h = SkillRegistry(d.skillRegistry).registerSkill("smoke-skill", "1.0.0", "", "smoke", tags);
        assertEq(h, SkillRegistry(d.skillRegistry).skillHashOf(member, "smoke-skill", "1.0.0"));
        assertEq(SkillRegistry(d.skillRegistry).totalSkills(), 1);
    }
}
