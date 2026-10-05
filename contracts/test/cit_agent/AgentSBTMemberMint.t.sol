// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../src/cit_agent/OrganizationSBT.sol";
import "../../src/cit_agent/AgentSBT.sol";
import "../../src/core_membership/CitrateMemberSBT.sol";

/// AgentSBT member-callable mint (owner decision 2026-10-04): a holder of the
/// Citrate membership SBT mints an agent to itself under the owner-set member
/// org, up to a per-member cap. The owner path, quarantine and the soulbound
/// rule are unchanged.
contract AgentSBTMemberMintTest is Test {
    OrganizationSBT internal org;
    CitrateMemberSBT internal members;
    AgentSBT internal agent;

    address internal admin;
    address internal alice; // member
    address internal bob; // member
    address internal mallory; // not a member

    uint256 internal memberOrg;

    event AgentMinted(
        uint256 indexed tokenId, uint256 indexed parent_org_id, bytes32 indexed did, bytes32 pubkey_fingerprint
    );
    event MemberAgentMinted(uint256 indexed tokenId, address indexed member, uint256 memberAgentCount);

    function setUp() public {
        admin = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        mallory = makeAddr("mallory");

        org = new OrganizationSBT(admin);
        members = new CitrateMemberSBT(admin);
        agent = new AgentSBT(admin, org, IERC721(address(members)));

        memberOrg = org.mintOrg(makeAddr("org-holder"), keccak256("did:citrate:org:members"), admin, new bytes32[](0));
        agent.setMemberOrg(memberOrg);

        _makeMember(alice, "sub:alice");
        _makeMember(bob, "sub:bob");
    }

    function _makeMember(address who, string memory sub) internal returns (uint256) {
        return members.mintMember(
            who, keccak256(bytes(sub)), uint64(block.timestamp), uint64(block.timestamp + 365 days)
        );
    }

    function _did(string memory s) internal pure returns (bytes32) {
        return keccak256(bytes(string.concat("did:citrate:agent:", s)));
    }

    // ── happy path ───────────────────────────────────────────────

    function test_memberMints_toSelf_underMemberOrg() public {
        bytes32 did = _did("alice-1");
        bytes32 fp = keccak256("fp-alice-1");
        uint256 expectedId = agent.nextTokenId();

        vm.expectEmit(true, true, true, true, address(agent));
        emit AgentMinted(expectedId, memberOrg, did, fp);
        vm.expectEmit(true, true, false, true, address(agent));
        emit MemberAgentMinted(expectedId, alice, 1);

        vm.prank(alice);
        uint256 id = agent.mintAgentAsMember(did, fp);

        assertEq(id, expectedId);
        assertEq(agent.ownerOf(id), alice);
        AgentSBT.Agent memory a = agent.getAgent(id);
        assertEq(a.parent_org_id, memberOrg);
        assertEq(a.did, did);
        assertEq(a.pubkey_fingerprint, fp);
        assertFalse(a.quarantined);
        assertEq(agent.memberAgentCount(alice), 1);
        assertTrue(agent.didMinted(did));
        uint256[] memory byOrg = agent.getAgentsForOrg(memberOrg);
        assertEq(byOrg.length, 1);
        assertEq(byOrg[0], id);
    }

    function test_defaults() public view {
        assertEq(agent.maxAgentsPerMember(), 5);
        assertEq(agent.DEFAULT_MAX_AGENTS_PER_MEMBER(), 5);
        assertEq(address(agent.memberSbt()), address(members));
        assertTrue(agent.memberOrgSet());
        assertEq(agent.memberOrgId(), memberOrg);
    }

    // ── membership gate ──────────────────────────────────────────

    function test_nonMember_reverts() public {
        vm.prank(mallory);
        vm.expectRevert(AgentSBT.NotMember.selector);
        agent.mintAgentAsMember(_did("mallory"), keccak256("fp"));
    }

    function test_revokedMember_reverts() public {
        uint256 carolToken = _makeMember(makeAddr("carol"), "sub:carol");
        members.revoke(carolToken); // burns the membership SBT
        vm.prank(makeAddr("carol"));
        vm.expectRevert(AgentSBT.NotMember.selector);
        agent.mintAgentAsMember(_did("carol"), keccak256("fp"));
    }

    // ── cap ──────────────────────────────────────────────────────

    function test_cap_isPerMember() public {
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(alice);
            agent.mintAgentAsMember(keccak256(abi.encode("alice", i)), keccak256(abi.encode("fp", i)));
        }
        assertEq(agent.memberAgentCount(alice), 5);
        vm.prank(alice);
        vm.expectRevert(AgentSBT.MemberAgentCapReached.selector);
        agent.mintAgentAsMember(_did("alice-6"), keccak256("fp-6"));

        // Bob's counter is his own.
        vm.prank(bob);
        agent.mintAgentAsMember(_did("bob-1"), keccak256("fp-bob"));
        assertEq(agent.memberAgentCount(bob), 1);
    }

    function test_cap_ownerSettable_andZeroPauses() public {
        agent.setMaxAgentsPerMember(1);
        vm.prank(alice);
        agent.mintAgentAsMember(_did("a1"), keccak256("f1"));
        vm.prank(alice);
        vm.expectRevert(AgentSBT.MemberAgentCapReached.selector);
        agent.mintAgentAsMember(_did("a2"), keccak256("f2"));

        agent.setMaxAgentsPerMember(0);
        vm.prank(bob);
        vm.expectRevert(AgentSBT.MemberAgentCapReached.selector);
        agent.mintAgentAsMember(_did("b1"), keccak256("f3"));

        agent.setMaxAgentsPerMember(2);
        vm.prank(alice);
        agent.mintAgentAsMember(_did("a2"), keccak256("f2"));
        assertEq(agent.memberAgentCount(alice), 2);
    }

    function test_setters_areOwnerOnly() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        agent.setMaxAgentsPerMember(100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        agent.setMemberOrg(memberOrg);
    }

    // ── member org ───────────────────────────────────────────────

    function test_memberOrgNotSet_reverts() public {
        AgentSBT fresh = new AgentSBT(admin, org, IERC721(address(members)));
        vm.prank(alice);
        vm.expectRevert(AgentSBT.MemberOrgNotSet.selector);
        fresh.mintAgentAsMember(_did("alice"), keccak256("fp"));
    }

    function test_setMemberOrg_refusesInactiveOrg() public {
        uint256 other = org.mintOrg(makeAddr("org-holder"), keccak256("did:citrate:org:other"), admin, new bytes32[](0));
        org.deactivate(other);
        vm.expectRevert(AgentSBT.OrgNotActive.selector);
        agent.setMemberOrg(other);
        vm.expectRevert(AgentSBT.OrgNotActive.selector);
        agent.setMemberOrg(999); // never minted
    }

    function test_inactiveMemberOrg_reverts() public {
        org.deactivate(memberOrg);
        vm.prank(alice);
        vm.expectRevert(AgentSBT.OrgNotActive.selector);
        agent.mintAgentAsMember(_did("alice"), keccak256("fp"));
        // The refused mint did not consume the member's allowance.
        assertEq(agent.memberAgentCount(alice), 0);
    }

    // ── DID and fingerprint ──────────────────────────────────────

    function test_duplicateDid_reverts_acrossMembers() public {
        bytes32 did = _did("shared");
        vm.prank(alice);
        agent.mintAgentAsMember(did, keccak256("fp-a"));
        vm.prank(bob);
        vm.expectRevert(AgentSBT.DidAlreadyMinted.selector);
        agent.mintAgentAsMember(did, keccak256("fp-b"));
    }

    function test_duplicateDid_reverts_acrossMintPaths() public {
        bytes32 did = _did("owner-first");
        agent.mintAgent(bob, memberOrg, did, keccak256("fp-owner"));
        vm.prank(alice);
        vm.expectRevert(AgentSBT.DidAlreadyMinted.selector);
        agent.mintAgentAsMember(did, keccak256("fp-member"));

        bytes32 did2 = _did("member-first");
        vm.prank(alice);
        agent.mintAgentAsMember(did2, keccak256("fp-2"));
        vm.expectRevert(AgentSBT.DidAlreadyMinted.selector);
        agent.mintAgent(bob, memberOrg, did2, keccak256("fp-3"));
    }

    function test_zeroDid_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgentSBT.ZeroDid.selector);
        agent.mintAgentAsMember(bytes32(0), keccak256("fp"));
    }

    function test_zeroFingerprint_reverts() public {
        vm.prank(alice);
        vm.expectRevert(AgentSBT.ZeroFingerprint.selector);
        agent.mintAgentAsMember(_did("alice"), bytes32(0));
    }

    // ── unchanged surfaces ───────────────────────────────────────

    function test_quarantine_stillWorks_onMemberMintedAgent() public {
        vm.prank(alice);
        uint256 id = agent.mintAgentAsMember(_did("alice"), keccak256("fp"));
        agent.quarantine(id);
        assertTrue(agent.getAgent(id).quarantined);
        agent.unquarantine(id);
        assertFalse(agent.getAgent(id).quarantined);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        agent.quarantine(id);
    }

    function test_memberMintedAgent_isSoulbound() public {
        vm.prank(alice);
        uint256 id = agent.mintAgentAsMember(_did("alice"), keccak256("fp"));
        vm.prank(alice);
        vm.expectRevert(AgentSBT.TransferNotAllowed.selector);
        agent.transferFrom(alice, bob, id);
        vm.prank(alice);
        vm.expectRevert(AgentSBT.TransferNotAllowed.selector);
        agent.safeTransferFrom(alice, bob, id);
        assertEq(agent.ownerOf(id), alice);
    }

    function test_ownerMintAgent_stillOwnerOnly() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        agent.mintAgent(alice, memberOrg, _did("x"), keccak256("y"));
        // The owner path does not count against a member's cap.
        agent.mintAgent(alice, memberOrg, _did("owner-minted"), keccak256("fp"));
        assertEq(agent.memberAgentCount(alice), 0);
    }

    function test_constructor_refusesZeroMemberSbt() public {
        vm.expectRevert(AgentSBT.ZeroMemberSbt.selector);
        new AgentSBT(admin, org, IERC721(address(0)));
    }
}
