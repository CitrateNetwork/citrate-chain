// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "../../src/core_membership/CitrateMemberSBT.sol";

/// Minimal child contract mirroring how AgentSBT gates minting on
/// OrganizationSBT.isActive — proves the parent-linkage surface of
/// CitrateMemberSBT is consumable by a member-parented SBT exactly the
/// way AgentSBT consumes OrganizationSBT (CORE-S5.4 deliverable 1).
contract MemberLinkedChildHarness {
    CitrateMemberSBT public immutable memberContract;

    error MemberNotActive();

    constructor(CitrateMemberSBT _memberContract) {
        memberContract = _memberContract;
    }

    function registerUnderMember(uint256 parent_member_id) external view returns (bool) {
        if (!memberContract.isActive(parent_member_id)) {
            revert MemberNotActive();
        }
        return true;
    }
}

/// CORE-S5.4 Foundry tests: soulbound transfer rejection, one-token-
/// per-sub binding, quarantine/revocation hooks, term lifecycle, and
/// the AgentSBT-style parent-linkage surface.
contract CitrateMemberSBTTest is Test {
    CitrateMemberSBT internal sbt;
    MemberLinkedChildHarness internal child;

    address internal admin;
    address internal alice;
    address internal bob;

    bytes32 internal constant SUB_ALICE = keccak256("auth.citrate.ai|sub|alice");
    bytes32 internal constant SUB_BOB = keccak256("auth.citrate.ai|sub|bob");

    uint64 internal termStart;
    uint64 internal termEnd;

    function setUp() public {
        admin = address(this);
        alice = address(0xA11CE);
        bob = address(0xB0B);

        sbt = new CitrateMemberSBT(admin);
        child = new MemberLinkedChildHarness(sbt);

        termStart = uint64(block.timestamp);
        termEnd = uint64(block.timestamp + 365 days);
    }

    function _mintAlice() internal returns (uint256) {
        return sbt.mintMember(alice, SUB_ALICE, termStart, termEnd);
    }

    // ── Mint ───────────────────────────────────────────────────────

    function testMint_happyPath() public {
        uint256 id = _mintAlice();
        assertEq(id, 0);
        assertEq(sbt.ownerOf(id), alice);
        assertEq(sbt.tokenIdForSub(SUB_ALICE), id);
        assertTrue(sbt.isSubBound(SUB_ALICE));

        CitrateMemberSBT.Member memory m = sbt.getMember(id);
        assertEq(m.subHash, SUB_ALICE);
        assertEq(m.termStart, termStart);
        assertEq(m.termEnd, termEnd);
        assertFalse(m.quarantined);
        assertFalse(m.revoked);
        assertTrue(sbt.isActive(id));
    }

    function testMint_requiresOwner() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        sbt.mintMember(alice, SUB_ALICE, termStart, termEnd);
    }

    function testMint_doubleMintPerSubReverts() public {
        _mintAlice();
        // Same sub, even to a different wallet, must revert.
        vm.expectRevert(CitrateMemberSBT.SubAlreadyBound.selector);
        sbt.mintMember(bob, SUB_ALICE, termStart, termEnd);
    }

    function testMint_distinctSubsGetDistinctTokens() public {
        uint256 idA = _mintAlice();
        uint256 idB = sbt.mintMember(bob, SUB_BOB, termStart, termEnd);
        assertEq(idA, 0);
        assertEq(idB, 1);
        assertEq(sbt.ownerOf(idB), bob);
    }

    function testMint_zeroAddressReverts() public {
        vm.expectRevert(CitrateMemberSBT.ZeroAddress.selector);
        sbt.mintMember(address(0), SUB_ALICE, termStart, termEnd);
    }

    function testMint_invalidTermReverts() public {
        vm.expectRevert(CitrateMemberSBT.InvalidTerm.selector);
        sbt.mintMember(alice, SUB_ALICE, termEnd, termStart);
    }

    // ── Soulbound enforcement ──────────────────────────────────────

    function testTransfer_transferFromReverts() public {
        uint256 id = _mintAlice();
        vm.prank(alice);
        vm.expectRevert(CitrateMemberSBT.TransferNotAllowed.selector);
        sbt.transferFrom(alice, bob, id);
    }

    function testTransfer_safeTransferFromReverts() public {
        uint256 id = _mintAlice();
        vm.prank(alice);
        vm.expectRevert(CitrateMemberSBT.TransferNotAllowed.selector);
        sbt.safeTransferFrom(alice, bob, id);
    }

    function testTransfer_approvedOperatorStillBlocked() public {
        uint256 id = _mintAlice();
        vm.prank(alice);
        sbt.approve(bob, id);
        vm.prank(bob);
        vm.expectRevert(CitrateMemberSBT.TransferNotAllowed.selector);
        sbt.transferFrom(alice, bob, id);
    }

    // ── Quarantine ─────────────────────────────────────────────────

    function testQuarantine_togglesActive() public {
        uint256 id = _mintAlice();
        assertTrue(sbt.isActive(id));

        sbt.quarantine(id);
        assertTrue(sbt.getMember(id).quarantined);
        assertFalse(sbt.isActive(id), "quarantined member must be inactive");

        sbt.unquarantine(id);
        assertFalse(sbt.getMember(id).quarantined);
        assertTrue(sbt.isActive(id));
    }

    function testQuarantine_requiresOwner() public {
        uint256 id = _mintAlice();
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, bob)
        );
        sbt.quarantine(id);
    }

    function testQuarantine_unknownTokenReverts() public {
        vm.expectRevert(CitrateMemberSBT.UnknownToken.selector);
        sbt.quarantine(99);
    }

    // ── Revocation ─────────────────────────────────────────────────

    function testRevoke_burnsAndDeactivates() public {
        uint256 id = _mintAlice();
        sbt.revoke(id);

        assertTrue(sbt.getMember(id).revoked);
        assertFalse(sbt.isActive(id));
        // Token is burned — ownerOf reverts (ERC721NonexistentToken).
        vm.expectRevert();
        sbt.ownerOf(id);
    }

    function testRevoke_bindingIsPermanent() public {
        uint256 id = _mintAlice();
        sbt.revoke(id);
        // Q1: revoked sub can never be re-minted, to any wallet.
        vm.expectRevert(CitrateMemberSBT.SubAlreadyBound.selector);
        sbt.mintMember(bob, SUB_ALICE, termStart, termEnd);
        assertTrue(sbt.isSubBound(SUB_ALICE));
    }

    function testRevoke_doubleRevokeReverts() public {
        uint256 id = _mintAlice();
        sbt.revoke(id);
        vm.expectRevert(CitrateMemberSBT.AlreadyRevoked.selector);
        sbt.revoke(id);
    }

    function testRevoke_requiresOwner() public {
        uint256 id = _mintAlice();
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice)
        );
        sbt.revoke(id);
    }

    // ── Term lifecycle ─────────────────────────────────────────────

    function testTerm_expiryDeactivates() public {
        uint256 id = _mintAlice();
        assertTrue(sbt.isActive(id));
        vm.warp(uint256(termEnd) + 1);
        assertFalse(sbt.isActive(id), "expired term must be inactive");
    }

    function testTerm_renewReactivates() public {
        uint256 id = _mintAlice();
        vm.warp(uint256(termEnd) + 1);
        assertFalse(sbt.isActive(id));

        uint64 newEnd = uint64(block.timestamp + 365 days);
        sbt.renewTerm(id, newEnd);
        assertEq(sbt.getMember(id).termEnd, newEnd);
        assertTrue(sbt.isActive(id));
    }

    function testTerm_renewMustExtend() public {
        uint256 id = _mintAlice();
        vm.expectRevert(CitrateMemberSBT.InvalidTerm.selector);
        sbt.renewTerm(id, termEnd); // not strictly greater
    }

    function testTerm_renewRevokedReverts() public {
        uint256 id = _mintAlice();
        sbt.revoke(id);
        vm.expectRevert(CitrateMemberSBT.AlreadyRevoked.selector);
        sbt.renewTerm(id, uint64(block.timestamp + 730 days));
    }

    // ── Lookups ────────────────────────────────────────────────────

    function testLookup_unknownSubReverts() public {
        vm.expectRevert(CitrateMemberSBT.UnknownSub.selector);
        sbt.tokenIdForSub(keccak256("never-minted"));
    }

    function testLookup_unknownTokenReverts() public {
        vm.expectRevert(CitrateMemberSBT.UnknownToken.selector);
        sbt.getMember(42);
    }

    function testLookup_isActiveFalseForNonexistent() public view {
        assertFalse(sbt.isActive(42));
    }

    // ── Parent linkage (AgentSBT mirror) ───────────────────────────

    function testLinkage_childGatesOnActiveMember() public {
        uint256 id = _mintAlice();
        assertTrue(child.registerUnderMember(id));
    }

    function testLinkage_childBlockedByQuarantine() public {
        uint256 id = _mintAlice();
        sbt.quarantine(id);
        vm.expectRevert(MemberLinkedChildHarness.MemberNotActive.selector);
        child.registerUnderMember(id);
    }

    function testLinkage_childBlockedByRevocation() public {
        uint256 id = _mintAlice();
        sbt.revoke(id);
        vm.expectRevert(MemberLinkedChildHarness.MemberNotActive.selector);
        child.registerUnderMember(id);
    }

    function testLinkage_childBlockedByExpiredTerm() public {
        uint256 id = _mintAlice();
        vm.warp(uint256(termEnd) + 1);
        vm.expectRevert(MemberLinkedChildHarness.MemberNotActive.selector);
        child.registerUnderMember(id);
    }
}
