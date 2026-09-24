// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {MembershipStakeVault} from "../../src/core_membership/MembershipStakeVault.sol";
import {MemberBond} from "../../src/core_membership/MemberBond.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {ValidatorRegistry} from "../../src/ValidatorRegistry.sol";

/// M-2 Foundry tests for MembershipStakeVault against the REAL
/// ValidatorRegistry and the REAL MemberBond clone (repo convention: no mocks).
/// The 0x0120 ed25519-verify precompile is mocked with `vm.mockCall`, matching
/// `test/ValidatorRegistry.t.sol`.
///
/// ## What changed from the CORE-S5.4 suite this replaces
///
/// The vault no longer deposits into `LiquidStakingPool`, so the tests that
/// covered stSALT share pricing and socialized-slash pass-through
/// (`testSlash_*`, `testGrant_attributionMatchesPoolSharesAtAppreciatedPrice`)
/// have no referent under bonding — there is no share price and no socialized
/// slash. They are replaced, not dropped, by the bond-custody and
/// attribution-meaning tests below; the exit lifecycle moved to
/// `MemberBond.t.sol` because exit is now the member's act, not the owner's.
contract MembershipStakeVaultTest is Test {
    ValidatorRegistry internal registry;
    CitrateMemberSBT internal sbt;
    MembershipStakeVault internal vault;
    MemberBond internal bondImpl;

    address internal admin;
    address internal member;
    address internal member2;
    address internal attacker;

    address internal gov = address(0x6011);
    address internal slasher = address(0x5142);
    address internal minter = address(0x11d7);

    uint256 internal constant GRANT_AMOUNT = 32_000 ether;
    bytes32 internal constant PK_A = bytes32(uint256(0xAAAA));
    bytes32 internal constant PK_B = bytes32(uint256(0xBBBB));
    bytes internal SIG = new bytes(64);

    uint256 internal tokenId;
    uint256 internal tokenId2;

    function setUp() public {
        admin = address(this);
        member = address(0x3E3B3);
        member2 = address(0x3E3B4);
        attacker = address(0xBAD);

        registry = new ValidatorRegistry(
            gov, slasher, minter, GRANT_AMOUNT, 1 ether, 5000, 10_000 ether
        );
        sbt = new CitrateMemberSBT(admin);
        bondImpl = new MemberBond();
        vault = _deployVault(admin);

        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(1)));
        vm.roll(10_000);
        vm.deal(admin, 1_000_000 ether);
        vm.deal(attacker, 100_000 ether);

        tokenId = sbt.mintMember(
            member, keccak256("sub-1"), uint64(block.timestamp), uint64(block.timestamp + 365 days)
        );
        tokenId2 = sbt.mintMember(
            member2, keccak256("sub-2"), uint64(block.timestamp), uint64(block.timestamp + 365 days)
        );
    }

    function _deployVault(address owner_) internal returns (MembershipStakeVault) {
        MembershipStakeVault impl = new MembershipStakeVault();
        return MembershipStakeVault(
            payable(address(new ERC1967Proxy(
                address(impl),
                abi.encodeCall(
                    MembershipStakeVault.initialize, (owner_, registry, sbt, address(bondImpl))
                )
            )))
        );
    }

    function _grant() internal returns (uint256) {
        return vault.grant{value: GRANT_AMOUNT}(member, GRANT_AMOUNT, tokenId);
    }

    // -- Grant ------------------------------------------------------

    function testGrant_bondsAndAttributes() public {
        uint256 id = _grant();
        MembershipStakeVault.Grant memory g = vault.getGrant(id);

        assertEq(g.member, member, "member recorded");
        assertEq(g.principal, GRANT_AMOUNT, "principal recorded");
        assertEq(g.bond, vault.bondOf(member), "bond address recorded");
        assertEq(uint8(g.state), uint8(MembershipStakeVault.GrantState.Attributed), "Attributed");
        assertEq(vault.attributedStake(member), GRANT_AMOUNT, "attribution");
    }

    function testGrant_requiresOwner() public {
        vm.deal(attacker, GRANT_AMOUNT);
        vm.prank(attacker);
        vm.expectRevert(MembershipStakeVault.NotOwner.selector);
        vault.grant{value: GRANT_AMOUNT}(member, GRANT_AMOUNT, tokenId);
    }

    function testGrant_zeroMemberReverts() public {
        vm.expectRevert(MembershipStakeVault.ZeroAddress.selector);
        vault.grant{value: GRANT_AMOUNT}(address(0), GRANT_AMOUNT, tokenId);
    }

    function testGrant_zeroAmountReverts() public {
        vm.expectRevert(MembershipStakeVault.ZeroAmount.selector);
        vault.grant{value: 0}(member, 0, tokenId);
    }

    function testGrant_valueMismatchReverts() public {
        vm.expectRevert(MembershipStakeVault.ValueMismatch.selector);
        vault.grant{value: GRANT_AMOUNT - 1}(member, GRANT_AMOUNT, tokenId);
    }

    /// The grant must be bound to a token the member actually holds, or the
    /// KYC gate would read somebody else's attestation.
    function testGrant_tokenMustBelongToTheMember() public {
        vm.expectRevert(MembershipStakeVault.NotTheMembersToken.selector);
        vault.grant{value: GRANT_AMOUNT}(member, GRANT_AMOUNT, tokenId2);
    }

    function testGrant_secondGrantSameMemberReverts() public {
        _grant();
        vm.expectRevert(MembershipStakeVault.BondExists.selector);
        _grant();
    }

    function testGrant_tracksGrantsPerMember() public {
        uint256 id = _grant();
        vault.grant{value: GRANT_AMOUNT}(member2, GRANT_AMOUNT, tokenId2);

        uint256[] memory mine = vault.grantsOf(member);
        assertEq(mine.length, 1, "one grant for member");
        assertEq(mine[0], id, "id matches");
        assertEq(vault.grantsOf(member2).length, 1, "one grant for member2");
        assertEq(vault.nextGrantId(), 2, "two grants issued");
    }

    /// The vault is a conduit, not a pocket: the principal must be in the
    /// member's bond escrow at the end of the same transaction.
    function testGrant_vaultRetainsNothing() public {
        _grant();
        assertEq(address(vault).balance, 0, "vault holds no principal");
        assertEq(vault.bondOf(member).balance, GRANT_AMOUNT, "the bond holds it");
    }

    // -- Attribution meaning (replaces the stSALT-preview tests) -----

    /// Attribution is now the BONDED PRINCIPAL, not a pool share preview. The
    /// distinction that matters: it does not float. Under the old pool model an
    /// oracle report moved every member's attribution; nothing outside this
    /// contract can move it now.
    function testAttribution_doesNotFloat() public {
        _grant();
        uint256 before = vault.attributedStake(member);

        // Drive the sort of registry activity that used to reprice attribution.
        vm.prank(attacker);
        registry.registerValidator{value: GRANT_AMOUNT}(PK_B, SIG);
        vm.deal(minter, 1_000_000 ether);
        vm.prank(minter);
        registry.creditReward{value: 500 ether}(PK_B, 500 ether);
        vm.roll(block.number + registry.EPOCH() * 5);

        assertEq(
            vault.attributedStake(member), before, "attribution is invariant to registry events"
        );
    }

    function testAttribution_eligibilityThreshold() public {
        assertFalse(vault.isValidatorEligible(member), "no grant, not eligible");
        _grant();
        assertTrue(vault.isValidatorEligible(member), "granted, eligible");
    }

    // -- Lapse / renew ----------------------------------------------

    function testLapse_detachesAttribution() public {
        uint256 id = _grant();
        vault.lapse(id);

        assertEq(vault.attributedStake(member), 0, "attribution detached");
        assertFalse(vault.isValidatorEligible(member), "eligibility drops");
        assertEq(
            uint8(vault.getGrant(id).state), uint8(MembershipStakeVault.GrantState.Lapsed), "Lapsed"
        );
    }

    /// Lapsing a membership must NOT seize the bond - the principal stays put.
    function testLapse_leavesPrincipalBonded() public {
        uint256 id = _grant();
        address bond = vault.bondOf(member);
        vault.lapse(id);
        assertEq(bond.balance, GRANT_AMOUNT, "principal untouched by a lapse");
    }

    function testRenew_reattachesAttribution() public {
        uint256 id = _grant();
        vault.lapse(id);
        vault.renew(id);

        assertEq(vault.attributedStake(member), GRANT_AMOUNT, "attribution restored");
        assertEq(
            uint8(vault.getGrant(id).state),
            uint8(MembershipStakeVault.GrantState.Attributed),
            "Attributed"
        );
    }

    function testLapse_wrongStateReverts() public {
        uint256 id = _grant();
        vault.lapse(id);
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector, MembershipStakeVault.GrantState.Lapsed
            )
        );
        vault.lapse(id);
    }

    function testRenew_wrongStateReverts() public {
        uint256 id = _grant();
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector, MembershipStakeVault.GrantState.Attributed
            )
        );
        vault.renew(id);
    }

    function testLapseRenew_requireOwner() public {
        uint256 id = _grant();
        vm.startPrank(attacker);
        vm.expectRevert(MembershipStakeVault.NotOwner.selector);
        vault.lapse(id);
        vm.expectRevert(MembershipStakeVault.NotOwner.selector);
        vault.renew(id);
        vm.stopPrank();
    }

    // -- Release accounting -----------------------------------------

    /// `recordRelease` only MIRRORS a decision the member already made. It must
    /// revert while they have not, or the vault could detach attribution from a
    /// member who never chose to exit.
    function testRecordRelease_revertsUnlessMemberActuallyReleased() public {
        uint256 id = _grant();
        vm.expectRevert(bytes("release not requested"));
        vault.recordRelease(id);
    }

    function _memberExits() internal returns (MemberBond bond) {
        bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);
        sbt.setKycVerified(tokenId, true);
        vm.roll(bond.unlockBlock());
        vm.prank(member);
        bond.requestRelease();
    }

    function testRecordRelease_detachesAttributionAfterMemberExits() public {
        uint256 id = _grant();
        _memberExits();

        vault.recordRelease(id);

        assertEq(vault.attributedStake(member), 0, "attribution detached on exit");
        assertEq(
            uint8(vault.getGrant(id).state),
            uint8(MembershipStakeVault.GrantState.Released),
            "Released"
        );
    }

    /// Permissionless by design: it carries no authority, only mirrors the
    /// member's own on-chain act. Anyone may poke it.
    function testRecordRelease_isPermissionless() public {
        uint256 id = _grant();
        _memberExits();

        vm.prank(attacker);
        vault.recordRelease(id);
        assertEq(vault.attributedStake(member), 0, "anyone may mirror the member's exit");
    }

    // -- Custody negatives - the vault has NO value-out path ---------

    /// The strongest custody statement available: the vault exposes no function
    /// that moves value out, so there is nothing to test but the absence. This
    /// asserts the balance invariant across the full grant lifecycle.
    function testCustody_vaultNeverHoldsOrReleasesValue() public {
        uint256 id = _grant();
        assertEq(address(vault).balance, 0, "after grant");
        vault.lapse(id);
        assertEq(address(vault).balance, 0, "after lapse");
        vault.renew(id);
        assertEq(address(vault).balance, 0, "after renew");
    }

    /// Neither the owner nor anyone else can reach a funded bond through the
    /// vault. There is no sweep, no clawback, no arbitrary call.
    function testCustody_ownerCannotReachTheBond() public {
        _grant();
        address bond = vault.bondOf(member);

        assertEq(bond.balance, GRANT_AMOUNT, "bond funded");
        vm.prank(admin);
        (bool ok, ) = address(vault).call(abi.encodeWithSignature("sweep(address)", bond));
        assertFalse(ok, "no sweep function exists");
        assertEq(bond.balance, GRANT_AMOUNT, "bond untouched");
    }

    function testCustody_plainTransfersToVaultRevert() public {
        (bool ok, ) = address(vault).call{value: 1 ether}("");
        assertFalse(ok, "the vault must not accept unsolicited SALT");
    }

    // -- Guards -----------------------------------------------------

    function testGuard_unknownGrantReverts() public {
        vm.expectRevert(MembershipStakeVault.UnknownGrant.selector);
        vault.getGrant(42);
    }

    function testGuard_validatorRequirementConstant() public view {
        assertEq(vault.VALIDATOR_STAKE_REQUIREMENT(), 32_000 ether, "40204 requirement");
    }

    function testGuard_initializeRejectsZeroAddresses() public {
        MembershipStakeVault impl = new MembershipStakeVault();
        vm.expectRevert(MembershipStakeVault.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                MembershipStakeVault.initialize, (address(0), registry, sbt, address(bondImpl))
            )
        );
    }

    /// The implementation must not be initializable directly - an attacker who
    /// initialized it could then authorize an upgrade of it.
    function testGuard_implementationCannotBeInitialized() public {
        MembershipStakeVault impl = new MembershipStakeVault();
        vm.expectRevert();
        impl.initialize(attacker, registry, sbt, address(bondImpl));
    }

    function testGuard_vaultCannotBeReinitialised() public {
        vm.expectRevert();
        vault.initialize(attacker, registry, sbt, address(bondImpl));
    }

    // -- Ownership / upgrade authority (M-2.1) ----------------------

    function testOwnership_transfer() public {
        vault.transferOwnership(member);
        assertEq(vault.owner(), member, "owner moved");

        vm.expectRevert(MembershipStakeVault.NotOwner.selector);
        vault.transferOwnership(attacker);
    }

    function testOwnership_cannotBeOrphaned() public {
        vm.expectRevert(MembershipStakeVault.OwnerIsZero.selector);
        vault.transferOwnership(address(0));
    }

    /// Upgrade authority is the owner and nobody else - this is the whole
    /// security boundary of a UUPS money contract.
    function testUpgrade_onlyOwnerMayAuthorize() public {
        MembershipStakeVault next = new MembershipStakeVault();
        vm.prank(attacker);
        vm.expectRevert(MembershipStakeVault.NotOwner.selector);
        vault.upgradeToAndCall(address(next), bytes(""));
    }

    /// An upgrade must preserve the grant ledger. If storage were laid out
    /// wrong, this is where it shows up.
    function testUpgrade_preservesState() public {
        uint256 id = _grant();
        MembershipStakeVault next = new MembershipStakeVault();
        vault.upgradeToAndCall(address(next), bytes(""));

        assertEq(vault.attributedStake(member), GRANT_AMOUNT, "attribution survives upgrade");
        assertEq(vault.getGrant(id).member, member, "grant survives upgrade");
        assertEq(vault.owner(), admin, "owner survives upgrade");
    }
}
