// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {MemberBond} from "../../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../../src/core_membership/MembershipStakeVault.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {ValidatorRegistry} from "../../src/ValidatorRegistry.sol";

/// M-2.0 / M-2.2 / M-2.3 — the membership grant as a VALIDATOR BOND.
///
/// Per citrate-chain #139 design (c): the vault stops depositing into
/// `LiquidStakingPool` and instead deploys a per-member CREATE2 `MemberBond`
/// clone that becomes the `staker` in `ValidatorRegistry`. The clone exists
/// because `registerValidator` reverts `StakerHasValidator()` once
/// `pubkeyOfStaker[msg.sender]` is set, so one vault contract could otherwise
/// bond exactly one member ever.
///
/// The ed25519 precompile at 0x0120 is mocked with `vm.mockCall`, matching
/// `test/ValidatorRegistry.t.sol`; verify semantics are covered by the Rust
/// precompile tests.
contract MemberBondTest is Test {
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
    bytes internal SIG = new bytes(64); // content irrelevant; precompile mocked

    uint256 internal memberTokenId;
    uint256 internal member2TokenId;

    function setUp() public {
        admin = address(this);
        member = address(0x3E3B3);
        member2 = address(0x3E3B4);
        attacker = address(0xBAD);

        registry = new ValidatorRegistry(
            gov,
            slasher,
            minter,
            GRANT_AMOUNT, // minStake — the membership grant IS the bond (owner decision A.1)
            1 ether,
            5000,
            10_000 ether
        );
        sbt = new CitrateMemberSBT(admin);
        bondImpl = new MemberBond();

        MembershipStakeVault impl = new MembershipStakeVault();
        vault = MembershipStakeVault(
            payable(
                address(
                    new ERC1967Proxy(
                        address(impl),
                        abi.encodeCall(
                            MembershipStakeVault.initialize,
                            (admin, registry, sbt, address(bondImpl))
                        )
                    )
                )
            )
        );

        _mockVerify(true);
        vm.roll(10_000);
        vm.deal(admin, 1_000_000 ether);
        vm.deal(attacker, 100 ether);

        memberTokenId = sbt.mintMember(
            member, keccak256("sub-member-1"), uint64(block.timestamp), uint64(block.timestamp + 365 days)
        );
        member2TokenId = sbt.mintMember(
            member2, keccak256("sub-member-2"), uint64(block.timestamp), uint64(block.timestamp + 365 days)
        );
    }

    function _mockVerify(bool ok) internal {
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(ok ? 1 : 0)));
    }

    function _grant(address to, uint256 tokenId) internal returns (uint256) {
        return vault.grant{value: GRANT_AMOUNT}(to, GRANT_AMOUNT, tokenId);
    }

    // ── M-2.0 — the grant becomes a bond, not a pool deposit ──────────────

    /// The whole point of M-2.0: the 32k lands in a per-member bond escrow,
    /// NOT in LiquidStakingPool, and NOT in the member's own hands.
    function test_grant_fundsTheMemberBond_notThePool() public {
        address predicted = vault.bondOf(member);
        assertEq(predicted.code.length, 0, "bond must not exist before the grant");

        _grant(member, memberTokenId);

        assertEq(predicted.code.length > 0, true, "grant must deploy the bond clone");
        assertEq(predicted.balance, GRANT_AMOUNT, "the bond escrow holds the principal");
        assertEq(address(vault).balance, 0, "the vault must not retain the principal");
        assertEq(member.balance, 0, "the member never takes custody of the grant");
    }

    /// The CREATE2 address must be computable BEFORE the grant exists — the
    /// app's SignatureCeremony signs an ed25519 digest that binds the staker
    /// address, and that signing happens before the bond is deployed.
    function test_bondAddressIsDeterministicAndPredictable() public {
        address predicted = vault.bondOf(member);
        _grant(member, memberTokenId);
        assertEq(vault.bondOf(member), predicted, "bondOf must be stable across deployment");
    }

    /// Attribution stops being an stSALT preview and becomes the bonded
    /// principal. Same numbers today, entirely different meaning.
    function test_attributionReflectsBondedPrincipal() public {
        _grant(member, memberTokenId);
        assertEq(vault.attributedStake(member), GRANT_AMOUNT, "attributed == bonded principal");
        assertTrue(vault.isValidatorEligible(member), "32k meets the 40204 requirement");
        assertFalse(vault.isValidatorEligible(member2), "an ungranted member is not eligible");
    }

    /// Two members must get two DISTINCT bonds. This is the entire reason the
    /// clone exists: `registerValidator` reverts `StakerHasValidator()` on the
    /// second registration from the same staker address.
    function test_twoMembersGetDistinctBonds_andBothCanRegister() public {
        _grant(member, memberTokenId);
        _grant(member2, member2TokenId);

        address b1 = vault.bondOf(member);
        address b2 = vault.bondOf(member2);
        assertTrue(b1 != b2, "each member gets their own staker identity");

        vm.prank(member);
        MemberBond(payable(b1)).activate(PK_A, SIG);
        vm.prank(member2);
        MemberBond(payable(b2)).activate(PK_B, SIG);

        assertEq(registry.stakeOf(PK_A), GRANT_AMOUNT, "member 1 bonded");
        assertEq(registry.stakeOf(PK_B), GRANT_AMOUNT, "member 2 bonded");
    }

    /// A second grant to the same member must not silently collide with the
    /// existing bond (CREATE2 would revert anyway; fail loudly and early).
    function test_secondGrantToSameMember_reverts() public {
        _grant(member, memberTokenId);
        vm.expectRevert(MembershipStakeVault.BondExists.selector);
        _grant(member, memberTokenId);
    }

    // ── M-2.0 — activation is the member's, principal is not ──────────────

    function test_activate_registersBondAsStaker() public {
        _grant(member, memberTokenId);
        address bond = vault.bondOf(member);

        vm.prank(member);
        MemberBond(payable(bond)).activate(PK_A, SIG);

        assertEq(registry.stakeOf(PK_A), GRANT_AMOUNT, "principal is bonded in the registry");
        assertEq(bond.balance, 0, "the bond forwarded its principal to the registry");
        assertTrue(registry.isActive(PK_A), "validator is active");
    }

    function test_activate_onlyMember() public {
        _grant(member, memberTokenId);
        address bond = vault.bondOf(member);

        vm.prank(attacker);
        vm.expectRevert(MemberBond.NotMember.selector);
        MemberBond(payable(bond)).activate(PK_A, SIG);

        // Not even the vault (the custodian) may activate — the proposer key
        // is the member's and only they can prove control of it.
        vm.prank(address(vault));
        vm.expectRevert(MemberBond.NotMember.selector);
        MemberBond(payable(bond)).activate(PK_A, SIG);
    }

    function test_activate_twice_reverts() public {
        _grant(member, memberTokenId);
        address bond = vault.bondOf(member);
        vm.startPrank(member);
        MemberBond(payable(bond)).activate(PK_A, SIG);
        vm.expectRevert(MemberBond.AlreadyActivated.selector);
        MemberBond(payable(bond)).activate(PK_B, SIG);
        vm.stopPrank();
    }

    /// Rewards are the MEMBER'S — only principal is locked (owner-confirmed
    /// in #139). If this ever regresses, membership silently confiscates
    /// earnings, which is the failure #139 called out explicitly.
    function test_claimRewards_forwardsToMember() public {
        _grant(member, memberTokenId);
        address bond = vault.bondOf(member);
        vm.prank(member);
        MemberBond(payable(bond)).activate(PK_A, SIG);
        sbt.setKycVerified(memberTokenId, true);

        // Credit rewards through the registry's minter path and mature them.
        vm.deal(minter, 1_000 ether);
        vm.prank(minter);
        registry.creditReward{value: 100 ether}(PK_A, 100 ether);
        vm.roll(block.number + registry.EPOCH() * (registry.REWARD_RING() + 1));

        uint256 before = member.balance;
        vm.prank(member);
        MemberBond(payable(bond)).claimRewards();

        assertEq(member.balance - before, 100 ether, "rewards belong to the member");
        assertEq(bond.balance, 0, "the bond must not retain rewards");
    }

    /// Rewards are money leaving to a person, so they sit behind the same KYC
    /// gate as principal (owner decision A.7 - a paid-but-unverified member
    /// "cannot withdraw"). They are NOT behind the time lock: only principal is
    /// locked, so a verified member earns and realises rewards throughout the
    /// year without ceasing to validate.
    function test_claimRewards_isKycGatedButNotTimeLocked() public {
        _grant(member, memberTokenId);
        address bond = vault.bondOf(member);
        vm.prank(member);
        MemberBond(payable(bond)).activate(PK_A, SIG);

        vm.deal(minter, 1_000 ether);
        vm.prank(minter);
        registry.creditReward{value: 100 ether}(PK_A, 100 ether);
        vm.roll(block.number + registry.EPOCH() * (registry.REWARD_RING() + 1));

        // Unverified: blocked, even though the rewards have matured.
        vm.prank(member);
        vm.expectRevert(MemberBond.KycRequired.selector);
        MemberBond(payable(bond)).claimRewards();

        // Verified: allowed, DESPITE the principal lock still being in force.
        sbt.setKycVerified(memberTokenId, true);
        assertFalse(MemberBond(payable(bond)).isUnlocked(), "principal is still locked");

        uint256 before = member.balance;
        vm.prank(member);
        MemberBond(payable(bond)).claimRewards();
        assertEq(member.balance - before, 100 ether, "rewards are claimable inside the lock");
    }

    // ── M-2.2 — the lock ─────────────────────────────────────────────────

    /// Both legs must be set at grant time. The height leg is primary; the
    /// timestamp leg exists because a pure height lock can only OVERSHOOT
    /// wall-clock when the chain stalls — and 40204 demonstrably stalls (it
    /// halted ~3h on 2026-07-29). Owner decision A.4: slightly early beats
    /// slightly late.
    function test_lockLegsAreSetAtGrantTime() public {
        uint256 grantBlock = block.number;
        uint256 grantTime = block.timestamp;
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));

        assertEq(bond.unlockBlock(), grantBlock + bond.LOCK_BLOCKS(), "height leg");
        assertEq(bond.unlockTimestamp(), grantTime + bond.LOCK_SECONDS(), "wall-clock leg");
        assertFalse(bond.isUnlocked(), "locked immediately after the grant");
    }

    /// LOCK_BLOCKS is derived from the MEASURED 40204 block time (2.000 s),
    /// not guessed: 364 days x 86400 / 2 = 15,724,800. 364 rather than 365 is
    /// owner decision A.4 — a year minus up to a day.
    function test_lockConstantsMatchMeasuredBlockTime() public {
        MemberBond b = bondImpl;
        assertEq(b.LOCK_SECONDS(), 364 days, "a year minus a day (owner decision A.4)");
        assertEq(b.LOCK_BLOCKS(), uint256(364 days) / 2, "364 days at the measured 2.000 s block time");
        assertEq(b.LOCK_BLOCKS(), 15_724_800, "pinned so a drift is a deliberate act");
    }

    function test_heightLegUnlocks() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));

        vm.roll(bond.unlockBlock() - 1);
        assertFalse(bond.isUnlocked(), "still locked one block early");
        vm.roll(bond.unlockBlock());
        assertTrue(bond.isUnlocked(), "unlock is inclusive at the height");
    }

    /// The reason the OR-leg exists: if the chain stalls, blocks do not arrive
    /// and a pure height lock holds the member's principal well past a year.
    /// Wall-clock must be able to unlock on its own.
    function test_timestampLegUnlocksWhenTheChainStalls() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));

        // Warp a full year WITHOUT advancing blocks — the stall case.
        vm.warp(block.timestamp + 364 days);
        assertTrue(
            block.number < bond.unlockBlock(),
            "precondition: the height leg has NOT been reached"
        );
        assertTrue(bond.isUnlocked(), "wall-clock alone must unlock a stalled chain");
    }

    function test_requestRelease_revertsWhileLocked() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        sbt.setKycVerified(memberTokenId, true);
        vm.prank(member);
        vm.expectRevert(MemberBond.StillLocked.selector);
        bond.requestRelease();
    }

    /// Owner decision A.5 — no auto-withdraw. Reaching the unlock makes exit
    /// ELIGIBLE; the funds stay bonded until the member acts.
    function test_unlockDoesNotAutoWithdraw() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        vm.roll(bond.unlockBlock());
        assertTrue(bond.isUnlocked(), "eligible");
        assertEq(member.balance, 0, "but nothing has moved on its own");
        assertEq(registry.stakeOf(PK_A), GRANT_AMOUNT, "principal is still bonded");
    }

    // ── M-2.3 — KYC supersedes everything, checked FIRST ──────────────────

    /// Owner decision A.6: KYC is checked FIRST, before the lock, and it
    /// supersedes every withdrawal check even after the lock has elapsed.
    function test_kycBlocksReleaseEvenAfterUnlock() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        vm.roll(bond.unlockBlock());
        assertTrue(bond.isUnlocked(), "the lock has elapsed");

        vm.prank(member);
        vm.expectRevert(MemberBond.KycRequired.selector);
        bond.requestRelease();
    }

    /// KYC is checked BEFORE the lock: an unverified member inside the lock
    /// must be told the KYC reason, not the lock reason. That ordering is the
    /// owner's explicit instruction, and it is observable only through which
    /// error surfaces.
    function test_kycIsCheckedBeforeTheLock() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        // Locked AND unverified — KYC must win.
        vm.prank(member);
        vm.expectRevert(MemberBond.KycRequired.selector);
        bond.requestRelease();
    }

    function test_verifiedMemberCanReleaseAfterUnlock() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        sbt.setKycVerified(memberTokenId, true);
        vm.roll(bond.unlockBlock());

        vm.prank(member);
        bond.requestRelease();

        assertEq(registry.stakeOf(PK_A), 0, "unbond initiated - principal leaves the bond");
    }

    /// A paid-but-unverified member still HAS the membership and the validator
    /// slot (owner decision A.7 — access is not gated on KYC); only the money
    /// out is. Guards against over-correcting the KYC gate into a paywall.
    function test_unverifiedMemberStillHoldsAnActiveValidator() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);

        assertFalse(sbt.isKycVerified(memberTokenId), "unverified");
        assertTrue(registry.isActive(PK_A), "but participation is NOT gated on KYC");
        assertTrue(vault.isValidatorEligible(member), "and eligibility stands");
    }

    // ── Custody negatives ────────────────────────────────────────────────

    function test_attackerCannotReleaseOrWithdraw() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);
        sbt.setKycVerified(memberTokenId, true);
        vm.roll(bond.unlockBlock());

        vm.startPrank(attacker);
        vm.expectRevert(MemberBond.NotMember.selector);
        bond.requestRelease();
        vm.expectRevert(MemberBond.NotMember.selector);
        bond.withdrawToMember();
        vm.stopPrank();
    }

    /// The bond must not be re-initialisable — a second `initialize` could
    /// repoint `member` at an attacker and hand them the principal.
    function test_bondCannotBeReinitialised() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));

        vm.prank(attacker);
        vm.expectRevert();
        bond.initialize(attacker, memberTokenId, registry, sbt, uint64(block.number), uint64(block.timestamp));
    }

    /// SALT must only ever leave the bond toward the member.
    function test_withdrawPaysTheMemberOnly() public {
        _grant(member, memberTokenId);
        MemberBond bond = MemberBond(payable(vault.bondOf(member)));
        vm.prank(member);
        bond.activate(PK_A, SIG);
        sbt.setKycVerified(memberTokenId, true);

        vm.roll(bond.unlockBlock());
        vm.prank(member);
        bond.requestRelease();

        // Clear the registry's own exit lock, then withdraw.
        vm.roll(block.number + registry.EPOCH() * (registry.EXIT_LOCK_EPOCHS() + 1));
        uint256 before = member.balance;
        vm.prank(member);
        bond.withdrawToMember();

        assertEq(member.balance - before, GRANT_AMOUNT, "principal reaches the member");
        assertEq(address(bond).balance, 0, "and nothing is stranded in the bond");
    }
}
