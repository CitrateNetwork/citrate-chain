// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import {MembershipStakeVault} from "../../src/core_membership/MembershipStakeVault.sol";
import {LiquidStakingPool} from "../../src/LiquidStakingPool.sol";

/// CORE-S5.4 Foundry tests for MembershipStakeVault against the REAL
/// LiquidStakingPool (repo convention: no mocks — the existing
/// LiquidStakingPool.t.sol instantiates the real pool and drives the
/// oracle committee; this suite follows that pattern for slash/reward
/// reporting and the 7-day withdrawal lockup).
///
/// Covers: full grant → attributed → (lapsed ⇄ renewed) → released →
/// claimed state machine; member-withdrawal reverts from EVERY state
/// (negative tests, not require-string trust); slash pass-through
/// accounting; attribution amounts vs actual pool shares.
contract MembershipStakeVaultTest is Test {
    LiquidStakingPool internal pool;
    MembershipStakeVault internal vault;

    address internal admin; // vault owner + pool governance (test contract)
    address internal member;
    address internal member2;
    address internal attacker;
    address internal oracle1;
    address internal oracle2;
    address internal oracle3;

    uint256 internal constant GRANT_AMOUNT = 32_000 ether;

    function setUp() public {
        admin = address(this);
        member = address(0x3E3B3);
        member2 = address(0x3E3B4);
        attacker = address(0xBAD);

        oracle1 = address(0x0AC1E1);
        oracle2 = address(0x0AC1E2);
        oracle3 = address(0x0AC1E3);

        pool = new LiquidStakingPool();
        vault = new MembershipStakeVault(admin, pool);

        // Treasury funding for grants + reward donations.
        vm.deal(admin, 1_000_000 ether);
        vm.deal(attacker, 100 ether);
    }

    // ── Helpers (LiquidStakingPool.t.sol oracle convention) ────────

    function _setupOraclesAndReport(uint256 rewards, uint256 slashed) internal {
        if (!pool.isOracle(oracle1)) pool.addOracle(oracle1);
        if (!pool.isOracle(oracle2)) pool.addOracle(oracle2);
        if (!pool.isOracle(oracle3)) pool.addOracle(oracle3);

        // Fund rewards via donate() (SOL-16: no unsolicited transfers).
        if (rewards > 0) {
            pool.donate{value: rewards}();
        }

        vm.prank(oracle1);
        pool.reportRewards(rewards, slashed);
        vm.prank(oracle2);
        pool.reportRewards(rewards, slashed);
        vm.prank(oracle3);
        pool.reportRewards(rewards, slashed);
    }

    function _grantToMember() internal returns (uint256) {
        return vault.grant{value: GRANT_AMOUNT}(member, GRANT_AMOUNT);
    }

    // ── Grant ──────────────────────────────────────────────────────

    function testGrant_stakesAndAttributes() public {
        uint256 id = _grantToMember();

        MembershipStakeVault.Grant memory g = vault.getGrant(id);
        assertEq(g.member, member);
        assertEq(g.principal, GRANT_AMOUNT);
        assertEq(uint256(g.state), uint256(MembershipStakeVault.GrantState.Attributed));

        // Shares held by the VAULT in the real pool, not the member.
        assertEq(pool.shares(address(vault)), g.shares, "vault holds the stSALT shares");
        assertEq(pool.shares(member), 0, "member holds no pool shares");
        assertEq(g.shares, GRANT_AMOUNT, "first deposit is 1:1 shares");

        // Attribution = validator stake coverage for the member.
        assertEq(vault.attributedShares(member), g.shares);
        assertEq(vault.attributedStake(member), GRANT_AMOUNT);
        assertTrue(vault.isValidatorEligible(member));

        // No SALT sits idle in the vault — it is all staked.
        assertEq(address(vault).balance, 0, "all granted SALT is staked in the pool");
    }

    function testGrant_requiresOwner() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker)
        );
        vault.grant{value: 1 ether}(attacker, 1 ether);
    }

    function testGrant_zeroMemberReverts() public {
        vm.expectRevert(MembershipStakeVault.ZeroAddress.selector);
        vault.grant{value: 1 ether}(address(0), 1 ether);
    }

    function testGrant_zeroAmountReverts() public {
        vm.expectRevert(MembershipStakeVault.ZeroAmount.selector);
        vault.grant{value: 0}(member, 0);
    }

    function testGrant_valueMismatchReverts() public {
        vm.expectRevert(MembershipStakeVault.ValueMismatch.selector);
        vault.grant{value: 1 ether}(member, 2 ether);
    }

    function testGrant_multipleGrantsTracked() public {
        uint256 id1 = _grantToMember();
        uint256 id2 = vault.grant{value: GRANT_AMOUNT}(member2, GRANT_AMOUNT);

        uint256[] memory ofMember = vault.grantsOf(member);
        assertEq(ofMember.length, 1);
        assertEq(ofMember[0], id1);

        uint256[] memory ofMember2 = vault.grantsOf(member2);
        assertEq(ofMember2.length, 1);
        assertEq(ofMember2[0], id2);
    }

    // ── Attribution vs pool shares at appreciated share price ──────

    function testGrant_attributionMatchesPoolSharesAtAppreciatedPrice() public {
        // First grant at share price 1.0 → 32k shares.
        uint256 id1 = _grantToMember();
        assertEq(vault.getGrant(id1).shares, GRANT_AMOUNT);

        // Pool rewards double the share price: 32k pooled + 32k rewards.
        _setupOraclesAndReport(32_000 ether, 0);
        assertEq(pool.getSharePrice(), 2e18, "share price doubled by rewards");

        // Second grant of 32k at price 2.0 → 16k shares from the REAL
        // pool — the vault records what the pool minted, not a local
        // recomputation.
        uint256 id2 = vault.grant{value: GRANT_AMOUNT}(member2, GRANT_AMOUNT);
        MembershipStakeVault.Grant memory g2 = vault.getGrant(id2);
        assertEq(g2.shares, 16_000 ether, "pool mints proportional shares at 2x price");
        assertEq(
            pool.shares(address(vault)),
            vault.getGrant(id1).shares + g2.shares,
            "vault pool balance equals sum of grant shares"
        );

        // Attribution is value-based: member2's coverage is still 32k
        // SALT even though the share count is 16k.
        assertApproxEqAbs(vault.attributedStake(member2), GRANT_AMOUNT, 2);
        assertTrue(vault.isValidatorEligible(member2));

        // member1's attribution appreciated with the pool (Q6).
        assertApproxEqAbs(vault.attributedStake(member), 64_000 ether, 2);
    }

    // ── Lapse ⇄ renew ──────────────────────────────────────────────

    function testLapse_detachesAttribution() public {
        uint256 id = _grantToMember();

        vault.lapse(id);
        assertEq(
            uint256(vault.getGrant(id).state),
            uint256(MembershipStakeVault.GrantState.Lapsed)
        );
        assertEq(vault.attributedShares(member), 0, "lapse detaches attribution");
        assertEq(vault.attributedStake(member), 0);
        assertFalse(vault.isValidatorEligible(member), "eligibility drops on lapse");

        // Principal remains vaulted and staked — nothing left the pool.
        assertEq(pool.shares(address(vault)), GRANT_AMOUNT);
    }

    function testRenew_reattachesAttribution() public {
        uint256 id = _grantToMember();
        vault.lapse(id);
        vault.renew(id);

        assertEq(
            uint256(vault.getGrant(id).state),
            uint256(MembershipStakeVault.GrantState.Attributed)
        );
        assertEq(vault.attributedShares(member), GRANT_AMOUNT);
        assertTrue(vault.isValidatorEligible(member), "eligibility restored on renew");
    }

    function testLapse_wrongStateReverts() public {
        uint256 id = _grantToMember();
        vault.lapse(id);
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector,
                MembershipStakeVault.GrantState.Lapsed
            )
        );
        vault.lapse(id);
    }

    function testRenew_wrongStateReverts() public {
        uint256 id = _grantToMember();
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector,
                MembershipStakeVault.GrantState.Attributed
            )
        );
        vault.renew(id);
    }

    function testLapseRenew_requireOwner() public {
        uint256 id = _grantToMember();
        vm.prank(member);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, member)
        );
        vault.lapse(id);

        vault.lapse(id);
        vm.prank(member);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, member)
        );
        vault.renew(id);
    }

    // ── Mainnet release ────────────────────────────────────────────

    function testRelease_blockedBeforeFlag() public {
        uint256 id = _grantToMember();
        // Even the OWNER cannot release before the flag — the flag is
        // the network-level policy gate (Q4).
        vm.expectRevert(MembershipStakeVault.ReleaseNotEnabled.selector);
        vault.releaseGrant(id);
    }

    function testEnableRelease_requiresOwnerAndIsOneWay() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker)
        );
        vault.enableMainnetRelease();

        vault.enableMainnetRelease();
        assertTrue(vault.mainnetReleaseEnabled());

        // One-way: re-enabling reverts; no disable function exists.
        vm.expectRevert(MembershipStakeVault.ReleaseAlreadyEnabled.selector);
        vault.enableMainnetRelease();
    }

    function testRelease_fullLifecycleFromAttributed() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vault.releaseGrant(id);

        MembershipStakeVault.Grant memory g = vault.getGrant(id);
        assertEq(uint256(g.state), uint256(MembershipStakeVault.GrantState.Released));
        assertEq(g.releaseAmount, GRANT_AMOUNT);
        assertEq(vault.attributedShares(member), 0, "release detaches attribution");
        assertEq(pool.shares(address(vault)), 0, "shares burned into withdrawal queue");

        // Pool lockup elapses; anyone may trigger the claim — funds can
        // only go to the member wallet.
        vm.roll(block.number + pool.WITHDRAWAL_DELAY());
        uint256 balBefore = member.balance;
        vm.prank(attacker);
        vault.claimReleased(id);

        assertEq(member.balance, balBefore + GRANT_AMOUNT, "member receives principal");
        assertEq(address(vault).balance, 0, "vault retains nothing");
        assertEq(
            uint256(vault.getGrant(id).state),
            uint256(MembershipStakeVault.GrantState.Claimed)
        );
    }

    function testRelease_fromLapsedState() public {
        uint256 id = _grantToMember();
        vault.lapse(id);
        vault.enableMainnetRelease();
        vault.releaseGrant(id); // lapsed principal is still releasable

        assertEq(
            uint256(vault.getGrant(id).state),
            uint256(MembershipStakeVault.GrantState.Released)
        );

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());
        vault.claimReleased(id);
        assertEq(member.balance, GRANT_AMOUNT);
    }

    function testRelease_requiresOwner() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vm.prank(member);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, member)
        );
        vault.releaseGrant(id);
    }

    function testRelease_doubleReleaseReverts() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vault.releaseGrant(id);
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector,
                MembershipStakeVault.GrantState.Released
            )
        );
        vault.releaseGrant(id);
    }

    // ── No member withdrawal path — negative tests from EVERY state ─
    //
    // D-11: "No path exists for the member to withdraw granted
    // principal pre-mainnet — by construction." These tests enumerate
    // every externally callable function that could move value and
    // prove each one reverts (or is inert) for the member in each
    // pre-release state. The only value-out path is claimReleased in
    // GrantState.Released, and it pays the member wallet exclusively.

    function testNoWithdrawal_fromAttributedState() public {
        uint256 id = _grantToMember();
        _assertMemberCannotExtract(id, MembershipStakeVault.GrantState.Attributed);
    }

    function testNoWithdrawal_fromLapsedState() public {
        uint256 id = _grantToMember();
        vault.lapse(id);
        _assertMemberCannotExtract(id, MembershipStakeVault.GrantState.Lapsed);
    }

    function testNoWithdrawal_fromReleasedStateInsideLockup() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vault.releaseGrant(id);

        // Inside the pool lockup the claim reverts in the pool itself.
        vm.prank(member);
        vm.expectRevert("Too early");
        vault.claimReleased(id);
        assertEq(member.balance, 0);
    }

    function testNoWithdrawal_fromClaimedState() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vault.releaseGrant(id);
        vm.roll(block.number + pool.WITHDRAWAL_DELAY());
        vault.claimReleased(id);

        // Double-claim: no second payout path.
        vm.prank(member);
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector,
                MembershipStakeVault.GrantState.Claimed
            )
        );
        vault.claimReleased(id);
    }

    /// Shared negative-path enumeration for pre-release states.
    function _assertMemberCannotExtract(
        uint256 grantId,
        MembershipStakeVault.GrantState state
    ) internal {
        // 1. claimReleased — the only value-out function — rejects the state.
        vm.prank(member);
        vm.expectRevert(
            abi.encodeWithSelector(MembershipStakeVault.WrongState.selector, state)
        );
        vault.claimReleased(grantId);

        // 2. Every owner-gated mutator rejects the member outright.
        vm.startPrank(member);
        bytes memory notOwner =
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, member);
        vm.expectRevert(notOwner);
        vault.releaseGrant(grantId);
        vm.expectRevert(notOwner);
        vault.enableMainnetRelease();
        vm.expectRevert(notOwner);
        vault.lapse(grantId);
        vm.expectRevert(notOwner);
        vault.renew(grantId);
        vm.expectRevert(notOwner);
        vault.grant{value: 0}(member, 0);
        vm.stopPrank();

        // 3. The member cannot reach the stake in the pool directly —
        //    the shares belong to the vault, not the member.
        assertEq(pool.shares(member), 0);
        vm.prank(member);
        vm.expectRevert("Insufficient shares");
        pool.requestWithdrawal(1);

        // 4. Nothing extractable sits in the vault, and the vault
        //    rejects direct sends (no dust/donation griefing).
        assertEq(address(vault).balance, 0);
        vm.deal(member, 1 ether);
        vm.prank(member);
        (bool ok, ) = address(vault).call{value: 1 ether}("");
        assertFalse(ok, "vault must reject unsolicited SALT");

        // 5. The member's balance never moved.
        assertEq(member.balance, 1 ether, "member gained nothing from any path");
    }

    // ── Slash pass-through ─────────────────────────────────────────

    function testSlash_passesThroughToVaultedPrincipalWithEvent() public {
        uint256 id = _grantToMember();

        // Oracle committee reports a 3,200 SALT slash (10% cap of the
        // 32k pool — MAX_SLASH_RATE_BPS).
        _setupOraclesAndReport(0, 3_200 ether);

        // Pool share price dropped; the grant's current value with it.
        uint256 expectedValue = 28_800 ether;
        assertApproxEqAbs(vault.attributedStake(member), expectedValue, 2);
        assertFalse(
            vault.isValidatorEligible(member),
            "slashed coverage below 32k drops eligibility honestly"
        );

        // pokeSlash surfaces the pass-through with an event.
        vm.expectEmit(true, true, false, false);
        emit MembershipStakeVault.SlashPassedThrough(id, member, 0, 0);
        vault.pokeSlash(id);

        MembershipStakeVault.Grant memory g = vault.getGrant(id);
        assertApproxEqAbs(g.lastKnownValue, expectedValue, 2);
        assertEq(g.principal, GRANT_AMOUNT, "nominal principal is preserved for the record");
    }

    function testSlash_exactEventAccounting() public {
        uint256 id = _grantToMember();
        _setupOraclesAndReport(0, 3_200 ether);

        uint256 current = pool.previewWithdraw(vault.getGrant(id).shares);
        vm.expectEmit(true, true, false, true);
        emit MembershipStakeVault.SlashPassedThrough(
            id, member, GRANT_AMOUNT - current, current
        );
        vault.pokeSlash(id);
    }

    function testSlash_noEventWithoutValueDrop() public {
        uint256 id = _grantToMember();
        // Rewards only — lastKnownValue tracks up silently, no slash event.
        _setupOraclesAndReport(1_000 ether, 0);

        vm.recordLogs();
        vault.pokeSlash(id);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0, "appreciation must not emit a slash event");
        assertApproxEqAbs(vault.getGrant(id).lastKnownValue, 33_000 ether, 2);
    }

    function testSlash_reflectedInReleaseAccounting() public {
        uint256 id = _grantToMember();
        _setupOraclesAndReport(0, 3_200 ether);

        vault.enableMainnetRelease();
        vault.releaseGrant(id);

        // Release locks in the post-slash value, not nominal principal.
        MembershipStakeVault.Grant memory g = vault.getGrant(id);
        assertApproxEqAbs(g.releaseAmount, 28_800 ether, 2);

        vm.roll(block.number + pool.WITHDRAWAL_DELAY());
        vault.claimReleased(id);
        assertApproxEqAbs(
            member.balance,
            28_800 ether,
            2,
            "member receives slashed principal, surfaced honestly"
        );
    }

    function testSlash_pokeRevertsForReleasedGrant() public {
        uint256 id = _grantToMember();
        vault.enableMainnetRelease();
        vault.releaseGrant(id);
        vm.expectRevert(
            abi.encodeWithSelector(
                MembershipStakeVault.WrongState.selector,
                MembershipStakeVault.GrantState.Released
            )
        );
        vault.pokeSlash(id);
    }

    // ── Guards ─────────────────────────────────────────────────────

    function testGuard_unknownGrantReverts() public {
        vm.expectRevert(MembershipStakeVault.UnknownGrant.selector);
        vault.getGrant(99);
        vm.expectRevert(MembershipStakeVault.UnknownGrant.selector);
        vault.lapse(99);
    }

    function testGuard_receiveRejectsNonPool() public {
        (bool ok, ) = address(vault).call{value: 1 ether}("");
        assertFalse(ok, "even the owner cannot park SALT in the vault");
    }

    function testGuard_constructorRejectsZeroPool() public {
        vm.expectRevert(MembershipStakeVault.ZeroAddress.selector);
        new MembershipStakeVault(admin, LiquidStakingPool(payable(address(0))));
    }

    function testGuard_validatorRequirementConstant() public view {
        // Planset 02 §4: validator path = stake >= 32,000 SALT.
        assertEq(vault.VALIDATOR_STAKE_REQUIREMENT(), 32_000 ether);
    }
}
