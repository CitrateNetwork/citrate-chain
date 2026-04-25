// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NematocystSlashing} from "../src/NematocystSlashing.sol";
import {Governable} from "../src/lib/Governable.sol";

contract NematocystSlashingTest is Test {
    NematocystSlashing internal slashing;

    address internal governance = address(this);
    address internal provider1 = address(0xF101);
    address internal provider2 = address(0xF102);
    address internal provider3 = address(0xF103);
    address internal provider4 = address(0xF104);
    address internal outsider = address(0xBAD1);

    bytes internal dummyEvidence = hex"deadbeef";

    function setUp() public {
        slashing = new NematocystSlashing();

        vm.deal(provider1, 1000 ether);
        vm.deal(provider2, 1000 ether);
        vm.deal(provider3, 1000 ether);
        vm.deal(provider4, 1000 ether);
        vm.deal(outsider, 100 ether);
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _stakeProvider(address provider, uint256 amount) internal {
        vm.prank(provider);
        slashing.stake{value: amount}();
    }

    function _stakeDefault(address provider) internal {
        _stakeProvider(provider, 200 ether);
    }

    // ── Staking Tests ───────────────────────────────────────────────

    function test_stake_and_slash_latency() public {
        _stakeDefault(provider1);
        assertEq(slashing.stakes(provider1), 200 ether);
        assertEq(slashing.totalProviders(), 1);

        // Latency slash = 5% of 200 = 10 SALT (at 1x correlation)
        slashing.slash(provider1, NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // With only 1 provider and 1 slash, correlation multiplier = max(1, 1*30/1) = 3x (capped at 3)
        // But that makes penalty = 10 * 3 = 30 SALT
        // However with only 1 provider, 1*30/1 = 30 > 3, so mul = 3x
        // penalty = (200 * 500 / 10000) * 3 = 10 * 3 = 30
        assertEq(slashing.stakes(provider1), 170 ether);
        assertFalse(slashing.banned(provider1));
    }

    function test_slash_inconsistency() public {
        // Stake 10 providers so correlation multiplier is low
        _stakeDefault(provider1);
        _stakeDefault(provider2);
        _stakeDefault(provider3);
        _stakeDefault(provider4);

        // Add more providers to dilute correlation
        for (uint160 i = 10; i < 40; i++) {
            address p = address(i);
            vm.deal(p, 500 ether);
            _stakeProvider(p, 200 ether);
        }

        uint256 numProviders = slashing.totalProviders();
        assertEq(numProviders, 34);

        // Inconsistency slash = 20% of 200 = 40 SALT base
        // With 34 providers and 1 slash: mul = max(1, 1*30/34) = max(1, 0.88) = 1x
        slashing.slash(provider1, NematocystSlashing.SlashTier.Inconsistency, dummyEvidence);

        // 40 * 1 = 40
        assertEq(slashing.stakes(provider1), 160 ether);
        assertFalse(slashing.banned(provider1));
    }

    function test_slash_byzantine_full() public {
        _stakeDefault(provider1);

        slashing.slash(provider1, NematocystSlashing.SlashTier.Byzantine, dummyEvidence);

        // Byzantine = 100% + ban. All 200 SALT forfeited.
        assertEq(slashing.stakes(provider1), 0);
        assertTrue(slashing.banned(provider1));
        assertEq(slashing.totalProviders(), 0);
    }

    function test_banned_cannot_restake() public {
        _stakeDefault(provider1);

        slashing.slash(provider1, NematocystSlashing.SlashTier.Byzantine, dummyEvidence);
        assertTrue(slashing.banned(provider1));

        vm.prank(provider1);
        vm.expectRevert("Provider is banned");
        slashing.stake{value: 200 ether}();
    }

    function test_correlation_multiplier_scales() public {
        // Setup: 10 providers
        for (uint160 i = 1; i <= 10; i++) {
            address p = address(i);
            vm.deal(p, 500 ether);
            _stakeProvider(p, 200 ether);
        }
        assertEq(slashing.totalProviders(), 10);

        // No slashes yet: multiplier should be 1x (floor)
        assertEq(slashing.getCorrelationMultiplier(), 1e18);

        // Slash 1 provider: mul = max(1, 1*30/10) = max(1, 3) = 3x
        slashing.slash(address(uint160(1)), NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // After 1 slash of 10 providers: 1*30/10 = 3x
        assertEq(slashing.getCorrelationMultiplier(), 3e18);
    }

    function test_isolated_slash_low_penalty() public {
        // 100 providers, 1 slash = low correlation
        for (uint160 i = 1; i <= 100; i++) {
            address p = address(i);
            vm.deal(p, 500 ether);
            _stakeProvider(p, 200 ether);
        }

        // Before any slashes, correlation = 1x (floor)
        assertEq(slashing.getCorrelationMultiplier(), 1e18);

        // Slash 1 out of 100: mul = max(1, 1*30/100) = max(1, 0.3) = 1x (floor)
        address target = address(uint160(1));
        uint256 stakeBefore = slashing.stakes(target);
        slashing.slash(target, NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // Penalty = 200 * 500/10000 * 1 = 10 SALT
        assertEq(slashing.stakes(target), stakeBefore - 10 ether);
    }

    function test_coordinated_slash_high_penalty() public {
        // 10 providers, slash 4 in the same block => correlated attack
        for (uint160 i = 1; i <= 10; i++) {
            address p = address(i);
            vm.deal(p, 500 ether);
            _stakeProvider(p, 200 ether);
        }

        // Slash providers 1, 2, 3 first
        slashing.slash(address(uint160(1)), NematocystSlashing.SlashTier.Latency, dummyEvidence);
        slashing.slash(address(uint160(2)), NematocystSlashing.SlashTier.Latency, dummyEvidence);
        slashing.slash(address(uint160(3)), NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // After 3 slashes: providers who lost all stake are deregistered
        // Provider 1 was slashed at 3x (30/10=3x), penalty=30. Stake=170. Still registered.
        // After slash 1: slashesInWindow=1, totalProviders=10. mul=max(1,1*30/10)=3x. penalty=30.
        // After slash 2: slashesInWindow=2, totalProviders=10. mul=max(1,2*30/10)=max(1,6)=3x (capped). penalty=30.
        // After slash 3: slashesInWindow=3, totalProviders=10. mul=max(1,3*30/10)=max(1,9)=3x (capped). penalty=30.

        // Now slash provider 4. mul should be capped at 3x.
        uint256 stake4Before = slashing.stakes(address(uint160(4)));
        slashing.slash(address(uint160(4)), NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // base = 200 * 500 / 10000 = 10 SALT. mul = 3x. penalty = 30.
        assertEq(slashing.stakes(address(uint160(4))), stake4Before - 30 ether);
    }

    function test_non_governance_cannot_slash() public {
        _stakeDefault(provider1);

        vm.prank(outsider);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        slashing.slash(provider1, NematocystSlashing.SlashTier.Latency, dummyEvidence);
    }

    // ── Additional Tests ─────────────────────────────────────────────

    function test_zero_stake_reverts() public {
        vm.prank(provider1);
        vm.expectRevert("Zero stake");
        slashing.stake{value: 0}();
    }

    function test_below_min_stake_reverts() public {
        vm.prank(provider1);
        vm.expectRevert("Below minimum stake");
        slashing.stake{value: 50 ether}();
    }

    function test_unstake_returns_funds() public {
        _stakeDefault(provider1);

        uint256 balBefore = provider1.balance;
        vm.prank(provider1);
        slashing.unstake();

        assertEq(provider1.balance, balBefore + 200 ether);
        assertEq(slashing.stakes(provider1), 0);
        assertEq(slashing.totalProviders(), 0);
    }

    function test_banned_cannot_unstake() public {
        _stakeDefault(provider1);
        slashing.slash(provider1, NematocystSlashing.SlashTier.Byzantine, dummyEvidence);

        vm.prank(provider1);
        vm.expectRevert("Provider is banned");
        slashing.unstake();
    }

    function test_slash_not_staked_reverts() public {
        vm.expectRevert("Not staked");
        slashing.slash(provider1, NematocystSlashing.SlashTier.Latency, dummyEvidence);
    }

    function test_slash_already_banned_reverts() public {
        _stakeDefault(provider1);
        slashing.slash(provider1, NematocystSlashing.SlashTier.Byzantine, dummyEvidence);

        vm.expectRevert("Already banned");
        slashing.slash(provider1, NematocystSlashing.SlashTier.Latency, dummyEvidence);
    }

    function test_slash_empty_evidence_reverts() public {
        _stakeDefault(provider1);

        vm.expectRevert("Evidence required");
        slashing.slash(provider1, NematocystSlashing.SlashTier.Latency, "");
    }

    function test_isSlashable() public {
        assertFalse(slashing.isSlashable(provider1));

        _stakeDefault(provider1);
        assertTrue(slashing.isSlashable(provider1));

        slashing.slash(provider1, NematocystSlashing.SlashTier.Byzantine, dummyEvidence);
        assertFalse(slashing.isSlashable(provider1));
    }

    function test_governance_transfer() public {
        // RM-B1 / WP-D1.1 (audit SOL-21): two-step transfer.
        slashing.transferGovernance(provider1);
        assertEq(slashing.pendingGovernance(), provider1);
        vm.prank(provider1);
        slashing.acceptGovernance();
        assertEq(slashing.governance(), provider1);

        // Old governance can no longer slash
        _stakeDefault(provider2);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        slashing.slash(provider2, NematocystSlashing.SlashTier.Latency, dummyEvidence);

        // New governance can slash
        vm.prank(provider1);
        slashing.slash(provider2, NematocystSlashing.SlashTier.Latency, dummyEvidence);
    }

    function test_add_stake_increments() public {
        _stakeProvider(provider1, 200 ether);
        assertEq(slashing.stakes(provider1), 200 ether);
        assertEq(slashing.totalProviders(), 1);

        // Adding more stake should not double-count the provider
        _stakeProvider(provider1, 100 ether);
        assertEq(slashing.stakes(provider1), 300 ether);
        assertEq(slashing.totalProviders(), 1);
    }

    function test_receive_accepts_salt() public {
        (bool ok, ) = address(slashing).call{value: 1 ether}("");
        assertTrue(ok, "Contract should accept direct SALT transfers");
    }
}
