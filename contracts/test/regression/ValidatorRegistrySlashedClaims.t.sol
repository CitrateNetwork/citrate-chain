// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../src/ValidatorRegistry.sol";

/// @notice Two properties of the equivocation slash:
///         (1) rewards that matured before the slash sit outside the penalty
///             base, so the staker can still claim them afterwards;
///         (2) slashing an old validator does not clear the staker binding of
///             a newer validator the same staker registered after exiting.
contract ValidatorRegistrySlashedClaimsTest is Test {
    ValidatorRegistry reg;

    address gov = address(0x6011);
    address slasher = address(0x5142);
    address minter = address(0x11d7);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    bytes32 constant PK_A = bytes32(uint256(0xAAAA));
    bytes32 constant PK_B = bytes32(uint256(0xBBBB));

    uint256 constant MIN = 32_000 ether;
    bytes SIG = new bytes(64); // content irrelevant; precompile is mocked

    function setUp() public {
        reg = new ValidatorRegistry(gov, slasher, minter, MIN, 1 ether, 5000, 10_000 ether);
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(1)));
        vm.roll(10_000);
        vm.deal(alice, 10_000_000 ether);
        vm.deal(bob, 10_000_000 ether);
    }

    function _register(address who, bytes32 pk, uint256 amount) internal {
        vm.prank(who);
        reg.registerValidator{value: amount}(pk, SIG);
    }

    function _credit(bytes32 pk, uint256 amount) internal {
        vm.deal(minter, amount);
        vm.prank(minter);
        reg.creditReward{value: amount}(pk, amount);
    }

    function _equivocate(bytes32 pk) internal {
        vm.prank(bob);
        reg.submitEquivocation(pk, 12345, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG);
    }

    function test_slashedValidator_canClaimRewardsThatMaturedBeforeTheSlash() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether);
        vm.roll(block.number + reg.REWARD_RING() * reg.EPOCH()); // the 10 matures

        _equivocate(PK_A);
        assertTrue(reg.slashedPubkey(PK_A), "precondition: slashed");
        assertEq(reg.stakeOf(PK_A), 0, "bond fully forfeited");

        uint256 before = alice.balance;
        vm.prank(alice);
        try reg.claimRewards(PK_A) {}
        catch {
            assertTrue(false, "matured rewards must stay claimable after a slash");
        }
        assertEq(alice.balance - before, 10 ether, "staker receives exactly the matured rewards");

        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.NothingToWithdraw.selector);
        reg.claimRewards(PK_A);
    }

    function test_slashedValidator_unmaturedRewardsAreNotClaimable() public {
        _register(alice, PK_A, MIN);
        _credit(PK_A, 10 ether); // still inside the evidence window
        _equivocate(PK_A);

        vm.roll(block.number + reg.REWARD_RING() * reg.EPOCH());
        vm.prank(alice);
        vm.expectRevert(ValidatorRegistry.NothingToWithdraw.selector);
        reg.claimRewards(PK_A);
    }

    function test_slashingOldValidator_keepsStakersNewerBinding() public {
        _register(alice, PK_A, MIN);
        vm.prank(alice);
        reg.initiateUnbond(PK_A, MIN); // full exit, binding released
        assertEq(reg.pubkeyOfStaker(alice), bytes32(0));

        _register(alice, PK_B, MIN);
        assertEq(reg.pubkeyOfStaker(alice), PK_B, "precondition: new binding");

        _equivocate(PK_A); // old validator is still slashable while exiting
        assertTrue(reg.slashedPubkey(PK_A), "old validator slashed");
        assertEq(reg.pubkeyOfStaker(alice), PK_B, "slashing the old validator must not erase the new binding");
    }

    function test_slashingCurrentValidator_clearsItsBinding() public {
        _register(alice, PK_A, MIN);
        _equivocate(PK_A);
        assertEq(reg.pubkeyOfStaker(alice), bytes32(0), "the slashed validator's own binding is cleared");
    }
}
