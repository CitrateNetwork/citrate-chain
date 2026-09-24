// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {InferenceRouter} from "../../src/InferenceRouter.sol";

/// @title RmQ_C028 — InferenceRouter.withdrawPlatformFees sweeps stakes/escrow
/// @notice CHAIN-B-C028 (HELD/reroll). Pre-fix "fees" were computed as
///         `address(this).balance` minus provider balances only — never the
///         provider `stake` (>=100 SALT each) nor open-request escrow — so the
///         admin swept funds belonging to providers and requesters, bricking
///         `withdrawStake` / `cancelRequest` / `withdrawEarnings`. Fix: only
///         withdraw `accruedPlatformFees`.
contract RmQ_C028_InferenceRouter is Test {
    InferenceRouter internal router;
    address internal admin = address(this); // DEFAULT_ADMIN_ROLE
    address internal provider = makeAddr("provider");

    bytes32 internal constant MODEL = bytes32(uint256(0xB1));

    function setUp() public {
        router = new InferenceRouter(address(0xDEAD)); // modelRegistry unused here
        vm.deal(provider, 200 ether);
    }

    function _registerProvider() internal {
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(provider);
        router.registerProvider{value: 100 ether}("http://p", 1 ether, models);
    }

    /// GREEN: with no inferences completed there are no fees; the admin call
    /// reverts and the provider's stake is untouched and fully withdrawable.
    /// RED (pre-fix): `withdrawPlatformFees()` computes 100 ether "fees"
    /// (balance minus zero provider balances), transfers the provider's stake
    /// to the admin, and the provider's `withdrawStake` then reverts.
    function test_C028_withdrawPlatformFees_cannot_seize_provider_stake() public {
        _registerProvider();
        assertEq(address(router).balance, 100 ether, "stake held by router");
        assertEq(router.accruedPlatformFees(), 0, "no fees accrued yet");

        vm.prank(admin);
        vm.expectRevert("No fees to withdraw");
        router.withdrawPlatformFees();

        assertEq(address(router).balance, 100 ether, "stake preserved");

        // Provider can deactivate and reclaim its full stake.
        vm.prank(provider);
        router.updateProviderStatus(false);
        uint256 before = provider.balance;
        vm.prank(provider);
        router.withdrawStake(100 ether);
        assertEq(provider.balance, before + 100 ether, "provider recovered stake");
    }

    receive() external payable {}
}
