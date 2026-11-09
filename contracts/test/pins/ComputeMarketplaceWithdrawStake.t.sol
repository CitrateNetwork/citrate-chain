// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";

/// `withdrawStake` lets an idle provider exit, but a partial withdrawal may
/// not leave a registered provider below the minimum stake.
contract ComputeMarketplaceWithdrawStakeTest is Test {
    ComputeMarketplace internal marketplace;
    address internal constant PROVIDER = address(0xBBB1);

    function setUp() public {
        ComputeVerifier verifier = new ComputeVerifier(address(1), address(this));
        marketplace = new ComputeMarketplace(address(verifier), address(0x77EA5), address(this));
        verifier.setMarketplace(address(marketplace));
        vm.deal(PROVIDER, 5000 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("m");
        uint256 min = marketplace.MIN_PROVIDER_STAKE();
        vm.prank(PROVIDER);
        marketplace.registerProvider{value: min}(models);
        vm.prank(PROVIDER);
        marketplace.addStake{value: min / 2}();
    }

    function test_partialWithdrawBelowMinimumReverts() public {
        uint256 min = marketplace.MIN_PROVIDER_STAKE();
        vm.prank(PROVIDER);
        vm.expectRevert("ComputeMarketplace: below minimum");
        marketplace.withdrawStake(min / 2 + 1);
        assertEq(marketplace.getProvider(PROVIDER).stake, min + min / 2, "stake untouched");
        assertTrue(marketplace.getProvider(PROVIDER).isRegistered);
    }

    function test_partialWithdrawDownToMinimumSucceeds() public {
        uint256 min = marketplace.MIN_PROVIDER_STAKE();
        uint256 bal = PROVIDER.balance;
        vm.prank(PROVIDER);
        marketplace.withdrawStake(min / 2);
        assertEq(marketplace.getProvider(PROVIDER).stake, min);
        assertEq(PROVIDER.balance, bal + min / 2);
        assertTrue(marketplace.getProvider(PROVIDER).isRegistered);
    }

    function test_fullWithdrawDeregisters() public {
        uint256 all = marketplace.getProvider(PROVIDER).stake;
        vm.prank(PROVIDER);
        marketplace.withdrawStake(all);
        assertEq(marketplace.getProvider(PROVIDER).stake, 0);
        assertFalse(marketplace.getProvider(PROVIDER).isRegistered, "full exit deregisters");
        assertEq(address(marketplace).balance, 0);
    }
}
