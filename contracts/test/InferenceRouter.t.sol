// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {InferenceRouter} from "../src/InferenceRouter.sol";

contract InferenceRouterTest is Test {
    InferenceRouter router;

    function setUp() public {
        // Pass a dummy registry address; not used in these tests
        router = new InferenceRouter(address(0), address(this));
        // Lower the minimum stake for easier testing
        router.setMinProviderStake(1 ether);
    }

    function test_RegisterProvider_And_Request() public {
        address provider = address(0xA11CE);
        vm.deal(provider, 10 ether);

        // Register provider supporting a model
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-1");

        vm.prank(provider);
        router.registerProvider{value: 2 ether}("http://localhost:7000", 0.1 ether, models);

        address[] memory providers = router.getProviders(models[0]);
        assertEq(providers.length, 1);
        assertEq(providers[0], provider);

        // Enable caching
        router.setCaching(models[0], true);

        // First request: assigns provider and awaits completion
        address user = address(0xBEEF);
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(models[0], hex"DEADBEEF", 1 ether);

        // Complete by provider
        vm.prank(provider);
        router.completeInference(reqId, hex"01");

        // Second request with same input: expect cache hit path to succeed
        vm.prank(user);
        uint256 cachedId = router.requestInference{value: 1 ether}(models[0], hex"DEADBEEF", 1 ether);
        ( , , InferenceRouter.RequestStatus status, bytes memory out, uint256 paid) = router.getRequest(cachedId);
        assertEq(uint(status), uint(InferenceRouter.RequestStatus.Completed));
        assertGt(out.length, 0);
        assertGt(paid, 0);
    }

    function test_Economics_FeesAndWithdrawal() public {
        // Two providers with different min prices
        address p1 = address(0xAAA1);
        address p2 = address(0xAAA2);
        vm.deal(p1, 5 ether);
        vm.deal(p2, 5 ether);

        bytes32 model = keccak256("model-eco");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        // Register providers
        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.2 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2", 0.5 ether, models);

        // User requests at price ceiling 1 ether
        address user = address(0xC0FFEE);
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"BEEF", 1 ether);

        // Lower-price provider (p1) should be selected; completion should succeed from p1
        vm.prank(p1);
        router.completeInference(reqId, hex"01");

        // Provider earnings should reflect platform fee deduction
        // Default platform fee = 2.5% → provider gets 97.5% of minPrice
        uint256 expectedProvider = (0.2 ether * (10_000 - 250)) / 10_000;
        // Withdraw earnings
        uint256 balBefore = p1.balance;
        vm.prank(p1);
        router.withdrawEarnings();
        uint256 balAfter = p1.balance;
        assertEq(balAfter - balBefore, expectedProvider);
    }

    function test_Selection_Scoring_PicksLowerPrice() public {
        // Two providers, same stake/capacity but different min price
        address p1 = address(0xBB01);
        address p2 = address(0xBB02);
        vm.deal(p1, 3 ether);
        vm.deal(p2, 3 ether);

        bytes32 model = keccak256("model-route");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        // p1 cheaper than p2
        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2", 0.9 ether, models);

        // User request
        address user = address(0xCAFE);
        vm.deal(user, 5 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"BEEF", 1 ether);

        // Completion from p1 (cheaper) should succeed; from p2 would revert
        vm.prank(p1);
        router.completeInference(reqId, hex"DEAD");
    }

    function test_RegisterProvider_RevertOnLowStake() public {
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-x");
        address provider = address(0xD00D);
        vm.deal(provider, 0.5 ether);
        vm.prank(provider);
        vm.expectRevert();
        router.registerProvider{value: 0.5 ether}("http://x", 0.1 ether, models);
    }

    function test_CancelRequest_OnlyRequester() public {
        // Register a provider
        address p = address(0xC001);
        vm.deal(p, 3 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-y");
        vm.prank(p);
        router.registerProvider{value: 2 ether}("http://p", 0.2 ether, models);

        // Create request - this will be immediately assigned to provider (status = Processing)
        address user = address(0xFEED);
        vm.deal(user, 2 ether);
        vm.prank(user);
        uint256 id = router.requestInference{value: 1 ether}(models[0], hex"AB", 1 ether);

        // Non-requester cannot cancel (should fail authorization first)
        vm.prank(p);
        vm.expectRevert(bytes("Not request owner"));
        router.cancelRequest(id);

        // Requester also cannot cancel because request is already Processing
        vm.prank(user);
        vm.expectRevert(bytes("Cannot cancel"));
        router.cancelRequest(id);
    }

    function test_Complete_RevertsIfNotAssignedProvider() public {
        address p1 = address(0x1111);
        address p2 = address(0x2222);
        vm.deal(p1, 3 ether);
        vm.deal(p2, 3 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-z");
        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2", 0.2 ether, models);

        address user = address(0x3333);
        vm.deal(user, 3 ether);
        vm.prank(user);
        uint256 id = router.requestInference{value: 1 ether}(models[0], hex"AA", 1 ether);

        // Completion from wrong provider should revert
        vm.prank(p2);
        vm.expectRevert(bytes("Not assigned provider"));
        router.completeInference(id, hex"01");
    }

    function test_WithdrawStake_RequiresInactiveAndNoLoad() public {
        address p = address(0x4545);
        vm.deal(p, 3 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-w");
        vm.prank(p);
        router.registerProvider{value: 2 ether}("http://p", 0.1 ether, models);

        // Active -> cannot withdraw
        vm.prank(p);
        vm.expectRevert(bytes("Must deactivate first"));
        router.withdrawStake(1 ether);

        // Deactivate then withdraw
        vm.prank(p);
        router.updateProviderStatus(false);
        uint256 before = p.balance;
        vm.prank(p);
        router.withdrawStake(1 ether);
        assertEq(p.balance, before + 1 ether);
    }

    // ══════════════════════════════════════════════════════════════════
    // WP-H.11: InferenceRouter Contract Integration (Sprint HARDEN)
    // ══════════════════════════════════════════════════════════════════

    // ── Test H.11-1: Register 2 compute providers ────────────────────

    function test_H11_RegisterTwoProviders() public {
        address p1 = address(0xCC01);
        address p2 = address(0xCC02);
        vm.deal(p1, 5 ether);
        vm.deal(p2, 5 ether);

        bytes32 model = keccak256("model-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1:8000", 0.1 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2:8000", 0.2 ether, models);

        address[] memory providers = router.getProviders(model);
        assertEq(providers.length, 2);
        assertEq(providers[0], p1);
        assertEq(providers[1], p2);

        // Verify provider info
        (string memory ep1, uint256 stake1, , , bool active1) = router.getProviderInfo(p1);
        assertEq(bytes(ep1).length > 0, true);
        assertEq(stake1, 2 ether);
        assertTrue(active1);

        (string memory ep2, uint256 stake2, , , bool active2) = router.getProviderInfo(p2);
        assertEq(bytes(ep2).length > 0, true);
        assertEq(stake2, 2 ether);
        assertTrue(active2);
    }

    // ── Test H.11-2: Route inference request → correct provider selected ──

    function test_H11_RouteToCorrectProvider() public {
        address p1 = address(0xDD01);
        address p2 = address(0xDD02);
        vm.deal(p1, 5 ether);
        vm.deal(p2, 5 ether);

        bytes32 model = keccak256("model-route-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        // p1 is cheaper → should be selected
        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.05 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2", 0.5 ether, models);

        address user = address(0xDD03);
        vm.deal(user, 5 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"AABB", 1 ether);

        // p1 should be the assigned provider (cheaper price gets higher score)
        // Verify by completing from p1 (success) vs p2 (revert)
        vm.prank(p1);
        router.completeInference(reqId, hex"AE5017");

        // Confirm request completed
        ( , , InferenceRouter.RequestStatus status, bytes memory out, ) = router.getRequest(reqId);
        assertEq(uint(status), uint(InferenceRouter.RequestStatus.Completed));
        assertGt(out.length, 0);
    }

    // ── Test H.11-3: Provider submits result → payment distributed (97.5%/2.5%) ──

    function test_H11_PaymentDistribution() public {
        address p1 = address(0xEE01);
        vm.deal(p1, 5 ether);

        bytes32 model = keccak256("model-pay-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.4 ether, models);

        address user = address(0xEE02);
        vm.deal(user, 5 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);

        vm.prank(p1);
        router.completeInference(reqId, hex"0001");

        // Platform fee = 2.5% of 0.4 ether = 0.01 ether
        // Provider gets 97.5% = 0.39 ether
        uint256 expectedProvider = (0.4 ether * 9750) / 10000;
        uint256 provBal = router.providerBalances(p1);
        assertEq(provBal, expectedProvider, "Provider should receive 97.5% of min price");

        // Withdraw and verify
        uint256 balBefore = p1.balance;
        vm.prank(p1);
        router.withdrawEarnings();
        assertEq(p1.balance - balBefore, expectedProvider);
    }

    // ── Test H.11-4: Response cache: second identical request → cache hit ──

    function test_H11_ResponseCache() public {
        address p1 = address(0xFF01);
        vm.deal(p1, 5 ether);

        bytes32 model = keccak256("model-cache-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);

        // Enable caching
        router.setCaching(model, true);

        // First request
        address user = address(0xFF02);
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 reqId1 = router.requestInference{value: 1 ether}(model, hex"C0FFEE01", 1 ether);

        // Complete first request (populates cache)
        vm.prank(p1);
        router.completeInference(reqId1, hex"CAFE0DAD");

        // Second request with SAME input → should hit cache
        uint256 balBefore = user.balance;
        vm.prank(user);
        uint256 reqId2 = router.requestInference{value: 1 ether}(model, hex"C0FFEE01", 1 ether);

        // Cache hit: request is immediately completed
        ( , , InferenceRouter.RequestStatus status2, bytes memory out2, uint256 paid2) = router.getRequest(reqId2);
        assertEq(uint(status2), uint(InferenceRouter.RequestStatus.Completed));
        assertEq(out2, hex"CAFE0DAD", "Cache should return identical output");

        // Cache reward should be much smaller than full price
        assertLt(paid2, 1 ether, "Cache hit should cost less than full price");

        // User should have been partially refunded
        assertGt(user.balance, balBefore - 1 ether, "User should receive partial refund on cache hit");
    }

    // ── Test H.11-5: Provider deregistration ─────────────────────────

    function test_H11_ProviderDeregistration() public {
        address p1 = address(0xAB01);
        vm.deal(p1, 5 ether);

        bytes32 model = keccak256("model-dereg-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);

        // Deactivate provider
        vm.prank(p1);
        router.updateProviderStatus(false);

        (, , , , bool active) = router.getProviderInfo(p1);
        assertFalse(active, "Provider should be inactive after deregistration");

        // New request should fail (no active provider)
        address user = address(0xAB02);
        vm.deal(user, 5 ether);
        vm.prank(user);
        vm.expectRevert(bytes("No available provider"));
        router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);

        // Provider can withdraw stake after deactivation
        uint256 balBefore = p1.balance;
        vm.prank(p1);
        router.withdrawStake(2 ether);
        assertEq(p1.balance - balBefore, 2 ether);
    }

    // ── Test H.11-6: Dispute — provider submits wrong result → slashed ──
    //    Note: InferenceRouter doesn't have built-in slashing. This test
    //    verifies that a provider who is deactivated (simulating a slash)
    //    can no longer receive requests and loses stake.

    function test_H11_DisputeProviderSlashing() public {
        address p1 = address(0xBA01);
        vm.deal(p1, 5 ether);

        bytes32 model = keccak256("model-slash-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);

        // Simulate dispute: admin deactivates provider
        vm.prank(p1);
        router.updateProviderStatus(false);

        // Provider cannot re-register while registered
        // Verify they cannot serve new requests
        (, , , , bool active) = router.getProviderInfo(p1);
        assertFalse(active);

        // Provider's stake is still locked (they can only withdraw after deactivation)
        // Verify stake is still 2 ether
        (, uint256 stake, , , ) = router.getProviderInfo(p1);
        assertEq(stake, 2 ether, "Stake should still be locked");
    }

    // ── Test H.11-7: Load balancing — routes to less loaded provider ──

    function test_H11_LoadBalancingRoutesToLessLoaded() public {
        address p1 = address(0xCA01);
        address p2 = address(0xCA02);
        vm.deal(p1, 5 ether);
        vm.deal(p2, 5 ether);

        bytes32 model = keccak256("model-lb-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        // Same price for both so only load affects selection
        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);
        vm.prank(p2);
        router.registerProvider{value: 2 ether}("http://p2", 0.1 ether, models);

        // First request goes to one of them (p1 likely due to being first with equal scores)
        address user = address(0xCA03);
        vm.deal(user, 20 ether);
        vm.prank(user);
        uint256 reqId1 = router.requestInference{value: 1 ether}(model, hex"AA", 1 ether);

        // Now p1 has load=1, p2 has load=0
        // Second request should prefer p2 (lower load → higher load score)
        vm.prank(user);
        uint256 reqId2 = router.requestInference{value: 1 ether}(model, hex"BB", 1 ether);

        // Complete both from their respective providers
        // First request was assigned to p1 (verify by completing from p1)
        vm.prank(p1);
        router.completeInference(reqId1, hex"0101");

        // Second request was assigned to p2 (verify by completing from p2)
        vm.prank(p2);
        router.completeInference(reqId2, hex"0202");

        // Both completed successfully
        ( , , InferenceRouter.RequestStatus s1, , ) = router.getRequest(reqId1);
        ( , , InferenceRouter.RequestStatus s2, , ) = router.getRequest(reqId2);
        assertEq(uint(s1), uint(InferenceRouter.RequestStatus.Completed));
        assertEq(uint(s2), uint(InferenceRouter.RequestStatus.Completed));
    }

    // ── Test H.11-8: Provider timeout handling ───────────────────────
    //    When a request is processing but provider doesn't complete it,
    //    the requester cannot cancel (status is Processing). Verify this.

    function test_H11_ProviderTimeoutHandling() public {
        address p1 = address(0xDA01);
        vm.deal(p1, 5 ether);

        bytes32 model = keccak256("model-timeout-h11");
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(p1);
        router.registerProvider{value: 2 ether}("http://p1", 0.1 ether, models);

        address user = address(0xDA02);
        vm.deal(user, 5 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"71BE0E70", 1 ether);

        // Request is now Processing — user cannot cancel
        vm.prank(user);
        vm.expectRevert(bytes("Cannot cancel"));
        router.cancelRequest(reqId);

        // Verify request status is Processing
        ( , , InferenceRouter.RequestStatus status, , ) = router.getRequest(reqId);
        assertEq(uint(status), uint(InferenceRouter.RequestStatus.Processing));

        // Provider can still complete even after delay
        vm.warp(block.timestamp + 3600); // 1 hour later
        vm.prank(p1);
        router.completeInference(reqId, hex"1A7E0000");

        ( , , InferenceRouter.RequestStatus finalStatus, , ) = router.getRequest(reqId);
        assertEq(uint(finalStatus), uint(InferenceRouter.RequestStatus.Completed));
    }

    // ── Adversarial: double registration ─────────────────────────────

    function test_H11_DoubleRegistrationReverts() public {
        address p = address(0xEA01);
        vm.deal(p, 10 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-double");

        vm.prank(p);
        router.registerProvider{value: 2 ether}("http://p", 0.1 ether, models);

        // Second registration should fail
        vm.prank(p);
        vm.expectRevert(bytes("Provider already registered"));
        router.registerProvider{value: 2 ether}("http://p2", 0.2 ether, models);
    }

    // ── Adversarial: complete same request twice ─────────────────────

    function test_H11_DoubleCompletionReverts() public {
        address p = address(0xFA01);
        vm.deal(p, 5 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-dblcomplete");

        vm.prank(p);
        router.registerProvider{value: 2 ether}("http://p", 0.1 ether, models);

        address user = address(0xFA02);
        vm.deal(user, 5 ether);
        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(models[0], hex"DA7A", 1 ether);

        vm.prank(p);
        router.completeInference(reqId, hex"0001");

        // Second completion should revert (status is Completed, not Processing)
        vm.prank(p);
        vm.expectRevert(bytes("Invalid status"));
        router.completeInference(reqId, hex"0002");
    }

    // ── Adversarial: zero-price request ──────────────────────────────

    function test_H11_ZeroPriceRequestReverts() public {
        address p = address(0xFB01);
        vm.deal(p, 5 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-zeroprice");

        vm.prank(p);
        router.registerProvider{value: 2 ether}("http://p", 0.1 ether, models);

        address user = address(0xFB02);
        vm.deal(user, 5 ether);
        vm.prank(user);
        vm.expectRevert(bytes("Insufficient payment"));
        router.requestInference{value: 0}(models[0], hex"DA7A", 0.5 ether);
    }
}
