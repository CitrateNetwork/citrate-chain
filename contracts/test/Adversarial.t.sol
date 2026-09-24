// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AgentDecisionRegistry.sol";
import "../src/SpecRegistry.sol";
import "../src/lib/Governable.sol";
import "../src/InferenceRouter.sol";
import "../src/ModelRegistry.sol";
import "../src/interfaces/IModelRegistry.sol";

/// @title Adversarial test harness for agent trust, spec registry, and inference routing.
/// @notice Tests attack vectors: trust manipulation, sybil agents, spec registry abuse,
///         underpayment, timeout, and double-submit attacks.
contract AdversarialTest is Test {
    AgentDecisionRegistry public agentRegistry;
    SpecRegistry public specRegistry;
    InferenceRouter public router;
    ModelRegistry public modelRegistry;

    address public attacker = address(0xBAD);
    address public governor;
    address public provider = address(0xA11CE);
    address public user = address(0xBEEF);

    bytes32 constant AGENT_ATTACKER = keccak256("agent_attacker");
    bytes32 constant AGENT_SYBIL_A = keccak256("sybil_a");
    bytes32 constant AGENT_SYBIL_B = keccak256("sybil_b");
    bytes32 constant AGENT_SYBIL_C = keccak256("sybil_c");

    function setUp() public {
        governor = address(this);

        // Deploy agent and spec registries
        agentRegistry = new AgentDecisionRegistry(governor);
        agentRegistry.setAuthorizedRecorder(attacker, true);
        agentRegistry.setAuthorizedDisputer(attacker, true);
        specRegistry = new SpecRegistry(governor);

        // Deploy model registry and inference router
        modelRegistry = new ModelRegistry();
        router = new InferenceRouter(address(modelRegistry));
        router.setMinProviderStake(1 ether);

        // Fund test accounts
        vm.deal(attacker, 100 ether);
        vm.deal(provider, 100 ether);
        vm.deal(user, 100 ether);
    }

    // =====================================================================
    // 1. TRUST SCORE MANIPULATION
    // =====================================================================

    /// @notice Attacker rapidly disputes their own agent's decisions to
    ///         tank the trust score. Verify the score decreases correctly
    ///         and disputes are tracked.
    function test_dispute_bombing() public {
        // Register 10 decisions for the attacker's agent
        for (uint256 i = 0; i < 10; i++) {
            agentRegistry.registerDecision(
                AGENT_ATTACKER,
                "tool_action",
                keccak256(abi.encode(i))
            );
        }

        // Trust score should be 10 (10 decisions, 0 disputes)
        assertEq(agentRegistry.getTrustScore(AGENT_ATTACKER), 10);

        // Now dispute ALL 10 decisions (dispute bombing)
        for (uint256 i = 0; i < 10; i++) {
            agentRegistry.disputeDecision(i, "Spam dispute");
        }

        // Trust score = 10 decisions - (10 disputes * 2) = 10 - 20 = -10
        assertEq(agentRegistry.getTrustScore(AGENT_ATTACKER), -10);
        assertEq(agentRegistry.disputeCount(AGENT_ATTACKER), 10);
        assertEq(agentRegistry.getTrustTier(AGENT_ATTACKER), "Untrusted");
    }

    /// @notice Trust score is computed as int256(total) - int256(disputes * 2).
    ///         When disputes exceed decisions, the score goes negative but must
    ///         not underflow or wrap around.
    function test_trust_score_cannot_go_negative_underflow() public {
        // Register 1 decision, dispute it
        uint256 id = agentRegistry.registerDecision(
            AGENT_ATTACKER,
            "single_action",
            keccak256("params")
        );
        agentRegistry.disputeDecision(id, "bad");

        // Score = 1 - 2 = -1
        int256 score = agentRegistry.getTrustScore(AGENT_ATTACKER);
        assertEq(score, -1);
        assertTrue(score < 0, "Score must be negative");

        // Tier must still be Untrusted (no crash on negative)
        assertEq(agentRegistry.getTrustTier(AGENT_ATTACKER), "Untrusted");

        // Register 1000 more decisions, dispute them all
        // This tests that deeply negative scores don't cause issues
        for (uint256 i = 1; i <= 50; i++) {
            uint256 decId = agentRegistry.registerDecision(
                AGENT_ATTACKER,
                "action",
                keccak256(abi.encode(i))
            );
            agentRegistry.disputeDecision(decId, "bad");
        }

        // Total decisions: 51, disputes: 51 -> score = 51 - 102 = -51
        assertEq(agentRegistry.getTrustScore(AGENT_ATTACKER), -51);
        assertEq(agentRegistry.getTrustTier(AGENT_ATTACKER), "Untrusted");
    }

    /// @notice Attacker creates multiple agent IDs that are all controlled
    ///         by the same address. Each agent ID gets its own trust score,
    ///         so sybil agents bypass the trust penalty on the original.
    function test_sybil_agent_ids() public {
        vm.startPrank(attacker);

        // Register decisions under multiple identities
        agentRegistry.registerDecision(AGENT_SYBIL_A, "tool", keccak256("a"));
        agentRegistry.registerDecision(AGENT_SYBIL_B, "tool", keccak256("b"));
        agentRegistry.registerDecision(AGENT_SYBIL_C, "tool", keccak256("c"));

        // Each sybil agent has an independent trust score of 1
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_A), 1);
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_B), 1);
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_C), 1);

        // Dispute one agent's decision — only that agent is affected
        agentRegistry.disputeDecision(0, "bad sybil A");
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_A), -1);
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_B), 1); // unaffected
        assertEq(agentRegistry.getTrustScore(AGENT_SYBIL_C), 1); // unaffected

        vm.stopPrank();

        // IMPORTANT: This test documents that sybil isolation is a known
        // limitation. The contract does not link agent IDs to addresses,
        // so any address can register decisions under any agent ID.
    }

    /// @notice Cannot dispute the same decision twice.
    function test_double_dispute_reverts() public {
        uint256 id = agentRegistry.registerDecision(
            AGENT_ATTACKER,
            "tool",
            keccak256("params")
        );
        agentRegistry.disputeDecision(id, "first dispute");

        vm.expectRevert("Decision already disputed or resolved");
        agentRegistry.disputeDecision(id, "second dispute");
    }

    /// @notice Cannot dispute a decision that has already been resolved.
    function test_dispute_resolved_decision_reverts() public {
        uint256 id = agentRegistry.registerDecision(
            AGENT_ATTACKER,
            "tool",
            keccak256("params")
        );
        agentRegistry.disputeDecision(id, "evidence");
        agentRegistry.resolveDispute(id, true);

        vm.expectRevert("Decision already disputed or resolved");
        agentRegistry.disputeDecision(id, "late dispute");
    }

    /// @notice Cannot dispute a nonexistent decision ID.
    function test_dispute_nonexistent_reverts() public {
        vm.expectRevert("Decision does not exist");
        agentRegistry.disputeDecision(9999, "evidence");
    }

    // =====================================================================
    // 2. SPEC REGISTRY ATTACKS
    // =====================================================================

    /// @notice Non-governor tries to update a spec.
    function test_unauthorized_spec_update() public {
        specRegistry.registerSpec("contract_deploy", "QmValidCID123");

        vm.prank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        specRegistry.updateSpec("contract_deploy", "QmMaliciousCID");
    }

    /// @notice Non-governor tries to register a new spec.
    function test_unauthorized_spec_register() public {
        vm.prank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        specRegistry.registerSpec("malicious_domain", "QmBadCID");
    }

    /// @notice Non-governor tries to deactivate/reactivate specs.
    function test_unauthorized_spec_deactivate_reactivate() public {
        specRegistry.registerSpec("test_domain", "QmCID");

        vm.startPrank(attacker);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        specRegistry.deactivateSpec("test_domain");

        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        specRegistry.reactivateSpec("test_domain");
        vm.stopPrank();
    }

    /// @notice Toggle deactivate/reactivate rapidly to test state consistency.
    function test_spec_deactivate_reactivate_spam() public {
        specRegistry.registerSpec("toggle_domain", "QmCID1");

        // Rapidly toggle 50 times
        for (uint256 i = 0; i < 50; i++) {
            specRegistry.deactivateSpec("toggle_domain");
            assertFalse(specRegistry.hasActiveSpec("toggle_domain"));

            specRegistry.reactivateSpec("toggle_domain");
            assertTrue(specRegistry.hasActiveSpec("toggle_domain"));
        }

        // Final state must be active with the original CID
        (string memory cid, bool active, uint256 version) = specRegistry.getSpec("toggle_domain");
        assertEq(cid, "QmCID1");
        assertTrue(active);
        // Version stays at 1 because deactivate/reactivate don't bump version
        assertEq(version, 1);
    }

    /// @notice Registering a spec with empty CID must revert.
    function test_empty_cid_rejected() public {
        vm.expectRevert("CID cannot be empty");
        specRegistry.registerSpec("some_domain", "");
    }

    /// @notice Registering a spec with empty domain must revert.
    function test_empty_domain_rejected() public {
        vm.expectRevert("Domain cannot be empty");
        specRegistry.registerSpec("", "QmSomeCID");
    }

    /// @notice Updating a spec with empty CID must revert.
    function test_update_empty_cid_rejected() public {
        specRegistry.registerSpec("test", "QmOriginal");

        vm.expectRevert("CID cannot be empty");
        specRegistry.updateSpec("test", "");
    }

    /// @notice Updating a nonexistent domain must revert.
    function test_update_nonexistent_domain_rejected() public {
        vm.expectRevert("Domain not registered");
        specRegistry.updateSpec("nonexistent", "QmCID");
    }

    /// @notice Cannot register the same domain twice.
    function test_duplicate_domain_rejected() public {
        specRegistry.registerSpec("unique_domain", "QmCID1");

        vm.expectRevert("Domain already registered");
        specRegistry.registerSpec("unique_domain", "QmCID2");
    }

    /// @notice Transfer governance to zero address must revert.
    /// RM-L / WP-L1.1: SpecRegistry now uses the Governable two-step
    /// pattern; the legacy `transferGovernor` is gone, replaced with
    /// `transferGovernance` which emits `Governable_ZeroAddress`.
    function test_transfer_governor_to_zero_rejected() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        specRegistry.transferGovernance(address(0));
    }

    // =====================================================================
    // 3. INFERENCE ROUTING ATTACKS
    // =====================================================================

    /// @notice Requester pays less than the maxPrice they specify.
    function test_underpay_inference() public {
        _setupProvider();

        bytes32 model = keccak256("model-underpay");

        vm.prank(user);
        vm.expectRevert("Insufficient payment");
        // msg.value (0.01 ether) < maxPrice (1 ether)
        router.requestInference{value: 0.01 ether}(model, hex"DA7A", 1 ether);
    }

    /// @notice Requester sends zero payment.
    function test_zero_payment_inference() public {
        _setupProvider();

        bytes32 model = keccak256("model-zeropay");

        vm.prank(user);
        vm.expectRevert("Insufficient payment");
        router.requestInference{value: 0}(model, hex"DA7A", 0.5 ether);
    }

    /// @notice Provider never responds — request stays in Processing state.
    ///         Requester cannot cancel a Processing request.
    function test_provider_timeout_handling() public {
        bytes32 model = keccak256("model-timeout-adv");
        _registerProvider(provider, model, 0.1 ether);

        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);

        // Fast-forward 1 hour — provider hasn't responded
        vm.warp(block.timestamp + 3600);

        // Requester cannot cancel (status is Processing, not Pending)
        vm.prank(user);
        vm.expectRevert("Cannot cancel");
        router.cancelRequest(reqId);

        // Request is still stuck at Processing
        ( , , InferenceRouter.RequestStatus status, , ) = router.getRequest(reqId);
        assertEq(uint(status), uint(InferenceRouter.RequestStatus.Processing));
    }

    /// @notice Provider submits a result for the same request twice.
    ///         Second submission must revert.
    function test_double_submit_result() public {
        bytes32 model = keccak256("model-double-submit");
        _registerProvider(provider, model, 0.1 ether);

        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);

        // First completion succeeds
        vm.prank(provider);
        router.completeInference(reqId, hex"AA01BB02");

        // Second completion reverts (status is Completed, not Processing)
        vm.prank(provider);
        vm.expectRevert("Invalid status");
        router.completeInference(reqId, hex"CC03DD04");
    }

    /// @notice Non-assigned provider tries to complete a request.
    function test_unassigned_provider_cannot_complete() public {
        bytes32 model = keccak256("model-unassigned");
        _registerProvider(provider, model, 0.1 ether);

        address otherProvider = address(0x07AE);
        vm.deal(otherProvider, 10 ether);
        _registerProviderFor(otherProvider, keccak256("other-model"), 0.1 ether);

        vm.prank(user);
        uint256 reqId = router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);

        // Other provider tries to complete — should revert
        vm.prank(otherProvider);
        vm.expectRevert("Not assigned provider");
        router.completeInference(reqId, hex"FA4E");
    }

    /// @notice Provider with insufficient stake cannot register.
    function test_provider_insufficient_stake() public {
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-lowstake");

        address lowStakeProvider = address(0xD00D);
        vm.deal(lowStakeProvider, 0.5 ether);

        vm.prank(lowStakeProvider);
        vm.expectRevert("Insufficient stake");
        router.registerProvider{value: 0.5 ether}("http://x", 0.1 ether, models);
    }

    /// @notice Provider with empty endpoint cannot register.
    function test_provider_empty_endpoint() public {
        bytes32[] memory models = new bytes32[](1);
        models[0] = keccak256("model-noep");

        vm.prank(provider);
        vm.expectRevert("Endpoint required");
        router.registerProvider{value: 2 ether}("", 0.1 ether, models);
    }

    /// @notice Provider with no supported models cannot register.
    function test_provider_no_models() public {
        bytes32[] memory models = new bytes32[](0);

        vm.prank(provider);
        vm.expectRevert("Must support at least one model");
        router.registerProvider{value: 2 ether}("http://p", 0.1 ether, models);
    }

    /// @notice Request inference on a model with no providers — must revert.
    function test_no_provider_available() public {
        bytes32 model = keccak256("model-no-provider");

        vm.prank(user);
        vm.expectRevert("No available provider");
        router.requestInference{value: 1 ether}(model, hex"DA7A", 1 ether);
    }

    /// @notice Provider cannot withdraw stake while active.
    function test_withdraw_stake_while_active_reverts() public {
        bytes32 model = keccak256("model-withdraw-active");
        _registerProvider(provider, model, 0.1 ether);

        vm.prank(provider);
        vm.expectRevert("Must deactivate first");
        router.withdrawStake(1 ether);
    }

    /// @notice Provider cannot double-register.
    function test_double_registration_reverts() public {
        bytes32 model = keccak256("model-doublereg");
        _registerProvider(provider, model, 0.1 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = model;

        vm.prank(provider);
        vm.expectRevert("Provider already registered");
        router.registerProvider{value: 2 ether}("http://p2", 0.2 ether, models);
    }

    /// @notice Non-admin cannot set platform fee.
    function test_unauthorized_set_platform_fee() public {
        vm.prank(attacker);
        vm.expectRevert();
        router.setPlatformFee(999);
    }

    /// @notice Platform fee cannot exceed 10%.
    function test_platform_fee_too_high() public {
        vm.expectRevert("Fee too high");
        router.setPlatformFee(1001); // 10.01%
    }

    /// @notice Provider with no earnings cannot withdraw.
    function test_withdraw_no_earnings() public {
        bytes32 model = keccak256("model-noearnings");
        _registerProvider(provider, model, 0.1 ether);

        vm.prank(provider);
        vm.expectRevert("No earnings");
        router.withdrawEarnings();
    }

    // =====================================================================
    // HELPERS
    // =====================================================================

    function _setupProvider() internal {
        bytes32 model = keccak256("model-underpay");
        _registerProvider(provider, model, 0.1 ether);

        bytes32 model2 = keccak256("model-zeropay");
        _registerProviderFor(address(0xA11C2), model2, 0.1 ether);
    }

    function _registerProvider(address p, bytes32 model, uint256 minPrice) internal {
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;
        vm.prank(p);
        router.registerProvider{value: 2 ether}(
            string(abi.encodePacked("http://", vm.toString(p))),
            minPrice,
            models
        );
    }

    function _registerProviderFor(address p, bytes32 model, uint256 minPrice) internal {
        vm.deal(p, 10 ether);
        bytes32[] memory models = new bytes32[](1);
        models[0] = model;
        vm.prank(p);
        router.registerProvider{value: 2 ether}(
            string(abi.encodePacked("http://", vm.toString(p))),
            minPrice,
            models
        );
    }
}
