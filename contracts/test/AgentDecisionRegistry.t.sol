// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AgentDecisionRegistry.sol";

contract AgentDecisionRegistryTest is Test {
    AgentDecisionRegistry public registry;
    bytes32 constant AGENT_1 = keccak256("agent_1");
    bytes32 constant AGENT_2 = keccak256("agent_2");
    address constant RECORDER = address(0xA11CE);
    address constant DISPUTER = address(0xB0B);
    address constant ATTACKER = address(0xBAD);

    function setUp() public {
        registry = new AgentDecisionRegistry(address(this));
    }

    // ── Registration ────────────────────────────────────────────────

    function test_registerDecision() public {
        uint256 id = registry.registerDecision(AGENT_1, "deploy_contract", keccak256("params"));
        assertEq(id, 0);
        assertEq(registry.decisionCount(), 1);
    }

    function test_registerMultipleDecisions() public {
        registry.registerDecision(AGENT_1, "deploy_contract", keccak256("p1"));
        registry.registerDecision(AGENT_1, "transfer_tokens", keccak256("p2"));
        registry.registerDecision(AGENT_2, "execute_contract", keccak256("p3"));

        assertEq(registry.decisionCount(), 3);
        assertEq(registry.getDecisionCount(AGENT_1), 2);
        assertEq(registry.getDecisionCount(AGENT_2), 1);
    }

    function test_decisionFieldsRecordedCorrectly() public {
        bytes32 paramsHash = keccak256("test_params");
        uint256 id = registry.registerDecision(AGENT_1, "deploy_contract", paramsHash);

        (bytes32 agentId, string memory toolName, bytes32 storedHash,
         uint256 blockNum, , address executor, , ) = registry.decisions(id);

        assertEq(agentId, AGENT_1);
        assertEq(toolName, "deploy_contract");
        assertEq(storedHash, paramsHash);
        assertEq(blockNum, block.number);
        assertEq(executor, address(this));
    }

    function test_decisionHistoryTracked() public {
        registry.registerDecision(AGENT_1, "tool_a", keccak256("a"));
        registry.registerDecision(AGENT_1, "tool_b", keccak256("b"));
        registry.registerDecision(AGENT_1, "tool_c", keccak256("c"));

        uint256[] memory history = registry.getDecisionHistory(AGENT_1);
        assertEq(history.length, 3);
        assertEq(history[0], 0);
        assertEq(history[1], 1);
        assertEq(history[2], 2);
    }

    function test_emptyHistoryForNewAgent() public view {
        uint256[] memory history = registry.getDecisionHistory(keccak256("unknown"));
        assertEq(history.length, 0);
    }

    // ── Authorization ────────────────────────────────────────────────

    function test_k1_2_constructor_rejects_zero_governance() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        new AgentDecisionRegistry(address(0));
    }

    function test_k1_2_initial_governance_is_default_recorder_and_disputer() public view {
        assertEq(registry.governance(), address(this));
        assertTrue(registry.authorizedRecorders(address(this)));
        assertTrue(registry.authorizedDisputers(address(this)));
    }

    function test_k1_2_non_recorder_cannot_register_decision() public {
        vm.prank(ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(AgentDecisionRegistry.NotAuthorizedRecorder.selector, ATTACKER)
        );
        registry.registerDecision(AGENT_1, "tool", keccak256("p"));
    }

    function test_k1_2_governance_can_authorize_recorder() public {
        registry.setAuthorizedRecorder(RECORDER, true);
        vm.prank(RECORDER);
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));

        assertEq(id, 0);
        (, , , , , address executor, , ) = registry.decisions(id);
        assertEq(executor, RECORDER);
    }

    function test_k1_2_non_governance_cannot_authorize_recorder() public {
        vm.prank(ATTACKER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        registry.setAuthorizedRecorder(RECORDER, true);
    }

    function test_k1_2_non_disputer_cannot_dispute_decision() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));

        vm.prank(ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(AgentDecisionRegistry.NotAuthorizedDisputer.selector, ATTACKER)
        );
        registry.disputeDecision(id, "fake evidence");
    }

    function test_k1_2_governance_can_authorize_disputer() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        registry.setAuthorizedDisputer(DISPUTER, true);

        vm.prank(DISPUTER);
        registry.disputeDecision(id, "real evidence");

        assertEq(registry.disputeCount(AGENT_1), 1);
    }

    function test_k1_2_non_governance_cannot_resolve_dispute() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        registry.disputeDecision(id, "evidence");

        vm.prank(ATTACKER);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        registry.resolveDispute(id, true);
    }

    function test_k1_2_governance_transfer_is_two_step() public {
        registry.transferGovernance(RECORDER);
        assertEq(registry.governance(), address(this));
        assertEq(registry.pendingGovernance(), RECORDER);

        vm.prank(RECORDER);
        registry.acceptGovernance();

        assertEq(registry.governance(), RECORDER);
        assertEq(registry.pendingGovernance(), address(0));
    }

    // ── Disputes ────────────────────────────────────────────────────

    function test_disputeDecision() public {
        uint256 id = registry.registerDecision(AGENT_1, "transfer_tokens", keccak256("p"));
        registry.disputeDecision(id, "Sent to wrong address");

        assertEq(uint256(registry.getDisputeStatus(id)), uint256(AgentDecisionRegistry.DecisionStatus.Disputed));
        assertEq(registry.disputeCount(AGENT_1), 1);
    }

    function test_cannotDisputeTwice() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        registry.disputeDecision(id, "Evidence 1");

        vm.expectRevert("Decision already disputed or resolved");
        registry.disputeDecision(id, "Evidence 2");
    }

    function test_cannotDisputeNonexistent() public {
        vm.expectRevert("Decision does not exist");
        registry.disputeDecision(999, "Evidence");
    }

    // ── Dispute Resolution ──────────────────────────────────────────

    function test_resolveDisputeUpheld() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        registry.disputeDecision(id, "Bad decision");
        registry.resolveDispute(id, true);

        assertEq(uint256(registry.getDisputeStatus(id)), uint256(AgentDecisionRegistry.DecisionStatus.Resolved));
        // Dispute count stays (upheld = agent was wrong)
        assertEq(registry.disputeCount(AGENT_1), 1);
    }

    function test_resolveDisputeNotUpheld() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        registry.disputeDecision(id, "False alarm");
        registry.resolveDispute(id, false);

        // Dispute count decremented (not upheld = agent was right)
        assertEq(registry.disputeCount(AGENT_1), 0);
    }

    function test_cannotResolveUndisputed() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        vm.expectRevert("Decision not disputed");
        registry.resolveDispute(id, true);
    }

    // ── Trust Score ─────────────────────────────────────────────────

    function test_trustScorePositive() public {
        registry.registerDecision(AGENT_1, "tool_a", keccak256("a"));
        registry.registerDecision(AGENT_1, "tool_b", keccak256("b"));
        registry.registerDecision(AGENT_1, "tool_c", keccak256("c"));

        // 3 decisions, 0 disputes → score = 3
        assertEq(registry.getTrustScore(AGENT_1), 3);
    }

    function test_trustScoreWithDisputes() public {
        registry.registerDecision(AGENT_1, "tool_a", keccak256("a"));
        registry.registerDecision(AGENT_1, "tool_b", keccak256("b"));
        registry.registerDecision(AGENT_1, "tool_c", keccak256("c"));

        uint256 id = registry.registerDecision(AGENT_1, "tool_d", keccak256("d"));
        registry.disputeDecision(id, "Bad call");

        // 4 decisions, 1 dispute → score = 4 - 2 = 2
        assertEq(registry.getTrustScore(AGENT_1), 2);
    }

    function test_trustScoreNegative() public {
        uint256 id0 = registry.registerDecision(AGENT_1, "tool_a", keccak256("a"));
        registry.disputeDecision(id0, "Bad");
        uint256 id1 = registry.registerDecision(AGENT_1, "tool_b", keccak256("b"));
        registry.disputeDecision(id1, "Also bad");

        // 2 decisions, 2 disputes → score = 2 - 4 = -2
        assertEq(registry.getTrustScore(AGENT_1), -2);
    }

    function test_trustScoreZeroForNewAgent() public view {
        assertEq(registry.getTrustScore(keccak256("new_agent")), 0);
    }

    // ── Events ──────────────────────────────────────────────────────

    function test_emitsDecisionRecorded() public {
        vm.expectEmit(true, true, false, true);
        emit AgentDecisionRegistry.DecisionRecorded(0, AGENT_1, "tool", keccak256("p"), block.number);
        registry.registerDecision(AGENT_1, "tool", keccak256("p"));
    }

    function test_emitsDecisionDisputed() public {
        uint256 id = registry.registerDecision(AGENT_1, "tool", keccak256("p"));
        vm.expectEmit(true, true, false, true);
        emit AgentDecisionRegistry.DecisionDisputed(id, AGENT_1, address(this), "evidence");
        registry.disputeDecision(id, "evidence");
    }

    // ── WP-H.16: Trust Tiers ──────────────────────────────────────────

    function test_newAgentStartsAtUntrusted() public view {
        // New agent has 0 decisions, 0 disputes → score 0 → Untrusted
        assertEq(registry.getTrustScore(keccak256("new_agent")), 0);
        assertEq(registry.getTrustTier(keccak256("new_agent")), "Untrusted");
    }

    function test_20SuccessfulDecisionsStillUntrusted() public {
        bytes32 agent = keccak256("agent_20");
        for (uint256 i = 0; i < 20; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }

        // 20 decisions, 0 disputes → score = 20 → still Untrusted (<100)
        assertEq(registry.getTrustScore(agent), 20);
        assertEq(registry.getTrustTier(agent), "Untrusted");
    }

    function test_100SuccessfulDecisionsReachesStandard() public {
        bytes32 agent = keccak256("agent_100");
        for (uint256 i = 0; i < 100; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }

        // 100 decisions, 0 disputes → score = 100 → Standard
        assertEq(registry.getTrustScore(agent), 100);
        assertEq(registry.getTrustTier(agent), "Standard");
    }

    function test_500SuccessfulDecisionsReachesTrusted() public {
        bytes32 agent = keccak256("agent_500");
        for (uint256 i = 0; i < 500; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }

        // 500 decisions, 0 disputes → score = 500 → Trusted
        assertEq(registry.getTrustScore(agent), 500);
        assertEq(registry.getTrustTier(agent), "Trusted");
    }

    function test_disputeDropsTrustBackToUntrusted() public {
        bytes32 agent = keccak256("agent_drop");

        // Register 102 decisions → score 102 → Standard
        for (uint256 i = 0; i < 102; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }
        assertEq(registry.getTrustScore(agent), 102);
        assertEq(registry.getTrustTier(agent), "Standard");

        // Dispute 2 decisions → disputeCount = 2, score = 102 - 4 = 98 → Untrusted
        registry.disputeDecision(0, "bad1");
        registry.disputeDecision(1, "bad2");

        assertEq(registry.disputeCount(agent), 2);
        assertEq(registry.getTrustScore(agent), 98);
        assertEq(registry.getTrustTier(agent), "Untrusted");
    }

    // ── Tier transition events ────────────────────────────────────────

    function test_tierTransitionEvent_UntrustedToStandard() public {
        bytes32 agent = keccak256("agent_tier_event");

        // Register 99 decisions normally (no event expected)
        for (uint256 i = 0; i < 99; i++) {
            registry.registerDecisionWithTierCheck(agent, "tool", keccak256(abi.encode(i)));
        }
        assertEq(registry.getTrustTier(agent), "Untrusted");

        // The 100th decision should trigger TrustTierChanged
        vm.expectEmit(true, false, false, true);
        emit AgentDecisionRegistry.TrustTierChanged(agent, "Untrusted", "Standard", 100);
        registry.registerDecisionWithTierCheck(agent, "tool", keccak256(abi.encode(99)));
        assertEq(registry.getTrustTier(agent), "Standard");
    }

    function test_tierTransitionEvent_StandardToUntrustedViaDispute() public {
        bytes32 agent = keccak256("agent_tier_drop_event");

        // Register 100 decisions → Standard
        for (uint256 i = 0; i < 100; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }
        assertEq(registry.getTrustTier(agent), "Standard");

        // Dispute 1 decision: score = 100 - 2 = 98 → Untrusted, should emit event
        vm.expectEmit(true, false, false, true);
        emit AgentDecisionRegistry.TrustTierChanged(agent, "Standard", "Untrusted", 98);
        registry.disputeDecisionWithTierCheck(0, "bad decision");
        assertEq(registry.getTrustTier(agent), "Untrusted");
    }

    // ── Adversarial: boundary conditions ──────────────────────────────

    function test_trustScoreAtExactBoundary_99() public {
        bytes32 agent = keccak256("agent_boundary_99");
        for (uint256 i = 0; i < 99; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }
        assertEq(registry.getTrustScore(agent), 99);
        assertEq(registry.getTrustTier(agent), "Untrusted");
    }

    function test_trustScoreAtExactBoundary_499() public {
        bytes32 agent = keccak256("agent_boundary_499");
        for (uint256 i = 0; i < 499; i++) {
            registry.registerDecision(agent, "tool", keccak256(abi.encode(i)));
        }
        assertEq(registry.getTrustScore(agent), 499);
        assertEq(registry.getTrustTier(agent), "Standard");
    }

    function test_negativeScoreStillUntrusted() public {
        bytes32 agent = keccak256("agent_negative_trust");
        uint256 id0 = registry.registerDecision(agent, "tool_a", keccak256("a"));
        registry.disputeDecision(id0, "Bad");
        uint256 id1 = registry.registerDecision(agent, "tool_b", keccak256("b"));
        registry.disputeDecision(id1, "Also bad");

        // 2 decisions, 2 disputes → score = 2 - 4 = -2 → Untrusted
        assertEq(registry.getTrustScore(agent), -2);
        assertEq(registry.getTrustTier(agent), "Untrusted");
    }
}
