// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AgentDecisionRegistry.sol";

contract AgentDecisionRegistryTest is Test {
    AgentDecisionRegistry public registry;
    bytes32 constant AGENT_1 = keccak256("agent_1");
    bytes32 constant AGENT_2 = keccak256("agent_2");

    function setUp() public {
        registry = new AgentDecisionRegistry();
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
}
