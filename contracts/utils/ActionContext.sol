// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ActionContext {
    address public agent;
    bytes32 public agentSbtId;
    uint256 public cost;

    constructor(address _agent, bytes32 _agentSbtId, uint256 _cost) {
        agent = _agent;
        agentSbtId = _agentSbtId;
        cost = _cost;
    }

    function validate() internal view {
        require(agentSbtId != bytes32(0), "ActionContext: Agent SBT required");
        require(cost > 0, "ActionContext: Cost must be positive");
    }
}