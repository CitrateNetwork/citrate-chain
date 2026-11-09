// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {GenesisProfile} from "../../script/lib/GenesisProfile.sol";
import {
    DormantWithHistory,
    GateWithHistory,
    MembershipWithHistory,
    RecordedRoleHistory
} from "./RoleHistoryHarness.sol";

/// @title Node stand-in for the GenesisProfile chain-id check
/// @notice `forge test` has no fork, so `vm.rpc("eth_chainId")` is unavailable there (the real
///         `_nodeChainId` then reports "no node", which the genesis profile refuses). These
///         harnesses replace only the node read:
///           HONEST : the node reports forge's simulated id (a correctly configured run)
///           FIXED  : the node reports `nodeId`, whatever forge simulates. A node at 40204 with
///                    vm.chainId(1) is what `--chain-id 1`, `--chain 1` and FOUNDRY_CHAIN_ID=1
///                    each produce in a real `forge script` run against that node (measured
///                    with forge 1.8.3 against anvil --chain-id 40204: block.chainid = 1,
///                    eth_chainId = 0x9d0c).
///           NONE   : no RPC (pure simulation)
///         DormantWithNode / GateWithNode also take the timelock role history from the test's
///         RoleLogArchive (RoleHistoryHarness: call `useArchive`), since both scripts now
///         establish complete timelock holder sets; without an archive that check fails closed.
abstract contract NodeStub {
    uint8 internal constant NONE = 0;
    uint8 internal constant HONEST = 1;
    uint8 internal constant FIXED = 2;

    uint8 internal nodeMode = HONEST;
    uint256 internal nodeId;

    function honestNode() external {
        nodeMode = HONEST;
    }

    function nodeReports(uint256 id) external {
        (nodeMode, nodeId) = (FIXED, id);
    }

    function noNode() external {
        nodeMode = NONE;
    }

    function _stubNode() internal view returns (bool ok, uint256 id) {
        if (nodeMode == NONE) return (false, 0);
        if (nodeMode == HONEST) return (true, block.chainid);
        return (true, nodeId);
    }
}

contract GovernanceWithNode is DeployGenesisGovernance, NodeStub {
    function _nodeChainId() internal view override returns (bool, uint256) {
        return _stubNode();
    }

    function decodeChainId(bytes memory r) external pure returns (uint256) {
        return _decodeChainId(r);
    }
}

contract DormantWithNode is DormantWithHistory, NodeStub {
    function _nodeChainId() internal view override returns (bool, uint256) {
        return _stubNode();
    }
}

contract GateWithNode is GateWithHistory, NodeStub {
    function _nodeChainId() internal view override returns (bool, uint256) {
        return _stubNode();
    }
}

/// Direct access to GenesisProfile `_bookGuardianCanceller`, over the test's recorded history.
contract BookCancellerChecks is GenesisProfile, RecordedRoleHistory {
    function problem(string memory json, address govTl) external returns (string memory, address) {
        return _bookGuardianCanceller(json, govTl);
    }

    function _timelockRoleHistory(address timelock)
        internal
        override(AdminChecks, RecordedRoleHistory)
        returns (bool, string memory, RoleEvent[] memory)
    {
        return RecordedRoleHistory._timelockRoleHistory(timelock);
    }
}

contract MembershipWithNode is MembershipWithHistory, NodeStub {
    function _nodeChainId() internal view override returns (bool, uint256) {
        return _stubNode();
    }
}
