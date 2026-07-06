// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @notice Minimal interface for the canonical LearningPool on 40204.
interface ILearningPool {
    function createPool(
        string calldata name,
        string calldata description,
        uint8 access, // AccessType: 0=Open,1=InviteOnly,2=ApplicationRequired
        uint256 minStake
    ) external payable returns (uint256 poolId);
    function whitelistModel(uint256 poolId, bytes32 modelHash) external;
    function joinPool(uint256 poolId) external payable;
    function startCycle(uint256 poolId) external;
}

/// @title StartLearningPool — bootstrap a live federated-learning pool + cycle.
/// @notice Creates a DefensePrime fleet-predictive-maintenance pool on the canonical
///         LearningPool (0xFc514b…D564), whitelists a model, joins a second
///         member, and starts the cycle — so the Federated Learning panel shows
///         an active pool aggregating. Two broadcasters: creator (deployer) and
///         member #2.
///
///   Env: FL_DEPLOYER_KEY (creator), FL_MEMBER2_KEY (2nd member, funded for gas)
///   Usage:
///     forge script script/StartLearningPool.s.sol \
///       --rpc-url https://rpc.citrate.ai --broadcast --slow
contract StartLearningPool is Script {
    ILearningPool constant POOL =
        ILearningPool(0xFc514b826dAeE16c590F86AD83370f4FB8a1D564);

    function run() external {
        uint256 creatorKey = vm.envUint("FL_DEPLOYER_KEY");
        uint256 member2Key = vm.envUint("FL_MEMBER2_KEY");

        // 1. Creator: create the pool (Open, no stake) + whitelist a model.
        vm.startBroadcast(creatorKey);
        uint256 poolId = POOL.createPool(
            "DefensePrime Fleet Predictive Maintenance",
            "Federated engine-bay + structural-fatigue models across government operators and the DefensePrime depot. Raw data never leaves the operator enclave.",
            0,
            0
        );
        POOL.whitelistModel(poolId, keccak256("engine-bay-prognostic-v3"));
        vm.stopBroadcast();

        // 2. Member #2 joins (satisfies the >=2 members rule for startCycle).
        vm.startBroadcast(member2Key);
        POOL.joinPool(poolId);
        vm.stopBroadcast();

        // 3. Creator starts the cycle.
        vm.startBroadcast(creatorKey);
        POOL.startCycle(poolId);
        vm.stopBroadcast();

        console2.log("Learning pool started. poolId:", poolId);
    }
}
