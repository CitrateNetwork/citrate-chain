// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {LiquidStakingPool} from "../src/LiquidStakingPool.sol";

/// @title DeployCoreMembership — CORE-S5.4 / Phase-D D1
/// @notice Deploys the two money-path membership contracts on 40204:
///   1. CitrateMemberSBT(initialOwner)
///   2. MembershipStakeVault(initialOwner, LiquidStakingPool)
/// The SBT and vault are independent at deploy (no cross-linkage); the vault
/// stakes grants into the existing LiquidStakingPool (no pool authorization
/// needed — the pool only gates withdrawals to the staker). initialOwner is
/// the deployer by default and is TRANSFERABLE to the grant-orchestrator /
/// droplet-signer address once `core-membership` exists (Ownable).
///
/// Env:
///   MEMBERSHIP_OWNER   (optional) — initialOwner; falls back to the broadcaster
///   LIQUID_STAKING_POOL (optional) — pool address; defaults to the 40204 book value
///
/// Broadcast (deployer holds SALT for gas):
///   MEMBERSHIP_OWNER=0x.. forge script script/DeployCoreMembership.s.sol \
///     --rpc-url https://rpc.citrate.ai --private-key 0x.. --broadcast --slow
contract DeployCoreMembership is Script {
    // The deployed LiquidStakingPool on 40204 (contracts/addresses/40204.json).
    address constant DEFAULT_POOL = 0xFD272195B55Cb4F5A240a5bE75AABaB0D1C5685E;

    function run() external {
        address owner = vm.envOr("MEMBERSHIP_OWNER", address(0));
        address poolAddr = vm.envOr("LIQUID_STAKING_POOL", DEFAULT_POOL);

        require(block.chainid == 40204, "refusing to deploy off chain 40204 (testnet-beta)");
        require(poolAddr.code.length > 0, "LiquidStakingPool has no code on this chain");

        vm.startBroadcast();
        if (owner == address(0)) {
            owner = msg.sender; // the broadcaster/deployer
        }

        CitrateMemberSBT sbt = new CitrateMemberSBT(owner);
        MembershipStakeVault vault =
            new MembershipStakeVault(owner, LiquidStakingPool(payable(poolAddr)));

        vm.stopBroadcast();

        console2.log("chainid           :", block.chainid);
        console2.log("initialOwner      :", owner);
        console2.log("LiquidStakingPool :", poolAddr);
        console2.log("CitrateMemberSBT  :", address(sbt));
        console2.log("MembershipStakeVault:", address(vault));
    }
}
