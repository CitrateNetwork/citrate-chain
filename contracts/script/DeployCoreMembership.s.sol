// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import "./Salts.sol";
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
/// Salted CREATE2 (WS-1): both contracts deploy through the genesis Arachnid
/// factory (0x4e59…4956C) via `new X{salt: Salts.salt("X")}(…)`, so their
/// addresses are a pure function of (salt, init_code) — reroll-stable and
/// nonce-independent. To keep those addresses FROZEN, every init_code input is
/// pinned as a literal (NOT read from env): the constructor args (FROZEN_OWNER,
/// DEFAULT_POOL) feed the init_code hash, so a single env drift would move the
/// address. The Create2Determinism tripwire (test/CoreMembershipCreate2.t.sol)
/// pins the resulting projections so a revert to plain CREATE or a bytecode
/// drift fails CI.
///
/// Broadcast (deployer holds SALT for gas):
///   forge script script/DeployCoreMembership.s.sol \
///     --rpc-url https://rpc.citrate.ai --private-key 0x.. --broadcast --slow
contract DeployCoreMembership is Script {
    /// The deployed LiquidStakingPool on 40204 (CREATE2-stable). PINNED — it
    /// feeds the vault init_code hash, so it must NOT come from env.
    address constant DEFAULT_POOL = 0xFD272195B55Cb4F5A240a5bE75AABaB0D1C5685E;

    /// The grant/treasury signer (current membership owner). PINNED — it is a
    /// constructor arg for BOTH contracts and thus part of each init_code hash.
    /// ROTATED 2026-07-20: prior 0x9aFFF274…8A50 was keccak256(OLD_DEPLOYER ‖
    /// "citrate/treasury-grant-signer/v1"); the old deployer leak makes that key
    /// derivable, so it rotates to the NEW-deployer-derived grant signer (matched
    /// by scripts/ops/derive-operator-keys.sh --print-only). Because it is a
    /// constructor arg, the SBT + vault CREATE2 addresses MOVE — the droplet
    /// treasury-signer must be rekeyed to this address and core-membership re-pinned.
    address constant FROZEN_OWNER = 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483;

    function run() external {
        require(block.chainid == 40204, "refusing to deploy off chain 40204 (testnet-beta)");
        require(DEFAULT_POOL.code.length > 0, "LiquidStakingPool has no code on this chain");

        vm.startBroadcast();

        CitrateMemberSBT sbt =
            new CitrateMemberSBT{salt: Salts.salt("CitrateMemberSBT")}(FROZEN_OWNER);
        MembershipStakeVault vault = new MembershipStakeVault{
            salt: Salts.salt("MembershipStakeVault")
        }(FROZEN_OWNER, LiquidStakingPool(payable(DEFAULT_POOL)));

        vm.stopBroadcast();

        console2.log("chainid           :", block.chainid);
        console2.log("initialOwner      :", FROZEN_OWNER);
        console2.log("LiquidStakingPool :", DEFAULT_POOL);
        console2.log("CitrateMemberSBT  :", address(sbt));
        console2.log("MembershipStakeVault:", address(vault));
    }
}
