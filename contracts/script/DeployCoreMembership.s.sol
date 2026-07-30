// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./Salts.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MemberBond} from "../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {ValidatorRegistry} from "../src/ValidatorRegistry.sol";

/// @title DeployCoreMembership — CORE-S5.4 / Phase-D D1, rebuilt for M-2
/// @notice Deploys the membership money path on 40204:
///   1. CitrateMemberSBT(initialOwner)
///   2. MemberBond()                       — the clone master copy
///   3. MembershipStakeVault()             — the UUPS implementation
///   4. ERC1967Proxy(impl, initialize(…))  — THE vault address the federation pins
///
/// ## What changed in M-2, and what it costs
///
/// The vault no longer stakes grants into `LiquidStakingPool`. It places each
/// grant in a per-member `MemberBond` escrow that bonds into
/// `ValidatorRegistry` (citrate-chain #139 design (c)). The pool is no longer a
/// constructor input and no longer appears here at all.
///
/// The vault is now UUPS behind an ERC-1967 proxy (owner decision A.3). That
/// means this deployment moves the vault address ONE more time — and never
/// again: every later change is an in-place upgrade behind the proxy. That is
/// the payoff for doing M-2.0 before M-2.1, so the storage layout is frozen
/// once.
///
/// ## Determinism
///
/// Salted CREATE2 (WS-1) through the genesis Arachnid factory, so every address
/// is a pure function of (salt, init_code) — reroll-stable, nonce-independent.
/// The chain is deliberate and fully determined:
///
///   SBT        <- (salt, creationCode, FROZEN_OWNER)
///   MemberBond <- (salt, creationCode)                 [no ctor args]
///   vaultImpl  <- (salt, creationCode)                 [no ctor args]
///   proxy      <- (salt, ERC1967Proxy creationCode, vaultImpl, initialize calldata)
///
/// The proxy's init_code embeds the initialize calldata, which embeds the SBT,
/// MemberBond and REGISTRY addresses. So a bytecode change to ANY of them moves
/// the vault proxy address. `test/CoreMembershipCreate2.t.sol` pins the whole
/// chain and fails closed before a deploy can land somewhere unexpected.
///
/// Broadcast (deployer holds SALT for gas):
///   forge script script/DeployCoreMembership.s.sol \
///     --rpc-url https://rpc.citrate.ai --private-key 0x.. --broadcast --slow \
///     --legacy --gas-limit 8000000
///
/// NOTE: chain 40204 REJECTS EIP-1559 transactions — `--legacy` with an
/// explicit gas limit is mandatory, not optional.
///
/// PRE-FLIGHT: this deployment is only safe once citrate-chain PR #140 is live
/// and past VALUE_TRANSFER_ACTIVATION_HEIGHT (300,000). Below that height the
/// EVM silently discards contract-initiated value transfers, so
/// `MemberBond.activate`'s `registerValidator{value: principal}` would register
/// a validator whose bond does not exist — phantom stake in the consensus
/// proposer set. `run()` refuses to broadcast before the activation height.
contract DeployCoreMembership is Script {
    /// The grant/treasury signer (current membership owner). PINNED — it is a
    /// constructor arg for the SBT and an initialize arg for the vault, so it
    /// feeds both init_code hashes and must NOT come from env.
    address constant FROZEN_OWNER = 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483;

    /// The deployed ValidatorRegistry on 40204. PINNED — it feeds the vault
    /// proxy's init_code hash through the initialize calldata.
    address constant REGISTRY = 0x61D44D8A14443646B756905410BE951e6eCE95A6;

    /// Height at which citrate-chain #140 makes contract-initiated value
    /// transfers real. Deploying below this would produce phantom bonds.
    uint256 constant VALUE_TRANSFER_ACTIVATION_HEIGHT = 300_000;

    function run() external {
        require(block.chainid == 40204, "refusing to deploy off chain 40204 (testnet-beta)");
        require(REGISTRY.code.length > 0, "ValidatorRegistry has no code on this chain");
        require(
            block.number >= VALUE_TRANSFER_ACTIVATION_HEIGHT,
            "refusing to deploy below the value-transfer activation height: bonds would be phantom"
        );

        vm.startBroadcast();

        CitrateMemberSBT sbt =
            new CitrateMemberSBT{salt: Salts.salt("CitrateMemberSBT")}(FROZEN_OWNER);

        MemberBond bondImpl = new MemberBond{salt: Salts.salt("MemberBond")}();

        MembershipStakeVault vaultImpl =
            new MembershipStakeVault{salt: Salts.salt("MembershipStakeVault.impl")}();

        ERC1967Proxy proxy = new ERC1967Proxy{salt: Salts.salt("MembershipStakeVault")}(
            address(vaultImpl),
            abi.encodeCall(
                MembershipStakeVault.initialize,
                (FROZEN_OWNER, ValidatorRegistry(payable(REGISTRY)), sbt, address(bondImpl))
            )
        );

        vm.stopBroadcast();

        console2.log("chainid             :", block.chainid);
        console2.log("initialOwner        :", FROZEN_OWNER);
        console2.log("ValidatorRegistry   :", REGISTRY);
        console2.log("CitrateMemberSBT    :", address(sbt));
        console2.log("MemberBond (impl)   :", address(bondImpl));
        console2.log("MembershipStakeVault impl :", address(vaultImpl));
        console2.log("MembershipStakeVault      :", address(proxy));
        console2.log("^ the proxy is THE vault address to pin federation-wide");
    }
}
