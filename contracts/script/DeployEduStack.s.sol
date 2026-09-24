// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";

import "../src/edu/InstitutionalVault.sol";
import "../src/edu/ClassroomClusterV1.sol";
import "../src/edu/Forwarder.sol";
import "../src/edu/BudgetAllocation.sol";
import "../src/edu/CashoutRequest.sol";

/**
 * @title DeployEduStack
 * @notice Deploys the 5 institutional education contracts in dependency order:
 *         1. InstitutionalVault (multi-sig treasury)
 *         2. ClassroomClusterV1 (RBAC + classrooms)
 *         3. Forwarder (meta-tx relay)
 *         4. BudgetAllocation (per-classroom spending)
 *         5. CashoutRequest (teacher cashout lifecycle)
 *
 * Run:
 *   forge script script/DeployEduStack.s.sol \
 *     --rpc-url http://localhost:8545 \
 *     --account ceremony-deployer \
 *     --sender $DEPLOYER_ADDRESS \
 *     --broadcast -vvvv
 *
 * Required env vars:
 *   CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS — deployer address
 *   SIGNER_1              — first vault signer address (optional, defaults to deployer)
 *   SIGNER_2              — second vault signer address (optional)
 *   SIGNER_3              — third vault signer address (optional)
 *   RELAYER               — institutional relayer address (optional, defaults to deployer)
 *   SALT_USD_RATE         — initial SALT/USD rate in basis points (optional, default 100 = $0.01)
 */
contract DeployEduStack is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();

        // Vault signers MUST be three distinct addresses — the 2-of-3 multisig
        // rejects duplicate signers (`AlreadySigner()`). The reroll script
        // (scripts/regenesis.sh) sets SIGNER_1=DEPLOYER, SIGNER_2=TEAM,
        // SIGNER_3=TREASURY by default. Production ceremony runs should pass
        // three distinct operator-controlled addresses.
        address signer1 = envAddressOr("SIGNER_1", deployer);
        address signer2 = envAddressOr("SIGNER_2", deployer);
        address signer3 = envAddressOr("SIGNER_3", deployer);
        require(
            signer1 != signer2 && signer2 != signer3 && signer1 != signer3,
            "DeployEduStack: SIGNER_1, SIGNER_2, SIGNER_3 must be three distinct addresses"
        );
        address relayer = envAddressOr("RELAYER", deployer);
        uint256 saltUsdRate = envUintOr("SALT_USD_RATE", uint256(100));

        console.log("=== Deploying Edu Stack ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast();

        // 1. InstitutionalVault — 2-of-3 multi-sig
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        InstitutionalVault vault = new InstitutionalVault{salt: Salts.salt("InstitutionalVault")}(signers, 2);
        console.log("InstitutionalVault:", address(vault));

        // 2. ClassroomClusterV1 — governance = vault
        ClassroomClusterV1 cluster = new ClassroomClusterV1{salt: Salts.salt("ClassroomClusterV1")}(address(vault));
        console.log("ClassroomClusterV1:", address(cluster));

        // 3. Forwarder — vault as governance, cluster for device/session validation
        Forwarder forwarder = new Forwarder{salt: Salts.salt("Forwarder")}(address(vault), address(cluster), address(vault));
        console.log("Forwarder:", address(forwarder));

        // 4. BudgetAllocation — governance = vault
        BudgetAllocation budget = new BudgetAllocation{salt: Salts.salt("BudgetAllocation")}(address(vault));
        console.log("BudgetAllocation:", address(budget));

        // 5. CashoutRequest — governance = vault, initial SALT/USD rate
        CashoutRequest cashout = new CashoutRequest{salt: Salts.salt("CashoutRequest")}(address(vault), saltUsdRate);
        console.log("CashoutRequest:", address(cashout));

        // Post-deploy: grant deployer Admin role so they can set up classrooms
        // This is done through the vault, but on testnet with deployer-as-signer
        // the deployer can propose and approve via the vault

        vm.stopBroadcast();

        console.log("");
        console.log("=== Edu Stack Deployed ===");
        console.log("Vault governance signers:", signer1, signer2, signer3);
        console.log("Relayer (add via vault.addRelayer on Forwarder):", relayer);
        console.log("Forwarder targets are denied by default.");
        console.log("Schedule vault txs: forwarder.setTargetAllowed(<audited target>, true).");
        console.log("SALT/USD rate (basis points):", saltUsdRate);
    }
}
