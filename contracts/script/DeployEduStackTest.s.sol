// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

import "../src/edu/InstitutionalVault.sol";
import "../src/edu/ClassroomClusterV1.sol";
import "../src/edu/Forwarder.sol";
import "../src/edu/BudgetAllocation.sol";
import "../src/edu/CashoutRequest.sol";

/**
 * @title DeployEduStackTest
 * @notice Test-only variant of DeployEduStack.
 *
 * Differences from the production script:
 *  - ClassroomClusterV1 governance = deployer (not vault)
 *  - BudgetAllocation governance  = deployer (not vault)
 *  - CashoutRequest governance    = deployer (not vault)
 *  - Forwarder governance         = deployer (not vault)
 *  - Forwarder targets            = denied by default; tests opt targets in
 *
 * This lets the Anvil test fixture's deployer account call grantOrgRole,
 * createClassroom, allocateBudget, and approveCashout directly without routing
 * through the multi-sig vault's proposal flow.
 *
 * Run (Anvil integration tests):
 *   forge script script/DeployEduStackTest.s.sol \
 *     --rpc-url http://localhost:<PORT> \
 *     --private-key <DEPLOYER_KEY> \
 *     --broadcast --silent
 */
contract DeployEduStackTest is ScriptEnv {
    function run() external {
        address deployer = deployerAddress();

        // Vault signers: deployer is SIGNER_1; IT_ADDR and ADMIN_ADDR are 2 & 3.
        address signer1 = envAddressOr("SIGNER_1", deployer);
        address signer2 = envAddressOr("SIGNER_2", deployer);
        address signer3 = envAddressOr("SIGNER_3", deployer);
        uint256 saltUsdRate = envUintOr("SALT_USD_RATE", uint256(100));

        console.log("=== Deploying Test Edu Stack ===");
        console.log("Deployer (governance):", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast();

        // 1. InstitutionalVault — 2-of-3 multi-sig (same as production)
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        InstitutionalVault vault = new InstitutionalVault(signers, 2);
        console.log("InstitutionalVault:", address(vault));

        // 2. ClassroomClusterV1 — governance = deployer (test-only)
        //    Production uses address(vault) as governance.
        ClassroomClusterV1 cluster = new ClassroomClusterV1(deployer);
        console.log("ClassroomClusterV1:", address(cluster));

        // 3. Forwarder — governance = deployer, relayer = deployer (test-only)
        Forwarder forwarder = new Forwarder(deployer, address(cluster), deployer);
        console.log("Forwarder:", address(forwarder));

        // 4. BudgetAllocation — governance = deployer (test-only)
        BudgetAllocation budget = new BudgetAllocation(deployer);
        console.log("BudgetAllocation:", address(budget));

        // 5. CashoutRequest — governance = deployer, initial SALT/USD rate (test-only)
        CashoutRequest cashout = new CashoutRequest(deployer, saltUsdRate);
        console.log("CashoutRequest:", address(cashout));

        vm.stopBroadcast();

        console.log("");
        console.log("=== Test Edu Stack Deployed ===");
        console.log("All contract governance set to deployer for direct test access.");
        console.log("Forwarder targets are denied by default; call setTargetAllowed for each test target.");
    }
}
