// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "../src/ComputeVerifier.sol";
import "../src/ComputeMarketplace.sol";
import "../src/TEEAttestationRegistry.sol";

/// @title DeployDpf08Refresh — Refresh the 3 drifted DPF-08 read-path contracts
/// @notice Re-deploys ComputeVerifier, ComputeMarketplace, and
///         TEEAttestationRegistry so their on-chain bytecode matches the
///         current source. The previously-deployed instances at the
///         CONFIG.md addresses return `0x` for source-defined selectors
///         (function-not-found) — they're an older revision.
///
///         WP-8 E2E tests of the Models & Compute panel read these three
///         contracts; the refresh is the gating step.
///
/// @dev Two-step wiring is unavoidable because the verifier and
///      marketplace reference each other:
///        1. Deploy ComputeVerifier with `deployer` as the placeholder
///           marketplace (verifier requires non-zero).
///        2. Deploy ComputeMarketplace with the fresh verifier address +
///           deployer as the treasury (testnet bootstrap).
///        3. Call `ComputeVerifier.setMarketplace(<fresh marketplace>)` to
///           rewire the verifier — within the same broadcast block so the
///           operator approves once.
///      The TEEAttestationRegistry is independent of the other two.
///
///      Per the established DPF pattern, `--broadcast` is HUMAN-IN-LOOP
///      (Saul holds the deployer key in .env.testnet).
///
/// Usage:
///   # Dry-run:
///   forge script script/DeployDpf08Refresh.s.sol \
///       --rpc-url https://rpc.citrate.ai
///
///   # Live broadcast (Saul):
///   forge script script/DeployDpf08Refresh.s.sol \
///       --rpc-url https://rpc.citrate.ai \
///       --private-key $DEPLOYER_PRIVATE_KEY \
///       --broadcast --slow
///
/// After broadcast, append to DEPLOYED_CONTRACTS_2026_05_10.md and
/// update CONFIG.md's "Deployed Contracts" table to point WP-8 E2E
/// tests at the new addresses.
contract DeployDpf08Refresh is ScriptEnv {
    struct DeployedAddresses {
        address computeVerifier;
        address computeMarketplace;
        address teeAttestationRegistry;
    }

    function run() external returns (DeployedAddresses memory addrs) {
        address deployer = deployerAddress();
        address governance = envAddressOr("GOVERNANCE", deployer);
        address treasury = envAddressOr("TREASURY", deployer);

        console.log("=== DPF-08 read-path contract refresh ===");
        console.log("Deployer:  ", deployer);
        console.log("Governance:", governance);
        console.log("Treasury:  ", treasury);
        console.log("Chain ID:  ", block.chainid);

        vm.startBroadcast();

        // 1. ComputeVerifier — initial marketplace = deployer placeholder.
        //    The constructor requires non-zero; we rewire below.
        // PBA-L2-002: governance is explicit (the broadcasting deployer, which
        // performs the setMarketplace rewire below; hand over afterwards).
        ComputeVerifier verifier = new ComputeVerifier(deployer, deployer);
        console.log("ComputeVerifier:", address(verifier));

        // 2. ComputeMarketplace — depends on the fresh verifier.
        ComputeMarketplace marketplace = new ComputeMarketplace(
            address(verifier),
            treasury,
            deployer
        );
        console.log("ComputeMarketplace:", address(marketplace));

        // 3. Rewire the verifier's marketplace pointer to the freshly
        //    deployed marketplace. Same broadcast block = same operator
        //    approval = atomic from the operator's POV.
        verifier.setMarketplace(address(marketplace));
        console.log("ComputeVerifier.setMarketplace -> ComputeMarketplace OK");

        // 4. TEEAttestationRegistry — independent of the compute pair.
        TEEAttestationRegistry tee = new TEEAttestationRegistry(governance);
        console.log("TEEAttestationRegistry:", address(tee));

        vm.stopBroadcast();

        addrs = DeployedAddresses({
            computeVerifier: address(verifier),
            computeMarketplace: address(marketplace),
            teeAttestationRegistry: address(tee)
        });

        console.log("=== Refresh complete ===");
        console.log("Update CONFIG.md + DEPLOYED_CONTRACTS_2026_05_10.md with these 3 addresses.");
        console.log("Previous drifted addresses (treat as deprecated):");
        console.log("  ComputeVerifier:        0x0aaa6e00FCab1dA5599F6DCE86e361A5e03A5759");
        console.log("  ComputeMarketplace:     0xA6a4122126A75611eA06241E404327ADdFe8eB5e");
        console.log("  TEEAttestationRegistry: 0x26333384a517c50d8B116979490b4AD1506F1F9a");
    }
}
