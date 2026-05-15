// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";

import "../src/cit_agent/MultisigTimelock2of3.sol";
import "../src/cit_agent/OrganizationSBT.sol";
import "../src/cit_agent/AgentSBT.sol";
import "../src/cit_agent/CapsuleRegistry.sol";
import "../src/cit_agent/AnchorRegistry.sol";
import "../src/cit_agent/BenchmarkRegistry.sol";

/// @title DeployCitAgent — CIT-AGENT-6c
/// @notice Deploys the 5 cit-agent contracts + the 2-of-3 multisig
///         timelock in the correct order, transfers ownership of the
///         admin-gated contracts to the timelock, and prints a
///         summary suitable for pasting into DEPLOYED_ADDRESSES.md.
///
/// @dev Mirrors the BFR-program ceremony pattern (DeployBfr*.s.sol):
///      broadcast is human-in-loop. Operator runs:
///
///      forge script script/DeployCitAgent.s.sol \
///          --rpc-url https://rpc.citrate.ai \
///          --private-key $DEPLOYER_PRIVATE_KEY \
///          --broadcast --slow
///
///      Env vars consumed:
///        DEPLOYER_ADDRESS or CEREMONY_DEPLOYER_ADDRESS (from ScriptEnv)
///        CIT_AGENT_TIMELOCK_OWNER_0  — first timelock owner (required)
///        CIT_AGENT_TIMELOCK_OWNER_1  — second timelock owner (required)
///        CIT_AGENT_TIMELOCK_OWNER_2  — third timelock owner (required)
///        CIT_AGENT_TIMELOCK_DELAY    — min delay in seconds (default: 2 days)
contract DeployCitAgent is ScriptEnv {
    struct Deployment {
        address timelock;
        address organizationSBT;
        address agentSBT;
        address capsuleRegistry;
        address anchorRegistry;
        address benchmarkRegistry;
    }

    function run() external returns (Deployment memory d) {
        // DEPLOYER_ADDRESS must equal the broadcaster identity (the
        // forge-CLI signer in live deploys, the configured broadcast
        // sender in tests). The contracts are constructed with this
        // address as initialOwner, and `transferOwnership(timelock)`
        // executes under the same identity so OZ Ownable's onlyOwner
        // check passes.
        address deployer = deployerAddress();
        address[3] memory timelockOwners = [
            envAddressOr("CIT_AGENT_TIMELOCK_OWNER_0", address(0)),
            envAddressOr("CIT_AGENT_TIMELOCK_OWNER_1", address(0)),
            envAddressOr("CIT_AGENT_TIMELOCK_OWNER_2", address(0))
        ];
        require(
            timelockOwners[0] != address(0)
                && timelockOwners[1] != address(0)
                && timelockOwners[2] != address(0),
            "set CIT_AGENT_TIMELOCK_OWNER_{0,1,2}"
        );
        uint256 minDelay = envUintOr("CIT_AGENT_TIMELOCK_DELAY", 2 days);

        console.log("=== CIT-AGENT-6c deployment ===");
        console.log("Deployer:               ", deployer);
        console.log("Timelock owner 0:       ", timelockOwners[0]);
        console.log("Timelock owner 1:       ", timelockOwners[1]);
        console.log("Timelock owner 2:       ", timelockOwners[2]);
        console.log("Timelock min delay (s): ", minDelay);
        console.log("Chain ID:               ", block.chainid);

        vm.startBroadcast(deployer);

        // 1. Timelock first — admin migration target.
        MultisigTimelock2of3 timelock =
            new MultisigTimelock2of3(timelockOwners, minDelay);
        console.log("MultisigTimelock2of3:   ", address(timelock));

        // 2. OrganizationSBT — initially owned by deployer.
        OrganizationSBT org = new OrganizationSBT(deployer);
        console.log("OrganizationSBT:        ", address(org));

        // 3. AgentSBT — references OrganizationSBT.
        AgentSBT agent = new AgentSBT(deployer, org);
        console.log("AgentSBT:               ", address(agent));

        // 4. CapsuleRegistry.
        CapsuleRegistry capsules = new CapsuleRegistry(deployer);
        console.log("CapsuleRegistry:        ", address(capsules));

        // 5. AnchorRegistry — no owner; append-anyone.
        AnchorRegistry anchors = new AnchorRegistry();
        console.log("AnchorRegistry:         ", address(anchors));

        // 6. BenchmarkRegistry — no owner; append-anyone.
        BenchmarkRegistry benchmarks = new BenchmarkRegistry();
        console.log("BenchmarkRegistry:      ", address(benchmarks));

        // 7. Transfer ownership of admin-gated contracts to the timelock.
        org.transferOwnership(address(timelock));
        agent.transferOwnership(address(timelock));
        capsules.transferOwnership(address(timelock));
        console.log("Ownership transferred:  org / agent / capsules -> timelock");

        vm.stopBroadcast();

        d = Deployment({
            timelock: address(timelock),
            organizationSBT: address(org),
            agentSBT: address(agent),
            capsuleRegistry: address(capsules),
            anchorRegistry: address(anchors),
            benchmarkRegistry: address(benchmarks)
        });

        console.log("=== Deployment complete ===");
        console.log("Append the addresses below to DEPLOYED_ADDRESSES.md");
        console.log("  MultisigTimelock2of3: %s", address(timelock));
        console.log("  OrganizationSBT:      %s", address(org));
        console.log("  AgentSBT:             %s", address(agent));
        console.log("  CapsuleRegistry:      %s", address(capsules));
        console.log("  AnchorRegistry:       %s", address(anchors));
        console.log("  BenchmarkRegistry:    %s", address(benchmarks));
    }
}
