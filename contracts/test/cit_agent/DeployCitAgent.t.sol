// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../../script/DeployCitAgent.s.sol";
import "../../src/cit_agent/MultisigTimelock2of3.sol";
import "../../src/cit_agent/OrganizationSBT.sol";
import "../../src/cit_agent/AgentSBT.sol";
import "../../src/cit_agent/CapsuleRegistry.sol";
import "../../src/cit_agent/AnchorRegistry.sol";
import "../../src/cit_agent/BenchmarkRegistry.sol";

/// CIT-AGENT-6c — dry-run test for the cit-agent deployment script.
/// Exercises the deploy sequence in Foundry's in-memory EVM and
/// asserts that ownership ends up where 6a/6b expect.
contract DeployCitAgentTest is Test {
    address internal deployer;
    address internal alice;
    address internal bob;
    address internal carol;

    function setUp() public {
        deployer = makeAddr("deployer");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
    }

    function testDeploy_endToEnd() public {
        // Set the env vars the script reads.
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(deployer));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_0", vm.toString(alice));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_1", vm.toString(bob));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_2", vm.toString(carol));
        vm.setEnv("CIT_AGENT_TIMELOCK_DELAY", "172800"); // 2 days

        DeployCitAgent script = new DeployCitAgent();
        // The script's `startBroadcast` runs as the test contract;
        // ownership transfers + deployments come from `address(this)`.
        // For dry-run we just need everything to deploy cleanly.
        DeployCitAgent.Deployment memory d = script.run();

        // All 6 addresses are non-zero.
        assertTrue(d.timelock != address(0));
        assertTrue(d.organizationSBT != address(0));
        assertTrue(d.agentSBT != address(0));
        assertTrue(d.capsuleRegistry != address(0));
        assertTrue(d.anchorRegistry != address(0));
        assertTrue(d.benchmarkRegistry != address(0));

        // Timelock has the expected owners.
        MultisigTimelock2of3 timelock = MultisigTimelock2of3(d.timelock);
        assertTrue(timelock.isOwner(alice));
        assertTrue(timelock.isOwner(bob));
        assertTrue(timelock.isOwner(carol));
        assertEq(timelock.minDelay(), 2 days);

        // Admin-gated contracts are now owned by the timelock.
        assertEq(OrganizationSBT(d.organizationSBT).owner(), d.timelock);
        assertEq(AgentSBT(d.agentSBT).owner(), d.timelock);
        assertEq(CapsuleRegistry(d.capsuleRegistry).owner(), d.timelock);

        // AgentSBT references the correct OrganizationSBT.
        assertEq(
            address(AgentSBT(d.agentSBT).orgContract()),
            d.organizationSBT
        );

        // AnchorRegistry / BenchmarkRegistry are non-Ownable; just
        // verify they deployed (the assertion above on non-zero
        // addresses already covers this).
    }

    // NOTE: the env-var-required-owner check is in the script
    // (require ... "set CIT_AGENT_TIMELOCK_OWNER_{0,1,2}") but is
    // not unit-tested here. Foundry's vm.setEnv is process-level +
    // doesn't isolate across tests cleanly enough to assert the
    // failure mode without flakiness. The check is exercised by
    // the operator runbook (forge script will fail-fast if any
    // owner env var is unset).

    function testDeploy_postDeployTimelockCanMint() public {
        // Smoke-test that the deployed timelock can actually drive
        // OrganizationSBT.mintOrg via the 2-of-3 proposal flow.
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(deployer));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_0", vm.toString(alice));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_1", vm.toString(bob));
        vm.setEnv("CIT_AGENT_TIMELOCK_OWNER_2", vm.toString(carol));
        vm.setEnv("CIT_AGENT_TIMELOCK_DELAY", "172800");

        DeployCitAgent script = new DeployCitAgent();
        DeployCitAgent.Deployment memory d = script.run();

        bytes32[] memory overlays = new bytes32[](0);
        bytes memory mintPayload = abi.encodeWithSelector(
            OrganizationSBT.mintOrg.selector,
            alice,
            keccak256("did:citrate:org:smoke"),
            bob,
            overlays
        );

        MultisigTimelock2of3 timelock = MultisigTimelock2of3(d.timelock);
        vm.prank(alice);
        bytes32 opId = timelock.propose(d.organizationSBT, mintPayload);
        vm.prank(bob);
        timelock.approve(opId);
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(alice);
        timelock.execute(opId);

        // Org id 0 was minted to alice.
        OrganizationSBT org = OrganizationSBT(d.organizationSBT);
        assertEq(org.ownerOf(0), alice);
    }
}
