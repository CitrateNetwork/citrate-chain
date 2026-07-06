// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {AgentDecisionRegistryV2} from "../src/rbac/AgentDecisionRegistryV2.sol";
import {AuditBundleRegistry} from "../src/defense_prime/AuditBundleRegistry.sol";
import {DefensePrimeFLScopeIndex} from "../src/defense_prime/DefensePrimeFLScopeIndex.sol";

/// @title SimulateActivity — one "tick" of live DefensePrime-network activity.
/// @notice Submits a batch of unique on-chain records each invocation so the
///         chain looks like a busy, multi-actor network during the demo. Run
///         repeatedly by chain_activity_daemon.sh (one tick per block-ish).
///
/// @dev Signer must be an authorized recorder (the DPF-DEMO deployer is, via
///      WireDpfOperators). IDs are (SIM_TICK, i)-scoped so re-runs never
///      collide. Addresses are the 2026-07-03 DPF-DEMO deploy on 40204.
///
///   Env:
///     SIM_TICK   monotonically-increasing tick number (default 0)
///     SIM_BATCH  records per tick (default 6)
///
///   Usage (broadcast):
///     SIM_TICK=$n forge script script/SimulateActivity.s.sol \
///       --rpc-url https://rpc.citrate.ai --private-key $DEPLOY_KEY --broadcast --slow
contract SimulateActivity is Script {
    AgentDecisionRegistryV2 constant ADR =
        AgentDecisionRegistryV2(0xb524C66176f11613c3A43b0B7DB796cce607C013);
    AuditBundleRegistry constant ABR =
        AuditBundleRegistry(0x8Ec50f940256EEA578C540Fd9887aC241AECecdc);
    DefensePrimeFLScopeIndex constant FL_IDX =
        DefensePrimeFLScopeIndex(0x5c24659E68285497E43F18C429151E902abf528A);

    bytes32 constant BCA_SCOPE = keccak256("scope-unit");
    bytes32 constant LINE_787 = keccak256("scope-787-line");

    function run() external {
        uint256 tick = vm.envOr("SIM_TICK", uint256(0));
        uint256 batch = vm.envOr("SIM_BATCH", uint256(6));

        vm.startBroadcast();

        for (uint256 i = 0; i < batch; i++) {
            bytes32 id = keccak256(abi.encodePacked("sim-dec-", tick, "-", i));
            bytes32 corr = keccak256(abi.encodePacked("sim-corr-", tick));
            bytes32 tenant = (i % 3 == 0) ? BCA_SCOPE : LINE_787;
            bytes32 user = keccak256(abi.encodePacked("sim-agent-", (tick + i) % 12));
            AgentDecisionRegistryV2.EventClass class_ =
                AgentDecisionRegistryV2.EventClass(uint8((tick + i) % 5));

            ADR.record(
                id,
                user,
                tenant,
                corr,
                class_,
                string(abi.encodePacked("Live agent decision t", vm.toString(tick), "-", vm.toString(i))),
                "PASSKEY",
                keccak256(abi.encodePacked("sim-artifact-", tick, "-", i)),
                (i % 4 == 0) ? "Verified" : "Pending",
                abi.encodePacked(keccak256(abi.encodePacked("sim-sig-", tick, "-", i)))
            );
        }

        // Anchor one audit bundle per tick (keeps Governance/Agent-Center live).
        ABR.anchor(
            uint8(tick % 3),
            keccak256(abi.encodePacked("sim-bundle-", tick)),
            keccak256(abi.encodePacked("sim-session-", tick)),
            BCA_SCOPE,
            keccak256(abi.encodePacked("sim-merkle-", tick)),
            keccak256(abi.encodePacked("sim-ipfs-", tick)),
            5 + tick
        );

        // Every 5th tick, tag an FL correlation (keeps the FL panel moving).
        if (tick % 5 == 0) {
            FL_IDX.tag(uint8(1 + (tick % 2)), (tick % 2 == 0) ? BCA_SCOPE : LINE_787,
                keccak256(abi.encodePacked("sim-fl-", tick)));
        }

        vm.stopBroadcast();
    }
}
