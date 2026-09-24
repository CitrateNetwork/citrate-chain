// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title INematocystSlashing — Minimal interface for triggering slashes
/// @notice Used by HeartbeatMonitor, DisputeResolution, and ComputePool to
///         integrate with the NematocystSlashing contract.
interface INematocystSlashing {
    function slash(address provider, uint8 tier, bytes calldata evidence) external;
}
