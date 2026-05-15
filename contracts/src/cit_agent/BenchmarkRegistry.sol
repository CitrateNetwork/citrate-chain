// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title BenchmarkRegistry — RFC-CIT-AGENT-0001 §11.2 + planset
///        06_ON_CHAIN_SURFACE.md "BenchmarkRegistry".
///
/// Records benchmark metric observations for (agent, capsule) pairs.
/// CIT-AGENT-3a's capsules ship `gherkin/` scenarios + optional
/// TLA+ specs (tier-high required); when a capsule runs through its
/// gherkin scenarios as part of doctor's continuous monitoring
/// (CIT-AGENT-7), the resulting per-metric observations land here.
///
/// Append-anyone. The audit chain (CIT-AGENT-5a) is the integrity-
/// preserving log; this contract is the publicly-queryable
/// summary surface for benchmarks specifically.
contract BenchmarkRegistry {
    struct BenchmarkRecord {
        uint256 agent_id;        // AgentSBT id (off-chain link)
        bytes32 capsule_id;      // capsule that produced the metric
        bytes32 metric_name;     // e.g. keccak256("inference_latency_p99_ms")
        uint256 value;           // metric value (units implied by metric_name)
        uint256 timestamp;
        address committer;
    }

    /// Per (agent_id, capsule_id, metric_name) → list of records.
    /// Three-level mapping is awkward in storage; we flatten via a
    /// composite key for the index.
    mapping(bytes32 => BenchmarkRecord[]) private _records;

    /// All metrics ever observed, for off-chain indexers.
    bytes32[] public allMetrics;
    mapping(bytes32 => bool) private _metricSeen;

    event BenchmarkRecorded(
        uint256 indexed agent_id,
        bytes32 indexed capsule_id,
        bytes32 indexed metric_name,
        uint256 value
    );

    function record(
        uint256 agent_id,
        bytes32 capsule_id,
        bytes32 metric_name,
        uint256 value
    ) external {
        bytes32 key = _keyFor(agent_id, capsule_id, metric_name);
        _records[key].push(BenchmarkRecord({
            agent_id: agent_id,
            capsule_id: capsule_id,
            metric_name: metric_name,
            value: value,
            timestamp: block.timestamp,
            committer: msg.sender
        }));
        if (!_metricSeen[metric_name]) {
            _metricSeen[metric_name] = true;
            allMetrics.push(metric_name);
        }
        emit BenchmarkRecorded(agent_id, capsule_id, metric_name, value);
    }

    function getMetric(
        uint256 agent_id,
        bytes32 capsule_id,
        bytes32 metric_name
    ) external view returns (BenchmarkRecord[] memory) {
        return _records[_keyFor(agent_id, capsule_id, metric_name)];
    }

    function metricCount(
        uint256 agent_id,
        bytes32 capsule_id,
        bytes32 metric_name
    ) external view returns (uint256) {
        return _records[_keyFor(agent_id, capsule_id, metric_name)].length;
    }

    function _keyFor(uint256 agent_id, bytes32 capsule_id, bytes32 metric_name)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(agent_id, capsule_id, metric_name));
    }
}
