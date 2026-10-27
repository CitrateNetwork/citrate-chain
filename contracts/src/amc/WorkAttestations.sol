// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @dev The AgentSBT reads WorkAttestations needs (view calls only).
interface IAgentSBT {
    struct Agent {
        uint256 parent_org_id;
        bytes32 did;
        bytes32 pubkey_fingerprint;
        bool quarantined;
    }

    function ownerOf(uint256 tokenId) external view returns (address);
    function getAgent(uint256 tokenId) external view returns (Agent memory);
}

/// @title WorkAttestations: a member's signed claim that a unit of agent work happened
/// @notice AMC 0.5.3 planset 06 section 5; ADR-2026-10-26 P-12, P-16. Spec:
///         docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md. Not in r1006 or block 0.
///
///         An attestation is the MEMBER'S CLAIM, labelled so (RT-17), not a proof of quality.
///         `verifierBits` are the sidecar workflow verifiers' pass bits (D-22), filled by core
///         from metering, never from the model's own statement. No content, model name or
///         provider name goes on chain: hashes, the AgentSBT id and a model class only.
///
///         Benchmarks are not duplicated here. `agentId` is the same AgentSBT id that
///         BenchmarkRegistry series are keyed by, so a reader joins an agent's attestations
///         (`byAgent`) with its benchmark series (`BenchmarkRegistry.getMetric(committer,
///         agentId, ...)`) off chain. This contract makes no call to BenchmarkRegistry.
///
///         Only the AgentSBT's owner attests for it, and not while it is quarantined. The
///         attester may revoke (sticky; the record stays). Any other address may acknowledge
///         receipt, which records receipt only, not approval. No value, no governance; the only
///         external calls are views on AgentSBT.
contract WorkAttestations {
    struct Attestation {
        uint256 agentId; // AgentSBT token, owned by msg.sender and not quarantined
        bytes32 taskHash; // salted hash of the task brief
        bytes32 artifactRoot; // RFC 6962 root over salted artifact content hashes
        bytes32 receiptRef; // optional UsageReceipts leaf hash (0 if none)
        uint32 verifierBits; // per-verifier pass bits from the sidecar workflow verifiers
        uint8 modelClass; // 0 local, 1 network (InferenceRouter), 2 API (BYOK), 3 custom-unverified, 4 delegate
        uint64 completedAt;
        address attester;
    }

    uint8 public constant MAX_MODEL_CLASS = 4;

    IAgentSBT public immutable agents;

    mapping(bytes32 => Attestation) private _attestations;
    mapping(bytes32 => bool) private _revoked;
    mapping(bytes32 => mapping(address => bool)) public acknowledged;
    mapping(uint256 => bytes32[]) private _byAgent;
    mapping(uint256 => uint256) public revokedCount;

    event Attested(bytes32 indexed id, uint256 indexed agentId, address indexed attester, bytes32 taskHash);
    event Revoked(bytes32 indexed id, uint16 reasonCode);
    event Acknowledged(bytes32 indexed id, address indexed counterparty);

    error NotAttester();
    error NotAgentOwner();
    error AgentQuarantined();
    error ZeroHash();
    error BadModelClass();
    error FutureCompletion();
    error AlreadyAttested(bytes32 id);
    error UnknownAttestation(bytes32 id);
    error AlreadyRevoked();
    error AlreadyAcknowledged();
    error SelfAcknowledge();
    error AgentsHasNoCode();

    constructor(IAgentSBT agents_) {
        if (address(agents_).code.length == 0) revert AgentsHasNoCode();
        agents = agents_;
    }

    /// @return id keccak256(abi.encode(a)); the same attestation is recorded once.
    function attest(Attestation calldata a) external returns (bytes32 id) {
        if (a.attester != msg.sender) revert NotAttester();
        if (agents.ownerOf(a.agentId) != msg.sender) revert NotAgentOwner();
        if (agents.getAgent(a.agentId).quarantined) revert AgentQuarantined();
        if (a.taskHash == bytes32(0) || a.artifactRoot == bytes32(0)) revert ZeroHash();
        if (a.modelClass > MAX_MODEL_CLASS) revert BadModelClass();
        if (a.completedAt > block.timestamp) revert FutureCompletion();
        id = keccak256(abi.encode(a));
        if (_attestations[id].attester != address(0)) revert AlreadyAttested(id);
        _attestations[id] = a;
        _byAgent[a.agentId].push(id);
        emit Attested(id, a.agentId, msg.sender, a.taskHash);
    }

    /// @notice The attester withdraws its claim. The record stays, marked revoked, for good.
    function revoke(bytes32 id, uint16 reasonCode) external {
        Attestation storage a = _known(id);
        if (msg.sender != a.attester) revert NotAttester();
        if (_revoked[id]) revert AlreadyRevoked();
        _revoked[id] = true;
        revokedCount[a.agentId] += 1;
        emit Revoked(id, reasonCode);
    }

    /// @notice A counterparty records that it received the work. Not an approval of quality.
    function acknowledge(bytes32 id) external {
        Attestation storage a = _known(id);
        if (msg.sender == a.attester) revert SelfAcknowledge();
        if (_revoked[id]) revert AlreadyRevoked();
        if (acknowledged[id][msg.sender]) revert AlreadyAcknowledged();
        acknowledged[id][msg.sender] = true;
        emit Acknowledged(id, msg.sender);
    }

    // ------------------------------------------------------------------ reads

    function get(bytes32 id) external view returns (Attestation memory, bool revoked) {
        return (_known(id), _revoked[id]);
    }

    function countByAgent(uint256 agentId) external view returns (uint256) {
        return _byAgent[agentId].length;
    }

    /// In attestation order. An out-of-range `start` or a large `count` returns the tail.
    function byAgent(uint256 agentId, uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        bytes32[] storage all = _byAgent[agentId];
        uint256 n = all.length;
        if (start >= n) return new bytes32[](0);
        uint256 avail = n - start;
        uint256 len = count < avail ? count : avail;
        out = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = all[start + i];
        }
    }

    function _known(bytes32 id) internal view returns (Attestation storage a) {
        a = _attestations[id];
        if (a.attester == address(0)) revert UnknownAttestation(id);
    }
}
