// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/Governable.sol";

/// @title SpecRegistry
/// @notice On-chain registry mapping operation domains to behavioral specifications
/// stored on IPFS as Gherkin feature files. Agents MUST check relevant specs
/// before executing critical on-chain operations.
///
/// Sprint HARDEN — WP-H.14
/// RM-L / WP-L1.1: migrated to the standardized `Governable` two-step
/// transfer mixin. Pre-migration the contract had its own
/// `transferGovernor(newGovernor)` that wrote the new address atomically
/// — a mistyped or revoked-key successor silently locked governance
/// forever. Post-migration the new account must call
/// `acceptGovernance()` to take effect; `cancelGovernanceTransfer()`
/// is also available before acceptance.
contract SpecRegistry is Governable {
    struct Spec {
        string domain;          // e.g., "contract_deploy", "token_transfer"
        string cid;             // IPFS CID of the Gherkin .feature file
        address registrar;      // Who registered this spec
        uint256 registeredAt;   // Block number when registered
        uint256 version;        // Monotonically increasing version
        bool active;            // Whether this spec is currently enforced
    }

    /// Domain → Spec mapping
    mapping(string => Spec) public specs;

    /// All registered domains (for enumeration)
    string[] public domains;

    /// Domain count
    uint256 public domainCount;

    // RM-L / WP-L1.1: `governor` field removed; `governance()` from
    // the Governable mixin is the single source of truth.
    // `onlyGovernor` modifier removed; `onlyGovernance` from the mixin
    // is used throughout.

    // ── Events ──────────────────────────────────────────────────────

    event SpecRegistered(string indexed domain, string cid, uint256 version);
    event SpecUpdated(string indexed domain, string oldCid, string newCid, uint256 version);
    event SpecDeactivated(string indexed domain);
    event SpecReactivated(string indexed domain);
    // RM-L / WP-L1.1: `GovernorTransferred` removed. Governable emits
    // `GovernanceTransferProposed`, `GovernanceTransferred`, and
    // `GovernanceTransferCancelled` for the two-step semantics.

    // ── Constructor ─────────────────────────────────────────────────

    /// @param initialGovernance Initial governance address (typically the
    /// deployer or the multisig per RM-L1.6 genesis runbook).
    constructor(address initialGovernance) Governable(initialGovernance) {}

    // ── Core Functions ──────────────────────────────────────────────

    /// @notice Register a new behavioral spec for a domain
    /// @param domain Operation domain (e.g., "contract_deploy")
    /// @param cid IPFS CID of the Gherkin feature file
    function registerSpec(
        string calldata domain,
        string calldata cid
    ) external onlyGovernance {
        require(bytes(domain).length > 0, "Domain cannot be empty");
        require(bytes(cid).length > 0, "CID cannot be empty");
        require(bytes(specs[domain].domain).length == 0, "Domain already registered");

        specs[domain] = Spec({
            domain: domain,
            cid: cid,
            registrar: msg.sender,
            registeredAt: block.number,
            version: 1,
            active: true
        });

        domains.push(domain);
        domainCount++;

        emit SpecRegistered(domain, cid, 1);
    }

    /// @notice Update the spec CID for an existing domain
    /// @param domain Operation domain to update
    /// @param newCid New IPFS CID
    function updateSpec(
        string calldata domain,
        string calldata newCid
    ) external onlyGovernance {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(bytes(newCid).length > 0, "CID cannot be empty");

        string memory oldCid = specs[domain].cid;
        specs[domain].cid = newCid;
        specs[domain].version++;

        emit SpecUpdated(domain, oldCid, newCid, specs[domain].version);
    }

    /// @notice Deactivate a spec (agents should skip checking)
    function deactivateSpec(string calldata domain) external onlyGovernance {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(specs[domain].active, "Already deactivated");
        specs[domain].active = false;
        emit SpecDeactivated(domain);
    }

    /// @notice Reactivate a deactivated spec
    function reactivateSpec(string calldata domain) external onlyGovernance {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(!specs[domain].active, "Already active");
        specs[domain].active = true;
        emit SpecReactivated(domain);
    }

    // RM-L / WP-L1.1: legacy `transferGovernor` removed. Use the
    // two-step pattern from `Governable`:
    //   1. current governance calls `transferGovernance(newAddr)`
    //      → emits `GovernanceTransferProposed`,
    //   2. the proposed address calls `acceptGovernance()`
    //      → emits `GovernanceTransferred`,
    //   3. or current governance calls `cancelGovernanceTransfer()`
    //      before acceptance.

    // ── View Functions ──────────────────────────────────────────────

    /// @notice Get the IPFS CID for a domain's spec
    function getSpec(string calldata domain) external view returns (string memory cid, bool active, uint256 version) {
        Spec memory s = specs[domain];
        return (s.cid, s.active, s.version);
    }

    /// @notice Check if a domain has an active spec
    function hasActiveSpec(string calldata domain) external view returns (bool) {
        return bytes(specs[domain].domain).length > 0 && specs[domain].active;
    }

    /// @notice Get all registered domains
    function getAllDomains() external view returns (string[] memory) {
        return domains;
    }
}
