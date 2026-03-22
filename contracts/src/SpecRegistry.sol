// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SpecRegistry
/// @notice On-chain registry mapping operation domains to behavioral specifications
/// stored on IPFS as Gherkin feature files. Agents MUST check relevant specs
/// before executing critical on-chain operations.
///
/// Sprint HARDEN — WP-H.14
contract SpecRegistry {
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

    /// Governance: who can register/update specs
    address public governor;

    // ── Events ──────────────────────────────────────────────────────

    event SpecRegistered(string indexed domain, string cid, uint256 version);
    event SpecUpdated(string indexed domain, string oldCid, string newCid, uint256 version);
    event SpecDeactivated(string indexed domain);
    event SpecReactivated(string indexed domain);
    event GovernorTransferred(address indexed oldGovernor, address indexed newGovernor);

    // ── Modifiers ───────────────────────────────────────────────────

    modifier onlyGovernor() {
        require(msg.sender == governor, "Only governor can modify specs");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor() {
        governor = msg.sender;
    }

    // ── Core Functions ──────────────────────────────────────────────

    /// @notice Register a new behavioral spec for a domain
    /// @param domain Operation domain (e.g., "contract_deploy")
    /// @param cid IPFS CID of the Gherkin feature file
    function registerSpec(
        string calldata domain,
        string calldata cid
    ) external onlyGovernor {
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
    ) external onlyGovernor {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(bytes(newCid).length > 0, "CID cannot be empty");

        string memory oldCid = specs[domain].cid;
        specs[domain].cid = newCid;
        specs[domain].version++;

        emit SpecUpdated(domain, oldCid, newCid, specs[domain].version);
    }

    /// @notice Deactivate a spec (agents should skip checking)
    function deactivateSpec(string calldata domain) external onlyGovernor {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(specs[domain].active, "Already deactivated");
        specs[domain].active = false;
        emit SpecDeactivated(domain);
    }

    /// @notice Reactivate a deactivated spec
    function reactivateSpec(string calldata domain) external onlyGovernor {
        require(bytes(specs[domain].domain).length > 0, "Domain not registered");
        require(!specs[domain].active, "Already active");
        specs[domain].active = true;
        emit SpecReactivated(domain);
    }

    /// @notice Transfer governance to a new address
    function transferGovernor(address newGovernor) external onlyGovernor {
        require(newGovernor != address(0), "Cannot transfer to zero address");
        emit GovernorTransferred(governor, newGovernor);
        governor = newGovernor;
    }

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
