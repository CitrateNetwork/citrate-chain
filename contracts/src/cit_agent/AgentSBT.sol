// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./OrganizationSBT.sol";

/// @title AgentSBT — RFC-CIT-AGENT-0001 §3.1 + planset
///        06_ON_CHAIN_SURFACE.md "AgentSBT".
///
/// Soulbound (non-transferable) ERC-721. Each agent is tied to a
/// parent OrganizationSBT; minting requires the parent org to be
/// `active`. The `pubkey_fingerprint` field matches the cit-agent
/// runtime's `hitl::signer_id_from_pubkey` computation so on-chain
/// identity binds to the off-chain signing-surface identity.
contract AgentSBT is ERC721, Ownable {
    struct Agent {
        uint256 parent_org_id;
        bytes32 did;
        bytes32 pubkey_fingerprint;
        bool quarantined;
    }

    mapping(uint256 => Agent) private _agents;
    mapping(uint256 => uint256[]) private _agentsByOrg;
    uint256 public nextTokenId;

    /// Reference to the OrganizationSBT contract for parent-org lookup.
    OrganizationSBT public immutable orgContract;

    error TransferNotAllowed();
    error OrgNotActive();

    event AgentMinted(
        uint256 indexed tokenId,
        uint256 indexed parent_org_id,
        bytes32 indexed did,
        bytes32 pubkey_fingerprint
    );
    event AgentQuarantined(uint256 indexed tokenId);
    event AgentUnquarantined(uint256 indexed tokenId);

    constructor(address initialOwner, OrganizationSBT _orgContract)
        ERC721("Citrate AgentSBT", "CIT-AGENT")
        Ownable(initialOwner)
    {
        orgContract = _orgContract;
    }

    /// Mint a new AgentSBT under a parent OrganizationSBT. Reverts
    /// if the parent org is not active.
    function mintAgent(
        address to,
        uint256 parent_org_id,
        bytes32 did,
        bytes32 pubkey_fingerprint
    ) external onlyOwner returns (uint256 tokenId) {
        if (!orgContract.isActive(parent_org_id)) {
            revert OrgNotActive();
        }
        tokenId = nextTokenId++;
        _agents[tokenId] = Agent({
            parent_org_id: parent_org_id,
            did: did,
            pubkey_fingerprint: pubkey_fingerprint,
            quarantined: false
        });
        _agentsByOrg[parent_org_id].push(tokenId);
        _safeMint(to, tokenId);
        emit AgentMinted(tokenId, parent_org_id, did, pubkey_fingerprint);
    }

    function getAgent(uint256 tokenId) external view returns (Agent memory) {
        return _agents[tokenId];
    }

    function getAgentsForOrg(uint256 org_id) external view returns (uint256[] memory) {
        return _agentsByOrg[org_id];
    }

    /// Quarantine an agent. The `Quarantine` event in the audit
    /// chain (per planset 05 EventType::Quarantine) is the off-chain
    /// twin of this transition.
    function quarantine(uint256 tokenId) external onlyOwner {
        _agents[tokenId].quarantined = true;
        emit AgentQuarantined(tokenId);
    }

    function unquarantine(uint256 tokenId) external onlyOwner {
        _agents[tokenId].quarantined = false;
        emit AgentUnquarantined(tokenId);
    }

    // ── Soulbound enforcement ──────────────────────────────────────

    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            revert TransferNotAllowed();
        }
        return super._update(to, tokenId, auth);
    }
}
