// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
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
///
/// Issuance (owner decision 2026-10-04, replaces the registrar default):
///   * `mintAgentAsMember`: any holder of the Citrate membership SBT
///     (`memberSbt.balanceOf(msg.sender) > 0`) mints an agent to itself
///     under the owner-set `memberOrgId`, up to `maxAgentsPerMember`
///     agents per holder (default 5).
///   * `mintAgent`: the owner (timelock) mints to any address under any
///     active org, as before.
/// A DID is minted once across both paths. Holding the membership SBT is
/// the gate: a revoked membership is burned, so its holder no longer
/// qualifies. Membership quarantine and term expiry are not visible from
/// a balance; the owner quarantines the agent for those.
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

    /// The Citrate membership SBT (CitrateMemberSBT) whose holders may mint.
    IERC721 public immutable memberSbt;

    /// Default per-member cap on agents minted through `mintAgentAsMember`.
    uint256 public constant DEFAULT_MAX_AGENTS_PER_MEMBER = 5;

    /// Parent org for member-minted agents (valid only when `memberOrgSet`).
    uint256 public memberOrgId;
    bool public memberOrgSet;
    /// Per-holder cap for `mintAgentAsMember` (owner-settable; 0 pauses member minting).
    uint256 public maxAgentsPerMember;
    /// Agents each holder has minted through `mintAgentAsMember`.
    mapping(address => uint256) public memberAgentCount;
    /// A DID is minted at most once, across both mint paths.
    mapping(bytes32 => bool) public didMinted;

    error TransferNotAllowed();
    error OrgNotActive();
    error ZeroMemberSbt();
    error NotMember();
    error MemberOrgNotSet();
    error MemberAgentCapReached();
    error ZeroDid();
    error ZeroFingerprint();
    error DidAlreadyMinted();

    event AgentMinted(
        uint256 indexed tokenId,
        uint256 indexed parent_org_id,
        bytes32 indexed did,
        bytes32 pubkey_fingerprint
    );
    event AgentQuarantined(uint256 indexed tokenId);
    event AgentUnquarantined(uint256 indexed tokenId);
    event MemberAgentMinted(uint256 indexed tokenId, address indexed member, uint256 memberAgentCount);
    event MemberOrgSet(uint256 indexed orgId);
    event MaxAgentsPerMemberSet(uint256 maxAgents);

    constructor(address initialOwner, OrganizationSBT _orgContract, IERC721 _memberSbt)
        ERC721("Citrate AgentSBT", "CIT-AGENT")
        Ownable(initialOwner)
    {
        InitialAdmin.check(initialOwner); // PBA-L2-002: never the CREATE2 factory
        if (address(_memberSbt) == address(0)) revert ZeroMemberSbt();
        orgContract = _orgContract;
        memberSbt = _memberSbt;
        maxAgentsPerMember = DEFAULT_MAX_AGENTS_PER_MEMBER;
    }

    /// Owner sets the parent org for member-minted agents. The org must be
    /// active now, and is checked again at every member mint.
    function setMemberOrg(uint256 orgId) external onlyOwner {
        if (!orgContract.isActive(orgId)) revert OrgNotActive();
        memberOrgId = orgId;
        memberOrgSet = true;
        emit MemberOrgSet(orgId);
    }

    /// Owner sets the per-member cap (0 pauses member minting).
    function setMaxAgentsPerMember(uint256 maxAgents) external onlyOwner {
        maxAgentsPerMember = maxAgents;
        emit MaxAgentsPerMemberSet(maxAgents);
    }

    /// A membership SBT holder mints an agent to itself under `memberOrgId`.
    function mintAgentAsMember(bytes32 did, bytes32 pubkey_fingerprint) external returns (uint256 tokenId) {
        if (memberSbt.balanceOf(msg.sender) == 0) revert NotMember();
        if (!memberOrgSet) revert MemberOrgNotSet();
        uint256 count = memberAgentCount[msg.sender];
        if (count >= maxAgentsPerMember) revert MemberAgentCapReached();
        memberAgentCount[msg.sender] = count + 1;
        tokenId = _mintAgent(msg.sender, memberOrgId, did, pubkey_fingerprint);
        emit MemberAgentMinted(tokenId, msg.sender, count + 1);
    }

    /// Mint a new AgentSBT under a parent OrganizationSBT. Reverts
    /// if the parent org is not active.
    function mintAgent(
        address to,
        uint256 parent_org_id,
        bytes32 did,
        bytes32 pubkey_fingerprint
    ) external onlyOwner returns (uint256 tokenId) {
        return _mintAgent(to, parent_org_id, did, pubkey_fingerprint);
    }

    /// Shared mint: checks the org, the DID and the fingerprint, writes all
    /// state, then mints (the ERC-721 receiver hook runs last).
    function _mintAgent(address to, uint256 parent_org_id, bytes32 did, bytes32 pubkey_fingerprint)
        internal
        returns (uint256 tokenId)
    {
        if (!orgContract.isActive(parent_org_id)) {
            revert OrgNotActive();
        }
        if (did == bytes32(0)) revert ZeroDid();
        if (pubkey_fingerprint == bytes32(0)) revert ZeroFingerprint();
        if (didMinted[did]) revert DidAlreadyMinted();
        didMinted[did] = true;
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
