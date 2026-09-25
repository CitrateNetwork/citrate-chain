// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title OrganizationSBT — RFC-CIT-AGENT-0001 §3.1 + planset
///        06_ON_CHAIN_SURFACE.md "OrganizationSBT".
///
/// Soulbound (non-transferable) ERC-721. One token per organization
/// in the cit-agent trust hierarchy. The organization's
/// `signing_authority` is the managed-tier publisher key the harness
/// trusts for capsule signing under that org's policy bundle.
///
/// CIT-AGENT-6a: admin is the deployer (`onlyOwner`). CIT-AGENT-6b
/// replaces this with the 2-of-3 timelocked controller.
contract OrganizationSBT is ERC721, Ownable {
    struct Org {
        bytes32 did;                 // hash of did:citrate:org:0x...
        address signing_authority;   // org's managed-tier publisher key
        bytes32[] active_overlays;   // FedRAMP / HIPAA / FERPA / etc.
        bool active;                 // true unless emergency-deactivated
    }

    /// Token id → org metadata.
    mapping(uint256 => Org) private _orgs;
    /// did → minted. Enforces one-org-per-DID (E09: `OrgAlreadyMinted` was
    /// declared but never checked, so a DID could be minted repeatedly).
    mapping(bytes32 => bool) private _didUsed;
    uint256 public nextTokenId;

    error TransferNotAllowed();
    error OrgNotActive();
    error OrgAlreadyMinted();

    event OrgMinted(uint256 indexed tokenId, bytes32 indexed did, address signing_authority);
    event OrgDeactivated(uint256 indexed tokenId);
    event OverlayActivated(uint256 indexed tokenId, bytes32 indexed overlay);

    constructor(address initialOwner) ERC721("Citrate OrganizationSBT", "CIT-ORG") Ownable(initialOwner) {
        InitialAdmin.check(initialOwner); // PBA-L2-002: never the CREATE2 factory
    }

    /// Mint a new OrganizationSBT. Admin-gated in 6a.
    function mintOrg(
        address to,
        bytes32 did,
        address signing_authority,
        bytes32[] calldata overlays
    ) external onlyOwner returns (uint256 tokenId) {
        if (_didUsed[did]) revert OrgAlreadyMinted();
        _didUsed[did] = true;
        tokenId = nextTokenId++;
        _orgs[tokenId] = Org({
            did: did,
            signing_authority: signing_authority,
            active_overlays: overlays,
            active: true
        });
        _safeMint(to, tokenId);
        emit OrgMinted(tokenId, did, signing_authority);
    }

    function getOrg(uint256 tokenId) external view returns (Org memory) {
        return _orgs[tokenId];
    }

    function isActive(uint256 tokenId) external view returns (bool) {
        return _orgs[tokenId].active;
    }

    /// Emergency deactivation. 6a: admin-gated; 6b: timelocked.
    function deactivate(uint256 tokenId) external onlyOwner {
        _orgs[tokenId].active = false;
        emit OrgDeactivated(tokenId);
    }

    /// Activate an overlay on an existing org. Overlays are a
    /// one-way ratchet per planset 02 — `not_certified` becomes
    /// `certified`, never the reverse.
    function activateOverlay(uint256 tokenId, bytes32 overlay) external onlyOwner {
        _orgs[tokenId].active_overlays.push(overlay);
        emit OverlayActivated(tokenId, overlay);
    }

    // ── Soulbound enforcement ──────────────────────────────────────

    /// Overrides ERC721's `_update` to block transfers between
    /// non-zero addresses. Mint (from = 0) and burn (to = 0) are
    /// allowed; transfers revert.
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
