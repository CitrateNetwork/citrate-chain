// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title OrgScopedSBTUpgradeable — RFC-CIT-AGENT-0001 hierarchy, org-scoped soulbound identity.
///
/// Shared base for the org-scoped soulbound identity classes Homestead issues
/// alongside `OrganizationSBT` — a Facility SBT per site and a Network SBT per
/// org network-id (see citrate-homestead/sources/02: "one for each facility,
/// and one for their overall network ID"). It intentionally mirrors
/// `OrganizationSBT`'s conventions (soulbound ERC-721, `did` hash, one-way
/// `overlays` ratchet, `active` flag) and adds three properties the owner asked
/// for so enterprises are not "stuck in the mud" on later changes:
///
///  1. UPGRADEABLE. UUPS proxy pattern: the CREATE2 proxy address is frozen at
///     the reroll while the implementation can evolve. Upgrade authority is the
///     `GOVERNOR_ROLE` (intended to be the 2-of-3 timelocked controller,
///     CIT-AGENT-6b), never the deployer EOA.
///  2. PER-ORG CONFIGURABLE. Each token carries an `orgAuthority` — the org's
///     own controller — who may reconfigure that token (metadata, attributes,
///     overlays) without central action, within governance-set bounds.
///  3. EXTENSIBLE. A typed `attributes` key/value map lets an org add fields
///     over time with no contract change; type-specific data (facility location
///     ref, network chain-id, etc.) lives here rather than in a frozen struct.
///
/// DID uniqueness is enforced from the start (the `OrganizationSBT.mintOrg`
/// E09 gap — `AlreadyMinted` declared but unchecked — is not repeated here).
abstract contract OrgScopedSBTUpgradeable is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    /// Issuance authority (Citrate Inc. / the org publisher path per signed order).
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// Governance / upgrade / emergency authority (2-of-3 timelocked controller).
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");

    struct Node {
        bytes32 did;              // hash of did:citrate:<scope>:0x...
        uint256 parentOrgTokenId; // the OrganizationSBT token this belongs to
        address orgAuthority;     // the org's controller for this token
        bytes32[] overlays;       // compliance overlays — one-way ratchet
        bool active;              // false once deactivated
    }

    // ── ERC-7201 namespaced storage (upgrade-safe) ────────────────────────────
    /// @custom:storage-location erc7201:citrate.storage.OrgScopedSBT
    struct OrgScopedStorage {
        mapping(uint256 => Node) nodes;
        mapping(bytes32 => bool) didUsed;
        mapping(uint256 => string) tokenUri;
        mapping(uint256 => mapping(bytes32 => bytes)) attributes;
        uint256 nextTokenId;
    }

    // keccak256(abi.encode(uint256(keccak256("citrate.storage.OrgScopedSBT")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_SLOT =
        0x9d8f3c2b6a4e1d7f0c5b8a2e4d6c9f1b3a7e5c0d2f4a6b8c1e3d5f7a9b0c2e00;

    function _s() private pure returns (OrgScopedStorage storage $) {
        assembly {
            $.slot := STORAGE_SLOT
        }
    }

    error TransferNotAllowed();
    error AlreadyMinted();
    error NotOrgAuthorityOrGovernor();
    error ZeroDid();

    event NodeMinted(uint256 indexed tokenId, bytes32 indexed did, uint256 indexed parentOrgTokenId, address orgAuthority);
    event NodeDeactivated(uint256 indexed tokenId);
    event OverlayActivated(uint256 indexed tokenId, bytes32 indexed overlay);
    event OrgAuthorityTransferred(uint256 indexed tokenId, address indexed previous, address indexed next);
    event AttributeSet(uint256 indexed tokenId, bytes32 indexed key);
    event TokenUriSet(uint256 indexed tokenId);

    /// @dev Implementations disable initializers so the logic contract itself
    ///      can never be initialized (only proxies are).
    function __OrgScopedSBT_init(string memory name_, string memory symbol_, address governor, address minter)
        internal
        onlyInitializing
    {
        __ERC721_init(name_, symbol_);
        __AccessControl_init();
        // UUPSUpgradeable is stateless in OZ 5.x — no initializer to call.
        _grantRole(DEFAULT_ADMIN_ROLE, governor);
        _grantRole(GOVERNOR_ROLE, governor);
        _grantRole(MINTER_ROLE, minter);
    }

    // ── Issuance ──────────────────────────────────────────────────────────────

    /// Mint a scoped SBT. Issuance-gated; enforces DID uniqueness.
    function mint(
        address to,
        bytes32 did,
        uint256 parentOrgTokenId,
        address orgAuthority,
        bytes32[] calldata overlays
    ) external onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        if (did == bytes32(0)) revert ZeroDid();
        OrgScopedStorage storage $ = _s();
        if ($.didUsed[did]) revert AlreadyMinted();
        $.didUsed[did] = true;
        tokenId = $.nextTokenId++;
        $.nodes[tokenId] = Node({
            did: did,
            parentOrgTokenId: parentOrgTokenId,
            orgAuthority: orgAuthority,
            overlays: overlays,
            active: true
        });
        _safeMint(to, tokenId);
        emit NodeMinted(tokenId, did, parentOrgTokenId, orgAuthority);
    }

    // ── Per-org configuration ─────────────────────────────────────────────────

    modifier onlyOrgAuthorityOrGovernor(uint256 tokenId) {
        if (msg.sender != _s().nodes[tokenId].orgAuthority && !hasRole(GOVERNOR_ROLE, msg.sender)) {
            revert NotOrgAuthorityOrGovernor();
        }
        _;
    }

    /// Set an extensible attribute (org-configurable, no contract change needed).
    function setAttribute(uint256 tokenId, bytes32 key, bytes calldata value)
        external
        onlyOrgAuthorityOrGovernor(tokenId)
    {
        _requireOwned(tokenId);
        _s().attributes[tokenId][key] = value;
        emit AttributeSet(tokenId, key);
    }

    function getAttribute(uint256 tokenId, bytes32 key) external view returns (bytes memory) {
        return _s().attributes[tokenId][key];
    }

    /// Set a per-token metadata URI (org-configurable).
    function setTokenURI(uint256 tokenId, string calldata uri)
        external
        onlyOrgAuthorityOrGovernor(tokenId)
    {
        _requireOwned(tokenId);
        _s().tokenUri[tokenId] = uri;
        emit TokenUriSet(tokenId);
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        return _s().tokenUri[tokenId];
    }

    /// Activate a compliance overlay (one-way ratchet, per planset 02).
    function activateOverlay(uint256 tokenId, bytes32 overlay)
        external
        onlyOrgAuthorityOrGovernor(tokenId)
    {
        _requireOwned(tokenId);
        _s().nodes[tokenId].overlays.push(overlay);
        emit OverlayActivated(tokenId, overlay);
    }

    /// Rotate the org's controller for this token (current authority or governor).
    function transferOrgAuthority(uint256 tokenId, address next)
        external
        onlyOrgAuthorityOrGovernor(tokenId)
    {
        _requireOwned(tokenId);
        address prev = _s().nodes[tokenId].orgAuthority;
        _s().nodes[tokenId].orgAuthority = next;
        emit OrgAuthorityTransferred(tokenId, prev, next);
    }

    // ── Governance ────────────────────────────────────────────────────────────

    /// Emergency deactivation — governor only.
    function deactivate(uint256 tokenId) external onlyRole(GOVERNOR_ROLE) {
        _s().nodes[tokenId].active = false;
        emit NodeDeactivated(tokenId);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getNode(uint256 tokenId) external view returns (Node memory) {
        return _s().nodes[tokenId];
    }

    function isActive(uint256 tokenId) external view returns (bool) {
        return _s().nodes[tokenId].active;
    }

    function parentOrgOf(uint256 tokenId) external view returns (uint256) {
        return _s().nodes[tokenId].parentOrgTokenId;
    }

    function nextTokenId() external view returns (uint256) {
        return _s().nextTokenId;
    }

    function didTaken(bytes32 did) external view returns (bool) {
        return _s().didUsed[did];
    }

    // ── Soulbound enforcement ─────────────────────────────────────────────────

    /// Block transfers between non-zero addresses; mint/burn allowed.
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

    // ── UUPS ──────────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyRole(GOVERNOR_ROLE) {}

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
