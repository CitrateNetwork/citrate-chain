// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title CapsuleRegistry — RFC-CIT-AGENT-0001 §4 + planset
///        06_ON_CHAIN_SURFACE.md "CapsuleRegistry".
///
/// ERC-1155 base. Each capsule has a unique tokenId equal to its
/// content hash; the supply field denotes how many active install
/// instances exist across the network. `mint` records the capsule's
/// manifest hash + publisher DID + signing tier. `revoke` marks the
/// capsule as recalled (the runtime refuses to load revoked
/// capsules per the planset Hermes-deprecation table).
///
/// CIT-AGENT-6a: minting authority depends on the signing tier:
///   * bundled — admin (`onlyOwner`)
///   * managed — any caller (per-org enforcement happens off-chain)
///   * workspace — any caller
///
/// CIT-AGENT-6b will refine this with the org-tier signature check.
contract CapsuleRegistry is ERC1155, Ownable {
    enum SigningTier { Bundled, Managed, Workspace }

    struct Capsule {
        bytes32 manifest_hash;       // SHA-256 of manifest.toml canonical
        bytes32 publisher_did;       // hash of did:citrate:agent:0x...
        SigningTier tier;
        bool revoked;
        uint256 registered_at;
    }

    mapping(uint256 => Capsule) private _capsules;

    error AlreadyRegistered();
    error NotRegistered();
    error BundledRequiresAdmin();
    error CapsuleAlreadyRevoked();
    error TransferNotAllowed();

    event CapsuleRegistered(
        uint256 indexed capsule_id,
        bytes32 indexed manifest_hash,
        bytes32 indexed publisher_did,
        SigningTier tier
    );
    event CapsuleRevoked(uint256 indexed capsule_id);

    constructor(address initialOwner)
        ERC1155("https://citrate.ai/capsule/{id}")
        Ownable(initialOwner)
    {}

    /// Register a new capsule + mint one instance to the caller. The
    /// caller MUST be the deployer (admin) for Bundled tier; Managed
    /// and Workspace tier accept any caller.
    function registerCapsule(
        uint256 capsule_id,
        bytes32 manifest_hash,
        bytes32 publisher_did,
        SigningTier tier
    ) external {
        if (_capsules[capsule_id].registered_at != 0) {
            revert AlreadyRegistered();
        }
        if (tier == SigningTier.Bundled && msg.sender != owner()) {
            revert BundledRequiresAdmin();
        }
        _capsules[capsule_id] = Capsule({
            manifest_hash: manifest_hash,
            publisher_did: publisher_did,
            tier: tier,
            revoked: false,
            registered_at: block.timestamp
        });
        _mint(msg.sender, capsule_id, 1, "");
        emit CapsuleRegistered(capsule_id, manifest_hash, publisher_did, tier);
    }

    /// Revoke a capsule. Admin-gated in 6a; 6b adds multi-sig
    /// (Compliance Officer + Security Officer) per planset 06.
    function revokeCapsule(uint256 capsule_id) external onlyOwner {
        Capsule storage c = _capsules[capsule_id];
        if (c.registered_at == 0) revert NotRegistered();
        if (c.revoked) revert CapsuleAlreadyRevoked();
        c.revoked = true;
        emit CapsuleRevoked(capsule_id);
    }

    function getCapsule(uint256 capsule_id) external view returns (Capsule memory) {
        return _capsules[capsule_id];
    }

    function isRevoked(uint256 capsule_id) external view returns (bool) {
        return _capsules[capsule_id].revoked;
    }

    // ── Soulbound: capsule install instances are not transferable ──
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override
    {
        // Mint (from = 0) and burn (to = 0) allowed; transfers revert.
        if (from != address(0) && to != address(0)) {
            revert TransferNotAllowed();
        }
        super._update(from, to, ids, values);
    }
}
