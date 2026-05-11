// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SponsorEvidenceRegistry — BFR-16 sponsor evidence bundle anchoring.
/// @notice Per planset 04_FEDRAMP_COMPLIANCE.md § FedRAMP sponsor
///         evidence package. Anchors signed evidence-bundle manifests
///         (the merkle root over the package contents) so any sponsor
///         or 3PAO can verify offline.
///
/// @dev Each manifest has:
///        - bundle_id (caller-chosen, typically keccak of contents)
///        - merkle_root (over the package files)
///        - sponsor_kind (caller-defined enum: 0=DOD, 1=AFWERX/SOFWERX,
///          2=FedRAMP-PMO, 3=Other; opaque to contract)
///        - ipfs_cid (full bundle bytes)
///        - signers (recorder identity + post-anchor sponsor sigs)
///
/// @dev Sponsors can add countersignatures via `addSponsorSignature`.
///      This produces a tamper-evident chain of co-attestation.
///
/// @dev Append-only: bundle_id recorded exactly once.
contract SponsorEvidenceRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error BundleAlreadyExists(bytes32 bundle_id);
    error UnknownBundle(bytes32 bundle_id);
    error ZeroBundleId();
    error InvalidSponsorKind(uint8 kind);
    error DuplicateSponsor(bytes32 bundle_id, bytes32 sponsor);

    // ── Types ──────────────────────────────────────────────────────────

    struct EvidenceBundle {
        bytes32 bundle_id;
        bytes32 merkle_root;
        bytes32 ipfs_cid;
        bytes32 anchored_by;        // recorder identity (typically Boeing IT)
        uint8   sponsor_kind;       // 0=DOD, 1=AFWERX/SOFWERX, 2=FedRAMP-PMO, 3=Other
        uint256 anchored_at_block;
        uint256 sponsor_sig_count;  // count of post-anchor sponsor signatures
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;
    mapping(address => bool) public is_recorder;

    /// @notice bundle_id → record.
    mapping(bytes32 => EvidenceBundle) public bundles;
    mapping(bytes32 => bool) public exists;

    /// @notice bundle_id → sponsor identity → has-signed.
    mapping(bytes32 => mapping(bytes32 => bool)) public sponsorHasSigned;
    /// @notice bundle_id → sponsor signers (append-only).
    mapping(bytes32 => bytes32[]) public sponsorSigners;

    /// @notice scope → bundle_ids (append-only).
    mapping(bytes32 => bytes32[]) public bundlesByKind;
    /// @notice All bundle_ids.
    bytes32[] public allBundleIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Anchored(
        bytes32 indexed bundle_id,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint8 indexed sponsor_kind
    );
    event SponsorSigned(
        bytes32 indexed bundle_id,
        bytes32 indexed sponsor,
        uint256 sig_count
    );

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Anchor a new evidence bundle.
    function anchor(
        bytes32 bundle_id,
        bytes32 merkle_root,
        bytes32 ipfs_cid,
        uint8 sponsor_kind
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (bundle_id == bytes32(0)) revert ZeroBundleId();
        if (sponsor_kind > 3) revert InvalidSponsorKind(sponsor_kind);
        if (exists[bundle_id]) revert BundleAlreadyExists(bundle_id);

        bundles[bundle_id] = EvidenceBundle({
            bundle_id: bundle_id,
            merkle_root: merkle_root,
            ipfs_cid: ipfs_cid,
            anchored_by: bytes32(uint256(uint160(msg.sender))),
            sponsor_kind: sponsor_kind,
            anchored_at_block: block.number,
            sponsor_sig_count: 0
        });
        exists[bundle_id] = true;
        bundlesByKind[bytes32(uint256(sponsor_kind))].push(bundle_id);
        allBundleIds.push(bundle_id);

        emit Anchored(bundle_id, merkle_root, ipfs_cid, sponsor_kind);
    }

    /// @notice Add a sponsor countersignature. Idempotent per
    ///         (bundle_id, sponsor); duplicate signers revert.
    ///         Permissionless — anyone can call on behalf of a sponsor
    ///         identity (the sponsor identity is opaque bytes32; off-chain
    ///         verification is recorder/sponsor responsibility).
    function addSponsorSignature(bytes32 bundle_id, bytes32 sponsor) external {
        if (!exists[bundle_id]) revert UnknownBundle(bundle_id);
        if (sponsorHasSigned[bundle_id][sponsor]) {
            revert DuplicateSponsor(bundle_id, sponsor);
        }

        sponsorHasSigned[bundle_id][sponsor] = true;
        sponsorSigners[bundle_id].push(sponsor);
        bundles[bundle_id].sponsor_sig_count =
            bundles[bundle_id].sponsor_sig_count + 1;

        emit SponsorSigned(
            bundle_id,
            sponsor,
            bundles[bundle_id].sponsor_sig_count
        );
    }

    // ── Views ──────────────────────────────────────────────────────────

    function getBundle(bytes32 bundle_id) external view returns (EvidenceBundle memory) {
        return bundles[bundle_id];
    }

    function signersOf(bytes32 bundle_id) external view returns (bytes32[] memory) {
        return sponsorSigners[bundle_id];
    }

    function byKind(uint8 sponsor_kind) external view returns (bytes32[] memory) {
        return bundlesByKind[bytes32(uint256(sponsor_kind))];
    }

    function allBundles() external view returns (bytes32[] memory) {
        return allBundleIds;
    }

    function bundleCount() external view returns (uint256) {
        return allBundleIds.length;
    }

    function countByKind(uint8 sponsor_kind) external view returns (uint256) {
        return bundlesByKind[bytes32(uint256(sponsor_kind))].length;
    }
}
