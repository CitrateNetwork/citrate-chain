// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title ReleaseManifestRegistry — DPF-17 release artifact anchor.
/// @notice Per NIST 800-53r5 SI-7 "Software, Firmware, Information
///         Integrity". Anchors release artifact manifests (sha256
///         per binary + GPG/notarize signature blob hash) as
///         immutable on-chain records.
///
/// @dev 6-state release lifecycle (mirrors
///      ReleaseManifestLifecycle.tla):
///        0 = NotStarted (sentinel)
///        1 = Drafted    (operator opened release)
///        2 = Building   (build pipeline running)
///        3 = Tested     (all artifacts pass perf gates + visual proofs)
///        4 = Notarized  (codesign + GPG signed)
///        5 = Published  (terminal-positive; manifest anchored)
///        6 = Withdrawn  (terminal-negative)
///
/// @dev Artifact addition only allowed in Drafted/Building.
///      Once Published, the manifest is immutable forever.
contract ReleaseManifestRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error ReleaseAlreadyDrafted(bytes32 release_id);
    error NotInState(bytes32 release_id, uint8 expected, uint8 actual);
    error UnknownRelease(bytes32 release_id);
    error TestedRequiresArtifacts(bytes32 release_id);
    error ZeroReleaseId();
    error ZeroArtifactHash();

    // ── Types ──────────────────────────────────────────────────────────

    struct Release {
        bytes32 release_id;         // e.g., keccak("v0.5.0")
        bytes32 version_tag;        // e.g., keccak("v0.5.0")
        bytes32 drafted_by;         // recorder identity
        uint8   state;
        uint8   artifact_count;
        uint256 drafted_at_block;
        uint256 published_at_block; // 0 until Published
    }

    struct Artifact {
        bytes32 artifact_hash;      // sha256 of the binary
        bytes32 signature_hash;     // sha256 of codesign / GPG blob
        bytes32 platform;           // e.g., keccak("linux-x86_64-deb")
        uint256 size_bytes;
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;
    mapping(address => bool) public is_recorder;

    mapping(bytes32 => Release) public releases;
    mapping(bytes32 => bool) public exists;

    /// @notice release_id → list of artifacts (append-only during
    ///         Drafted/Building only).
    mapping(bytes32 => Artifact[]) public artifactsOf;

    /// @notice version_tag → release_ids (append-only).
    mapping(bytes32 => bytes32[]) public releasesByVersionTag;

    /// @notice All release_ids in insertion order.
    bytes32[] public allReleaseIds;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);
    event Drafted(bytes32 indexed release_id, bytes32 indexed version_tag);
    event ArtifactAdded(
        bytes32 indexed release_id,
        bytes32 indexed platform,
        bytes32 artifact_hash,
        uint8 artifact_idx
    );
    event StateChanged(bytes32 indexed release_id, uint8 from_state, uint8 to_state);

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

    /// @notice Draft a new release.
    function draftRelease(bytes32 release_id, bytes32 version_tag) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (release_id == bytes32(0)) revert ZeroReleaseId();
        if (exists[release_id]) revert ReleaseAlreadyDrafted(release_id);

        releases[release_id] = Release({
            release_id: release_id,
            version_tag: version_tag,
            drafted_by: bytes32(uint256(uint160(msg.sender))),
            state: 1, // Drafted
            artifact_count: 0,
            drafted_at_block: block.number,
            published_at_block: 0
        });
        exists[release_id] = true;
        releasesByVersionTag[version_tag].push(release_id);
        allReleaseIds.push(release_id);

        emit Drafted(release_id, version_tag);
    }

    /// @notice Add an artifact hash. Only allowed in Drafted (1) or Building (2).
    function addArtifact(
        bytes32 release_id,
        bytes32 platform,
        bytes32 artifact_hash,
        bytes32 signature_hash,
        uint256 size_bytes
    ) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (artifact_hash == bytes32(0)) revert ZeroArtifactHash();
        Release storage r = releases[release_id];
        if (r.state != 1 && r.state != 2) revert NotInState(release_id, 1, r.state);

        artifactsOf[release_id].push(
            Artifact({
                artifact_hash: artifact_hash,
                signature_hash: signature_hash,
                platform: platform,
                size_bytes: size_bytes
            })
        );
        uint8 idx = uint8(artifactsOf[release_id].length - 1);
        r.artifact_count = r.artifact_count + 1;

        emit ArtifactAdded(release_id, platform, artifact_hash, idx);
    }

    /// @notice Transition Drafted (1) → Building (2).
    function beginBuild(bytes32 release_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Release storage r = releases[release_id];
        if (r.state != 1) revert NotInState(release_id, 1, r.state);
        uint8 prev = r.state;
        r.state = 2;
        emit StateChanged(release_id, prev, 2);
    }

    /// @notice Transition Building (2) → Tested (3). Requires ≥1 artifact.
    function markTested(bytes32 release_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Release storage r = releases[release_id];
        if (r.state != 2) revert NotInState(release_id, 2, r.state);
        if (r.artifact_count == 0) revert TestedRequiresArtifacts(release_id);
        r.state = 3;
        emit StateChanged(release_id, 2, 3);
    }

    /// @notice Transition Tested (3) → Notarized (4).
    function markNotarized(bytes32 release_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Release storage r = releases[release_id];
        if (r.state != 3) revert NotInState(release_id, 3, r.state);
        r.state = 4;
        emit StateChanged(release_id, 3, 4);
    }

    /// @notice Transition Notarized (4) → Published (5). Permissionless.
    function publish(bytes32 release_id) external {
        Release storage r = releases[release_id];
        if (r.state != 4) revert NotInState(release_id, 4, r.state);
        r.state = 5;
        r.published_at_block = block.number;
        emit StateChanged(release_id, 4, 5);
    }

    /// @notice Withdraw from any non-terminal state.
    function withdraw(bytes32 release_id) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        Release storage r = releases[release_id];
        if (r.state == 0 || r.state >= 5) revert NotInState(release_id, 1, r.state);
        uint8 prev = r.state;
        r.state = 6;
        emit StateChanged(release_id, prev, 6);
    }

    // ── Views ──────────────────────────────────────────────────────────

    function getRelease(bytes32 release_id) external view returns (Release memory) {
        return releases[release_id];
    }

    function artifacts(bytes32 release_id) external view returns (Artifact[] memory) {
        return artifactsOf[release_id];
    }

    function artifactCount(bytes32 release_id) external view returns (uint256) {
        return artifactsOf[release_id].length;
    }

    function byVersionTag(bytes32 version_tag) external view returns (bytes32[] memory) {
        return releasesByVersionTag[version_tag];
    }

    function allReleases() external view returns (bytes32[] memory) {
        return allReleaseIds;
    }

    function releaseCount() external view returns (uint256) {
        return allReleaseIds.length;
    }
}
