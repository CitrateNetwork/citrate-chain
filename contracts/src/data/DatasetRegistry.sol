// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Governable} from "../lib/Governable.sol";

/// @title DatasetRegistry: versioned, labelled dataset manifests (0.6.0, FLM-CON-2)
/// @notice Spec: citrate-federation `.agentile/planset/2026-11-07-v060/06_CONTRACTS.md` §5 and §6.
///         Ceremony-genesis candidate (owner answer 7, 2026-11-07). Not deployed.
///
///         Holds no funds: no function is payable and there is no `receive` or `fallback`, so a
///         value transfer reverts. Stores no content, only hashes, labels and CIDs.
///
///         Rules:
///         * The publisher of version 1 owns the dataset id for life. Only that owner publishes later
///           versions, and each version's `prev` must equal the latest version's `manifestHash`
///           (a linear hash chain). Version numbers are 1-based.
///         * `manifestHash` is non-zero and differs from `prev`.
///         * `license` is non-empty, at most `MAX_STRING_BYTES` bytes, and not "unknown" in any ASCII
///           letter case (core blocks this earlier; the contract refuses too).
///         * Privacy labels: `Public` = `cid` is the plaintext CID; `Members` and `Group` = `cid` is a
///           ciphertext CID (the key travels over MLS; the contract cannot check this); `IndexOnly`
///           = no content is published, so `cid` must be empty. Every other label needs a non-empty
///           `cid`. `Group` needs a non-zero `groupHash`; every other label needs `groupHash == 0`.
///         * `publisher`, `publishedAt` and `withdrawn` in the calldata must be zero/false; the
///           contract writes `msg.sender`, `block.timestamp` and `false`. Requiring zero (rather than
///           silently ignoring) makes a caller's mistaken assumption fail loudly.
///         * `cid` and `license` are bounded to `MAX_STRING_BYTES` so a publisher cannot grief storage
///           or the indexers that read the events.
///         * Withdraw is sticky and sets only the flag. The publisher may withdraw with a publisher
///           reason code (1..999). Governance (the timelock at genesis) may withdraw any version, but
///           only with a takedown reason code (>= 1000). Governance cannot edit or delete anything.
///           There is no legal review before publishing (owner answer 6); takedown is the remedy.
///         * A withdrawn version stays in the chain: a later version still links to it through `prev`.
contract DatasetRegistry is Governable {
    enum Privacy {
        Public,
        Members,
        Group,
        IndexOnly
    }

    struct Version {
        address publisher; // msg.sender (must be zero in calldata)
        bytes32 manifestHash; // keccak of the manifest JSON
        bytes32 prev; // previous version's manifestHash (0 for v1)
        bytes32 groupHash; // for Group privacy
        string cid; // ciphertext CID unless Public; empty for IndexOnly
        string license; // SPDX id or "LicenseRef-…"
        Privacy privacy;
        uint64 publishedAt; // block.timestamp (must be zero in calldata)
        bool withdrawn; // must be false in calldata
    }

    /// @notice Upper bound on `cid` and `license` byte lengths.
    uint256 public constant MAX_STRING_BYTES = 256;
    /// @notice Publisher reason codes are 1..999; governance takedown codes start here.
    uint16 public constant TAKEDOWN_REASON_MIN = 1000;

    mapping(bytes32 datasetId => address) private _owner;
    mapping(bytes32 datasetId => Version[]) private _versions;

    event DatasetPublished(
        bytes32 indexed datasetId, uint32 version, address indexed publisher, Privacy privacy, string license
    );
    event DatasetWithdrawn(bytes32 indexed datasetId, uint32 version, uint16 reason);

    error NotDatasetOwner();
    error BadPrev();
    error ZeroManifestHash();
    error ManifestUnchanged();
    error BadLicense();
    error BadCid();
    error BadGroupHash();
    error ReservedFieldSet();
    error StringTooLong();
    error UnknownVersion();
    error AlreadyWithdrawn();
    error BadReason();
    error NotAuthorized();
    error TooManyVersions();

    constructor(address governance_) Governable(governance_) {}

    // ── writes ──────────────────────────────────────────────────────

    /// @notice Publish the next version of `datasetId`. The first publisher owns the id.
    function publish(bytes32 datasetId, Version calldata v) external returns (uint32 version) {
        if (v.publisher != address(0) || v.publishedAt != 0 || v.withdrawn) revert ReservedFieldSet();
        if (v.manifestHash == bytes32(0)) revert ZeroManifestHash();
        if (v.manifestHash == v.prev) revert ManifestUnchanged();

        Version[] storage vs = _versions[datasetId];
        uint256 n = vs.length;
        if (n == 0) {
            if (v.prev != bytes32(0)) revert BadPrev();
        } else {
            if (msg.sender != _owner[datasetId]) revert NotDatasetOwner();
            if (v.prev != vs[n - 1].manifestHash) revert BadPrev();
        }
        if (n >= type(uint32).max) revert TooManyVersions();

        _checkLicense(v.license);
        uint256 cidLen = bytes(v.cid).length;
        if (cidLen > MAX_STRING_BYTES) revert StringTooLong();
        if (v.privacy == Privacy.IndexOnly ? cidLen != 0 : cidLen == 0) revert BadCid();
        if (v.privacy == Privacy.Group ? v.groupHash == bytes32(0) : v.groupHash != bytes32(0)) {
            revert BadGroupHash();
        }

        if (n == 0) _owner[datasetId] = msg.sender;
        _versions[datasetId].push(
            Version({
                publisher: msg.sender,
                manifestHash: v.manifestHash,
                prev: v.prev,
                groupHash: v.groupHash,
                cid: v.cid,
                license: v.license,
                privacy: v.privacy,
                publishedAt: uint64(block.timestamp),
                withdrawn: false
            })
        );
        version = uint32(n + 1);
        emit DatasetPublished(datasetId, version, msg.sender, v.privacy, v.license);
    }

    /// @notice Withdraw one version. Sticky; sets only the flag.
    /// @param reason 1..999 when the dataset owner withdraws; >= 1000 (a takedown code) when
    ///        governance withdraws. 0 is never valid.
    function withdraw(bytes32 datasetId, uint32 version, uint16 reason) external {
        Version storage v = _version(datasetId, version);
        if (v.withdrawn) revert AlreadyWithdrawn();
        if (msg.sender == _owner[datasetId]) {
            if (reason == 0 || reason >= TAKEDOWN_REASON_MIN) revert BadReason();
        } else if (msg.sender == governance()) {
            if (reason < TAKEDOWN_REASON_MIN) revert BadReason();
        } else {
            revert NotAuthorized();
        }
        v.withdrawn = true;
        emit DatasetWithdrawn(datasetId, version, reason);
    }

    // ── views ───────────────────────────────────────────────────────

    function ownerOf(bytes32 datasetId) external view returns (address) {
        return _owner[datasetId];
    }

    function versionCount(bytes32 datasetId) external view returns (uint32) {
        return uint32(_versions[datasetId].length);
    }

    function getVersion(bytes32 datasetId, uint32 version) external view returns (Version memory) {
        return _version(datasetId, version);
    }

    /// @notice The latest version (withdrawn or not) and its number. Reverts if none exists.
    function latest(bytes32 datasetId) external view returns (uint32 version, Version memory v) {
        uint256 n = _versions[datasetId].length;
        if (n == 0) revert UnknownVersion();
        version = uint32(n);
        v = _versions[datasetId][n - 1];
    }

    // ── internals ───────────────────────────────────────────────────

    function _version(bytes32 datasetId, uint32 version) internal view returns (Version storage) {
        Version[] storage vs = _versions[datasetId];
        if (version == 0 || version > vs.length) revert UnknownVersion();
        return vs[version - 1];
    }

    /// @dev Non-empty, bounded, and not "unknown" compared ASCII case-insensitively.
    function _checkLicense(string calldata license) internal pure {
        bytes calldata b = bytes(license);
        if (b.length == 0) revert BadLicense();
        if (b.length > MAX_STRING_BYTES) revert StringTooLong();
        if (b.length == 7) {
            bytes7 word = 0x756e6b6e6f776e; // "unknown"
            bool same = true;
            for (uint256 i = 0; i < 7; i++) {
                bytes1 c = b[i];
                if (c >= 0x41 && c <= 0x5a) c = bytes1(uint8(c) + 32); // A-Z -> a-z
                if (c != word[i]) {
                    same = false;
                    break;
                }
            }
            if (same) revert BadLicense();
        }
    }
}
