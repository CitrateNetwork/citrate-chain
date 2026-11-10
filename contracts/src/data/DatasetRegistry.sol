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
///         * Dataset ids are namespaced by publisher: the top 20 bytes of `datasetId` are the
///           address allowed to publish version 1, and the low 12 bytes are the publisher's own
///           label (`datasetIdFor(publisher, name)` takes the low 96 bits of `keccak256(name)`).
///           Nobody can claim an id in another address's namespace, so copying a pending v1
///           transaction cannot take the id first.
///         * The publisher of version 1 owns the dataset id for life. Only that owner publishes later
///           versions, and each version's `prev` must equal the latest version's `manifestHash`
///           (a linear hash chain). Version numbers are 1-based.
///         * `manifestHash` is non-zero and differs from `prev`.
///         * `license` is non-empty, at most `MAX_STRING_BYTES` bytes, has no leading or trailing
///           ASCII whitespace or control byte, and is neither "unknown" nor the SPDX placeholder
///           "NOASSERTION" in any ASCII letter case (core blocks these earlier; the contract refuses
///           too). The contract does not parse SPDX expressions.
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
///         * A governance takedown freezes the whole dataset id: it never accepts another version
///           (owner decision Q15, 2026-11-09). Withdrawals of its other versions stay possible.
///           The takedown applies whatever the version's state: if the publisher already withdrew
///           the version (for example while the takedown sat in the timelock queue), the takedown
///           still freezes the id. A takedown that changes nothing (version withdrawn, id frozen)
///           succeeds without effect or event, so a second queued operation cannot revert.
///         * Governance that owns a dataset withdraws one version with a publisher code (1..999)
///           and takes the dataset down with a takedown code (>= 1000).
///         * A publisher withdrawal affects one version: a later version still links to the
///           withdrawn one through `prev`.
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
    mapping(bytes32 datasetId => bool) private _frozen;

    event DatasetPublished(
        bytes32 indexed datasetId, uint32 version, address indexed publisher, Privacy privacy, string license
    );
    event DatasetWithdrawn(bytes32 indexed datasetId, uint32 version, uint16 reason);
    /// @notice A governance takedown froze `datasetId`: it can never gain another version.
    event DatasetIdFrozen(bytes32 indexed datasetId, uint32 version, uint16 reason);

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
    error DatasetFrozen();

    constructor(address governance_) Governable(governance_) {}

    /// @notice The dataset id `publisher` publishes `name` under: the publisher address in the top
    ///         20 bytes, the low 96 bits of `keccak256(bytes(name))` below. Core and SDKs derive ids
    ///         this way; any id whose top 20 bytes equal the publisher is accepted.
    function datasetIdFor(address publisher, string calldata name) external pure returns (bytes32) {
        return bytes32((uint256(uint160(publisher)) << 96) | uint256(uint96(uint256(keccak256(bytes(name))))));
    }

    // ── writes ──────────────────────────────────────────────────────

    /// @notice Publish the next version of `datasetId`. The first publisher owns the id.
    function publish(bytes32 datasetId, Version calldata v) external returns (uint32 version) {
        if (v.publisher != address(0) || v.publishedAt != 0 || v.withdrawn) revert ReservedFieldSet();
        if (v.manifestHash == bytes32(0)) revert ZeroManifestHash();
        if (v.manifestHash == v.prev) revert ManifestUnchanged();

        if (_frozen[datasetId]) revert DatasetFrozen();
        Version[] storage vs = _versions[datasetId];
        uint256 n = vs.length;
        if (n == 0) {
            // the id's namespace is its top 20 bytes
            if (msg.sender != address(uint160(uint256(datasetId) >> 96))) revert NotDatasetOwner();
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
    /// @param reason 1..999 when the dataset owner withdraws (that version only); >= 1000 (a
    ///        takedown code) when governance withdraws, which also freezes the id whatever the
    ///        version's state. 0 is never valid.
    function withdraw(bytes32 datasetId, uint32 version, uint16 reason) external {
        Version storage v = _version(datasetId, version);
        if (msg.sender == governance() && reason >= TAKEDOWN_REASON_MIN) {
            // Takedown (Q15): never blocked by an earlier publisher withdrawal.
            if (!v.withdrawn) {
                v.withdrawn = true;
                emit DatasetWithdrawn(datasetId, version, reason);
            }
            if (!_frozen[datasetId]) {
                _frozen[datasetId] = true;
                emit DatasetIdFrozen(datasetId, version, reason);
            }
            return;
        }
        if (msg.sender == _owner[datasetId]) {
            if (reason == 0 || reason >= TAKEDOWN_REASON_MIN) revert BadReason();
        } else if (msg.sender == governance()) {
            revert BadReason();
        } else {
            revert NotAuthorized();
        }
        if (v.withdrawn) revert AlreadyWithdrawn();
        v.withdrawn = true;
        emit DatasetWithdrawn(datasetId, version, reason);
    }

    // ── views ───────────────────────────────────────────────────────

    /// @notice True once a governance takedown (reason >= TAKEDOWN_REASON_MIN) hit any version of
    ///         `datasetId`; a frozen id accepts no further version (owner decision Q15, 2026-11-09).
    function frozen(bytes32 datasetId) external view returns (bool) {
        return _frozen[datasetId];
    }

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

    /// @dev Non-empty, bounded, not padded, and neither "unknown" nor "noassertion" compared
    ///      ASCII case-insensitively.
    function _checkLicense(string calldata license) internal pure {
        bytes calldata b = bytes(license);
        uint256 len = b.length;
        if (len == 0) revert BadLicense();
        if (len > MAX_STRING_BYTES) revert StringTooLong();
        // space, tab, newline and every other control byte, at either end
        if (uint8(b[0]) <= 0x20 || uint8(b[0]) == 0x7f) revert BadLicense();
        if (uint8(b[len - 1]) <= 0x20 || uint8(b[len - 1]) == 0x7f) revert BadLicense();
        if (_equalsLower(b, "unknown") || _equalsLower(b, "noassertion")) revert BadLicense();
    }

    /// @dev True iff `b` equals the lowercase ASCII `word` after folding A-Z to a-z.
    function _equalsLower(bytes calldata b, bytes memory word) internal pure returns (bool) {
        if (b.length != word.length) return false;
        for (uint256 i = 0; i < word.length; i++) {
            bytes1 c = b[i];
            if (c >= 0x41 && c <= 0x5a) c = bytes1(uint8(c) + 32); // A-Z -> a-z
            if (c != word[i]) return false;
        }
        return true;
    }
}
