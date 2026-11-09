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
    error NotImplemented();

    constructor(address governance_) Governable(governance_) {}

    // RED SKELETON: interface only; every entry point reverts until the implementation lands.

    function publish(bytes32, Version calldata) external pure returns (uint32) {
        revert NotImplemented();
    }

    function withdraw(bytes32, uint32, uint16) external pure {
        revert NotImplemented();
    }

    function ownerOf(bytes32) external pure returns (address) {
        revert NotImplemented();
    }

    function versionCount(bytes32) external pure returns (uint32) {
        revert NotImplemented();
    }

    function getVersion(bytes32, uint32) external pure returns (Version memory) {
        revert NotImplemented();
    }

    function latest(bytes32) external pure returns (uint32, Version memory) {
        revert NotImplemented();
    }
}
