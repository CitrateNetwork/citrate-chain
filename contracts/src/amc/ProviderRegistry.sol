// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Governable} from "../lib/Governable.sol";
import {InitialAdmin} from "../lib/InitialAdmin.sol";

/// @title ProviderRegistry: governed list state for the cloud model providers core already knows
/// @notice AMC 0.5.3 planset 06 section 2; ADR-2026-10-26 P-4, P-12, P-13, P-14. Spec:
///         docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md. Not in r1006 or block 0: deployed after
///         genesis through the GOVERNANCE timelock.
///
///         NARROWS ONLY (RT-3). The registry stores no host, path, model or URL. The hosts a vendor
///         key may be sent to are compiled into core (`provider_egress::VENDORS`); the registry
///         stores a commitment to that entry so drift is visible. Core refuses a vendor call unless
///         the registry says `Listed` AND `hostsCommitment` equals the hash of core's own compiled
///         entry. Nothing here can make core call a host it would not call without the registry.
///
///         State machine:
///           Unlisted | Delisted | EmergencyDelisted  --proposeListing (GOVERNANCE)-->  PendingListing
///           Listed                                   --updateCommitments (GOVERNANCE)-> PendingListing
///           PendingListing --finalizeListing (anyone, at or after vetoEndsAt)-->     Listed
///           PendingListing --veto (GUARDIAN)-->                                      Unlisted
///           Listed | PendingListing | EmergencyDelisted --delist (GOVERNANCE)-->     Delisted
///           Listed --emergencyDelist (GUARDIAN, immediate)-->                        EmergencyDelisted
///         Every path back to Listed passes PendingListing, so it waits the GOVERNANCE timelock
///         and then the registry's own veto window.
///
///         Guardian (RT-15, X-6): its veto is local to this registry's listing queue. It holds no
///         timelock role, cannot cancel `setGuardian` (that is not a listing), cannot list or
///         restore anything, and has no path to governance.
contract ProviderRegistry is Governable {
    enum Kind {
        Vendor, // serves models through an API key held by the member (BYOK)
        Delegate // runs remote agent sessions (Cognition), per-task approval in core
    }

    enum Status {
        Unlisted,
        PendingListing,
        Listed,
        Delisted,
        EmergencyDelisted
    }

    struct Provider {
        Kind kind;
        Status status;
        bytes32 hostsCommitment; // keccak256 of the canonical JSON of core's VENDORS entry
        bytes32 policyCommitment; // keccak256 of the governance policy doc for this listing
        uint64 listedAt; // last time it became Listed (0 if never)
        uint64 vetoEndsAt; // PendingListing only; 0 otherwise
        uint16 reasonCode; // last veto / delist reason (registry-defined codes, no free text)
    }

    /// Bounds on the veto window chosen at deployment (owner question on delist timing pending).
    uint64 public constant MIN_VETO_WINDOW = 1 hours;
    uint64 public constant MAX_VETO_WINDOW = 7 days;

    /// @notice How long a pending listing waits for a guardian veto. Fixed at deployment.
    uint64 public immutable vetoWindow;
    /// @notice The GUARDIAN seat. Replaceable only by governance.
    address public guardian;

    mapping(bytes32 => Provider) private _providers;
    bytes32[] private _ids;
    mapping(bytes32 => bool) private _known;

    event ListingProposed(
        bytes32 indexed providerId, Kind kind, bytes32 hostsCommitment, bytes32 policyCommitment, uint64 vetoEndsAt
    );
    event ListingVetoed(bytes32 indexed providerId, uint16 reasonCode);
    event Listed(bytes32 indexed providerId);
    event Delisted(bytes32 indexed providerId, uint16 reasonCode);
    event EmergencyDelisted(bytes32 indexed providerId, uint16 reasonCode, address indexed guardian);
    event CommitmentsUpdated(bytes32 indexed providerId, bytes32 hostsCommitment, bytes32 policyCommitment);
    event GuardianSet(address indexed previous, address indexed next);

    error NotGuardian();
    error GuardianIsGovernance();
    error BadVetoWindow();
    error ZeroCommitment();
    error ZeroProviderId();
    error WrongStatus(Status status);
    error VetoWindowOpen(uint64 vetoEndsAt);

    constructor(address governance_, address guardian_, uint64 vetoWindow_) Governable(governance_) {
        if (vetoWindow_ < MIN_VETO_WINDOW || vetoWindow_ > MAX_VETO_WINDOW) revert BadVetoWindow();
        vetoWindow = vetoWindow_;
        _setGuardian(guardian_);
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    // ------------------------------------------------------------------ governance

    /// @notice Queue a provider for listing (first listing or relisting).
    function proposeListing(bytes32 providerId, Kind kind, bytes32 hostsC, bytes32 policyC) external onlyGovernance {
        if (providerId == bytes32(0)) revert ZeroProviderId();
        Provider storage p = _providers[providerId];
        Status s = p.status;
        if (s != Status.Unlisted && s != Status.Delisted && s != Status.EmergencyDelisted) revert WrongStatus(s);
        if (!_known[providerId]) {
            _known[providerId] = true;
            _ids.push(providerId);
        }
        p.kind = kind;
        _queue(p, hostsC, policyC);
        emit ListingProposed(providerId, kind, hostsC, policyC, p.vetoEndsAt);
    }

    /// @notice Change a Listed provider's commitments. It goes back through PendingListing, so
    ///         core stops using it until the new commitments clear the veto window.
    function updateCommitments(bytes32 providerId, bytes32 hostsC, bytes32 policyC) external onlyGovernance {
        Provider storage p = _providers[providerId];
        if (p.status != Status.Listed) revert WrongStatus(p.status);
        _queue(p, hostsC, policyC);
        emit CommitmentsUpdated(providerId, hostsC, policyC);
        emit ListingProposed(providerId, p.kind, hostsC, policyC, p.vetoEndsAt);
    }

    function delist(bytes32 providerId, uint16 reasonCode) external onlyGovernance {
        Provider storage p = _providers[providerId];
        Status s = p.status;
        if (s != Status.Listed && s != Status.PendingListing && s != Status.EmergencyDelisted) revert WrongStatus(s);
        p.status = Status.Delisted;
        p.vetoEndsAt = 0;
        p.reasonCode = reasonCode;
        emit Delisted(providerId, reasonCode);
    }

    function setGuardian(address next) external onlyGovernance {
        _setGuardian(next);
    }

    // ------------------------------------------------------------------ anyone

    /// @notice Complete a listing once its veto window has passed (permissionless liveness).
    function finalizeListing(bytes32 providerId) external {
        Provider storage p = _providers[providerId];
        if (p.status != Status.PendingListing) revert WrongStatus(p.status);
        if (block.timestamp < p.vetoEndsAt) revert VetoWindowOpen(p.vetoEndsAt);
        p.status = Status.Listed;
        p.listedAt = uint64(block.timestamp);
        p.vetoEndsAt = 0;
        emit Listed(providerId);
    }

    // ------------------------------------------------------------------ guardian (narrow only)

    /// @notice Reject a pending listing or commitment update. PendingListing -> Unlisted.
    function veto(bytes32 providerId, uint16 reasonCode) external onlyGuardian {
        Provider storage p = _providers[providerId];
        if (p.status != Status.PendingListing) revert WrongStatus(p.status);
        p.status = Status.Unlisted;
        p.vetoEndsAt = 0;
        p.reasonCode = reasonCode;
        emit ListingVetoed(providerId, reasonCode);
    }

    /// @notice Take a Listed provider out of use at once. Sticky: only a new proposal relists it.
    function emergencyDelist(bytes32 providerId, uint16 reasonCode) external onlyGuardian {
        Provider storage p = _providers[providerId];
        if (p.status != Status.Listed) revert WrongStatus(p.status);
        p.status = Status.EmergencyDelisted;
        p.reasonCode = reasonCode;
        emit EmergencyDelisted(providerId, reasonCode, msg.sender);
    }

    // ------------------------------------------------------------------ reads (core's API)

    /// @notice `id` is core's ProviderId string: openai, anthropic, gemini, xai, deepseek, meta,
    ///         cognition.
    function providerIdOf(string calldata id) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("citrate.provider.v1:", id));
    }

    function statusOf(bytes32 providerId) external view returns (Status) {
        return _providers[providerId].status;
    }

    function get(bytes32 providerId) external view returns (Provider memory) {
        return _providers[providerId];
    }

    /// @notice The one check core makes before reading a vendor key: Listed, and the governed
    ///         host commitment equals the hash of core's own compiled entry.
    function isListedWith(bytes32 providerId, bytes32 compiledHostsCommitment) external view returns (bool) {
        Provider storage p = _providers[providerId];
        return p.status == Status.Listed && p.hostsCommitment == compiledHostsCommitment;
    }

    function providerCount() external view returns (uint256) {
        return _ids.length;
    }

    /// Every id ever proposed, in first-proposal order. An out-of-range `start` or a large
    /// `count` returns the available tail (never reverts).
    function providerIds(uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        uint256 n = _ids.length;
        if (start >= n) return new bytes32[](0);
        uint256 avail = n - start;
        uint256 len = count < avail ? count : avail;
        out = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = _ids[start + i];
        }
    }

    // ------------------------------------------------------------------ internals

    function _queue(Provider storage p, bytes32 hostsC, bytes32 policyC) internal {
        if (hostsC == bytes32(0) || policyC == bytes32(0)) revert ZeroCommitment();
        p.status = Status.PendingListing;
        p.hostsCommitment = hostsC;
        p.policyCommitment = policyC;
        p.vetoEndsAt = uint64(block.timestamp) + vetoWindow;
        p.reasonCode = 0;
    }

    function _setGuardian(address next) internal {
        InitialAdmin.check(next); // nonzero, never the CREATE2 factory
        if (next == governance()) revert GuardianIsGovernance();
        emit GuardianSet(guardian, next);
        guardian = next;
    }
}
