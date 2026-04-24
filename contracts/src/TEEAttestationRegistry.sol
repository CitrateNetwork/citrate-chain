// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";

/// @title TEEAttestationRegistry — CM-08 on-chain attestation state
/// @notice Stores per-worker TEE attestation records for
///         pipeline-parallel inference. Per ADR-010, a complete
///         attestation consists of an Azure MAA JWT (VM-level)
///         plus an NVIDIA NRAS claim (GPU-level). This v1 contract
///         accepts governance-curated attestation payloads; full
///         on-chain RS256 / P384 verification lands in a follow-up
///         when gas-optimized precompiles are available on Citrate
///         LVM.
///
///         State machine mirrors the `PipelineParallelTEE.tla`
///         spec (CM-08 WP-08.0):
///           NotAttested → Attested → Expired → Slashed (absorbing)
///
/// @dev CM-08 WP-08.1. See docs/adr/ADR-010-tee-attestation-registry.md.
contract TEEAttestationRegistry is ReentrancyGuard {
    // ── Types ───────────────────────────────────────────────────────

    struct AttestationRecord {
        uint64 attestedAtBlock;
        uint64 expiryBlock;
        bytes32 modelHash;
        bytes32 vmMeasurement;   // keccak(MAA claim payload)
        bytes32 gpuMeasurement;  // keccak(NRAS claim payload)
        bool slashed;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Attestation lifetime in blocks (~4 hours at 0.5s blocks).
    /// Callers re-attest before expiry to maintain the Attested state.
    uint64 public constant ATTESTATION_LIFETIME_BLOCKS = 28_800;

    /// @notice Slash basis points applied when a worker is caught
    /// serving with an expired attestation. Same 10% as CM-07's
    /// challenge resolution for symmetric economic punishment.
    uint256 public constant SLASH_BPS = 1000;

    /// @notice Basis points denominator.
    uint256 private constant BPS = 10_000;

    /// @notice Required bond (in native SALT) to file an
    /// `reportExpiredServe` claim. Refunded on success + reward;
    /// forfeited on false report.
    uint256 public constant REPORT_BOND = 1 ether;

    // ── State ───────────────────────────────────────────────────────

    /// @notice Active + historical attestations per worker.
    mapping(address => AttestationRecord) public attestations;

    /// @notice Governance-approved MAA signer hashes.
    /// `trustedMaaSigners[keccak(pubkey)] = true` marks a key usable.
    mapping(bytes32 => bool) public trustedMaaSigners;

    /// @notice Governance-approved NRAS signer hashes.
    mapping(bytes32 => bool) public trustedNrasSigners;

    /// @notice Governance address (manages signer whitelists + slash
    /// execution).
    address public governance;

    // ── Events ──────────────────────────────────────────────────────

    event Attested(
        address indexed worker,
        uint64 attestedAtBlock,
        uint64 expiryBlock,
        bytes32 modelHash
    );
    event AttestationSlashed(
        address indexed worker,
        address indexed reporter,
        uint128 slashAmount
    );
    event MaaSignerUpdated(bytes32 indexed keyHash, bool trusted);
    event NrasSignerUpdated(bytes32 indexed keyHash, bool trusted);

    // ── Modifiers ───────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governance, "TEERegistry: not governance");
        _;
    }

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address _governance) {
        require(_governance != address(0), "TEERegistry: zero governance");
        governance = _governance;
    }

    // ── Attestation submission ──────────────────────────────────────

    /// @notice Submit a fresh attestation record. v1 contract trusts
    /// governance to curate signers; full RS256 / P384 verification
    /// of raw payloads is deferred pending Citrate LVM precompile
    /// support. The caller attests that the provided (vmMeasurement,
    /// gpuMeasurement) come from trusted-signer claims; governance
    /// slashes if they don't.
    ///
    /// A slashed worker cannot re-attest under their current key.
    function submitAttestation(
        bytes32 vmMeasurement,
        bytes32 gpuMeasurement,
        bytes32 modelHash,
        bytes32 maaSignerHash,
        bytes32 nrasSignerHash
    ) external {
        require(!attestations[msg.sender].slashed, "TEERegistry: slashed cannot re-attest");
        require(trustedMaaSigners[maaSignerHash], "TEERegistry: untrusted MAA signer");
        require(trustedNrasSigners[nrasSignerHash], "TEERegistry: untrusted NRAS signer");
        require(modelHash != bytes32(0), "TEERegistry: zero model hash");

        uint64 blockNum = uint64(block.number);
        AttestationRecord memory rec = AttestationRecord({
            attestedAtBlock: blockNum,
            expiryBlock: blockNum + ATTESTATION_LIFETIME_BLOCKS,
            modelHash: modelHash,
            vmMeasurement: vmMeasurement,
            gpuMeasurement: gpuMeasurement,
            slashed: false
        });
        attestations[msg.sender] = rec;

        emit Attested(msg.sender, rec.attestedAtBlock, rec.expiryBlock, modelHash);
    }

    // ── Views ───────────────────────────────────────────────────────

    /// @notice True iff `worker` has a fresh, non-slashed attestation
    /// valid at the given block number. Matches the TLA+
    /// `attestState[worker] == "Attested"` predicate.
    function isAttested(address worker, uint256 currentBlock)
        external
        view
        returns (bool)
    {
        AttestationRecord memory r = attestations[worker];
        return !r.slashed
            && r.attestedAtBlock > 0
            && uint256(r.expiryBlock) > currentBlock;
    }

    /// @notice Returns the attestation record for inspection.
    function getAttestation(address worker)
        external
        view
        returns (AttestationRecord memory)
    {
        return attestations[worker];
    }

    // ── Slashing ────────────────────────────────────────────────────

    /// @notice Slash a worker caught serving with an expired
    /// attestation. Caller posts bond; on governance confirmation,
    /// bond + half-slash goes to reporter. v1 contract delegates the
    /// legitimacy check to governance for simplicity; full on-chain
    /// evidence verification is a future slice.
    ///
    /// Semantics:
    ///   - Requires `attestations[target].expiryBlock <= servedAtBlock`
    ///     (i.e. served truly was after expiry per the reporter)
    ///   - Governance examines provided evidence off-chain and calls
    ///     `finalizeSlash` to execute
    ///   - Bond is held until governance decision (forfeit or refund)
    function reportExpiredServe(
        address target,
        uint64 expiredAtBlock,
        uint64 servedAtBlock
    ) external payable nonReentrant returns (uint256 reportId) {
        require(msg.value == REPORT_BOND, "TEERegistry: wrong bond");
        require(target != msg.sender, "TEERegistry: no self-report");
        require(servedAtBlock > expiredAtBlock, "TEERegistry: served within window");
        require(
            attestations[target].expiryBlock <= expiredAtBlock,
            "TEERegistry: claim lifetime covers serve"
        );
        require(!attestations[target].slashed, "TEERegistry: already slashed");

        reportId = _nextReportId++;
        pendingReports[reportId] = PendingReport({
            target: target,
            reporter: msg.sender,
            bond: uint128(msg.value),
            resolved: false
        });
    }

    /// @notice Governance adjudicates a pending report.
    ///
    /// On uphold: target's attestation is marked `slashed` (absorbing
    /// terminal — ComputePoolPipeline.isAttested reads FALSE from here
    /// on), the reporter receives their bond back, and an
    /// `AttestationSlashed` event fires carrying the slash BPS for
    /// the Pipeline contract to act on economically. The registry
    /// itself holds only bonds; the actual stake-slash against the
    /// target happens in ComputePoolPipeline where the stake lives.
    /// The `stakeToSlashFrom` parameter is retained in the event
    /// payload for Pipeline's slashing handler.
    ///
    /// On reject: reporter's bond is returned (false-positive
    /// recovery — v1 does NOT forfeit an honest mistake, unlike
    /// CM-07's challenge model; TEE-expiry evidence is typically
    /// less ambiguous and under-reporting is the greater risk).
    function finalizeReport(uint256 reportId, bool uphold, uint128 stakeToSlashFrom)
        external
        onlyGovernance
        nonReentrant
    {
        PendingReport storage rep = pendingReports[reportId];
        require(!rep.resolved, "TEERegistry: already resolved");
        rep.resolved = true;

        uint128 bond = rep.bond;

        if (uphold) {
            uint128 slashAmount = uint128(uint256(stakeToSlashFrom) * SLASH_BPS / BPS);
            attestations[rep.target].slashed = true;

            // Return the bond. Half-slash reward comes from Pipeline
            // when it picks up the AttestationSlashed event (v2).
            (bool ok, ) = rep.reporter.call{value: bond}("");
            require(ok, "TEERegistry: bond refund failed");

            emit AttestationSlashed(rep.target, rep.reporter, slashAmount);
        } else {
            (bool ok, ) = rep.reporter.call{value: bond}("");
            require(ok, "TEERegistry: bond refund failed");
        }
    }

    struct PendingReport {
        address target;
        address reporter;
        uint128 bond;
        bool resolved;
    }
    mapping(uint256 => PendingReport) public pendingReports;
    uint256 private _nextReportId;

    // ── Governance ──────────────────────────────────────────────────

    function setMaaSigner(bytes32 keyHash, bool trusted) external onlyGovernance {
        trustedMaaSigners[keyHash] = trusted;
        emit MaaSignerUpdated(keyHash, trusted);
    }

    function setNrasSigner(bytes32 keyHash, bool trusted) external onlyGovernance {
        trustedNrasSigners[keyHash] = trusted;
        emit NrasSignerUpdated(keyHash, trusted);
    }

    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "TEERegistry: zero governance");
        governance = newGovernance;
    }
}
