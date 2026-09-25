// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/RS256.sol";
import "./lib/JWTParser.sol";
import "./lib/Governable.sol";

/// @title TEEAttestationRegistry — CM-08 on-chain attestation state
/// @notice Stores per-worker TEE attestation records for
///         pipeline-parallel inference. Per ADR-010, a complete
///         attestation consists of an Azure MAA JWT (VM-level)
///         plus an NVIDIA NRAS claim (GPU-level).
///
///         Two submission paths exist:
///         1. `submitAttestation` (governance-trusted, V1) —
///            governance pre-approves signer hashes; caller
///            promises the (vmMeasurement, gpuMeasurement) come
///            from those signers.
///         2. `submitAttestationStrictBound` (cryptographic, V2) —
///            caller supplies the raw MAA JWT + signature + literal
///            JWT claim bytes for the VM measurement; the contract
///            verifies the RS256 signature on-chain against a
///            governance-published RSA public key AND verifies that
///            the literal claim bytes appear inside the decoded JWT
///            payload (binding the on-chain `vmMeasurement` to actual
///            JWT content via `JWTParser`). The NRAS (P384)
///            verification side is still governance-trusted pending
///            P-384 ECDSA precompile / vetted Solidity lib;
///            documented in ADR-010 §"P384 deferred".
///
///         The `strictCryptographicMode` flag controls whether the
///         V1 path is still permitted. When ON, only V2 is allowed
///         for new attestations. This lets the cutover land in
///         stages: contract-side V2 deployed and exercised in
///         shadow → audit → flip the flag → V1 path closed.
///
///         State machine mirrors the `PipelineParallelTEE.tla`
///         spec (CM-08 WP-08.0):
///           NotAttested → Attested → Expired → Slashed (absorbing)
///
/// @dev CM-08 WP-08.1. See docs/adr/ADR-010-tee-attestation-registry.md.
contract TEEAttestationRegistry is ReentrancyGuard, Governable {
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

    /// @notice MAA RSA public keys mirrored from Azure JWKS.
    /// Keyed by `kid` (key id) string from the JWT header.
    /// Governance is responsible for keeping this in sync with
    /// the live Azure MAA endpoint (`https://sharedeus2.eus2.attest.azure.net/.well-known/jwks`).
    /// Lookup is by keccak(kid) to avoid storing variable-length
    /// strings as map keys.
    struct MaaRsaKey {
        bytes modulus;   // big-endian modulus N (typically 256 bytes for RSA-2048)
        bytes exponent;  // big-endian exponent e (typically 3 bytes: 0x010001)
        bool active;     // governance can deactivate without deleting (audit trail)
    }
    mapping(bytes32 => MaaRsaKey) internal _maaRsaKeys;

    /// @notice When true, ONLY `submitAttestationStrictBound` accepts
    /// new attestations. The V1 governance-trusted `submitAttestation`
    /// path is still callable but reverts immediately.
    /// RM-B1 / WP-D3.1 (audit SOL-03): defaults to TRUE — secure-by-
    /// default. Pre-fix the constructor left this as the bool zero
    /// (false), which silently degraded a fresh deployment to V1's
    /// governance-trusted mode. Operators who need V1 during the
    /// cutover must explicitly opt-in via `setStrictCryptographicMode(false)`.
    bool public strictCryptographicMode;

    /// @notice Tracks JWT signatures already consumed by
    /// `submitAttestationStrictBound`. Keyed by `keccak256(jwtSignature)`.
    /// RM-B1 / WP-D3.2 (audit SOL-05): pre-fix the same valid MAA
    /// JWT could be replayed indefinitely (by the same worker every
    /// few seconds, or by a different worker forging the address
    /// claim) because the contract had no notion of signature
    /// uniqueness. Post-fix every successful strict submission marks
    /// the signature as consumed; a re-submit of the same JWT
    /// reverts with "TEERegistry: jwt replay".
    mapping(bytes32 => bool) public usedJwtSignatures;

    /// @notice PBA-L2-024: governance-approved VM measurements. `isAttested`
    ///         is false for any record whose measurement is not on this list.
    mapping(bytes32 => bool) public approvedVmMeasurement;

    event VmMeasurementApproval(bytes32 indexed measurement, bool approved);

    /// @notice Pending two-step RSA key updates. Governance proposes
    /// a new key; after `RSA_KEY_TIMELOCK_BLOCKS` blocks anyone may
    /// finalize the proposal. Protects against compromised governance:
    /// even if an attacker hijacks governance for one block, they
    /// cannot install a malicious MAA RSA key (or activate a dormant
    /// one) without surviving the timelock window.
    /// RM-B1 / WP-D3.3 (audit SOL-05).
    struct PendingMaaRsaKey {
        bytes modulus;
        bytes exponent;
        bool active;
        uint64 etaBlock;
        bool exists;
    }
    mapping(bytes32 => PendingMaaRsaKey) internal _pendingMaaRsaKeys;

    /// @notice Number of blocks between an RSA key proposal and the
    /// earliest block at which it can be finalized.
    /// ~30 minutes at 0.5s blocks — long enough for off-chain
    /// monitoring + an emergency abort, short enough not to break
    /// real key-rotation timelines.
    uint64 public constant RSA_KEY_TIMELOCK_BLOCKS = 3600;

    // Governance state lives in Governable mixin (RM-B1 / WP-D1.1,
    // audit SOL-21). Read via `governance()` view; mutations go
    // through `transferGovernance` + `acceptGovernance`.

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
    event MaaRsaKeyUpdated(bytes32 indexed kidHash, bool active);
    event MaaRsaKeyProposed(bytes32 indexed kidHash, uint64 etaBlock, bool active);
    event MaaRsaKeyProposalCancelled(bytes32 indexed kidHash);
    event StrictCryptographicModeChanged(bool enabled);
    event AttestedStrict(
        address indexed worker,
        uint64 attestedAtBlock,
        uint64 expiryBlock,
        bytes32 modelHash,
        bytes32 indexed kidHash
    );
    // `onlyGovernance` is inherited from Governable.

    // ── Constructor ─────────────────────────────────────────────────

    constructor(address _governance) Governable(_governance) {
        // RM-B1 / WP-D3.1 (audit SOL-03): secure-by-default. The V1
        // governance-trusted path requires an explicit opt-out.
        strictCryptographicMode = true;
        emit StrictCryptographicModeChanged(true);
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
        require(!strictCryptographicMode, "TEERegistry: strict mode active, use submitAttestationStrictBound");
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

    /// @notice JWT-content-bound strict submission. In addition to
    /// verifying the RS256 signature, this variant requires that the
    /// caller-supplied `vmMeasurementClaim` bytes appear LITERALLY
    /// inside the JWT payload. The on-chain `vmMeasurement` is then
    /// derived as `keccak256(vmMeasurementClaim)` — the caller cannot
    /// substitute an unrelated measurement.
    ///
    /// `vmMeasurementClaim` should be the EXACT bytes of the
    /// JSON pair, including field name, colon, and quotes —
    /// e.g. `"x-ms-runtime-vm-measurement":"0xabcd..."`. ADR-010
    /// §"MAA schema" enumerates the valid field names.
    ///
    /// RM-B1 / WP-D3.4 (audit SOL-05): the cryptographic V2 path.
    /// An earlier `submitAttestationStrict` variant (now removed in
    /// RM-J3 post-RM-I-3 cleanup) trusted a caller-asserted
    /// `vmMeasurement bytes32`; an attacker holding any valid MAA
    /// JWT could substitute an arbitrary measurement. This Bound
    /// variant binds the measurement to actual JWT content via
    /// `JWTParser.containsClaim`.
    function submitAttestationStrictBound(
        bytes calldata signedJwtPayload,
        bytes calldata jwtSignature,
        bytes32 kidHash,
        bytes calldata vmMeasurementClaim,
        bytes32 gpuMeasurement,
        bytes32 modelHash,
        bytes32 nrasSignerHash
    ) external {
        require(!attestations[msg.sender].slashed, "TEERegistry: slashed cannot re-attest");
        require(modelHash != bytes32(0), "TEERegistry: zero model hash");
        require(trustedNrasSigners[nrasSignerHash], "TEERegistry: untrusted NRAS signer");
        require(vmMeasurementClaim.length > 0, "TEERegistry: empty vm claim");

        MaaRsaKey storage key = _maaRsaKeys[kidHash];
        require(key.active, "TEERegistry: unknown or inactive MAA kid");

        // Replay protection: each (signedJwtPayload, jwtSignature)
        // is consumed exactly once via the keccak256(jwtSignature)
        // index. Re-submission by the same or another worker reverts.
        bytes32 sigHash = keccak256(jwtSignature);
        require(!usedJwtSignatures[sigHash], "TEERegistry: jwt replay");
        usedJwtSignatures[sigHash] = true;

        // RS256 signature verification.
        bool sigOk = RS256.verify(
            signedJwtPayload,
            jwtSignature,
            key.modulus,
            key.exponent
        );
        require(sigOk, "TEERegistry: invalid MAA JWT signature");

        // Bind: parse the JWT payload and verify the measurement
        // claim is literally present.
        bytes memory payloadJson = JWTParser.extractPayload(signedJwtPayload);
        // PBA-L2-024: the claim must be a TOP-LEVEL member of the signed
        // payload (a raw substring match accepted a lone `"` or a string the
        // guest embedded in nested runtime data), and it must be a
        // measurement governance has approved.
        require(
            JWTParser.containsTopLevelClaim(payloadJson, vmMeasurementClaim),
            "TEERegistry: vm claim not in jwt"
        );
        require(
            approvedVmMeasurement[keccak256(vmMeasurementClaim)],
            "TEERegistry: vm measurement not approved"
        );

        // CHAIN-B-C019 (audit 2026-09-02): bind the JWT to the caller. The
        // strict-bound path USED to write `attestations[msg.sender]` from any
        // valid MAA JWT without checking the JWT named the caller — so an
        // attacker who observed a JWT in the mempool (or obtained a leaked one)
        // could resubmit it from their own address, claim the Attested record,
        // and — because the one-time-use `usedJwtSignatures` guard then fires —
        // permanently lock the genuine worker out. The JWT payload must now
        // literally contain the caller's address as a `"holder"` claim.
        // OWNER/reroll-provisioning: the worker enclave's MAA JWT MUST embed a
        // `"holder":"<lowercase 0x address>"` runtime claim naming the address
        // that will submit it.
        require(
            JWTParser.containsTopLevelClaim(payloadJson, _holderClaim(msg.sender)),
            "TEERegistry: jwt not bound to caller"
        );

        bytes32 vmMeasurement = keccak256(vmMeasurementClaim);

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
        emit AttestedStrict(
            msg.sender,
            rec.attestedAtBlock,
            rec.expiryBlock,
            modelHash,
            kidHash
        );
    }

    /// @notice CHAIN-B-C019: the exact claim bytes the strict-bound JWT must
    ///         contain to bind the attestation to `who`:
    ///         `"holder":"0x<40 lowercase hex chars>"`.
    function _holderClaim(address who) internal pure returns (bytes memory) {
        bytes16 digits = "0123456789abcdef";
        bytes memory hexAddr = new bytes(42);
        hexAddr[0] = "0";
        hexAddr[1] = "x";
        uint160 v = uint160(who);
        for (uint256 i = 0; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            hexAddr[2 + i * 2] = digits[b >> 4];
            hexAddr[3 + i * 2] = digits[b & 0x0f];
        }
        return abi.encodePacked('"holder":"', hexAddr, '"');
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
        // PBA-L2-024: an attestation only counts while its VM measurement is
        // on governance's approved list (revoking a measurement de-attests
        // every worker running it).
        return !r.slashed
            && r.attestedAtBlock > 0
            && uint256(r.expiryBlock) > currentBlock
            && approvedVmMeasurement[r.vmMeasurement];
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

    /// @notice PBA-L2-024: approve (or revoke) a VM measurement. For the
    ///         strict-bound path the value is `keccak256` of the exact
    ///         top-level `"key":"value"` claim bytes; for the legacy path it is
    ///         the asserted `vmMeasurement`.
    function setApprovedVmMeasurement(bytes32 measurement, bool approved) external onlyGovernance {
        approvedVmMeasurement[measurement] = approved;
        emit VmMeasurementApproval(measurement, approved);
    }

    function setMaaSigner(bytes32 keyHash, bool trusted) external onlyGovernance {
        trustedMaaSigners[keyHash] = trusted;
        emit MaaSignerUpdated(keyHash, trusted);
    }

    function setNrasSigner(bytes32 keyHash, bool trusted) external onlyGovernance {
        trustedNrasSigners[keyHash] = trusted;
        emit NrasSignerUpdated(keyHash, trusted);
    }

    /// @notice Propose registering / updating an MAA RSA public key.
    /// The key is staged but NOT yet usable; finalization requires
    /// `RSA_KEY_TIMELOCK_BLOCKS` to elapse and a separate
    /// `finalizeMaaRsaKey` call.
    /// RM-B1 / WP-D3.3 (audit SOL-05): two-step key install. Pre-fix
    /// a one-block governance compromise could install a malicious
    /// MAA RSA key and immediately accept forged attestations.
    /// Post-fix the timelock gives off-chain monitors a window to
    /// observe and abort via `cancelMaaRsaKeyProposal`.
    ///
    /// Emergency *deactivation* of an already-active key remains a
    /// single-step call (`setMaaRsaKeyActive(_, false)`) so a
    /// compromised key can be killed instantly. Only *activation*
    /// is gated.
    function proposeMaaRsaKey(
        bytes32 kidHash,
        bytes calldata modulus,
        bytes calldata exponent,
        bool active
    ) external onlyGovernance {
        require(modulus.length > 0, "TEERegistry: empty modulus");
        require(exponent.length > 0, "TEERegistry: empty exponent");
        uint64 eta = uint64(block.number) + RSA_KEY_TIMELOCK_BLOCKS;
        _pendingMaaRsaKeys[kidHash] = PendingMaaRsaKey({
            modulus: modulus,
            exponent: exponent,
            active: active,
            etaBlock: eta,
            exists: true
        });
        emit MaaRsaKeyProposed(kidHash, eta, active);
    }

    /// @notice Cancel a pending key proposal before it finalizes.
    function cancelMaaRsaKeyProposal(bytes32 kidHash) external onlyGovernance {
        require(_pendingMaaRsaKeys[kidHash].exists, "TEERegistry: no pending proposal");
        delete _pendingMaaRsaKeys[kidHash];
        emit MaaRsaKeyProposalCancelled(kidHash);
    }

    /// @notice Finalize a pending key proposal once its timelock
    /// has elapsed. Permissionless — anyone may push the change
    /// across the line, since governance has already signed off
    /// via `proposeMaaRsaKey` and the timelock gives the community
    /// time to react.
    function finalizeMaaRsaKey(bytes32 kidHash) external {
        PendingMaaRsaKey storage p = _pendingMaaRsaKeys[kidHash];
        require(p.exists, "TEERegistry: no pending proposal");
        require(uint64(block.number) >= p.etaBlock, "TEERegistry: timelock not elapsed");
        _maaRsaKeys[kidHash] = MaaRsaKey({
            modulus: p.modulus,
            exponent: p.exponent,
            active: p.active
        });
        bool wasActive = p.active;
        delete _pendingMaaRsaKeys[kidHash];
        emit MaaRsaKeyUpdated(kidHash, wasActive);
    }

    /// @notice Activate or deactivate an existing MAA RSA key without
    /// re-uploading bytes. Deactivation (`active = false`) is
    /// deliberately single-step so a compromised key can be killed
    /// instantly. Activation of a previously-deactivated key is
    /// also single-step but constrained: the key bytes have already
    /// been through the timelocked install path, so no new key
    /// material enters the system here.
    function setMaaRsaKeyActive(bytes32 kidHash, bool active) external onlyGovernance {
        require(_maaRsaKeys[kidHash].modulus.length > 0, "TEERegistry: unknown kid");
        _maaRsaKeys[kidHash].active = active;
        emit MaaRsaKeyUpdated(kidHash, active);
    }

    /// @notice View the pending RSA key proposal for `kidHash`.
    /// Returns zero/empty fields if no proposal is active.
    function getPendingMaaRsaKey(bytes32 kidHash)
        external
        view
        returns (
            bytes memory modulus,
            bytes memory exponent,
            bool active,
            uint64 etaBlock,
            bool exists
        )
    {
        PendingMaaRsaKey storage p = _pendingMaaRsaKeys[kidHash];
        return (p.modulus, p.exponent, p.active, p.etaBlock, p.exists);
    }

    /// @notice View accessor for stored MAA RSA keys.
    function getMaaRsaKey(bytes32 kidHash)
        external
        view
        returns (bytes memory modulus, bytes memory exponent, bool active)
    {
        MaaRsaKey storage k = _maaRsaKeys[kidHash];
        return (k.modulus, k.exponent, k.active);
    }

    /// @notice Toggle the strict cryptographic mode. When true, the
    /// V1 governance-trusted `submitAttestation` path reverts and
    /// only `submitAttestationStrictBound` is accepted. Allows
    /// staged cutover: deploy V2, exercise it in shadow, then flip
    /// the flag once governance is comfortable.
    function setStrictCryptographicMode(bool enabled) external onlyGovernance {
        strictCryptographicMode = enabled;
        emit StrictCryptographicModeChanged(enabled);
    }

    // transferGovernance / acceptGovernance / cancelGovernanceTransfer
    // are inherited from Governable.
}
