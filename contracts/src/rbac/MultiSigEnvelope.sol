// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MultiSigEnvelope — N-of-M signed decisions, cross-org
/// @notice Generic multi-signer envelope generalizing Docusign+CLEAR
///         semantics. Any decision that requires multiple signers
///         (TINA workpaper, supplier suspension, ITAR escalation,
///         inter-org transfer) rides this contract.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/MultiSigEnvelopeFlow.tla`
/// @dev Cited invariants:
///   - `SignedCountLeRequired` — `signed_by.length <= required_signers.length`
///     at all times.
///   - `SignersUnique` — each `required_signer` can sign at most once
///     per envelope. Enforced in `sign()` revert path.
///   - `ThresholdSatisfiedImpliesSignedOrLater` — when
///     `signed_by.length >= threshold`, state transitions to Signed.
///   - `DraftedHasNoSignatures` — Drafted state has empty `signed_by`;
///     enforced by ordering: `sign()` requires Signing or later.
///   - `ExpiredImpliesNoActiveSign` — past `expires_at` blocks `sign()`.
///   - `ClosedIsTerminal` — Closed cannot transition.
///   - `AcceptOrRejectExclusive` — Accepted and Rejected are mutually
///     exclusive terminal states.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § 4. BFR-02 deliverable.
contract MultiSigEnvelope {
    // ── Types ───────────────────────────────────────────────────────

    enum EnvelopeState {
        NotExist,    // 0 — default for unseen envelope_id
        Drafted,     // 1 — draft() called, no signatures yet
        Signing,     // 2 — at least one sign() but threshold not reached
        Signed,      // 3 — threshold reached, awaiting markDelivered
        Delivered,   // 4 — delivered to counterparty (cross-org case)
        Accepted,    // 5 — counterparty accepted (terminal-success)
        Rejected,    // 6 — counterparty rejected (terminal-fail)
        Closed       // 7 — withdrawn by initiator (terminal)
    }

    struct Envelope {
        bytes32 envelope_id;
        bytes32 artifact_root;
        string  artifact_cid;
        bytes32[] required_signers;
        bytes32[] signed_by;
        uint8   threshold;
        EnvelopeState state;
        bytes32 corr_id;
        uint64  created_at;
        uint64  signed_at;
        uint64  expires_at;
        bytes32 initiator;
    }

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 envelope_id => Envelope) private _envelopes;
    mapping(bytes32 envelope_id => mapping(bytes32 signer => bytes)) private _signatures;

    // ── Events ──────────────────────────────────────────────────────

    event EnvelopeDrafted(
        bytes32 indexed envelope_id,
        bytes32 indexed initiator,
        bytes32 indexed corr_id,
        uint8 threshold,
        uint64 expires_at
    );
    event EnvelopeSigned(
        bytes32 indexed envelope_id,
        bytes32 indexed signer,
        string auth_mode
    );
    event EnvelopeStateChanged(
        bytes32 indexed envelope_id,
        EnvelopeState old_state,
        EnvelopeState new_state
    );
    event EnvelopeAccepted(bytes32 indexed envelope_id, bytes32 indexed corr_id);
    event EnvelopeRejected(
        bytes32 indexed envelope_id,
        bytes32 indexed corr_id,
        string reason
    );

    // ── Errors ──────────────────────────────────────────────────────

    error AlreadyExists(bytes32 envelope_id);
    error DoesNotExist(bytes32 envelope_id);
    error EmptyRequiredSigners();
    error InvalidThreshold(uint8 threshold, uint256 signer_count);
    error EmptyAuthMode();
    error EmptyArtifactCid();
    error PastExpiry(uint64 expires_at, uint64 now_ts);
    error NotRequiredSigner(bytes32 signer);
    error AlreadySigned(bytes32 signer);
    error InvalidStateForSign(EnvelopeState state);
    error InvalidStateForDeliver(EnvelopeState state);
    error InvalidStateForAcceptReject(EnvelopeState state);
    error InvalidStateForClose(EnvelopeState state);

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Open a new envelope in Drafted state.
    function draft(
        bytes32 envelope_id,
        bytes32 initiator,
        bytes32 artifact_root,
        string calldata artifact_cid,
        bytes32[] calldata required_signers,
        uint8 threshold,
        uint64 expires_at,
        bytes32 corr_id
    ) external {
        if (_envelopes[envelope_id].state != EnvelopeState.NotExist) {
            revert AlreadyExists(envelope_id);
        }
        if (required_signers.length == 0) revert EmptyRequiredSigners();
        if (threshold == 0 || threshold > required_signers.length) {
            revert InvalidThreshold(threshold, required_signers.length);
        }
        if (bytes(artifact_cid).length == 0) revert EmptyArtifactCid();
        if (expires_at != 0 && expires_at <= block.timestamp) {
            revert PastExpiry(expires_at, uint64(block.timestamp));
        }

        Envelope storage e = _envelopes[envelope_id];
        e.envelope_id = envelope_id;
        e.initiator = initiator;
        e.artifact_root = artifact_root;
        e.artifact_cid = artifact_cid;
        e.threshold = threshold;
        e.state = EnvelopeState.Drafted;
        e.corr_id = corr_id;
        e.created_at = uint64(block.timestamp);
        e.expires_at = expires_at;
        // Copy required_signers element-by-element (calldata->storage).
        for (uint256 i; i < required_signers.length; ++i) {
            e.required_signers.push(required_signers[i]);
        }

        emit EnvelopeDrafted(envelope_id, initiator, corr_id, threshold, expires_at);
        emit EnvelopeStateChanged(envelope_id, EnvelopeState.NotExist, EnvelopeState.Drafted);
    }

    /// @notice Sign an envelope. Transitions Drafted→Signing on first
    ///         signature; Signing→Signed when threshold reached.
    /// @dev `signer` is the hashed identity of the signing party
    ///      (typically `keccak256(user_id)`); the actual signature
    ///      authentication is the caller's responsibility (the
    ///      orchestrator's HSM verifies the cryptographic proof
    ///      before invoking this method).
    function sign(
        bytes32 envelope_id,
        bytes32 signer,
        bytes calldata signer_sig,
        string calldata auth_mode
    ) external {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        if (e.state != EnvelopeState.Drafted && e.state != EnvelopeState.Signing) {
            revert InvalidStateForSign(e.state);
        }
        if (e.expires_at != 0 && e.expires_at <= block.timestamp) {
            revert PastExpiry(e.expires_at, uint64(block.timestamp));
        }
        if (bytes(auth_mode).length == 0) revert EmptyAuthMode();
        if (!_isRequiredSigner(e, signer)) revert NotRequiredSigner(signer);
        if (_alreadySigned(e, signer)) revert AlreadySigned(signer);

        _signatures[envelope_id][signer] = signer_sig;
        e.signed_by.push(signer);
        emit EnvelopeSigned(envelope_id, signer, auth_mode);

        EnvelopeState oldState = e.state;
        if (e.signed_by.length >= e.threshold) {
            e.state = EnvelopeState.Signed;
            e.signed_at = uint64(block.timestamp);
        } else if (e.state == EnvelopeState.Drafted) {
            e.state = EnvelopeState.Signing;
        }
        if (oldState != e.state) {
            emit EnvelopeStateChanged(envelope_id, oldState, e.state);
        }
    }

    /// @notice Mark an envelope as delivered to the counterparty.
    /// @dev Only callable on Signed-state envelopes.
    function markDelivered(bytes32 envelope_id) external {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        if (e.state != EnvelopeState.Signed) revert InvalidStateForDeliver(e.state);
        EnvelopeState oldState = e.state;
        e.state = EnvelopeState.Delivered;
        emit EnvelopeStateChanged(envelope_id, oldState, e.state);
    }

    /// @notice Counterparty accepts. Terminal state.
    function accept(bytes32 envelope_id) external {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        if (e.state != EnvelopeState.Delivered) revert InvalidStateForAcceptReject(e.state);
        EnvelopeState oldState = e.state;
        e.state = EnvelopeState.Accepted;
        emit EnvelopeStateChanged(envelope_id, oldState, e.state);
        emit EnvelopeAccepted(envelope_id, e.corr_id);
    }

    /// @notice Counterparty rejects. Terminal state.
    function reject(bytes32 envelope_id, string calldata reason) external {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        if (e.state != EnvelopeState.Delivered) revert InvalidStateForAcceptReject(e.state);
        EnvelopeState oldState = e.state;
        e.state = EnvelopeState.Rejected;
        emit EnvelopeStateChanged(envelope_id, oldState, e.state);
        emit EnvelopeRejected(envelope_id, e.corr_id, reason);
    }

    /// @notice Initiator can close the envelope before delivery.
    /// @dev Closing an envelope that was already Accepted or Rejected
    ///      reverts (those are terminal). Closing during
    ///      Drafted/Signing/Signed is permitted.
    function close(bytes32 envelope_id, bytes32 initiator) external {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        if (
            e.state == EnvelopeState.Accepted ||
            e.state == EnvelopeState.Rejected ||
            e.state == EnvelopeState.Closed ||
            e.state == EnvelopeState.Delivered
        ) {
            revert InvalidStateForClose(e.state);
        }
        require(e.initiator == initiator, "MultiSigEnvelope: not initiator");
        EnvelopeState oldState = e.state;
        e.state = EnvelopeState.Closed;
        emit EnvelopeStateChanged(envelope_id, oldState, e.state);
    }

    // ── Read views ──────────────────────────────────────────────────

    function getEnvelope(bytes32 envelope_id)
        external view returns (Envelope memory)
    {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) revert DoesNotExist(envelope_id);
        return e;
    }

    function getState(bytes32 envelope_id) external view returns (EnvelopeState) {
        return _envelopes[envelope_id].state;
    }

    function signatureOf(bytes32 envelope_id, bytes32 signer)
        external view returns (bytes memory)
    {
        return _signatures[envelope_id][signer];
    }

    function signedCount(bytes32 envelope_id) external view returns (uint256) {
        return _envelopes[envelope_id].signed_by.length;
    }

    function isSignedThresholdMet(bytes32 envelope_id) external view returns (bool) {
        Envelope storage e = _envelopes[envelope_id];
        if (e.state == EnvelopeState.NotExist) return false;
        return e.signed_by.length >= e.threshold;
    }

    // ── Internal ────────────────────────────────────────────────────

    function _isRequiredSigner(Envelope storage e, bytes32 signer)
        internal view returns (bool)
    {
        uint256 n = e.required_signers.length;
        for (uint256 i; i < n; ++i) {
            if (e.required_signers[i] == signer) return true;
        }
        return false;
    }

    function _alreadySigned(Envelope storage e, bytes32 signer)
        internal view returns (bool)
    {
        uint256 n = e.signed_by.length;
        for (uint256 i; i < n; ++i) {
            if (e.signed_by[i] == signer) return true;
        }
        return false;
    }
}
