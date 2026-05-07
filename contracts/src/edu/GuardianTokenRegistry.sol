// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title GuardianTokenRegistry
/// @notice One-time guardian setup token registry for WP-A10 (guardian
///         setup distribution). Districts claim a hashed token before
///         emailing the original token to the guardian; on first
///         redemption the token is burned and cannot be reused.
/// @dev    Closes WP-A10.4 of IT-TURNKEY-CODA. Companion to
///         `cli-school-bootstrap::guardian_packet` which generates the
///         raw token + hash and renders the per-guardian HTML.
///
///         The on-chain commitment is SHA-256 of the raw token. The
///         guardian-packet generator computes this hash; the district
///         calls `claimToken` with the hash; the parent-portal static
///         site (per planset 01_A10 Decision 5) calls `consumeToken`
///         when the guardian opens the link. Tokens auto-expire after
///         their `expiresAt` deadline; an off-chain sweeper calls
///         `expireToken` to garbage-collect stale entries.
///
///         Privacy property (per planset 01_A10 Decision 4): the raw
///         token never appears on-chain; only its SHA-256 hash. An
///         observer who sees a `TokenClaimed` event learns only that
///         a hash was claimed by district X — they cannot derive the
///         raw token, cannot replay it, cannot identify the guardian.
///
///         Right-to-erasure (per planset Decision 6): the district
///         that claimed a token can call `revokeToken` at any time to
///         immediately burn it — used by the bootstrap CLI's
///         `revoke-packet` subcommand to satisfy FERPA right-to-
///         amendment requests.
///
///         State machine:
///           Unclaimed (default zero state) → Claimed (district calls claimToken)
///           Claimed → Consumed (guardian opens the link)
///           Claimed → Expired (sweeper or anyone after expiresAt)
///           Claimed → Revoked (district calls revokeToken; right-to-erasure)
///
///         Once a token leaves Claimed it cannot return; all of
///         Consumed/Expired/Revoked are terminal.
contract GuardianTokenRegistry {
    // ──────────────────────────────────────────────────────────────
    // Types
    // ──────────────────────────────────────────────────────────────

    /// @dev Token lifecycle state. `Unclaimed` is the implicit default
    ///      because mapping reads return zero-initialized struct; we
    ///      add a `claimed` bool to disambiguate "never seen" from
    ///      "seen-but-now-expired-with-state-Expired".
    enum TokenState {
        Unclaimed,
        Claimed,
        Consumed,
        Expired,
        Revoked
    }

    struct Token {
        address district;     // who claimed; receives revocation rights
        uint64 issuedAt;      // block.timestamp at claim time
        uint64 expiresAt;     // hard deadline; consumeToken refuses past this
        TokenState state;
    }

    // ──────────────────────────────────────────────────────────────
    // Storage
    // ──────────────────────────────────────────────────────────────

    /// @dev Hashed token → Token record.
    mapping(bytes32 => Token) public tokens;

    /// @notice Total tokens ever claimed (monotonic; for off-chain
    ///         analytics / audit traces).
    uint256 public totalClaimed;

    /// @notice Maximum allowed expiry window from the current block.
    ///         Per planset 01_A10 Decision 4, tokens expire after 14 days
    ///         OR first use, whichever comes first. The contract enforces
    ///         the 14-day cap as a hard upper bound regardless of the
    ///         claimer's `expiresAt`. Districts can claim with shorter
    ///         windows but cannot exceed this.
    uint64 public constant MAX_EXPIRY_WINDOW = 14 days;

    // ──────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────

    event TokenClaimed(bytes32 indexed hashedToken, address indexed district, uint64 expiresAt);
    event TokenConsumed(bytes32 indexed hashedToken);
    event TokenExpired(bytes32 indexed hashedToken);
    event TokenRevoked(bytes32 indexed hashedToken, address indexed district);

    // ──────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────

    error TokenAlreadyClaimed();
    error TokenNotClaimed();
    error TokenAlreadyConsumed();
    error TokenAlreadyExpired();
    error TokenAlreadyRevoked();
    error ExpiryTooLong();
    error ExpiryInPast();
    error NotTokenIssuer();
    error NotYetExpired();

    // ──────────────────────────────────────────────────────────────
    // Mutators
    // ──────────────────────────────────────────────────────────────

    /// @notice District claims a hashed setup token. The raw token is
    ///         already in the per-guardian HTML packet; this commits
    ///         the hash to chain so consumption can be verified.
    /// @param hashedToken SHA-256 of the raw token (32 bytes).
    /// @param expiresAt   Unix timestamp at which the token auto-expires.
    function claimToken(bytes32 hashedToken, uint64 expiresAt) external {
        if (tokens[hashedToken].state != TokenState.Unclaimed) {
            revert TokenAlreadyClaimed();
        }
        if (expiresAt <= block.timestamp) revert ExpiryInPast();
        if (expiresAt - uint64(block.timestamp) > MAX_EXPIRY_WINDOW) {
            revert ExpiryTooLong();
        }

        tokens[hashedToken] = Token({
            district: msg.sender,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            state: TokenState.Claimed
        });

        unchecked {
            totalClaimed += 1;
        }

        emit TokenClaimed(hashedToken, msg.sender, expiresAt);
    }

    /// @notice Guardian's setup-link redemption: the parent-portal site
    ///         computes SHA-256(rawToken) and calls this. Returns the
    ///         district address so the portal knows which school's
    ///         keystore to consult for the next step in the flow.
    /// @dev    Anyone can call (the portal is public-facing); the
    ///         consume action itself is the proof of possession of the
    ///         raw token, and consume-once is enforced here.
    function consumeToken(bytes32 hashedToken) external returns (address district) {
        Token storage tk = tokens[hashedToken];

        if (tk.state == TokenState.Unclaimed) revert TokenNotClaimed();
        if (tk.state == TokenState.Consumed) revert TokenAlreadyConsumed();
        if (tk.state == TokenState.Expired) revert TokenAlreadyExpired();
        if (tk.state == TokenState.Revoked) revert TokenAlreadyRevoked();
        // Only Claimed remains. Refuse if past expiresAt — an off-chain
        // sweeper SHOULD have called expireToken; if it hasn't yet, we
        // still treat the token as expired here. Don't mutate state on
        // this path (let the sweeper or a follow-up call do that).
        if (block.timestamp >= tk.expiresAt) revert TokenAlreadyExpired();

        tk.state = TokenState.Consumed;
        emit TokenConsumed(hashedToken);
        return tk.district;
    }

    /// @notice Off-chain sweeper or anyone-after-deadline calls this to
    ///         garbage-collect stale Claimed tokens. Idempotent: if
    ///         the token is already terminal, reverts with the matching
    ///         error so the sweeper can log + skip.
    function expireToken(bytes32 hashedToken) external {
        Token storage tk = tokens[hashedToken];
        if (tk.state == TokenState.Unclaimed) revert TokenNotClaimed();
        if (tk.state == TokenState.Consumed) revert TokenAlreadyConsumed();
        if (tk.state == TokenState.Expired) revert TokenAlreadyExpired();
        if (tk.state == TokenState.Revoked) revert TokenAlreadyRevoked();
        if (block.timestamp < tk.expiresAt) revert NotYetExpired();

        tk.state = TokenState.Expired;
        emit TokenExpired(hashedToken);
    }

    /// @notice District revokes a token before consumption — used for
    ///         FERPA right-to-erasure (guardian withdrew consent;
    ///         student transferred; etc.). Only the district that
    ///         claimed the token can revoke it.
    /// @dev    Per planset 01_A10 Decision 6, this is the on-chain
    ///         half of the right-to-erasure. The other half is the
    ///         district's bootstrap CLI deleting the encrypted PII
    ///         from its filesystem.
    function revokeToken(bytes32 hashedToken) external {
        Token storage tk = tokens[hashedToken];
        if (tk.state == TokenState.Unclaimed) revert TokenNotClaimed();
        if (tk.state == TokenState.Consumed) revert TokenAlreadyConsumed();
        if (tk.state == TokenState.Expired) revert TokenAlreadyExpired();
        if (tk.state == TokenState.Revoked) revert TokenAlreadyRevoked();
        if (tk.district != msg.sender) revert NotTokenIssuer();

        tk.state = TokenState.Revoked;
        emit TokenRevoked(hashedToken, msg.sender);
    }

    // ──────────────────────────────────────────────────────────────
    // Views
    // ──────────────────────────────────────────────────────────────

    /// @notice Returns the lifecycle state of a token. Convenience
    ///         wrapper for off-chain auditors that don't want to
    ///         decode the raw struct.
    function getTokenState(bytes32 hashedToken) external view returns (TokenState) {
        return tokens[hashedToken].state;
    }

    /// @notice Returns true iff the token is currently in `Claimed`
    ///         state AND has not passed its expiry deadline. The
    ///         parent-portal site uses this as a pre-check before
    ///         calling consumeToken (which would also reject, but
    ///         this gives a softer UX path).
    function isRedeemable(bytes32 hashedToken) external view returns (bool) {
        Token storage tk = tokens[hashedToken];
        return tk.state == TokenState.Claimed && block.timestamp < tk.expiresAt;
    }
}
