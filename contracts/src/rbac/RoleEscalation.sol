// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title RoleEscalation — time-bounded admin elevation
/// @notice Encodes the existing `it_elevation.rs` semantics on-chain.
///         A user holds a base role; can request elevation to a higher
///         role for a bounded duration; expiry auto-revokes; correlation
///         IDs flow through every event for audit replay.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/RoleEscalationGrant.tla`
/// @dev Cited invariants:
///   - `NoDoubleActiveGrant` — at most one active grant per (user, tenant).
///     Enforced by `requestElevation` revert when an active grant exists.
///   - `EnteredImpliesReauthProof` — every active grant has a non-empty
///     `reauth_proof_kind`. Enforced by `requestElevation` require.
///   - `InactiveImpliesNoProof` — exited grants are flagged inactive
///     and the reauth_proof is no longer authoritative.
///   - `ActiveExpiresAfterGranted` — `expires_at > granted_at`.
///     Enforced by duration > 0 require.
///   - `ActiveImpliesNotExpired` — caller of `requestElevation` cannot
///     re-elevate while an unexpired grant is still active.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § 2. DPF-02 deliverable.
contract RoleEscalation {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice One elevation grant. Append-only history per (user, tenant).
    /// @dev `reauth_proof_kind` is a small tag string ("kba" / "biometric"
    ///      / "sms_otp" / "email" / "agent_obo") attesting the kind of
    ///      proof the caller presented; the cryptographic proof itself
    ///      is consumed off-chain (HSM, oracle) and the `reauth_proof`
    ///      bytes argument is hashed and stored as audit trail only.
    struct RoleGrant {
        bytes32 user;
        bytes32 tenant;
        bytes32 role;
        uint64  granted_at;
        uint64  expires_at;
        bytes32 corr_id;
        bytes32 reauth_proof_hash;
        string  reauth_proof_kind;
        bool    active;
    }

    // ── Constants ───────────────────────────────────────────────────

    /// @notice Default elevation window. Mirrors prototype's 60-min
    ///         RoleEscalationTimer window. Configurable per call.
    uint32 public constant DEFAULT_ELEVATION_SECONDS = 3600;

    /// @notice Hard cap on a single elevation duration.
    /// @dev Caps long-lived elevations that would defeat the
    ///      "time-bounded" semantic. 8h matches prototype's session
    ///      timeout (used in WP-5 RoleTimer "session timeout" copy).
    uint32 public constant MAX_ELEVATION_SECONDS = 8 hours;

    // ── State ───────────────────────────────────────────────────────

    /// @notice Append-only grant log per (user, tenant).
    mapping(bytes32 user => mapping(bytes32 tenant => RoleGrant[])) private _grants;

    /// @notice Each user's base role per tenant. Set by tenant admins
    ///         (off-chain multi-sig batches via MultiSigEnvelope).
    mapping(bytes32 user => mapping(bytes32 tenant => bytes32)) public base_role;

    /// @notice Authorized base-role setters. The full RBAC dependency
    ///         chain (TenantHierarchy admin -> MultiSigEnvelope -> here)
    ///         lives off-chain; this contract trusts the configured
    ///         setters as the system's single point of admin-action
    ///         entry. The setter list is itself governed by the
    ///         root-tenant multi-sig (initialized at construction).
    mapping(address => bool) public is_role_admin;
    /// @notice CHAIN-B-C044(c): count of live role-admins, so the last one can
    ///         never be removed (which would permanently brick every
    ///         admin-gated path — base roles, elevations and the admin set).
    uint256 public roleAdminCount;

    // ── Events ──────────────────────────────────────────────────────

    /// @notice Emitted when an elevation grant becomes active.
    /// @param user The hashed user id.
    /// @param tenant The scope of the grant.
    /// @param role The granted role.
    /// @param expires_at Unix timestamp when the grant auto-expires.
    /// @param corr_id Correlation id flowing through the audit trail.
    /// @param reauth_proof_kind Tag identifying the proof type.
    event Entered(
        bytes32 indexed user,
        bytes32 indexed tenant,
        bytes32 indexed role,
        uint64 expires_at,
        bytes32 corr_id,
        string reauth_proof_kind
    );

    /// @notice Emitted when an active grant is deactivated.
    /// @param reason "voluntary" | "expired" | "auto-revoke" | "admin-revoke"
    event Exited(
        bytes32 indexed user,
        bytes32 indexed tenant,
        bytes32 indexed role,
        bytes32 corr_id,
        string  reason
    );

    /// @notice Emitted when a request is denied without taking effect.
    /// @param reason "stale-reauth" | "already-elevated" | "base-role-not-admin"
    event Refused(
        bytes32 indexed user,
        bytes32 indexed tenant,
        bytes32 indexed role,
        bytes32 corr_id,
        string  reason
    );

    /// @notice Emitted when the base role mapping changes.
    event BaseRoleSet(
        bytes32 indexed user,
        bytes32 indexed tenant,
        bytes32 indexed role,
        address admin
    );

    /// @notice Emitted when an address is added/removed from the
    ///         role-admin set.
    event RoleAdminSet(address indexed admin, bool authorized);

    // ── Errors ──────────────────────────────────────────────────────

    error NotRoleAdmin(address caller);
    error EmptyReauthProof();
    error EmptyReauthProofKind();
    error ZeroDuration();
    error ExceedsMaxDuration(uint32 requested, uint32 max);
    error AlreadyElevated(bytes32 user, bytes32 tenant);
    error NoActiveGrant(bytes32 user, bytes32 tenant);
    error InvalidThreshold();
    /// @notice The subject has no base role set in this tenant, so there
    ///         is nothing to elevate FROM. FWA-C3-01 hardening.
    error NoBaseRole(bytes32 user, bytes32 tenant);
    /// @notice The last role-admin may not be removed (would brick the contract).
    error CannotRemoveLastAdmin();

    // ── Constructor ─────────────────────────────────────────────────

    /// @notice Initialize with the address authorized to set base roles
    ///         and add/remove other role-admins. Typically the
    ///         MultiSigEnvelope executor that lands the root-tenant
    ///         multi-sig on-chain.
    constructor(address initialAdmin) {
        require(initialAdmin != address(0), "RoleEscalation: zero admin");
        is_role_admin[initialAdmin] = true;
        roleAdminCount = 1;
        emit RoleAdminSet(initialAdmin, true);
    }

    // ── Admin set ───────────────────────────────────────────────────

    /// @notice Add or remove a role-admin. Self-bootstrapping: any
    ///         existing role-admin can adjust the set.
    function setRoleAdmin(address admin, bool authorized) external {
        if (!is_role_admin[msg.sender]) revert NotRoleAdmin(msg.sender);
        // CHAIN-B-C044(c): maintain a live count and refuse to remove the last
        // admin. Pre-fix any role-admin could remove every other admin
        // (including the bootstrap one), leaving the contract with no admin and
        // permanently un-administrable. Idempotent writes change no count.
        bool was = is_role_admin[admin];
        if (was != authorized) {
            if (authorized) {
                roleAdminCount++;
            } else {
                if (roleAdminCount <= 1) revert CannotRemoveLastAdmin();
                roleAdminCount--;
            }
        }
        is_role_admin[admin] = authorized;
        emit RoleAdminSet(admin, authorized);
    }

    /// @notice Set or update a user's base role within a tenant.
    function setBaseRole(bytes32 user, bytes32 tenant, bytes32 role) external {
        if (!is_role_admin[msg.sender]) revert NotRoleAdmin(msg.sender);
        base_role[user][tenant] = role;
        emit BaseRoleSet(user, tenant, role, msg.sender);
    }

    // ── Elevation flow ──────────────────────────────────────────────

    /// @notice Request a time-bounded elevation. Must present a non-empty
    ///         `reauth_proof` (its hash is stored as audit material; the
    ///         cryptographic verification of the proof itself is the
    ///         caller's responsibility — the off-chain orchestrator
    ///         must have already verified the proof before calling).
    /// @param user The hashed user id (typically `keccak256(user_id)`).
    /// @param tenant The scope under which the elevation applies.
    /// @param role The role to elevate to.
    /// @param duration_sec Elevation window. 0 means use the default.
    /// @param corr_id Correlation id for audit replay.
    /// @param reauth_proof Non-empty proof bytes; only its hash persists.
    /// @param reauth_proof_kind Non-empty tag of the proof type.
    ///
    /// @dev FWA-C3-01 hardening. The off-chain orchestrator that
    ///      cryptographically verifies the re-auth proof (HSM / oracle)
    ///      is the system's single authorized elevation issuer; it is
    ///      registered as a role-admin (`is_role_admin`). This function
    ///      therefore requires `msg.sender` to be a role-admin so an
    ///      arbitrary EOA can NO LONGER mint an active grant for any
    ///      principal. It additionally requires the subject to hold a
    ///      base role in this tenant — there is nothing to elevate FROM
    ///      otherwise, and a missing base role signals the (user,tenant)
    ///      pair was never provisioned.
    function requestElevation(
        bytes32 user,
        bytes32 tenant,
        bytes32 role,
        uint32  duration_sec,
        bytes32 corr_id,
        bytes calldata reauth_proof,
        string calldata reauth_proof_kind
    ) external {
        // FWA-C3-01: gate on the authorized elevation issuer. The proof
        // is verified off-chain by this same role-admin before it calls.
        if (!is_role_admin[msg.sender]) revert NotRoleAdmin(msg.sender);
        if (reauth_proof.length == 0) revert EmptyReauthProof();
        if (bytes(reauth_proof_kind).length == 0) revert EmptyReauthProofKind();
        // FWA-C3-01: the subject must already hold a base role in this
        // tenant; elevation lifts an existing role, it cannot bootstrap one.
        if (base_role[user][tenant] == bytes32(0)) revert NoBaseRole(user, tenant);

        uint32 dur = duration_sec == 0 ? DEFAULT_ELEVATION_SECONDS : duration_sec;
        if (dur > MAX_ELEVATION_SECONDS) {
            revert ExceedsMaxDuration(dur, MAX_ELEVATION_SECONDS);
        }

        // NoDoubleActiveGrant — sweep any expired grants first, then
        // refuse if an active one survives.
        _expireOne(user, tenant);
        if (_findActive(user, tenant) != type(uint256).max) {
            emit Refused(user, tenant, role, corr_id, "already-elevated");
            revert AlreadyElevated(user, tenant);
        }

        uint64 grantedAt = uint64(block.timestamp);
        uint64 expiresAt = grantedAt + dur;
        _grants[user][tenant].push(
            RoleGrant({
                user: user,
                tenant: tenant,
                role: role,
                granted_at: grantedAt,
                expires_at: expiresAt,
                corr_id: corr_id,
                reauth_proof_hash: keccak256(reauth_proof),
                reauth_proof_kind: reauth_proof_kind,
                active: true
            })
        );

        emit Entered(user, tenant, role, expiresAt, corr_id, reauth_proof_kind);
    }

    /// @notice Voluntary step-down. Caller specifies the (user, tenant)
    ///         and corr_id; the active grant is exited with reason
    ///         "voluntary".
    /// @dev FWA-C3-15 hardening. Because `user` is an opaque bytes32 hash
    ///      (not an address), there is no on-chain way to prove the caller
    ///      IS the subject. Gate on the role-admin so an arbitrary EOA can
    ///      no longer deactivate any principal's active grant (griefing /
    ///      availability DoS). The off-chain orchestrator acting on the
    ///      user's behalf is a role-admin.
    function stepDown(bytes32 user, bytes32 tenant, bytes32 corr_id) external {
        if (!is_role_admin[msg.sender]) revert NotRoleAdmin(msg.sender);
        uint256 idx = _findActive(user, tenant);
        if (idx == type(uint256).max) revert NoActiveGrant(user, tenant);
        RoleGrant storage g = _grants[user][tenant][idx];
        g.active = false;
        emit Exited(user, tenant, g.role, corr_id, "voluntary");
    }

    /// @notice Admin-gated revoke. Used by HR oracle for foreign-national
    ///         cascade and by tenant admins for misuse cases.
    function revoke(
        bytes32 user,
        bytes32 tenant,
        bytes32 reason,
        bytes32 corr_id
    ) external {
        if (!is_role_admin[msg.sender]) revert NotRoleAdmin(msg.sender);
        uint256 idx = _findActive(user, tenant);
        if (idx == type(uint256).max) revert NoActiveGrant(user, tenant);
        RoleGrant storage g = _grants[user][tenant][idx];
        g.active = false;
        // Cast bytes32 reason to a short string for the event reason
        // tag. Callers typically use keccak256("auto-revoke") etc.;
        // the off-chain log decoder maps the topic back to a label.
        emit Exited(
            user,
            tenant,
            g.role,
            corr_id,
            string(abi.encodePacked("admin-revoke:", _bytes32ToHex(reason)))
        );
    }

    /// @notice Public expiry tick. Anyone may call. Iterates the most
    ///         recent grant slot per (user, tenant) provided in the
    ///         `pairs` array and expires it if past its window.
    /// @dev Bounded gas — caller-batched. Off-chain cron is expected
    ///      to call this regularly.
    function tickExpire(bytes32[] calldata users, bytes32[] calldata tenants)
        external
    {
        require(users.length == tenants.length, "RoleEscalation: arity mismatch");
        for (uint256 i; i < users.length; ++i) {
            _expireOne(users[i], tenants[i]);
        }
    }

    // ── Read views ──────────────────────────────────────────────────

    /// @notice Returns the most-recent grant struct for (user, tenant).
    /// @dev Reverts if no grant has ever been issued.
    function latestGrant(bytes32 user, bytes32 tenant)
        external view returns (RoleGrant memory)
    {
        RoleGrant[] storage gs = _grants[user][tenant];
        if (gs.length == 0) revert NoActiveGrant(user, tenant);
        return gs[gs.length - 1];
    }

    /// @notice Returns the grant log length for (user, tenant).
    function grantCount(bytes32 user, bytes32 tenant) external view returns (uint256) {
        return _grants[user][tenant].length;
    }

    /// @notice Returns the grant at the given index.
    function grantAt(bytes32 user, bytes32 tenant, uint256 index)
        external view returns (RoleGrant memory)
    {
        return _grants[user][tenant][index];
    }

    /// @notice Returns whether (user, tenant) has any unexpired active
    ///         grant. Pure view; does NOT auto-expire.
    function isActiveNow(bytes32 user, bytes32 tenant) external view returns (bool) {
        uint256 idx = _findActive(user, tenant);
        return idx != type(uint256).max;
    }

    // ── Internal ────────────────────────────────────────────────────

    function _findActive(bytes32 user, bytes32 tenant)
        internal view returns (uint256)
    {
        RoleGrant[] storage gs = _grants[user][tenant];
        if (gs.length == 0) return type(uint256).max;
        // Most-recent grant is the only candidate; older grants are
        // already inactive (closed by stepDown / revoke / expire) by
        // the NoDoubleActiveGrant invariant.
        uint256 last = gs.length - 1;
        RoleGrant storage g = gs[last];
        if (g.active && g.expires_at > block.timestamp) return last;
        return type(uint256).max;
    }

    function _expireOne(bytes32 user, bytes32 tenant) internal {
        RoleGrant[] storage gs = _grants[user][tenant];
        if (gs.length == 0) return;
        RoleGrant storage g = gs[gs.length - 1];
        if (g.active && g.expires_at <= block.timestamp) {
            g.active = false;
            emit Exited(user, tenant, g.role, g.corr_id, "expired");
        }
    }

    function _bytes32ToHex(bytes32 v) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i; i < 32; ++i) {
            uint8 b = uint8(v[i]);
            out[2 * i] = hexChars[b >> 4];
            out[2 * i + 1] = hexChars[b & 0x0f];
        }
        return string(out);
    }
}
