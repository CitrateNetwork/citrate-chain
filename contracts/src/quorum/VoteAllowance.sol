// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title VoteAllowance — the franchise for agents
/// @notice citrate-quorum QRM-S6.6. Planset `03_GOVERNANCE_CONTRACTS.md` §4.
/// Formal spec: `specs/tla/contracts/VoteAllowance.tla` (VA-1…VA-4).
///
/// **Agents never hold voting power.** They spend an allowance a human
/// principal delegated to them, with ERC-20-allowance semantics: a cap, a
/// running total, and an immediate revoke. Every vote an agent casts is
/// therefore a vote some specific person is answerable for.
///
/// ## The four invariants
///
/// **VA-1 `spent <= weightCap`, always.** Enforced by refusing an over-cap
/// cast rather than clamping it, so a partial vote is never recorded as if it
/// were the whole one.
///
/// **VA-2 an expired or revoked allowance can never be spent.** Revocation is
/// immediate and unconditional — the "pull the plug" property an executive will
/// ask about, and the honest answer has to be "the next block", not "once
/// in-flight work drains".
///
/// **VA-3 every agent vote traces to exactly one human principal.** The
/// principal is `msg.sender` at grant time and is never settable afterwards, and
/// every cast emits it. There is no path that produces a vote whose principal is
/// ambiguous or absent.
///
/// **VA-4 allowances never compound.** There is no API to delegate an allowance
/// onward. This is structural, not a check: the delegate is an `agentSbtId` —
/// not an address — so a delegate has nothing to grant *from*, and `grant`
/// always writes `principal = msg.sender`. A chain of delegation cannot form
/// because there is no way to name someone else as the source of authority.
///
/// ## Why this is stricter than `CapabilityGrant`, on purpose
///
/// `CapabilityGrant` lets a tenant admin issue a grant on another person's
/// behalf, because authorizing an agent to do work is an administrative act
/// somebody may legitimately perform for a colleague.
///
/// A franchise is not. Delegating **someone else's vote** is precisely the thing
/// that must be impossible, so `grant` here has no on-behalf-of path at all and
/// no admin override — not even the tenant's. An admin who wants an agent to
/// vote their way can vote themselves.
///
/// ## What this contract deliberately does not know
///
/// It does not know what a vote is worth. Voting-power basis — SALT/stSALT, an
/// org governance token, role-weighted one-person-one-vote — is planset Q7 and
/// is unresolved. The allowance layer is basis-agnostic by design: it records
/// that weight W was cast by agent A under principal P on proposal X, and
/// whatever tallies votes reads that. Building a tally in here would quietly
/// decide Q7.
///
/// ## Units, kept identical to `CapabilityGrant` and to the Rust
///
/// Expiry is epoch **milliseconds** compared against `block.timestamp * 1000`,
/// and caps are bounded by `type(uint64).max`, for the reasons documented on
/// `CapabilityGrant`: `quorum-policy`'s `VoteAllowance` is the same rules in
/// process, with `i64` ms and a `u64` cap, and a value that cannot round-trip
/// between the two is a divergence waiting to decide something.
contract VoteAllowance {
    struct Allowance {
        address principal;
        /// Who submits casts on the agent's behalf. Agents are keyless
        /// (citrate-quorum rule 4), so something with a key has to transact;
        /// naming it here means only that one address can spend this franchise.
        address caster;
        uint256 agentSbtId;
        bytes32 tenantScope;
        bytes32[] proposalClasses;
        uint256 weightCap;
        uint256 spent;
        /// Epoch MILLISECONDS.
        uint64 expiresAtMs;
        bool revoked;
        /// The HIC capability grant this franchise hangs off, so an auditor can
        /// go from a vote to the envelope that permitted the agent to act at all.
        bytes32 hicGrantId;
        bool exists;
    }

    uint256 public constant MAX_PROPOSAL_CLASSES = 32;

    mapping(bytes32 => Allowance) private _allowances;
    /// principal → allowance ids, in grant order.
    mapping(address => bytes32[]) private _byPrincipal;
    mapping(address => uint256) public grantNonce;
    /// allowance → proposal → already cast. One allowance votes once per
    /// proposal; see `castVote`.
    mapping(bytes32 => mapping(bytes32 => bool)) public hasCast;

    error UnknownAllowance(bytes32 allowanceId);
    error NotPrincipal(bytes32 allowanceId, address caller);
    error NotCaster(bytes32 allowanceId, address caller);
    error AllowanceInactive(bytes32 allowanceId);
    error ClassNotCovered(bytes32 allowanceId, bytes32 proposalClass);
    error OverAllowance(bytes32 allowanceId, uint256 weight, uint256 remaining);
    error AlreadyCast(bytes32 allowanceId, bytes32 proposalId);
    error ZeroCaster();
    error NoProposalClasses();
    error TooManyProposalClasses(uint256 count);
    error DuplicateProposalClass(bytes32 proposalClass);
    error ZeroWeightCap();
    error WeightCapTooLarge(uint256 weightCap);
    error AlreadyExpired(uint64 expiresAtMs, uint64 nowMs);
    error CannotReduceBelowSpent(bytes32 allowanceId, uint256 requested, uint256 spent);
    error ZeroIncrease();
    error DecreaseWouldWiden(bytes32 allowanceId, uint256 requested, uint256 weightCap);

    event AllowanceGranted(
        bytes32 indexed allowanceId,
        address indexed principal,
        uint256 indexed agentSbtId,
        bytes32 tenantScope,
        uint256 weightCap,
        uint64 expiresAtMs,
        bytes32 hicGrantId,
        address caster
    );
    event AllowanceIncreased(bytes32 indexed allowanceId, uint256 by, uint256 newCap);
    event AllowanceDecreased(bytes32 indexed allowanceId, uint256 to, uint256 spent);
    event AllowanceRevoked(bytes32 indexed allowanceId, address indexed principal);
    event AgentVoteCast(
        bytes32 indexed proposalId,
        uint256 indexed agentSbtId,
        address indexed principal,
        uint8 support,
        uint256 weight,
        bytes32 allowanceId,
        uint256 spentTotal
    );

    // ── Delegating ──────────────────────────────────────────────────

    /// Delegate part of your franchise to an agent.
    ///
    /// The principal is `msg.sender`, always. There is no on-behalf-of path —
    /// see the contract header for why this is stricter than `CapabilityGrant`.
    function grant(
        uint256 agentSbtId,
        address caster,
        bytes32 tenantScope,
        bytes32[] calldata proposalClasses,
        uint256 weightCap,
        uint64 expiresAtMs,
        bytes32 hicGrantId
    ) external returns (bytes32 allowanceId) {
        if (caster == address(0)) revert ZeroCaster();
        if (proposalClasses.length == 0) revert NoProposalClasses();
        if (proposalClasses.length > MAX_PROPOSAL_CLASSES) revert TooManyProposalClasses(proposalClasses.length);
        for (uint256 i = 0; i < proposalClasses.length; ++i) {
            for (uint256 j = i + 1; j < proposalClasses.length; ++j) {
                if (proposalClasses[i] == proposalClasses[j]) revert DuplicateProposalClass(proposalClasses[i]);
            }
        }
        // A zero-cap allowance can never be spent. It would read, to anyone
        // reviewing delegations, like a franchise that exists.
        if (weightCap == 0) revert ZeroWeightCap();
        if (weightCap > type(uint64).max) revert WeightCapTooLarge(weightCap);

        uint64 nowMs = uint64(block.timestamp * 1000);
        if (expiresAtMs <= nowMs) revert AlreadyExpired(expiresAtMs, nowMs);

        allowanceId =
            keccak256(abi.encode(address(this), msg.sender, agentSbtId, tenantScope, grantNonce[msg.sender]++));

        Allowance storage a = _allowances[allowanceId];
        a.principal = msg.sender;
        a.caster = caster;
        a.agentSbtId = agentSbtId;
        a.tenantScope = tenantScope;
        a.weightCap = weightCap;
        a.expiresAtMs = expiresAtMs;
        a.hicGrantId = hicGrantId;
        a.exists = true;
        for (uint256 i = 0; i < proposalClasses.length; ++i) {
            a.proposalClasses.push(proposalClasses[i]);
        }
        _byPrincipal[msg.sender].push(allowanceId);

        emit AllowanceGranted(
            allowanceId, msg.sender, agentSbtId, tenantScope, weightCap, expiresAtMs, hicGrantId, caster
        );
    }

    /// Widen an existing allowance. Principal only.
    function increase(bytes32 allowanceId, uint256 by) external {
        Allowance storage a = _principalOnly(allowanceId);
        if (by == 0) revert ZeroIncrease();
        uint256 newCap = a.weightCap + by;
        if (newCap > type(uint64).max) revert WeightCapTooLarge(newCap);
        a.weightCap = newCap;
        emit AllowanceIncreased(allowanceId, by, newCap);
    }

    /// Narrow an existing allowance. Principal only.
    ///
    /// Not in the planset's `grant / increase / revoke` list, and added
    /// deliberately: without it, the only way to reduce a franchise is to revoke
    /// and re-grant, which mints a new allowance id and breaks the trace from an
    /// in-flight vote back to the delegation that permitted it. Reduction is
    /// always the safe direction.
    ///
    /// It cannot go below what has already been spent — that would make VA-1
    /// retroactively false and imply votes that were cast never were.
    function decrease(bytes32 allowanceId, uint256 to) external {
        Allowance storage a = _principalOnly(allowanceId);
        if (to < a.spent) revert CannotReduceBelowSpent(allowanceId, to, a.spent);
        // `decrease` may only narrow. Without this it could *raise* the cap
        // past `grant`/`increase`'s `type(uint64).max` bound and desync the
        // on-chain franchise from the u64 `quorum-policy` mirror.
        if (to > a.weightCap) revert DecreaseWouldWiden(allowanceId, to, a.weightCap);
        a.weightCap = to;
        emit AllowanceDecreased(allowanceId, to, a.spent);
    }

    /// Immediate and unconditional. VA-2. Principal only, idempotent.
    ///
    /// Not even a tenant admin: an allowance is one person's franchise, and
    /// someone else being able to end it is a different power than the one this
    /// contract is modelling. (Contrast `CapabilityGrant.revoke`, where an admin
    /// pulling the plug on an agent's *work* is exactly right.)
    function revoke(bytes32 allowanceId) external {
        Allowance storage a = _principalOnly(allowanceId);
        if (a.revoked) return;
        a.revoked = true;
        emit AllowanceRevoked(allowanceId, msg.sender);
    }

    // ── Spending ────────────────────────────────────────────────────

    /// Cast a vote against an allowance.
    ///
    /// Refuses — never clamps — if the allowance is dead, does not cover the
    /// class, or the weight exceeds what is left. A clamped vote would be
    /// recorded as though the agent had voted the amount it asked for.
    ///
    /// One cast per `(allowance, proposal)`. An allowance voting twice on one
    /// proposal is either a duplicate or a contradiction, and neither should be
    /// resolved silently by whatever tallies. Changing a position means the
    /// principal voting themselves; there is deliberately no agent-facing path
    /// to revise a cast.
    ///
    /// `support` is passed through untouched. This contract does not interpret
    /// it — see the header on Q7.
    function castVote(bytes32 allowanceId, bytes32 proposalId, bytes32 proposalClass, uint8 support, uint256 weight)
        external
        returns (uint256 spentTotal)
    {
        Allowance storage a = _get(allowanceId);
        if (msg.sender != a.caster) revert NotCaster(allowanceId, msg.sender);
        if (!isLive(allowanceId)) revert AllowanceInactive(allowanceId);
        if (!_covers(a, proposalClass)) revert ClassNotCovered(allowanceId, proposalClass);
        if (hasCast[allowanceId][proposalId]) revert AlreadyCast(allowanceId, proposalId);

        uint256 left = a.weightCap - a.spent;
        if (weight > left) revert OverAllowance(allowanceId, weight, left);

        a.spent += weight;
        hasCast[allowanceId][proposalId] = true;
        spentTotal = a.spent;

        // VA-3: the principal is in every cast event. A vote whose principal had
        // to be reconstructed from elsewhere would not be traceable, it would be
        // inferable.
        emit AgentVoteCast(proposalId, a.agentSbtId, a.principal, support, weight, allowanceId, a.spent);
    }

    // ── Views ───────────────────────────────────────────────────────

    /// Not revoked, not expired. VA-2 means revocation wins over any remaining
    /// time.
    function isLive(bytes32 allowanceId) public view returns (bool) {
        Allowance storage a = _allowances[allowanceId];
        if (!a.exists) return false;
        return !a.revoked && a.expiresAtMs > uint64(block.timestamp * 1000);
    }

    /// Weight left. Saturating, matching `quorum_policy::VoteAllowance::remaining`.
    function remaining(bytes32 allowanceId) public view returns (uint256) {
        Allowance storage a = _allowances[allowanceId];
        return a.spent >= a.weightCap ? 0 : a.weightCap - a.spent;
    }

    /// Could this allowance cast this weight on this class right now? The whole
    /// precondition of `castVote`, exposed so a caller can ask before it acts
    /// instead of learning from a revert.
    ///
    /// False for an unknown id rather than reverting — a caller may ask about
    /// ids that do not exist, and "no" answers all of them.
    function covers(bytes32 allowanceId, bytes32 proposalId, bytes32 proposalClass, uint256 weight)
        external
        view
        returns (bool)
    {
        if (!isLive(allowanceId)) return false;
        if (hasCast[allowanceId][proposalId]) return false;
        Allowance storage a = _allowances[allowanceId];
        if (weight > remaining(allowanceId)) return false;
        return _covers(a, proposalClass);
    }

    function allowanceOf(bytes32 allowanceId) external view returns (Allowance memory) {
        return _get(allowanceId);
    }

    function proposalClassesOf(bytes32 allowanceId) external view returns (bytes32[] memory) {
        return _get(allowanceId).proposalClasses;
    }

    function allowanceCount(address principal) external view returns (uint256) {
        return _byPrincipal[principal].length;
    }

    function allowanceAt(address principal, uint256 index) external view returns (bytes32) {
        return _byPrincipal[principal][index];
    }

    // ── Internal ────────────────────────────────────────────────────

    function _get(bytes32 allowanceId) private view returns (Allowance storage a) {
        a = _allowances[allowanceId];
        if (!a.exists) revert UnknownAllowance(allowanceId);
    }

    function _principalOnly(bytes32 allowanceId) private view returns (Allowance storage a) {
        a = _get(allowanceId);
        if (msg.sender != a.principal) revert NotPrincipal(allowanceId, msg.sender);
    }

    function _covers(Allowance storage a, bytes32 proposalClass) private view returns (bool) {
        for (uint256 i = 0; i < a.proposalClasses.length; ++i) {
            if (a.proposalClasses[i] == proposalClass) return true;
        }
        return false;
    }
}
