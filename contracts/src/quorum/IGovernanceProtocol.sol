// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title IGovernanceProtocol — what every deployed governance protocol answers
/// @notice citrate-quorum QRM-S6. Planset `03_GOVERNANCE_CONTRACTS.md` §3.
///
/// A governance protocol is a deployed, template-bounded contract that answers
/// ONE question about ONE proposed action: may it proceed, and if not, what does
/// it need? `PolicyBinding` fans a `(tenant, actionClass)` out to the protocols
/// bound to it and combines their verdicts.
///
/// ## Why this is a `view` and returns a reason
///
/// The caller may be a contract enforcing on chain, or citrate-quorum's policy
/// gate deciding whether to let an agent act. Neither can use a bare boolean:
/// the gate has to TELL the operator what happened, and "denied" with no reason
/// is the failure this whole product exists to avoid. So a verdict always
/// carries a machine-readable `reasonCode` that the app maps to a sentence.
///
/// ## The enforcement honesty this interface forces
///
/// `check` cannot execute anything. A protocol says what SHOULD happen; whether
/// that is binding depends entirely on where it is called from:
///
/// | Enforcement | Where `check` is called | Bindingness |
/// |---|---|---|
/// | Advisory  | quorum's gate, before an off-chain action | an agent outside our adapter is not bound |
/// | Binding   | on chain, by the contract about to act | cannot be bypassed |
/// | Attested  | after the fact, recorded with the verdict it got | provable, not preventive |
///
/// Most agent work (writing code, sending mail) is off chain, so most
/// enforcement is advisory + attested. That distinction is stated here, in the
/// interface every protocol implements, because it is the thing most likely to
/// be blurred in a room where someone wants to say "our agents are governed".
interface IGovernanceProtocol {
    /// What a protocol concluded about a proposed action.
    enum Verdict {
        /// Proceed. Nothing further is required.
        Allow,
        /// Refused by this protocol's rules.
        Deny,
        /// A human must approve before it proceeds (HIC-1).
        RequireApproval,
        /// A vote of the named class must pass before it proceeds.
        RequireVote
    }

    /// Everything a protocol is allowed to reason about.
    ///
    /// Deliberately narrow and hash-shaped: no names, no free text, no payload.
    /// A protocol that could read the *content* of an action would put customer
    /// material on a public ledger the moment anyone called it with real data
    /// (planset D6 — hashes and CIDs only).
    struct ActionContext {
        /// The acting agent's `AgentSBT` id, or 0 when a human acts directly.
        uint256 agentSbtId;
        /// The accountable human. Never zero for a governed action — an action
        /// with no principal is `ungoverned`, which quorum records and alerts
        /// on rather than asking a protocol about.
        address principal;
        /// Classification of the material the action touches (0..3, the
        /// `ClassificationRegistry` ladder).
        uint8 classification;
        /// Cost in the action's own units. 0 for actions that do not spend.
        uint256 cost;
        /// `keccak256` of the ABI-encoded call parameters — the *what*, without
        /// the payload.
        bytes32 paramsHash;
        /// Threads related actions (meeting → grant → actions → PR).
        bytes32 correlationId;
    }

    /// May this action proceed under this protocol?
    ///
    /// MUST be `view`: a protocol that could mutate state while being consulted
    /// would make the answer depend on who asked first.
    ///
    /// @param tenantId    the tenant whose rules apply
    /// @param actionClass e.g. `keccak256("repo.write")`
    /// @param ctx         the action, in hashes
    /// @return v               the verdict
    /// @return reasonCode      a stable code the app maps to a sentence; never 0
    /// @return requiredSigners for `RequireApproval`/`RequireVote`, the role or
    ///         signer set that must act. Empty otherwise.
    function check(
        bytes32 tenantId,
        bytes32 actionClass,
        ActionContext calldata ctx
    )
        external
        view
        returns (Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners);

    /// The template this protocol was deployed from, and its version.
    ///
    /// Lets a verifier go from a live protocol address back to the audited
    /// bytecode it must have been built from, without trusting the factory's
    /// event log to still be indexed.
    function template() external view returns (bytes32 templateId, uint32 version);

    /// The canonical Governance Spec this protocol implements.
    ///
    /// GF-3 makes these inseparable from the bytecode at deploy time, so the app
    /// can always put "what we said this does" next to "what it does".
    function spec() external view returns (bytes32 specHash, string memory specCID);
}
