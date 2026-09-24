// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IGovernanceProtocol} from "./IGovernanceProtocol.sol";
import {GovernanceProtocolFactory, ITenantHierarchy} from "./GovernanceProtocolFactory.sol";

/// @title PolicyBinding — the runtime hook
/// @notice citrate-quorum QRM-S6.4. Planset `03_GOVERNANCE_CONTRACTS.md` §3.
///
/// **A deployed protocol is useless if agents can ignore it.** This maps
/// `(tenant, actionClass)` to the protocols that govern it, and answers the one
/// question a capability check asks: may this action proceed, and if not, what
/// does it need?
///
/// ## Enforcement: where the answer binds, and where it only advises
///
/// This is the table the planset requires ship with this contract, and it is
/// stated per call site because blurring it is the single most tempting
/// dishonesty in the product:
///
/// | Class | Where `check` is called | What a verdict is worth |
/// |---|---|---|
/// | **Binding** | On chain, by the contract that is about to act, in the same transaction | Cannot be bypassed. The action reverts. |
/// | **Advisory** | citrate-quorum's policy gate, in the agent adapter, before an off-chain action | Binds every agent that goes through our adapter. An agent operating outside it is not bound by anything here. |
/// | **Attested** | After the fact — the action's decision record carries the verdict it got | Provable, not preventive. |
///
/// Enterprise reality, stated rather than glossed: **most agent work is off
/// chain** — writing code, sending mail, filing tickets — so most enforcement is
/// advisory + attested, with binding enforcement for what touches chain state,
/// money, or capability grants. A deck that says "our agents are governed"
/// without saying which of the three is meant is making a claim this contract
/// does not support.
///
/// What *is* supported, and is worth more than it sounds: an action that took
/// place without a verdict is visible as such, and one that took place against a
/// `Deny` is provably a violation rather than a disagreement.
///
/// ## How several protocols combine (PB-1)
///
/// Most restrictive wins: `Deny` > `RequireVote` > `RequireApproval` > `Allow`.
/// A tenant that binds two protocols to one action class means both, not either
/// — so a single `Deny` ends it no matter what else allows, and the loosest any
/// answer can be is the strictest thing any protocol said.
///
/// `check` returns the combined verdict with the reason of the protocol that set
/// it. [`explain`] returns every protocol's verdict separately, because an
/// operator who was refused deserves the whole picture, not the first sentence.
///
/// ## Unbound is not the same as allowed (PB-4)
///
/// An action class nobody has bound returns `Allow` with the reason
/// `PB_UNGOVERNED`, which a caller MUST NOT treat as `PB_ALLOWED`. That mirrors
/// citrate-quorum's own rule 5 — an action without a live grant is recorded as
/// `ungoverned` and alerted, never silently allowed and never silently dropped.
///
/// The alternative — deny everything unbound — sounds safer and is worse: it
/// means a tenant is dead until every action class its agents might ever touch
/// has been enumerated, which in practice produces one permissive catch-all
/// binding and a false sense of coverage. A tenant that genuinely wants
/// fail-closed opts in with [`setDefaultDeny`], and then unbound is
/// `PB_NO_BINDING`.
///
/// ## Only what the factory built (PB-2/PB-3)
///
/// A binding may name only a protocol `GovernanceProtocolFactory` deployed, and
/// only into the tenant that protocol was deployed for. Without the first, the
/// whole audit chain — audited template → pinned bytecode → deployed protocol —
/// ends at a binding that can point anywhere. Without the second, one tenant's
/// admin could bind another tenant's protocol and govern their actions by
/// somebody else's rules.
contract PolicyBinding {
    bytes32 public constant REASON_UNGOVERNED = bytes32("PB_UNGOVERNED");
    bytes32 public constant REASON_NO_BINDING = bytes32("PB_NO_BINDING");
    bytes32 public constant REASON_ALLOWED = bytes32("PB_ALLOWED");
    /// A protocol whose `check` reverted. Fail-closed (PB-6).
    bytes32 public constant REASON_PROTOCOL_FAILED = bytes32("PB_PROTOCOL_FAILED");

    /// `check` loops over every bound protocol. Unbounded fan-out would make a
    /// binding enforcement site un-callable at some size, which is a denial of
    /// service that arrives silently and long after the binding was made.
    uint256 public constant MAX_PROTOCOLS_PER_ACTION = 16;

    GovernanceProtocolFactory public immutable factory;
    ITenantHierarchy public immutable tenants;

    /// `keccak256(tenant, actionClass)` → protocols, in binding order.
    mapping(bytes32 => address[]) private _bound;
    /// Tenants that opted into refusing unbound action classes.
    mapping(bytes32 => bool) public defaultDeny;

    error NotTenantAdmin(bytes32 tenantId, address caller);
    error NotFactoryDeployed(address protocol);
    error WrongTenantForProtocol(address protocol, bytes32 boundTo, bytes32 deployedFor);
    error AlreadyBound(bytes32 tenantId, bytes32 actionClass, address protocol);
    error NotBound(bytes32 tenantId, bytes32 actionClass, address protocol);
    error TooManyProtocols(bytes32 tenantId, bytes32 actionClass);

    event ProtocolBound(bytes32 indexed tenantId, bytes32 indexed actionClass, address indexed protocol, address by);
    event ProtocolUnbound(bytes32 indexed tenantId, bytes32 indexed actionClass, address indexed protocol, address by);
    event DefaultDenySet(bytes32 indexed tenantId, bool enabled, address by);

    constructor(GovernanceProtocolFactory factory_, ITenantHierarchy tenants_) {
        factory = factory_;
        tenants = tenants_;
    }

    /// The storage key for a bound action class. Exposed so an indexer computes
    /// it the same way rather than reimplementing the encoding.
    function bindingKey(bytes32 tenantId, bytes32 actionClass) public pure returns (bytes32) {
        return keccak256(abi.encode(tenantId, actionClass));
    }

    // ── Binding ─────────────────────────────────────────────────────

    /// Bind a protocol to an action class. Tenant admins only.
    function bind(bytes32 tenantId, bytes32 actionClass, address protocol) external {
        _requireTenantAdmin(tenantId);

        // PB-2 — the audit chain has to reach all the way here. A binding that
        // could name arbitrary code would make "only audited bytecode governs"
        // true of deployment and false of enforcement.
        if (!factory.wasDeployedHere(protocol)) revert NotFactoryDeployed(protocol);

        // PB-3 — and only into its own tenant.
        GovernanceProtocolFactory.Deployment memory d = factory.deploymentOf(protocol);
        if (d.tenantId != tenantId) revert WrongTenantForProtocol(protocol, tenantId, d.tenantId);

        address[] storage list = _bound[bindingKey(tenantId, actionClass)];
        if (list.length >= MAX_PROTOCOLS_PER_ACTION) revert TooManyProtocols(tenantId, actionClass);
        for (uint256 i = 0; i < list.length; ++i) {
            // Binding the same protocol twice would double its say in nothing —
            // the combination is a maximum, not a tally — but it would consume a
            // slot and mislead anyone reading the list.
            if (list[i] == protocol) revert AlreadyBound(tenantId, actionClass, protocol);
        }

        list.push(protocol);
        emit ProtocolBound(tenantId, actionClass, protocol, msg.sender);
    }

    /// Remove a binding. Tenant admins only.
    ///
    /// Unbinding is deliberately possible: a rule a tenant can never withdraw is
    /// not governance, it is a hostage situation. What makes it safe is that the
    /// removal is an event with an actor on it — the decision to stop being
    /// governed by a protocol is itself part of the record.
    function unbind(bytes32 tenantId, bytes32 actionClass, address protocol) external {
        _requireTenantAdmin(tenantId);

        address[] storage list = _bound[bindingKey(tenantId, actionClass)];
        for (uint256 i = 0; i < list.length; ++i) {
            if (list[i] != protocol) continue;
            list[i] = list[list.length - 1];
            list.pop();
            emit ProtocolUnbound(tenantId, actionClass, protocol, msg.sender);
            return;
        }
        revert NotBound(tenantId, actionClass, protocol);
    }

    /// Opt a tenant into refusing action classes nobody has bound. Tenant admins
    /// only. Off by default — see the contract header for why.
    function setDefaultDeny(bytes32 tenantId, bool enabled) external {
        _requireTenantAdmin(tenantId);
        defaultDeny[tenantId] = enabled;
        emit DefaultDenySet(tenantId, enabled, msg.sender);
    }

    // ── The runtime question ────────────────────────────────────────

    /// May this action proceed? PB-1: most restrictive wins.
    ///
    /// `view`, and every protocol it consults is `view`, so a check cannot
    /// change what the next check answers.
    function check(bytes32 tenantId, bytes32 actionClass, IGovernanceProtocol.ActionContext calldata ctx)
        external
        view
        returns (IGovernanceProtocol.Verdict v, bytes32 reasonCode, bytes32[] memory requiredSigners)
    {
        address[] storage list = _bound[bindingKey(tenantId, actionClass)];

        if (list.length == 0) {
            // PB-4 — an answer, and a distinguishable one.
            if (defaultDeny[tenantId]) {
                return (IGovernanceProtocol.Verdict.Deny, REASON_NO_BINDING, new bytes32[](0));
            }
            return (IGovernanceProtocol.Verdict.Allow, REASON_UNGOVERNED, new bytes32[](0));
        }

        v = IGovernanceProtocol.Verdict.Allow;
        reasonCode = REASON_ALLOWED;
        requiredSigners = new bytes32[](0);

        for (uint256 i = 0; i < list.length; ++i) {
            (IGovernanceProtocol.Verdict pv, bytes32 pr, bytes32[] memory ps) = _ask(list[i], tenantId, actionClass, ctx);
            if (_severity(pv) > _severity(v)) {
                v = pv;
                reasonCode = pr;
                requiredSigners = ps;
            } else if (pv == v && pv != IGovernanceProtocol.Verdict.Allow) {
                // Two protocols asking for the same class of action both have to
                // be satisfied, so the outstanding sets merge rather than the
                // first one winning.
                requiredSigners = _union(requiredSigners, ps);
            }
        }
    }

    /// Every bound protocol's verdict, separately.
    ///
    /// `check` answers; this explains. An operator who was refused by one of
    /// four protocols needs to know which one and why, and reconstructing that
    /// from a single combined reason code is guesswork.
    function explain(bytes32 tenantId, bytes32 actionClass, IGovernanceProtocol.ActionContext calldata ctx)
        external
        view
        returns (address[] memory protocols, IGovernanceProtocol.Verdict[] memory verdicts, bytes32[] memory reasons)
    {
        address[] storage list = _bound[bindingKey(tenantId, actionClass)];
        protocols = new address[](list.length);
        verdicts = new IGovernanceProtocol.Verdict[](list.length);
        reasons = new bytes32[](list.length);

        for (uint256 i = 0; i < list.length; ++i) {
            protocols[i] = list[i];
            (verdicts[i], reasons[i],) = _ask(list[i], tenantId, actionClass, ctx);
        }
    }

    /// Ask one protocol, and treat a failure as a refusal (PB-6).
    ///
    /// A protocol that reverts — out of gas on its own loop, a source contract
    /// that was self-destructed, a bug — must not be skipped. Skipping would mean
    /// the way to escape a rule is to break the contract that enforces it.
    function _ask(address protocol, bytes32 tenantId, bytes32 actionClass, IGovernanceProtocol.ActionContext calldata ctx)
        private
        view
        returns (IGovernanceProtocol.Verdict, bytes32, bytes32[] memory)
    {
        try IGovernanceProtocol(protocol).check(tenantId, actionClass, ctx) returns (
            IGovernanceProtocol.Verdict pv, bytes32 pr, bytes32[] memory ps
        ) {
            return (pv, pr, ps);
        } catch {
            return (IGovernanceProtocol.Verdict.Deny, REASON_PROTOCOL_FAILED, new bytes32[](0));
        }
    }

    /// The restrictiveness order. `Deny` is absolute; a vote is a heavier demand
    /// than an approval, so it outranks it when both are asked for.
    function _severity(IGovernanceProtocol.Verdict v) private pure returns (uint8) {
        if (v == IGovernanceProtocol.Verdict.Deny) return 3;
        if (v == IGovernanceProtocol.Verdict.RequireVote) return 2;
        if (v == IGovernanceProtocol.Verdict.RequireApproval) return 1;
        return 0;
    }

    function _union(bytes32[] memory a, bytes32[] memory b) private pure returns (bytes32[] memory) {
        bytes32[] memory merged = new bytes32[](a.length + b.length);
        uint256 n;
        for (uint256 i = 0; i < a.length; ++i) {
            merged[n++] = a[i];
        }
        for (uint256 i = 0; i < b.length; ++i) {
            bool seen;
            for (uint256 j = 0; j < n; ++j) {
                if (merged[j] == b[i]) {
                    seen = true;
                    break;
                }
            }
            if (!seen) merged[n++] = b[i];
        }
        bytes32[] memory out = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = merged[i];
        }
        return out;
    }

    function _requireTenantAdmin(bytes32 tenantId) private view {
        // `getNode` reverts for an unknown tenant, which is the correct
        // fail-closed behaviour: you cannot bind into a tenant that does not
        // exist. Matches `GovernanceProtocolFactory`'s GF-4, including its
        // documented membership-only (not M-of-N) semantics.
        ITenantHierarchy.TenantNode memory node = tenants.getNode(tenantId);
        for (uint256 i = 0; i < node.admins.length; ++i) {
            if (node.admins[i] == msg.sender) return;
        }
        revert NotTenantAdmin(tenantId, msg.sender);
    }

    // ── Views ───────────────────────────────────────────────────────

    function protocolCount(bytes32 tenantId, bytes32 actionClass) external view returns (uint256) {
        return _bound[bindingKey(tenantId, actionClass)].length;
    }

    function protocolsFor(bytes32 tenantId, bytes32 actionClass) external view returns (address[] memory) {
        return _bound[bindingKey(tenantId, actionClass)];
    }

    function isBound(bytes32 tenantId, bytes32 actionClass, address protocol) external view returns (bool) {
        address[] storage list = _bound[bindingKey(tenantId, actionClass)];
        for (uint256 i = 0; i < list.length; ++i) {
            if (list[i] == protocol) return true;
        }
        return false;
    }
}
