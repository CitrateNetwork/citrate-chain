// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {GovernanceTemplateRegistry} from "./GovernanceTemplateRegistry.sol";

/// Minimal view of `TenantHierarchy` — the two facts GF-4 needs.
///
/// Declared here rather than importing the contract so the factory links against
/// an interface it can be pointed at, and so a customer running their own tenant
/// tree does not have to deploy ours.
interface ITenantHierarchy {
    struct TenantNode {
        bytes32 parent;
        bytes32 self;
        string display_name;
        uint8 level;
        bytes32 hkdf_salt;
        address[] admins;
        uint8 admin_threshold;
        uint8 classification_max;
        bool exists;
    }

    function getNode(bytes32 tenant_id) external view returns (TenantNode memory);
}

/// @title GovernanceProtocolFactory — deploys template-bounded protocols
/// @notice citrate-quorum QRM-S6.2. Planset `03_GOVERNANCE_CONTRACTS.md` §2.
///
/// The registry says which bytecode is audited; this contract is what makes that
/// binding. A protocol that governs agents can only come from here, and this
/// refuses anything whose creation code does not hash to a registered,
/// still-active template.
///
/// ## The five properties, and what each one is defending against
///
/// **GF-1 Deterministic.** CREATE2, so the address is computable off chain
/// before anyone signs. The SignatureCeremony displays the exact address the
/// human is authorising — not "a protocol will be created somewhere".
/// [`predict`] is that computation, exposed so the app and a verifier agree with
/// the factory by construction instead of by reimplementation.
///
/// **GF-2 Template-bounded.** `keccak256(creationCode)` must equal the
/// template's pinned `initCodeHash`, and the template must still be `active`.
/// This is the whole audit story: without it, "deployed from audited bytecode"
/// is a claim about paperwork rather than about the bytes that are running.
///
/// **GF-3 Spec-bound.** A protocol cannot be deployed without a `specHash` and a
/// `specCID`. The plain-English document and the bytecode are inseparable on
/// chain, so the app can always put "what we said this does" next to "what it
/// does". A deployment with an empty spec would be a protocol nobody can explain.
///
/// **GF-4 Tenant-gated.** The caller must be an admin of the tenant, and the
/// protocol's classification ceiling must not exceed the tenant's
/// `classification_max`. Without this, anyone could deploy a protocol that
/// governs someone else's agents, or one that operates above what the tenant is
/// cleared for.
///
/// **GF-5 Single-owner-per-salt.** CREATE2 gives this for free — a second deploy
/// at the same address reverts — and the deployment record makes it legible
/// rather than a raw EVM failure. Version bumps change the salt; the registry
/// keeps the lineage.
///
/// ## Two things this deliberately does NOT do
///
/// **It does not validate params against the schema.** The template pins a
/// `paramSchemaHash`, and a JSON schema cannot be evaluated on chain at sane
/// cost. The factory records which schema the params were *supposed* to satisfy;
/// checking them against it is the authoring pipeline's job (QRM-S7), off chain,
/// before the ceremony. Pretending otherwise would put a validation claim on
/// chain that nothing on chain performs.
///
/// **It does not enforce the tenant's M-of-N threshold.** `TenantHierarchy`
/// records `admin_threshold` as data and its own `createNode` checks membership
/// only — any single admin satisfies it. This factory matches that behaviour
/// deliberately rather than inventing a stricter rule the tree itself does not
/// keep, and the deployment record names the single admin that acted so an
/// M-of-N envelope can be reconciled off chain. When `MultiSigEnvelope` becomes
/// the caller, that envelope IS the threshold and this check still holds.
contract GovernanceProtocolFactory {
    /// What was deployed, and everything needed to explain it later.
    struct Deployment {
        bytes32 tenantId;
        bytes32 templateId;
        /// The spec the protocol claims to implement (GF-3).
        bytes32 specHash;
        string specCID;
        /// The schema the params were supposed to satisfy — copied from the
        /// template at deploy time so a later template row cannot change what
        /// this deployment was checked against.
        bytes32 paramSchemaHash;
        uint8 classificationCeiling;
        /// The admin that actually sent the transaction.
        address deployer;
        uint64 blockNumber;
    }

    GovernanceTemplateRegistry public immutable registry;
    ITenantHierarchy public immutable tenants;

    /// protocol address → what it is. Never deleted: a protocol that is no
    /// longer bound still has to be explainable.
    mapping(address => Deployment) private _deployments;
    /// tenant → protocols, in deploy order, so the app can enumerate without
    /// replaying logs.
    mapping(bytes32 => address[]) private _byTenant;

    error UnknownOrInactiveTemplate(bytes32 templateId);
    error CreationCodeMismatch(bytes32 templateId, bytes32 supplied, bytes32 expected);
    error EmptySpecHash();
    error EmptySpecCID();
    error NotTenantAdmin(bytes32 tenantId, address caller);
    error CeilingExceedsTenant(uint8 requested, uint8 tenantMax);
    error AlreadyDeployedAtSalt(address protocol);
    error DeploymentFailed();

    event ProtocolDeployed(
        bytes32 indexed tenantId,
        address indexed protocol,
        bytes32 indexed templateId,
        bytes32 specHash,
        string specCID,
        address deployer,
        bytes32 correlationId
    );

    constructor(GovernanceTemplateRegistry registry_, ITenantHierarchy tenants_) {
        registry = registry_;
        tenants = tenants_;
    }

    /// The address a deployment WILL have. GF-1.
    ///
    /// Pure given its inputs, so the ceremony can show the human the exact
    /// address before they approve, and anyone can recompute it afterwards. The
    /// init code is `creationCode ‖ params` — the standard CREATE2 layout, and
    /// the reason params change the address: two protocols from one template
    /// with different parameters are different protocols and must not collide.
    function predict(bytes calldata creationCode, bytes calldata params, bytes32 salt)
        public
        view
        returns (address)
    {
        bytes32 initCodeHash = keccak256(abi.encodePacked(creationCode, params));
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))
            )
        );
    }

    /// Deploy a governance protocol for a tenant.
    ///
    /// `creationCode` is supplied by the caller and checked against the
    /// template's pinned hash (GF-2) — the factory does not store bytecode, so a
    /// template can be audited and registered without this contract ever being
    /// redeployed.
    function deployProtocol(
        bytes32 tenantId,
        bytes32 templateId,
        bytes calldata creationCode,
        bytes calldata params,
        bytes32 specHash,
        string calldata specCID,
        uint8 classificationCeiling,
        bytes32 salt,
        bytes32 correlationId
    ) external returns (address protocol) {
        // GF-3 first: cheapest checks before any external call.
        if (specHash == bytes32(0)) revert EmptySpecHash();
        if (bytes(specCID).length == 0) revert EmptySpecCID();

        // GF-2 — the audit boundary.
        bytes32 supplied = keccak256(creationCode);
        if (!registry.isDeployable(templateId, supplied)) {
            // Distinguish the two ways this fails, because they need different
            // fixes: an unknown/deprecated template is a governance question, a
            // code mismatch means someone is holding different bytes than the
            // ones that were audited.
            if (!registry.exists(templateId) || !registry.get(templateId).active) {
                revert UnknownOrInactiveTemplate(templateId);
            }
            revert CreationCodeMismatch(templateId, supplied, registry.get(templateId).initCodeHash);
        }

        // GF-4 — tenant gating. `getNode` reverts for an unknown tenant, which
        // is the correct fail-closed behaviour: you cannot deploy into a tenant
        // that does not exist.
        ITenantHierarchy.TenantNode memory node = tenants.getNode(tenantId);
        if (!_isAdmin(node, msg.sender)) revert NotTenantAdmin(tenantId, msg.sender);
        if (classificationCeiling > node.classification_max) {
            revert CeilingExceedsTenant(classificationCeiling, node.classification_max);
        }

        // GF-5 — a salt is used once. CREATE2 would revert anyway; checking the
        // record first turns a bare EVM failure into a sentence.
        address predicted = predict(creationCode, params, salt);
        if (_deployments[predicted].blockNumber != 0) revert AlreadyDeployedAtSalt(predicted);

        bytes memory initCode = abi.encodePacked(creationCode, params);
        assembly {
            protocol := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        if (protocol == address(0)) revert DeploymentFailed();

        _deployments[protocol] = Deployment({
            tenantId: tenantId,
            templateId: templateId,
            specHash: specHash,
            specCID: specCID,
            // Copied, not referenced: a later template row must not be able to
            // change what THIS deployment was supposed to satisfy.
            paramSchemaHash: registry.get(templateId).paramSchemaHash,
            classificationCeiling: classificationCeiling,
            deployer: msg.sender,
            blockNumber: uint64(block.number)
        });
        _byTenant[tenantId].push(protocol);

        emit ProtocolDeployed(tenantId, protocol, templateId, specHash, specCID, msg.sender, correlationId);
    }

    /// Membership, matching `TenantHierarchy._isAdmin` exactly — see the header
    /// for why the threshold is not enforced here.
    function _isAdmin(ITenantHierarchy.TenantNode memory node, address who) private pure returns (bool) {
        for (uint256 i = 0; i < node.admins.length; ++i) {
            if (node.admins[i] == who) return true;
        }
        return false;
    }

    // ── Views ───────────────────────────────────────────────────────

    /// What a protocol is. Reverts for an address this factory never deployed,
    /// so "not ours" cannot be mistaken for "ours, with empty fields".
    function deploymentOf(address protocol) external view returns (Deployment memory) {
        Deployment storage d = _deployments[protocol];
        if (d.blockNumber == 0) revert DeploymentFailed();
        return d;
    }

    function wasDeployedHere(address protocol) external view returns (bool) {
        return _deployments[protocol].blockNumber != 0;
    }

    function protocolCount(bytes32 tenantId) external view returns (uint256) {
        return _byTenant[tenantId].length;
    }

    function protocolAt(bytes32 tenantId, uint256 index) external view returns (address) {
        return _byTenant[tenantId][index];
    }
}
