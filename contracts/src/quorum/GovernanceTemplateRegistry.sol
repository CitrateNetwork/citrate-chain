// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Governable} from "../lib/Governable.sol";

/// @title GovernanceTemplateRegistry — the audit boundary
/// @notice citrate-quorum QRM-S6. Planset `03_GOVERNANCE_CONTRACTS.md` §1.
///
/// **Only bytecode that has passed audit can ever govern agents.** That is the
/// entire purpose of this contract, and it is the answer to planset risk R3:
/// *"LLM-authored governance logic is indefensible to a board."* Quorum's
/// authoring pipeline turns a plain-English policy into constructor PARAMETERS
/// for an audited template — never into new Solidity. A board can be shown the
/// audit of the template and the parameters of the deployment, and those two
/// things together are the whole of what governs their agents.
///
/// The registry is what makes that claim checkable rather than procedural:
/// `GovernanceProtocolFactory` refuses to deploy anything whose creation code
/// does not hash to a registered template's `initCodeHash` (GF-2).
///
/// ## What is immutable, and why it has to be
///
/// **TR-1: a registered row is immutable except `active`.** If `initCodeHash`
/// could be edited, "this protocol was deployed from audited bytecode" would
/// mean "…from whatever bytecode the registry pointed at when someone last
/// looked", and every deployment's provenance would be retroactively rewritable
/// by governance. A template that turns out to be wrong is DEPRECATED, not
/// mutated — and the deployments made from it keep running, because silently
/// changing what they were built from would be worse than letting an operator
/// see "your protocol uses a deprecated template" and decide.
///
/// Registering a *fixed* version of a template means registering a NEW row with
/// a new version, which produces a new id and a new audit CID. The lineage is
/// visible; nothing is edited underneath anyone.
///
/// ## Deprecation is not deletion
///
/// `deprecate` flips `active` to false. The row stays readable forever, because
/// a protocol deployed two years ago must still be explainable — an auditor
/// asking "what governed this decision" needs the template row even if nobody
/// may deploy from it again.
///
/// ## Governance
///
/// `register` and `deprecate` are governance-gated through the two-step
/// [`Governable`] mixin (RM-B1/WP-D1.1): a proposed successor must accept before
/// it takes effect, so a mistyped key cannot lock the audit boundary forever.
///
/// Note what governance can and cannot do here. It can add a template, and it
/// can stop new deploys from one. It **cannot** alter what an existing template
/// is, and it cannot reach into deployed protocols. The blast radius of a
/// compromised governance key is "new bad templates may be registered" — which
/// the factory's `initCodeHash` check makes visible in every deployment record —
/// not "every existing protocol silently changed".
contract GovernanceTemplateRegistry is Governable {
    /// One audited, deployable template.
    struct Template {
        /// `keccak256(abi.encode(name, version))`. Derived, not supplied, so two
        /// rows can never disagree about their own identity.
        bytes32 id;
        /// Human name, e.g. "ThresholdApproval". Free text for display only —
        /// nothing resolves by name.
        string name;
        uint32 version;
        /// `keccak256` of the creation code. THE pin: the factory recomputes
        /// this from the code it is handed and refuses a mismatch (GF-2).
        bytes32 initCodeHash;
        /// Hash of the JSON-schema the constructor params must satisfy. The
        /// schema itself lives off chain; the hash makes "these params were
        /// checked against that schema" verifiable.
        bytes32 paramSchemaHash;
        /// IPFS CID of the audit report. Required and non-empty: a template
        /// with no audit is exactly what this registry exists to exclude.
        string auditCID;
        /// False once deprecated. The only mutable field (TR-1).
        bool active;
        /// Block the row was registered in. Set by the chain, not the caller,
        /// so "when did this become deployable" cannot be backdated.
        uint64 registeredAt;
    }

    /// id → row. Never deleted.
    mapping(bytes32 => Template) private _templates;
    /// Registration order, so an indexer can enumerate without replaying logs.
    bytes32[] private _ids;

    error TemplateExists(bytes32 id);
    error UnknownTemplate(bytes32 id);
    error AlreadyDeprecated(bytes32 id);
    error EmptyName();
    error ZeroInitCodeHash();
    error ZeroParamSchemaHash();
    error EmptyAuditCID();

    event TemplateRegistered(
        bytes32 indexed id,
        string name,
        uint32 version,
        bytes32 indexed initCodeHash,
        bytes32 paramSchemaHash,
        string auditCID
    );
    event TemplateDeprecated(bytes32 indexed id, address indexed by);

    constructor(address initialGovernance) Governable(initialGovernance) {}

    /// The id a `(name, version)` pair resolves to.
    ///
    /// `public pure` so the authoring pipeline and any verifier compute it the
    /// same way this contract does, rather than reimplementing the encoding.
    /// `abi.encode` (not `encodePacked`): with packed encoding
    /// `("AB", 1)` and `("A", 0x4231…)` could collide, and a template id
    /// collision is a way to make one audited template answer for another.
    function templateId(string memory name, uint32 version) public pure returns (bytes32) {
        return keccak256(abi.encode(name, version));
    }

    /// Register an audited template. Governance only.
    ///
    /// Every argument is required. There is no "register now, add the audit
    /// later" path, because a row that exists without an audit CID is
    /// indistinguishable — to the factory — from one that has been audited.
    function register(
        string calldata name,
        uint32 version,
        bytes32 initCodeHash_,
        bytes32 paramSchemaHash_,
        string calldata auditCID
    ) external onlyGovernance returns (bytes32 id) {
        if (bytes(name).length == 0) revert EmptyName();
        if (initCodeHash_ == bytes32(0)) revert ZeroInitCodeHash();
        if (paramSchemaHash_ == bytes32(0)) revert ZeroParamSchemaHash();
        if (bytes(auditCID).length == 0) revert EmptyAuditCID();

        id = templateId(name, version);
        // `registeredAt` is the existence flag: a zero row has never been
        // written, and the chain sets it, so an existence check cannot be
        // fooled by a caller supplying zeroes.
        if (_templates[id].registeredAt != 0) revert TemplateExists(id);

        _templates[id] = Template({
            id: id,
            name: name,
            version: version,
            initCodeHash: initCodeHash_,
            paramSchemaHash: paramSchemaHash_,
            auditCID: auditCID,
            active: true,
            registeredAt: uint64(block.number)
        });
        _ids.push(id);

        emit TemplateRegistered(id, name, version, initCodeHash_, paramSchemaHash_, auditCID);
    }

    /// Stop new deployments from a template. Governance only. Idempotence is
    /// deliberately NOT offered: deprecating twice is a sign the caller thinks
    /// it is doing something it already did, and silently accepting that hides
    /// a mistaken assumption about which template they are looking at.
    function deprecate(bytes32 id) external onlyGovernance {
        Template storage t = _templates[id];
        if (t.registeredAt == 0) revert UnknownTemplate(id);
        if (!t.active) revert AlreadyDeprecated(id);
        t.active = false;
        emit TemplateDeprecated(id, msg.sender);
    }

    // ── Views ───────────────────────────────────────────────────────

    /// The full row. Reverts for an unknown id rather than returning a zero
    /// struct, so a caller cannot mistake "no such template" for "a template
    /// with an empty audit".
    function get(bytes32 id) external view returns (Template memory) {
        Template storage t = _templates[id];
        if (t.registeredAt == 0) revert UnknownTemplate(id);
        return t;
    }

    /// Is this template deployable RIGHT NOW? The single question the factory
    /// asks (GF-2), kept as its own view so the factory cannot accidentally
    /// accept an inactive row by reading the wrong field.
    function isDeployable(bytes32 id, bytes32 initCodeHash_) external view returns (bool) {
        Template storage t = _templates[id];
        return t.registeredAt != 0 && t.active && t.initCodeHash == initCodeHash_;
    }

    function exists(bytes32 id) external view returns (bool) {
        return _templates[id].registeredAt != 0;
    }

    function count() external view returns (uint256) {
        return _ids.length;
    }

    function idAt(uint256 index) external view returns (bytes32) {
        return _ids[index];
    }
}
