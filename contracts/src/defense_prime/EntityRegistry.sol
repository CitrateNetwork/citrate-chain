// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title EntityRegistry — Entity-type + schema registry for DPF-12.
/// @notice Per-(scope, type_id) entity-type registry with append-only
///         IDs + monotonic schema versions.
///
/// @dev Cites TLA+ spec:
///        - contracts/EntityRegistryLifecycle.tla (NEW in DPF-12)
///          — schema versioning state machine + append-only history
///
/// @dev Lifecycle:
///        - `registerType(scope, name, description, schema_cid)`
///          creates a new EntityType at version 1
///        - `bumpSchema(type_id, new_schema_cid)` increments version
///          + re-pushes to allTypeIds (history append-only)
///
/// Source: .agentile/sprints/active/2026-05-11-dpf-12-ontology-panel/SPRINT.md D-2
contract EntityRegistry {
    // ── Errors ─────────────────────────────────────────────────────────

    error ZeroGovernance();
    error NotGovernance(address caller);
    error NotRecorder(address caller);
    error AlreadyRegistered(bytes32 type_id);
    error NotRegistered(bytes32 type_id);
    error ZeroScope();
    error ZeroSchemaCid();
    error EmptyName();

    // ── Types ──────────────────────────────────────────────────────────

    /// @notice EntityType storage record.
    struct EntityType {
        bytes32 type_id;
        bytes32 scope;
        bytes32 schema_cid;
        bytes32 created_by;
        string  name;
        string  description;
        uint8   version;
        uint256 created_at_block;
        uint256 updated_at_block;
    }

    // ── Storage ────────────────────────────────────────────────────────

    address public governance;

    mapping(address => bool) public is_recorder;

    /// @notice type_id → EntityType (latest).
    mapping(bytes32 => EntityType) public typesByID;

    /// @notice scope → type_ids (append-only; one append per registerType).
    mapping(bytes32 => bytes32[]) public typesByScope;

    /// @notice All type_ids in registration + bumpSchema order
    ///         (history; same id appears once per version per
    ///         the EntityRegistryLifecycle.tla::VersionEqualsAppendCount
    ///         invariant).
    bytes32[] public allTypeIds;

    /// @notice Cheap O(1) existence check.
    mapping(bytes32 => bool) public exists;

    // ── Events ─────────────────────────────────────────────────────────

    event RecorderSet(address indexed recorder, bool authorized);

    event TypeRegistered(
        bytes32 indexed type_id,
        bytes32 indexed scope,
        bytes32 schema_cid,
        string name
    );

    event SchemaBumped(
        bytes32 indexed type_id,
        bytes32 schema_cid,
        uint8 new_version
    );

    // ── Constructor ────────────────────────────────────────────────────

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
    }

    // ── Governance ─────────────────────────────────────────────────────

    function setRecorder(address recorder, bool authorized) external {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        is_recorder[recorder] = authorized;
        emit RecorderSet(recorder, authorized);
    }

    // ── Mutators ───────────────────────────────────────────────────────

    /// @notice Register a new EntityType. type_id = keccak256(scope, name).
    function registerType(
        bytes32 scope,
        string calldata name,
        string calldata description,
        bytes32 schema_cid
    ) external returns (bytes32 type_id) {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (scope == bytes32(0)) revert ZeroScope();
        if (schema_cid == bytes32(0)) revert ZeroSchemaCid();
        if (bytes(name).length == 0) revert EmptyName();

        type_id = keccak256(abi.encode(scope, name));
        if (exists[type_id]) revert AlreadyRegistered(type_id);

        typesByID[type_id] = EntityType({
            type_id: type_id,
            scope: scope,
            schema_cid: schema_cid,
            created_by: bytes32(uint256(uint160(msg.sender))),
            name: name,
            description: description,
            version: 1,
            created_at_block: block.number,
            updated_at_block: block.number
        });
        exists[type_id] = true;
        typesByScope[scope].push(type_id);
        allTypeIds.push(type_id);

        emit TypeRegistered(type_id, scope, schema_cid, name);
    }

    /// @notice Increment the schema version of an existing type. The
    ///         old schema is unrecoverable on-chain (only the latest
    ///         CID is stored); audit history lives in `allTypeIds`
    ///         + emitted events.
    function bumpSchema(bytes32 type_id, bytes32 new_schema_cid) external {
        if (!is_recorder[msg.sender]) revert NotRecorder(msg.sender);
        if (new_schema_cid == bytes32(0)) revert ZeroSchemaCid();
        if (!exists[type_id]) revert NotRegistered(type_id);

        EntityType storage t = typesByID[type_id];
        t.version = t.version + 1;
        t.schema_cid = new_schema_cid;
        t.updated_at_block = block.number;
        allTypeIds.push(type_id);

        emit SchemaBumped(type_id, new_schema_cid, t.version);
    }

    // ── Views ──────────────────────────────────────────────────────────

    /// @notice Full record. Returns the latest schema and version.
    function getType(bytes32 type_id) external view returns (EntityType memory) {
        return typesByID[type_id];
    }

    /// @notice All type_ids registered under a scope (no duplicates;
    ///         each id pushed once per registerType).
    function types(bytes32 scope) external view returns (bytes32[] memory) {
        return typesByScope[scope];
    }

    /// @notice Latest schema CID for a type.
    function schema(bytes32 type_id) external view returns (bytes32) {
        return typesByID[type_id].schema_cid;
    }

    /// @notice All historical entries (registration + every bumpSchema
    ///         appends one). Length-of-allTypeIds equals total
    ///         registerType calls + total bumpSchema calls.
    function allTypes() external view returns (bytes32[] memory) {
        return allTypeIds;
    }

    /// @notice Total entries in `allTypeIds` (includes version bumps).
    function totalEntries() external view returns (uint256) {
        return allTypeIds.length;
    }

    /// @notice Cheap O(1) per-scope count.
    function countByScope(bytes32 scope) external view returns (uint256) {
        return typesByScope[scope].length;
    }
}
