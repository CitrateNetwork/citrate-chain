// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title TenantHierarchy — root of the DPF-02 RBAC access model
/// @notice 4-level tenant tree with HKDF-derived sub-secrets per node.
///         Root key is held by the tenant org's HSM; sub-secrets are
///         derivable client-side, so access to a scope is *cryptographic*,
///         not just policy-based.
///
/// @dev Formal spec: `.agentile/formal/specs/contracts/TenantHierarchyTree.tla`
/// @dev Cited invariants enforced or supported by this implementation:
///   - `ParentExists` — every non-root node references a parent that
///     itself exists. Enforced in `createNode` revert path.
///   - `ParentImpliesChildListed` — every node appears in its parent's
///     `children[]` array. Enforced by `createNode` push.
///   - `ChildImpliesParent` — every entry in any `children[]` array
///     points to a node whose `parent` matches the array owner.
///     Enforced by `createNode` write order.
///   - `LevelsRespected` — `level == parent.level + 1` for non-root.
///     Enforced in `createNode` require.
///   - `ClearanceMaxMonotonicDownTree` — `classification_max <=
///     parent.classification_max` for non-root. Enforced in
///     `createNode` and `setClassificationMax` reverts.
///   - `RootSetWellFormed` — root is set exactly once at construction.
///     Enforced by `_initialized` guard.
///   - `LevelBounded` — `level in 0..3` (enterprise / BU / site / team).
///     Enforced in `createNode` require.
///
/// @dev Per `03_RBAC_CONTRACTS.md` § 1. DPF-02 deliverable.
contract TenantHierarchy {
    // ── Types ───────────────────────────────────────────────────────

    /// @notice One node in the tenant tree.
    /// @dev `classification_max` uses the same enum encoding as
    ///      ClassificationRegistry: 0=Public, 1=Proprietary, 2=CUI, 3=ITAR.
    struct TenantNode {
        bytes32 parent;
        bytes32 self;
        string  display_name;
        uint8   level;
        bytes32 hkdf_salt;
        address[] admins;
        uint8   admin_threshold;
        uint8   classification_max;
        bool    exists;
    }

    // ── Constants ───────────────────────────────────────────────────

    uint8 internal constant MAX_LEVEL = 3;
    uint8 internal constant MAX_CLASSIFICATION = 3; // ITAR

    // ── State ───────────────────────────────────────────────────────

    mapping(bytes32 tenant_id => TenantNode) private _nodes;
    mapping(bytes32 tenant_id => bytes32[]) private _children;
    bytes32 public root;
    bool private _initialized;

    /// @notice The deployer, authorized to perform the one-shot
    ///         `initRoot`. FWA-C3-02: without this, the first caller
    ///         (a mempool front-runner) could seize the RBAC root and
    ///         set themselves as the root admin set.
    address public immutable deployer;

    // ── Events ──────────────────────────────────────────────────────

    /// @notice Emitted when a new tenant node is created.
    /// @param tenant_id The newly-created tenant's id.
    /// @param parent The parent node's id (zero for root).
    /// @param level Tree depth: 0=enterprise, 1=BU, 2=site, 3=team.
    event NodeCreated(bytes32 indexed tenant_id, bytes32 indexed parent, uint8 level);

    /// @notice Emitted when a node's mutable parameter is updated.
    /// @param tenant_id The node id.
    /// @param param Hash of the parameter name (keccak256 of the field name).
    /// @param value Encoded new value (caller decodes per `param`).
    event NodeUpdated(bytes32 indexed tenant_id, bytes32 indexed param, bytes value);

    /// @notice Emitted when a node is logically removed.
    /// @dev Removal is allowed only when the node has no children.
    event NodeRemoved(bytes32 indexed tenant_id, address indexed admin);

    // ── Errors ──────────────────────────────────────────────────────

    error AlreadyInitialized();
    error NotInitialized();
    error NodeAlreadyExists(bytes32 tenant_id);
    error NodeDoesNotExist(bytes32 tenant_id);
    error InvalidLevel(uint8 level);
    error LevelMismatch(uint8 expected, uint8 got);
    error InvalidClassification(uint8 max);
    error ClassificationExceedsParent(uint8 child_max, uint8 parent_max);
    /// @notice `setClassificationMax` may only lower a node's ceiling.
    error ClassificationNotMonotoneDown(uint8 requested, uint8 current);
    /// @notice A child already holds a max above the requested value.
    error ChildExceedsClassification(bytes32 child, uint8 child_max, uint8 requested);
    error NotAdmin(address caller);
    error InvalidThreshold(uint8 threshold, uint256 admin_count);
    error EmptyAdmins();
    error HasChildren(bytes32 tenant_id);
    /// @notice `initRoot` may be called only by the deployer. FWA-C3-02.
    error NotDeployer(address caller);

    // ── Constructor / init ──────────────────────────────────────────

    /// @notice Pins the deployer as the sole address allowed to run the
    ///         one-shot `initRoot`. Closes the front-run window where any
    ///         EOA could seize the RBAC root (FWA-C3-02).
    constructor() {
        deployer = msg.sender;
    }

    /// @notice Initializes the root tenant node. Callable exactly once.
    /// @param self The root tenant id (typically `keccak256("DefensePrime")`).
    /// @param display Human-readable display name (e.g., "DefensePrime").
    /// @param hkdf_salt 32-byte salt for HKDF sub-secret derivation.
    /// @param admins Initial multi-sig admins for the root scope.
    /// @param threshold M-of-N admin threshold for root admin actions.
    /// @param classification_max Maximum clearance below the root scope.
    function initRoot(
        bytes32 self,
        string calldata display,
        bytes32 hkdf_salt,
        address[] calldata admins,
        uint8 threshold,
        uint8 classification_max
    ) external {
        // FWA-C3-02: only the deployer may seed the root, and only once.
        if (msg.sender != deployer) revert NotDeployer(msg.sender);
        if (_initialized) revert AlreadyInitialized();
        if (admins.length == 0) revert EmptyAdmins();
        if (threshold == 0 || threshold > admins.length) {
            revert InvalidThreshold(threshold, admins.length);
        }
        if (classification_max > MAX_CLASSIFICATION) {
            revert InvalidClassification(classification_max);
        }

        _nodes[self] = TenantNode({
            parent: bytes32(0),
            self: self,
            display_name: display,
            level: 0,
            hkdf_salt: hkdf_salt,
            admins: admins,
            admin_threshold: threshold,
            classification_max: classification_max,
            exists: true
        });
        root = self;
        _initialized = true;

        emit NodeCreated(self, bytes32(0), 0);
    }

    // ── Mutators ────────────────────────────────────────────────────

    /// @notice Create a child node under an existing parent.
    /// @dev Caller must be one of `parent.admins` (single-sig is
    ///      sufficient at the contract level; the M-of-N policy is
    ///      enforced by the off-chain orchestrator that batches the
    ///      admin signatures into a MultiSigEnvelope before calling
    ///      this method via that envelope's executor).
    /// @param parent The existing parent's id.
    /// @param self The new tenant's id (caller chooses; must be unique).
    /// @param display Human-readable display name.
    /// @param level Tree depth: 1=BU, 2=site, 3=team.
    /// @param hkdf_salt 32-byte salt for sub-secret derivation.
    /// @param admins Multi-sig admins for this scope.
    /// @param threshold M-of-N for this scope's admin actions.
    /// @param classification_max Max clearance below this scope.
    function createNode(
        bytes32 parent,
        bytes32 self,
        string calldata display,
        uint8 level,
        bytes32 hkdf_salt,
        address[] calldata admins,
        uint8 threshold,
        uint8 classification_max
    ) external {
        if (!_initialized) revert NotInitialized();
        TenantNode storage parentNode = _nodes[parent];
        if (!parentNode.exists) revert NodeDoesNotExist(parent);
        if (_nodes[self].exists) revert NodeAlreadyExists(self);
        if (level == 0 || level > MAX_LEVEL) revert InvalidLevel(level);
        if (level != parentNode.level + 1) {
            revert LevelMismatch(parentNode.level + 1, level);
        }
        if (classification_max > MAX_CLASSIFICATION) {
            revert InvalidClassification(classification_max);
        }
        if (classification_max > parentNode.classification_max) {
            revert ClassificationExceedsParent(
                classification_max, parentNode.classification_max
            );
        }
        if (!_isAdmin(parentNode, msg.sender)) revert NotAdmin(msg.sender);
        if (admins.length == 0) revert EmptyAdmins();
        if (threshold == 0 || threshold > admins.length) {
            revert InvalidThreshold(threshold, admins.length);
        }

        _nodes[self] = TenantNode({
            parent: parent,
            self: self,
            display_name: display,
            level: level,
            hkdf_salt: hkdf_salt,
            admins: admins,
            admin_threshold: threshold,
            classification_max: classification_max,
            exists: true
        });
        _children[parent].push(self);

        emit NodeCreated(self, parent, level);
    }

    /// @notice Lower a node's classification ceiling. Cannot raise
    ///         beyond the parent's `classification_max`.
    /// @param tenant_id The node to update.
    /// @param max New classification maximum.
    function setClassificationMax(bytes32 tenant_id, uint8 max) external {
        TenantNode storage node = _nodes[tenant_id];
        if (!node.exists) revert NodeDoesNotExist(tenant_id);
        if (max > MAX_CLASSIFICATION) revert InvalidClassification(max);
        if (tenant_id != root) {
            TenantNode storage parentNode = _nodes[node.parent];
            if (max > parentNode.classification_max) {
                revert ClassificationExceedsParent(
                    max, parentNode.classification_max
                );
            }
        }
        // This function is a *ceiling reduction*: `ClearanceMaxMonotonicDownTree`
        // must hold after the call, not only at creation. Raising the ceiling —
        // even up to the parent's max — would let a node's own admins clear their
        // scope above what the parent deliberately capped, without the parent's
        // consent. Only allow lowering.
        if (max > node.classification_max) {
            revert ClassificationNotMonotoneDown(max, node.classification_max);
        }
        // A reduction that drops below an already-created child's ceiling would
        // silently leave the child cleared above this node — the mirror hole.
        bytes32[] storage kids = _children[tenant_id];
        uint256 kidCount = kids.length;
        for (uint256 i; i < kidCount; ++i) {
            uint8 childMax = _nodes[kids[i]].classification_max;
            if (childMax > max) revert ChildExceedsClassification(kids[i], childMax, max);
        }
        if (!_isAdmin(node, msg.sender)) revert NotAdmin(msg.sender);

        node.classification_max = max;
        emit NodeUpdated(tenant_id, keccak256("classification_max"), abi.encode(max));
    }

    /// @notice Logically remove a node. Allowed only when childless.
    /// @param tenant_id The node to remove.
    function removeNode(bytes32 tenant_id) external {
        TenantNode storage node = _nodes[tenant_id];
        if (!node.exists) revert NodeDoesNotExist(tenant_id);
        if (tenant_id == root) revert NodeAlreadyExists(tenant_id); // root cannot be removed; reuse error
        if (_children[tenant_id].length != 0) revert HasChildren(tenant_id);
        if (!_isAdmin(node, msg.sender)) revert NotAdmin(msg.sender);

        // Remove from parent's children list.
        bytes32 parent = node.parent;
        bytes32[] storage siblings = _children[parent];
        uint256 n = siblings.length;
        for (uint256 i; i < n; ++i) {
            if (siblings[i] == tenant_id) {
                siblings[i] = siblings[n - 1];
                siblings.pop();
                break;
            }
        }

        delete _nodes[tenant_id];
        emit NodeRemoved(tenant_id, msg.sender);
    }

    // ── Read views ──────────────────────────────────────────────────

    /// @notice Returns the chain from the root down to the given node.
    /// @dev Returned in root-first order. Cost is O(depth) ≤ O(4).
    function getPath(bytes32 tenant_id) external view returns (bytes32[] memory path) {
        if (!_nodes[tenant_id].exists) revert NodeDoesNotExist(tenant_id);
        // Walk up to root counting depth.
        bytes32 cursor = tenant_id;
        uint256 depth = 1;
        while (cursor != root) {
            cursor = _nodes[cursor].parent;
            depth++;
        }
        path = new bytes32[](depth);
        cursor = tenant_id;
        // Fill backwards (deepest first), then it's already root-to-leaf.
        for (uint256 i = depth; i > 0; --i) {
            path[i - 1] = cursor;
            if (cursor != root) {
                cursor = _nodes[cursor].parent;
            }
        }
        return path;
    }

    /// @notice Returns the immediate children of a node.
    function getChildren(bytes32 tenant_id) external view returns (bytes32[] memory) {
        if (!_nodes[tenant_id].exists) revert NodeDoesNotExist(tenant_id);
        return _children[tenant_id];
    }

    /// @notice Returns the full TenantNode struct for `tenant_id`.
    function getNode(bytes32 tenant_id) external view returns (TenantNode memory) {
        if (!_nodes[tenant_id].exists) revert NodeDoesNotExist(tenant_id);
        return _nodes[tenant_id];
    }

    /// @notice Returns whether a tenant_id is registered.
    function exists(bytes32 tenant_id) external view returns (bool) {
        return _nodes[tenant_id].exists;
    }

    /// @notice View-only HKDF chain derivation. The contract performs
    ///         no key-material expansion itself — this method records
    ///         the path's hkdf_salt sequence for the caller to feed
    ///         into an off-chain HKDF computation. Used via `eth_call`
    ///         only.
    /// @param leaf_tenant The deepest tenant in the chain.
    /// @return salts The hkdf_salt of every node from root → leaf.
    function deriveSubSecretSalts(bytes32 leaf_tenant)
        external view returns (bytes32[] memory salts)
    {
        if (!_nodes[leaf_tenant].exists) revert NodeDoesNotExist(leaf_tenant);
        bytes32 cursor = leaf_tenant;
        uint256 depth = 1;
        while (cursor != root) {
            cursor = _nodes[cursor].parent;
            depth++;
        }
        salts = new bytes32[](depth);
        cursor = leaf_tenant;
        for (uint256 i = depth; i > 0; --i) {
            salts[i - 1] = _nodes[cursor].hkdf_salt;
            if (cursor != root) {
                cursor = _nodes[cursor].parent;
            }
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    function _isAdmin(TenantNode storage node, address caller)
        internal view returns (bool)
    {
        uint256 n = node.admins.length;
        for (uint256 i; i < n; ++i) {
            if (node.admins[i] == caller) return true;
        }
        return false;
    }
}
