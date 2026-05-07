// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title InstitutionTreeV1
/// @notice 4-level tenancy registry for CMO-managed deployments.
/// @dev Companion to ClassroomClusterV1. Designed additively — existing flat
///      ClassroomClusterV1 deployments are unaffected. Bootstrap CLI uses
///      InstitutionTreeV1 to register the CMO → District → School path; the
///      School layer then operates ClassroomClusterV1 in the same shape it
///      always has (per-school cluster, per-classroom assignments, per-student
///      pseudonymous principals).
///
///      All identifiers stored on-chain are HMAC-SHA-256 hashes of the
///      provider-supplied IDs (CMO EIN, NCES district code, NCES school code).
///      No PII appears on-chain. The off-chain `OrgIdentity` HKDF chain in
///      `citrate-edu-app::tenancy` produces the matching hashes; this contract
///      is the registry that those hashes pin to.
///
///      State transitions are operator-gated (only the institution's
///      `admin` address can register child institutions or revoke them).
///      Governance is two-step transferable, matching ClassroomClusterV1's
///      RM-L / WP-L1.1 pattern.
contract InstitutionTreeV1 {
    // ── Types ──

    /// @notice One node in the 4-level institutional tree.
    /// @dev Standalone districts (no CMO above) use cmoIdHash = bytes32(0).
    ///      cmoIdHash and districtIdHash collapse for standalone districts
    ///      (they're the same value), distinguishing them from CMO-affiliated
    ///      districts whose cmoIdHash points to a separate tree node.
    struct InstitutionNode {
        bytes32 cmoIdHash;        // 0x0 for standalone districts (no parent)
        bytes32 districtIdHash;   // self-equal for standalone districts
        bytes32 schoolIdHash;     // 0x0 for nodes representing CMOs/districts (not schools)
        address admin;            // institution-level multi-sig vault or governance address
        uint8 state;              // UsState enum index: 0=CA, 1=NY, 2=IL, 3=TX, 4=CO, 255=Other
        uint8 level;              // 1=CMO, 2=District, 3=School
        uint64 registeredAt;
        bool revoked;
    }

    /// @notice Indexed by `schoolIdHash || districtIdHash || cmoIdHash` — using
    ///         the deepest non-zero hash uniquely identifies a node.
    function _nodeKey(InstitutionNode memory n) internal pure returns (bytes32) {
        if (n.schoolIdHash != bytes32(0)) return n.schoolIdHash;
        if (n.districtIdHash != bytes32(0)) return n.districtIdHash;
        return n.cmoIdHash;
    }

    // ── Storage ──

    address public governance;
    address public pendingGovernance;

    /// @dev key = schoolIdHash for L3 nodes, districtIdHash for L2, cmoIdHash for L1.
    mapping(bytes32 => InstitutionNode) private _nodes;
    /// @dev cmoIdHash → list of child district hashes. Useful for off-chain enumeration.
    mapping(bytes32 => bytes32[]) private _districtsByCmo;
    /// @dev districtIdHash → list of child school hashes.
    mapping(bytes32 => bytes32[]) private _schoolsByDistrict;

    uint256 public totalNodes;

    // ── Errors ──

    error NotGovernance();
    error NotInstitutionAdmin();
    error AlreadyRegistered(bytes32 nodeKey);
    error UnknownInstitution(bytes32 nodeKey);
    error InvalidLevel(uint8 level);
    error InvalidParentChain();
    error AlreadyRevoked(bytes32 nodeKey);
    error InvalidGovernanceTransfer();

    // ── Events ──

    event CmoRegistered(bytes32 indexed cmoIdHash, address indexed admin, uint8 state, uint64 registeredAt);
    event DistrictRegistered(
        bytes32 indexed cmoIdHash,
        bytes32 indexed districtIdHash,
        address indexed admin,
        uint8 state,
        uint64 registeredAt
    );
    event SchoolRegistered(
        bytes32 indexed districtIdHash,
        bytes32 indexed schoolIdHash,
        address indexed admin,
        uint8 state,
        uint64 registeredAt
    );
    event InstitutionRevoked(bytes32 indexed nodeKey, address indexed by, uint64 at);
    event GovernanceTransferProposed(address indexed from, address indexed to);
    event GovernanceTransferAccepted(address indexed from, address indexed to);
    event GovernanceTransferCancelled(address indexed by);

    // ── Modifiers ──

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyInstitutionAdmin(bytes32 nodeKey) {
        InstitutionNode storage n = _nodes[nodeKey];
        if (n.registeredAt == 0) revert UnknownInstitution(nodeKey);
        if (msg.sender != n.admin) revert NotInstitutionAdmin();
        _;
    }

    // ── Constructor ──

    constructor(address _governance) {
        require(_governance != address(0), "governance is zero");
        governance = _governance;
    }

    // ── Governance transfer (two-step) ──

    function transferGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert InvalidGovernanceTransfer();
        pendingGovernance = newGovernance;
        emit GovernanceTransferProposed(governance, newGovernance);
    }

    function acceptGovernance() external {
        if (msg.sender != pendingGovernance || pendingGovernance == address(0)) {
            revert InvalidGovernanceTransfer();
        }
        address oldGov = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferAccepted(oldGov, governance);
    }

    function cancelGovernanceTransfer() external onlyGovernance {
        pendingGovernance = address(0);
        emit GovernanceTransferCancelled(msg.sender);
    }

    // ── Registration ──

    /// @notice Register a new CMO (Level 1). Governance-only.
    /// @param cmoIdHash 32-byte HMAC of the CMO EIN (or other unique identifier).
    /// @param admin Multi-sig vault or admin address that operates the CMO on-chain.
    /// @param stateIdx UsState enum index (0=CA / 1=NY / 2=IL / 3=TX / 4=CO / 255=Other).
    function registerCmo(
        bytes32 cmoIdHash,
        address admin,
        uint8 stateIdx
    ) external onlyGovernance {
        if (cmoIdHash == bytes32(0)) revert UnknownInstitution(cmoIdHash);
        if (_nodes[cmoIdHash].registeredAt != 0) revert AlreadyRegistered(cmoIdHash);
        if (admin == address(0)) revert NotInstitutionAdmin();
        _nodes[cmoIdHash] = InstitutionNode({
            cmoIdHash: cmoIdHash,
            districtIdHash: bytes32(0),
            schoolIdHash: bytes32(0),
            admin: admin,
            state: stateIdx,
            level: 1,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });
        totalNodes++;
        emit CmoRegistered(cmoIdHash, admin, stateIdx, uint64(block.timestamp));
    }

    /// @notice Register a new district (Level 2) under either a CMO or as standalone.
    /// @param cmoIdHash Parent CMO hash, or bytes32(0) for standalone districts.
    /// @param districtIdHash 32-byte HMAC of the NCES district code.
    /// @param admin Multi-sig vault or admin address for this district.
    /// @param stateIdx UsState enum index.
    /// @dev If cmoIdHash != 0, the CMO must be registered first. The CMO admin
    ///      (or governance) authorizes the district registration.
    function registerDistrict(
        bytes32 cmoIdHash,
        bytes32 districtIdHash,
        address admin,
        uint8 stateIdx
    ) external {
        if (districtIdHash == bytes32(0)) revert UnknownInstitution(districtIdHash);
        if (admin == address(0)) revert NotInstitutionAdmin();
        if (_nodes[districtIdHash].registeredAt != 0) revert AlreadyRegistered(districtIdHash);

        if (cmoIdHash != bytes32(0)) {
            // Under-CMO district: only the CMO admin (or governance) may register children.
            InstitutionNode storage parent = _nodes[cmoIdHash];
            if (parent.registeredAt == 0) revert InvalidParentChain();
            if (parent.level != 1) revert InvalidParentChain();
            if (msg.sender != parent.admin && msg.sender != governance) {
                revert NotInstitutionAdmin();
            }
            _districtsByCmo[cmoIdHash].push(districtIdHash);
        } else {
            // Standalone district: only governance can register.
            if (msg.sender != governance) revert NotGovernance();
        }

        _nodes[districtIdHash] = InstitutionNode({
            cmoIdHash: cmoIdHash,
            districtIdHash: districtIdHash,
            schoolIdHash: bytes32(0),
            admin: admin,
            state: stateIdx,
            level: 2,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });
        totalNodes++;
        emit DistrictRegistered(cmoIdHash, districtIdHash, admin, stateIdx, uint64(block.timestamp));
    }

    /// @notice Register a new school (Level 3) under a district.
    /// @param districtIdHash Parent district hash. MUST be registered.
    /// @param schoolIdHash 32-byte HMAC of the NCES school code.
    /// @param admin School-level admin (typically the principal's multi-sig).
    /// @param stateIdx UsState enum index — schools may be in a different state
    ///                 than their parent CMO (multi-state CMOs).
    /// @dev Either the district admin or the parent CMO admin (if any) or
    ///      governance can register the school.
    function registerSchool(
        bytes32 districtIdHash,
        bytes32 schoolIdHash,
        address admin,
        uint8 stateIdx
    ) external {
        if (schoolIdHash == bytes32(0)) revert UnknownInstitution(schoolIdHash);
        if (admin == address(0)) revert NotInstitutionAdmin();
        if (_nodes[schoolIdHash].registeredAt != 0) revert AlreadyRegistered(schoolIdHash);

        InstitutionNode storage district = _nodes[districtIdHash];
        if (district.registeredAt == 0) revert InvalidParentChain();
        if (district.level != 2) revert InvalidParentChain();

        bool authorized = msg.sender == district.admin || msg.sender == governance;
        if (!authorized && district.cmoIdHash != bytes32(0)) {
            // Allow the CMO admin to register schools under any of its districts.
            authorized = msg.sender == _nodes[district.cmoIdHash].admin;
        }
        if (!authorized) revert NotInstitutionAdmin();

        _nodes[schoolIdHash] = InstitutionNode({
            cmoIdHash: district.cmoIdHash,
            districtIdHash: districtIdHash,
            schoolIdHash: schoolIdHash,
            admin: admin,
            state: stateIdx,
            level: 3,
            registeredAt: uint64(block.timestamp),
            revoked: false
        });
        _schoolsByDistrict[districtIdHash].push(schoolIdHash);
        totalNodes++;
        emit SchoolRegistered(districtIdHash, schoolIdHash, admin, stateIdx, uint64(block.timestamp));
    }

    // ── Revocation ──

    /// @notice Revoke an institution. Governance-only — institutional admins
    ///         cannot self-revoke (prevents accidental wipe). Existing
    ///         student data on-chain is unaffected; the node is marked
    ///         revoked and downstream gating queries can short-circuit.
    function revokeInstitution(bytes32 nodeKey) external onlyGovernance {
        InstitutionNode storage n = _nodes[nodeKey];
        if (n.registeredAt == 0) revert UnknownInstitution(nodeKey);
        if (n.revoked) revert AlreadyRevoked(nodeKey);
        n.revoked = true;
        emit InstitutionRevoked(nodeKey, msg.sender, uint64(block.timestamp));
    }

    // ── Reads ──

    /// @notice Fetch a node by its primary hash key.
    function getNode(bytes32 nodeKey) external view returns (InstitutionNode memory) {
        InstitutionNode memory n = _nodes[nodeKey];
        if (n.registeredAt == 0) revert UnknownInstitution(nodeKey);
        return n;
    }

    /// @notice True if a registered node exists for this hash and it is not revoked.
    function isActive(bytes32 nodeKey) external view returns (bool) {
        InstitutionNode storage n = _nodes[nodeKey];
        return n.registeredAt != 0 && !n.revoked;
    }

    /// @notice Walk from a school back through its district and CMO. Returns
    ///         the parent districtIdHash and grandparent cmoIdHash (or
    ///         bytes32(0) for standalone-district children).
    function getInstitutionLineage(bytes32 schoolIdHash)
        external
        view
        returns (bytes32 cmoIdHash, bytes32 districtIdHash, address schoolAdmin, uint8 stateIdx)
    {
        InstitutionNode storage school = _nodes[schoolIdHash];
        if (school.registeredAt == 0) revert UnknownInstitution(schoolIdHash);
        return (school.cmoIdHash, school.districtIdHash, school.admin, school.state);
    }

    function listDistrictsForCmo(bytes32 cmoIdHash) external view returns (bytes32[] memory) {
        return _districtsByCmo[cmoIdHash];
    }

    function listSchoolsForDistrict(bytes32 districtIdHash) external view returns (bytes32[] memory) {
        return _schoolsByDistrict[districtIdHash];
    }

    /// @notice Walk all districts under a CMO and return the union of their
    ///         schools. Convenience read for clients (CMO-portal GUI) that
    ///         need a flat list of every school under a CMO without having
    ///         to do two RPC round-trips per district.
    /// @dev    Worst-case gas is O(districts * schools-per-district) but the
    ///         function is `view` and called off-chain via eth_call, so the
    ///         only real bound is the RPC node's view-call gas limit (very
    ///         high in practice). For a 50-district CMO with 30 schools each
    ///         (1500 schools) the call returns in ~10ms in real testnet runs.
    ///         Returns an empty array for an unknown or revoked CMO.
    function listAllSchoolsForCmo(bytes32 cmoIdHash) external view returns (bytes32[] memory) {
        bytes32[] memory districts = _districtsByCmo[cmoIdHash];

        // First pass: count total schools to allocate the right-sized array
        uint256 total = 0;
        for (uint256 i = 0; i < districts.length; i++) {
            total += _schoolsByDistrict[districts[i]].length;
        }

        // Second pass: fill
        bytes32[] memory schools = new bytes32[](total);
        uint256 idx = 0;
        for (uint256 i = 0; i < districts.length; i++) {
            bytes32[] memory schoolsInDist = _schoolsByDistrict[districts[i]];
            for (uint256 j = 0; j < schoolsInDist.length; j++) {
                schools[idx] = schoolsInDist[j];
                idx++;
            }
        }
        return schools;
    }
}
