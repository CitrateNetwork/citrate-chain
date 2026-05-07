// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

/// @title IInstitutionTreeV1
/// @notice Minimal read-only interface to the InstitutionTreeV1 4-level
///         tenancy registry. Companion contracts (ComplianceRegistry,
///         GuardianTokenRegistry, etc.) depend on this stable surface so
///         they don't pull the full implementation as a dependency.
/// @dev    Mirrors the public read functions of `InstitutionTreeV1.sol`.
///         Adding new functions here is non-breaking; removing or changing
///         a signature is a breaking change that requires a V2 interface.
interface IInstitutionTreeV1 {
    /// @notice One node in the 4-level tree. Mirrors the storage struct in
    ///         InstitutionTreeV1.sol — kept identical so callers can share types.
    struct InstitutionNode {
        bytes32 cmoIdHash;
        bytes32 districtIdHash;
        bytes32 schoolIdHash;
        address admin;
        uint8 state;     // UsState index: 0=CA, 1=NY, 2=IL, 3=TX, 4=CO, 255=Other
        uint8 level;     // 1=CMO, 2=District, 3=School
        uint64 registeredAt;
        bool revoked;
    }

    /// @notice Reverts if the node is not registered. Returns the full node otherwise.
    function getNode(bytes32 nodeKey) external view returns (InstitutionNode memory);

    /// @notice True if the node exists AND is not revoked.
    function isActive(bytes32 nodeKey) external view returns (bool);

    /// @notice Walk a school's lineage to its parent district + grandparent CMO.
    function getInstitutionLineage(bytes32 schoolIdHash)
        external
        view
        returns (bytes32 cmoIdHash, bytes32 districtIdHash, address schoolAdmin, uint8 stateIdx);

    /// @notice Enumerate child districts under a CMO.
    function listDistrictsForCmo(bytes32 cmoIdHash) external view returns (bytes32[] memory);

    /// @notice Enumerate child schools under a district.
    function listSchoolsForDistrict(bytes32 districtIdHash) external view returns (bytes32[] memory);
}
