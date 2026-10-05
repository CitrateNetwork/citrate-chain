// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title DevnetAllowList: TEST FIXTURE for scripts/fl/devnet-round-e2e.sh only.
/// @notice Stands in for the KYC registry and the membership contract that
///         citrate-coop's PatronageLedger consults, on a throwaway local devnet. It
///         answers "verified" and "member" for the addresses the harness listed at
///         deployment and nobody else. Never deployed anywhere but a local devnet.
contract DevnetAllowList {
    mapping(address => bool) public listed;

    constructor(address[] memory members) {
        for (uint256 i = 0; i < members.length; i++) {
            listed[members[i]] = true;
        }
    }

    function isVerified(address a) external view returns (bool) {
        return listed[a];
    }

    function identityOf(address a) external view returns (bytes32) {
        return listed[a] ? keccak256(abi.encodePacked(a)) : bytes32(0);
    }

    function isMember(address a) external view returns (bool) {
        return listed[a];
    }
}
