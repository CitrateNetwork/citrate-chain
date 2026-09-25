// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title InitialAdmin — constructor-time admin sanity check (PBA-L2-002)
/// @notice Every contract in the deterministic-deploy ceremony is created with
///         `new X{salt: ...}()` from a forge script, which Foundry routes
///         through the Arachnid CREATE2 deployer. Inside such a constructor
///         `msg.sender` is that factory, not the ceremony key. The factory's
///         runtime can only CREATE2, so any admin/owner/governance slot seeded
///         from `msg.sender` was permanently orphaned on chain 40204 (21
///         contracts, pre-bounty audit 2026-09-24 PBA-L2-002).
///
///         Constructors now take the admin as an explicit argument, and run it
///         through `check`, which refuses the zero address and the factory.
library InitialAdmin {
    /// @notice The Arachnid deterministic-deployment proxy (genesis-allocated
    ///         on every Citrate profile; also present in forge's EVM).
    address internal constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error InitialAdmin_Zero();
    error InitialAdmin_Create2Factory();

    /// @dev Reverts unless `admin` is a usable, non-factory address.
    function check(address admin) internal pure returns (address) {
        if (admin == address(0)) revert InitialAdmin_Zero();
        if (admin == CREATE2_FACTORY) revert InitialAdmin_Create2Factory();
        return admin;
    }
}
