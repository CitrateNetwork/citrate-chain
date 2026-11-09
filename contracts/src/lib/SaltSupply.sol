// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title SaltSupply — the canonical SALT supply, for contracts that need it
/// @notice SALT is the native coin, so no token contract exposes a totalSupply.
///         Contracts that take a supply basis (TreasuryGovernor's quorum) read it
///         from here. The value mirrors `TOTAL_SUPPLY` in
///         core/economics/src/lib.rs, the genesis cap the node enforces;
///         scripts/ci/salt_supply_tripwire.sh fails if the two drift apart or if
///         a deploy script passes a literal supply instead of this constant.
library SaltSupply {
    /// @notice 1,000,000,000,000 SALT in wei (18 decimals).
    uint256 internal constant TOTAL_SUPPLY = 1_000_000_000_000 ether;
}
