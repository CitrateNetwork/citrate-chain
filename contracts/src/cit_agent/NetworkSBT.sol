// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {OrgScopedSBTUpgradeable} from "./OrgScopedSBTUpgradeable.sol";

/// @title NetworkSBT — one soulbound token per organization network identity.
///
/// The "overall network ID" an organization holds (citrate-homestead/sources/02).
/// A network belongs to an `OrganizationSBT` (`parentOrgTokenId`) and, where the
/// org runs a private Citrate L1, records that chain's id via the conventional
/// `CHAIN_ID` attribute. Chain-id allocation is central within a chain profile and
/// is not a claim of worldwide uniqueness (see citrate-homestead chain baseline).
/// Deployed behind a UUPS proxy: address frozen at the reroll, logic upgradeable
/// by governance.
contract NetworkSBT is OrgScopedSBTUpgradeable {
    /// Conventional attribute key for the org's private-chain id (abi-encoded uint256).
    bytes32 public constant CHAIN_ID = keccak256("citrate.network.chain_id");

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address governor, address minter) external initializer {
        __OrgScopedSBT_init("Citrate NetworkSBT", "CIT-NET", governor, minter);
    }

    /// Convenience reader for the conventional private-chain id, 0 if unset.
    function chainIdOf(uint256 tokenId) external view returns (uint256) {
        bytes memory v = this.getAttribute(tokenId, CHAIN_ID);
        if (v.length == 0) return 0;
        return abi.decode(v, (uint256));
    }
}
