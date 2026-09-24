// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {OrgScopedSBTUpgradeable} from "./OrgScopedSBTUpgradeable.sol";

/// @title FacilitySBT — one soulbound token per organization facility/site.
///
/// A facility belongs to an `OrganizationSBT` (`parentOrgTokenId`). Site-specific
/// data (a hashed location reference, capacity class, site policy pin, etc.) is
/// held in the extensible `attributes` map so an org can evolve it without a
/// contract change; the well-known `LOCATION_REF` key is a convention, not a
/// fixed struct field. Deployed behind a UUPS proxy — the CREATE2 proxy address
/// is frozen at the reroll while the implementation can be upgraded by governance.
contract FacilitySBT is OrgScopedSBTUpgradeable {
    /// Conventional attribute key for a privacy-preserving hashed location ref.
    bytes32 public constant LOCATION_REF = keccak256("citrate.facility.location_ref");

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address governor, address minter) external initializer {
        __OrgScopedSBT_init("Citrate FacilitySBT", "CIT-FAC", governor, minter);
    }

    /// Convenience reader for the conventional hashed location reference.
    function locationRef(uint256 tokenId) external view returns (bytes memory) {
        return this.getAttribute(tokenId, LOCATION_REF);
    }
}
