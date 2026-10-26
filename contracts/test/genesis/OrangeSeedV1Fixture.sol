// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {OrangeSeedV0} from "../../src/genesis/OrangeSeedV0.sol";

/// @title OrangeSeedV1Fixture: a test-only upgrade target
/// @notice The shape a real V1 takes: same namespace, V0's fields untouched, new fields
///         appended in their own namespace, a `reinitializer(2)` step, and a `germinate`
///         that does something. Used to prove the planting record survives an upgrade.
contract OrangeSeedV1Fixture is OrangeSeedV0 {
    /// @custom:storage-location erc7201:citrate.storage.OrangeSeed.V1
    struct SproutStorage {
        uint256 sprouts;
        string note;
    }

    /// keccak256(abi.encode(uint256(keccak256("citrate.storage.OrangeSeed.V1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant SPROUT_STORAGE_LOCATION =
        0x2b6efde0a78f94e2452dea3f3ef1ba9ac9935a749b44174bb04e922f62e13b00;

    function initializeV1(string calldata note_) external reinitializer(2) {
        _sprout().note = note_;
    }

    function version() external pure override returns (uint256) {
        return 1;
    }

    /// Keeps OrangeSeedV0's `germinate` signature, now with an effect.
    function germinate() external override {
        _sprout().sprouts += 1;
    }

    function sprouts() external view returns (uint256) {
        return _sprout().sprouts;
    }

    function note() external view returns (string memory) {
        return _sprout().note;
    }

    function _sprout() private pure returns (SproutStorage storage $) {
        assembly {
            $.slot := SPROUT_STORAGE_LOCATION
        }
    }
}
