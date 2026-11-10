// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {GuardianCancellerV2} from "../../src/genesis/GuardianCancellerV2.sol";

/// @title V060GovernanceSpec: the 0.6.0 guardian veto P1 deploys, and the D-K3 key rule
/// @notice The part of the 0.6.0 ceremony-genesis spec that P1 (DeployGenesisGovernance in its
///         GENESIS_V060 mode) and the shared admin checks (GenesisProfile) read. It imports only
///         ProviderRegistry and GuardianCancellerV2, so their compile closure does not grow by the
///         rest of the 0.6.0 set (V060GenesisSpec). Salts: `Salts.salt(name)`.
///
///         ProviderRegistry(GOVERNANCE timelock, guardian = GUARDIAN timelock (Q9 a), 24 h)
///         GuardianCancellerV2(GOVERNANCE timelock, GUARDIAN timelock, that registry) (Q21)
library V060GovernanceSpec {
    string internal constant PROVIDER_REGISTRY = "Genesis.ProviderRegistry";
    string internal constant GUARDIAN_CANCELLER_V2 = "Genesis.GuardianCancellerV2";

    /// ProviderRegistry veto window (chain #400 deploy profile).
    uint64 internal constant PROVIDER_VETO_WINDOW = 24 hours;

    /// The governance book records which canceller generation holds GOVERNANCE's CANCELLER seat.
    uint256 internal constant CANCELLER_V2 = 2;

    /// @notice The key parameters the 0.6.0 genesis is built with (fed #467 §0.6; D-K3). Public
    ///         addresses only, owner-provided, no defaults:
    ///           keyInventory        the r1007 key inventory: every account the genesis funds,
    ///                               references or gives a role must be in it (an allowlist);
    ///                               the ceremony deployer is the one exception, and it must end
    ///                               with no role and (checked at alloc time) zero balance
    ///           retiredKeys         the r1006 non-producer keys D-K3 retired (an extra denylist)
    ///           guardianVetoMargin  seconds the GUARDIAN timelock delay must leave inside the
    ///                               ProviderRegistry veto window, so a veto lands in time
    struct KeyParams {
        address[] keyInventory;
        address[] retiredKeys;
        uint256 guardianVetoMargin;
    }

    string internal constant PENDING_KEY_INVENTORY =
        "PENDING PARAMETER: GENESIS_KEY_INVENTORY must list the r1007 key inventory (public addresses; fed #467 section 0.6)";
    string internal constant PENDING_VETO_MARGIN =
        "PENDING PARAMETER: GENESIS_GUARDIAN_VETO_MARGIN (seconds, above zero) is the owner's margin inside the ProviderRegistry veto window";
    string internal constant VETO_MARGIN_TOO_SMALL =
        "GUARDIAN timelock: minDelay plus GENESIS_GUARDIAN_VETO_MARGIN must fit inside the ProviderRegistry veto window (24 h)";

    /// @notice Reverts unless all three key parameters are given (none has a default).
    function requireKeyParams(KeyParams memory k) internal pure {
        require(k.keyInventory.length != 0, PENDING_KEY_INVENTORY);
        require(k.retiredKeys.length != 0, PENDING_RETIRED_KEYS);
        require(k.guardianVetoMargin != 0, PENDING_VETO_MARGIN);
    }

    /// @notice A council owner: on the inventory (allowlist) and not a retired key (denylist).
    function requireKnownKey(string memory role, address who, KeyParams memory k) internal pure {
        requireNotRetired(role, who, k.retiredKeys);
        for (uint256 i = 0; i < k.keyInventory.length; i++) {
            if (k.keyInventory[i] == who) return;
        }
        revert(string.concat(role, " is not in GENESIS_KEY_INVENTORY (the r1007 key inventory)"));
    }

    /// @notice The GUARDIAN timelock delay leaves `margin` inside the registry veto window.
    function requireVetoMargin(uint256 guardianDelay, uint256 margin) internal pure {
        require(margin != 0, PENDING_VETO_MARGIN);
        require(guardianDelay + margin <= PROVIDER_VETO_WINDOW, VETO_MARGIN_TOO_SMALL);
    }

    string internal constant PENDING_RETIRED_KEYS =
        "PENDING PARAMETER: GENESIS_RETIRED_KEYS must list the r1006 non-producer EVM keys retired at the r1007 ceremony (D-K3, owner 2026-11-10)";

    /// @notice Reverts when `who` is one of the retired r1006 keys (D-K3): every non-producer
    ///         EVM account the 0.6.0 genesis names must be a new key.
    function requireNotRetired(string memory role, address who, address[] memory retiredKeys) internal pure {
        for (uint256 i = 0; i < retiredKeys.length; i++) {
            require(
                who != retiredKeys[i],
                string.concat(role, " is a key retired at the r1007 ceremony (D-K3); the 0.6.0 genesis needs a new one")
            );
        }
    }

    function providerRegistryInit(address governanceTimelock, address guardianTimelock)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            type(ProviderRegistry).creationCode, abi.encode(governanceTimelock, guardianTimelock, PROVIDER_VETO_WINDOW)
        );
    }

    function guardianCancellerV2Init(address governanceTimelock, address guardianTimelock, address registry)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            type(GuardianCancellerV2).creationCode, abi.encode(governanceTimelock, guardianTimelock, registry)
        );
    }
}
