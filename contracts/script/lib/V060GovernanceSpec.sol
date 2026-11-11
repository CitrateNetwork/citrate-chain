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

    /// @notice The key parameters the 0.6.0 genesis is built with (fed #467 section 0.6; D-K3).
    ///         Public addresses only, owner-provided, no defaults:
    ///           governanceOwners    the r1007 key inventory's keys with role GOV_OWNERS
    ///           guardianOwners      the r1007 key inventory's keys with role GRD_OWNERS
    ///                               (GENESIS_KEY_INVENTORY is role-tagged JSON {address: [roles]};
    ///                               a council owner must be on it WITH its council's role. P0
    ///                               checks every other role input and the role vocabulary. The
    ///                               ceremony deployer is never on it and ends with no role)
    ///           retiredKeys         the r1006 non-producer keys D-K3 retired (an extra denylist)
    ///           guardianVetoMargin  seconds the GUARDIAN timelock delay must leave inside the
    ///                               ProviderRegistry veto window, so a veto lands in time;
    ///                               decided by the owner on 2026-11-11 as 7200 s
    ///                               (DECIDED_GUARDIAN_VETO_MARGIN), and still a required input
    struct KeyParams {
        address[] governanceOwners;
        address[] guardianOwners;
        address[] retiredKeys;
        uint256 guardianVetoMargin;
        /// the inventory's keys with role V060_DEPLOYER (a post-genesis key; live mode only)
        address[] v060Deployers;
    }

    string internal constant PENDING_KEY_INVENTORY =
        "PENDING PARAMETER: GENESIS_KEY_INVENTORY must list the r1007 key inventory (public addresses; fed #467 section 0.6)";
    string internal constant PENDING_VETO_MARGIN =
        "PENDING PARAMETER: GENESIS_GUARDIAN_VETO_MARGIN (seconds, above zero) is the owner's margin inside the ProviderRegistry veto window";
    /// GENESIS_GUARDIAN_VETO_MARGIN as the owner decided it (2026-11-11): 2 h. Not a default:
    /// the input must still be given, and any other value is refused.
    uint256 internal constant DECIDED_GUARDIAN_VETO_MARGIN = 2 hours;
    string internal constant VETO_MARGIN_NOT_DECIDED =
        "GENESIS_GUARDIAN_VETO_MARGIN is not the owner's decided value (7200 s, owner 2026-11-11)";
    string internal constant VETO_MARGIN_TOO_SMALL =
        "GUARDIAN timelock: minDelay plus GENESIS_GUARDIAN_VETO_MARGIN must fit inside the ProviderRegistry veto window (24 h)";

    string internal constant PENDING_V060_DEPLOYER =
        "PENDING PARAMETER: the live mode needs a GENESIS_KEY_INVENTORY key with role V060_DEPLOYER (the r1007 V060_DEPLOYER, lead decision fed #561)";

    /// The salt of the r1007 canceller-swap batch on the GOVERNANCE timelock (fed #561 section 3.1).
    bytes32 internal constant SWAP_SALT = keccak256("r1007.v060.d2c.canceller-v2");
    string internal constant SWAP_NEEDS_V2_CODE =
        "GuardianCancellerV2 has no code with this build's code hash at its predicted address: queue the swap only after D2c's receipts (fed #561 review)";

    /// @notice Live mode (r1007, post-genesis): the deployer is on the inventory with role
    ///         V060_DEPLOYER (a key that holds no block-0 seat).
    function requireLiveDeployer(address deployer, KeyParams memory k) internal pure {
        require(k.v060Deployers.length != 0, PENDING_V060_DEPLOYER);
        for (uint256 i = 0; i < k.v060Deployers.length; i++) {
            if (k.v060Deployers[i] == deployer) return;
        }
        revert("deployer is not in GENESIS_KEY_INVENTORY with role V060_DEPLOYER");
    }

    /// @notice Reverts unless all three key parameters are given (none has a default).
    function requireKeyParams(KeyParams memory k) internal pure {
        require(k.governanceOwners.length != 0 && k.guardianOwners.length != 0, PENDING_KEY_INVENTORY);
        require(k.retiredKeys.length != 0, PENDING_RETIRED_KEYS);
        require(k.guardianVetoMargin != 0, PENDING_VETO_MARGIN);
    }

    /// @notice A council owner: off the retired list (denylist), and on the inventory with its
    ///         council's role (`tag`, GOV_OWNERS or GRD_OWNERS; `allowed` is that role's keys).
    function requireKnownKey(
        string memory role,
        string memory tag,
        address who,
        address[] memory allowed,
        KeyParams memory k
    ) internal pure {
        requireNotRetired(role, who, k.retiredKeys);
        for (uint256 i = 0; i < allowed.length; i++) {
            if (allowed[i] == who) return;
        }
        revert(string.concat(role, " is not in GENESIS_KEY_INVENTORY with role ", tag));
    }

    /// @notice The GUARDIAN timelock delay leaves `margin` inside the registry veto window.
    function requireVetoMargin(uint256 guardianDelay, uint256 margin) internal pure {
        require(margin != 0, PENDING_VETO_MARGIN);
        require(margin == DECIDED_GUARDIAN_VETO_MARGIN, VETO_MARGIN_NOT_DECIDED);
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
