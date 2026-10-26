// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title OrangeSeedV0: the seed planted in the genesis block
/// @notice A small upgradeable contract placed in the block-0 allocation. It records who
///         planted it and when, carries a short orchard message, and does nothing else yet.
///         Its only privileged operation is the upgrade, which belongs to the genesis
///         GOVERNANCE timelock: a later version, chosen through governance, is what the
///         seed grows into.
/// @dev    UUPS behind an ERC-1967 proxy, the pattern this repo already uses
///         (`OrgScopedSBTUpgradeable`, `MembershipStakeVault`). All state lives in one
///         ERC-7201 namespace, so a future version appends fields to `SeedStorage` (never
///         reorders or removes them) and cannot collide with it.
///
///         It holds no value: there is no `receive` or payable `fallback`, every function is
///         non-payable, and `upgradeToAndCall` (payable in OZ) refuses a non-zero value.
///
///         Genesis: `script/GenesisOrangeSeed.s.sol` produces the exact code and storage of
///         the proxy and this implementation for the block-0 allocation. Off genesis,
///         `script/DeployOrangeSeed.s.sol` deploys the proxy with `initialize` in its
///         constructor, so initialization is atomic and cannot be front-run.
contract OrangeSeedV0 is Initializable, UUPSUpgradeable {
    /// @custom:storage-location erc7201:citrate.storage.OrangeSeed
    struct SeedStorage {
        /// Citrate Inc.'s planting address (a treasury or governance address, not a person).
        address planter;
        /// The only account that may upgrade the seed: the genesis GOVERNANCE timelock.
        address governance;
        /// Block the seed was planted in (0 for the genesis predeploy).
        uint256 plantedAtBlock;
        /// Timestamp of that block (the genesis timestamp for the predeploy).
        uint256 plantedAtTimestamp;
        /// keccak256 of the V0 story, so later versions can show what was planted.
        bytes32 storyHash;
    }

    /// keccak256(abi.encode(uint256(keccak256("citrate.storage.OrangeSeed")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant SEED_STORAGE_LOCATION =
        0x341195138d1c2c942beec98fd1e2c3287168a3890a2078215c65e5e0c1413000;

    string internal constant STORY =
        "A seed, planted at block zero by the people who tend this orchard. "
        "We grow the patient way: plant, tend, prune what cracks, and keep it all open to be checked. "
        "Fruit carries seeds... when the grove is ready, this one grows into whatever its members decide.";

    /// Emitted once, when the seed is planted.
    event Planted(
        address indexed planter, address indexed governance, uint256 plantedAtBlock, uint256 plantedAtTimestamp
    );

    error ZeroAddress();
    error NotGovernance(address caller);
    error ValueNotAccepted();
    /// `germinate` is reserved for a later version; V0 is still a seed.
    error NotYetGerminated();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Plant the seed. Runs once, through the proxy, in the same frame that sets the
    ///         proxy's implementation (the proxy constructor, or the genesis state).
    /// @param governance_ the genesis GOVERNANCE timelock: the only upgrade authority.
    /// @param planter_ Citrate Inc.'s planting address.
    function initialize(address governance_, address planter_) external initializer {
        if (governance_ == address(0) || planter_ == address(0)) revert ZeroAddress();
        SeedStorage storage $ = _seed();
        $.planter = planter_;
        $.governance = governance_;
        $.plantedAtBlock = block.number;
        $.plantedAtTimestamp = block.timestamp;
        $.storyHash = keccak256(bytes(STORY));
        emit Planted(planter_, governance_, block.number, block.timestamp);
    }

    // ── the seed ─────────────────────────────────────────────────────────────

    function story() external pure returns (string memory) {
        return STORY;
    }

    function version() external pure virtual returns (uint256) {
        return 0;
    }

    /// @notice Not yet. A future version, upgraded in by governance, decides what this does.
    /// @dev Deliberately non-payable rather than `pure`: an override may only tighten state
    ///      mutability, so `pure` here would stop a version that inherits V0 from giving
    ///      `germinate` an effect. (solc notes it could be pure; that is intended.)
    function germinate() external virtual {
        revert NotYetGerminated();
    }

    function planter() external view returns (address) {
        return _seed().planter;
    }

    function governance() external view returns (address) {
        return _seed().governance;
    }

    function plantedAtBlock() external view returns (uint256) {
        return _seed().plantedAtBlock;
    }

    function plantedAtTimestamp() external view returns (uint256) {
        return _seed().plantedAtTimestamp;
    }

    function storyHash() external view returns (bytes32) {
        return _seed().storyHash;
    }

    // ── upgrade (the only privileged operation) ─────────────────────────────

    /// @dev OZ declares this payable; the seed never accepts value, even from governance.
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual override {
        if (msg.value != 0) revert ValueNotAccepted();
        super.upgradeToAndCall(newImplementation, data);
    }

    function _authorizeUpgrade(address) internal view virtual override {
        if (msg.sender != _seed().governance) revert NotGovernance(msg.sender);
    }

    function _seed() internal pure returns (SeedStorage storage $) {
        assembly {
            $.slot := SEED_STORAGE_LOCATION
        }
    }
}
