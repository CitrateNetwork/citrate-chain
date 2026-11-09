// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {OrangeSeedBase} from "./OrangeSeedBase.sol";
import {OrangeSeedV0} from "../../src/genesis/OrangeSeedV0.sol";
import {OrangeSeedV1Fixture} from "./OrangeSeedV1Fixture.sol";

/// @notice Drives the upgrade path with arbitrary callers, targets, values and calls.
contract OrangeSeedHandler is Test {
    OrangeSeedV0 public immutable seed;
    address public immutable governance;
    address public immutable implV0;
    address[] public actors;
    address[] public targets;

    uint256 public nonGovernanceUpgrades; // must stay 0
    uint256 public governanceUpgrades;
    uint256 public valueAccepted; // must stay 0

    constructor(OrangeSeedV0 seed_, address governance_, address implV0_, address planter_, address deployer_) {
        seed = seed_;
        governance = governance_;
        implV0 = implV0_;
        actors.push(governance_);
        actors.push(planter_);
        actors.push(deployer_);
        actors.push(makeAddr("eoa1"));
        actors.push(makeAddr("eoa2"));
        targets.push(address(new OrangeSeedV1Fixture()));
        targets.push(address(new OrangeSeedV1Fixture()));
        targets.push(implV0_);
    }

    function upgrade(uint256 actorSeed, uint256 targetSeed) external {
        address who = actors[actorSeed % actors.length];
        address target = targets[targetSeed % targets.length];
        vm.prank(who);
        try seed.upgradeToAndCall(target, "") {
            if (who == governance) governanceUpgrades++;
            else nonGovernanceUpgrades++;
        } catch {}
    }

    function upgradeAsAnyone(address who, uint256 targetSeed) external {
        address target = targets[targetSeed % targets.length];
        vm.prank(who);
        try seed.upgradeToAndCall(target, "") {
            if (who == governance) governanceUpgrades++;
            else nonGovernanceUpgrades++;
        } catch {}
    }

    function upgradeImplementationDirectly(uint256 actorSeed, uint256 targetSeed) external {
        address who = actors[actorSeed % actors.length];
        vm.prank(who);
        try OrangeSeedV0(implV0).upgradeToAndCall(targets[targetSeed % targets.length], "") {
            nonGovernanceUpgrades++; // never legitimate
        } catch {}
    }

    function sendValue(uint256 actorSeed, uint96 amount, bytes calldata data) external {
        if (amount == 0) return;
        address who = actors[actorSeed % actors.length];
        vm.deal(who, amount);
        vm.prank(who);
        (bool ok,) = address(seed).call{value: amount}(data);
        if (ok) valueAccepted++;
    }

    function reinitialize(uint256 actorSeed) external {
        address who = actors[actorSeed % actors.length];
        vm.prank(who);
        try seed.initialize(who, who) {
            nonGovernanceUpgrades++; // re-planting is never legitimate
        } catch {}
    }

    function germinate() external {
        try seed.germinate() {} catch {}
    }
}

contract OrangeSeedInvariantTest is OrangeSeedBase {
    OrangeSeedHandler internal handler;
    bytes32 internal storyHash0;

    function setUp() public override {
        super.setUp();
        storyHash0 = seed.storyHash();
        handler = new OrangeSeedHandler(seed, governance, implAddr, planter, deployer);
        targetContract(address(handler));
    }

    function invariant_onlyGovernanceUpgrades() public view {
        assertEq(handler.nonGovernanceUpgrades(), 0);
    }

    function invariant_plantingRecordNeverChanges() public view {
        assertEq(seed.plantedAtBlock(), 0);
        assertEq(seed.plantedAtTimestamp(), GENESIS_TS);
        assertEq(seed.planter(), planter);
        assertEq(seed.governance(), governance);
        assertEq(seed.storyHash(), storyHash0);
    }

    function invariant_holdsNoValue() public view {
        assertEq(address(seed).balance, 0);
        assertEq(implAddr.balance, 0);
        assertEq(handler.valueAccepted(), 0);
    }

    function invariant_implementationIsAKnownTarget() public view {
        address impl = address(uint160(uint256(vm.load(proxyAddr, IMPLEMENTATION_SLOT))));
        bool known = impl == implAddr;
        for (uint256 i = 0; i < 3; i++) {
            if (impl == handler.targets(i)) known = true;
        }
        assertTrue(known);
    }
}
