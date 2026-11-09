// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";

/// Stand-ins, each exposing one privileged slot under the getter name a
/// deployed contract uses for it.
contract HasTreasury {
    address public treasury;
    constructor(address a) { treasury = a; }
}

contract HasTreasuryAddress {
    address public treasuryAddress;
    constructor(address a) { treasuryAddress = a; }
}

contract HasMarketplace {
    address public marketplace;
    constructor(address a) { marketplace = a; }
}

contract HasPendingOwner {
    address public pendingOwner;
    constructor(address a) { pendingOwner = a; }
}

contract HasGuardian {
    address public guardian;
    constructor(address a) { guardian = a; }
}

contract HasMarketMaker {
    address public marketMaker;
    constructor(address a) { marketMaker = a; }
}

contract HasTeeOracle {
    mapping(address => bool) public teeOracles;
    constructor(address a) { teeOracles[a] = true; }
}

contract HasRecorder {
    mapping(address => bool) public authorizedActivityRecorders;
    constructor(address a) { authorizedActivityRecorders[a] = true; }
}

/// AccessControl-style: holds one non-admin role.
contract HasOperatorRole {
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    address holder;
    constructor(address a) { holder = a; }
    function hasRole(bytes32 role, address a) external view returns (bool) {
        return role == OPERATOR_ROLE && a == holder;
    }
}

/// Returns a uint that is not a bool encoding from a set-shaped getter; the
/// sweep must treat it as "not this slot" rather than revert.
contract OddSetGetter {
    function teeOracles(address) external pure returns (uint256) { return 7; }
}

contract DeployerSlotHarness is AdminChecks {
    function problem(address t, address deployer) external view returns (string memory) {
        return _deployerAdminProblem(t, deployer);
    }
}

/// The deployer check reads every privileged address slot, not only the
/// governance/owner/admin ones: fee recipients, bound callers, pending
/// owners, guardians, set memberships and every probed role.
contract DeployerSlotCheckTest is Test {
    address deployer = makeAddr("deployer");
    address other = makeAddr("other");
    DeployerSlotHarness h;

    function setUp() public {
        h = new DeployerSlotHarness();
    }

    function _planted(address who) internal returns (address[] memory t) {
        t = new address[](8);
        t[0] = address(new HasTreasury(who));
        t[1] = address(new HasTreasuryAddress(who));
        t[2] = address(new HasMarketplace(who));
        t[3] = address(new HasPendingOwner(who));
        t[4] = address(new HasGuardian(who));
        t[5] = address(new HasMarketMaker(who));
        t[6] = address(new HasTeeOracle(who));
        t[7] = address(new HasRecorder(who));
    }

    function test_deployerInAnyPrivilegedSlot_isFlagged() public {
        address[] memory t = _planted(deployer);
        for (uint256 i = 0; i < t.length; i++) {
            assertTrue(bytes(h.problem(t[i], deployer)).length != 0, string.concat("not flagged: stand-in #", vm.toString(i)));
        }
        assertTrue(bytes(h.problem(address(new HasOperatorRole(deployer)), deployer)).length != 0, "role not flagged");
    }

    /// Negative control: the same slots holding someone else are clean.
    function test_otherAddressInTheSameSlots_isClean() public {
        address[] memory t = _planted(other);
        for (uint256 i = 0; i < t.length; i++) {
            assertEq(h.problem(t[i], deployer), "", string.concat("false positive: stand-in #", vm.toString(i)));
        }
        assertEq(h.problem(address(new HasOperatorRole(other)), deployer), "");
    }

    function test_nonBoolSetGetter_doesNotRevert() public {
        assertEq(h.problem(address(new OddSetGetter()), deployer), "");
    }

    function test_checkDeployedAdmins_failsOnADeployerFeeRecipient() public {
        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, hex"600160005260206000f3");
        HasTreasury bad = new HasTreasury(deployer);
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        vm.expectRevert(bytes("CheckDeployedAdmins: deployer EOA holds a privileged slot (see log)"));
        c.check(_book(string.concat('"Fees":"', vm.toString(address(bad)), '"')), false);

        HasTreasury good = new HasTreasury(other);
        CheckDeployedAdmins c2 = new CheckDeployedAdmins();
        c2.check(_book(string.concat('"Fees":"', vm.toString(address(good)), '"')), false);
        assertEq(c2.deployerAdmin(), 0);
    }

    function _book(string memory body) internal view returns (string memory) {
        return string.concat('{"deployer":"', vm.toString(deployer), '","contracts":{', body, '},"aaStack":{}}');
    }
}
