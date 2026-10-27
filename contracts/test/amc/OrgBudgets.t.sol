// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AmcTestBase} from "./AmcTestBase.sol";
import {OrgBudgets, IOrganizationSBT} from "../../src/amc/OrgBudgets.sol";
import {OrganizationSBT} from "../../src/cit_agent/OrganizationSBT.sol";
import {Governable} from "../../src/lib/Governable.sol";

contract OrgBudgetsTest is AmcTestBase {
    uint64 internal constant RAISE = 24 hours;
    OrgBudgets.Unit internal constant USD = OrgBudgets.Unit.VENDOR_LIST_MICRO_USD;
    OrgBudgets.Unit internal constant SALT = OrgBudgets.Unit.SALT_WEI;
    OrgBudgets.Unit internal constant TOK = OrgBudgets.Unit.TOKENS;
    OrgBudgets.Period internal constant DAY = OrgBudgets.Period.Day;
    OrgBudgets.Period internal constant MONTH = OrgBudgets.Period.Month;

    OrganizationSBT internal orgSbt;
    OrgBudgets internal ob;
    address internal sbtAdmin = makeAddr("sbtAdmin");
    address internal holder = makeAddr("holder");
    address internal admin = makeAddr("orgAdmin");
    address internal member = makeAddr("member");
    uint256 internal orgId;

    function setUp() public {
        vm.warp(1_800_000_000);
        _deployTimelock();
        orgSbt = new OrganizationSBT(sbtAdmin);
        vm.prank(sbtAdmin);
        orgId = orgSbt.mintOrg(holder, keccak256("did:citrate:org:acme"), holder, new bytes32[](0));
        ob = new OrgBudgets(address(timelock), IOrganizationSBT(address(orgSbt)), RAISE);
    }

    function _set(address who, address m, OrgBudgets.Unit u, OrgBudgets.Period p, uint128 amount) internal {
        vm.prank(who);
        ob.setCeiling(orgId, m, u, p, amount);
    }

    function _ceiling(address m, OrgBudgets.Unit u, OrgBudgets.Period p) internal view returns (bool, uint128) {
        return ob.ceilingOf(orgId, m, u, p);
    }

    // ------------------------------------------------------------------ construction

    function test_constructorChecks() public {
        vm.expectRevert(Governable.Governable_ZeroAddress.selector);
        new OrgBudgets(address(0), IOrganizationSBT(address(orgSbt)), RAISE);
        vm.expectRevert(OrgBudgets.OrgsHasNoCode.selector);
        new OrgBudgets(address(timelock), IOrganizationSBT(makeAddr("eoa")), RAISE);
        vm.expectRevert(OrgBudgets.BadRaiseDelay.selector);
        new OrgBudgets(address(timelock), IOrganizationSBT(address(orgSbt)), 1 hours - 1);
        vm.expectRevert(OrgBudgets.BadRaiseDelay.selector);
        new OrgBudgets(address(timelock), IOrganizationSBT(address(orgSbt)), 7 days + 1);
        assertEq(ob.raiseDelay(), RAISE);
        assertEq(address(ob.orgs()), address(orgSbt));
    }

    // ------------------------------------------------------------------ lower now, raise later

    function test_absentMeansNoCeilingAndFirstSetIsImmediate() public {
        (bool set, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertFalse(set);
        assertEq(amount, 0);
        _set(holder, address(0), USD, DAY, 5_000_000); // $5 a day
        (set, amount) = _ceiling(address(0), USD, DAY);
        assertTrue(set);
        assertEq(amount, 5_000_000);
    }

    function test_zeroBlocks() public {
        _set(holder, address(0), USD, DAY, 0);
        (bool set, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertTrue(set, "0 is a ceiling (blocked), not absence");
        assertEq(amount, 0);
    }

    function test_lowerIsImmediateRaiseWaits() public {
        _set(holder, address(0), USD, DAY, 5_000_000);
        _set(holder, address(0), USD, DAY, 1_000_000);
        (, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 1_000_000, "lowering is immediate");

        uint64 t = uint64(vm.getBlockTimestamp());
        vm.expectEmit(true, true, false, true, address(ob));
        emit OrgBudgets.CeilingSet(orgId, address(0), USD, DAY, 9_000_000, t + RAISE);
        _set(holder, address(0), USD, DAY, 9_000_000);
        (, amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 1_000_000, "a raise is not in effect yet");
        (bool pending, bool clears, uint128 pAmount, uint64 at) = ob.pendingOf(orgId, address(0), USD, DAY);
        assertTrue(pending);
        assertFalse(clears);
        assertEq(pAmount, 9_000_000);
        assertEq(at, t + RAISE);

        vm.warp(t + RAISE - 1);
        (, amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 1_000_000);
        vm.warp(t + RAISE);
        (, amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 9_000_000, "in effect at effectiveAt");
        (pending,,,) = ob.pendingOf(orgId, address(0), USD, DAY);
        assertFalse(pending);
    }

    function test_aLowerCancelsAPendingRaise() public {
        _set(holder, address(0), USD, DAY, 5_000_000);
        _set(holder, address(0), USD, DAY, 50_000_000); // queued raise
        _set(holder, address(0), USD, DAY, 4_000_000); // lower at once, raise dropped
        vm.warp(vm.getBlockTimestamp() + RAISE + 1);
        (, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 4_000_000);
    }

    function test_aSecondRaiseRestartsTheDelay() public {
        _set(holder, address(0), USD, DAY, 1);
        uint64 t0 = uint64(vm.getBlockTimestamp());
        _set(holder, address(0), USD, DAY, 10);
        vm.warp(t0 + RAISE - 10);
        _set(holder, address(0), USD, DAY, 20); // re-raise before the first one landed
        vm.warp(t0 + RAISE);
        (, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 1, "the first raise did not land");
        vm.warp(t0 + RAISE - 10 + RAISE);
        (, amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 20);
    }

    function test_aMaturedRaiseIsKeptByTheNextWrite() public {
        _set(holder, address(0), USD, DAY, 1);
        _set(holder, address(0), USD, DAY, 10);
        vm.warp(vm.getBlockTimestamp() + RAISE);
        _set(holder, address(0), USD, DAY, 8); // a lower from the matured 10
        (, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertEq(amount, 8);
    }

    function test_clearIsARaise() public {
        vm.prank(holder);
        vm.expectRevert(OrgBudgets.NoCeiling.selector);
        ob.clearCeiling(orgId, address(0), USD, DAY);
        _set(holder, address(0), USD, DAY, 5);
        uint64 t = uint64(vm.getBlockTimestamp());
        vm.prank(holder);
        ob.clearCeiling(orgId, address(0), USD, DAY);
        (bool set, uint128 amount) = _ceiling(address(0), USD, DAY);
        assertTrue(set);
        assertEq(amount, 5);
        (bool pending, bool clears,,) = ob.pendingOf(orgId, address(0), USD, DAY);
        assertTrue(pending && clears);
        vm.warp(t + RAISE);
        (set,) = _ceiling(address(0), USD, DAY);
        assertFalse(set);
    }

    function test_unitsAndPeriodsAreIndependent() public {
        _set(holder, address(0), SALT, MONTH, 100 ether);
        _set(holder, address(0), TOK, DAY, 1_000_000);
        (bool set,) = _ceiling(address(0), USD, DAY);
        assertFalse(set);
        (set,) = _ceiling(address(0), SALT, DAY);
        assertFalse(set);
        (, uint128 a) = _ceiling(address(0), SALT, MONTH);
        assertEq(a, 100 ether);
        (, a) = _ceiling(address(0), TOK, DAY);
        assertEq(a, 1_000_000);
    }

    // ------------------------------------------------------------------ who may set

    function test_holderAppointsOneAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(OrgBudgets.NotOrgAdmin.selector);
        ob.setCeiling(orgId, address(0), USD, DAY, 1);

        vm.prank(admin);
        vm.expectRevert(OrgBudgets.NotOrgHolder.selector);
        ob.setOrgAdmin(orgId, admin);

        vm.prank(holder);
        ob.setOrgAdmin(orgId, admin);
        assertEq(ob.orgAdminOf(orgId), admin);
        assertTrue(ob.isOrgAdmin(orgId, admin));
        assertTrue(ob.isOrgAdmin(orgId, holder));
        _set(admin, member, USD, DAY, 7);

        vm.prank(admin);
        vm.expectRevert(OrgBudgets.NotOrgHolder.selector);
        ob.setOrgAdmin(orgId, stranger); // an admin cannot appoint

        vm.prank(holder);
        ob.setOrgAdmin(orgId, address(0));
        assertFalse(ob.isOrgAdmin(orgId, admin));
        assertFalse(ob.isOrgAdmin(orgId, address(0)));
        vm.prank(admin);
        vm.expectRevert(OrgBudgets.NotOrgAdmin.selector);
        ob.setCeiling(orgId, member, USD, DAY, 1);
    }

    function test_unknownOrgReverts() public {
        vm.prank(holder);
        vm.expectRevert(); // ERC721NonexistentToken
        ob.setCeiling(orgId + 1, address(0), USD, DAY, 1);
    }

    function test_deactivatedOrgCanOnlyLower() public {
        _set(holder, address(0), USD, DAY, 10);
        vm.prank(sbtAdmin);
        orgSbt.deactivate(orgId);
        _set(holder, address(0), USD, DAY, 5); // lowering still works
        vm.startPrank(holder);
        vm.expectRevert(OrgBudgets.OrgNotActive.selector);
        ob.setCeiling(orgId, address(0), USD, DAY, 50);
        vm.expectRevert(OrgBudgets.OrgNotActive.selector);
        ob.clearCeiling(orgId, address(0), USD, DAY);
        vm.expectRevert(OrgBudgets.OrgNotActive.selector);
        ob.setOrgAdmin(orgId, admin);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ global max and effective

    function test_globalMaxIsGovernanceOnlyAndBoundsEveryCeiling() public {
        vm.prank(holder);
        vm.expectRevert(Governable.Governable_NotGovernance.selector);
        ob.setGlobalMax(USD, DAY, 1);

        _set(holder, address(0), USD, DAY, 30_000_000);
        _govCall(address(ob), abi.encodeCall(OrgBudgets.setGlobalMax, (USD, DAY, 20_000_000)));
        (bool gs, uint128 g) = ob.globalMaxOf(USD, DAY);
        assertTrue(gs);
        assertEq(g, 20_000_000);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(OrgBudgets.AboveGlobalMax.selector, uint128(20_000_000)));
        ob.setCeiling(orgId, address(0), USD, DAY, 20_000_001);

        // A ceiling set before the max is clamped in the effective value.
        (bool set, uint128 eff) = ob.effectiveCeilingOf(orgId, address(0), USD, DAY);
        assertTrue(set);
        assertEq(eff, 20_000_000);
        // An org with no ceiling of its own still gets the global max.
        (set, eff) = ob.effectiveCeilingOf(orgId + 7, address(0), USD, DAY);
        assertTrue(set);
        assertEq(eff, 20_000_000);

        _govCall(address(ob), abi.encodeCall(OrgBudgets.clearGlobalMax, (USD, DAY)));
        (set, eff) = ob.effectiveCeilingOf(orgId, address(0), USD, DAY);
        assertEq(eff, 30_000_000);
    }

    function test_effectiveIsTheMinimumOfMemberDefaultAndGlobal() public {
        (bool set, uint128 eff) = ob.effectiveCeilingOf(orgId, member, USD, DAY);
        assertFalse(set);
        assertEq(eff, 0);
        _set(holder, member, USD, DAY, 3);
        (set, eff) = ob.effectiveCeilingOf(orgId, member, USD, DAY);
        assertEq(eff, 3);
        _set(holder, address(0), USD, DAY, 2);
        (set, eff) = ob.effectiveCeilingOf(orgId, member, USD, DAY);
        assertEq(eff, 2, "the org default narrows a looser member ceiling");
        (set, eff) = ob.effectiveCeilingOf(orgId, address(0), USD, DAY);
        assertEq(eff, 2);
        (set, eff) = ob.effectiveCeilingOf(orgId, stranger, USD, DAY);
        assertEq(eff, 2, "default applies to members without their own");
    }

    function test_holdsNoValue() public {
        _assertRejectsValue(address(ob));
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_lowerNowRaiseAfterDelay(uint128 first, uint128 second, uint32 wait) public {
        _set(holder, address(0), USD, DAY, first);
        uint64 t = uint64(vm.getBlockTimestamp());
        _set(holder, address(0), USD, DAY, second);
        vm.warp(t + bound(wait, 0, 3 * RAISE));
        (, uint128 amount) = _ceiling(address(0), USD, DAY);
        if (second <= first || vm.getBlockTimestamp() >= t + RAISE) assertEq(amount, second);
        else assertEq(amount, first);
    }

    function testFuzz_effectiveNeverAboveGlobalMax(uint128 c, uint128 g) public {
        _set(holder, address(0), TOK, MONTH, c);
        vm.prank(address(timelock));
        ob.setGlobalMax(TOK, MONTH, g);
        (bool set, uint128 eff) = ob.effectiveCeilingOf(orgId, member, TOK, MONTH);
        assertTrue(set);
        assertLe(eff, g);
        assertLe(eff, c);
    }
}

/// Random lowers, raises, clears, global-max changes and time; checked against a reference model.
contract OrgBudgetsHandler is Test {
    OrgBudgets public ob;
    uint256 public orgId;
    address public holder;
    address public gov;
    uint64 public delay;

    // Reference model of the org-default USD/Day slot.
    bool public mSet;
    uint128 public mAmount;
    bool public mPending;
    bool public mPendingClear;
    uint128 public mPendingAmount;
    uint64 public mPendingAt;
    bool public gSet;
    uint128 public gAmount;
    bool public violation;

    constructor(OrgBudgets ob_, uint256 orgId_, address holder_, address gov_) {
        ob = ob_;
        orgId = orgId_;
        holder = holder_;
        gov = gov_;
        delay = ob_.raiseDelay();
    }

    function _modelNow() public view returns (bool, uint128) {
        if (mPending && vm.getBlockTimestamp() >= mPendingAt) {
            return mPendingClear ? (false, uint128(0)) : (true, mPendingAmount);
        }
        return (mSet, mAmount);
    }

    function _fold() internal returns (bool s, uint128 a) {
        (s, a) = _modelNow();
        mSet = s;
        mAmount = a;
        mPending = false;
        mPendingClear = false;
    }

    function warp(uint32 dt) external {
        vm.warp(vm.getBlockTimestamp() + bound(dt, 0, 2 days));
    }

    function set(uint128 amount) external {
        amount = uint128(bound(amount, 0, 1_000));
        vm.prank(holder);
        try ob.setCeiling(orgId, address(0), OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day, amount) {
            if (gSet && amount > gAmount) violation = true;
            (bool s, uint128 a) = _fold();
            if (!s || amount <= a) {
                mSet = true;
                mAmount = amount;
            } else {
                mPending = true;
                mPendingAmount = amount;
                mPendingAt = uint64(vm.getBlockTimestamp()) + delay;
            }
        } catch {
            if (!(gSet && amount > gAmount)) violation = true;
        }
    }

    function clear() external {
        vm.prank(holder);
        try ob.clearCeiling(orgId, address(0), OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day) {
            (bool s,) = _fold();
            if (!s) violation = true;
            mPending = true;
            mPendingClear = true;
            mPendingAt = uint64(vm.getBlockTimestamp()) + delay;
        } catch {
            (bool s,) = _modelNow();
            if (s) violation = true;
        }
    }

    function globalMax(uint128 amount, bool clearIt) external {
        vm.startPrank(gov);
        if (clearIt) {
            ob.clearGlobalMax(OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day);
            gSet = false;
        } else {
            amount = uint128(bound(amount, 0, 1_000));
            ob.setGlobalMax(OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day, amount);
            gSet = true;
            gAmount = amount;
        }
        vm.stopPrank();
    }
}

contract OrgBudgetsInvariantTest is Test {
    OrgBudgets internal ob;
    OrgBudgetsHandler internal handler;
    uint256 internal orgId;

    function setUp() public {
        vm.warp(1_800_000_000);
        address gov = makeAddr("gov");
        address holder = makeAddr("holder");
        address sbtAdmin = makeAddr("sbtAdmin");
        OrganizationSBT orgSbt = new OrganizationSBT(sbtAdmin);
        vm.prank(sbtAdmin);
        orgId = orgSbt.mintOrg(holder, keccak256("did:org"), holder, new bytes32[](0));
        ob = new OrgBudgets(gov, IOrganizationSBT(address(orgSbt)), 24 hours);
        handler = new OrgBudgetsHandler(ob, orgId, holder, gov);
        targetContract(address(handler));
    }

    /// The slot always equals the model: lowers at once, raises only at effectiveAt.
    function invariant_ceilingMatchesModel() public view {
        assertFalse(handler.violation());
        (bool s, uint128 a) =
            ob.ceilingOf(orgId, address(0), OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day);
        (bool ms, uint128 ma) = handler._modelNow();
        assertEq(s, ms);
        assertEq(a, ma);
    }

    /// No effective ceiling exceeds the global max when one is set.
    function invariant_effectiveNeverAboveGlobalMax() public view {
        (bool s, uint128 a) =
            ob.effectiveCeilingOf(orgId, address(0), OrgBudgets.Unit.VENDOR_LIST_MICRO_USD, OrgBudgets.Period.Day);
        if (handler.gSet()) {
            assertTrue(s);
            assertLe(a, handler.gAmount());
        }
    }

    function invariant_holdsNoValue() public view {
        assertEq(address(ob).balance, 0);
    }
}
