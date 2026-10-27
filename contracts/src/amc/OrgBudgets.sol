// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Governable} from "../lib/Governable.sol";

/// @dev The two OrganizationSBT reads OrgBudgets needs (view calls only).
interface IOrganizationSBT {
    function ownerOf(uint256 tokenId) external view returns (address);
    function isActive(uint256 tokenId) external view returns (bool);
}

/// @title OrgBudgets: per-org spending ceilings as an accounting limit, never a payment
/// @notice AMC 0.5.3 planset 06 section 4; ADR-2026-10-26 P-15. Spec:
///         docs/amc/PROVIDER_GOVERNANCE_CONTRACTS.md. Not in r1006 or block 0.
///
///         No SALT moves here: no payable path, no token, no balance. Core's spend guard applies
///         min(member's local cap, effective org ceiling) per matching unit and period, using its
///         own usage-log totals. A modified client can ignore a ceiling, so it is an accounting
///         ceiling, not a security boundary (RT-5); org-side evidence comes from receipts.
///
///         Units (RT-1). Each ceiling carries its unit; the contract stores NO conversion rate.
///           SALT_WEI               SALT-paid work only (InferenceRouter, network compute, agent tasks)
///           VENDOR_LIST_MICRO_USD  BYOK calls, compared with the usage log's vendor list-price cost
///           TOKENS                 BYOK calls, compared with the usage log's token totals
///         Owner decision Q-3 (2026-10-26): split by what is paid. `effectiveCeilingOf` takes the
///         payment kind and reverts `UnitNotForPayment` when asked for a SALT ceiling on vendor-key
///         spend (or a USD / token ceiling on SALT-paid work), so a SALT ceiling can never bind
///         BYO vendor spend and no SALT/USD rate is ever implied.
///
///         Who sets: only the OrganizationSBT holder (owner decision Q-10, 2026-10-26; no
///         appointed admins).
///         Lowering takes effect at once; raising (including removing a ceiling) waits
///         `RAISE_DELAY` (24 h, owner decision), so a stolen holder key can stop spend at once but cannot open it silently.
///         A ceiling of 0 blocks; no ceiling means none set. Governance may set a global max per
///         (unit, period) that bounds every effective ceiling; it never sets a floor.
contract OrgBudgets is Governable {
    enum Unit {
        SALT_WEI,
        VENDOR_LIST_MICRO_USD,
        TOKENS
    }

    enum Period {
        Day,
        Month
    }

    /// What the spend being checked is paid with (owner decision Q-3, 2026-10-26).
    enum Payment {
        SaltPaid, // InferenceRouter, network compute, agent-to-agent tasks: SALT_WEI only
        VendorKey // BYO vendor key: VENDOR_LIST_MICRO_USD or TOKENS only, never SALT_WEI
    }

    /// In-effect value plus at most one pending raise (or pending removal).
    struct Slot {
        bool set;
        uint128 amount;
        uint64 effectiveAt;
        bool pending;
        bool pendingClear;
        uint128 pendingAmount;
        uint64 pendingAt;
    }

    struct GlobalMax {
        bool set;
        uint128 amount;
    }

    /// @notice How long a raise (or removal) waits. Owner decision 2026-10-26.
    uint64 public constant RAISE_DELAY = 24 hours;

    IOrganizationSBT public immutable orgs;

    mapping(uint256 => mapping(address => mapping(Unit => mapping(Period => Slot)))) private _slots;
    mapping(Unit => mapping(Period => GlobalMax)) private _globalMax;

    event CeilingSet(
        uint256 indexed orgId, address indexed member, Unit unit, Period period, uint128 amount, uint64 effectiveAt
    );
    event CeilingCleared(uint256 indexed orgId, address indexed member, Unit unit, Period period, uint64 effectiveAt);
    event GlobalMaxSet(Unit unit, Period period, uint128 amount);
    event GlobalMaxCleared(Unit unit, Period period);

    error NotOrgHolder();
    error OrgNotActive();
    error AboveGlobalMax(uint128 globalMax);
    error NoCeiling();
    error OrgsHasNoCode();
    error UnitNotForPayment(Unit unit, Payment payment);

    constructor(address governance_, IOrganizationSBT orgs_) Governable(governance_) {
        if (address(orgs_).code.length == 0) revert OrgsHasNoCode();
        orgs = orgs_;
    }

    // ------------------------------------------------------------------ org holder

    /// @param member 0 for the org default, or one member's address.
    function setCeiling(uint256 orgId, address member, Unit unit, Period period, uint128 amount) external {
        _onlyOrgHolder(orgId);
        GlobalMax storage g = _globalMax[unit][period];
        if (g.set && amount > g.amount) revert AboveGlobalMax(g.amount);
        Slot storage s = _slots[orgId][member][unit][period];
        (bool curSet, uint128 cur) = _materialize(s);
        uint64 effectiveAt;
        if (!curSet || amount <= cur) {
            s.set = true;
            s.amount = amount;
            s.effectiveAt = uint64(block.timestamp);
            effectiveAt = uint64(block.timestamp);
        } else {
            if (!orgs.isActive(orgId)) revert OrgNotActive();
            effectiveAt = uint64(block.timestamp) + RAISE_DELAY;
            s.pending = true;
            s.pendingAmount = amount;
            s.pendingAt = effectiveAt;
        }
        emit CeilingSet(orgId, member, unit, period, amount, effectiveAt);
    }

    /// @notice Remove a ceiling. A removal is a raise, so it waits `RAISE_DELAY`.
    function clearCeiling(uint256 orgId, address member, Unit unit, Period period) external {
        _onlyOrgHolder(orgId);
        if (!orgs.isActive(orgId)) revert OrgNotActive();
        Slot storage s = _slots[orgId][member][unit][period];
        (bool curSet,) = _materialize(s);
        if (!curSet) revert NoCeiling();
        uint64 effectiveAt = uint64(block.timestamp) + RAISE_DELAY;
        s.pending = true;
        s.pendingClear = true;
        s.pendingAt = effectiveAt;
        emit CeilingCleared(orgId, member, unit, period, effectiveAt);
    }

    // ------------------------------------------------------------------ governance

    /// @notice Bound every org's effective ceiling for (unit, period). A cap on ceilings only.
    function setGlobalMax(Unit unit, Period period, uint128 amount) external onlyGovernance {
        _globalMax[unit][period] = GlobalMax({set: true, amount: amount});
        emit GlobalMaxSet(unit, period, amount);
    }

    function clearGlobalMax(Unit unit, Period period) external onlyGovernance {
        delete _globalMax[unit][period];
        emit GlobalMaxCleared(unit, period);
    }

    // ------------------------------------------------------------------ reads (core's API)

    /// @notice This slot's own value in effect now (member 0 = the org default).
    function ceilingOf(uint256 orgId, address member, Unit unit, Period period)
        public
        view
        returns (bool set, uint128 amount)
    {
        return _inEffect(_slots[orgId][member][unit][period]);
    }

    /// @notice What core applies for `member`: the minimum of the member's ceiling, the org
    ///         default and the global max, each only when set.
    function effectiveCeilingOf(uint256 orgId, address member, Payment payment, Unit unit, Period period)
        external
        view
        returns (bool set, uint128 amount)
    {
        if (!unitAppliesTo(unit, payment)) revert UnitNotForPayment(unit, payment);
        amount = type(uint128).max;
        bool ms = false;
        uint128 m = 0;
        if (member != address(0)) (ms, m) = ceilingOf(orgId, member, unit, period);
        (bool ds, uint128 d) = ceilingOf(orgId, address(0), unit, period);
        GlobalMax storage g = _globalMax[unit][period];
        if (ms && m < amount) amount = m;
        if (ds && d < amount) amount = d;
        if (g.set && g.amount < amount) amount = g.amount;
        set = ms || ds || g.set;
        if (!set) amount = 0;
    }

    /// @notice Which units bind which spend: SALT_WEI only SALT-paid work; USD and TOKENS only
    ///         vendor-key spend.
    function unitAppliesTo(Unit unit, Payment payment) public pure returns (bool) {
        return payment == Payment.SaltPaid ? unit == Unit.SALT_WEI : unit != Unit.SALT_WEI;
    }

    /// @notice A raise or removal waiting for `RAISE_DELAY`, if any.
    function pendingOf(uint256 orgId, address member, Unit unit, Period period)
        external
        view
        returns (bool pending, bool clears, uint128 amount, uint64 effectiveAt)
    {
        Slot storage s = _slots[orgId][member][unit][period];
        if (!s.pending || block.timestamp >= s.pendingAt) return (false, false, 0, 0);
        return (true, s.pendingClear, s.pendingAmount, s.pendingAt);
    }

    function globalMaxOf(Unit unit, Period period) external view returns (bool set, uint128 amount) {
        GlobalMax storage g = _globalMax[unit][period];
        return (g.set, g.amount);
    }

    /// @notice True when `who` holds the org's OrganizationSBT, the only budget authority.
    function isOrgHolder(uint256 orgId, address who) public view returns (bool) {
        return who != address(0) && who == orgs.ownerOf(orgId);
    }

    // ------------------------------------------------------------------ internals

    function _onlyOrgHolder(uint256 orgId) internal view {
        if (!isOrgHolder(orgId, msg.sender)) revert NotOrgHolder();
    }

    function _inEffect(Slot storage s) internal view returns (bool, uint128) {
        if (s.pending && block.timestamp >= s.pendingAt) {
            return s.pendingClear ? (false, uint128(0)) : (true, s.pendingAmount);
        }
        return (s.set, s.amount);
    }

    /// Fold a matured pending change into the slot and drop an unmatured one; returns the value
    /// in effect now. A new write therefore always cancels a raise that has not landed.
    function _materialize(Slot storage s) internal returns (bool, uint128) {
        (bool set, uint128 amount) = _inEffect(s);
        if (s.pending) {
            if (block.timestamp >= s.pendingAt) {
                s.set = set;
                s.amount = amount;
                s.effectiveAt = s.pendingAt;
            }
            s.pending = false;
            s.pendingClear = false;
            s.pendingAmount = 0;
            s.pendingAt = 0;
        }
        return (set, amount);
    }
}
