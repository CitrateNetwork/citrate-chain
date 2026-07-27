// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ValidatorRegistry} from "../../src/ValidatorRegistry.sol";

/// @title ValidatorRegistryInvariant.t.sol — VALIDATOR-S1 (chain) — campaign track 4/4
/// @notice Handler-driven Foundry invariant suite for ValidatorRegistry, run against the
///         REAL contract (no mocks except the 0x0120 ed25519 precompile, which is replaced
///         with vm.mockCall — the identical stand-in the unit suite uses; ed25519 verify
///         semantics themselves are covered by core/execution/src/precompiles/ed25519.rs and
///         by the targeted BadSig fuzz in ValidatorRegistryFuzz.t.sol with the mock OFF).
///
///   Invariants asserted under arbitrary register/stake/unbond/withdraw/credit/slash/govern
///   call sequences (final WS-5 ctor params: minStake 32000e18, subsidy 1e18, share 5000 bps,
///   maxEpochEmission 10000e18):
///
///   1. SOLVENCY          — Σ(bonded+escrow+vestedRewards) + Σ claimable <= registry ETH balance.
///   2. EMISSION CAP      — emittedInEpoch[e] <= maxEpochEmission for every touched epoch e
///                          (the governance handler deliberately does NOT retune maxEpochEmission,
///                          so the cap in force is constant across the run and the property is exact;
///                          the maxEpochEmission bound is covered separately in the fuzz suite).
///   3. STAKING INTEGRITY — active => bonded>=admissionMinStake, active <=> in-set, pubkeyOfStaker
///                          binds back to the active pubkey (=> one active pubkey per staker).
///   4. ACTIVE SET        — |set| <= MAX_ACTIVE_SET, canonical strict-ascending (=> unique), each
///                          eff <= raw bond, and the 1/3 effective-stake cap holds for n>=3.
///   5. PARAM BOUNDS      — priorityFeeShareBps<=10000, minStake in [FLOOR,CEIL], subsidy<=CEIL,
///                          maxEpochEmission<=CEIL, through arbitrary queue->apply sequences.

/// @dev The handler owns a fixed roster of actors, pranks as them into the real registry, and
///      records ghost state (all registered pubkeys, touched emission epochs) the invariants read.
///      Every entry point is wrapped in try/catch: reverts (dup pubkey, churn cap, emission cap,
///      timelock, ...) are legitimate no-ops and must not abort the sequence.
contract ValidatorRegistryHandler is Test {
    ValidatorRegistry public reg;

    address public gov;
    address public slasher;
    address public minter;

    address[] public actors;
    bytes32 public constant SENTINEL = bytes32(0);

    bytes SIG = new bytes(64); // precompile is mocked; content irrelevant

    // Ghost state read by the invariants.
    bytes32[] public registeredPubkeys;
    mapping(bytes32 => bool) public pubkeyKnown;
    mapping(address => bytes32) public lastPubkeyOfActor; // survives exit (registry clears its map)

    uint256[] public touchedEpochs;
    mapping(uint256 => bool) internal seenEpoch;

    constructor(ValidatorRegistry reg_, address gov_, address slasher_, address minter_) {
        reg = reg_;
        gov = gov_;
        slasher = slasher_;
        minter = minter_;
        for (uint256 i = 0; i < 15; i++) {
            actors.push(address(uint160(0xACC0 + i)));
        }
    }

    receive() external payable {}

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function allPubkeys() external view returns (bytes32[] memory) {
        return registeredPubkeys;
    }

    function allTouchedEpochs() external view returns (uint256[] memory) {
        return touchedEpochs;
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _recordEpoch(uint256 e) internal {
        if (!seenEpoch[e]) {
            seenEpoch[e] = true;
            touchedEpochs.push(e);
        }
    }

    // ── Registration ─────────────────────────────────────────────────────────
    function register(uint256 actorSeed, uint256 pkSeed, uint256 stakeSeed) external {
        address actor = _actor(actorSeed);
        bytes32 pk = keccak256(abi.encode(actor, pkSeed, registeredPubkeys.length));
        if (pk == SENTINEL) pk = bytes32(uint256(1));
        uint256 minS = reg.minStake();
        uint256 stake = bound(stakeSeed, minS, minS + 300_000 ether);
        vm.prank(actor);
        try reg.registerValidator{value: stake}(pk, SIG) {
            if (!pubkeyKnown[pk]) {
                pubkeyKnown[pk] = true;
                registeredPubkeys.push(pk);
            }
            lastPubkeyOfActor[actor] = pk;
        } catch {}
    }

    function increaseStake(uint256 actorSeed, uint256 amtSeed) external {
        address actor = _actor(actorSeed);
        bytes32 pk = lastPubkeyOfActor[actor];
        if (pk == SENTINEL) return;
        uint256 amt = bound(amtSeed, 0, 100_000 ether);
        vm.prank(actor);
        try reg.increaseStake{value: amt}(pk) {} catch {}
    }

    function initiateUnbond(uint256 actorSeed, uint256 amtSeed) external {
        address actor = _actor(actorSeed);
        bytes32 pk = lastPubkeyOfActor[actor];
        if (pk == SENTINEL) return;
        uint256 bonded = reg.stakeOf(pk);
        if (bonded == 0) return;
        uint256 amt = bound(amtSeed, 1, bonded);
        vm.prank(actor);
        try reg.initiateUnbond(pk, amt) {} catch {}
    }

    function withdraw(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        bytes32 pk = lastPubkeyOfActor[actor];
        if (pk == SENTINEL) return;
        vm.prank(actor);
        try reg.withdraw(pk) {} catch {}
    }

    // ── Rewards ──────────────────────────────────────────────────────────────
    function creditReward(uint256 actorSeed, uint256 amtSeed) external {
        address actor = _actor(actorSeed);
        bytes32 pk = lastPubkeyOfActor[actor];
        if (pk == SENTINEL) return;
        uint256 amt = bound(amtSeed, 0, reg.maxEpochEmission());
        vm.prank(minter);
        try reg.creditReward{value: amt}(pk, amt) {
            _recordEpoch(reg.currentEpoch());
        } catch {}
    }

    // ── Slashing ─────────────────────────────────────────────────────────────
    function equivocate(uint256 victimSeed, uint256 reporterSeed, uint64 height) external {
        address victim = _actor(victimSeed);
        bytes32 pk = lastPubkeyOfActor[victim];
        if (pk == SENTINEL) return;
        address reporter = _actor(reporterSeed);
        if (reporter == victim) return;
        vm.prank(reporter);
        try reg.submitEquivocation(pk, height, bytes32(uint256(1)), SIG, bytes32(uint256(2)), SIG) {} catch {}
    }

    function slashTier(uint256 victimSeed, uint8 tierSeed) external {
        address victim = _actor(victimSeed);
        bytes32 pk = lastPubkeyOfActor[victim];
        if (pk == SENTINEL) return;
        ValidatorRegistry.SlashTier tier = ValidatorRegistry.SlashTier(uint8(bound(tierSeed, 0, 2)));
        vm.prank(slasher);
        try reg.slash(pk, tier, "") {} catch {}
    }

    function claimBounty(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        vm.prank(actor);
        try reg.claimBounty() {} catch {}
    }

    // ── Governance ───────────────────────────────────────────────────────────
    // Deliberately excludes maxEpochEmission so the emission cap in force stays constant
    // across the run (keeps invariant #2 exact); the maxEpochEmission bound is fuzzed
    // separately in ValidatorRegistryFuzz.t.sol.
    function _govName(uint256 seed) internal pure returns (bytes32) {
        uint256 k = seed % 3;
        if (k == 0) return keccak256("minStake");
        if (k == 1) return keccak256("blockSubsidy");
        return keccak256("priorityFeeShareBps");
    }

    function queueParam(uint256 nameSeed, uint256 valueSeed) external {
        bytes32 name = _govName(nameSeed);
        uint256 value = bound(valueSeed, 0, 2_000_000 ether); // wide; the contract clamps it
        vm.prank(gov);
        try reg.queueParam(name, value) {} catch {}
    }

    function executeParam(uint256 nameSeed) external {
        bytes32 name = _govName(nameSeed);
        vm.prank(gov);
        try reg.executeParam(name) {} catch {}
    }

    // ── Time ─────────────────────────────────────────────────────────────────
    function advanceTime(uint256 epochsSeed) external {
        uint256 k = bound(epochsSeed, 1, 5);
        vm.roll(block.number + k * reg.EPOCH());
        vm.warp(block.timestamp + reg.GOV_TIMELOCK() + 1); // let queued params mature
    }
}

/// forge-config: default.invariant.runs = 128
/// forge-config: default.invariant.depth = 150
/// forge-config: default.invariant.fail-on-revert = false
contract ValidatorRegistryInvariant is StdInvariant, Test {
    ValidatorRegistry internal reg;
    ValidatorRegistryHandler internal handler;

    address internal gov = address(0x6011);
    address internal slasher = address(0x5142);
    address internal minter = address(0x11d7);

    uint256 internal constant MIN = 32_000 ether;

    function setUp() public {
        reg = new ValidatorRegistry(
            gov,
            slasher,
            minter,
            MIN, // minStake (32000e18)
            1 ether, // blockSubsidy
            5000, // priorityFeeShareBps (50%)
            10_000 ether // maxEpochEmission
        );
        // Real contract; only the 0x0120 ed25519 precompile is stood in (valid=1 for all inputs).
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(1)));
        vm.roll(10_000);

        handler = new ValidatorRegistryHandler(reg, gov, slasher, minter);
        vm.deal(address(handler), 1e15 ether); // funds every forwarded stake/reward/credit

        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = handler.register.selector;
        selectors[1] = handler.increaseStake.selector;
        selectors[2] = handler.initiateUnbond.selector;
        selectors[3] = handler.withdraw.selector;
        selectors[4] = handler.creditReward.selector;
        selectors[5] = handler.equivocate.selector;
        selectors[6] = handler.slashTier.selector;
        selectors[7] = handler.claimBounty.selector;
        selectors[8] = handler.queueParam.selector;
        selectors[9] = handler.executeParam.selector;
        selectors[10] = handler.advanceTime.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    // (1) SOLVENCY — every liability is ETH-backed; withdraw/credit can never make the
    //     registry insolvent. Slash residue (90% of penalty) stays in the contract, so the
    //     bound only ever gains headroom.
    function invariant_Solvency() public view {
        bytes32[] memory pks = handler.allPubkeys();
        uint256 liabilities;
        for (uint256 i = 0; i < pks.length; i++) {
            (, uint256 bonded, uint256 rewards, uint256 escrow,,,,,,) = reg.validatorInfo(pks[i]);
            liabilities += bonded + rewards + escrow;
        }
        uint256 n = handler.actorCount();
        for (uint256 i = 0; i < n; i++) {
            liabilities += reg.claimable(handler.actors(i));
        }
        assertLe(liabilities, address(reg).balance, "registry insolvent: liabilities exceed balance");
    }

    // (2) EMISSION CAP — no epoch ever emits past maxEpochEmission; creditReward past the cap
    //     reverts (EmissionCapped) rather than over-minting.
    function invariant_EmissionCap() public view {
        uint256[] memory eps = handler.allTouchedEpochs();
        uint256 cap = reg.maxEpochEmission();
        for (uint256 i = 0; i < eps.length; i++) {
            assertLe(reg.emittedInEpoch(eps[i]), cap, "epoch emission exceeded cap");
        }
    }

    // (3) STAKING INTEGRITY — no sub-minStake member stays Active; active<=>in-set; the
    //     staker->pubkey binding is consistent (=> at most one Active pubkey per staker).
    function invariant_StakingIntegrity() public view {
        bytes32[] memory pks = handler.allPubkeys();
        for (uint256 i = 0; i < pks.length; i++) {
            (address staker, uint256 bonded,,, uint256 admissionMin,,,, ValidatorRegistry.Status status,) =
                reg.validatorInfo(pks[i]);
            if (status == ValidatorRegistry.Status.Active) {
                assertTrue(reg.isActive(pks[i]), "Active status but not in active set");
                assertGe(bonded, admissionMin, "sub-admission-min validator left Active");
                assertEq(reg.pubkeyOfStaker(staker), pks[i], "staker->pubkey binding broken");
            } else {
                assertFalse(reg.isActive(pks[i]), "non-Active status still isActive()");
            }
        }
    }

    // (4) ACTIVE SET — bounded, canonically ordered/unique, eff<=bond, and the 1/3 cap holds.
    function invariant_ActiveSet() public view {
        (bytes32[] memory pks, uint256[] memory eff) = reg.activeSet();
        assertLe(pks.length, reg.MAX_ACTIVE_SET(), "active set over MAX_ACTIVE_SET");
        assertEq(reg.activeCount(), pks.length, "activeCount disagrees with activeSet length");
        for (uint256 i = 1; i < pks.length; i++) {
            assertTrue(pks[i - 1] < pks[i], "active set not strictly ascending (dup or unsorted)");
        }
        for (uint256 i = 0; i < pks.length; i++) {
            assertLe(eff[i], reg.stakeOf(pks[i]), "effective stake exceeds raw bond");
        }
        if (pks.length >= 3) {
            uint256 total;
            for (uint256 i = 0; i < eff.length; i++) total += eff[i];
            uint256 cap = total / 3;
            for (uint256 i = 0; i < eff.length; i++) {
                assertLe(eff[i], cap + 1, "1/3 effective-stake cap violated"); // +1: integer rounding
            }
        }
    }

    // (5) PARAM BOUNDS — governed params never escape their immutable floors/ceilings.
    function invariant_ParamBounds() public view {
        assertLe(reg.priorityFeeShareBps(), 10000, "priorityFeeShareBps over 100%");
        assertGe(reg.minStake(), reg.MIN_STAKE_FLOOR(), "minStake below floor");
        assertLe(reg.minStake(), reg.MIN_STAKE_CEIL(), "minStake above ceil");
        assertLe(reg.blockSubsidy(), reg.BLOCK_SUBSIDY_CEIL(), "blockSubsidy above ceil");
        assertLe(reg.maxEpochEmission(), reg.MAX_EPOCH_EMISSION_CEIL(), "maxEpochEmission above ceil");
    }
}
