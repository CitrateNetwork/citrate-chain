// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV2} from "../src/IPFSIncentivesV2.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// @notice Toggleable 0x0108 mock; verdict in storage slot 0.
contract InvVerifier {
    function setVerdict(uint256 v) external {
        assembly { sstore(0, v) }
    }
    fallback(bytes calldata) external returns (bytes memory) {
        uint256 v;
        assembly { v := sload(0) }
        return abi.encode(v);
    }
}

/// @notice Handler that drives randomized sequences of the TLA actions across a
///         fixed small set of pinners/slots, mirroring the spec's `Next` choice.
///         Forge fuzzes the public functions; each maps to one TLA action.
contract Handler is Test {
    IPFSIncentivesV2 public inc;
    KYCRegistry public kyc;
    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    uint256 public constant ROUNDS = 4;
    uint256 public constant WINDOW = 5;

    // Cached so we never make an external call AFTER vm.prank (which would consume
    // the prank and send the tx as the handler, not the pinner).
    uint256 internal immutable BOND;
    uint256 internal immutable QUORUM;

    // Tiny instance (matches the kept-small TLA model): 2 pinners x 2 cids x 1 sector.
    address[2] public pinners = [address(0xA1), address(0xA2)];
    bytes32[2] public cids = [bytes32(uint256(1)), bytes32(uint256(2))];
    uint256 public constant SECTOR = 0;

    // Ghost counters proving the fuzz is non-vacuous (reaches deep states).
    uint256 public sealedCount;
    uint256 public postPassCount;
    uint256 public slashedCount;
    uint256 public doneCount;
    uint256 public claimedCount;

    constructor(IPFSIncentivesV2 _inc, KYCRegistry _kyc) {
        inc = _inc;
        kyc = _kyc;
        BOND = _inc.BOND();
        QUORUM = _inc.QUORUM();
        // KYC verification is performed by the test (which holds KYC_UPDATER_ROLE)
        // before this handler is constructed; here we register + fund the pinners.
        // Under vm.prank, msg.value is charged to the pranked address, so the
        // pinners (not the handler) must hold the bond ETH.
        for (uint256 i = 0; i < pinners.length; i++) {
            vm.deal(pinners[i], 1_000_000 ether);
            vm.prank(pinners[i]);
            inc.registerPinner();
        }
    }

    receive() external payable {}

    function _pinner(uint256 s) internal view returns (address) {
        return pinners[s % pinners.length];
    }
    function _cid(uint256 s) internal view returns (bytes32) {
        return cids[s % cids.length];
    }

    function _setVerdict(uint256 v) internal {
        (bool ok, ) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", v));
        require(ok);
    }

    // ── TLA Seal ──
    function seal(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        _setVerdict(1);
        (IPFSIncentivesV2.Status st, , , , , , , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV2.Status.None) return;
        (, , uint256 live) = inc.getSlot(cid, SECTOR);
        if (live >= QUORUM) return;
        vm.prank(who);
        try inc.sealCommit{value: BOND}(cid, SECTOR, keccak256("D"), keccak256("R"), keccak256("C"), hex"AA") {
            sealedCount++;
        } catch {}
    }

    // ── challenge then TLA PoStPass (verdict 1) ──
    function postPass(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        (IPFSIncentivesV2.Status st, uint64 round, , , , bool open, , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV2.Status.Active || round >= ROUNDS) return;
        if (!open) {
            vm.prank(who);
            try inc.challenge(cid, SECTOR) {} catch { return; }
        }
        (, , , , , , , uint256 nonce) = inc.getPin(who, cid, SECTOR);
        _setVerdict(1);
        vm.prank(who);
        try inc.submitPoSt(cid, SECTOR, keccak256("R"), keccak256("C"), nonce, hex"AA") {
            postPassCount++;
            (IPFSIncentivesV2.Status nst, , , , , , , ) = inc.getPin(who, cid, SECTOR);
            if (nst == IPFSIncentivesV2.Status.Done) doneCount++;
        } catch {}
    }

    // ── TLA Claim ──
    function claim(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        vm.prank(who);
        try inc.claim(cid, SECTOR) returns (uint256 owed) {
            if (owed > 0) claimedCount++;
        } catch {}
    }

    // ── TLA PoStFail / slash (open + lapse + slash) ──
    function postFail(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        (IPFSIncentivesV2.Status st, uint64 round, , , , bool open, , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV2.Status.Active || round >= ROUNDS) return;
        if (!open) {
            vm.prank(who);
            try inc.challenge(cid, SECTOR) {} catch { return; }
        }
        vm.roll(block.number + WINDOW + 1);
        try inc.slash(who, cid, SECTOR) {
            (IPFSIncentivesV2.Status nst, , , , , , , ) = inc.getPin(who, cid, SECTOR);
            if (nst == IPFSIncentivesV2.Status.Slashed) slashedCount++;
        } catch {}
    }

    // ── TLA ClearSlashed ──
    function clearSlashed(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        vm.prank(who);
        try inc.clearSlashed(cid, SECTOR) {} catch {}
    }

    // ── TLA ReturnBond ──
    function returnBond(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        vm.prank(who);
        try inc.returnBond(cid, SECTOR) {} catch {}
    }

    // Advance blocks so challenge windows can pass naturally.
    function roll(uint256 n) external {
        vm.roll(block.number + (n % (WINDOW + 2)));
    }
}

/// @title IPFSIncentivesV2 — TLA safety invariants as Foundry invariant properties
contract IPFSIncentivesV2InvariantTest is Test {
    IPFSIncentivesV2 internal inc;
    KYCRegistry internal kyc;
    Handler internal handler;
    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    uint256 internal constant BOND = 10 ether;
    uint256 internal constant REWARD = 4 ether;
    uint256 internal constant ROUNDS = 4;
    uint256 internal constant MAX_MISSED = 1;
    uint256 internal constant CHALLENGER_BPS = 5000;
    uint256 internal constant QUORUM = 2;
    uint256 internal constant WINDOW = 5;
    uint256 internal constant CHALLENGE_N = 16;
    uint256 internal constant PER_ROUND = REWARD / ROUNDS;

    function setUp() public {
        vm.etch(VERIFY, type(InvVerifier).runtimeCode);
        kyc = new KYCRegistry(address(0));
        inc = new IPFSIncentivesV2(
            kyc, BOND, REWARD, ROUNDS, MAX_MISSED, CHALLENGER_BPS, QUORUM, WINDOW, CHALLENGE_N
        );
        vm.deal(address(this), 1_000_000 ether);
        inc.fund{value: 100_000 ether}();

        // KYC-verify the two handler pinners up front (test holds KYC_UPDATER_ROLE),
        // so the handler's constructor can register them.
        kyc.setVerified(address(0xA1));
        kyc.setVerified(address(0xA2));

        handler = new Handler(inc, kyc);
        targetContract(address(handler));
    }

    // The enumerated set the TLA quantifies over (2 pinners x 2 cids x 1 sector).
    function _pinSet() internal view returns (address[2] memory ps, bytes32[2] memory cs) {
        ps = [handler.pinners(0), handler.pinners(1)];
        cs = [handler.cids(0), handler.cids(1)];
    }

    // ── NoPayWithoutProof: claimed <= round*PerRound for every pin ──
    function invariant_NoPayWithoutProof() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, uint64 round, , uint256 claimed, , , , ) = inc.getPin(ps[i], cs[j], 0);
            assertLe(claimed, uint256(round) * PER_ROUND);
        }
    }

    // ── PerPinRewardCap: claimed <= Reward ──
    function invariant_PerPinRewardCap() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, , , uint256 claimed, , , , ) = inc.getPin(ps[i], cs[j], 0);
            assertLe(claimed, REWARD);
        }
    }

    // ── BudgetNonNegative: every slot budget >= 0 (unsigned can't go negative;
    //    assert it never underflowed past the funded ceiling either) ──
    function invariant_BudgetNonNegative() public view {
        (, bytes32[2] memory cs) = _pinSet();
        for (uint256 j; j < 2; j++) {
            (bool funded, uint256 budget, ) = inc.getSlot(cs[j], 0);
            // budget never exceeds the funded ceiling (it would on a conservation bug)
            assertLe(budget, funded ? QUORUM * REWARD : 0);
        }
    }

    // ── QuorumRespected: live pins per slot <= Quorum ──
    function invariant_QuorumRespected() public view {
        (, bytes32[2] memory cs) = _pinSet();
        for (uint256 j; j < 2; j++) {
            (, , uint256 live) = inc.getSlot(cs[j], 0);
            assertLe(live, QUORUM);
        }
    }

    // ── Conservation: sum(budget) + paidTotal + sum(owed) == Funded(touched slots) ──
    function invariant_Conservation() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        uint256 budgetSum;
        uint256 funded;
        for (uint256 j; j < 2; j++) {
            (bool isFunded, uint256 budget, ) = inc.getSlot(cs[j], 0);
            budgetSum += budget;
            if (isFunded) funded += QUORUM * REWARD;
        }
        uint256 owedSum;
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            owedSum += inc.owedOf(ps[i], cs[j], 0);
        }
        assertEq(budgetSum + inc.paidTotal() + owedSum, funded);
    }

    // ── BondCoversExposure: active => bondHeld >= Reward - claimed ──
    function invariant_BondCoversExposure() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (IPFSIncentivesV2.Status st, , , uint256 claimed, uint256 bondHeld, , , ) = inc.getPin(ps[i], cs[j], 0);
            if (st == IPFSIncentivesV2.Status.Active) {
                assertGe(bondHeld, REWARD - claimed);
            }
        }
    }

    // ── SlashedNoBond: slashed => bondHeld == 0 ──
    function invariant_SlashedNoBond() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (IPFSIncentivesV2.Status st, , , , uint256 bondHeld, , , ) = inc.getPin(ps[i], cs[j], 0);
            if (st == IPFSIncentivesV2.Status.Slashed) {
                assertEq(bondHeld, 0);
            }
        }
    }

    // ── BondConservation: bondedTotal == sum(bondHeld) + burned + challengerPaid + returned ──
    function invariant_BondConservation() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        uint256 heldSum;
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, , , , uint256 bondHeld, , , ) = inc.getPin(ps[i], cs[j], 0);
            heldSum += bondHeld;
        }
        assertEq(
            inc.bondedTotal(),
            heldSum + inc.burned() + inc.challengerPaid() + inc.returned()
        );
    }

    // ── Non-vacuity proof: deterministically drive the handler through enough
    //    actions to reach EVERY deep TLA state (Seal, PoStPass, Claim, slash->
    //    Slashed, Done), re-checking all 8 safety invariants after each call.
    //    This guarantees the invariants above are not trivially satisfied by a
    //    fuzz that never leaves the initial state. ──
    function test_nonVacuous_reachesAllStates_invariantsHold() public {
        // Part A: drive pinner-0/cid-0 to full vest (Done) + claim + returnBond.
        handler.seal(0, 0);
        _checkAll();
        for (uint256 r = 0; r < ROUNDS; r++) {
            handler.postPass(0, 0);
            _checkAll();
        }
        handler.claim(0, 0);
        _checkAll();
        handler.returnBond(0, 0);
        _checkAll();

        // Part B: drive pinner-1/cid-1 to SLASH via MAX_MISSED+1 consecutive
        // un-answered challenges (no intervening PoStPass to reset `missed`),
        // then re-seal it (ClearSlashed) and vest again from the same slot budget.
        handler.seal(1, 1);
        _checkAll();
        for (uint256 m = 0; m <= MAX_MISSED + 1; m++) {
            handler.postFail(1, 1); // open+lapse -> miss; final one slashes
            _checkAll();
        }
        handler.clearSlashed(1, 1); // re-seal prep
        _checkAll();
        handler.seal(1, 1);         // re-seal
        _checkAll();
        handler.postPass(1, 1);
        _checkAll();
        handler.claim(1, 1);
        _checkAll();
        // Deep states reached at least once.
        assertGt(handler.sealedCount(), 0, "no seals");
        assertGt(handler.postPassCount(), 0, "no PoStPass");
        assertGt(handler.claimedCount(), 0, "no successful claim");
        assertGt(handler.slashedCount(), 0, "no slash->Slashed");
        assertGt(handler.doneCount(), 0, "no Done");
    }

    function _checkAll() internal view {
        invariant_NoPayWithoutProof();
        invariant_PerPinRewardCap();
        invariant_BudgetNonNegative();
        invariant_QuorumRespected();
        invariant_Conservation();
        invariant_BondCoversExposure();
        invariant_SlashedNoBond();
        invariant_BondConservation();
    }

    receive() external payable {}
}
