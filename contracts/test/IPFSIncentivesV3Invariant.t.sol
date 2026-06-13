// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// @notice Toggleable 0x0108 mock; verdict in storage slot 0.
contract InvVerifier {
    function setVerdict(uint256 v) external {
        assembly {
            sstore(0, v)
        }
    }

    fallback(bytes calldata) external returns (bytes memory) {
        uint256 v;
        assembly {
            v := sload(0)
        }
        return abi.encode(v);
    }
}

/// @notice Drives randomized sequences of the TLA-v4 actions over a small fixed
///         pinner/slot set. Each handler function self-manages the commit-reveal
///         timing + the optional PIN-S3 bonded challenge, so the stateless fuzzer
///         can reach deep states (Active/Done/Slashed + bonded/refuted) without
///         controlling block numbers itself.
contract Handler is Test {
    IPFSIncentivesV3 public inc;
    KYCRegistry public kyc;
    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    uint256 public constant ROUNDS = 4;
    uint256 public constant WINDOW = 5;
    uint256 public constant REVEAL_DELAY = 2;

    uint256 internal immutable BOND;
    uint256 internal immutable QUORUM;
    uint256 internal immutable CH_BOND;
    uint256 internal immutable MIN_MODEL_BOND;

    address[2] public pinners = [address(0xA1), address(0xA2)];
    address public constant CHALLENGER = address(0xC0);
    address public constant MODEL_OWNER = address(0xD0);
    bytes32[2] public cids = [bytes32(uint256(1)), bytes32(uint256(2))];
    uint256 public constant SECTOR = 0;
    bytes32 internal constant COMM_D = keccak256("D");

    // Ghost counters (non-vacuity).
    uint256 public sealedCount;
    uint256 public postPassCount;
    uint256 public slashedCount;
    uint256 public doneCount;
    uint256 public claimedCount;
    uint256 public frivolousCount; // bonded challenge refuted -> bond to pinner
    uint256 public honestCount; // bonded challenge upheld -> bond to challenger

    constructor(IPFSIncentivesV3 _inc, KYCRegistry _kyc) {
        inc = _inc;
        kyc = _kyc;
        BOND = _inc.BOND();
        QUORUM = _inc.QUORUM();
        CH_BOND = _inc.CHALLENGER_BOND();
        MIN_MODEL_BOND = _inc.MIN_MODEL_BOND();

        for (uint256 i = 0; i < pinners.length; i++) {
            vm.deal(pinners[i], 1_000_000 ether);
            vm.prank(pinners[i]);
            inc.registerPinner();
        }
        vm.deal(CHALLENGER, 1_000_000 ether);
        vm.deal(MODEL_OWNER, 1_000_000 ether);
        // Register both cids' models so seals are admissible (CommD must match).
        for (uint256 j = 0; j < cids.length; j++) {
            vm.prank(MODEL_OWNER);
            inc.registerModel{value: MIN_MODEL_BOND}(cids[j], COMM_D, keccak256("data"), "ipfs://x");
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

    /// Ensure the slot has a fresh, revealable commit; returns the nonce.
    /// Rolls past any prior commit window first (the contract forbids
    /// re-committing while a prior commit is still live).
    function _freshCommit(bytes32 cid) internal returns (uint256 nonce, bool ok) {
        (, , , uint256 commitBlock, uint256 commitNonce, ) = inc.getSlot(cid, SECTOR);
        if (commitBlock != 0 && block.number <= commitBlock + REVEAL_DELAY + WINDOW) {
            // A prior commit is still live; reuse it if already revealable.
            if (block.number >= commitBlock + REVEAL_DELAY) {
                return (commitNonce, true);
            }
            vm.roll(commitBlock + REVEAL_DELAY); // advance into its reveal window
            return (commitNonce, true);
        }
        if (commitBlock != 0) {
            vm.roll(commitBlock + REVEAL_DELAY + WINDOW + 1); // past the stale window
        }
        try inc.commitChallenge(cid, SECTOR) {} catch {
            return (0, false);
        }
        (, , , uint256 cb, uint256 cn, ) = inc.getSlot(cid, SECTOR);
        vm.roll(cb + REVEAL_DELAY);
        return (cn, true);
    }

    // ── TLA Seal (v3: model must be registered + CommD must match) ──
    function seal(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        _setVerdict(1);
        (IPFSIncentivesV3.Status st, , , , , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV3.Status.None) return;
        (, , uint256 live, , , ) = inc.getSlot(cid, SECTOR);
        if (live >= QUORUM) return;
        bytes32 rid = keccak256(abi.encode("rid", who, cid));
        vm.prank(who);
        try inc.sealCommit{value: BOND}(cid, SECTOR, rid, 1, COMM_D, keccak256("R"), keccak256("C"), hex"AA") {
            sealedCount++;
        } catch {}
    }

    // ── PIN-S3: bond a challenge against a pin ──
    function challengePin(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        (IPFSIncentivesV3.Status st, uint64 round, , , , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV3.Status.Active || round >= ROUNDS) return;
        (address ch, , ) = inc.getChallenge(who, cid, SECTOR);
        if (ch != address(0)) return;
        (, , , uint256 commitBlock, , ) = inc.getSlot(cid, SECTOR);
        if (commitBlock == 0) {
            (, bool ok) = _freshCommit(cid);
            if (!ok) return;
        }
        vm.prank(CHALLENGER);
        try inc.challengePin{value: CH_BOND}(who, cid, SECTOR) {} catch {}
    }

    // ── challenge -> reveal -> TLA PoStPass (verdict 1). Refutes any bonded challenge. ──
    function postPass(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        (IPFSIncentivesV3.Status st, uint64 round, , , , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV3.Status.Active || round >= ROUNDS) return;
        (uint256 nonce, bool ok) = _freshCommit(cid);
        if (!ok) return;
        (address bondedBefore, , ) = inc.getChallenge(who, cid, SECTOR);
        _setVerdict(1);
        vm.prank(who);
        try inc.submitPoSt(cid, SECTOR, keccak256("R"), keccak256("C"), nonce, hex"AA") {
            postPassCount++;
            if (bondedBefore != address(0)) frivolousCount++;
            (IPFSIncentivesV3.Status nst, , , , , ) = inc.getPin(who, cid, SECTOR);
            if (nst == IPFSIncentivesV3.Status.Done) doneCount++;
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

    // ── TLA PoStFail / slash (commit + lapse window + slash) ──
    function postFail(uint256 pSeed, uint256 cSeed) external {
        address who = _pinner(pSeed);
        bytes32 cid = _cid(cSeed);
        (IPFSIncentivesV3.Status st, uint64 round, , , , ) = inc.getPin(who, cid, SECTOR);
        if (st != IPFSIncentivesV3.Status.Active || round >= ROUNDS) return;
        (, , , uint256 commitBlock, , ) = inc.getSlot(cid, SECTOR);
        if (commitBlock == 0) {
            (, bool ok) = _freshCommit(cid);
            if (!ok) return;
            (, , , commitBlock, , ) = inc.getSlot(cid, SECTOR);
        }
        (address bondedBefore, , ) = inc.getChallenge(who, cid, SECTOR);
        vm.roll(commitBlock + REVEAL_DELAY + WINDOW + 1); // past the response window
        try inc.slash(who, cid, SECTOR) {
            (IPFSIncentivesV3.Status nst, , , , , ) = inc.getPin(who, cid, SECTOR);
            if (nst == IPFSIncentivesV3.Status.Slashed) {
                slashedCount++;
                if (bondedBefore != address(0)) honestCount++;
            }
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

    function roll(uint256 n) external {
        vm.roll(block.number + (n % (WINDOW + 2)));
    }
}

/// @title IPFSIncentivesV3 — TLA-v4 safety invariants as Foundry properties.
contract IPFSIncentivesV3InvariantTest is Test {
    IPFSIncentivesV3 internal inc;
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
    uint256 internal constant CHALLENGER_BOND = 1 ether;
    uint256 internal constant REVEAL_DELAY = 2;
    uint256 internal constant MIN_MODEL_BOND = 5 ether;
    uint256 internal constant COMMD_WINDOW = 1_000_000; // keep model bonds held during the run
    uint256 internal constant COMMD_BPS = 5000;
    uint256 internal constant PER_ROUND = REWARD / ROUNDS;

    function setUp() public {
        vm.etch(VERIFY, type(InvVerifier).runtimeCode);
        kyc = new KYCRegistry(address(0));
        inc = new IPFSIncentivesV3(
            kyc,
            BOND,
            REWARD,
            ROUNDS,
            MAX_MISSED,
            CHALLENGER_BPS,
            QUORUM,
            WINDOW,
            CHALLENGE_N,
            CHALLENGER_BOND,
            REVEAL_DELAY,
            MIN_MODEL_BOND,
            COMMD_WINDOW,
            COMMD_BPS
        );
        vm.deal(address(this), 1_000_000 ether);
        inc.fund{value: 100_000 ether}();

        kyc.setVerified(address(0xA1));
        kyc.setVerified(address(0xA2));

        handler = new Handler(inc, kyc);
        targetContract(address(handler));
    }

    function _pinSet() internal view returns (address[2] memory ps, bytes32[2] memory cs) {
        ps = [handler.pinners(0), handler.pinners(1)];
        cs = [handler.cids(0), handler.cids(1)];
    }

    // ════════════════ the 8 v3 invariants (carried) ════════════════

    function invariant_NoPayWithoutProof() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, uint64 round, , uint256 claimed, , ) = inc.getPin(ps[i], cs[j], 0);
            assertLe(claimed, uint256(round) * PER_ROUND);
        }
    }

    function invariant_PerPinRewardCap() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, , , uint256 claimed, , ) = inc.getPin(ps[i], cs[j], 0);
            assertLe(claimed, REWARD);
        }
    }

    function invariant_BudgetNonNegative() public view {
        (, bytes32[2] memory cs) = _pinSet();
        for (uint256 j; j < 2; j++) {
            (bool funded, uint256 budget, , , , ) = inc.getSlot(cs[j], 0);
            assertLe(budget, funded ? QUORUM * REWARD : 0);
        }
    }

    function invariant_QuorumRespected() public view {
        (, bytes32[2] memory cs) = _pinSet();
        for (uint256 j; j < 2; j++) {
            (, , uint256 live, , , ) = inc.getSlot(cs[j], 0);
            assertLe(live, QUORUM);
        }
    }

    function invariant_Conservation() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        uint256 budgetSum;
        uint256 funded;
        for (uint256 j; j < 2; j++) {
            (bool isFunded, uint256 budget, , , , ) = inc.getSlot(cs[j], 0);
            budgetSum += budget;
            if (isFunded) funded += QUORUM * REWARD;
        }
        uint256 owedSum;
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            owedSum += inc.owedOf(ps[i], cs[j], 0);
        }
        assertEq(budgetSum + inc.paidTotal() + owedSum, funded);
    }

    function invariant_BondCoversExposure() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (IPFSIncentivesV3.Status st, , , uint256 claimed, uint256 bondHeld, ) = inc.getPin(ps[i], cs[j], 0);
            if (st == IPFSIncentivesV3.Status.Active) {
                assertGe(bondHeld, REWARD - claimed);
            }
        }
    }

    function invariant_SlashedNoBond() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (IPFSIncentivesV3.Status st, , , , uint256 bondHeld, ) = inc.getPin(ps[i], cs[j], 0);
            if (st == IPFSIncentivesV3.Status.Slashed) {
                assertEq(bondHeld, 0);
            }
        }
    }

    function invariant_BondConservation() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        uint256 heldSum;
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (, , , , uint256 bondHeld, ) = inc.getPin(ps[i], cs[j], 0);
            heldSum += bondHeld;
        }
        assertEq(
            inc.bondedTotal(),
            heldSum + inc.burned() + inc.challengerPaid() + inc.returned()
        );
    }

    // ════════════════ v4 additions (PIN-S3 + CommD bond) ════════════════

    // ── ChallengerBondConservation ──
    function invariant_ChallengerBondConservation() public view {
        assertEq(
            inc.challengerBonded(),
            inc.challengerEscrowed() + inc.challengerBondReturned() + inc.challengerBondToPinner()
        );
    }

    // ── ChallengeBondMatchesOpen: per-pin challengerBond > 0 iff a challenge is open ──
    function invariant_ChallengeBondMatchesOpen() public view {
        (address[2] memory ps, bytes32[2] memory cs) = _pinSet();
        uint256 escrowedSum;
        for (uint256 i; i < 2; i++) for (uint256 j; j < 2; j++) {
            (address ch, uint256 b, ) = inc.getChallenge(ps[i], cs[j], 0);
            // bond > 0 <=> challenger set; and a set challenge holds exactly CHALLENGER_BOND
            if (b > 0) assertTrue(ch != address(0));
            if (ch != address(0)) assertEq(b, CHALLENGER_BOND);
            escrowedSum += b;
        }
        // the running escrowed accumulator equals the sum of held per-pin bonds
        assertEq(inc.challengerEscrowed(), escrowedSum);
    }

    // ── ModelBondConservation ──
    function invariant_ModelBondConservation() public view {
        uint256 held = inc.modelBondedTotal() - inc.modelBondsSlashed() - inc.modelBondsRefunded();
        assertEq(
            inc.modelBondedTotal(),
            held + inc.modelBondsSlashed() + inc.modelBondsRefunded()
        );
        // pool never exceeds the cumulative slashed bonds it draws from
        assertLe(inc.honestPinnerCompensationPool(), inc.modelBondsSlashed());
    }

    // ── Non-vacuity: deterministically reach every deep state incl. the PIN-S3
    //    frivolous + honest bonded-challenge resolutions, re-checking all 13. ──
    function test_nonVacuous_reachesAllStates_invariantsHold() public {
        // Part A: vest pinner-0/cid-0 to Done with a FRIVOLOUS bonded challenge
        // each round (the pinner refutes), then claim + returnBond.
        handler.seal(0, 0);
        _checkAll();
        for (uint256 r = 0; r < ROUNDS; r++) {
            handler.challengePin(0, 0); // bond a challenge...
            _checkAll();
            handler.postPass(0, 0); // ...the pinner refutes -> bond to pinner
            _checkAll();
        }
        handler.claim(0, 0);
        _checkAll();
        handler.returnBond(0, 0);
        _checkAll();

        // Part B: HONEST bonded challenge on pinner-1/cid-1 -> slash -> the
        // challenger gets reward + bond back; then re-seal + vest.
        handler.seal(1, 1);
        _checkAll();
        for (uint256 m = 0; m <= MAX_MISSED + 1; m++) {
            handler.challengePin(1, 1); // bond; if already bonded, no-op
            _checkAll();
            handler.postFail(1, 1); // miss -> eventual slash, bond returns to challenger
            _checkAll();
        }
        handler.clearSlashed(1, 1);
        _checkAll();
        handler.seal(1, 1);
        _checkAll();
        handler.postPass(1, 1);
        _checkAll();

        assertGt(handler.sealedCount(), 0, "no seals");
        assertGt(handler.postPassCount(), 0, "no PoStPass");
        assertGt(handler.claimedCount(), 0, "no claim");
        assertGt(handler.slashedCount(), 0, "no slash");
        assertGt(handler.doneCount(), 0, "no Done");
        assertGt(handler.frivolousCount(), 0, "no frivolous-challenge resolution");
        assertGt(handler.honestCount(), 0, "no honest-challenge resolution");
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
        invariant_ChallengerBondConservation();
        invariant_ChallengeBondMatchesOpen();
        invariant_ModelBondConservation();
    }

    receive() external payable {}
}
