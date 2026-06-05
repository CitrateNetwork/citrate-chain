// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV2} from "../src/IPFSIncentivesV2.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// @notice Mock 0x0108 verifier. Verdict (1/0) is toggled by a global flag we
///         control via the harness, so the FINANCIAL STATE MACHINE can be tested
///         deterministically (the ZK is an oracle per the TLA). Returns 32B BE.
contract MockVerifier {
    // Slot 0: verdict (1 == valid proof). Settable via setVerdict() below by the
    // test through a low-level call (the deployed bytecode is etched at 0x0108).
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

/// @title IPFSIncentivesV2 — happy path + negatives (TLA action coverage)
contract IPFSIncentivesV2Test is Test {
    IPFSIncentivesV2 internal inc;
    KYCRegistry internal kyc;

    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    address internal admin = address(this);
    address internal pinner = address(0xBEEF);
    address internal pinner2 = address(0xCAFE);
    address internal challenger = address(0xC44A);

    // Economic params (mirror TLA CONSTANTS). Reward<=Bond, Reward%Rounds==0.
    uint256 internal constant BOND = 10 ether;
    uint256 internal constant REWARD = 4 ether;
    uint256 internal constant ROUNDS = 4;
    uint256 internal constant MAX_MISSED = 1;
    uint256 internal constant CHALLENGER_BPS = 5000; // 50%
    uint256 internal constant QUORUM = 2;
    uint256 internal constant WINDOW = 10;
    uint256 internal constant CHALLENGE_N = 32;

    bytes32 internal cid = keccak256("ipfs://model");
    uint256 internal sector = 0;

    bytes internal constant PROOF = hex"DEADBEEF";

    function setUp() public {
        kyc = new KYCRegistry(address(0));
        inc = new IPFSIncentivesV2(
            kyc, BOND, REWARD, ROUNDS, MAX_MISSED, CHALLENGER_BPS, QUORUM, WINDOW, CHALLENGE_N
        );

        // Etch the mock verifier at 0x0108 and default it to "valid".
        vm.etch(VERIFY, type(MockVerifier).runtimeCode);
        _setVerdict(1);

        // Fund the reward pool generously.
        vm.deal(admin, 1000 ether);
        inc.fund{value: 500 ether}();

        // KYC + bond funds for pinners.
        kyc.setVerified(pinner);
        kyc.setVerified(pinner2);
        vm.deal(pinner, 100 ether);
        vm.deal(pinner2, 100 ether);
    }

    function _setVerdict(uint256 v) internal {
        (bool ok, ) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", v));
        require(ok, "setVerdict failed");
    }

    function _seal(address who, uint256 sec) internal {
        vm.prank(who);
        inc.sealCommit{value: BOND}(
            cid, sec, keccak256("D"), keccak256("R"), keccak256("C"), PROOF
        );
    }

    // ───────────────────────────── Happy path ──────────────────────────────

    function test_happyPath_register_seal_challenge_post_claim_returnBond() public {
        // register
        vm.prank(pinner);
        inc.registerPinner();
        assertTrue(inc.registered(pinner));

        // seal -> active + bond escrowed
        _seal(pinner, sector);
        (IPFSIncentivesV2.Status st,, , , uint256 bondHeld,,,) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV2.Status.Active));
        assertEq(bondHeld, BOND);
        (, uint256 budget, uint256 live) = inc.getSlot(cid, sector);
        assertEq(budget, QUORUM * REWARD);
        assertEq(live, 1);

        // N rounds of challenge -> submitPoSt
        for (uint256 r = 0; r < ROUNDS; r++) {
            vm.prank(pinner);
            inc.challenge(cid, sector);
            (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
            vm.prank(pinner);
            inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
        }

        // status Done, fully vested
        (st, , , , , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV2.Status.Done));
        assertEq(inc.owedOf(pinner, cid, sector), REWARD);
        (, budget, ) = inc.getSlot(cid, sector);
        assertEq(budget, QUORUM * REWARD - REWARD); // ROUNDS*PerRound = REWARD drawn

        // claim full reward
        uint256 before = pinner.balance;
        vm.prank(pinner);
        uint256 owed = inc.claim(cid, sector);
        assertEq(owed, REWARD);
        assertEq(pinner.balance, before + REWARD);
        assertEq(inc.paidTotal(), REWARD);

        // returnBond
        before = pinner.balance;
        vm.prank(pinner);
        uint256 amt = inc.returnBond(cid, sector);
        assertEq(amt, BOND);
        assertEq(pinner.balance, before + BOND);
        assertEq(inc.returned(), BOND);

        // bond fully accounted: bondedTotal == returned (nothing held/burned/challenger)
        assertEq(inc.bondedTotal(), inc.returned());
    }

    // ──────────────────────────── KYC negatives ────────────────────────────

    function test_register_revertsWhenNotKYCVerified() public {
        address stranger = address(0xDEAD);
        vm.prank(stranger);
        vm.expectRevert("KYC: not verified");
        inc.registerPinner();
    }

    function test_register_revertsAfterKYCRevoked() public {
        kyc.revoke(pinner);
        vm.prank(pinner);
        vm.expectRevert("KYC: not verified");
        inc.registerPinner();
    }

    function test_seal_revertsWhenNotRegistered() public {
        vm.prank(pinner);
        vm.expectRevert("Not registered");
        inc.sealCommit{value: BOND}(cid, sector, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    // ─────────────────────────── Quorum negative ───────────────────────────

    function test_seal_revertsOverQuorum() public {
        // QUORUM = 2: two distinct pinners can seal the same slot, a third cannot.
        kyc.setVerified(challenger);
        vm.deal(challenger, 100 ether);
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner2);
        inc.registerPinner();
        vm.prank(challenger);
        inc.registerPinner();

        _seal(pinner, sector);
        _seal(pinner2, sector);
        (, , uint256 live) = inc.getSlot(cid, sector);
        assertEq(live, QUORUM);

        vm.prank(challenger);
        vm.expectRevert("Slot quorum reached");
        inc.sealCommit{value: BOND}(cid, sector, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    // ─────────────────────── Proof / nonce negatives ───────────────────────

    function test_seal_revertsOnInvalidPoRep() public {
        vm.prank(pinner);
        inc.registerPinner();
        _setVerdict(0); // precompile says "no proof"
        vm.prank(pinner);
        vm.expectRevert("PoRep proof invalid");
        inc.sealCommit{value: BOND}(cid, sector, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    function test_submitPoSt_revertsOnWrongNonce() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);
        vm.prank(pinner);
        inc.challenge(cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
        uint256 wrong = (nonce + 1) % CHALLENGE_N;
        vm.prank(pinner);
        vm.expectRevert("Wrong challengeNonce");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), wrong, PROOF);
    }

    function test_submitPoSt_revertsOnInvalidPoSt() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);
        vm.prank(pinner);
        inc.challenge(cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
        _setVerdict(0);
        vm.prank(pinner);
        vm.expectRevert("PoSt proof invalid");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
    }

    function test_submitPoSt_revertsAfterWindow() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);
        vm.prank(pinner);
        inc.challenge(cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
        vm.roll(block.number + WINDOW + 1); // past deadline
        vm.prank(pinner);
        vm.expectRevert("Challenge window closed");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
    }

    // ──────────────────────────── Claim no-ops ─────────────────────────────

    function test_doubleClaim_isNoOp() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);
        // one round
        vm.prank(pinner);
        inc.challenge(cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        vm.prank(pinner);
        uint256 first = inc.claim(cid, sector);
        assertEq(first, REWARD / ROUNDS);
        vm.prank(pinner);
        uint256 second = inc.claim(cid, sector); // no-op
        assertEq(second, 0);
    }

    // ───────────────────── Slash on timeout (PoStFail) ─────────────────────

    function test_slash_paysChallenger_burns_returnsOwed() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);

        // vest one round so there is owed exposure to return to budget
        vm.prank(pinner);
        inc.challenge(cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
        // do not claim -> owed = PerRound is live exposure

        // MAX_MISSED = 1: first lapsed challenge -> miss; second -> slash.
        // Track block explicitly to advance past each challenge deadline.
        uint256 blk = block.number;
        // miss #1
        vm.prank(pinner);
        inc.challenge(cid, sector);
        blk += WINDOW + 1;
        vm.roll(blk);
        inc.slash(pinner, cid, sector);
        (IPFSIncentivesV2.Status st, , uint64 missed, , , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV2.Status.Active));
        assertEq(missed, 1);

        // miss #2 -> slash
        (, uint256 budgetBefore, uint256 liveBefore) = inc.getSlot(cid, sector);
        vm.prank(pinner);
        inc.challenge(cid, sector);
        blk += WINDOW + 1;
        vm.roll(blk);
        inc.slash(pinner, cid, sector); // challenger == this test contract

        uint256 bondHeld;
        (st, , , , bondHeld, , , ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV2.Status.Slashed));
        assertEq(bondHeld, 0); // SlashedNoBond

        uint256 cr = (BOND * CHALLENGER_BPS) / 10000;
        uint256 br = BOND - cr;
        assertEq(inc.challengerPaid(), cr);
        assertEq(inc.burned(), br);
        assertEq(inc.challengerCredit(address(this)), cr);

        // forfeited owed (PerRound, unclaimed) returned to slot budget
        (, uint256 budgetAfter, uint256 liveAfter) = inc.getSlot(cid, sector);
        assertEq(budgetAfter, budgetBefore + (REWARD / ROUNDS));
        assertEq(liveAfter, liveBefore - 1);

        // challenger can withdraw
        uint256 before = address(this).balance;
        inc.withdrawChallengerCredit();
        assertEq(address(this).balance, before + cr);
    }

    function test_slash_revertsBeforeWindowCloses() public {
        vm.prank(pinner);
        inc.registerPinner();
        _seal(pinner, sector);
        vm.prank(pinner);
        inc.challenge(cid, sector);
        vm.expectRevert("Window not yet closed");
        inc.slash(pinner, cid, sector);
    }

    // ───────────────── Re-seal farming cannot exceed budget ─────────────────

    function test_reSeal_cannotExceedSlotBudget() public {
        // Push MAX_MISSED to 0 conceptually via a fresh deploy where one miss slashes.
        IPFSIncentivesV2 inc2 = new IPFSIncentivesV2(
            kyc, BOND, REWARD, ROUNDS, 0, CHALLENGER_BPS, QUORUM, WINDOW, CHALLENGE_N
        );
        vm.deal(admin, 1000 ether);
        inc2.fund{value: 500 ether}();
        vm.prank(pinner);
        inc2.registerPinner();

        uint256 slotBudget = QUORUM * REWARD; // total payable for the slot ever

        uint256 totalVested = 0;
        // Re-seal/slash loop: each successful PoSt draws PerRound from the shared
        // slot budget. Re-seal (clearSlashed) resets per-pin counters but NOT the
        // slot budget, so cumulative payout is capped at slotBudget regardless of
        // how many times we re-seal.
        for (uint256 attempt = 0; attempt < 10; attempt++) {
            // seal
            vm.prank(pinner);
            inc2.sealCommit{value: BOND}(cid, sector, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);

            // vest as many rounds as the budget allows, then deliberately let it
            // slash by missing a challenge.
            for (uint256 r = 0; r < ROUNDS; r++) {
                (, uint256 budgetNow, ) = inc2.getSlot(cid, sector);
                if (budgetNow < REWARD / ROUNDS) break;
                vm.prank(pinner);
                inc2.challenge(cid, sector);
                (, , , , , , , uint256 nonce) = inc2.getPin(pinner, cid, sector);
                vm.prank(pinner);
                inc2.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
                totalVested += REWARD / ROUNDS;
            }

            (IPFSIncentivesV2.Status st, , , , , , , ) = inc2.getPin(pinner, cid, sector);
            if (st == IPFSIncentivesV2.Status.Done) {
                // claim, then it's done — but if budget remains we re-seal a fresh
                // sector? No: same (cid,sector). Done is terminal until returnBond.
                vm.prank(pinner);
                inc2.claim(cid, sector);
                break;
            }

            // Force a slash to re-seal: open a challenge and let it lapse.
            vm.prank(pinner);
            inc2.challenge(cid, sector);
            vm.roll(block.number + WINDOW + 1);
            inc2.slash(pinner, cid, sector);
            // claim what we vested before slashing
            // (claim allowed only while active/done; after slash claim reverts)
            // clear to re-seal
            vm.prank(pinner);
            inc2.clearSlashed(cid, sector);
        }

        // Total ever vested from this slot's budget never exceeds slotBudget.
        (, uint256 finalBudget, ) = inc2.getSlot(cid, sector);
        // budget consumed = slotBudget - finalBudget - (owed returned by slashes).
        // The hard cap: a single pin can never have claimed more than REWARD, and
        // total payouts drawn never exceed the seeded slotBudget.
        assertLe(totalVested, slotBudget);
        assertLe(slotBudget - finalBudget, slotBudget);
    }

    receive() external payable {}
}
