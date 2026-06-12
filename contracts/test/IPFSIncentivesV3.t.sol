// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// @notice RED tests for IPFSIncentivesV3 (PIN-CR-S1) — written BEFORE the
///         contract per the red-test-first protocol. They pin the guarantees of
///         the three ADR-2026-06-07 mechanisms, formalized in
///         `formal/PINIncentiveV4.tla`:
///           1. commit-reveal challenge (grind-resistance) — the nonce is fixed
///              at COMMIT; a PoSt before `commitBlock + REVEAL_DELAY` reverts;
///           2. PIN-S3 third-party challenger bond — an answered (frivolous)
///              challenge forfeits the challenger's bond to the pinner; a missed
///              (honest) one returns it AND pays the challenger from the slash;
///           3. CommD registrant bond — a proven wrong-root challenge slashes
///              the model-owner bond (split challenger reward + honest-pinner
///              pool); an unchallenged bond is reclaimable after the window.
///
///         Until IPFSIncentivesV3.sol exists, this suite fails to COMPILE — the
///         reddest possible state. The implementation makes it green.
///
/// @dev The ZK proof is an oracle (TLA): a MockVerifier etched at 0x0108 returns
///      a settable verdict, so the FINANCIAL state machine is tested
///      deterministically (mirrors the v2 suite).
contract MockVerifier {
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

contract IPFSIncentivesV3Test is Test {
    IPFSIncentivesV3 internal inc;
    KYCRegistry internal kyc;

    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;

    address internal admin = address(this);
    address internal pinner = address(0xBEEF);
    address internal pinner2 = address(0xCAFE);
    address internal challenger = address(0xC44A);
    address internal modelOwner = address(0x310D);

    // PIN money params (mirror v2 / TLA CONSTANTS; Reward<=Bond, Reward%Rounds==0).
    uint256 internal constant BOND = 10 ether;
    uint256 internal constant REWARD = 4 ether;
    uint256 internal constant ROUNDS = 4;
    uint256 internal constant MAX_MISSED = 0; // one missed window slashes
    uint256 internal constant CHALLENGER_BPS = 5000; // 50% of a slashed pin bond
    uint256 internal constant QUORUM = 2;
    uint256 internal constant WINDOW = 10; // response window (blocks) after reveal
    uint256 internal constant CHALLENGE_N = 32;

    // V3 new params.
    uint256 internal constant CHALLENGER_BOND = 1 ether; // PIN-S3 challenger escrow
    uint256 internal constant REVEAL_DELAY = 32; // commit→reveal gap (blocks)
    uint256 internal constant MIN_MODEL_BOND = 5 ether; // CommD registrant floor
    uint256 internal constant MODEL_CHALLENGE_WINDOW = 100; // wrong-root window (blocks)
    uint256 internal constant MODEL_CHALLENGER_BPS = 5000; // 50/50 challenger/pool

    bytes32 internal cid = keccak256("ipfs://model");
    uint256 internal sector = 0;
    bytes internal constant PROOF = hex"DEADBEEF";

    function setUp() public {
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
            MODEL_CHALLENGE_WINDOW,
            MODEL_CHALLENGER_BPS
        );

        vm.etch(VERIFY, type(MockVerifier).runtimeCode);
        _setVerdict(1);

        vm.deal(admin, 10_000 ether);
        inc.fund{value: 5_000 ether}();

        kyc.setVerified(pinner);
        kyc.setVerified(pinner2);
        vm.deal(pinner, 1_000 ether);
        vm.deal(pinner2, 1_000 ether);
        vm.deal(challenger, 1_000 ether);
        vm.deal(modelOwner, 1_000 ether);
    }

    function _setVerdict(uint256 v) internal {
        (bool ok, ) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", v));
        require(ok, "setVerdict failed");
    }

    function _registerAndSeal(address who) internal {
        vm.prank(who);
        inc.registerPinner();
        vm.prank(who);
        inc.sealCommit{value: BOND}(cid, sector, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    /// Open a challenge as `who` (a third-party challenger posts CHALLENGER_BOND),
    /// advance past the reveal delay, return the committed nonce.
    function _commitAndReveal(address who) internal returns (uint256 nonce) {
        vm.prank(who);
        inc.commitChallenge{value: CHALLENGER_BOND}(pinner, cid, sector);
        (, , , , , , , nonce) = inc.getPin(pinner, cid, sector);
        vm.roll(block.number + REVEAL_DELAY); // now revealable
    }

    // ════════════════════ 1. commit-reveal grind-resistance ════════════════════

    function test_commitReveal_submitBeforeRevealDelay_reverts() public {
        _registerAndSeal(pinner);
        vm.prank(challenger);
        inc.commitChallenge{value: CHALLENGER_BOND}(pinner, cid, sector);
        (, , , , , , , uint256 nonce) = inc.getPin(pinner, cid, sector);

        // Same block as commit (and any block < commitBlock + REVEAL_DELAY) must
        // reject — the pinner can't reveal early, defeating commit-block grinding.
        vm.prank(pinner);
        vm.expectRevert("Reveal too early");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        vm.roll(block.number + REVEAL_DELAY - 1); // still one short
        vm.prank(pinner);
        vm.expectRevert("Reveal too early");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
    }

    function test_commitReveal_nonceFixedAtCommit_notReveal() public {
        _registerAndSeal(pinner);
        vm.prevrandao(bytes32(uint256(0xA11CE))); // beacon at commit
        vm.prank(challenger);
        inc.commitChallenge{value: CHALLENGER_BOND}(pinner, cid, sector);
        (, , , , , , , uint256 committedNonce) = inc.getPin(pinner, cid, sector);

        // Change the beacon at reveal time: the required nonce MUST be unchanged
        // (it was committed) — this is the anti-grind property.
        vm.roll(block.number + REVEAL_DELAY);
        vm.prevrandao(bytes32(uint256(0xBEEF))); // different beacon at reveal
        (, , , , , , , uint256 nonceAtReveal) = inc.getPin(pinner, cid, sector);
        assertEq(nonceAtReveal, committedNonce, "nonce must be fixed at commit");

        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), committedNonce, PROOF);
        (, uint64 round, , , , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(round, 1, "valid reveal vests one round");
    }

    function test_commitReveal_happyPath_vests() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commitAndReveal(challenger);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
        (, uint64 round, , , , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(round, 1);
    }

    // ════════════════════ 2. PIN-S3 challenger bond economics ═══════════════════

    function test_commitChallenge_requiresExactChallengerBond() public {
        _registerAndSeal(pinner);
        vm.prank(challenger);
        vm.expectRevert("Must post exact challenger bond");
        inc.commitChallenge{value: CHALLENGER_BOND - 1}(pinner, cid, sector);
    }

    /// Frivolous challenge: the challenger opens against a pinner who IS storing;
    /// the pinner proves possession → the challenger's bond is forfeit to the
    /// pinner (TLA `PoStPass`: challengerBondToPinner += chBond).
    function test_frivolousChallenge_bondForfeitToPinner() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commitAndReveal(challenger);

        uint256 pinnerCreditBefore = inc.challengerCredit(pinner);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        // The challenger's escrow is credited to the pinner (pull-payment).
        assertEq(
            inc.challengerCredit(pinner),
            pinnerCreditBefore + CHALLENGER_BOND,
            "frivolous challenge bond goes to the pinner"
        );
        // The challenger gets nothing back.
        assertEq(inc.challengerCredit(challenger), 0);
    }

    /// Honest challenge: the challenger opens against a pinner who is NOT storing;
    /// the pinner misses → slash. The challenger earns the reward share of the
    /// slashed PIN bond AND gets their own challenger bond back (TLA `PoStFail`).
    function test_honestChallenge_paysFromSlash_andReturnsBond() public {
        _registerAndSeal(pinner);
        vm.prank(challenger);
        inc.commitChallenge{value: CHALLENGER_BOND}(pinner, cid, sector);

        // Pinner never reveals; advance past reveal delay + response window.
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1);
        vm.prank(challenger);
        inc.slash(pinner, cid, sector);

        (IPFSIncentivesV3.Status st, , , , uint256 bondHeld, , , ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Slashed));
        assertEq(bondHeld, 0); // SlashedNoBond

        uint256 cr = (BOND * CHALLENGER_BPS) / 10000;
        // Reward-from-slash + the returned challenger bond are both credited.
        assertEq(
            inc.challengerCredit(challenger),
            cr + CHALLENGER_BOND,
            "honest challenge: slash reward + own bond back"
        );
    }

    function test_slash_revertsBeforeWindowCloses() public {
        _registerAndSeal(pinner);
        vm.prank(challenger);
        inc.commitChallenge{value: CHALLENGER_BOND}(pinner, cid, sector);
        vm.roll(block.number + REVEAL_DELAY + 1); // revealable but window open
        vm.expectRevert("Window not yet closed");
        inc.slash(pinner, cid, sector);
    }

    // ════════════════════════ 3. CommD registrant bond ══════════════════════════

    function test_registerModel_requiresMinBond() public {
        vm.prank(modelOwner);
        vm.expectRevert("Model bond too low");
        inc.registerModel{value: MIN_MODEL_BOND - 1}(cid, keccak256("commD"));
    }

    function test_registerModel_revertsOnDoubleRegister() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"));
        vm.prank(modelOwner);
        vm.expectRevert("Already registered");
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD2"));
    }

    /// A proven wrong-CommD challenge slashes the registrant bond, splitting it
    /// into the challenger reward and the honest-pinner compensation pool (TLA
    /// `ChallengeWrongCommD`: modelSlashedChallenger += cr; pinnerPool += pr).
    function test_challengeWrongCommD_slashesAndSplits() public {
        bytes32 registered = keccak256("WRONG_commD");
        bytes32 truth = keccak256("TRUE_commD");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, registered);

        uint256 poolBefore = inc.pinnerPool();
        // The challenger proves the registered root differs from the canonical
        // one (option-B witness; the implementation verifies the Merkle path —
        // here the mock-friendly form: a directly-provided true root != registered).
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, truth);

        uint256 cr = (MIN_MODEL_BOND * MODEL_CHALLENGER_BPS) / 10000;
        uint256 pr = MIN_MODEL_BOND - cr;
        assertEq(inc.challengerCredit(challenger), cr, "challenger reward from model slash");
        assertEq(inc.pinnerPool(), poolBefore + pr, "remainder to honest-pinner pool");
    }

    function test_challengeWrongCommD_revertsWhenRootMatches() public {
        bytes32 root = keccak256("commD");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, root);
        // No dispute: the challenger's root equals the registered one.
        vm.prank(challenger);
        vm.expectRevert("No dispute");
        inc.challengeWrongCommD(cid, root);
    }

    function test_reclaimModelBond_afterWindow_returnsBond() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"));
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW + 1);

        uint256 before = modelOwner.balance;
        vm.prank(modelOwner);
        uint256 amt = inc.reclaimModelBond(cid);
        assertEq(amt, MIN_MODEL_BOND);
        assertEq(modelOwner.balance, before + MIN_MODEL_BOND);
    }

    function test_reclaimModelBond_revertsDuringWindow() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"));
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW - 1);
        vm.prank(modelOwner);
        vm.expectRevert("Window still open");
        inc.reclaimModelBond(cid);
    }

    function test_reclaimModelBond_revertsAfterSlash() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("WRONG"));
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, keccak256("TRUTH"));
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW + 1);
        vm.prank(modelOwner);
        vm.expectRevert("Bond slashed");
        inc.reclaimModelBond(cid);
    }

    // ════════════════════ conservation smoke (TLA invariants) ═══════════════════

    /// After a frivolous-challenge round, the challenger-bond subsystem balances:
    /// every posted challenger bond is either still escrowed, returned, or
    /// forfeit to a pinner (ChallengerBondConservation).
    function test_challengerBondConservation_afterFrivolous() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commitAndReveal(challenger);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        // bonded == escrowed(0, challenge closed) + returned + toPinner
        assertEq(
            inc.challengerBonded(),
            inc.challengerEscrowed() + inc.challengerBondReturned() + inc.challengerBondToPinner()
        );
        // exactly one bond posted, forfeit to the pinner
        assertEq(inc.challengerBonded(), CHALLENGER_BOND);
        assertEq(inc.challengerBondToPinner(), CHALLENGER_BOND);
    }

    function test_modelBondConservation_afterSlash() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("WRONG"));
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, keccak256("TRUTH"));

        // bonded == held + slashedToChallenger + pool + paidFromPool + returned
        assertEq(
            inc.modelBonded(),
            inc.modelBondHeldTotal() + inc.modelSlashedChallenger() + inc.pinnerPool()
                + inc.pinnerPoolPaid() + inc.modelReturned()
        );
        assertEq(inc.modelBonded(), MIN_MODEL_BOND);
    }

    receive() external payable {}
}
