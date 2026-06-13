// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../src/KYCRegistry.sol";

/// @notice Adversarial suite for IPFSIncentivesV3 (PIN-CR-S1), pinning the
///         guarantees of the four hardening mechanisms — formalized in
///         `formal/PINIncentiveV4.tla`:
///           Q1 commit-reveal (grind-resistance) — the nonce is fixed at
///              COMMIT; a PoSt before commitBlock + REVEAL_DELAY reverts.
///           PIN-S3 third-party challenger bond — a refuted (frivolous)
///              challenge forfeits the bond to the pinner; an unrefuted
///              (honest) one returns it AND pays the slash reward.
///           Q2 CommD registrant bond — a proven wrong-root challenge slashes
///              + splits (challenger reward / honest-pinner pool); an
///              unchallenged bond is reclaimable only after the window.
///
/// @dev The ZK proof is an oracle (TLA): a MockVerifier etched at 0x0108
///      returns a settable verdict, so the FINANCIAL machine is tested
///      deterministically.
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

    uint256 internal constant BOND = 10 ether;
    uint256 internal constant REWARD = 4 ether;
    uint256 internal constant ROUNDS = 4;
    uint256 internal constant MAX_MISSED = 0; // one missed window slashes
    uint256 internal constant CHALLENGER_BPS = 5000; // 50% of a slashed pin bond
    uint256 internal constant QUORUM = 2;
    uint256 internal constant WINDOW = 10; // response window (blocks) after reveal
    uint256 internal constant CHALLENGE_N = 32;

    // V3 params.
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

    /// In v3, sealing requires the model's CommD to be registered (Q2 bond)
    /// and to MATCH the sealed CommD. Register once (idempotent across pinners).
    function _ensureModelRegistered() internal {
        (address owner, , , , , , ) = inc.getModel(cid);
        if (owner == address(0)) {
            vm.prank(modelOwner);
            inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("D"), keccak256("data"), "ipfs://x");
        }
    }

    function _registerAndSeal(address who) internal {
        _ensureModelRegistered();
        vm.prank(who);
        inc.registerPinner();
        vm.prank(who);
        inc.sealCommit{value: BOND}(
            cid, sector, _replicaId(who), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF
        );
    }

    /// A per-pinner circuit-replicaID stand-in (the real value is the prover's
    /// Poseidon output; the mock verifier accepts any 32 bytes, so the test
    /// exercises the contract's replicaID-owner binding, not the ZK).
    function _replicaId(address who) internal pure returns (bytes32) {
        return keccak256(abi.encode("rid", who));
    }

    /// Open the per-slot commit (sets the nonce), return the committed nonce.
    function _commit() internal returns (uint256 nonce) {
        inc.commitChallenge(cid, sector);
        (, , , , uint256 commitNonce, ) = inc.getSlot(cid, sector);
        nonce = commitNonce;
    }

    // ════════════════════ PIN-S4: Sybil binding (one identity / slot) ═══════════

    function test_sybilBinding_defaultsOff() public view {
        assertFalse(inc.sybilBindingActive());
    }

    function test_setSybilBinding_onlyAdmin() public {
        vm.prank(pinner);
        vm.expectRevert("AccessControl: account missing role");
        inc.setSybilBinding(true);
        inc.setSybilBinding(true); // admin (this) ok
        assertTrue(inc.sybilBindingActive());
    }

    /// With binding ON, two addresses of the SAME identity cannot both occupy
    /// one slot's replication quorum — one identity can't farm N rewards.
    function test_sybilBinding_rejectsSameIdentityInSlot() public {
        _ensureModelRegistered();
        bytes32 sub = keccak256("sub:sybil");
        // Link both pinner addresses to ONE identity (IDP-S3 wallet-linking).
        kyc.setVerifiedWithIdentity(pinner, sub);
        kyc.setVerifiedWithIdentity(pinner2, sub);
        inc.setSybilBinding(true);

        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner2);
        inc.registerPinner();

        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        // pinner2 = same identity → rejected from the same slot.
        vm.prank(pinner2);
        vm.expectRevert("Identity already in slot");
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner2), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    /// Distinct identities fill the quorum normally.
    function test_sybilBinding_allowsDistinctIdentities() public {
        _ensureModelRegistered();
        kyc.setVerifiedWithIdentity(pinner, keccak256("sub:a"));
        kyc.setVerifiedWithIdentity(pinner2, keccak256("sub:b"));
        inc.setSybilBinding(true);
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner2);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        vm.prank(pinner2);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner2), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        (, , uint256 live, , , ) = inc.getSlot(cid, sector);
        assertEq(live, 2);
    }

    /// Binding OFF (provisional, pre-IDP-S3): no identity check — current
    /// behavior. (setUp KYC-verifies via plain setVerified = self-identities.)
    function test_sybilBinding_inactive_isNoOp() public {
        _ensureModelRegistered();
        // binding stays off (default); two distinct addresses seal the slot.
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner2);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        vm.prank(pinner2);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner2), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        (, , uint256 live, , , ) = inc.getSlot(cid, sector);
        assertEq(live, 2);
    }

    /// A slashed pin frees its identity slot so the person can re-seal.
    function test_sybilBinding_slashFreesIdentity() public {
        _ensureModelRegistered();
        bytes32 sub = keccak256("sub:reseal");
        kyc.setVerifiedWithIdentity(pinner, sub);
        inc.setSybilBinding(true);
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        // Open a commit + miss the window → slash (MAX_MISSED=0).
        inc.commitChallenge(cid, sector);
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1);
        inc.slash(pinner, cid, sector);
        // Identity slot freed → the same person can clear + re-seal.
        vm.prank(pinner);
        inc.clearSlashed(cid, sector);
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, _replicaId(pinner), 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        (IPFSIncentivesV3.Status st, , , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Active));
    }

    // ════════════════════ replicaID binding (PIN-S6 finding) ════════════════════

    /// A replicaID is owned by the first pinner who commits it; a second pinner
    /// cannot re-submit another's (replicaID, proof) to seal a pin (anti-theft).
    function test_replicaId_cannotBeReusedByAnotherPinner() public {
        _ensureModelRegistered();
        bytes32 rid = _replicaId(pinner); // pinner1 claims it
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, rid, 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);

        // pinner2 (a different (cid,sector) sector so the slot has room) tries to
        // reuse pinner1's replicaID -> rejected by the owner binding.
        vm.prank(pinner2);
        inc.registerPinner();
        vm.prank(pinner2);
        vm.expectRevert("replicaID owned by another");
        inc.sealCommit{value: BOND}(cid, 1, rid, 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
    }

    function test_replicaId_ownerCanReuseAcrossOwnSectors() public {
        _ensureModelRegistered();
        bytes32 rid = _replicaId(pinner);
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, sector, rid, 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        // The same owner reusing the same replicaID on another sector is allowed
        // (the per-pin key differs; the owner binding only blocks OTHER pinners).
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(cid, 1, rid, 1, keccak256("D"), keccak256("R"), keccak256("C"), PROOF);
        assertEq(inc.replicaIdOwner(rid), pinner);
    }

    // ════════════════════ Q1: commit-reveal grind-resistance ════════════════════

    function test_commitReveal_submitBeforeRevealDelay_reverts() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commit();

        // Same block as commit (and any block < commitBlock + REVEAL_DELAY).
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
        uint256 committedNonce = _commit();

        // Change the beacon at reveal time: the required nonce MUST be unchanged.
        vm.roll(block.number + REVEAL_DELAY);
        vm.prevrandao(bytes32(uint256(0xBEEF)));
        (, , , , uint256 nonceAtReveal, ) = inc.getSlot(cid, sector);
        assertEq(nonceAtReveal, committedNonce, "nonce fixed at commit");

        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), committedNonce, PROOF);
        (, uint64 round, , , , ) = inc.getPin(pinner, cid, sector);
        assertEq(round, 1, "valid reveal vests one round");
    }

    function test_commitReveal_afterWindow_reverts() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commit();
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1); // past the response window
        vm.prank(pinner);
        vm.expectRevert("Challenge window closed");
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);
    }

    // ════════════════════ PIN-S3: challenger bond economics ═════════════════════

    function test_challengePin_requiresExactBond() public {
        _registerAndSeal(pinner);
        _commit();
        vm.prank(challenger);
        vm.expectRevert("Must post exact challenger bond");
        inc.challengePin{value: CHALLENGER_BOND - 1}(pinner, cid, sector);
    }

    function test_challengePin_requiresOutstandingCommit() public {
        _registerAndSeal(pinner);
        // No commit yet → the pinner couldn't refute → challenge is unrefutable.
        vm.prank(challenger);
        vm.expectRevert("No committed challenge");
        inc.challengePin{value: CHALLENGER_BOND}(pinner, cid, sector);
    }

    /// Frivolous: challenger bonds against a pinner who IS storing; the pinner
    /// refutes (submitPoSt) → the challenger's bond is forfeit to the pinner.
    function test_frivolousChallenge_bondForfeitToPinner() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commit();
        vm.prank(challenger);
        inc.challengePin{value: CHALLENGER_BOND}(pinner, cid, sector);

        vm.roll(block.number + REVEAL_DELAY);
        uint256 pinnerCreditBefore = inc.challengerCredit(pinner);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        assertEq(
            inc.challengerCredit(pinner),
            pinnerCreditBefore + CHALLENGER_BOND,
            "frivolous bond goes to the pinner"
        );
        assertEq(inc.challengerCredit(challenger), 0, "challenger gets nothing back");
        assertEq(inc.challengerBondToPinner(), CHALLENGER_BOND);
        // challenge cleared
        (address ch, uint256 b, ) = inc.getChallenge(pinner, cid, sector);
        assertEq(ch, address(0));
        assertEq(b, 0);
    }

    /// Honest: challenger bonds against a pinner who is NOT storing; the pinner
    /// misses → slash; the challenger earns the slash reward AND gets the bond
    /// back (and the reward routes to THEM, not an arbitrary slash caller).
    function test_honestChallenge_paysFromSlash_andReturnsBond() public {
        _registerAndSeal(pinner);
        _commit();
        vm.prank(challenger);
        inc.challengePin{value: CHALLENGER_BOND}(pinner, cid, sector);

        // Pinner never reveals; advance past reveal delay + response window.
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1);
        // A DIFFERENT account triggers the slash — the reward must still go to
        // the bonded challenger.
        vm.prank(pinner2);
        inc.slash(pinner, cid, sector);

        (IPFSIncentivesV3.Status st, , , , uint256 bondHeld, ) = inc.getPin(pinner, cid, sector);
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Slashed));
        assertEq(bondHeld, 0);

        uint256 cr = (BOND * CHALLENGER_BPS) / 10000;
        assertEq(
            inc.challengerCredit(challenger),
            cr + CHALLENGER_BOND,
            "honest challenge: slash reward + own bond back, to the bonded challenger"
        );
        assertEq(inc.challengerCredit(pinner2), 0, "the slash caller gets nothing");
        assertEq(inc.challengerBondReturned(), CHALLENGER_BOND);
    }

    function test_unbondedSlash_rewardGoesToCaller() public {
        // No challengePin: a permissionless slash keeps the v2 behaviour
        // (reward to the caller).
        _registerAndSeal(pinner);
        _commit();
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1);
        vm.prank(pinner2);
        inc.slash(pinner, cid, sector);
        uint256 cr = (BOND * CHALLENGER_BPS) / 10000;
        assertEq(inc.challengerCredit(pinner2), cr, "unbonded slash pays the caller");
    }

    // ════════════════════════ Q2: CommD registrant bond ══════════════════════════

    function test_registerModel_requiresMinBond() public {
        vm.prank(modelOwner);
        vm.expectRevert("Bond too low");
        inc.registerModel{value: MIN_MODEL_BOND - 1}(cid, keccak256("commD"), keccak256("data"), "ipfs://x");
    }

    function test_registerModel_revertsOnDoubleRegister() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"), keccak256("data"), "ipfs://x");
        vm.prank(modelOwner);
        vm.expectRevert("Already registered");
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD2"), keccak256("data"), "ipfs://x");
    }

    /// A proven wrong-CommD challenge slashes the registrant bond and splits it
    /// into the challenger reward + the honest-pinner pool.
    function test_challengeWrongCommD_slashesAndSplits() public {
        bytes memory data = bytes("the-canonical-model-bytes");
        bytes32 dataHash = keccak256(data);
        bytes32 registered = keccak256("WRONG_commD");
        bytes32 truth = keccak256("TRUE_commD"); // != registered → dispute
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, registered, dataHash, "ipfs://x");

        uint256 poolBefore = inc.honestPinnerCompensationPool();
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, data, truth);

        uint256 cr = (MIN_MODEL_BOND * MODEL_CHALLENGER_BPS) / 10000;
        uint256 pr = MIN_MODEL_BOND - cr;
        assertEq(inc.challengerCredit(challenger), cr, "challenger reward from model slash");
        assertEq(inc.honestPinnerCompensationPool(), poolBefore + pr, "remainder to pool");
        assertEq(inc.modelBondsSlashed(), MIN_MODEL_BOND);
    }

    function test_challengeWrongCommD_revertsWhenRootMatches() public {
        bytes memory data = bytes("bytes");
        bytes32 root = keccak256("commD");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, root, keccak256(data), "ipfs://x");
        vm.prank(challenger);
        vm.expectRevert("No dispute");
        inc.challengeWrongCommD(cid, data, root); // same root → no dispute
    }

    function test_challengeWrongCommD_revertsOnDataHashMismatch() public {
        bytes32 root = keccak256("commD");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, root, keccak256("real"), "ipfs://x");
        vm.prank(challenger);
        vm.expectRevert("Data hash mismatch");
        inc.challengeWrongCommD(cid, bytes("forged"), keccak256("other"));
    }

    function test_challengeWrongCommD_revertsAfterWindow() public {
        bytes memory data = bytes("bytes");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("WRONG"), keccak256(data), "ipfs://x");
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW + 1);
        vm.prank(challenger);
        vm.expectRevert("Window closed");
        inc.challengeWrongCommD(cid, data, keccak256("TRUTH"));
    }

    function test_reclaimBond_afterWindow_returnsBond() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"), keccak256("data"), "ipfs://x");
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW + 1);

        uint256 before = modelOwner.balance;
        vm.prank(modelOwner);
        uint256 amt = inc.reclaimBond(cid);
        assertEq(amt, MIN_MODEL_BOND);
        assertEq(modelOwner.balance, before + MIN_MODEL_BOND);
        assertEq(inc.modelBondsRefunded(), MIN_MODEL_BOND);
    }

    function test_reclaimBond_revertsDuringWindow() public {
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("commD"), keccak256("data"), "ipfs://x");
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW - 1);
        vm.prank(modelOwner);
        vm.expectRevert("Window open");
        inc.reclaimBond(cid);
    }

    function test_reclaimBond_revertsAfterSlash() public {
        bytes memory data = bytes("bytes");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("WRONG"), keccak256(data), "ipfs://x");
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, data, keccak256("TRUTH"));
        vm.roll(block.number + MODEL_CHALLENGE_WINDOW + 1);
        vm.prank(modelOwner);
        vm.expectRevert("Bond slashed");
        inc.reclaimBond(cid);
    }

    // ════════════════════ conservation (TLA-v4 invariants) ══════════════════════

    function test_challengerBondConservation_afterFrivolous() public {
        _registerAndSeal(pinner);
        uint256 nonce = _commit();
        vm.prank(challenger);
        inc.challengePin{value: CHALLENGER_BOND}(pinner, cid, sector);
        vm.roll(block.number + REVEAL_DELAY);
        vm.prank(pinner);
        inc.submitPoSt(cid, sector, keccak256("R"), keccak256("C"), nonce, PROOF);

        // bonded == escrowed + returned + toPinner (ChallengerBondConservation)
        assertEq(
            inc.challengerBonded(),
            inc.challengerEscrowed() + inc.challengerBondReturned() + inc.challengerBondToPinner()
        );
        assertEq(inc.challengerBonded(), CHALLENGER_BOND);
        assertEq(inc.challengerEscrowed(), 0); // resolved
        assertEq(inc.challengerBondToPinner(), CHALLENGER_BOND);
    }

    function test_modelBondConservation_afterSlash() public {
        bytes memory data = bytes("bytes");
        vm.prank(modelOwner);
        inc.registerModel{value: MIN_MODEL_BOND}(cid, keccak256("WRONG"), keccak256(data), "ipfs://x");
        vm.prank(challenger);
        inc.challengeWrongCommD(cid, data, keccak256("TRUTH"));

        // bonded == held(0, slashed) + slashed + refunded (ModelBondConservation)
        uint256 held = inc.modelBondedTotal() - inc.modelBondsSlashed() - inc.modelBondsRefunded();
        assertEq(held, 0);
        assertEq(
            inc.modelBondedTotal(),
            held + inc.modelBondsSlashed() + inc.modelBondsRefunded()
        );
        assertEq(inc.modelBondedTotal(), MIN_MODEL_BOND);
    }

    receive() external payable {}
}
