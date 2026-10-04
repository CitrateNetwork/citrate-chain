// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {FederatedRoundLedger} from "../src/FederatedRoundLedger.sol";

/// @notice TEST DOUBLE for the 0x0110 precompile, etched at address(0x0110).
///         Forge's EVM has no Citrate precompiles, so this answers only the
///         vectors a test registers. The golden vector below was produced by the
///         real precompile on a local Citrate devnet and is pinned on the Rust
///         side by the kernel itself (tools/fl-replay/tests/golden.rs).
contract BelnapVectorOracle {
    mapping(bytes32 => bytes) internal vectors;

    function set(bytes calldata input, bytes calldata output) external {
        vectors[keccak256(input)] = output;
    }

    fallback(bytes calldata input) external returns (bytes memory) {
        bytes memory out = vectors[keccak256(input)];
        require(out.length > 0, "no vector");
        return out;
    }
}

contract FederatedRoundLedgerTest is Test {
    FederatedRoundLedger internal ledger;
    address internal coordinator = address(0xC0);
    address internal stranger = address(0xBAD);
    bytes32 internal constant SALT = keccak256("cluster-a");
    bytes32 internal clusterId;

    uint64 internal constant WINDOW = 20;

    // Workers, ascending.
    address internal constant W1 = address(0x1001);
    address internal constant W2 = address(0x1002);
    address internal constant W3 = address(0x1003);

    // The golden chunk: 3 participants x 4 coordinates.
    int64[4][3] internal rows;

    bytes internal constant GOLDEN_OUTPUT =
        hex"0000000000006aa9ffffffffffffbfff0000000000000000000000000000003903030001";

    function setUp() public {
        ledger = new FederatedRoundLedger();
        rows[0] = [int64(65536), -32768, 0, 100];
        rows[1] = [int64(32768), -32768, 0, 50];
        rows[2] = [int64(-16384), 16384, 0, 25];
        vm.prank(coordinator);
        clusterId = ledger.registerCluster(SALT, _rules());
    }

    // ── helpers: the FL_ROUND_V1 tree and encodings ────────────────────

    function _rules() internal pure returns (FederatedRoundLedger.ClusterRules memory r) {
        r = FederatedRoundLedger.ClusterRules({
            minParticipants: 3,
            chunkDim: 4,
            valueScaleLog2: 8,
            thresholdPos: 32768,
            thresholdNeg: -32768,
            confidenceRule: 1,
            weightRule: 1,
            challengeWindow: WINDOW
        });
    }

    function _leaf(uint256 i, bytes32 payload) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), uint32(i), payload));
    }

    function _node(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), l, r));
    }

    /// Root over 3 payloads (padded to 4) and the proof for index `i`.
    function _tree3(bytes32[3] memory p, uint256 i) internal pure returns (bytes32 root, bytes32[] memory proof) {
        bytes32[4] memory l = [_leaf(0, p[0]), _leaf(1, p[1]), _leaf(2, p[2]), bytes32(0)];
        bytes32 a = _node(l[0], l[1]);
        bytes32 b = _node(l[2], l[3]);
        root = _node(a, b);
        proof = new bytes32[](2);
        proof[0] = l[i ^ 1];
        proof[1] = i < 2 ? b : a;
    }

    function _rowBytes(int64[4] memory r) internal pure returns (bytes memory) {
        return abi.encodePacked(r[0], r[1], r[2], r[3]);
    }

    function _input(int64[4][3] memory rs, int64 w, int64 tpos, int64 tneg, bool honestConf)
        internal
        pure
        returns (bytes memory b)
    {
        b = abi.encodePacked(uint32(4), uint32(3));
        for (uint256 i = 0; i < 3; i++) {
            b = bytes.concat(b, _rowBytes(rs[i]));
        }
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 d = 0; d < 4; d++) {
                int64 c = rs[i][d] == 0 ? int64(0) : int64(65536);
                if (!honestConf && i == 1 && d == 2) c = 65536; // a confidence the rule forbids
                b = bytes.concat(b, abi.encodePacked(c));
            }
        }
        b = bytes.concat(b, abi.encodePacked(w, w, w, tpos, tneg));
    }

    function _goldenInput() internal view returns (bytes memory) {
        return _input(rows, 21845, 32768, -32768, true);
    }

    function _etchOracle() internal {
        vm.etch(address(0x0110), address(new BelnapVectorOracle()).code);
        BelnapVectorOracle(address(0x0110)).set(_goldenInput(), GOLDEN_OUTPUT);
    }

    struct Committed {
        bytes32 roundId;
        bytes32[3] deltaRoots;
        bytes32 participantsRoot;
        bytes input;
        bytes32 outputHash;
    }

    /// Commit a one-chunk round whose leaves are as given.
    function _commit(bytes memory input, bytes32 outputHash, bytes32[3] memory deltaRoots, address[3] memory ws)
        internal
        returns (Committed memory c)
    {
        bytes32[3] memory pp;
        for (uint256 i = 0; i < 3; i++) {
            pp[i] = keccak256(abi.encodePacked(ws[i], deltaRoots[i]));
        }
        (c.participantsRoot,) = _tree3(pp, 0);
        c.deltaRoots = deltaRoots;
        c.input = input;
        c.outputHash = outputHash;
        FederatedRoundLedger.RoundCommit memory rc = FederatedRoundLedger.RoundCommit({
            clusterId: clusterId,
            ordinal: ledger.getCluster(clusterId).nextOrdinal,
            configHash: keccak256("config"),
            participantsRoot: c.participantsRoot,
            participants: 3,
            nValues: 4,
            inputRoot: _leaf(0, keccak256(input)),
            outputRoot: _leaf(0, outputHash),
            chunks: 1,
            adapterHash: keccak256("adapter")
        });
        vm.prank(coordinator);
        c.roundId = ledger.commitRound(rc);
    }

    function _honestDeltaRoots() internal view returns (bytes32[3] memory d) {
        for (uint256 i = 0; i < 3; i++) {
            d[i] = _leaf(0, keccak256(_rowBytes(rows[i])));
        }
    }

    function _honest() internal returns (Committed memory) {
        return _commit(_goldenInput(), keccak256(GOLDEN_OUTPUT), _honestDeltaRoots(), [W1, W2, W3]);
    }

    function _status(bytes32 id) internal view returns (FederatedRoundLedger.Status) {
        return ledger.getRound(id).status;
    }

    // ── clusters ─────────────────────────────────────────────────────

    function test_cluster_id_binds_chain_ledger_coordinator_and_salt() public view {
        assertEq(
            clusterId,
            keccak256(
                abi.encodePacked("citrate-fl-cluster/1", uint64(block.chainid), address(ledger), coordinator, SALT)
            )
        );
        assertEq(ledger.getCluster(clusterId).coordinator, coordinator);
    }

    function test_a_cluster_cannot_be_registered_twice() public {
        vm.prank(coordinator);
        vm.expectRevert(FederatedRoundLedger.ClusterExists.selector);
        ledger.registerCluster(SALT, _rules());
    }

    function test_rules_outside_the_safe_envelope_are_refused() public {
        FederatedRoundLedger.ClusterRules memory r;
        bytes32[8] memory salts;
        for (uint256 i = 0; i < 8; i++) {
            salts[i] = keccak256(abi.encode(i));
        }
        r = _rules();
        r.minParticipants = 2;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[0], r);
        r = _rules();
        r.chunkDim = 0;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[1], r);
        r = _rules();
        r.chunkDim = 1025;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[2], r);
        r = _rules();
        r.valueScaleLog2 = 17;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[3], r);
        r = _rules();
        r.thresholdPos = 0;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[4], r);
        r = _rules();
        r.confidenceRule = 2;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[5], r);
        r = _rules();
        r.challengeWindow = 0;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[6], r);
        r = _rules();
        r.minParticipants = 1025;
        vm.expectRevert(FederatedRoundLedger.BadRules.selector);
        ledger.registerCluster(salts[7], r);
    }

    // ── commit ───────────────────────────────────────────────────────

    function test_round_id_is_the_packed_key_rust_computes() public {
        Committed memory c = _honest();
        assertEq(c.roundId, ledger.roundIdOf(clusterId, 0));
        assertEq(
            c.roundId,
            keccak256(
                abi.encodePacked("citrate-fl-round-key/1", uint64(block.chainid), address(ledger), clusterId, uint64(0))
            )
        );
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(uint8(r.status), uint8(FederatedRoundLedger.Status.Committed));
        assertEq(r.deadline, block.number + WINDOW);
        assertEq(ledger.getCluster(clusterId).nextOrdinal, 1);
    }

    function test_only_the_cluster_coordinator_commits() public {
        FederatedRoundLedger.RoundCommit memory rc = _validCommit();
        vm.prank(stranger);
        vm.expectRevert(FederatedRoundLedger.NotCoordinator.selector);
        ledger.commitRound(rc);
    }

    function _validCommit() internal view returns (FederatedRoundLedger.RoundCommit memory) {
        return FederatedRoundLedger.RoundCommit({
            clusterId: clusterId,
            ordinal: 0,
            configHash: keccak256("c"),
            participantsRoot: keccak256("p"),
            participants: 3,
            nValues: 9,
            inputRoot: keccak256("i"),
            outputRoot: keccak256("o"),
            chunks: 3,
            adapterHash: keccak256("a")
        });
    }

    function test_commits_that_break_the_round_shape_are_refused() public {
        FederatedRoundLedger.RoundCommit memory rc;
        vm.startPrank(coordinator);

        rc = _validCommit();
        rc.ordinal = 1;
        vm.expectRevert(FederatedRoundLedger.BadOrdinal.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.participants = 2;
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.chunks = 2; // 9 values at chunkDim 4 is 3 chunks
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.participants = 1025; // 1025 x 4 cells > 4096
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.nValues = 0;
        rc.chunks = 0;
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.outputRoot = bytes32(0);
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.adapterHash = bytes32(0);
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc = _validCommit();
        rc.clusterId = keccak256("nope");
        vm.expectRevert(FederatedRoundLedger.NotCoordinator.selector);
        ledger.commitRound(rc);
        vm.stopPrank();
    }

    /// A round with more participants than 0x0110 accepts could never be proven wrong: every
    /// output challenge would revert in the precompile. Narrow chunks keep the cell bound from
    /// catching it, so the participant cap has to hold on its own.
    function test_a_round_the_precompile_cannot_recompute_is_refused() public {
        FederatedRoundLedger.ClusterRules memory narrow = _rules();
        narrow.chunkDim = 1;
        vm.startPrank(coordinator);
        bytes32 narrowId = ledger.registerCluster(keccak256("narrow"), narrow);
        FederatedRoundLedger.RoundCommit memory rc = _validCommit();
        rc.clusterId = narrowId;
        rc.chunks = 9; // 9 values at chunkDim 1
        rc.participants = 1025; // 1025 x 1 cells is within 4096, but 0x0110 takes at most 1024
        vm.expectRevert(FederatedRoundLedger.BadShape.selector);
        ledger.commitRound(rc);

        rc.participants = 1024;
        ledger.commitRound(rc);
        vm.stopPrank();
    }

    function test_record_digest_is_the_abi_encoding_settlement_anchors() public {
        Committed memory c = _honest();
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(
            ledger.recordDigest(c.roundId),
            keccak256(
                abi.encode(
                    block.chainid,
                    address(ledger),
                    c.roundId,
                    r.configHash,
                    r.participantsRoot,
                    r.inputRoot,
                    r.outputRoot,
                    r.adapterHash,
                    uint256(r.nValues),
                    uint256(r.chunks),
                    uint256(r.participants)
                )
            )
        );
        vm.expectRevert(FederatedRoundLedger.UnknownRound.selector);
        ledger.recordDigest(keccak256("x"));
    }

    // ── the challenge window ─────────────────────────────────────────

    function test_an_unchallenged_round_is_accepted_after_the_window() public {
        Committed memory c = _honest();
        vm.expectRevert(FederatedRoundLedger.WindowOpen.selector);
        ledger.finalize(c.roundId);
        vm.roll(block.number + WINDOW);
        vm.expectRevert(FederatedRoundLedger.WindowOpen.selector);
        ledger.finalize(c.roundId);
        vm.roll(block.number + 1);
        ledger.finalize(c.roundId);
        assertTrue(ledger.isAccepted(c.roundId));
        vm.expectRevert(FederatedRoundLedger.NotCommitted.selector);
        ledger.finalize(c.roundId);
    }

    function test_an_honest_output_survives_its_challenge() public {
        _etchOracle();
        Committed memory c = _honest();
        bytes32[] memory none = new bytes32[](0);
        vm.prank(stranger);
        vm.expectRevert(FederatedRoundLedger.ChallengeFailed.selector);
        ledger.challengeOutput(c.roundId, 0, c.input, none, c.outputHash, none);
        assertEq(uint8(_status(c.roundId)), uint8(FederatedRoundLedger.Status.Committed));
    }

    function test_a_wrong_output_is_proven_wrong_by_the_precompile() public {
        _etchOracle();
        bytes memory lie = hex"0000000000007fffffffffffffffbfff0000000000000000000000000000003903030001";
        Committed memory c = _commit(_goldenInput(), keccak256(lie), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        vm.prank(stranger);
        ledger.challengeOutput(c.roundId, 0, c.input, none, c.outputHash, none);
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(uint8(r.status), uint8(FederatedRoundLedger.Status.Rejected));
        assertEq(uint8(r.fault), uint8(FederatedRoundLedger.Fault.OutputMismatch));
        // A rejected round is final: never accepted, never challenged again.
        vm.roll(block.number + WINDOW + 1);
        vm.expectRevert(FederatedRoundLedger.NotCommitted.selector);
        ledger.finalize(c.roundId);
        assertFalse(ledger.isAccepted(c.roundId));
    }

    function test_without_the_precompile_a_challenge_changes_nothing() public {
        // No etch: address(0x0110) has no code here, as on anvil.
        bytes memory lie = hex"0000000000007fffffffffffffffbfff0000000000000000000000000000003903030001";
        Committed memory c = _commit(_goldenInput(), keccak256(lie), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        vm.expectRevert(FederatedRoundLedger.PrecompileUnavailable.selector);
        ledger.challengeOutput(c.roundId, 0, c.input, none, c.outputHash, none);
        assertEq(uint8(_status(c.roundId)), uint8(FederatedRoundLedger.Status.Committed));
    }

    function test_proofs_must_open_the_committed_leaves() public {
        _etchOracle();
        Committed memory c = _honest();
        bytes32[] memory none = new bytes32[](0);
        // An input the round did not commit.
        bytes memory other = _input(rows, 21845, 32768, -32767, true);
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeOutput(c.roundId, 0, other, none, c.outputHash, none);
        // An output hash the round did not commit.
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeOutput(c.roundId, 0, c.input, none, keccak256("other"), none);
        // A chunk the round does not have.
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeOutput(c.roundId, 1, c.input, none, c.outputHash, none);
    }

    function test_challenges_close_with_the_window() public {
        _etchOracle();
        bytes memory lie = hex"0000000000007fffffffffffffffbfff0000000000000000000000000000003903030001";
        Committed memory c = _commit(_goldenInput(), keccak256(lie), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        vm.roll(block.number + WINDOW + 1);
        vm.expectRevert(FederatedRoundLedger.WindowClosed.selector);
        ledger.challengeOutput(c.roundId, 0, c.input, none, c.outputHash, none);
    }

    // ── row consistency ──────────────────────────────────────────────

    function _rowClaim(Committed memory c, address[3] memory ws, uint16 p)
        internal
        view
        returns (FederatedRoundLedger.RowClaim memory rc)
    {
        bytes32[3] memory pp;
        for (uint256 i = 0; i < 3; i++) {
            pp[i] = keccak256(abi.encodePacked(ws[i], c.deltaRoots[i]));
        }
        (, bytes32[] memory proof) = _tree3(pp, p);
        rc = FederatedRoundLedger.RowClaim({
            participant: p,
            worker: ws[p],
            deltaRoot: c.deltaRoots[p],
            participantProof: proof,
            rowHash: keccak256(_rowBytes(rows[p])),
            rowProof: new bytes32[](0)
        });
    }

    function test_an_honest_row_survives_its_challenge() public {
        Committed memory c = _honest();
        bytes32[] memory none = new bytes32[](0);
        for (uint16 p = 0; p < 3; p++) {
            FederatedRoundLedger.RowClaim memory rc = _rowClaim(c, [W1, W2, W3], p);
            vm.expectRevert(FederatedRoundLedger.ChallengeFailed.selector);
            ledger.challengeRow(c.roundId, 0, c.input, none, rc);
        }
    }

    function test_an_input_row_that_is_not_the_workers_committed_row_rejects_the_round() public {
        // The coordinator aggregated a different row 1 than worker 2 committed to.
        int64[4][3] memory swapped = rows;
        swapped[1] = [int64(500000), -32768, 0, 50];
        bytes memory input = _input(swapped, 21845, 32768, -32768, true);
        Committed memory c = _commit(input, keccak256("whatever the precompile said"), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        FederatedRoundLedger.RowClaim memory rc = _rowClaim(c, [W1, W2, W3], 1);
        ledger.challengeRow(c.roundId, 0, c.input, none, rc);
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(uint8(r.status), uint8(FederatedRoundLedger.Status.Rejected));
        assertEq(uint8(r.fault), uint8(FederatedRoundLedger.Fault.RowMismatch));
    }

    function test_a_row_claim_must_open_the_committed_participant_and_row() public {
        Committed memory c = _honest();
        bytes32[] memory none = new bytes32[](0);
        FederatedRoundLedger.RowClaim memory rc = _rowClaim(c, [W1, W2, W3], 1);
        rc.worker = stranger;
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeRow(c.roundId, 0, c.input, none, rc);
        rc = _rowClaim(c, [W1, W2, W3], 1);
        rc.rowHash = keccak256("not committed");
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeRow(c.roundId, 0, c.input, none, rc);
    }

    function test_a_malformed_input_is_a_rules_fault_not_a_row_fault() public {
        // The header claims 3-wide rows in a 4-wide input: read as rows it would "mismatch",
        // but the fault is the shape, so the row challenge declines and challengeRules applies.
        bytes memory b = _goldenInput();
        b[3] = 0x03;
        Committed memory c = _commit(b, keccak256("o"), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        FederatedRoundLedger.RowClaim memory rc = _rowClaim(c, [W1, W2, W3], 1);
        vm.expectRevert(FederatedRoundLedger.ChallengeFailed.selector);
        ledger.challengeRow(c.roundId, 0, c.input, none, rc);
        assertEq(uint8(_status(c.roundId)), uint8(FederatedRoundLedger.Status.Committed));
        ledger.challengeRules(c.roundId, 0, c.input, none);
        assertEq(uint8(ledger.getRound(c.roundId).fault), uint8(FederatedRoundLedger.Fault.RuleViolation));
    }

    // ── the round's rules ────────────────────────────────────────────

    function test_an_input_that_follows_the_rules_survives() public {
        Committed memory c = _honest();
        bytes32[] memory none = new bytes32[](0);
        vm.expectRevert(FederatedRoundLedger.ChallengeFailed.selector);
        ledger.challengeRules(c.roundId, 0, c.input, none);
    }

    function _assertRulesReject(bytes memory input) internal {
        Committed memory c = _commit(input, keccak256("o"), _honestDeltaRoots(), [W1, W2, W3]);
        bytes32[] memory none = new bytes32[](0);
        ledger.challengeRules(c.roundId, 0, c.input, none);
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(uint8(r.status), uint8(FederatedRoundLedger.Status.Rejected));
        assertEq(uint8(r.fault), uint8(FederatedRoundLedger.Fault.RuleViolation));
    }

    function test_weighting_one_participant_up_rejects_the_round() public {
        bytes memory b = _input(rows, 21845, 32768, -32768, true);
        // Overwrite the first weight (offset 8 + 2*3*4*8) with 1.0.
        bytes memory w = abi.encodePacked(int64(65536));
        for (uint256 k = 0; k < 8; k++) {
            b[8 + 192 + k] = w[k];
        }
        _assertRulesReject(b);
    }

    function test_a_confidence_the_rule_forbids_rejects_the_round() public {
        _assertRulesReject(_input(rows, 21845, 32768, -32768, false));
    }

    function test_thresholds_other_than_the_clusters_reject_the_round() public {
        _assertRulesReject(_input(rows, 21845, 1, -32768, true));
    }

    function test_a_chunk_of_the_wrong_width_or_length_rejects_the_round() public {
        // Header claims dim 3 for a chunk that must be 4 wide.
        bytes memory b = _goldenInput();
        b[3] = 0x03;
        _assertRulesReject(b);
        // A truncated input.
        bytes memory t = _goldenInput();
        bytes memory cut = new bytes(t.length - 8);
        for (uint256 k = 0; k < cut.length; k++) {
            cut[k] = t[k];
        }
        _assertRulesReject(cut);
    }

    function test_a_well_formed_chunk_of_the_wrong_width_rejects_the_round() public {
        // Internally consistent (header, length, weights, confidences, thresholds all fine)
        // but 3 wide where the round's only chunk must hold all 4 values.
        bytes memory b = abi.encodePacked(uint32(3), uint32(3));
        for (uint256 i = 0; i < 3; i++) {
            b = bytes.concat(b, abi.encodePacked(rows[i][0], rows[i][1], rows[i][2]));
        }
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 d = 0; d < 3; d++) {
                b = bytes.concat(b, abi.encodePacked(rows[i][d] == 0 ? int64(0) : int64(65536)));
            }
        }
        b = bytes.concat(b, abi.encodePacked(int64(21845), int64(21845), int64(21845), int64(32768), int64(-32768)));
        assertEq(b.length, 24 + 16 * 3 * 3 + 8 * 3);
        _assertRulesReject(b);
    }

    // ── participant order ────────────────────────────────────────────

    function test_a_repeated_worker_rejects_the_round() public {
        Committed memory c = _commit(_goldenInput(), keccak256(GOLDEN_OUTPUT), _honestDeltaRoots(), [W1, W2, W2]);
        FederatedRoundLedger.RowClaim memory a = _rowClaim(c, [W1, W2, W2], 1);
        FederatedRoundLedger.RowClaim memory b = _rowClaim(c, [W1, W2, W2], 2);
        ledger.challengeOrder(c.roundId, a, b);
        FederatedRoundLedger.Round memory r = ledger.getRound(c.roundId);
        assertEq(uint8(r.status), uint8(FederatedRoundLedger.Status.Rejected));
        assertEq(uint8(r.fault), uint8(FederatedRoundLedger.Fault.ParticipantOrder));
    }

    function test_ascending_workers_survive_an_order_challenge() public {
        Committed memory c = _honest();
        FederatedRoundLedger.RowClaim memory a = _rowClaim(c, [W1, W2, W3], 0);
        FederatedRoundLedger.RowClaim memory b = _rowClaim(c, [W1, W2, W3], 2);
        vm.expectRevert(FederatedRoundLedger.ChallengeFailed.selector);
        ledger.challengeOrder(c.roundId, a, b);
        // The pair must be given in index order.
        vm.expectRevert(FederatedRoundLedger.BadProof.selector);
        ledger.challengeOrder(c.roundId, b, a);
    }

    // ── the aggregation view the coordinator calls ───────────────────

    function test_belnap_aggregate_returns_the_precompile_output() public {
        _etchOracle();
        assertEq(ledger.belnapAggregate(_goldenInput()), GOLDEN_OUTPUT);
    }

    function test_belnap_aggregate_fails_closed_without_the_precompile() public {
        vm.expectRevert(FederatedRoundLedger.PrecompileUnavailable.selector);
        ledger.belnapAggregate(_goldenInput());
        vm.expectRevert(FederatedRoundLedger.PrecompileUnavailable.selector);
        ledger.belnapAggregate(hex"0000");
    }
}
