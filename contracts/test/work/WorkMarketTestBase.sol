// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IVerifier, IWorkMarket} from "../../src/work/IVerifier.sol";

/// @notice TEST DOUBLE verifier: the test decides when an offer's work counts as verified. The
///         real verifiers (FLRoundVerifier over FederatedRoundLedger, TaskVerifier) have their own
///         suites and an end-to-end path in WorkMarketVerifiers.t.sol.
contract SwitchVerifier is IVerifier {
    mapping(uint256 => bytes32) public digestOf;

    function setAccepted(uint256 offerId, bytes32 digest) external {
        digestOf[offerId] = digest;
    }

    function accepted(uint256 offerId, bytes32) external view returns (bool, bytes32) {
        bytes32 d = digestOf[offerId];
        return (d != bytes32(0), d);
    }
}

/// @notice A worker contract that tries to re-enter `withdraw` when paid.
contract ReenteringWorker {
    WorkMarket internal market;
    uint256 public reentries;

    constructor(WorkMarket m) {
        market = m;
    }

    function joinOffer(uint256 id, uint128 minPrice) external payable {
        bytes32[] memory none;
        market.join{value: msg.value}(id, minPrice, none);
    }

    function pull() external {
        market.withdraw();
    }

    receive() external payable {
        if (reentries == 0) {
            reentries = 1;
            try market.withdraw() {} catch {}
        }
    }
}

abstract contract WorkMarketTestBase is Test {
    WorkMarket internal market;
    SwitchVerifier internal verifier;

    address internal governance = makeAddr("governance");
    address internal guardian = makeAddr("guardian");
    address internal poster = makeAddr("poster");
    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");
    /// The governance treasury stand-in that receives slashes the poster must not take back.
    address internal SINK = makeAddr("slashSink");
    uint128 internal constant MINBOND = 0.1 ether;
    uint256 internal coordKey = 0xC00D;
    address internal coordinator;

    uint128 internal constant PRICE = 1 ether;
    uint128 internal constant BUDGET = 10 ether;
    uint32 internal constant WINDOW = 24 hours;
    uint128 internal constant CBOND = 2 ether;
    /// Challenge bond for CBOND offers: CHALLENGE_BOND_BPS (10 %) of the coordinator bond.
    uint128 internal constant CHBOND = 0.2 ether;
    bytes32 internal constant BIND = keccak256("bind");
    bytes32 internal constant DIGEST = keccak256("digest");

    // Sorted worker addresses used across suites.
    address internal w1 = address(0x1001);
    address internal w2 = address(0x2002);
    address internal w3 = address(0x3003);

    struct Entry {
        address worker;
        uint64 units;
    }

    function setUp() public virtual {
        coordinator = vm.addr(coordKey);
        verifier = new SwitchVerifier();
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        market = new WorkMarket(governance, guardian, SINK, 1 ether, MINBOND, vs);
        vm.deal(poster, 1_000_000 ether);
        vm.deal(coordinator, 1_000 ether);
        vm.deal(w1, 100 ether);
        vm.deal(w2, 100 ether);
        vm.deal(w3, 100 ether);
        vm.deal(stranger, 100 ether);
        vm.warp(1_000_000);
    }

    // ── offer helpers ──────────────────────────────────────────────

    function _params(IWorkMarket.Kind kind) internal view returns (WorkMarket.OpenParams memory p) {
        p = WorkMarket.OpenParams({
            kind: kind,
            verifier: address(verifier),
            bindRef: BIND,
            jobSpecHash: keccak256("job"),
            requirementsHash: keccak256("req"),
            requirementsCid: "bafy-req",
            groupHash: bytes32(0),
            allowlistRoot: bytes32(0),
            pricePerUnit: PRICE,
            deadline: uint64(block.timestamp + 7 days),
            disputeWindow: WINDOW,
            maxWorkers: 16,
            joinBond: 0,
            coordinator: coordinator,
            coordinatorBond: CBOND,
            disputeAdmin: address(0)
        });
    }

    function _open(WorkMarket.OpenParams memory p, uint256 budget) internal returns (uint256 id) {
        vm.prank(poster);
        id = market.open{value: budget}(p);
    }

    function _openFl() internal returns (uint256) {
        return _open(_params(IWorkMarket.Kind.FL_ROUND), BUDGET);
    }

    function _join(uint256 id, address w) internal {
        bytes32[] memory none;
        uint128 bond = market.getOffer(id).joinBond;
        vm.prank(w);
        market.join{value: bond}(id, 0, none);
    }

    function _accept(uint256 id) internal {
        verifier.setAccepted(id, DIGEST);
    }

    /// Posts an arbitrary root at depth 0 (tests that never open a leaf).
    function _post(uint256 id, bytes32 root, uint64 units) internal {
        vm.prank(coordinator);
        market.postPayout{value: CBOND}(id, root, units, 0);
    }

    /// Posts the tree over `leaves` (length 2^depth) at its depth.
    function _postTree(uint256 id, bytes32[] memory leaves, uint64 units) internal {
        vm.prank(coordinator);
        market.postPayout{value: CBOND}(id, _rootOf(leaves), units, uint8(_depthFor(leaves.length)));
    }

    // ── payout tree (mirrors WorkMarket's leaf/node rules) ─────────

    function _node(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), l, r));
    }

    function _depthFor(uint256 n) internal pure returns (uint256 d) {
        while ((uint256(1) << d) < n) d++;
    }

    /// Builds leaves for `entries` in the given order with prefix sums, padded to 2^depth.
    /// `cumOverride`, if non-empty, replaces the computed prefix sums (for malformed trees).
    function _leaves(uint256 id, Entry[] memory entries, uint64[] memory cumOverride, uint256 depth)
        internal
        view
        returns (bytes32[] memory leaves, uint64[] memory cums)
    {
        uint256 size = uint256(1) << depth;
        leaves = new bytes32[](size);
        cums = new uint64[](entries.length);
        uint64 cum;
        for (uint256 i = 0; i < entries.length; i++) {
            cums[i] = cumOverride.length > 0 ? cumOverride[i] : cum;
            leaves[i] = market.leafHash(uint32(i), market.leafPayload(id, entries[i].worker, entries[i].units, cums[i]));
            cum += entries[i].units;
        }
    }

    function _rootOf(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; i++) {
                next[i] = _node(level[2 * i], level[2 * i + 1]);
            }
            level = next;
        }
        return level[0];
    }

    function _proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory path) {
        uint256 depth = _depthFor(leaves.length);
        path = new bytes32[](depth);
        bytes32[] memory level = leaves;
        uint256 idx = index;
        for (uint256 d = 0; d < depth; d++) {
            path[d] = level[idx ^ 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; i++) {
                next[i] = _node(level[2 * i], level[2 * i + 1]);
            }
            level = next;
            idx >>= 1;
        }
    }

    function _entries3() internal view returns (Entry[] memory e) {
        e = new Entry[](3);
        e[0] = Entry(w1, 2);
        e[1] = Entry(w2, 3);
        e[2] = Entry(w3, 1);
    }

    function _noOverride() internal pure returns (uint64[] memory none) {}

    function _opening(bytes32[] memory leaves, uint256 index, Entry memory e, uint64 cum)
        internal
        pure
        returns (WorkMarket.LeafOpening memory l)
    {
        l = WorkMarket.LeafOpening({
            index: uint32(index), worker: e.worker, units: e.units, cumBefore: cum, path: _proof(leaves, index)
        });
    }

    function _padding(bytes32[] memory leaves, uint256 index) internal pure returns (WorkMarket.LeafOpening memory l) {
        l = WorkMarket.LeafOpening({
            index: uint32(index), worker: address(0), units: 0, cumBefore: 0, path: _proof(leaves, index)
        });
    }

    function _receipt(uint256 id, address worker, bytes32 leaseId) internal view returns (WorkMarket.Receipt memory r) {
        bytes32 d = market.receiptDigest(id, worker, leaseId, keccak256(abi.encode("delta", leaseId)));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", d));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(coordKey, eth);
        r = WorkMarket.Receipt({
            worker: worker,
            leaseId: leaseId,
            deltaHash: keccak256(abi.encode("delta", leaseId)),
            signature: abi.encodePacked(rr, s, v)
        });
    }

    /// Opens an FL offer, joins w1..w3, accepts, posts the 3-entry tree; returns id and leaves.
    function _postedFl3() internal returns (uint256 id, bytes32[] memory leaves) {
        id = _openFl();
        _join(id, w1);
        _join(id, w2);
        _join(id, w3);
        _accept(id);
        (leaves,) = _leaves(id, _entries3(), _noOverride(), 2);
        _postTree(id, leaves, 6);
    }

    function _settle(uint256 id, bytes32[] memory leaves, uint256 index, Entry memory e, uint64 cum) internal {
        market.settle(id, e.worker, e.units, cum, uint32(index), _proof(leaves, index));
    }
}
