// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {SwitchVerifier} from "./WorkMarketTestBase.sol";

/// @notice Drives WorkMarket through random sequences of every entry point and keeps ghost
///         records for the 0.6.0 planset 06 §7 invariants.
contract WorkMarketHandler is Test {
    WorkMarket public market;
    SwitchVerifier public verifier;
    address public governance;
    address public guardian;

    address[4] internal actors = [address(0xA1), address(0xA2), address(0xA3), address(0xA4)];
    address public poster = address(0x9001);
    uint256 internal constant COORD_KEY = 0xC0FFEE;
    address public coordinator = vm.addr(COORD_KEY);

    uint32 internal constant WINDOW = 24 hours;
    uint8 internal constant DEPTH = 2; // maxWorkers 4: four slots

    /// One slot of the posted tree as the coordinator built it. `idx` is the index hashed into
    /// the leaf (differs from the slot for an out-of-range leaf); `garbage` has no preimage.
    struct Slot {
        address worker;
        uint64 units;
        uint64 cum;
        uint32 idx;
        bool garbage;
    }

    struct Range {
        uint64 lo;
        uint64 hi;
    }

    uint256[] public ids;
    mapping(uint256 => uint128) public priceAtOpen;
    mapping(uint256 => bytes32[]) internal leavesOf;
    mapping(uint256 => Slot[4]) internal slotsOf;
    /// The honest watcher of a malformed tree (the worker the tree cheats) and the slots it has seen.
    mapping(uint256 => address) internal watcherOf;
    mapping(uint256 => bool[4]) internal revealedOf;
    mapping(uint256 => mapping(address => uint256)) public settleCount;
    mapping(bytes32 => Range[]) internal settledRanges; // keccak(id, payoutEpoch)

    // ghost flags: any true is an invariant violation
    bool public postedWithoutAcceptance;
    bool public refundTooEarly;
    bool public pauseBlockedExit;
    bool public settledWhileChallenged;
    bool public overlapSettled;
    bool public malformedRootPaid;
    mapping(uint256 => bool) internal malformedLive;
    uint256 public challengesRaised;
    uint256 public challengesResolved;

    // liveness: the run actually exercised the market (an all-revert run proves nothing)
    uint256 public opens;
    uint256 public opensTriedUnpaused;
    uint256 public posts;
    uint256 public maliciousPosts;
    uint256 public settles;

    constructor(WorkMarket m, SwitchVerifier v, address gov, address guard) {
        market = m;
        verifier = v;
        governance = gov;
        guardian = guard;
        vm.deal(poster, type(uint128).max);
        vm.deal(coordinator, 1e30);
        for (uint256 i = 0; i < 4; i++) {
            vm.deal(actors[i], 1e24);
        }
    }

    function idsLength() external view returns (uint256) {
        return ids.length;
    }

    function actorAt(uint256 i) external view returns (address) {
        return actors[i];
    }

    function _id(uint256 seed) internal view returns (uint256) {
        return ids[seed % ids.length];
    }

    // ── tree helpers ───────────────────────────────────────────────

    function _node(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), l, r));
    }

    function _path(bytes32[] memory leaves, uint256 slot) internal pure returns (bytes32[] memory path) {
        path = new bytes32[](2);
        path[0] = leaves[slot ^ 1];
        path[1] = slot < 2 ? _node(leaves[2], leaves[3]) : _node(leaves[0], leaves[1]);
    }

    /// The opening of `slot` as an honest holder of the tree would present it.
    function _openingAt(uint256 id, uint256 slot) internal view returns (WorkMarket.LeafOpening memory l) {
        Slot memory s = slotsOf[id][slot];
        l = WorkMarket.LeafOpening({
            index: uint32(slot), worker: s.worker, units: s.units, cumBefore: s.cum, path: _path(leavesOf[id], slot)
        });
    }

    function _clearTree(uint256 id) internal {
        delete leavesOf[id];
        delete slotsOf[id];
        delete watcherOf[id];
        delete revealedOf[id];
        delete malformedLive[id];
    }

    // ── actions ────────────────────────────────────────────────────

    function open(uint128 price, uint64 units, uint128 joinBond, uint128 cbond, bool task) external {
        price = uint128(bound(price, 1, 1e21));
        units = uint64(bound(units, 1, 50));
        joinBond = uint128(bound(joinBond, 0, 1e18));
        cbond = uint128(bound(cbond, 0, 1e19));
        WorkMarket.OpenParams memory p = WorkMarket.OpenParams({
            kind: task ? IWorkMarket.Kind.TASK : IWorkMarket.Kind.FL_ROUND,
            verifier: address(verifier),
            bindRef: keccak256(abi.encode(ids.length)),
            jobSpecHash: bytes32(0),
            requirementsHash: bytes32(0),
            requirementsCid: "",
            groupHash: bytes32(0),
            allowlistRoot: bytes32(0),
            pricePerUnit: price,
            deadline: uint64(block.timestamp + 3 days),
            disputeWindow: WINDOW,
            maxWorkers: 4,
            joinBond: joinBond,
            coordinator: coordinator,
            coordinatorBond: cbond,
            disputeAdmin: address(0)
        });
        if (!market.newOffersPaused()) opensTriedUnpaused++;
        vm.prank(poster);
        try market.open{value: uint256(price) * units + price / 2}(p) returns (uint256 id) {
            ids.push(id);
            priceAtOpen[id] = price;
            opens++;
        } catch {}
    }

    /// actorSeed % 5 == 4 joins the coordinator (a TASK's selected worker must have joined).
    function join(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address a = actorSeed % 5 == 4 ? coordinator : actors[actorSeed % 4];
        uint128 bond = market.getOffer(id).joinBond;
        bytes32[] memory none;
        vm.prank(a);
        try market.join{value: bond}(id, 0, none) {} catch {}
    }

    function accept(uint256 seed) external {
        if (ids.length == 0) return;
        verifier.setAccepted(_id(seed), keccak256(abi.encode("digest", seed)));
    }

    /// Posts a payout tree. mode % 4: 0 a well-formed tree over the joined actors (published to
    /// everyone); 1 honest `a` and sybil `b` claim the same range across a garbage separator;
    /// 2 the sybil leaf sits at slot 1 hashed with out-of-range index 5; 3 the same overlap across
    /// a padding slot. In modes 1-3 the coordinator publishes nothing, so the cheated worker `a`
    /// (the watcher) holds only its own leaf and challenges every other index at once.
    function postPayout(uint256 seed, uint64 units, bool acceptFirst, uint8 mode) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (acceptFirst) verifier.setAccepted(id, keccak256(abi.encode("digest", id)));
        WorkMarket.Offer memory o = market.getOffer(id);
        if (o.maxUnits == 0) return;
        units = uint64(bound(units, 1, o.maxUnits));
        mode = mode % 4;

        Slot[4] memory slots;
        uint64 total;
        if (o.kind == IWorkMarket.Kind.TASK) {
            mode = 0;
            slots[0] = Slot(coordinator, 1, 0, 0, false);
            total = 1;
        } else {
            (address a, address b) = (address(0), address(0));
            for (uint256 i = 0; i < 4; i++) {
                if (!market.joined(id, actors[i])) continue;
                if (a == address(0)) a = actors[i];
                else b = actors[i];
            }
            if (b == address(0)) mode = 0;
            if (mode == 0) {
                uint64 left = units;
                uint256 n;
                for (uint256 i = 0; i < 4 && left > 0; i++) {
                    if (!market.joined(id, actors[i])) continue;
                    uint64 u = left / 2 == 0 ? left : left / 2;
                    slots[n] = Slot(actors[i], u, total, uint32(n), false);
                    total += u;
                    left -= u;
                    n++;
                }
                if (total == 0) total = units;
            } else {
                // claim twice the units when the budget allows, so both overlapping leaves fit
                total = uint256(units) * 2 <= o.maxUnits ? units * 2 : units;
                slots[0] = Slot(a, units, 0, 0, false);
                if (mode == 1) {
                    slots[1].garbage = true;
                    slots[2] = Slot(b, units, 0, 2, false);
                } else if (mode == 2) {
                    slots[1] = Slot(b, units, 0, 5, false);
                } else {
                    slots[2] = Slot(b, units, 0, 2, false);
                }
            }
        }

        bytes32[] memory leaves = new bytes32[](4);
        for (uint256 s = 0; s < 4; s++) {
            if (slots[s].garbage) {
                leaves[s] = keccak256(abi.encode("garbage", id, s));
            } else if (slots[s].worker != address(0)) {
                leaves[s] = market.leafHash(
                    slots[s].idx, market.leafPayload(id, slots[s].worker, slots[s].units, slots[s].cum)
                );
            }
        }
        bytes32 root = _node(_node(leaves[0], leaves[1]), _node(leaves[2], leaves[3]));
        (bool ok,) = verifier.accepted(id, o.bindRef);
        vm.prank(coordinator);
        try market.postPayout{value: o.coordinatorBond}(id, root, total, DEPTH) {
            if (!ok) postedWithoutAcceptance = true;
            posts++;
            _clearTree(id);
            leavesOf[id] = leaves;
            for (uint256 s = 0; s < 4; s++) {
                slotsOf[id][s] = slots[s];
            }
            if (mode == 0) {
                revealedOf[id] = [true, true, true, true];
            } else {
                maliciousPosts++;
                malformedLive[id] = true;
                address w = slots[0].worker;
                watcherOf[id] = w;
                revealedOf[id][0] = true;
                for (uint32 s = 1; s < 4; s++) {
                    vm.prank(w);
                    try market.challengeIndex(id, s) {
                        challengesRaised++;
                    } catch {}
                }
            }
        } catch {}
    }

    /// The watcher disputes as soon as two leaves it has seen prove a bad order.
    function _watch(uint256 id) internal {
        address w = watcherOf[id];
        if (w == address(0)) return;
        bool[4] memory seen = revealedOf[id];
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 4; j++) {
                if (!seen[i] || !seen[j]) continue;
                bytes memory ev = abi.encode(uint8(3), abi.encode(_openingAt(id, i), _openingAt(id, j)));
                vm.prank(w);
                try market.dispute(id, ev) {
                    _clearTree(id);
                    return;
                } catch {}
            }
        }
    }

    function settle(uint256 seed, uint256 slotSeed, bool jumpPastWindow) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        bytes32[] memory leaves = leavesOf[id];
        if (leaves.length == 0) return;
        WorkMarket.Offer memory o = market.getOffer(id);
        uint256 opensAt = uint256(o.payoutPostedAt) + o.disputeWindow;
        if (o.answerGraceUntil > opensAt) opensAt = o.answerGraceUntil;
        if (jumpPastWindow && o.payoutPostedAt != 0 && block.timestamp < opensAt) vm.warp(opensAt);
        for (uint256 k = 0; k < 4; k++) {
            uint256 slot = (slotSeed + k) % 4;
            Slot memory s = slotsOf[id][slot];
            if (s.worker == address(0)) continue;
            uint32 openBefore = o.openChallenges;
            try market.settle(id, s.worker, s.units, s.cum, s.idx, _path(leaves, slot)) {
                if (openBefore != 0) settledWhileChallenged = true;
                settleCount[id][s.worker] += 1;
                settles++;
                if (malformedLive[id]) malformedRootPaid = true;
                bytes32 key = keccak256(abi.encode(id, o.payoutEpoch));
                Range[] storage rs = settledRanges[key];
                uint64 lo = s.cum;
                uint64 hi = s.cum + s.units;
                for (uint256 r = 0; r < rs.length; r++) {
                    if (lo < rs[r].hi && rs[r].lo < hi) overlapSettled = true;
                }
                rs.push(Range(lo, hi));
            } catch {}
            return;
        }
    }

    /// The challenger (the worker itself) presents 1..3 coordinator-signed receipts.
    function challenge(uint256 seed, uint256 actorSeed, uint8 count) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address w = actors[actorSeed % 4];
        uint256 n = bound(count, 1, 3);
        WorkMarket.Receipt[] memory rs = new WorkMarket.Receipt[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 lease = bytes32(i + 1);
            bytes32 delta = keccak256(abi.encode(lease));
            bytes32 d = market.receiptDigest(id, w, lease, delta);
            (uint8 v, bytes32 r, bytes32 s_) =
                vm.sign(COORD_KEY, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", d)));
            rs[i] = WorkMarket.Receipt({
                worker: w, leaseId: lease, deltaHash: delta, signature: abi.encodePacked(r, s_, v)
            });
        }
        vm.prank(w);
        try market.challengeInclusion(id, rs) {
            challengesRaised++;
        } catch {}
    }

    /// The coordinator answers a worker challenge whenever the worker's leaf opens.
    function answer(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        address w = actors[actorSeed % 4];
        for (uint256 slot = 0; slot < 4; slot++) {
            Slot memory s = slotsOf[id][slot];
            if (s.worker != w || s.garbage || s.idx != slot) continue;
            vm.prank(coordinator);
            try market.answerChallenge(id, _openingAt(id, slot)) {
                revealedOf[id][slot] = true;
                _watch(id);
            } catch {}
            return;
        }
    }

    function resolve(uint256 seed, uint256 actorSeed, bool jump) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address w = actors[actorSeed % 4];
        WorkMarket.Challenge memory c = market.challengeOf(id, w);
        if (jump && c.open && block.timestamp <= c.answerBy) vm.warp(uint256(c.answerBy) + 1);
        try market.resolveChallenge(id, w) {
            challengesResolved++;
            _clearTree(id);
        } catch {}
    }

    /// Any joined actor (or the poster) challenges one index of the live tree.
    function challengeIdx(uint256 seed, uint256 actorSeed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address a = actorSeed % 5 == 4 ? poster : actors[actorSeed % 4];
        vm.prank(a);
        try market.challengeIndex(id, uint32(slot % 5)) {
            challengesRaised++;
        } catch {}
    }

    /// The coordinator answers an index challenge whenever the slot opens (real or padding).
    function answerIdx(uint256 seed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        uint256 sl = slot % 4;
        Slot memory s = slotsOf[id][sl];
        if (s.garbage || (s.worker != address(0) && s.idx != sl)) return;
        vm.prank(coordinator);
        try market.answerIndexChallenge(id, _openingAt(id, sl)) {
            revealedOf[id][sl] = true;
            _watch(id);
        } catch {}
    }

    function resolveIdx(uint256 seed, uint8 slot, bool jump) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        uint32 sl = uint32(slot % 4);
        WorkMarket.IndexChallenge memory c = market.indexChallengeOf(id, sl);
        if (jump && c.open && block.timestamp <= c.answerBy) vm.warp(uint256(c.answerBy) + 1);
        try market.resolveIndexChallenge(id, sl) {
            challengesResolved++;
            _clearTree(id);
        } catch {}
    }

    function disputeOrder(uint256 seed) external {
        // A subjective-free objective dispute that must fail on well-formed trees.
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        vm.prank(poster);
        try market.dispute(id, abi.encode(uint8(3), bytes(""))) {} catch {}
    }

    function refund(uint256 seed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        WorkMarket.Offer memory o = market.getOffer(id);
        vm.prank(poster);
        try market.refund(id) {
            WorkMarket.Offer memory after_ = market.getOffer(id);
            if (after_.state != IWorkMarket.State.Expired && block.timestamp < uint256(o.deadline) + o.disputeWindow) {
                refundTooEarly = true;
            }
            if (after_.state == IWorkMarket.State.Expired && block.timestamp <= o.deadline) refundTooEarly = true;
        } catch {}
    }

    function claimBond(uint256 seed, uint256 actorSeed, bool asCoordinator) external {
        if (ids.length == 0) return;
        address a = asCoordinator ? coordinator : actors[actorSeed % 4];
        vm.prank(a);
        try market.claimBond(_id(seed)) {} catch {}
    }

    function withdraw(uint256 actorSeed, uint8 who) external {
        address a = who % 3 == 0 ? poster : (who % 3 == 1 ? coordinator : actors[actorSeed % 4]);
        uint256 bal = market.balanceOf(a);
        vm.prank(a);
        try market.withdraw() {}
        catch {
            if (bal != 0) pauseBlockedExit = true;
        }
    }

    function pause(bool byGuardian, bool paused) external {
        vm.prank(byGuardian ? guardian : governance);
        try market.setNewOffersPaused(paused) {} catch {}
    }

    function warp(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 1, 12 hours));
    }

    receive() external payable {}
}

contract WorkMarketInvariantTest is Test {
    WorkMarket internal market;
    SwitchVerifier internal verifier;
    WorkMarketHandler internal handler;

    function setUp() public {
        vm.warp(1_000_000);
        verifier = new SwitchVerifier();
        address[] memory vs = new address[](1);
        vs[0] = address(verifier);
        address gov = makeAddr("gov");
        address guard = makeAddr("guard");
        market = new WorkMarket(gov, guard, 1 ether, vs);
        handler = new WorkMarketHandler(market, verifier, gov, guard);
        targetContract(address(handler));
    }

    /// A run that tried to open an offer while new offers were not paused must have opened one;
    /// otherwise every call reverted and the run proved nothing.
    function afterInvariant() public view {
        if (handler.opensTriedUnpaused() > 0) {
            assertGt(handler.opens(), 0, "no offer opened: the run exercised nothing");
        }
    }

    function _pullTotal() internal view returns (uint256 t) {
        t = market.balanceOf(handler.poster()) + market.balanceOf(handler.coordinator());
        for (uint256 i = 0; i < 4; i++) {
            t += market.balanceOf(handler.actorAt(i));
        }
    }

    /// 06 §7.1: balance held == escrow left + bonds held + pull balances.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_balance_conservation() public view {
        uint256 owed;
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            owed += market.owedOn(handler.ids(i));
        }
        assertEq(address(market).balance, owed + _pullTotal());
    }

    /// 06 §7.2: paid <= budget, and paid == settled units x price.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_paid_le_budget() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            WorkMarket.Offer memory o = market.getOffer(handler.ids(i));
            assertLe(uint256(o.paid) + o.refunded, o.budget);
            assertEq(uint256(o.paid), uint256(o.settledUnits) * o.pricePerUnit);
        }
    }

    /// 06 §7.3: a worker is paid at most once per offer.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_paid_at_most_once() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            for (uint256 a = 0; a < 4; a++) {
                assertLe(handler.settleCount(handler.ids(i), handler.actorAt(a)), 1);
            }
        }
    }

    /// 06 §7.4: no payout is posted unless the verifier accepted.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_no_payout_without_acceptance() public view {
        assertFalse(handler.postedWithoutAcceptance());
    }

    /// 06 §7.5: no refund before deadline + window unless Expired (and Expired only after the deadline).
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_refund_never_early() public view {
        assertFalse(handler.refundTooEarly());
    }

    /// 06 §7.6: price never changes after open.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_price_immutable() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            uint256 id = handler.ids(i);
            assertEq(market.getOffer(id).pricePerUnit, handler.priceAtOpen(id));
        }
    }

    /// Q11: no worker settles while an inclusion challenge is open under the root.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_no_settle_while_challenged() public view {
        assertFalse(handler.settledWhileChallenged());
    }

    /// Q11: open challenges never outnumber the joined workers plus the tree's slots.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_open_challenges_bounded() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            WorkMarket.Offer memory o = market.getOffer(handler.ids(i));
            assertLe(o.openChallenges, uint256(o.workers) + (uint256(1) << o.payoutDepth));
        }
    }

    /// Tree integrity: a posted root never pays out more units than it posted.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_settled_units_le_payout_units() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            WorkMarket.Offer memory o = market.getOffer(handler.ids(i));
            assertLe(o.settledUnits, o.payoutUnits);
        }
    }

    /// Tree integrity: no two leaves settled under one root claim overlapping unit ranges, even
    /// when the coordinator posts malformed trees (sybil overlap behind a garbage leaf, an
    /// out-of-range index, or a padding separator), given a watcher that challenges the slots it
    /// was not shown and disputes as soon as an answer reveals a bad pair.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_settled_leaves_never_overlap() public view {
        assertFalse(handler.overlapSettled());
        assertFalse(handler.malformedRootPaid());
    }

    /// 06 §7.7: pause never stops anyone pulling what they are owed.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_pause_never_blocks_exit() public view {
        assertFalse(handler.pauseBlockedExit());
    }
}
