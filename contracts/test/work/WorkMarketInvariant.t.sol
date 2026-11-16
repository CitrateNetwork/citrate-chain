// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {IWorkMarket} from "../../src/work/IVerifier.sol";
import {SwitchVerifier} from "./WorkMarketTestBase.sol";
import {SignsNothing} from "./WorkMarketHardening.t.sol";

/// @notice Drives WorkMarket through random sequences of every entry point and keeps ghost
///         records for the 0.6.0 planset 06 §7 invariants.
contract WorkMarketHandler is Test {
    WorkMarket public market;
    SwitchVerifier public verifier;
    address public governance;
    address public guardian;

    uint256 public constant ACTORS = 6;
    address[6] internal actors =
        [address(0xA1), address(0xA2), address(0xA3), address(0xA4), address(0xA5), address(0xA6)];
    address public poster = address(0x9001);
    uint256 internal constant COORD_KEY = 0xC0FFEE;
    address public coordinator = vm.addr(COORD_KEY);
    /// A poster that coordinates its own offers (FL only).
    uint256 internal constant PC_KEY = 0xBADC0DE;
    address public pc = vm.addr(PC_KEY);
    /// The colluding side of a self-coordinated offer: the poster `pc`, a second address `pc2`
    /// it may coordinate through, and a sybil worker `pcSy` it joins to every such offer.
    uint256 internal constant PC2_KEY = 0xBADC0DF;
    address public pc2 = vm.addr(PC2_KEY);
    address public pcSy = address(0x5B11);
    mapping(uint256 => address) public posterOf;
    mapping(uint256 => address) public coordOf;
    mapping(uint256 => uint256) internal keyOf;
    // value accounting for the coordinating poster
    uint256 public pcIn; // everything the colluding side sent the market
    uint256 public pcWithdrawn; // everything the colluding side withdrew
    uint256 public pcDismissedEarned; // dismissed challenge bonds paid to pc / pc2 as coordinator
    uint256 public reveals;
    /// The least the colluding side must have lost to upheld slashes of its roots: the sink's
    /// half of each slashed bond (bond - bond * SLASH_DISPUTER_BPS / BPS).
    uint256 public pcMinLoss;

    uint32 internal constant WINDOW = 24 hours;
    uint8 internal constant DEPTH = 3; // maxWorkers 8: eight slots
    uint256 internal constant SLOTS = 8;
    /// Units an offer may buy: past 256, so a leaf can pay more units than any fixed receipt count.
    uint64 internal constant MAX_UNITS = 600;

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
    mapping(uint256 => Slot[8]) internal slotsOf;
    /// The honest watcher of a malformed tree (the worker the tree cheats) and the slots it has seen.
    mapping(uint256 => address) internal watcherOf;
    mapping(uint256 => bool[8]) internal revealedOf;
    /// Slots whose leaf is an honest worker's real claim (receipted work the tree must pay).
    mapping(uint256 => bool[8]) internal honestOf;
    /// A root that short-pays (mode 6) or leaves out (mode 7) a worker holding the coordinator's
    /// receipt for its `owedOf` leases.
    mapping(uint256 => bool) internal receiptCheatLive;
    mapping(uint256 => mapping(address => uint256)) public settleCount;
    mapping(bytes32 => Range[]) internal settledRanges; // keccak(id, payoutEpoch)

    // ghost flags: any true is an invariant violation
    bool public postedWithoutAcceptance;
    bool public refundTooEarly;
    bool public pauseBlockedExit;
    bool public settledWhileChallenged;
    bool public overlapSettled;
    bool public malformedRootPaid;
    bool public honestLeafBlocked;
    /// A root that short-paid or left out a receipted worker paid anyone.
    bool public receiptCheatPaid;
    /// An FL offer opened with a coordinator that has code.
    bool public contractCoordinatorOpened;
    mapping(uint256 => bool) internal malformedLive;
    uint256 public challengesRaised;
    uint256 public challengesResolved;

    // liveness: the run actually exercised the market (an all-revert run proves nothing)
    uint256 public opens;
    uint256 public opensTriedUnpaused;
    uint256 public posts;
    uint256 public maliciousPosts;
    uint256 public settles;
    uint256 public receiptCheats;
    uint256 public receiptRemedies;
    uint256 public coordinatorCodeAdded;

    constructor(WorkMarket m, SwitchVerifier v, address gov, address guard) {
        market = m;
        verifier = v;
        governance = gov;
        guardian = guard;
        vm.deal(poster, type(uint128).max);
        vm.deal(coordinator, 1e30);
        vm.deal(pc, type(uint128).max);
        vm.deal(pc2, 1e30);
        vm.deal(pcSy, 1e24);
        for (uint256 i = 0; i < ACTORS; i++) {
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
        path = new bytes32[](DEPTH);
        bytes32[] memory level = leaves;
        uint256 idx = slot;
        for (uint256 d = 0; d < DEPTH; d++) {
            path[d] = level[idx ^ 1];
            level = _up(level);
            idx >>= 1;
        }
    }

    function _up(bytes32[] memory level) internal pure returns (bytes32[] memory next) {
        next = new bytes32[](level.length / 2);
        for (uint256 i = 0; i < next.length; i++) {
            next[i] = _node(level[2 * i], level[2 * i + 1]);
        }
    }

    function _rootOf(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory level = leaves;
        while (level.length > 1) level = _up(level);
        return level[0];
    }

    /// The coordinator's signed receipt for `w`'s `ordinal`-th verified lease on `id`.
    function _receiptFor(uint256 id, address w, uint64 ordinal) internal view returns (WorkMarket.Receipt memory) {
        bytes32 lease = keccak256(abi.encode("lease", id, w, ordinal));
        bytes32 delta = keccak256(abi.encode(lease));
        bytes32 d = market.receiptDigest(id, w, lease, delta, ordinal);
        (uint8 v, bytes32 r, bytes32 s_) =
            vm.sign(keyOf[id], keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", d)));
        return WorkMarket.Receipt({
            worker: w, leaseId: lease, deltaHash: delta, ordinal: ordinal, signature: abi.encodePacked(r, s_, v)
        });
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
        delete honestOf[id];
        delete malformedLive[id];
        delete receiptCheatLive[id];
    }

    /// Records a slash of pc's bond when an upholding call withdrew a pc root.
    function _snap(uint256 id) internal view returns (uint32 epoch, bool held, uint128 bond) {
        WorkMarket.Offer memory o = market.getOffer(id);
        return (o.payoutEpoch, o.coordinatorBondHeld, o.coordinatorBond);
    }

    function _noteUpheld(uint256 id, uint32 epoch, bool held, uint128 bond) internal {
        if (posterOf[id] != pc || !held) return;
        WorkMarket.Offer memory o = market.getOffer(id);
        if (o.payoutEpoch != epoch && o.state == IWorkMarket.State.Running && !o.coordinatorBondHeld) {
            pcMinLoss += bond - (uint256(bond) * 5000) / 10_000;
        }
    }

    // ── actions ────────────────────────────────────────────────────

    /// `selfCoordinated`: an FL offer whose poster `pc` is also its coordinator.
    function open(uint128 price, uint64 units, uint128 joinBond, uint128 cbond, bool task, bool selfCoordinated)
        external
    {
        price = uint128(bound(price, 1, 1e21));
        units = uint64(bound(units, 1, MAX_UNITS));
        joinBond = uint128(bound(joinBond, market.minJoinBond(), 2e18));
        // 0 takes the default; otherwise at least the market minimum
        if (cbond != 0) cbond = uint128(bound(cbond, market.minCoordinatorBond(), 1e19));
        bool pcMode = selfCoordinated && !task;
        address who = pcMode ? pc : poster;
        // a self-coordinated offer names pc itself or its second address pc2
        address coord = pcMode ? (units % 2 == 0 ? pc : pc2) : coordinator;
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
            maxWorkers: uint32(SLOTS),
            joinBond: joinBond,
            coordinator: coord,
            coordinatorBond: cbond,
            disputeAdmin: address(0)
        });
        if (!market.newOffersPaused()) opensTriedUnpaused++;
        uint256 budget = uint256(price) * units + price / 2;
        vm.prank(who);
        try market.open{value: budget}(p) returns (uint256 id) {
            ids.push(id);
            priceAtOpen[id] = price;
            posterOf[id] = who;
            coordOf[id] = coord;
            keyOf[id] = !pcMode ? COORD_KEY : (coord == pc ? PC_KEY : PC2_KEY);
            if (pcMode) {
                pcIn += budget;
                bytes32[] memory none;
                vm.prank(pcSy);
                try market.join{value: joinBond}(id, 0, none) {
                    pcIn += joinBond;
                } catch {}
            }
            opens++;
        } catch {}
    }

    /// actorSeed % 7 == 6 joins the coordinator (a TASK's selected worker must have joined).
    function join(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address a = actorSeed % 7 == 6 ? coordinator : actors[actorSeed % ACTORS];
        uint128 bond = market.getOffer(id).joinBond;
        bytes32[] memory none;
        vm.prank(a);
        try market.join{value: bond}(id, 0, none) {} catch {}
    }

    function accept(uint256 seed) external {
        if (ids.length == 0) return;
        verifier.setAccepted(_id(seed), keccak256(abi.encode("digest", seed)));
    }

    /// Posts a payout tree. mode % 8: 0 a well-formed tree over the joined actors (published to
    /// everyone); 1 honest `a` and sybil `b` claim the same range across a garbage separator;
    /// 2 the sybil leaf sits at slot 1 hashed with out-of-range index 5; 3 the same overlap across
    /// a padding slot. In modes 1-3 the coordinator publishes nothing, so the cheated worker `a`
    /// (the watcher) holds only its own leaf and challenges every other index at once.
    /// Mode 4: the sybil `a` takes `units` at 0 and honest `b` gets 1 unit at `units`, posted
    /// `units` (the leaves sum past payoutUnits). Mode 5: a well-formed tree over `a` (1 unit)
    /// and `b` (`units`), under-posted by one. In modes 4-5 the watcher is `b`, holding its leaf.
    /// Mode 6: honest `a` did `units` verified leases (it holds the receipt for the last one),
    /// the well-formed tree pays it fewer and gives the rest to the sybil `b`. Mode 7: the tree
    /// pays only the sybil `b` and leaves out honest `a`, which holds a receipt. In modes 6-7
    /// the coordinator's address may gain code (`addCode`) before `a` acts on its receipt.
    function postPayout(uint256 seed, uint64 units, bool acceptFirst, uint8 mode) external {
        _postPayout(seed, units, acceptFirst, mode, false);
    }

    function postPayoutThenAddCode(uint256 seed, uint64 units, uint8 mode) external {
        _postPayout(seed, units, true, 6 + (mode % 2), true);
    }

    function _postPayout(uint256 seed, uint64 units, bool acceptFirst, uint8 mode, bool addCode) internal {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (acceptFirst) verifier.setAccepted(id, keccak256(abi.encode("digest", id)));
        WorkMarket.Offer memory o = market.getOffer(id);
        if (o.maxUnits == 0) return;
        units = uint64(bound(units, 1, o.maxUnits));
        mode = mode % 8;

        Slot[8] memory slots;
        uint64 total;
        if (o.kind == IWorkMarket.Kind.TASK) {
            mode = 0;
            slots[0] = Slot(coordOf[id], 1, 0, 0, false);
            total = 1;
        } else {
            (address a, address b) = (address(0), address(0));
            for (uint256 i = 0; i < ACTORS; i++) {
                if (!market.joined(id, actors[i])) continue;
                if (a == address(0)) a = actors[i];
                else b = actors[i];
            }
            if (b == address(0) || (mode == 6 && units < 2)) mode = 0;
            if (mode == 0) {
                uint64 left = units;
                uint256 n;
                for (uint256 i = 0; i < ACTORS && left > 0; i++) {
                    if (!market.joined(id, actors[i])) continue;
                    uint64 u = left / 2 == 0 ? left : left / 2;
                    slots[n] = Slot(actors[i], u, total, uint32(n), false);
                    total += u;
                    left -= u;
                    n++;
                }
                if (total == 0) total = units;
            } else if (mode == 6) {
                // a is owed `units` (its receipt's ordinal); the tree pays it half, b the rest
                total = units;
                slots[0] = Slot(a, units / 2, 0, 0, false);
                slots[1] = Slot(b, units - units / 2, units / 2, 1, false);
            } else if (mode == 7) {
                // a is owed 1 + units/2 leases but has no leaf; b takes everything
                total = units;
                slots[0] = Slot(b, units, 0, 0, false);
            } else if (mode >= 4) {
                total = units;
                slots[0] = Slot(a, mode == 4 ? units : 1, 0, 0, false);
                slots[1] = Slot(b, mode == 4 ? 1 : units, mode == 4 ? units : 1, 1, false);
            } else {
                // claim twice the units when the budget allows, so both overlapping leaves fit
                total = uint256(units) * 2 <= o.maxUnits ? units * 2 : units;
                slots[0] = Slot(a, units, 0, 0, false);
                if (mode == 1) {
                    slots[1].garbage = true;
                    slots[2] = Slot(b, units, 0, 2, false);
                } else if (mode == 2) {
                    slots[1] = Slot(b, units, 0, 9, false); // index 9 is past the 8 slots
                } else {
                    slots[2] = Slot(b, units, 0, 2, false);
                }
            }
        }

        bytes32[] memory leaves = new bytes32[](SLOTS);
        for (uint256 s = 0; s < SLOTS; s++) {
            if (slots[s].garbage) {
                leaves[s] = keccak256(abi.encode("garbage", id, s));
            } else if (slots[s].worker != address(0)) {
                leaves[s] = market.leafHash(
                    slots[s].idx, market.leafPayload(id, slots[s].worker, slots[s].units, slots[s].cum)
                );
            }
        }
        bytes32 root = _rootOf(leaves);
        (bool ok,) = verifier.accepted(id, o.bindRef);
        uint128 chBond = market.challengeBondOf(id);
        vm.prank(coordOf[id]);
        try market.postPayout{value: o.coordinatorBond}(id, root, total, DEPTH) {
            if (posterOf[id] == pc) pcIn += o.coordinatorBond;
            if (!ok) postedWithoutAcceptance = true;
            posts++;
            _clearTree(id);
            leavesOf[id] = leaves;
            for (uint256 s = 0; s < SLOTS; s++) {
                slotsOf[id][s] = slots[s];
            }
            if (mode == 0) {
                for (uint256 s = 0; s < SLOTS; s++) {
                    revealedOf[id][s] = true;
                    honestOf[id][s] = slots[s].worker != address(0);
                }
            } else if (mode >= 6) {
                // the cheated worker sorts first among the joined actors
                address a = mode == 6 ? slots[0].worker : address(0);
                for (uint256 i = 0; i < ACTORS && a == address(0); i++) {
                    if (market.joined(id, actors[i])) a = actors[i];
                }
                uint64 owed = mode == 6 ? total : 1 + total / 2;
                receiptCheats++;
                receiptCheatLive[id] = true;
                for (uint256 s = 0; s < SLOTS; s++) {
                    revealedOf[id][s] = true;
                }
                if (addCode) _addCode(coordOf[id]);
                _watchReceipt(id, a, owed, uint256(keccak256(abi.encode(seed, units))));
            } else if (mode >= 4) {
                maliciousPosts++;
                malformedLive[id] = true;
                watcherOf[id] = slots[1].worker;
                revealedOf[id][1] = true;
                honestOf[id][1] = true;
                if (mode == 5) {
                    revealedOf[id][0] = true;
                    honestOf[id][0] = true;
                }
                _watch(id);
            } else {
                maliciousPosts++;
                malformedLive[id] = true;
                address w = slots[0].worker;
                watcherOf[id] = w;
                revealedOf[id][0] = true;
                honestOf[id][0] = true;
                for (uint32 s = 1; s < SLOTS; s++) {
                    vm.prank(w);
                    try market.challengeIndex{value: chBond}(id, s) {
                        challengesRaised++;
                    } catch {}
                }
            }
        } catch {}
    }

    /// The watcher disputes as soon as a leaf it has seen breaks the posted total, or two leaves
    /// it has seen prove a bad order.
    function _watch(uint256 id) internal {
        address w = watcherOf[id];
        if (w == address(0)) return;
        bool[8] memory seen = revealedOf[id];
        for (uint256 i = 0; i < SLOTS; i++) {
            if (!seen[i] || slotsOf[id][i].worker == address(0)) continue;
            WorkMarket.LeafOpening memory next;
            if (i + 1 < SLOTS) next = _openingAt(id, i + 1);
            bytes memory tev = abi.encode(uint8(6), abi.encode(_openingAt(id, i), next));
            if (id % 2 == 0 && _commitReveal(id, w, tev)) return;
            if (leavesOf[id].length == 0) return;
            (uint32 ep, bool held, uint128 bond) = _snap(id);
            vm.prank(w);
            try market.dispute(id, tev) {
                _noteUpheld(id, ep, held, bond);
                _clearTree(id);
                return;
            } catch {}
        }
        for (uint256 i = 0; i < SLOTS; i++) {
            for (uint256 j = i + 1; j < SLOTS; j++) {
                if (!seen[i] || !seen[j]) continue;
                bytes memory ev = abi.encode(uint8(3), abi.encode(_openingAt(id, i), _openingAt(id, j)));
                (uint32 ep, bool held, uint128 bond) = _snap(id);
                vm.prank(w);
                try market.dispute(id, ev) {
                    _noteUpheld(id, ep, held, bond);
                    _clearTree(id);
                    return;
                } catch {}
            }
        }
    }

    /// The coordinator's address gains code that answers every EIP-1271 query with "not signed"
    /// (a CREATE2 address deployed later, or a delegated key). Its key's receipts must still count.
    function _addCode(address c) internal {
        if (c.code.length != 0) return;
        vm.etch(c, type(SignsNothing).runtimeCode);
        coordinatorCodeAdded++;
    }

    /// A coordinator address that gained code drops it again (so new FL offers can name it).
    function dropCoordinatorCode(uint256 who) external {
        address c = who % 3 == 0 ? coordinator : (who % 3 == 1 ? pc : pc2);
        vm.etch(c, "");
    }

    function addCoordinatorCode(uint256 who) external {
        if (opens == 0) return; // let the run open offers first
        _addCode(who % 3 == 0 ? coordinator : (who % 3 == 1 ? pc : pc2));
    }

    /// The cheated worker `a` holds the coordinator's receipt for its `owed`-th lease and uses it
    /// at once: a LOW_UNITS (mode 6) or MISSING_LEAF (mode 7) dispute, directly or by
    /// commit-reveal, or an inclusion challenge that the root cannot answer.
    function _watchReceipt(uint256 id, address a, uint64 owed, uint256 how) internal {
        WorkMarket.Receipt memory r = _receiptFor(id, a, owed);
        Slot memory s0 = slotsOf[id][0];
        bytes memory ev;
        if (s0.worker == a) {
            ev = abi.encode(uint8(2), abi.encode(_openingAt(id, 0), r)); // LOW_UNITS
        } else {
            WorkMarket.LeafOpening memory none;
            ev = abi.encode(uint8(1), abi.encode(r, uint8(1), none, _openingAt(id, 0))); // ABSENT_BEFORE_FIRST
        }
        how %= 3;
        (uint32 ep, bool held, uint128 bond) = _snap(id);
        if (how == 0) {
            vm.prank(a);
            try market.dispute(id, ev) {
                _noteUpheld(id, ep, held, bond);
                receiptRemedies++;
                _clearTree(id);
            } catch {}
        } else if (how == 1) {
            if (_commitReveal(id, a, ev)) receiptRemedies++;
        } else {
            uint128 chBond = market.challengeBondOf(id);
            vm.prank(a);
            try market.challengeInclusion{value: chBond}(id, r) {
                challengesRaised++;
                receiptRemedies++;
            } catch {}
        }
    }

    /// Tries to open an FL offer whose coordinator is a contract; it must be refused.
    function openWithContractCoordinator(uint128 price) external {
        price = uint128(bound(price, 1, 1e21));
        address c = address(new SignsNothing());
        WorkMarket.OpenParams memory p = WorkMarket.OpenParams({
            kind: IWorkMarket.Kind.FL_ROUND,
            verifier: address(verifier),
            bindRef: keccak256(abi.encode("contract coordinator", ids.length)),
            jobSpecHash: bytes32(0),
            requirementsHash: bytes32(0),
            requirementsCid: "",
            groupHash: bytes32(0),
            allowlistRoot: bytes32(0),
            pricePerUnit: price,
            deadline: uint64(block.timestamp + 3 days),
            disputeWindow: WINDOW,
            maxWorkers: uint32(SLOTS),
            joinBond: market.minJoinBond(),
            coordinator: c,
            coordinatorBond: 0,
            disputeAdmin: address(0)
        });
        vm.prank(poster);
        try market.open{value: price}(p) returns (uint256) {
            contractCoordinatorOpened = true;
        } catch {}
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
        for (uint256 k = 0; k < SLOTS; k++) {
            uint256 slot = (slotSeed + k) % SLOTS;
            Slot memory s = slotsOf[id][slot];
            if (s.worker == address(0)) continue;
            uint32 openBefore = o.openChallenges;
            try market.settle(id, s.worker, s.units, s.cum, s.idx, _path(leaves, slot)) {
                if (openBefore != 0) settledWhileChallenged = true;
                settleCount[id][s.worker] += 1;
                settles++;
                if (malformedLive[id]) malformedRootPaid = true;
                if (receiptCheatLive[id]) receiptCheatPaid = true;
                bytes32 key = keccak256(abi.encode(id, o.payoutEpoch));
                Range[] storage rs = settledRanges[key];
                uint64 lo = s.cum;
                uint64 hi = s.cum + s.units;
                for (uint256 r = 0; r < rs.length; r++) {
                    if (lo < rs[r].hi && rs[r].lo < hi) overlapSettled = true;
                }
                rs.push(Range(lo, hi));
            } catch (bytes memory err) {
                // an honest leaf of a live, undisputed root must always settle once it may
                bytes4 sel = bytes4(err);
                if (
                    honestOf[id][slot]
                        && (sel == WorkMarket.ExceedsPayout.selector || sel == WorkMarket.BadProof.selector)
                ) honestLeafBlocked = true;
            }
            return;
        }
    }

    /// The challenger (the worker itself) presents the coordinator's receipt for its 1st..3rd lease.
    function challenge(uint256 seed, uint256 actorSeed, uint8 count) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address w = actors[actorSeed % ACTORS];
        uint64 n = uint64(bound(count, 1, 3));
        bytes32 lease = bytes32(uint256(n));
        bytes32 delta = keccak256(abi.encode(lease));
        bytes32 d = market.receiptDigest(id, w, lease, delta, n);
        (uint8 v, bytes32 r, bytes32 s_) =
            vm.sign(keyOf[id], keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", d)));
        WorkMarket.Receipt memory rc = WorkMarket.Receipt({
            worker: w, leaseId: lease, deltaHash: delta, ordinal: n, signature: abi.encodePacked(r, s_, v)
        });
        uint128 chBond = market.challengeBondOf(id);
        vm.prank(w);
        try market.challengeInclusion{value: chBond}(id, rc) {
            challengesRaised++;
        } catch {}
    }

    /// The coordinator answers a worker challenge whenever the worker's leaf opens.
    function answer(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        address w = actors[actorSeed % ACTORS];
        for (uint256 slot = 0; slot < SLOTS; slot++) {
            Slot memory s = slotsOf[id][slot];
            if (s.worker != w || s.garbage || s.idx != slot) continue;
            vm.prank(coordOf[id]);
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
        address w = actors[actorSeed % ACTORS];
        WorkMarket.Challenge memory c = market.challengeOf(id, w);
        if (jump && c.open && block.timestamp <= c.answerBy) vm.warp(uint256(c.answerBy) + 1);
        (uint32 ep, bool held, uint128 bond) = _snap(id);
        try market.resolveChallenge(id, w) {
            _noteUpheld(id, ep, held, bond);
            challengesResolved++;
            _clearTree(id);
        } catch {}
    }

    /// Any joined actor (or the poster) challenges one index of the live tree.
    function challengeIdx(uint256 seed, uint256 actorSeed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address a = actorSeed % 7 == 6 ? posterOf[id] : actors[actorSeed % ACTORS];
        uint128 chBond = market.challengeBondOf(id);
        vm.prank(a);
        try market.challengeIndex{value: chBond}(id, uint32(slot % (SLOTS + 1))) {
            if (a == pc) pcIn += chBond;
            challengesRaised++;
        } catch {}
    }

    /// The coordinator answers an index challenge whenever the slot opens (real or padding).
    function answerIdx(uint256 seed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        uint256 sl = slot % SLOTS;
        Slot memory s = slotsOf[id][sl];
        if (s.garbage || (s.worker != address(0) && s.idx != sl)) return;
        vm.prank(coordOf[id]);
        try market.answerIndexChallenge(id, _openingAt(id, sl)) {
            revealedOf[id][sl] = true;
            _watch(id);
        } catch {}
    }

    function resolveIdx(uint256 seed, uint8 slot, bool jump) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        uint32 sl = uint32(slot % SLOTS);
        WorkMarket.IndexChallenge memory c = market.indexChallengeOf(id, sl);
        if (jump && c.open && block.timestamp <= c.answerBy) vm.warp(uint256(c.answerBy) + 1);
        (uint32 ep, bool held, uint128 bond) = _snap(id);
        try market.resolveIndexChallenge(id, sl) {
            _noteUpheld(id, ep, held, bond);
            challengesResolved++;
            _clearTree(id);
        } catch {}
    }

    /// Releases challenge bonds: to the challenger when the root was withdrawn, to the
    /// coordinator once an answered challenge's root survived.
    function release(uint256 seed, uint256 actorSeed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        uint256 before = _colluders();
        try market.releaseChallengeBond(id, actors[actorSeed % ACTORS]) {} catch {}
        try market.releaseIndexChallengeBond(id, uint32(slot % SLOTS)) {} catch {}
        if (posterOf[id] == pc) pcDismissedEarned += _colluders() - before;
    }

    function _colluders() internal view returns (uint256) {
        return market.balanceOf(pc) + market.balanceOf(pc2) + market.balanceOf(pcSy);
    }

    function colluderBalances() external view returns (uint256) {
        return _colluders();
    }

    /// The coordinating poster's sybil worker commits and reveals a dispute against the poster's
    /// own root (TOTAL or ORDER over the stored tree), e.g. right after it was posted.
    function sybilDispute(uint256 seed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (posterOf[id] != pc || leavesOf[id].length == 0) return;
        uint256 i = slot % SLOTS;
        WorkMarket.LeafOpening memory next;
        if (i + 1 < SLOTS) next = _openingAt(id, i + 1);
        bytes memory ev = slot % 2 == 0
            ? abi.encode(uint8(6), abi.encode(_openingAt(id, i), next))
            : abi.encode(uint8(3), abi.encode(_openingAt(id, i), next));
        _commitReveal(id, pcSy, ev);
    }

    /// A joined actor commits to TOTAL or ORDER evidence over leaves it has seen, waits the
    /// reveal delay and reveals.
    function commitReveal(uint256 seed, uint256 actorSeed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        address a = actors[actorSeed % ACTORS];
        uint256 i = slot % SLOTS;
        WorkMarket.LeafOpening memory next;
        if (i + 1 < SLOTS) next = _openingAt(id, i + 1);
        bytes memory ev = slot % 2 == 0
            ? abi.encode(uint8(6), abi.encode(_openingAt(id, i), next))
            : abi.encode(uint8(3), abi.encode(_openingAt(id, i), next));
        _commitReveal(id, a, ev);
    }

    function _commitReveal(uint256 id, address a, bytes memory ev) internal returns (bool ok) {
        bytes32 salt = keccak256(abi.encode(id, a, ev));
        bytes32 c = market.disputeCommitment(id, market.getOffer(id).payoutEpoch, a, ev, salt);
        vm.prank(a);
        try market.commitDispute(id, c) {}
        catch {
            return false;
        }
        vm.warp(block.timestamp + market.DISPUTE_REVEAL_DELAY());
        (uint32 ep, bool held, uint128 bond) = _snap(id);
        vm.prank(a);
        try market.revealDispute(id, ev, salt) {
            _noteUpheld(id, ep, held, bond);
            reveals++;
            _clearTree(id);
            return true;
        } catch {}
    }

    /// The poster (as coordinator: the party at fault) disputes its own root directly with any
    /// TOTAL or ORDER evidence over the stored tree, e.g. on seeing a worker's commitment.
    function selfDispute(uint256 seed, uint8 slot) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (leavesOf[id].length == 0) return;
        uint256 i = slot % SLOTS;
        WorkMarket.LeafOpening memory next;
        if (i + 1 < SLOTS) next = _openingAt(id, i + 1);
        bytes memory ev = slot % 2 == 0
            ? abi.encode(uint8(6), abi.encode(_openingAt(id, i), next))
            : abi.encode(uint8(3), abi.encode(_openingAt(id, i), next));
        (uint32 ep, bool held, uint128 bond) = _snap(id);
        vm.prank(posterOf[id]);
        try market.dispute(id, ev) {
            _noteUpheld(id, ep, held, bond);
            _clearTree(id);
        } catch {}
    }

    function disputeOrder(uint256 seed) external {
        // A subjective-free objective dispute that must fail on well-formed trees.
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        vm.prank(posterOf[id]);
        try market.dispute(id, abi.encode(uint8(3), bytes(""))) {} catch {}
    }

    function refund(uint256 seed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        WorkMarket.Offer memory o = market.getOffer(id);
        vm.prank(posterOf[id]);
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
        uint256 id = _id(seed);
        address a = asCoordinator ? coordOf[id] : actors[actorSeed % ACTORS];
        vm.prank(a);
        try market.claimBond(id) {} catch {}
    }

    function withdraw(uint256 actorSeed, uint8 who) external {
        uint8 k = who % 7;
        address a = k == 0 ? poster : (k == 1 ? coordinator : (k == 2 ? pc : actors[actorSeed % ACTORS]));
        if (k == 4) a = market.slashSink();
        if (k == 5) a = pc2;
        if (k == 6) a = pcSy;
        uint256 bal = market.balanceOf(a);
        vm.prank(a);
        try market.withdraw() {
            if (a == pc || a == pc2 || a == pcSy) pcWithdrawn += bal;
        } catch {
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
        market = new WorkMarket(gov, guard, makeAddr("slashSink"), 1 ether, 1 ether, 1 ether, vs);
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

    /// The handler reaches the receipt paths it is meant to: a leaf short-paid past 256 units, a
    /// left-out worker after the coordinator's address gained code, and a contract coordinator
    /// (refused). Each remedy lands and the market stays balanced.
    function test_handler_reaches_the_receipt_paths() public {
        handler.open(1 ether, 600, 1 ether, 0, false, false);
        handler.join(0, 0);
        handler.join(0, 1);
        handler.postPayout(0, 400, true, 6); // owed 400, the leaf pays 200
        assertEq(handler.receiptCheats(), 1);
        assertEq(handler.receiptRemedies(), 1);

        handler.open(1 ether, 50, 1 ether, 0, false, false);
        handler.join(1, 0);
        handler.join(1, 1);
        handler.postPayoutThenAddCode(1, 5, 1); // left out, then the coordinator gains code
        assertGt(handler.coordinator().code.length, 0);
        assertEq(handler.coordinatorCodeAdded(), 1);
        assertEq(handler.receiptRemedies(), 2);

        handler.openWithContractCoordinator(1 ether);
        assertFalse(handler.contractCoordinatorOpened());
        invariant_balance_conservation();
        invariant_receipted_work_is_never_short_paid();
    }

    /// Deterministic past-256 short pay through the handler: a worker owed 600 units whose leaf pays
    /// 300 (both above 256) acts on its one receipt, the short root is withdrawn and never pays.
    function test_handler_short_pay_past_256_units_is_disputed_and_never_settles() public {
        handler.open(1 ether, 600, 1 ether, 0, false, false);
        handler.join(0, 0);
        handler.join(0, 1);
        uint256 id = handler.ids(0);
        handler.postPayout(0, 600, true, 6); // owed 600 (the receipt's ordinal), the leaf pays 300
        assertEq(handler.receiptCheats(), 1);
        assertEq(handler.receiptRemedies(), 1, "the receipt for lease 600 lands");
        WorkMarket.Offer memory o = market.getOffer(id);
        if (o.state == IWorkMarket.State.PayoutPosted) {
            // the inclusion-challenge remedy: the root cannot answer, so it is upheld after answerBy
            assertEq(o.openChallenges, 1);
            handler.resolve(0, 0, true);
            o = market.getOffer(id);
        }
        assertEq(uint8(o.state), uint8(IWorkMarket.State.Running), "the short root is withdrawn");
        assertEq(o.payoutRoot, bytes32(0));
        handler.settle(0, 0, true);
        assertEq(handler.settles(), 0, "nothing settles under the withdrawn root");
        invariant_receipted_work_is_never_short_paid();
        invariant_balance_conservation();
    }

    function _pullTotal() internal view returns (uint256 t) {
        t = market.balanceOf(handler.poster()) + market.balanceOf(handler.coordinator())
            + market.balanceOf(handler.pc()) + market.balanceOf(market.slashSink()) + market.balanceOf(handler.pc2())
            + market.balanceOf(handler.pcSy());
        for (uint256 i = 0; i < handler.ACTORS(); i++) {
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
            for (uint256 a = 0; a < handler.ACTORS(); a++) {
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

    /// Tree totals: an honest worker's leaf in a live root always settles (never ExceedsPayout or
    /// BadProof), including when the coordinator posts leaves summing past payoutUnits or
    /// under-posts payoutUnits, given a watcher that disputes with the leaf it holds.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_honest_leaf_always_settles() public view {
        assertFalse(handler.honestLeafBlocked());
    }

    /// Slash rules (owner 2026-11-09, Q4 revised): a poster that coordinates its own offers, in
    /// its own name or through a second address, and keeps a sybil worker, never ends with more
    /// than it put in, apart from dismissed challenge bonds earned as coordinator of a surviving
    /// root (the documented withholding remainder), and loses at least the sink's half of every
    /// bond slashed by an upheld dispute against its roots.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_coordinating_poster_never_profits() public view {
        assertLe(
            handler.colluderBalances() + handler.pcWithdrawn() + handler.pcMinLoss(),
            handler.pcIn() + handler.pcDismissedEarned()
        );
    }

    /// Receipts: a root that short-pays a worker holding the coordinator's receipt for
    /// more leases than its leaf pays (at any unit count, past 256 included), or that leaves out a
    /// receipted worker, never pays anyone, given that worker acts on its receipt at once (dispute,
    /// commit-reveal or inclusion challenge), even when the coordinator's address gains code
    /// in between.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_receipted_work_is_never_short_paid() public view {
        assertFalse(handler.receiptCheatPaid());
    }

    /// An FL offer's coordinator is never a contract at open (its receipts must be ECDSA).
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_no_fl_offer_has_a_contract_coordinator() public view {
        assertFalse(handler.contractCoordinatorOpened());
    }

    /// 06 §7.7: pause never stops anyone pulling what they are owed.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_pause_never_blocks_exit() public view {
        assertFalse(handler.pauseBlockedExit());
    }
}
