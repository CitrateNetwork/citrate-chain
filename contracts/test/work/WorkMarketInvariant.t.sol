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

    uint256[] public ids;
    mapping(uint256 => uint128) public priceAtOpen;
    mapping(uint256 => bytes32[]) internal leavesOf;
    mapping(uint256 => uint64[]) internal unitsOf; // per actor index in the posted tree
    mapping(uint256 => mapping(address => uint256)) public settleCount;

    // ghost flags: any true is an invariant violation
    bool public postedWithoutAcceptance;
    bool public refundTooEarly;
    bool public pauseBlockedExit;
    bool public settledWhileChallenged;
    uint256 public challengesRaised;
    uint256 public challengesResolved;

    // liveness: the run actually exercised the market (an all-revert run proves nothing)
    uint256 public opens;
    uint256 public opensTriedUnpaused;
    uint256 public posts;
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

    function join(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address a = actors[actorSeed % 4];
        uint128 bond = market.getOffer(id).joinBond;
        bytes32[] memory none;
        vm.prank(a);
        try market.join{value: bond}(id, 0, none) {} catch {}
    }

    function accept(uint256 seed) external {
        if (ids.length == 0) return;
        verifier.setAccepted(_id(seed), keccak256(abi.encode("digest", seed)));
    }

    /// Posts a well-formed tree over the joined actors, splitting `units` among them.
    function postPayout(uint256 seed, uint64 units, bool acceptFirst) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        if (acceptFirst) verifier.setAccepted(id, keccak256(abi.encode("digest", id)));
        WorkMarket.Offer memory o = market.getOffer(id);
        if (o.maxUnits == 0) return;
        units = uint64(bound(units, 1, o.maxUnits));
        if (o.kind == IWorkMarket.Kind.TASK) units = 1;

        bytes32[] memory leaves = new bytes32[](4);
        uint64[] memory per = new uint64[](4);
        uint64 left = units;
        uint64 cum;
        uint256 n;
        for (uint256 i = 0; i < 4 && left > 0; i++) {
            if (!market.joined(id, actors[i])) continue;
            uint64 u = (o.kind == IWorkMarket.Kind.TASK) ? 1 : (left / 2 == 0 ? left : left / 2);
            per[i] = u;
            leaves[n] = market.leafHash(uint32(n), market.leafPayload(id, actors[i], u, cum));
            cum += u;
            left -= u;
            n++;
        }
        bytes32 root = keccak256(
            abi.encodePacked(
                bytes1(0x01),
                keccak256(abi.encodePacked(bytes1(0x01), leaves[0], leaves[1])),
                keccak256(abi.encodePacked(bytes1(0x01), leaves[2], leaves[3]))
            )
        );
        (bool ok,) = verifier.accepted(id, o.bindRef);
        vm.prank(coordinator);
        try market.postPayout{value: o.coordinatorBond}(id, root, cum == 0 ? units : cum) {
            if (!ok) postedWithoutAcceptance = true;
            posts++;
            leavesOf[id] = leaves;
            unitsOf[id] = per;
        } catch {}
    }

    function settle(uint256 seed, uint256 actorSeed, bool jumpPastWindow) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        bytes32[] memory leaves = leavesOf[id];
        if (leaves.length == 0) return;
        WorkMarket.Offer memory o = market.getOffer(id);
        uint256 opensAt = uint256(o.payoutPostedAt) + o.disputeWindow;
        if (jumpPastWindow && o.payoutPostedAt != 0 && block.timestamp < opensAt) vm.warp(opensAt);
        uint64[] memory per = unitsOf[id];
        // the first actor at or after the seed that has a leaf
        uint256 target = 4;
        for (uint256 k = 0; k < 4; k++) {
            if (per[(actorSeed % 4 + k) % 4] != 0) {
                target = (actorSeed % 4 + k) % 4;
                break;
            }
        }
        if (target == 4) return;
        uint256 n;
        uint64 cum;
        for (uint256 i = 0; i < 4; i++) {
            if (per[i] == 0) continue;
            if (i == target) {
                bytes32[] memory path = new bytes32[](2);
                path[0] = leaves[n ^ 1];
                path[1] = n < 2
                    ? keccak256(abi.encodePacked(bytes1(0x01), leaves[2], leaves[3]))
                    : keccak256(abi.encodePacked(bytes1(0x01), leaves[0], leaves[1]));
                uint32 openBefore = market.getOffer(id).openChallenges;
                try market.settle(id, actors[i], per[i], cum, uint32(n), path) {
                    if (openBefore != 0) settledWhileChallenged = true;
                    settleCount[id][actors[i]] += 1;
                    settles++;
                } catch {}
                return;
            }
            cum += per[i];
            n++;
        }
    }

    /// Opens the actor's leaf (or returns an empty opening if it has none) from the stored tree.
    function _openingFor(uint256 id, uint256 target) internal view returns (WorkMarket.LeafOpening memory l, bool has) {
        bytes32[] memory leaves = leavesOf[id];
        uint64[] memory per = unitsOf[id];
        if (leaves.length == 0 || per[target] == 0) return (l, false);
        uint256 n;
        uint64 cum;
        for (uint256 i = 0; i < target; i++) {
            if (per[i] == 0) continue;
            cum += per[i];
            n++;
        }
        bytes32[] memory path = new bytes32[](2);
        path[0] = leaves[n ^ 1];
        path[1] = n < 2
            ? keccak256(abi.encodePacked(bytes1(0x01), leaves[2], leaves[3]))
            : keccak256(abi.encodePacked(bytes1(0x01), leaves[0], leaves[1]));
        l = WorkMarket.LeafOpening({
            index: uint32(n), worker: actors[target], units: per[target], cumBefore: cum, path: path
        });
        return (l, true);
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

    /// An honest coordinator answers whenever the leaf covers the claim.
    function answer(uint256 seed, uint256 actorSeed) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        (WorkMarket.LeafOpening memory l, bool has) = _openingFor(id, actorSeed % 4);
        if (!has) return;
        vm.prank(coordinator);
        try market.answerChallenge(id, l) {} catch {}
    }

    function resolve(uint256 seed, uint256 actorSeed, bool jump) external {
        if (ids.length == 0) return;
        uint256 id = _id(seed);
        address w = actors[actorSeed % 4];
        WorkMarket.Challenge memory c = market.challengeOf(id, w);
        if (jump && c.open && block.timestamp <= c.answerBy) vm.warp(uint256(c.answerBy) + 1);
        try market.resolveChallenge(id, w) {
            challengesResolved++;
            delete leavesOf[id];
            delete unitsOf[id];
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

    /// Q11: open challenges never outnumber the joined workers of an offer.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_open_challenges_bounded() public view {
        for (uint256 i = 0; i < handler.idsLength(); i++) {
            WorkMarket.Offer memory o = market.getOffer(handler.ids(i));
            assertLe(o.openChallenges, o.workers);
        }
    }

    /// 06 §7.7: pause never stops anyone pulling what they are owed.
    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 200
    /// forge-config: default.invariant.fail-on-revert = false
    function invariant_pause_never_blocks_exit() public view {
        assertFalse(handler.pauseBlockedExit());
    }
}
