// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Governable} from "../lib/Governable.sol";
import {ReentrancyGuard} from "../lib/ReentrancyGuard.sol";
import {InitialAdmin} from "../lib/InitialAdmin.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IVerifier, IWorkMarket} from "./IVerifier.sol";

/// @title WorkMarket: one SALT escrow for federated-learning rounds and agent tasks
/// @notice 0.6.0 planset 06 §2 (decision X-1). A poster opens an offer with a budget and a fixed
///         per-unit price, workers join if the price meets their floor, a coordinator posts a
///         payout root once the offer's verifier reports the work accepted, and after a dispute
///         window every worker in the root settles its own leaf into a pull balance.
///
///         Native SALT only. No proxy, no upgrade path (a v2 is a new deployment). Governance can
///         allow or deny verifiers for NEW offers and pause NEW offers; nothing lets governance,
///         the guardian, the poster or the coordinator take escrowed SALT except a payout proven
///         against a verified root, or the poster's refund of what no root can claim.
///
/// @dev Payout tree (one per posted payout), shared shape with FederatedRoundLedger:
///        payload_i = keccak256(abi.encode(LEAF_TAG, chainid, market, offerId, worker_i, units_i, cumBefore_i))
///        leaf_i    = keccak256(0x00 ‖ uint32 i ‖ payload_i); padding leaves are bytes32(0)
///        node      = keccak256(0x01 ‖ left ‖ right); leaf list padded with zero leaves to 2^depth
///      Real leaves are sorted by strictly ascending worker address, come before all padding, and
///      carry a running prefix sum (`cumBefore_0 = 0`, `cumBefore_{i+1} = cumBefore_i + units_i`).
///      The sort makes absence provable (two neighbours bracket the missing worker); the prefix
///      sum makes over-allocation provable (two neighbours whose ranges do not abut) and lets
///      `settle` check `cumBefore + units <= payoutUnits` leaf by leaf. A tree that breaks either
///      rule is a coordinator fault anyone can prove inside the window (DISPUTE_ORDER/FIRST_LEAF):
///      the order proof takes any two openable leaves `i < j`, not only neighbours.
///
///      The tree depth is fixed when the root is posted (`payoutDepth`, at most what `maxWorkers`
///      needs) and every opening, in `settle` and in disputes alike, must carry a path of exactly
///      that length and an index below `2^payoutDepth`. A leaf that settles therefore always opens
///      in a dispute too.
///
///      Inclusion challenge (owner 2026-11-09, V60-GEN-Q11): a leaf whose payload has no valid
///      preimage cannot be opened, so it could hide one absent worker from a MISSING_LEAF proof.
///      Inside the dispute window, a joined worker or the poster may instead present
///      coordinator-signed receipts for a worker and make the coordinator answer: anyone may
///      answer by opening that worker's leaf with at least the receipted units before
///      `answerBy`; if nobody does, the challenge is upheld like any objective dispute. Settling
///      and the coordinator's bond wait while a challenge is open.
///
///      Index challenge: the same, for one tree index instead of one worker. The answer opens the
///      slot as a real leaf or as padding (the zero leaf); a slot that opens as neither (a leaf with
///      no preimage) is upheld when the answer time runs out. So every slot can be forced open,
///      and with the any-pair order proof no two leaves can claim overlapping unit ranges unseen.
///      An answer keeps disputes open for `POST_ANSWER_DISPUTE_WINDOW` after it, so a leaf opened
///      late in the window can still be disputed; settling waits for that too.
contract WorkMarket is IWorkMarket, Governable, ReentrancyGuard {
    // ── constants ───────────────────────────────────────────────────

    uint32 public constant MIN_DISPUTE_WINDOW = 24 hours;
    uint32 public constant MAX_WORKERS_CAP = 1024;
    /// @notice Share of a slashed coordinator bond paid to a disputer who is not the poster; the
    ///         rest goes to the poster. Owner question V60-GEN-Q4 (06 §2.2 does not fix the split).
    uint16 public constant SLASH_DISPUTER_BPS = 5000;
    uint16 internal constant BPS = 10_000;
    /// @notice Bounds the receipts one LOW_UNITS dispute may carry (calldata and gas).
    uint256 public constant MAX_RECEIPTS_PER_DISPUTE = 256;
    /// @notice Subjective (TASK) dispute reason codes start here; lower codes name objective kinds.
    uint16 public constant SUBJECTIVE_REASON_MIN = 256;
    /// @notice How long the coordinator (or anyone holding the tree) has to answer an inclusion
    ///         challenge by opening the challenged worker's leaf.
    uint32 public constant CHALLENGE_RESPONSE_WINDOW = 24 hours;
    /// @notice After a challenge is answered, disputes stay open at least this long, so the leaf
    ///         the answer opened can be used in an objective dispute.
    uint32 public constant POST_ANSWER_DISPUTE_WINDOW = 24 hours;
    /// @notice After `deadline + disputeWindow + RESERVE_CLAIM_PERIOD`, the poster may take back
    ///         what a posted root reserved for workers who never settled (owner 2026-11-09, Q3).
    uint64 public constant RESERVE_CLAIM_PERIOD = 180 days;

    bytes32 public constant LEAF_TAG = keccak256("citrate-workmarket-leaf/1");
    bytes32 public constant RECEIPT_TAG = keccak256("citrate-workmarket-lease-receipt/1");
    bytes32 public constant PAYOUT_TAG = keccak256("citrate-workmarket-payout/1");

    /// Dispute evidence tags (first field of the abi-encoded evidence).
    uint8 public constant DISPUTE_SUBJECTIVE = 0;
    uint8 public constant DISPUTE_MISSING_LEAF = 1;
    uint8 public constant DISPUTE_LOW_UNITS = 2;
    uint8 public constant DISPUTE_ORDER = 3;
    uint8 public constant DISPUTE_FIRST_LEAF = 4;
    /// Reason code emitted when an inclusion challenge went unanswered.
    uint8 public constant DISPUTE_UNANSWERED_CHALLENGE = 5;
    uint8 public constant DISPUTE_TOTAL = 6;
    uint16 public constant CHALLENGE_BOND_BPS = 1000;
    uint32 public constant DISPUTE_REVEAL_DELAY = 60;

    /// Non-inclusion modes for DISPUTE_MISSING_LEAF.
    uint8 public constant ABSENT_BETWEEN = 0;
    uint8 public constant ABSENT_BEFORE_FIRST = 1;
    uint8 public constant ABSENT_AFTER_LAST = 2;
    uint8 public constant ABSENT_EMPTY = 3;

    // ── types ───────────────────────────────────────────────────────

    /// @notice What `open` takes. 06 §2 lists these as flat arguments; they are a struct here to
    ///         keep the ABI readable, plus `coordinatorBond` and `disputeAdmin` (06 §2 names both
    ///         in the offer and in §2.2 but `open` had no argument for them: V60-GEN-Q1, -Q2).
    struct OpenParams {
        Kind kind;
        address verifier;
        bytes32 bindRef;
        bytes32 jobSpecHash;
        bytes32 requirementsHash;
        string requirementsCid;
        bytes32 groupHash;
        bytes32 allowlistRoot;
        uint128 pricePerUnit;
        uint64 deadline;
        uint32 disputeWindow;
        uint32 maxWorkers;
        uint128 joinBond;
        address coordinator;
        uint128 coordinatorBond;
        address disputeAdmin;
    }

    struct Offer {
        Kind kind;
        State state;
        address poster;
        address verifier; // allowlisted at open; fixed for the offer's life
        bytes32 bindRef; // FL: the FRL round id; TASK: keccak(skillId, versionHash, inputCid)
        bytes32 jobSpecHash;
        bytes32 requirementsHash;
        bytes32 groupHash; // 0 = open offer
        bytes32 allowlistRoot; // 0 = anyone
        uint128 pricePerUnit; // immutable after open
        uint128 budget; // escrowed at open
        uint128 paid; // settled to workers
        uint128 refunded; // returned to the poster
        uint64 maxUnits; // budget / pricePerUnit
        uint64 deadline;
        uint32 disputeWindow;
        uint32 maxWorkers;
        uint32 workers; // joined
        uint32 joinBondsReleased;
        uint128 joinBond;
        address coordinator; // FL: who posts the payout; TASK: the selected worker
        uint128 coordinatorBond; // the bond `postPayout` must carry (poster-set; 0 at open = default)
        address disputeAdmin; // group TASK offers only; resolves subjective disputes
        bytes32 payoutRoot; // keccak(PAYOUT_TAG, digest, leavesRoot); 0 = none live
        bytes32 leavesRoot;
        bytes32 digest;
        uint64 payoutPostedAt;
        uint64 payoutUnits;
        uint64 settledUnits;
        bool coordinatorBondHeld;
        bool subjectiveDisputeUsed; // one subjective dispute per posted payout
        bool reserveSwept; // the poster took back the unsettled reserve after the claim period
        uint32 payoutEpoch; // bumps whenever a posted root is withdrawn; scopes challenges
        uint32 openChallenges; // inclusion and index challenges awaiting an answer under the live root
        uint8 payoutDepth; // the posted tree's depth: every opening carries exactly this many siblings
        uint64 answerGraceUntil; // disputes stay open until at least this time (set by answers)
        uint32 resultEpoch; // bumps when a subjective dispute is upheld (TaskVerifier scopes results to it)
        uint128 challengeBondsHeld;
    }

    struct Challenge {
        uint32 epoch; // payoutEpoch it was raised under
        bool open;
        address challenger;
        uint64 claimedUnits; // distinct receipted leases
        uint64 answeredUnits; // highest claim already answered under this epoch
        uint64 answerBy;
    }

    struct IndexChallenge {
        uint32 epoch; // payoutEpoch it was raised under
        bool open;
        bool answered; // a slot answered under this epoch cannot be challenged again
        address challenger;
        uint64 answerBy;
    }

    struct WorkerSlot {
        bool joined;
        bool settled;
        bool bondReleased;
    }

    /// @notice One leaf of a payout tree, opened. `worker == address(0)` opens a padding leaf.
    struct LeafOpening {
        uint32 index;
        address worker;
        uint64 units;
        uint64 cumBefore;
        bytes32[] path;
    }

    /// @notice A coordinator-signed lease receipt `(offerId, worker, leaseId, deltaHash, verified=true)`
    ///         (06 §2.2). Signed over `receiptDigest` with EIP-191; EIP-1271 for contract coordinators.
    struct Receipt {
        address worker;
        bytes32 leaseId;
        bytes32 deltaHash;
        bytes signature;
    }

    // ── state ───────────────────────────────────────────────────────

    uint256 public nextOfferId;
    /// @notice The coordinator bond an offer gets when its poster passes 0 (owner 2026-11-09, Q1).
    uint128 public immutable defaultCoordinatorBond;
    address public guardian;
    bool public newOffersPaused;

    mapping(address => bool) public verifierAllowed;
    mapping(uint256 => Offer) internal _offers;
    mapping(uint256 => mapping(address => WorkerSlot)) internal _slots;
    /// @notice Pull balances (payouts, refunds, released and slashed bonds).
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => mapping(address => Challenge)) internal _challenges;
    mapping(uint256 => mapping(uint32 => IndexChallenge)) internal _indexChallenges;
    /// @notice Block a dispute commitment was made in (0 = none); see `commitDispute`.
    mapping(bytes32 => uint256) public disputeCommitBlock;

    // ── events ──────────────────────────────────────────────────────

    event OfferOpened(
        uint256 indexed id,
        Kind kind,
        address indexed poster,
        bytes32 indexed groupHash,
        uint128 pricePerUnit,
        uint128 budget,
        uint64 deadline,
        string requirementsCid
    );
    event Joined(uint256 indexed id, address indexed worker, uint128 minPrice);
    event PayoutPosted(uint256 indexed id, bytes32 root, uint64 units, bytes32 digest);
    event Disputed(uint256 indexed id, address indexed by, uint16 reason);
    event DisputeResolved(uint256 indexed id, address indexed admin, bool upheld);
    event CoordinatorSlashed(uint256 indexed id, address indexed disputer, uint128 toDisputer, uint128 toPoster);
    event Settled(uint256 indexed id, address indexed worker, uint64 units, uint128 amount);
    event Refunded(uint256 indexed id, uint128 amount);
    event BondReleased(uint256 indexed id, address indexed to, uint128 amount);
    event OfferClosed(uint256 indexed id, State finalState);
    event Withdrawn(address indexed to, uint256 amount);
    event VerifierAllowed(address indexed verifier, bool ok);
    event NewOffersPaused(address indexed by, bool paused);
    event GuardianSet(address indexed guardian);
    event InclusionChallenged(
        uint256 indexed id, address indexed worker, address indexed challenger, uint64 claimedUnits, uint64 answerBy
    );
    event ChallengeAnswered(uint256 indexed id, address indexed worker, uint64 leafUnits);
    event ReserveSwept(uint256 indexed id, uint128 amount);
    event DisputeCommitted(uint256 indexed id, address indexed by, bytes32 commitment);
    event IndexChallenged(uint256 indexed id, uint32 indexed index, address indexed challenger, uint64 answerBy);
    event IndexChallengeAnswered(uint256 indexed id, uint32 indexed index, address worker);

    // ── errors ──────────────────────────────────────────────────────

    error NewOffersArePaused();
    error VerifierNotAllowed();
    error BadPrice();
    error BudgetBelowPrice();
    error BudgetTooLarge();
    error BadDeadline();
    error BadDisputeWindow();
    error BadMaxWorkers();
    error BadParty();
    error BadBindRef();
    error UnknownOffer();
    error WrongState();
    error PastDeadline();
    error PriceBelowFloor(uint128 pricePerUnit, uint128 minPrice);
    error NotAllowlisted();
    error AlreadyJoined();
    error OfferFull();
    error WrongBond();
    error NotCoordinator();
    error NotAccepted();
    error BadUnits();
    error BadRoot();
    error NotDisputer();
    error WindowClosed();
    error WindowOpen();
    error BadEvidence();
    error DisputeNotProven();
    error NotDisputeAdmin();
    error NotJoined();
    error AlreadySettled();
    error BadProof();
    error ExceedsPayout();
    error NotPoster();
    error TooEarly();
    error NothingToClaim();
    error TransferFailed();
    error NotGuardianOrGovernance();
    error BadDefaultBond();
    error ChallengeOpen();
    error NoOpenChallenge();
    error AnswerTooLate();
    error AnswerTooEarly();
    error BadAnswer();
    error ReserveGone();
    error BadDepth();

    // ── construction ────────────────────────────────────────────────

    /// @param governance_       the governance timelock (3-of-5 / 48 h); allows verifiers, pauses, unpauses
    /// @param guardian_         the guardian council (2-of-3); may pause new offers, nothing else; not 0 (InitialAdmin)
    /// @param defaultCoordinatorBond_ the bond an offer requires when its poster passes 0; above zero
    /// @param initialVerifiers_ verifiers allowed at block 0 (CREATE2-predicted FLRoundVerifier and TaskVerifier)
    constructor(
        address governance_,
        address guardian_,
        uint128 defaultCoordinatorBond_,
        address[] memory initialVerifiers_
    ) Governable(governance_) {
        if (defaultCoordinatorBond_ == 0) revert BadDefaultBond();
        defaultCoordinatorBond = defaultCoordinatorBond_;
        guardian = InitialAdmin.check(guardian_);
        emit GuardianSet(guardian_);
        for (uint256 i = 0; i < initialVerifiers_.length; i++) {
            address v = initialVerifiers_[i];
            if (v == address(0)) revert BadParty();
            verifierAllowed[v] = true;
            emit VerifierAllowed(v, true);
        }
    }

    // ── governance (new offers only) ────────────────────────────────

    function setVerifierAllowed(address verifier, bool ok) external onlyGovernance {
        if (verifier == address(0)) revert BadParty();
        verifierAllowed[verifier] = ok;
        emit VerifierAllowed(verifier, ok);
    }

    /// @notice Rotate the guardian seat, or clear it with zero. Never the CREATE2 factory.
    function setGuardian(address guardian_) external onlyGovernance {
        if (guardian_ == InitialAdmin.CREATE2_FACTORY) revert InitialAdmin.InitialAdmin_Create2Factory();
        guardian = guardian_;
        emit GuardianSet(guardian_);
    }

    /// @notice Pause or unpause NEW offers. Governance may do both; the guardian may only pause.
    ///         Never affects join, postPayout, dispute, settle, refund, claimBond or withdraw.
    function setNewOffersPaused(bool paused) external {
        if (msg.sender != governance() && !(paused && msg.sender == guardian && guardian != address(0))) {
            revert NotGuardianOrGovernance();
        }
        newOffersPaused = paused;
        emit NewOffersPaused(msg.sender, paused);
    }

    // ── open ────────────────────────────────────────────────────────

    /// @notice Open an offer. `msg.value` is the budget.
    function open(OpenParams calldata p) external payable returns (uint256 id) {
        if (newOffersPaused) revert NewOffersArePaused();
        if (!verifierAllowed[p.verifier]) revert VerifierNotAllowed();
        if (p.pricePerUnit == 0) revert BadPrice();
        if (msg.value > type(uint128).max) revert BudgetTooLarge();
        uint128 budget = uint128(msg.value);
        if (budget < p.pricePerUnit) revert BudgetBelowPrice();
        uint256 maxUnits = budget / p.pricePerUnit;
        if (maxUnits > type(uint64).max) revert BudgetTooLarge();
        if (p.disputeWindow < MIN_DISPUTE_WINDOW) revert BadDisputeWindow();
        if (p.deadline <= block.timestamp + p.disputeWindow) revert BadDeadline();
        if (p.maxWorkers == 0 || p.maxWorkers > MAX_WORKERS_CAP) revert BadMaxWorkers();
        if (p.coordinator == address(0)) revert BadParty();
        if (p.bindRef == bytes32(0)) revert BadBindRef();
        // Subjective disputes exist only for group TASK offers (06 §2.2); an admin anywhere
        // else would be a party that can freeze a payout without the contract checking anything.
        if (p.disputeAdmin != address(0) && (p.kind != Kind.TASK || p.groupHash == bytes32(0))) {
            revert BadParty();
        }
        // A group task's subjective dispute has only the admin to rule on it; without one the
        // group would fall back to the open-task timeout, which the group did not choose.
        if (p.kind == Kind.TASK && p.groupHash != bytes32(0) && p.disputeAdmin == address(0)) revert BadParty();

        id = ++nextOfferId;
        Offer storage o = _offers[id];
        o.kind = p.kind;
        o.state = State.Open;
        o.poster = msg.sender;
        o.verifier = p.verifier;
        o.bindRef = p.bindRef;
        o.jobSpecHash = p.jobSpecHash;
        o.requirementsHash = p.requirementsHash;
        o.groupHash = p.groupHash;
        o.allowlistRoot = p.allowlistRoot;
        o.pricePerUnit = p.pricePerUnit;
        o.budget = budget;
        o.maxUnits = uint64(maxUnits);
        o.deadline = p.deadline;
        o.disputeWindow = p.disputeWindow;
        o.maxWorkers = p.maxWorkers;
        o.joinBond = p.joinBond;
        o.coordinator = p.coordinator;
        o.coordinatorBond = p.coordinatorBond == 0 ? defaultCoordinatorBond : p.coordinatorBond;
        o.disputeAdmin = p.disputeAdmin;

        emit OfferOpened(id, p.kind, msg.sender, p.groupHash, p.pricePerUnit, budget, p.deadline, p.requirementsCid);
    }

    // ── join ────────────────────────────────────────────────────────

    /// @notice Join an offer whose price meets `minPrice`. `msg.value` must equal the offer's join bond.
    /// @param allowProof proof of `keccak256(bytes.concat(keccak256(abi.encode(worker))))` under
    ///        `allowlistRoot` (OpenZeppelin standard leaf, sorted-pair tree); ignored when the root is 0
    function join(uint256 id, uint128 minPrice, bytes32[] calldata allowProof) external payable {
        Offer storage o = _offer(id);
        if (o.state != State.Open && o.state != State.Running) revert WrongState();
        if (block.timestamp > o.deadline) revert PastDeadline();
        if (o.pricePerUnit < minPrice) revert PriceBelowFloor(o.pricePerUnit, minPrice);
        if (o.allowlistRoot != bytes32(0)) {
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender))));
            if (!MerkleProof.verifyCalldata(allowProof, o.allowlistRoot, leaf)) revert NotAllowlisted();
        }
        WorkerSlot storage s = _slots[id][msg.sender];
        if (s.joined) revert AlreadyJoined();
        if (o.workers >= o.maxWorkers) revert OfferFull();
        if (msg.value != o.joinBond) revert WrongBond();

        s.joined = true;
        o.workers += 1;
        if (o.state == State.Open) o.state = State.Running;
        emit Joined(id, msg.sender, minPrice);
    }

    // ── payout ──────────────────────────────────────────────────────

    /// @notice Post the payout tree once the verifier accepts the work. Only the coordinator, at or
    ///         before the deadline, carrying exactly the offer's coordinator bond.
    /// @param root  the payout tree's root over sorted, prefix-summed leaves (see contract notes)
    /// @param units the total units the tree pays (`<= maxUnits`; exactly 1 for TASK)
    /// @param depth the tree's depth (`2^depth` slots), at most what `maxWorkers` needs; every
    ///        opening of this tree must carry exactly `depth` siblings
    function postPayout(uint256 id, bytes32 root, uint64 units, uint8 depth) external payable {
        Offer storage o = _offer(id);
        if (msg.sender != o.coordinator) revert NotCoordinator();
        if (o.state != State.Open && o.state != State.Running) revert WrongState();
        if (block.timestamp > o.deadline) revert PastDeadline();
        if (msg.value != o.coordinatorBond) revert WrongBond();
        if (root == bytes32(0)) revert BadRoot();
        if (units == 0 || units > o.maxUnits) revert BadUnits();
        if (o.kind == Kind.TASK && units != 1) revert BadUnits();
        if (depth > _depthFor(o.maxWorkers)) revert BadDepth();
        // TASK: the coordinator is the selected worker and the root's single leaf pays it.
        if (o.kind == Kind.TASK && !_slots[id][o.coordinator].joined) revert NotJoined();

        (bool ok, bytes32 digest) = IVerifier(o.verifier).accepted(id, o.bindRef);
        if (!ok || digest == bytes32(0)) revert NotAccepted();

        o.leavesRoot = root;
        o.digest = digest;
        o.payoutRoot = keccak256(abi.encode(PAYOUT_TAG, digest, root));
        o.payoutPostedAt = uint64(block.timestamp);
        o.payoutUnits = units;
        o.payoutDepth = depth;
        o.answerGraceUntil = 0;
        o.settledUnits = 0;
        o.coordinatorBondHeld = true;
        o.subjectiveDisputeUsed = false;
        o.state = State.PayoutPosted;
        emit PayoutPosted(id, root, units, digest);
    }

    // ── disputes ────────────────────────────────────────────────────

    /// @notice Dispute a posted payout inside its window. Joined workers and the poster may dispute.
    /// @param evidence `abi.encode(uint8 tag, bytes body)`:
    ///        DISPUTE_SUBJECTIVE  body = abi.encode(uint16 reason)                      TASK, poster only
    ///        DISPUTE_MISSING_LEAF body = abi.encode(Receipt, uint8 mode, LeafOpening lo, LeafOpening hi)
    ///        DISPUTE_LOW_UNITS   body = abi.encode(LeafOpening leaf, Receipt[] receipts)
    ///        DISPUTE_ORDER       body = abi.encode(LeafOpening a, LeafOpening b)       a.index < b.index
    ///        DISPUTE_FIRST_LEAF  body = abi.encode(LeafOpening first)                  index 0
    function dispute(uint256 id, bytes calldata evidence) external nonReentrant {
        _dispute(id, evidence);
    }

    /// @notice Commit to a dispute before revealing its evidence, so a copier who sees the
    ///         evidence in the mempool cannot take the disputer's share of the slash. The
    ///         commitment is `disputeCommitment(id, payoutEpoch, msg.sender, evidence, salt)`;
    ///         reveal it with `revealDispute` from the next block on, inside the dispute window.
    function commitDispute(uint256 id, bytes32 commitment) external {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted) revert WrongState();
        if (block.timestamp >= _disputeEnd(o)) revert WindowClosed();
        if (msg.sender != o.poster && !_slots[id][msg.sender].joined) revert NotDisputer();
        if (commitment == bytes32(0) || disputeCommitBlock[commitment] != 0) revert BadEvidence();
        disputeCommitBlock[commitment] = block.number;
        emit DisputeCommitted(id, msg.sender, commitment);
    }

    /// @notice Reveal a committed dispute (same rules and outcome as `dispute`).
    function revealDispute(uint256 id, bytes calldata evidence, bytes32 salt) external nonReentrant {
        bytes32 commitment = disputeCommitment(id, _offer(id).payoutEpoch, msg.sender, evidence, salt);
        uint256 committedAt = disputeCommitBlock[commitment];
        if (committedAt == 0) revert BadEvidence();
        if (committedAt >= block.number) revert TooEarly();
        delete disputeCommitBlock[commitment];
        _dispute(id, evidence);
    }

    function disputeCommitment(uint256 id, uint32 epoch, address disputer, bytes calldata evidence, bytes32 salt)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), id, epoch, disputer, keccak256(evidence), salt));
    }

    function _dispute(uint256 id, bytes calldata evidence) internal {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted) revert WrongState();
        if (block.timestamp >= _disputeEnd(o)) revert WindowClosed();
        if (msg.sender != o.poster && !_slots[id][msg.sender].joined) revert NotDisputer();

        (uint8 tag, bytes memory body) = abi.decode(evidence, (uint8, bytes));
        if (tag == DISPUTE_SUBJECTIVE) {
            if (o.kind != Kind.TASK || msg.sender != o.poster || o.subjectiveDisputeUsed) revert BadEvidence();
            uint16 reason = abi.decode(body, (uint16));
            if (reason < SUBJECTIVE_REASON_MIN) revert BadEvidence();
            o.subjectiveDisputeUsed = true;
            o.state = State.Disputed;
            emit Disputed(id, msg.sender, reason);
            return;
        }

        bool proven = false;
        if (tag == DISPUTE_MISSING_LEAF) {
            proven = _provesMissingLeaf(id, o, body);
        } else if (tag == DISPUTE_LOW_UNITS) {
            proven = _provesLowUnits(id, o, body);
        } else if (tag == DISPUTE_ORDER) {
            proven = _provesBadOrder(id, o, body);
        } else if (tag == DISPUTE_FIRST_LEAF) {
            proven = _provesBadFirstLeaf(id, o, body);
        } else {
            revert BadEvidence();
        }
        if (!proven) revert DisputeNotProven();

        emit Disputed(id, msg.sender, tag);
        _upholdObjective(id, o, msg.sender);
    }

    /// @notice The offer's dispute admin (group TASK offers) rules on a subjective dispute.
    ///         Upheld: the payout is withdrawn, the worker's bond is returned (a bad result is not
    ///         fraud) and the offer runs again until its deadline. Rejected: the payout stands.
    function resolveDispute(uint256 id, bool upheld) external nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.Disputed) revert WrongState();
        if (o.disputeAdmin == address(0) || msg.sender != o.disputeAdmin) revert NotDisputeAdmin();
        if (upheld) {
            // An open challenge keeps its challenger's claim on the bond: resolve it first.
            if (o.openChallenges != 0) revert ChallengeOpen();
            _releaseCoordinatorBond(id, o);
            _clearPayout(o);
            o.resultEpoch += 1; // the rejected result no longer counts as verified
            o.state = State.Running;
        } else {
            o.state = State.PayoutPosted;
        }
        emit DisputeResolved(id, msg.sender, upheld);
    }

    // ── settle ──────────────────────────────────────────────────────

    /// @notice Credit `worker`'s leaf after the dispute window. Anyone may call; once per worker.
    function settle(uint256 id, address worker, uint64 units, uint64 cumBefore, uint32 index, bytes32[] calldata proof)
        external
        nonReentrant
    {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted && o.state != State.Closed) revert WrongState();
        if (o.payoutRoot == bytes32(0)) revert WrongState();
        if (block.timestamp < _disputeEnd(o)) revert WindowOpen();
        if (o.openChallenges != 0) revert ChallengeOpen();
        if (o.reserveSwept) revert ReserveGone();
        WorkerSlot storage s = _slots[id][worker];
        if (!s.joined) revert NotJoined();
        if (s.settled) revert AlreadySettled();
        if (units == 0) revert BadUnits();
        // The same opening rule as disputes (depth and index range): a leaf that settles can be
        // used as evidence against the tree.
        if (!_opens(id, o, LeafOpening(index, worker, units, cumBefore, proof))) revert BadProof();
        if (uint256(cumBefore) + units > o.payoutUnits) revert ExceedsPayout();
        if (uint256(o.settledUnits) + units > o.payoutUnits) revert ExceedsPayout();

        uint128 amount = uint128(uint256(units) * o.pricePerUnit);
        // payoutUnits <= maxUnits = budget / price, so paid never passes budget; checked anyway.
        if (uint256(o.paid) + amount > o.budget) revert ExceedsPayout();

        s.settled = true;
        o.settledUnits += units;
        o.paid += amount;
        balanceOf[worker] += amount;
        emit Settled(id, worker, units, amount);

        if (!s.bondReleased && o.joinBond != 0) {
            s.bondReleased = true;
            o.joinBondsReleased += 1;
            balanceOf[worker] += o.joinBond;
            emit BondReleased(id, worker, o.joinBond);
        }
    }

    // ── refund ──────────────────────────────────────────────────────

    /// @notice Return to the poster what no payout can claim.
    ///         - Open/Running after the deadline (no live payout; none can be posted): all of
    ///           `budget - paid`; the offer is Expired.
    ///         - PayoutPosted at or after `deadline + disputeWindow`: `budget` minus what the posted
    ///           root reserves (`payoutUnits * price`); unsettled workers can still settle (RT-11).
    ///         - Disputed (unresolved subjective dispute) at or after `deadline + disputeWindow`:
    ///           all of `budget - paid`; the coordinator's bond is returned to it.
    function refund(uint256 id) external nonReentrant {
        Offer storage o = _offer(id);
        if (msg.sender != o.poster) revert NotPoster();
        uint256 afterWindow = uint256(o.deadline) + o.disputeWindow;
        uint128 amount = 0;
        State finalState = o.state;
        if (o.state == State.Open || o.state == State.Running) {
            if (block.timestamp <= o.deadline) revert TooEarly();
            amount = o.budget - o.paid;
            finalState = State.Expired;
        } else if (o.state == State.PayoutPosted) {
            if (block.timestamp < afterWindow || block.timestamp < _disputeEnd(o)) revert TooEarly();
            if (o.openChallenges != 0) revert ChallengeOpen();
            amount = o.budget - uint128(uint256(o.payoutUnits) * o.pricePerUnit);
            finalState = State.Closed;
        } else if (o.state == State.Disputed) {
            if (block.timestamp < afterWindow) revert TooEarly();
            // An open challenge keeps its challenger's claim on the bond: resolve it first.
            if (o.openChallenges != 0) revert ChallengeOpen();
            _releaseCoordinatorBond(id, o);
            _clearPayout(o);
            amount = o.budget - o.paid;
            finalState = State.Closed;
        } else {
            revert WrongState();
        }
        o.refunded = amount;
        o.state = finalState;
        balanceOf[o.poster] += amount;
        emit Refunded(id, amount);
        emit OfferClosed(id, finalState);
    }

    // ── bonds ───────────────────────────────────────────────────────

    /// @notice Release the caller's bonds on `id` into its pull balance.
    ///         Join bond: after the worker settled, or once the offer is Closed/Expired, or after
    ///         `deadline + disputeWindow` (join bonds are never slashed).
    ///         Coordinator bond: once the posted payout's window has passed undisputed.
    function claimBond(uint256 id) external nonReentrant {
        Offer storage o = _offer(id);
        uint128 total = 0;

        WorkerSlot storage s = _slots[id][msg.sender];
        if (s.joined && !s.bondReleased && o.joinBond != 0) {
            bool over = o.state == State.Closed || o.state == State.Expired
                || block.timestamp >= uint256(o.deadline) + o.disputeWindow;
            if (over) {
                s.bondReleased = true;
                o.joinBondsReleased += 1;
                total += o.joinBond;
                emit BondReleased(id, msg.sender, o.joinBond);
            }
        }

        if (
            msg.sender == o.coordinator && o.coordinatorBondHeld && o.payoutRoot != bytes32(0) && o.openChallenges == 0
                && (o.state == State.PayoutPosted || o.state == State.Closed) && block.timestamp >= _disputeEnd(o)
        ) {
            o.coordinatorBondHeld = false;
            total += o.coordinatorBond;
            emit BondReleased(id, msg.sender, o.coordinatorBond);
        }

        if (total == 0) revert NothingToClaim();
        balanceOf[msg.sender] += total;
    }

    // ── inclusion challenge (V60-GEN-Q11) ───────────────────────────

    /// @notice Inside the dispute window, a joined worker or the poster presents `receipts` (distinct,
    ///         coordinator-signed, strictly ascending lease ids, all for one joined worker) and makes
    ///         the root answer for that worker within `CHALLENGE_RESPONSE_WINDOW`. A worker may be
    ///         challenged again under the same root only with more receipts than the answered leaf pays.
    function challengeInclusion(uint256 id, Receipt[] calldata receipts) external payable nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted) revert WrongState();
        if (block.timestamp >= uint256(o.payoutPostedAt) + o.disputeWindow) revert WindowClosed();
        if (msg.sender != o.poster && !_slots[id][msg.sender].joined) revert NotDisputer();
        if (receipts.length == 0 || receipts.length > MAX_RECEIPTS_PER_DISPUTE) revert BadEvidence();
        address w = receipts[0].worker;
        if (w == address(0) || !_slots[id][w].joined) revert BadEvidence();
        bytes32 prevLease = bytes32(0);
        for (uint256 i = 0; i < receipts.length; i++) {
            Receipt calldata r = receipts[i];
            if (r.worker != w || (i > 0 && r.leaseId <= prevLease)) revert BadEvidence();
            if (!_receiptValid(id, o, r)) revert BadEvidence();
            prevLease = r.leaseId;
        }
        Challenge storage c = _challenges[id][w];
        uint64 claimed = uint64(receipts.length);
        if (c.epoch != o.payoutEpoch) {
            c.epoch = o.payoutEpoch;
            c.open = false;
            c.answeredUnits = 0;
        }
        if (c.open) revert ChallengeOpen();
        if (claimed <= c.answeredUnits) revert BadEvidence();
        uint64 answerBy = uint64(block.timestamp) + CHALLENGE_RESPONSE_WINDOW;
        c.open = true;
        c.challenger = msg.sender;
        c.claimedUnits = claimed;
        c.answerBy = answerBy;
        o.openChallenges += 1;
        emit InclusionChallenged(id, w, msg.sender, claimed, answerBy);
    }

    /// @notice Answer an open challenge by opening the worker's leaf with at least the claimed
    ///         units. Anyone may answer (the proof is objective); only until `answerBy`.
    function answerChallenge(uint256 id, LeafOpening calldata leaf) external nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted && o.state != State.Disputed) revert WrongState();
        Challenge storage c = _challenges[id][leaf.worker];
        if (leaf.worker == address(0) || !c.open || c.epoch != o.payoutEpoch) revert NoOpenChallenge();
        if (block.timestamp > c.answerBy) revert AnswerTooLate();
        if (leaf.units < c.claimedUnits || !_opens(id, o, leaf)) revert BadAnswer();
        c.open = false;
        c.answeredUnits = leaf.units; // the leaf pays this much: only a claim above it is new
        o.openChallenges -= 1;
        _extendForAnswer(o);
        emit ChallengeAnswered(id, leaf.worker, leaf.units);
    }

    /// @notice After `answerBy`, an unanswered challenge is upheld: the root is withdrawn, the
    ///         coordinator bond slashed (to the challenger and the poster) and the offer runs again.
    function resolveChallenge(uint256 id, address worker) external nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted && o.state != State.Disputed) revert WrongState();
        Challenge storage c = _challenges[id][worker];
        if (!c.open || c.epoch != o.payoutEpoch) revert NoOpenChallenge();
        if (block.timestamp <= c.answerBy) revert AnswerTooEarly();
        c.open = false;
        address challenger = c.challenger;
        emit Disputed(id, challenger, DISPUTE_UNANSWERED_CHALLENGE);
        _upholdObjective(id, o, challenger);
    }

    /// @inheritdoc IWorkMarket
    function resultEpochOf(uint256 id) external view returns (uint32) {
        return _offers[id].resultEpoch;
    }

    function challengeOf(uint256 id, address worker) external view returns (Challenge memory) {
        return _challenges[id][worker];
    }

    /// @notice Inside the dispute window, a joined worker or the poster makes the root answer for
    ///         tree slot `index` (`< 2^payoutDepth`) within `CHALLENGE_RESPONSE_WINDOW`. A slot
    ///         answered under the live root cannot be challenged again.
    function challengeIndex(uint256 id, uint32 index) external payable nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted) revert WrongState();
        if (block.timestamp >= uint256(o.payoutPostedAt) + o.disputeWindow) revert WindowClosed();
        if (msg.sender != o.poster && !_slots[id][msg.sender].joined) revert NotDisputer();
        if (uint256(index) >> o.payoutDepth != 0) revert BadEvidence();
        IndexChallenge storage c = _indexChallenges[id][index];
        if (c.epoch != o.payoutEpoch) {
            c.epoch = o.payoutEpoch;
            c.open = false;
            c.answered = false;
        }
        if (c.open) revert ChallengeOpen();
        if (c.answered) revert BadEvidence();
        uint64 answerBy = uint64(block.timestamp) + CHALLENGE_RESPONSE_WINDOW;
        c.open = true;
        c.challenger = msg.sender;
        c.answerBy = answerBy;
        o.openChallenges += 1;
        emit IndexChallenged(id, index, msg.sender, answerBy);
    }

    /// @notice Answer an open index challenge by opening slot `leaf.index` as a real leaf or as
    ///         padding (`leaf.worker == 0`). Anyone may answer; only until `answerBy`.
    function answerIndexChallenge(uint256 id, LeafOpening calldata leaf) external nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted && o.state != State.Disputed) revert WrongState();
        IndexChallenge storage c = _indexChallenges[id][leaf.index];
        if (!c.open || c.epoch != o.payoutEpoch) revert NoOpenChallenge();
        if (block.timestamp > c.answerBy) revert AnswerTooLate();
        if (!_opens(id, o, leaf)) revert BadAnswer();
        c.open = false;
        c.answered = true;
        o.openChallenges -= 1;
        _extendForAnswer(o);
        emit IndexChallengeAnswered(id, leaf.index, leaf.worker);
    }

    /// @notice After `answerBy`, an unanswered index challenge is upheld like an objective dispute.
    function resolveIndexChallenge(uint256 id, uint32 index) external nonReentrant {
        Offer storage o = _offer(id);
        if (o.state != State.PayoutPosted && o.state != State.Disputed) revert WrongState();
        IndexChallenge storage c = _indexChallenges[id][index];
        if (!c.open || c.epoch != o.payoutEpoch) revert NoOpenChallenge();
        if (block.timestamp <= c.answerBy) revert AnswerTooEarly();
        c.open = false;
        address challenger = c.challenger;
        emit Disputed(id, challenger, DISPUTE_UNANSWERED_CHALLENGE);
        _upholdObjective(id, o, challenger);
    }

    function challengeBondOf(uint256 id) public view returns (uint128) {
        uint256 cb = _offers[id].coordinatorBond;
        return uint128((cb * CHALLENGE_BOND_BPS + BPS - 1) / BPS);
    }

    // red: challenge bonds not refunded yet
    function reclaimChallengeBond(uint256, address) external pure {
        revert NothingToClaim();
    }

    function reclaimIndexChallengeBond(uint256, uint32) external pure {
        revert NothingToClaim();
    }

    function indexChallengeOf(uint256 id, uint32 index) external view returns (IndexChallenge memory) {
        return _indexChallenges[id][index];
    }

    // ── reserve sweep (V60-GEN-Q3) ──────────────────────────────────

    /// @notice After the poster's refund and `deadline + disputeWindow + RESERVE_CLAIM_PERIOD`,
    ///         return what the posted root reserved for workers who never settled. Settling stops.
    function sweepReserve(uint256 id) external nonReentrant {
        Offer storage o = _offer(id);
        if (msg.sender != o.poster) revert NotPoster();
        if (o.state != State.Closed || o.payoutRoot == bytes32(0) || o.reserveSwept) revert WrongState();
        if (block.timestamp < uint256(o.deadline) + o.disputeWindow + RESERVE_CLAIM_PERIOD) revert TooEarly();
        uint128 amount = uint128(uint256(o.payoutUnits) * o.pricePerUnit) - o.paid;
        o.reserveSwept = true;
        o.refunded += amount;
        balanceOf[o.poster] += amount;
        emit ReserveSwept(id, amount);
    }

    // ── withdraw ────────────────────────────────────────────────────

    function withdraw() external nonReentrant {
        uint256 amount = balanceOf[msg.sender];
        if (amount == 0) revert NothingToClaim();
        balanceOf[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // ── views ───────────────────────────────────────────────────────

    function getOffer(uint256 id) external view returns (Offer memory) {
        return _offers[id];
    }

    function offerParties(uint256 id)
        external
        view
        returns (Kind kind, State state, address poster, address verifier, address coordinator, bytes32 bindRef)
    {
        Offer storage o = _offers[id];
        return (o.kind, o.state, o.poster, o.verifier, o.coordinator, o.bindRef);
    }

    function joined(uint256 id, address worker) external view returns (bool) {
        return _slots[id][worker].joined;
    }

    function settled(uint256 id, address worker) external view returns (bool) {
        return _slots[id][worker].settled;
    }

    function joinBondReleased(uint256 id, address worker) external view returns (bool) {
        return _slots[id][worker].bondReleased;
    }

    /// @notice SALT the contract owes on `id` (escrow left plus bonds held), excluding pull balances.
    function owedOn(uint256 id) public view returns (uint256) {
        Offer storage o = _offers[id];
        uint256 owed = uint256(o.budget) - o.paid - o.refunded;
        owed += uint256(o.joinBond) * (o.workers - o.joinBondsReleased);
        if (o.coordinatorBondHeld) owed += o.coordinatorBond;
        return owed;
    }

    function leafPayload(uint256 id, address worker, uint64 units, uint64 cumBefore) public view returns (bytes32) {
        return keccak256(abi.encode(LEAF_TAG, block.chainid, address(this), id, worker, units, cumBefore));
    }

    function leafHash(uint32 index, bytes32 payload) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), index, payload));
    }

    function receiptDigest(uint256 id, address worker, bytes32 leaseId, bytes32 deltaHash)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(RECEIPT_TAG, block.chainid, address(this), id, worker, leaseId, deltaHash, true));
    }

    // ── internals ───────────────────────────────────────────────────

    function _offer(uint256 id) internal view returns (Offer storage o) {
        o = _offers[id];
        if (o.poster == address(0)) revert UnknownOffer();
    }

    function _clearPayout(Offer storage o) internal {
        o.payoutRoot = bytes32(0);
        o.leavesRoot = bytes32(0);
        o.digest = bytes32(0);
        o.payoutPostedAt = 0;
        o.payoutUnits = 0;
        o.settledUnits = 0;
        o.payoutEpoch += 1;
        o.openChallenges = 0;
        o.payoutDepth = 0;
        o.answerGraceUntil = 0;
    }

    /// Disputes close at the end of the posted root's window, or `POST_ANSWER_DISPUTE_WINDOW` after
    /// the latest challenge answer, whichever is later. Settling and the coordinator bond wait for it.
    function _disputeEnd(Offer storage o) internal view returns (uint256 end) {
        end = uint256(o.payoutPostedAt) + o.disputeWindow;
        if (o.answerGraceUntil > end) end = o.answerGraceUntil;
    }

    function _extendForAnswer(Offer storage o) internal {
        uint64 until = uint64(block.timestamp) + POST_ANSWER_DISPUTE_WINDOW;
        if (until > o.answerGraceUntil) o.answerGraceUntil = until;
    }

    /// Smallest depth whose `2^depth` slots hold `maxWorkers` leaves (`maxWorkers <= 1024`).
    function _depthFor(uint32 maxWorkers) internal pure returns (uint8 d) {
        while ((uint256(1) << d) < maxWorkers) d++;
    }

    function _releaseCoordinatorBond(uint256 id, Offer storage o) internal {
        if (!o.coordinatorBondHeld) return;
        o.coordinatorBondHeld = false;
        if (o.coordinatorBond != 0) {
            balanceOf[o.coordinator] += o.coordinatorBond;
            emit BondReleased(id, o.coordinator, o.coordinatorBond);
        }
    }

    /// Objective dispute upheld: payout frozen and withdrawn, bond slashed, offer runs again.
    function _upholdObjective(uint256 id, Offer storage o, address disputer) internal {
        uint128 bond = o.coordinatorBondHeld ? o.coordinatorBond : 0;
        o.coordinatorBondHeld = false;
        uint128 toDisputer = 0;
        if (disputer != o.poster) toDisputer = uint128((uint256(bond) * SLASH_DISPUTER_BPS) / BPS);
        uint128 toPoster = bond - toDisputer;
        if (toDisputer != 0) balanceOf[disputer] += toDisputer;
        if (toPoster != 0) balanceOf[o.poster] += toPoster;
        emit CoordinatorSlashed(id, disputer, toDisputer, toPoster);
        _clearPayout(o);
        o.state = State.Running;
    }

    /// Opens a leaf (real or padding) against the posted root and returns false if it does not open.
    /// The path must have exactly the posted depth and the index must name one of its slots.
    function _opens(uint256 id, Offer storage o, LeafOpening memory l) internal view returns (bool) {
        if (l.path.length != o.payoutDepth) return false;
        if (uint256(l.index) >> o.payoutDepth != 0) return false;
        bytes32 leaf =
            l.worker == address(0) ? bytes32(0) : leafHash(l.index, leafPayload(id, l.worker, l.units, l.cumBefore));
        return _rootFrom(leaf, l.index, l.path) == o.leavesRoot;
    }

    function _rootFrom(bytes32 leaf, uint32 index, bytes32[] memory path) internal pure returns (bytes32 h) {
        h = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < path.length; i++) {
            h = (idx & 1) == 0
                ? keccak256(abi.encodePacked(bytes1(0x01), h, path[i]))
                : keccak256(abi.encodePacked(bytes1(0x01), path[i], h));
            idx >>= 1;
        }
    }

    function _receiptValid(uint256 id, Offer storage o, Receipt memory r) internal view returns (bool) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(receiptDigest(id, r.worker, r.leaseId, r.deltaHash));
        return SignatureChecker.isValidSignatureNow(o.coordinator, digest, r.signature);
    }

    /// The coordinator signed a verified lease for a joined worker, and the worker has no leaf.
    function _provesMissingLeaf(uint256 id, Offer storage o, bytes memory body) internal view returns (bool) {
        (Receipt memory r, uint8 mode, LeafOpening memory lo, LeafOpening memory hi) =
            abi.decode(body, (Receipt, uint8, LeafOpening, LeafOpening));
        address w = r.worker;
        if (w == address(0) || !_slots[id][w].joined) return false;
        if (!_receiptValid(id, o, r)) return false;

        if (mode == ABSENT_BETWEEN) {
            return lo.worker != address(0) && hi.worker != address(0) && hi.index == uint256(lo.index) + 1
                && lo.worker < w && w < hi.worker && _opens(id, o, lo) && _opens(id, o, hi);
        }
        if (mode == ABSENT_BEFORE_FIRST) {
            return hi.index == 0 && hi.worker != address(0) && w < hi.worker && _opens(id, o, hi);
        }
        if (mode == ABSENT_AFTER_LAST) {
            if (lo.worker == address(0) || !(lo.worker < w) || !_opens(id, o, lo)) return false;
            // lo is the last real leaf: it is the tree's last slot, or the next slot is padding.
            bool lastSlot = uint256(lo.index) + 1 == (uint256(1) << o.payoutDepth);
            if (lastSlot) return true;
            return hi.worker == address(0) && hi.index == uint256(lo.index) + 1 && _opens(id, o, hi);
        }
        if (mode == ABSENT_EMPTY) {
            return hi.index == 0 && hi.worker == address(0) && _opens(id, o, hi);
        }
        return false;
    }

    /// The coordinator signed more distinct verified leases for a worker than its leaf pays.
    function _provesLowUnits(uint256 id, Offer storage o, bytes memory body) internal view returns (bool) {
        (LeafOpening memory leaf, Receipt[] memory receipts) = abi.decode(body, (LeafOpening, Receipt[]));
        if (leaf.worker == address(0) || !_opens(id, o, leaf)) return false;
        if (receipts.length > MAX_RECEIPTS_PER_DISPUTE || receipts.length <= leaf.units) return false;
        bytes32 prevLease = bytes32(0);
        for (uint256 i = 0; i < receipts.length; i++) {
            Receipt memory r = receipts[i];
            // strictly ascending lease ids: distinct without a set
            if (r.worker != leaf.worker || (i > 0 && r.leaseId <= prevLease)) return false;
            if (!_receiptValid(id, o, r)) return false;
            prevLease = r.leaseId;
        }
        return true;
    }

    /// Two openable leaves `a.index < b.index` (any two, not only neighbours) break the tree
    /// rules: padding before a real leaf, workers not strictly ascending, or overlapping ranges
    /// (`a.cumBefore + a.units > b.cumBefore`). Neighbours must also abut exactly.
    function _provesBadOrder(uint256 id, Offer storage o, bytes memory body) internal view returns (bool) {
        (LeafOpening memory a, LeafOpening memory b) = abi.decode(body, (LeafOpening, LeafOpening));
        if (a.index >= b.index) return false;
        if (!_opens(id, o, a) || !_opens(id, o, b)) return false;
        if (b.worker == address(0)) return false; // real-then-padding or padding-then-padding is fine
        if (a.worker == address(0)) return true; // padding before a real leaf
        if (a.worker >= b.worker) return true;
        uint256 aEnd = uint256(a.cumBefore) + a.units;
        if (b.index == uint256(a.index) + 1) return aEnd != b.cumBefore;
        return aEnd > b.cumBefore;
    }

    /// The first real leaf must start the prefix sum at zero.
    function _provesBadFirstLeaf(uint256 id, Offer storage o, bytes memory body) internal view returns (bool) {
        LeafOpening memory f = abi.decode(body, (LeafOpening));
        return f.index == 0 && f.worker != address(0) && f.cumBefore != 0 && _opens(id, o, f);
    }
}
