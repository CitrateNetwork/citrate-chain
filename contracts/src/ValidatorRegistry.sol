// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/Governable.sol";

/// @title ValidatorRegistry — stake-gated proposer-set membership for chain 40204 (VALIDATOR-S1 v5)
/// @notice Binds an ed25519 block-proposer key to a staked identity. A node may
///         propose blocks only if its proposer key is in the ACTIVE SET at the
///         block's epoch snapshot with bonded stake >= its admission minStake.
///         Consensus enforces MEMBERSHIP only (no per-slot lottery); leadership is
///         a soft producer-side round-robin (see
///         docs/consensus/VALIDATOR_S1_stake_gated_eligibility.md).
///
/// @dev Hardened across THREE adversarial review rounds (spec ×2 + code ×1). Round-3
///      (code) resolutions baked in here:
///        - **Every exit of principal is escrowed and stays slashable** for the full
///          UNBOND+EVIDENCE window — including PARTIAL unbonds. This closes the
///          "pull everything but minStake instantly, then double-sign" slash-evasion
///          that capped real at-risk stake at minStake regardless of bond size.
///        - **Rewards are ETH-backed at credit time**: creditReward is payable and
///          requires msg.value == amount, so vestedRewards can never exceed balance
///          (no reward-driven insolvency draining other validators' principal).
///        - **Non-Byzantine slashing demotes** a validator whose bond falls below its
///          admission minStake (no sub-minStake member left Active/in-set).
///        - **Bounties are pull-payment** (claimBounty) — a reverting reporter can
///          never block a proven equivocation slash, and slashing does no external call.
///        - **1/3 effective-stake cap is a true fixpoint** (clamp to effTotal/3 until
///          stable) — the previous raw-total clamp did NOT bound effective share.
///          NOTE: the cap is per-PUBKEY, not per-beneficial-owner; a sybil operator
///          running N funded identities is not bounded on-chain (documented residual;
///          per-owner grouping needs an off-chain sybil-resistance assumption).
///        - **Grandfathering is real**: each validator stores its admission minStake;
///          a governance minStake raise is prospective (new registrations only) and
///          never demotes or blocks partial-unbond of a sitting validator.
///        - **All governance params have immutable absolute floors/ceilings**, enforced
///          even on the current==0 bootstrap path (the anti-hyperinflation emission cap
///          is itself bounded).
///
///      COMPANION (node-side §8) REQUIREMENT — NOT satisfiable by this contract alone:
///        submitEquivocation verifies each double-sign signature over the EIP-712
///        EquivocationVote(chainId, registry, height, blockHash) digest. The node MUST
///        sign that exact digest as a block-vote (in addition to / instead of the raw
///        block hash in core/consensus/src/crypto.rs::sign_block) and make both
///        signatures retrievable, or the permissionless Byzantine-slash path is inert.
///        A raw-block-hash signature cannot prove two blocks share a height, so the
///        height-binding vote is mandatory. Tracked in the spec §8 companion changes.
contract ValidatorRegistry is ReentrancyGuard, Governable {
    // ─────────────────────────────────────────────────────────────────────────
    // Epoch / snapshot geometry — MUST match the node's canonical epoch()/S()
    // (docs/consensus/VALIDATOR_S1_...): epoch(h)=h/EPOCH, S(E)=E*EPOCH-SNAPSHOT_LAG.
    // ─────────────────────────────────────────────────────────────────────────
    uint256 public constant EPOCH = 1000;
    uint256 public constant SNAPSHOT_LAG = 200;
    uint256 public constant MAX_ACTIVE_SET = 100;

    // Anti-capture knobs (immutable).
    uint256 public constant EVICTION_MARGIN_BPS = 2500; // newcomer must exceed incumbent-min by 25%
    uint256 public constant CHURN_CAP = 5;              // max evictions per epoch
    uint256 public constant UNBOND_PERIOD_EPOCHS = 3;   // >= activation + 2*finality
    uint256 public constant EVIDENCE_WINDOW_EPOCHS = 3; // principal stays slashable this long after unbond
    uint256 public constant EXIT_LOCK_EPOCHS = UNBOND_PERIOD_EPOCHS + EVIDENCE_WINDOW_EPOCHS;
    uint256 public constant MAX_CAP_ITERS = 256;        // fixpoint bound for the 1/3 cap (converges well below)

    // Governance absolute bounds (immutable) — governance may move params only within these.
    uint256 public constant MIN_STAKE_FLOOR = 1_000 ether;          // 1k SALT
    uint256 public constant MIN_STAKE_CEIL = 1_000_000 ether;       // 1M SALT
    uint256 public constant BLOCK_SUBSIDY_CEIL = 1_000 ether;       // <= 1k SALT / block
    uint256 public constant MAX_EPOCH_EMISSION_CEIL = 1_000_000 ether; // <= 1M SALT / epoch (~1k/block avg)
    uint256 public constant GOV_TIMELOCK = 2 days;
    uint256 public constant GOV_MAX_DELTA_BPS = 5000;               // a single change may move a param <= 50%

    // Equivocation bounty is a fraction of the slashed stake, capped low so self-slash is -EV.
    uint256 public constant BOUNTY_BPS = 1000; // 10%

    // The 0x0120 ed25519-verify precompile: input = pubkey(32)||sig(64)||message; out 32B (1=valid).
    address public constant ED25519_VERIFY = address(0x0120);

    // EIP-712-style domains signed by the ed25519 proposer key.
    bytes32 public constant REGISTER_TYPEHASH =
        keccak256("Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)");
    bytes32 public constant EQUIVOCATION_TYPEHASH =
        keccak256("EquivocationVote(uint256 chainId,address registry,uint64 height,bytes32 blockHash)");

    enum Status { None, Active, Exiting, Slashed }
    enum SlashTier { Latency, Inconsistency, Byzantine } // mirrors NematocystSlashing

    struct Validator {
        address staker;
        uint256 bondedStake;      // active slashable principal (backs membership + reward weight)
        uint256 vestedRewards;    // UNMATURED rewards — still inside the evidence window, still slashable
        uint256 ripeRewards;      // ADR-5: survived the window — claimable while ACTIVE, NOT slashable
        uint256 escrow;           // unbonded principal, STILL SLASHABLE until escrowUnlockEpoch
        uint256 admissionMinStake;// minStake in effect at registration (grandfathering anchor)
        uint64 activationEpoch;
        uint64 exitEpoch;         // epoch a full exit began; 0 while Active
        uint64 escrowUnlockEpoch; // when `escrow` becomes withdrawable
        Status status;
        bool withdrawn;           // final rewards released (full-exit terminal flag)
    }

    // ── ADR-5: matured-reward ring ──────────────────────────────────────────
    // Rewards leave the slashable base only after surviving REWARD_RING epochs,
    // which is strictly longer than EVIDENCE_WINDOW_EPOCHS — so equivocation
    // slashing is never weakened by a claim.
    //
    // A fixed ring indexed by `epoch % REWARD_RING` bounds this to O(1) writes
    // and an O(REWARD_RING) sweep. Because two epochs mapping to the same slot
    // are always a multiple of REWARD_RING apart, a slot holding a DIFFERENT
    // epoch than the current one is necessarily already matured — the property
    // that makes the ring correct without storing an unbounded history.
    uint256 public constant REWARD_RING = EVIDENCE_WINDOW_EPOCHS + 1; // 4
    mapping(bytes32 => uint256[4]) private _rewardRing;
    mapping(bytes32 => uint64[4]) private _rewardRingEpoch;

    // proposerPubkey (canonical 32-byte ed25519 encoding) => record
    mapping(bytes32 => Validator) private _validators;
    mapping(address => bytes32) public pubkeyOfStaker;       // one active binding per staker
    mapping(bytes32 => bool) public pubkeyEverRegistered;    // permanent single-use of a key
    mapping(bytes32 => bool) public slashedPubkey;           // permanent ban (key)
    mapping(address => bool) public slashedStaker;           // permanent ban (staker)
    mapping(address => uint256) public registrationNonce;    // replay guard
    mapping(bytes32 => bool) public usedEquivocation;        // proof dedup
    mapping(address => uint256) public claimable;            // pull-payment bounties

    // Bounded active set (canonical order computed in the view).
    bytes32[] private _activeSet;
    mapping(bytes32 => uint256) private _activeIndexPlusOne; // 0 = not in set

    // Per-epoch churn + emission meters.
    mapping(uint256 => uint256) public evictionsInEpoch;
    mapping(uint256 => uint256) public emittedInEpoch;

    // ── Governance params (timelocked, bounded; read by the node at S(E)) ──
    uint256 public minStake;
    uint256 public blockSubsidy;
    uint256 public priorityFeeShareBps; // <= 10000 (100% admissible; WS-5 reconcile)
    uint256 public maxEpochEmission;    // hard cap per epoch
    address public slasher;             // authorizes non-equivocation slash tiers
    address public immutable rewardMinter; // execution-layer system address that funds+credits reward

    struct PendingParam { uint256 value; uint256 eta; bool exists; }
    mapping(bytes32 => PendingParam) public pendingParam;
    struct PendingAddr { address value; uint256 eta; bool exists; }
    mapping(bytes32 => PendingAddr) public pendingAddr;

    // ── Events ──
    event ValidatorRegistered(bytes32 indexed pubkey, address indexed staker, uint256 stake, uint64 activationEpoch);
    event StakeIncreased(bytes32 indexed pubkey, uint256 newStake);
    event UnbondInitiated(bytes32 indexed pubkey, uint256 amount, uint256 remaining, uint64 unlockEpoch);
    event Withdrawn(bytes32 indexed pubkey, address indexed staker, uint256 amount);
    event Evicted(bytes32 indexed pubkey, uint256 incumbentStake, bytes32 indexed byPubkey, uint256 newcomerStake);
    event Slashed(bytes32 indexed pubkey, SlashTier tier, uint256 penalty, address indexed reporter, uint256 bounty);
    event Demoted(bytes32 indexed pubkey, uint256 bondedStake, uint256 admissionMinStake);
    event BountyClaimed(address indexed reporter, uint256 amount);
    event RewardCredited(bytes32 indexed pubkey, uint256 amount, uint256 epoch);
    /// ADR-5: matured rewards paid out to an ACTIVE validator (no unbond required).
    event RewardsClaimed(bytes32 indexed pubkey, address indexed staker, uint256 amount);
    event ParamQueued(bytes32 indexed name, uint256 value, uint256 eta);
    event ParamExecuted(bytes32 indexed name, uint256 value);
    event SlasherQueued(address slasher, uint256 eta);
    event SlasherSet(address slasher);

    // ── Errors ──
    error BadStake();
    error Banned();
    error PubkeyTaken();
    error StakerHasValidator();
    error NotStaker();
    error NotActive();
    error BadSig();
    error SetFullNoMargin();
    error ChurnExceeded();
    error Locked();
    error NothingToWithdraw();
    error AlreadyWithdrawn();
    error AlreadySlashed();
    error NotSlasher();
    error NotMinter();
    error BadValue();
    error EmissionCapped();
    error BadEvidence();
    error DupEvidence();
    error SelfReport();
    error Timelock();
    error OutOfBounds();
    error ZeroAddr();

    constructor(
        address governance_,
        address slasher_,
        address rewardMinter_,
        uint256 minStake_,
        uint256 blockSubsidy_,
        uint256 priorityFeeShareBps_,
        uint256 maxEpochEmission_
    ) Governable(governance_) {
        if (slasher_ == address(0) || rewardMinter_ == address(0)) revert ZeroAddr();
        if (minStake_ < MIN_STAKE_FLOOR || minStake_ > MIN_STAKE_CEIL) revert OutOfBounds();
        // Admit up to and INCLUDING 100% (10000 bps): the owner routes the entire
        // priority-fee share to validators (WS-4 §R'). Only > 100% is nonsensical.
        if (priorityFeeShareBps_ > 10000) revert OutOfBounds();
        if (blockSubsidy_ > BLOCK_SUBSIDY_CEIL) revert OutOfBounds();
        if (maxEpochEmission_ > MAX_EPOCH_EMISSION_CEIL) revert OutOfBounds();
        slasher = slasher_;
        rewardMinter = rewardMinter_;
        minStake = minStake_;
        blockSubsidy = blockSubsidy_;
        priorityFeeShareBps = priorityFeeShareBps_;
        maxEpochEmission = maxEpochEmission_;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Epoch helpers (canonical — the node uses the identical math)
    // ─────────────────────────────────────────────────────────────────────────
    function epochOf(uint256 blockHeight) public pure returns (uint256) {
        return blockHeight / EPOCH;
    }

    /// Smallest E with S(E)=E*EPOCH-SNAPSHOT_LAG strictly after `blockHeight`, so a
    /// registration is only promised activation once the snapshot can actually see it.
    function firstEpochAfterSnapshot(uint256 blockHeight) public pure returns (uint64) {
        return uint64((blockHeight + SNAPSHOT_LAG) / EPOCH + 1);
    }

    function currentEpoch() public view returns (uint256) {
        return block.number / EPOCH;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Registration
    // ─────────────────────────────────────────────────────────────────────────
    function registerValidator(bytes32 proposerPubkey, bytes calldata ed25519Sig)
        external
        payable
        nonReentrant
    {
        if (msg.value < minStake) revert BadStake();
        if (slashedPubkey[proposerPubkey] || slashedStaker[msg.sender]) revert Banned();
        if (_validators[proposerPubkey].status != Status.None || pubkeyEverRegistered[proposerPubkey]) {
            revert PubkeyTaken();
        }
        if (pubkeyOfStaker[msg.sender] != bytes32(0)) revert StakerHasValidator();

        // Proof of proposer-key control: the ed25519 key signs the EIP-712 register digest.
        uint256 nonce = registrationNonce[msg.sender];
        bytes32 digest = keccak256(
            abi.encode(REGISTER_TYPEHASH, block.chainid, address(this), msg.sender, proposerPubkey, nonce)
        );
        if (!_ed25519Verify(proposerPubkey, ed25519Sig, abi.encodePacked(digest))) revert BadSig();
        registrationNonce[msg.sender] = nonce + 1;

        // Set admission: if full, require a margin over the incumbent minimum + churn budget.
        if (_activeSet.length >= MAX_ACTIVE_SET) {
            (bytes32 minPubkey, uint256 minStakeInSet) = _minActive();
            uint256 required = minStakeInSet + (minStakeInSet * EVICTION_MARGIN_BPS) / 10000;
            if (msg.value < required) revert SetFullNoMargin();
            uint256 ep = currentEpoch();
            if (evictionsInEpoch[ep] >= CHURN_CAP) revert ChurnExceeded();
            evictionsInEpoch[ep] += 1;
            _beginExit(minPubkey); // evicted incumbent's bond escrows + stays slashable (no seizure)
            emit Evicted(minPubkey, minStakeInSet, proposerPubkey, msg.value);
        }

        uint64 actEpoch = firstEpochAfterSnapshot(block.number);
        _validators[proposerPubkey] = Validator({
            staker: msg.sender,
            bondedStake: msg.value,
            vestedRewards: 0,
            ripeRewards: 0,
            escrow: 0,
            admissionMinStake: minStake,
            activationEpoch: actEpoch,
            exitEpoch: 0,
            escrowUnlockEpoch: 0,
            status: Status.Active,
            withdrawn: false
        });
        pubkeyOfStaker[msg.sender] = proposerPubkey;
        pubkeyEverRegistered[proposerPubkey] = true;
        _activeSet.push(proposerPubkey);
        _activeIndexPlusOne[proposerPubkey] = _activeSet.length;

        emit ValidatorRegistered(proposerPubkey, msg.sender, msg.value, actEpoch);
    }

    function increaseStake(bytes32 pubkey) external payable nonReentrant {
        Validator storage v = _validators[pubkey];
        if (v.staker != msg.sender) revert NotStaker();
        if (v.status != Status.Active) revert NotActive();
        v.bondedStake += msg.value;
        emit StakeIncreased(pubkey, v.bondedStake);
    }

    /// Reduce bonded stake. The withdrawn principal is ESCROWED and stays fully slashable
    /// for the UNBOND+EVIDENCE window — a partial unbond is NOT an instant, risk-free exit.
    /// Full exit (amount == bond) → Exiting + leaves the active set. Partial exit must leave
    /// >= the validator's ADMISSION minStake (grandfathered, not the live governance value).
    function initiateUnbond(bytes32 pubkey, uint256 amount) external nonReentrant {
        Validator storage v = _validators[pubkey];
        if (v.staker != msg.sender) revert NotStaker();
        if (v.status != Status.Active) revert NotActive();
        if (amount == 0 || amount > v.bondedStake) revert BadStake();
        uint256 remaining = v.bondedStake - amount;
        if (remaining != 0 && remaining < v.admissionMinStake) revert BadStake();

        uint64 unlock = uint64(currentEpoch() + EXIT_LOCK_EPOCHS);
        v.escrow += amount;
        v.escrowUnlockEpoch = unlock; // conservative: extends the whole escrow to the latest lock

        if (remaining == 0) {
            v.bondedStake = 0;
            v.status = Status.Exiting;
            v.exitEpoch = uint64(currentEpoch());
            _removeFromActive(pubkey);
            pubkeyOfStaker[msg.sender] = bytes32(0);
        } else {
            v.bondedStake = remaining; // stays Active; escrowed amount is still slashable
        }
        emit UnbondInitiated(pubkey, amount, remaining, unlock);
    }

    /// Withdraw matured escrow, and (on full exit, once bond+escrow are gone) the vested rewards.
    /// Escrow is only payable after escrowUnlockEpoch, so the evidence window always covers it.
    function withdraw(bytes32 pubkey) external nonReentrant {
        Validator storage v = _validators[pubkey];
        if (v.staker != msg.sender) revert NotStaker();
        if (v.status == Status.Slashed) revert AlreadySlashed();

        uint256 payout;
        if (v.escrow > 0) {
            if (currentEpoch() < v.escrowUnlockEpoch) revert Locked();
            payout += v.escrow;
            v.escrow = 0;
        }
        // Terminal reward release for a fully-exited validator (bond and escrow both cleared).
        if (v.status == Status.Exiting && v.bondedStake == 0 && v.escrow == 0 && !v.withdrawn) {
            if (currentEpoch() < uint256(v.exitEpoch) + EXIT_LOCK_EPOCHS) revert Locked();
            // ADR-5: the terminal release covers BOTH buckets — anything still
            // inside its window and anything already matured but never claimed.
            payout += v.vestedRewards + v.ripeRewards;
            v.vestedRewards = 0;
            v.ripeRewards = 0;
            delete _rewardRing[pubkey];
            delete _rewardRingEpoch[pubkey];
            v.withdrawn = true;
        }
        if (payout == 0) revert NothingToWithdraw();
        (bool ok, ) = payable(msg.sender).call{value: payout}("");
        require(ok, "xfer");
        emit Withdrawn(pubkey, msg.sender, payout);
    }

    /// Pull-payment for equivocation bounties — decoupled from the slash so a reverting
    /// reporter can never block a proven slash.
    function claimBounty() external nonReentrant {
        uint256 amt = claimable[msg.sender];
        if (amt == 0) revert NothingToWithdraw();
        claimable[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok, "xfer");
        emit BountyClaimed(msg.sender, amt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slashing
    // ─────────────────────────────────────────────────────────────────────────

    /// Permissionless equivocation slash. Evidence = two DISTINCT block hashes at the SAME
    /// height, each signed by `pubkey` in the EquivocationVote domain (verified on-chain).
    function submitEquivocation(
        bytes32 pubkey,
        uint64 height,
        bytes32 blockHashA,
        bytes calldata sigA,
        bytes32 blockHashB,
        bytes calldata sigB
    ) external nonReentrant {
        if (blockHashA == blockHashB) revert BadEvidence();
        Validator storage v = _validators[pubkey];
        if (v.status == Status.None || v.status == Status.Slashed) revert BadEvidence();
        if (v.staker == msg.sender) revert SelfReport();

        bytes32 lo = blockHashA < blockHashB ? blockHashA : blockHashB;
        bytes32 hi = blockHashA < blockHashB ? blockHashB : blockHashA;
        bytes32 dedup = keccak256(abi.encodePacked(pubkey, height, lo, hi));
        if (usedEquivocation[dedup]) revert DupEvidence();

        bytes32 digestA = keccak256(abi.encode(EQUIVOCATION_TYPEHASH, block.chainid, address(this), height, blockHashA));
        bytes32 digestB = keccak256(abi.encode(EQUIVOCATION_TYPEHASH, block.chainid, address(this), height, blockHashB));
        if (!_ed25519Verify(pubkey, sigA, abi.encodePacked(digestA))) revert BadEvidence();
        if (!_ed25519Verify(pubkey, sigB, abi.encodePacked(digestB))) revert BadEvidence();

        usedEquivocation[dedup] = true;
        _slash(pubkey, SlashTier.Byzantine, msg.sender);
    }

    /// Non-equivocation tiers (Latency/Inconsistency), authorized by the slasher.
    function slash(bytes32 pubkey, SlashTier tier, bytes calldata /*evidence*/) external nonReentrant {
        if (msg.sender != slasher) revert NotSlasher();
        _slash(pubkey, tier, address(0));
    }

    /// @dev No external calls — bounties accrue to `claimable` (pull-payment). CEI-clean.
    function _slash(bytes32 pubkey, SlashTier tier, address reporter) internal {
        Validator storage v = _validators[pubkey];
        if (v.status == Status.Slashed) revert AlreadySlashed();
        if (v.status == Status.None) revert BadEvidence();

        // ADR-5: realize maturity BEFORE computing the penalty base. Without
        // this the sweep is lazy (it happens only on credit/claim), so whether a
        // matured reward is slashable would depend on whether anyone happened to
        // call `claimRewards` first — and a validator expecting a slash could
        // shrink its own base by claiming at the right moment. Sweeping here
        // makes the base a pure function of the epoch.
        _sweepMatured(pubkey, v);

        uint256 penaltyBps = tier == SlashTier.Byzantine ? 10000 : (tier == SlashTier.Inconsistency ? 2000 : 500);
        // Slashable base includes escrowed (unbonded-but-still-locked) principal + vested rewards.
        uint256 slashable = v.bondedStake + v.escrow + v.vestedRewards;
        uint256 penalty = (slashable * penaltyBps) / 10000;

        // Draw from bond, then escrow, then rewards.
        uint256 rem = penalty;
        if (rem >= v.bondedStake) { rem -= v.bondedStake; v.bondedStake = 0; }
        else { v.bondedStake -= rem; rem = 0; }
        if (rem > 0) {
            if (rem >= v.escrow) { rem -= v.escrow; v.escrow = 0; }
            else { v.escrow -= rem; rem = 0; }
        }
        if (rem > 0) {
            v.vestedRewards = rem >= v.vestedRewards ? 0 : v.vestedRewards - rem;
        }

        if (reporter != address(0) && penalty > 0) {
            uint256 bounty = (penalty * BOUNTY_BPS) / 10000;
            if (bounty > 0) claimable[reporter] += bounty; // pull-payment; residue stays in contract
        }

        if (tier == SlashTier.Byzantine) {
            v.status = Status.Slashed;
            slashedPubkey[pubkey] = true;
            slashedStaker[v.staker] = true;
            if (_activeIndexPlusOne[pubkey] != 0) _removeFromActive(pubkey);
            pubkeyOfStaker[v.staker] = bytes32(0);
        } else if (v.status == Status.Active && v.bondedStake < v.admissionMinStake) {
            // A non-Byzantine slash that drops the bond below admission minStake demotes the
            // validator — no sub-minStake member is left Active / in the set. The reduced bond
            // escrows and stays slashable through the window.
            _beginExit(pubkey);
            emit Demoted(pubkey, v.bondedStake, v.admissionMinStake);
        }
        emit Slashed(pubkey, tier, penalty, reporter, reporter == address(0) ? 0 : (penalty * BOUNTY_BPS) / 10000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rewards — funded + credited per selected-chain block by the execution layer.
    // creditReward is PAYABLE and requires msg.value == amount, so every credited unit
    // is backed by real balance (no reward-driven insolvency). Integer only.
    // ─────────────────────────────────────────────────────────────────────────
    function creditReward(bytes32 pubkey, uint256 amount) external payable {
        if (msg.sender != rewardMinter) revert NotMinter();
        if (msg.value != amount) revert BadValue();
        Validator storage v = _validators[pubkey];
        if (v.status != Status.Active) revert NotActive();
        uint256 ep = currentEpoch();
        uint256 newTotal = emittedInEpoch[ep] + amount;
        if (newTotal > maxEpochEmission) revert EmissionCapped();
        emittedInEpoch[ep] = newTotal;

        // ADR-5: age out anything that has cleared the window, THEN book this
        // epoch's credit. After the sweep the target slot is either empty or
        // already holds `ep`, so the accumulate below can never merge two
        // different epochs into one bucket.
        _sweepMatured(pubkey, v);
        uint256 slot = ep % REWARD_RING;
        _rewardRing[pubkey][slot] += amount;
        _rewardRingEpoch[pubkey][slot] = uint64(ep);

        v.vestedRewards += amount;
        emit RewardCredited(pubkey, amount, ep);
    }

    /// ADR-5: move every ring bucket that has survived `REWARD_RING` epochs out
    /// of the slashable base (`vestedRewards`) and into claimable `ripeRewards`.
    ///
    /// Bounded at REWARD_RING iterations. Idempotent — safe to call on any path.
    ///
    /// The decrement is CLAMPED to `vestedRewards`: a non-Byzantine slash draws
    /// down `vestedRewards` without touching the ring, so the ring can transiently
    /// exceed it. Without the clamp that underflows and bricks every subsequent
    /// credit and claim for that validator.
    function _sweepMatured(bytes32 pubkey, Validator storage v) internal {
        uint256 ep = currentEpoch();
        uint256[4] storage ring = _rewardRing[pubkey];
        uint64[4] storage ringEpoch = _rewardRingEpoch[pubkey];
        for (uint256 i = 0; i < REWARD_RING; ++i) {
            uint256 amt = ring[i];
            if (amt == 0) continue;
            if (ep < uint256(ringEpoch[i]) + REWARD_RING) continue; // still slashable
            ring[i] = 0;
            uint256 dec = amt > v.vestedRewards ? v.vestedRewards : amt;
            v.vestedRewards -= dec;
            v.ripeRewards += dec;
        }
    }

    /// ADR-5: claim matured rewards WITHOUT unbonding.
    ///
    /// Before this existed, `withdraw` released rewards only on a full exit after
    /// `EXIT_LOCK_EPOCHS` — so a member could realise earnings only by ceasing to
    /// validate, which makes "run a node, earn SALT" untrue in practice.
    ///
    /// Only rewards that have cleared `REWARD_RING` epochs (> the equivocation
    /// evidence window) are payable, so this never shrinks the penalty available
    /// for provable equivocation.
    function claimRewards(bytes32 pubkey) external nonReentrant {
        Validator storage v = _validators[pubkey];
        if (v.staker != msg.sender) revert NotStaker();
        if (v.status == Status.Slashed) revert AlreadySlashed();

        _sweepMatured(pubkey, v);
        uint256 amt = v.ripeRewards;
        if (amt == 0) revert NothingToWithdraw();
        v.ripeRewards = 0; // CEI: zeroed before the transfer, and nonReentrant.

        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok, "xfer");
        emit RewardsClaimed(pubkey, msg.sender, amt);
    }

    /// Total unclaimed rewards (slashable + matured) and the portion claimable now.
    function rewardsOf(bytes32 pubkey) external view returns (uint256 total, uint256 claimableNow) {
        Validator storage v = _validators[pubkey];
        uint256 ep = currentEpoch();
        uint256 ripe = v.ripeRewards;
        uint256 unmatured = v.vestedRewards;
        uint256[4] storage ring = _rewardRing[pubkey];
        uint64[4] storage ringEpoch = _rewardRingEpoch[pubkey];
        for (uint256 i = 0; i < REWARD_RING; ++i) {
            uint256 amt = ring[i];
            if (amt == 0) continue;
            if (ep < uint256(ringEpoch[i]) + REWARD_RING) continue;
            uint256 dec = amt > unmatured ? unmatured : amt;
            unmatured -= dec;
            ripe += dec;
        }
        return (unmatured + ripe, ripe);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timelocked governance (bounded delta + absolute bounds; sitting validators grandfathered)
    // ─────────────────────────────────────────────────────────────────────────
    function queueParam(bytes32 name, uint256 value) external onlyGovernance {
        uint256 current = _paramValue(name);
        // Bounded per-change delta. current==0 would freeze the param under a % bound, so a
        // bootstrap-from-zero is allowed — but the absolute ceiling below still applies.
        if (current != 0) {
            uint256 maxDelta = (current * GOV_MAX_DELTA_BPS) / 10000;
            if (value > current + maxDelta || (value < current && current - value > maxDelta)) revert OutOfBounds();
        }
        // Absolute bounds — enforced for ALL params, including the bootstrap path.
        if (name == keccak256("minStake")) {
            if (value < MIN_STAKE_FLOOR || value > MIN_STAKE_CEIL) revert OutOfBounds();
        } else if (name == keccak256("blockSubsidy")) {
            if (value > BLOCK_SUBSIDY_CEIL) revert OutOfBounds();
        } else if (name == keccak256("priorityFeeShareBps")) {
            if (value > 10000) revert OutOfBounds(); // <= 100% (owner may route the full share)
        } else if (name == keccak256("maxEpochEmission")) {
            if (value > MAX_EPOCH_EMISSION_CEIL) revert OutOfBounds();
        } else {
            revert OutOfBounds();
        }
        pendingParam[name] = PendingParam({ value: value, eta: block.timestamp + GOV_TIMELOCK, exists: true });
        emit ParamQueued(name, value, block.timestamp + GOV_TIMELOCK);
    }

    function executeParam(bytes32 name) external onlyGovernance {
        PendingParam memory p = pendingParam[name];
        if (!p.exists) revert Timelock();
        if (block.timestamp < p.eta) revert Timelock();
        delete pendingParam[name];
        if (name == keccak256("minStake")) {
            // Prospective only: existing validators carry their own admissionMinStake, so a raise
            // never demotes or blocks the partial-unbond of a sitting validator.
            minStake = p.value;
        } else if (name == keccak256("blockSubsidy")) {
            blockSubsidy = p.value;
        } else if (name == keccak256("priorityFeeShareBps")) {
            priorityFeeShareBps = p.value;
        } else if (name == keccak256("maxEpochEmission")) {
            maxEpochEmission = p.value;
        } else {
            revert OutOfBounds();
        }
        emit ParamExecuted(name, p.value);
    }

    function queueSlasher(address newSlasher) external onlyGovernance {
        if (newSlasher == address(0)) revert ZeroAddr();
        pendingAddr[keccak256("slasher")] = PendingAddr({ value: newSlasher, eta: block.timestamp + GOV_TIMELOCK, exists: true });
        emit SlasherQueued(newSlasher, block.timestamp + GOV_TIMELOCK);
    }

    function executeSlasher() external onlyGovernance {
        PendingAddr memory p = pendingAddr[keccak256("slasher")];
        if (!p.exists) revert Timelock();
        if (block.timestamp < p.eta) revert Timelock();
        delete pendingAddr[keccak256("slasher")];
        slasher = p.value;
        emit SlasherSet(p.value);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Views (consensus reads these at the finalized snapshot block S(E))
    // ─────────────────────────────────────────────────────────────────────────

    /// Active set as (pubkey, effectiveStake) in CANONICAL order (sorted by pubkey), active-only,
    /// bounded by MAX_ACTIVE_SET. effectiveStake is the TRUE 1/3 cap: iteratively clamp every
    /// entry to floor(effectiveTotal/3) until no entry exceeds it (fixpoint). The node consumes
    /// effStakes for reward-weighting/leadership and MUST replicate this algorithm byte-for-byte.
    function activeSet() external view returns (bytes32[] memory pubkeys, uint256[] memory effStakes) {
        uint256 n = _activeSet.length;
        pubkeys = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) pubkeys[i] = _activeSet[i];
        // insertion sort by pubkey (n <= 100; view only)
        for (uint256 i = 1; i < n; i++) {
            bytes32 key = pubkeys[i];
            uint256 j = i;
            while (j > 0 && pubkeys[j - 1] > key) { pubkeys[j] = pubkeys[j - 1]; j--; }
            pubkeys[j] = key;
        }
        effStakes = new uint256[](n);
        for (uint256 i = 0; i < n; i++) effStakes[i] = _validators[pubkeys[i]].bondedStake;
        if (n < 3) return (pubkeys, effStakes); // cap is meaningless / self-defeating below 3

        // Fixpoint clamp: no entry may exceed floor(sum(effStakes)/3).
        for (uint256 iter = 0; iter < MAX_CAP_ITERS; iter++) {
            uint256 total;
            for (uint256 i = 0; i < n; i++) total += effStakes[i];
            uint256 cap = total / 3;
            bool changed = false;
            for (uint256 i = 0; i < n; i++) {
                if (effStakes[i] > cap) { effStakes[i] = cap; changed = true; }
            }
            if (!changed) break;
        }
    }

    function isActive(bytes32 pubkey) external view returns (bool) {
        return _validators[pubkey].status == Status.Active && _activeIndexPlusOne[pubkey] != 0;
    }

    function stakeOf(bytes32 pubkey) external view returns (uint256) {
        return _validators[pubkey].bondedStake;
    }

    function admissionMinStakeOf(bytes32 pubkey) external view returns (uint256) {
        return _validators[pubkey].admissionMinStake;
    }

    function validatorInfo(bytes32 pubkey)
        external
        view
        returns (
            address staker,
            uint256 bonded,
            uint256 rewards,
            uint256 escrow,
            uint256 admissionMin,
            uint64 actEpoch,
            uint64 exitEpoch,
            uint64 escrowUnlock,
            Status status,
            uint256 claimableNow
        )
    {
        Validator storage v = _validators[pubkey];
        // ADR-5: `rewards` is TOTAL unclaimed (slashable + matured) — what a
        // member has earned and not yet taken. `claimableNow` is the matured
        // portion `claimRewards` would pay right now. The trailing position keeps
        // every existing index stable for consumers already decoding this tuple.
        (uint256 total, uint256 ripe) = this.rewardsOf(pubkey);
        return (
            v.staker, v.bondedStake, total, v.escrow, v.admissionMinStake,
            v.activationEpoch, v.exitEpoch, v.escrowUnlockEpoch, v.status, ripe
        );
    }

    function activeCount() external view returns (uint256) {
        return _activeSet.length;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internals
    // ─────────────────────────────────────────────────────────────────────────
    function _paramValue(bytes32 name) internal view returns (uint256) {
        if (name == keccak256("minStake")) return minStake;
        if (name == keccak256("blockSubsidy")) return blockSubsidy;
        if (name == keccak256("priorityFeeShareBps")) return priorityFeeShareBps;
        if (name == keccak256("maxEpochEmission")) return maxEpochEmission;
        revert OutOfBounds();
    }

    function _minActive() internal view returns (bytes32 minPubkey, uint256 minStakeInSet) {
        minStakeInSet = type(uint256).max;
        uint256 n = _activeSet.length;
        for (uint256 i = 0; i < n; i++) {
            bytes32 pk = _activeSet[i];
            uint256 s = _validators[pk].bondedStake;
            if (s < minStakeInSet) { minStakeInSet = s; minPubkey = pk; }
        }
    }

    /// Move a validator's remaining bond into slashable escrow, drop it from the active set,
    /// and free its staker binding. Used by full unbond, eviction, and non-Byzantine demotion.
    /// The bond is NOT seized — it becomes withdrawable after EXIT_LOCK_EPOCHS.
    function _beginExit(bytes32 pubkey) internal {
        Validator storage v = _validators[pubkey];
        v.escrow += v.bondedStake;
        v.bondedStake = 0;
        v.escrowUnlockEpoch = uint64(currentEpoch() + EXIT_LOCK_EPOCHS);
        v.status = Status.Exiting;
        v.exitEpoch = uint64(currentEpoch());
        if (_activeIndexPlusOne[pubkey] != 0) _removeFromActive(pubkey);
        if (pubkeyOfStaker[v.staker] == pubkey) pubkeyOfStaker[v.staker] = bytes32(0);
    }

    function _removeFromActive(bytes32 pubkey) internal {
        uint256 idxPlus = _activeIndexPlusOne[pubkey];
        if (idxPlus == 0) return;
        uint256 idx = idxPlus - 1;
        uint256 last = _activeSet.length - 1;
        if (idx != last) {
            bytes32 moved = _activeSet[last];
            _activeSet[idx] = moved;
            _activeIndexPlusOne[moved] = idx + 1;
        }
        _activeSet.pop();
        _activeIndexPlusOne[pubkey] = 0;
    }

    /// STATICCALL the 0x0120 ed25519 precompile: input = pubkey(32)||sig(64)||message.
    /// Returns true iff the precompile returns a 32-byte word == 1. Fail-CLOSED on any anomaly
    /// (incl. an old binary without the precompile: codeless staticcall → out.length 0 → false).
    function _ed25519Verify(bytes32 pubkey, bytes calldata sig, bytes memory message) internal view returns (bool) {
        if (sig.length != 64) return false;
        bytes memory input = abi.encodePacked(pubkey, sig, message);
        (bool ok, bytes memory out) = ED25519_VERIFY.staticcall(input);
        if (!ok || out.length != 32) return false;
        return abi.decode(out, (uint256)) == 1;
    }

    receive() external payable {} // accept slashed-penalty residue / direct funding; no accounting
}
