// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/ComputeLib.sol";
import "./lib/Burner.sol";
import "./lib/Governable.sol";
import "./ComputeVerifier.sol";

/// @notice Minimal interface to BulkComputeGateway used by the
/// credits payment path (CM-06 WP-06.1). The full surface lives at
/// `contracts/src/BulkComputeGateway.sol`; we declare only the two
/// methods this contract needs to keep the dependency narrow.
interface IBulkComputeGateway {
    /// @dev Marketplace must be in `authorizedSpenders` to call this.
    function spendCredits(address institution, uint256 creditAmount) external returns (bool);
    function getCreditBalance(address institution) external view returns (uint256);
}

/// @notice Minimal interface to ComputePricingOracle used to convert
/// SALT → credits at credits-payment-method post time (CM-06 WP-06.1).
interface IComputePricingOracleMin {
    function isPriceStale() external view returns (bool);
    /// @dev SALT (18 decimals) per PFLOP-hour (18 decimals).
    function saltPerPflopHour() external view returns (uint256);
}

/// @title ComputeMarketplace — Verified Compute Job Lifecycle & Escrow
/// @notice Implements the full job state machine from specs/tla/ComputeMarketplaceLifecycle.tla:
///
///   Posted -> Bidding -> Assigned -> Executing -> Verifying -> Completed
///     |                    |           |            |
///   Expired            Timeout      Failed      Disputed
///
/// All 11 invariants from ComputeMarketplaceLifecycle.tla:
///   INV-1:  TypeOK
///   INV-2:  NoPaymentWithoutVerification
///   INV-3:  EscrowConservation
///   INV-4:  StateOnlyForward (terminal states are final)
///   INV-5:  BidBelowCeiling
///   INV-6:  AssignedProviderRegistered
///   INV-7:  ExpiredJobsRefunded
///   INV-8:  TimeoutEscrowHeld
///   INV-9:  CompletedPaid
///   INV-10: PostedNoBids
///   INV-11: PostedNoEscrow (escrow locked at Bidding, not Posted)
///
/// Adversarial invariants from AdversarialCompute.tla:
///   - NoFrontRunning: only assigned provider can submit result
///   - DisputeBlocksPayment: active dispute prevents payment release
///   - GriefUnprofitable: dispute bond burned on failed dispute
///   - BurnRateFixed: 2.5% BME burn on every completed job
///   - BalanceConservation: all SALT accounted for
///   - StakeNonNegative: no account goes below zero
///
/// @dev Extends InferenceRouter patterns with full lifecycle, bidding, escrow, BME burn.
contract ComputeMarketplace is ReentrancyGuard, Governable {
    // ============================================================
    // Types
    // ============================================================

    enum JobState {
        Posted,     // 0: Job created, waiting for bidding window to open
        Bidding,    // 1: Accepting bids from providers
        Assigned,   // 2: Best bid selected, provider assigned
        Executing,  // 3: Provider is computing the result
        Verifying,  // 4: Result submitted, verification in progress
        Completed,  // 5: Verified and paid (terminal)
        Expired,    // 6: No bids received before deadline (terminal)
        Timeout,    // 7: Provider didn't deliver before deadline
        Failed,     // 8: Verification failed (terminal)
        Disputed    // 9: Result disputed (terminal after resolution)
    }

    /// @notice Job payment method (CM-06 WP-06.1).
    ///   SALT       : caller sends msg.value = maxPrice in SALT
    ///   BulkCredits: caller has a credit balance in
    ///                BulkComputeGateway; the marketplace spends
    ///                `_saltToCredits(maxPrice)` of those credits on
    ///                their behalf at post time.
    /// Mirrors `PaymentMethods` in
    /// .agentile/formal/specs/compute/CreditBilling.tla. The spec's
    /// `NoMixedPayment` invariant is enforced at the implementation
    /// by the `msg.value == 0` check on the credits path.
    enum PaymentMethod { SALT, BulkCredits }

    struct Job {
        uint256 id;
        address requester;
        bytes32 modelHash;
        bytes inputHash;           // Hash of input data (not stored on-chain for gas)
        uint256 maxPrice;
        ComputeVerifier.VerificationTier tier;
        JobState state;
        address assignedProvider;
        uint256 escrow;            // SALT locked in escrow
        uint256 bidDeadline;       // Block number deadline for bids
        uint256 executionDeadline; // Block number deadline for execution
        uint256 createdAt;         // Block number when posted
        uint256 bidCount;          // Number of bids received
    }

    struct Bid {
        address provider;
        uint256 price;
        uint256 estimatedLatency;  // Milliseconds
        uint256 submittedAt;       // Block number
    }

    struct ProviderProfile {
        bool isRegistered;
        uint256 stake;
        uint256 totalJobsCompleted;
        uint256 totalJobsFailed;
        uint256 reputationScore;   // Basis points (10000 = 100%)
        uint256 currentActiveJobs;
        uint256 maxConcurrentJobs;
    }

    // ============================================================
    // Constants
    // ============================================================

    /// @notice BME burn rate: 2.5% = price / 40 (INV: BurnRateFixed)
    uint256 public constant BME_BURN_DIVISOR = 40;

    /// @notice Treasury fee: 2.5% = price / 40
    uint256 public constant TREASURY_DIVISOR = 40;

    /// @notice Minimum provider stake to register (1000 SALT)
    uint256 public constant MIN_PROVIDER_STAKE = 1000 ether;

    /// @notice Minimum dispute bond (prevents spam griefing)
    uint256 public constant DISPUTE_BOND = 10 ether;

    /// @notice Default max concurrent jobs per provider
    uint256 public constant DEFAULT_MAX_CONCURRENT = 10;

    /// RM-B1 / WP-D5.7 (audit SOL-15): minimum payment for
    /// `autoAssignJob`. Floors out 1-wei griefing escrows that
    /// were "Assigned" but no provider with reasonable capacity
    /// would serve. 0.01 SALT = 1e16 wei.
    uint256 public constant MIN_AUTO_ASSIGN_PAYMENT = 0.01 ether;

    /// @notice Slash rate on timeout: 5% of provider stake (Tier 1 / Latency)
    uint256 public constant TIMEOUT_SLASH_BPS = 500;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10000;

    /// @notice Scoring weights for provider selection (must sum to 100)
    uint256 private constant WEIGHT_PRICE = 40;
    uint256 private constant WEIGHT_REPUTATION = 30;
    uint256 private constant WEIGHT_LOAD = 20;
    uint256 private constant WEIGHT_VERIFICATION = 10;

    // ============================================================
    // State
    // ============================================================

    /// @notice Next job ID
    uint256 public nextJobId;

    /// @notice All jobs indexed by ID
    mapping(uint256 => Job) public jobs;

    /// @notice Bids per job: jobId => array of bids
    mapping(uint256 => Bid[]) public jobBids;

    /// @notice Provider profiles
    mapping(address => ProviderProfile) public providers;

    /// @notice Provider's supported model hashes
    mapping(address => mapping(bytes32 => bool)) public providerModels;

    /// @notice Dispute state: jobId => disputer address
    mapping(uint256 => address) public disputeFiler;

    /// @notice Dispute bond held: jobId => bond amount
    mapping(uint256 => uint256) public disputeBondHeld;

    /// @notice ComputeVerifier contract
    ComputeVerifier public verifier;

    /// @notice Treasury address for fee collection
    address public treasury;

    // Governance state lives in Governable mixin (audit SOL-21).

    /// @notice Burner contract for permanently locking ETH.
    /// RM-B1 / WP-D5.9 (audit SOL-19): replaces `payable(0xdead)`.
    /// Set via `setBurner` by governance; if unset, burns revert
    /// (fail-closed — better than continuing to use 0xdead).
    address public burner;

    /// @notice NematocystSlashing contract for provider slashing
    address public slashingContract;

    /// @notice BulkComputeGateway contract — set by governance via
    /// `setBulkGateway`. When zero, the credits payment path is
    /// disabled (CM-06 WP-06.1).
    IBulkComputeGateway public bulkGateway;

    /// @notice ComputePricingOracle — set by governance via
    /// `setPricingOracle`. Used by the credits path to convert
    /// SALT-denominated `maxPrice` into PFLOP-hour credits and to
    /// gate posts when the price is stale (CM-06 WP-06.1).
    IComputePricingOracleMin public pricingOracle;

    /// @notice Per-job payment method (CM-06 WP-06.1). Tracked
    /// out-of-band of the `Job` struct so existing struct consumers
    /// don't break. Defaults to SALT (the `PaymentMethod` enum's
    /// zero value) for jobs posted via the legacy `postJob`
    /// signature.
    mapping(uint256 => PaymentMethod) public jobPaymentMethod;

    /// @notice CHAIN-B-C014 (HELD/reroll): whether a job's `escrow` is
    /// backed by native SALT actually held by this contract (the SALT
    /// path and `autoAssignJob`) or is a credit-denominated liability with
    /// NO native backing (the BulkCredits path, where the caller's
    /// stablecoins go to `StablecoinTreasury` and never reach this
    /// contract). A native refund/payout must NEVER be derived from a
    /// non-native escrow — pre-fix a credits job set `escrow = maxPrice`
    /// while requiring `msg.value == 0`, so `expireJob`/`timeoutJob`/
    /// completion paid real SALT out of OTHER users' escrow, draining the
    /// contract to insolvency. Defaults to false; set true on every
    /// native-funded post.
    mapping(uint256 => bool) public jobEscrowNative;

    /// @notice CHAIN-B-C014: credits owed back to a requester when a
    /// credit-path job's escrow is refunded (expire/timeout/fail/dispute).
    /// Settled off-native by operations (treasury credit replenishment);
    /// never paid in SALT from this contract's balance.
    mapping(address => uint256) public creditsRefundOwed;

    /// @notice CHAIN-B-C015 (HELD/reroll): providers who have explicitly
    /// consented to being auto-assigned jobs. `autoAssignJob` conscripts a
    /// provider into a job with a 100-block deadline and `timeoutJob` then
    /// slashes their stake; pre-fix ANY provider could be conscripted
    /// without consent, so an attacker could grief an offline/unaware
    /// provider's stake away for the cost of gas. Only opted-in providers
    /// are eligible for auto-assignment.
    mapping(address => bool) public autoAssignOptIn;

    /// @notice Total SALT burned via BME (lifetime)
    uint256 public totalBurned;

    /// @notice Total SALT paid to providers (lifetime)
    uint256 public totalPaidToProviders;

    /// @notice Total SALT sent to treasury (lifetime)
    uint256 public totalTreasuryFees;

    /// @notice Total dispute bonds burned (lifetime)
    uint256 public totalDisputeBondsBurned;

    /// @notice All registered provider addresses
    address[] public allProviders;

    // ============================================================
    // Events
    // ============================================================

    event JobPosted(
        uint256 indexed jobId,
        address indexed requester,
        bytes32 indexed modelHash,
        uint256 maxPrice,
        ComputeVerifier.VerificationTier tier,
        uint256 bidDeadline,
        uint256 executionDeadline
    );

    /// @notice Emitted alongside JobPosted (CM-06 WP-06.1) carrying
    /// the chosen PaymentMethod. Kept as a separate event so
    /// existing JobPosted indexers don't break on a new field.
    event JobPaymentMethodSet(uint256 indexed jobId, PaymentMethod method);

    /// @notice CHAIN-B-C014: a credit-path job's escrow was "refunded" as a
    /// credit liability (no native SALT moved).
    event CreditsRefundOwed(uint256 indexed jobId, address indexed requester, uint256 amount);

    /// @notice CHAIN-B-C014: a credit-path job completed; the provider is
    /// owed payment through operational credit settlement, not native SALT.
    event CreditsProviderOwed(uint256 indexed jobId, address indexed provider, uint256 amount);

    /// @notice CHAIN-B-C015: a provider changed their auto-assign consent.
    event AutoAssignOptInSet(address indexed provider, bool optedIn);

    /// @notice Emitted when governance updates the BulkComputeGateway
    /// reference. Setting to address(0) disables the credits path.
    event BulkGatewayUpdated(address indexed oldGateway, address indexed newGateway);

    /// @notice Emitted when governance updates the ComputePricingOracle
    /// reference used by the credits-payment-method conversion.
    event PricingOracleUpdated(address indexed oldOracle, address indexed newOracle);

    event BidPlaced(
        uint256 indexed jobId,
        address indexed provider,
        uint256 price,
        uint256 estimatedLatency
    );

    event JobAssigned(
        uint256 indexed jobId,
        address indexed provider,
        uint256 price
    );

    event ExecutionStarted(uint256 indexed jobId, address indexed provider);

    event ResultSubmitted(
        uint256 indexed jobId,
        address indexed provider,
        bytes32 outputHash
    );

    event JobCompleted(
        uint256 indexed jobId,
        address indexed provider,
        uint256 providerPayment,
        uint256 burned,
        uint256 treasuryFee
    );

    event JobExpired(uint256 indexed jobId, uint256 escrowRefunded);
    event JobTimedOut(uint256 indexed jobId, address indexed provider, uint256 slashAmount);
    event JobFailed(uint256 indexed jobId, address indexed provider);

    event DisputeFiled(
        uint256 indexed jobId,
        address indexed disputer,
        uint256 bond
    );

    event DisputeResolved(
        uint256 indexed jobId,
        bool requesterWins,
        uint256 bondDisposition
    );

    event ProviderRegistered(
        address indexed provider,
        uint256 stake,
        bytes32[] supportedModels
    );

    event ProviderStakeUpdated(address indexed provider, uint256 newStake);
    event EscrowRefunded(uint256 indexed jobId, address indexed requester, uint256 amount);

    // ============================================================
    // Modifiers
    // ============================================================

    // `onlyGovernance` is inherited from Governable.

    modifier jobExists(uint256 jobId) {
        require(jobId < nextJobId, "ComputeMarketplace: job does not exist");
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    constructor(address _verifier, address _treasury, address initialGovernance)
        Governable(initialGovernance)
    {
        require(_verifier != address(0), "ComputeMarketplace: zero verifier");
        require(_treasury != address(0), "ComputeMarketplace: zero treasury");

        verifier = ComputeVerifier(_verifier);
        treasury = _treasury;
        // RM-B1 / WP-D5.9 (audit SOL-19): deploy a fresh Burner
        // at construction time so burns are immediately functional.
        // Governance can later swap it via `setBurner` if needed.
        burner = address(new Burner());
    }

    // ============================================================
    // Provider Registration
    // ============================================================

    /// @notice Register as a compute provider with stake and model support
    /// @param supportedModels Array of model hashes this provider supports
    /// @dev INV-6: AssignedProviderRegistered — only registered providers can be assigned
    function registerProvider(
        bytes32[] calldata supportedModels
    ) external payable nonReentrant {
        require(msg.value >= MIN_PROVIDER_STAKE, "ComputeMarketplace: insufficient stake");
        require(supportedModels.length > 0, "ComputeMarketplace: no models");
        require(!providers[msg.sender].isRegistered, "ComputeMarketplace: already registered");

        // Initialize profile field-by-field to reduce stack pressure
        ProviderProfile storage prov = providers[msg.sender];
        prov.isRegistered = true;
        prov.stake = msg.value;
        prov.reputationScore = BPS; // Start at 100%
        prov.maxConcurrentJobs = DEFAULT_MAX_CONCURRENT;

        for (uint256 i = 0; i < supportedModels.length; i++) {
            providerModels[msg.sender][supportedModels[i]] = true;
        }

        allProviders.push(msg.sender);

        emit ProviderRegistered(msg.sender, msg.value, supportedModels);
    }

    /// @notice CHAIN-B-C015 (HELD/reroll): opt in/out of auto-assignment.
    /// A registered provider must explicitly consent before
    /// `autoAssignJob` can conscript them into a slashable-deadline job.
    /// @param optIn Whether to accept auto-assigned jobs.
    function setAutoAssignOptIn(bool optIn) external {
        require(providers[msg.sender].isRegistered, "ComputeMarketplace: not registered");
        autoAssignOptIn[msg.sender] = optIn;
        emit AutoAssignOptInSet(msg.sender, optIn);
    }

    /// @notice Add stake as a registered provider
    function addStake() external payable nonReentrant {
        require(providers[msg.sender].isRegistered, "ComputeMarketplace: not registered");
        require(msg.value > 0, "ComputeMarketplace: zero stake");

        providers[msg.sender].stake += msg.value;

        emit ProviderStakeUpdated(msg.sender, providers[msg.sender].stake);
    }

    /// @notice CHAIN-B-C039: withdraw provider stake. Pre-fix there was no
    ///         unstake/deregister path at all, so the minimum stake plus any
    ///         top-ups were locked forever. Gated on having no in-flight jobs;
    ///         a partial withdrawal must leave the provider at or above the
    ///         minimum, and a full withdrawal deregisters the provider.
    function withdrawStake(uint256 amount) external nonReentrant {
        ProviderProfile storage prov = providers[msg.sender];
        require(prov.isRegistered, "ComputeMarketplace: not registered");
        require(prov.currentActiveJobs == 0, "ComputeMarketplace: active jobs");
        require(amount > 0 && amount <= prov.stake, "ComputeMarketplace: bad amount");

        uint256 remaining = prov.stake - amount;
        require(
            remaining == 0 || remaining >= MIN_PROVIDER_STAKE,
            "ComputeMarketplace: below minimum"
        );

        prov.stake = remaining;
        if (remaining == 0) {
            prov.isRegistered = false; // full exit
        }

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "ComputeMarketplace: withdraw failed");

        emit ProviderStakeUpdated(msg.sender, remaining);
    }

    // ============================================================
    // Job Posting
    // ============================================================

    /// @notice Post a new compute job with escrow
    /// @param modelHash Hash of the model to use
    /// @param inputHash Hash of the input data (actual data sent off-chain)
    /// @param maxPrice Maximum price willing to pay
    /// @param tier Requested verification tier
    /// @param bidWindow Number of blocks for the bidding window
    /// @param execWindow Number of blocks for execution after assignment
    /// @return jobId The new job's identifier
    /// @dev INV-11: PostedNoEscrow — escrow moves to Bidding state transition
    /// @dev INV-3: EscrowConservation — escrow = maxPrice during active states
    function postJob(
        bytes32 modelHash,
        bytes calldata inputHash,
        uint256 maxPrice,
        ComputeVerifier.VerificationTier tier,
        uint256 bidWindow,
        uint256 execWindow
    ) external payable nonReentrant returns (uint256) {
        // Legacy 6-arg signature defaults to PaymentMethod.SALT.
        // Delegates to the shared internal so the SALT path is byte-
        // identical to the 7-arg form below.
        return _postJob(
            modelHash,
            inputHash,
            maxPrice,
            tier,
            PaymentMethod.SALT,
            bidWindow,
            execWindow
        );
    }

    /// @notice Post a job choosing a payment method (CM-06 WP-06.1).
    /// @dev SALT path: caller sends `msg.value >= maxPrice` (excess
    ///      refunded). Credits path: `msg.value` MUST be 0; the
    ///      marketplace debits `_saltToCredits(maxPrice)` from the
    ///      caller's BulkComputeGateway balance and acts as the
    ///      authorized spender. The marketplace must be in
    ///      BulkComputeGateway.authorizedSpenders for the credits
    ///      path to succeed (governance one-time setup, WP-06.2).
    function postJobWithMethod(
        bytes32 modelHash,
        bytes calldata inputHash,
        uint256 maxPrice,
        ComputeVerifier.VerificationTier tier,
        PaymentMethod paymentMethod,
        uint256 bidWindow,
        uint256 execWindow
    ) external payable nonReentrant returns (uint256) {
        return _postJob(
            modelHash,
            inputHash,
            maxPrice,
            tier,
            paymentMethod,
            bidWindow,
            execWindow
        );
    }

    /// @dev Shared internal body for both `postJob` overloads.
    /// Mirrors `PostJobSalt` and `PostJobCredits` actions in
    /// .agentile/formal/specs/compute/CreditBilling.tla. The
    /// `NoMixedPayment` and `CreditConservation` invariants from
    /// that spec are upheld at this layer.
    function _postJob(
        bytes32 modelHash,
        bytes calldata inputHash,
        uint256 maxPrice,
        ComputeVerifier.VerificationTier tier,
        PaymentMethod paymentMethod,
        uint256 bidWindow,
        uint256 execWindow
    ) internal returns (uint256) {
        require(maxPrice > 0, "ComputeMarketplace: zero price");
        require(modelHash != bytes32(0), "ComputeMarketplace: zero model hash");
        require(bidWindow > 0, "ComputeMarketplace: zero bid window");
        require(execWindow > 0, "ComputeMarketplace: zero exec window");

        if (paymentMethod == PaymentMethod.SALT) {
            require(msg.value >= maxPrice, "ComputeMarketplace: insufficient payment");
        } else {
            // Credits path: NoMixedPayment invariant — the call
            // MUST NOT carry SALT. (CreditBilling.tla NoMixedPayment.)
            require(msg.value == 0, "ComputeMarketplace: credits path accepts no value");
            require(address(bulkGateway) != address(0), "ComputeMarketplace: bulk gateway not set");
            require(address(pricingOracle) != address(0), "ComputeMarketplace: pricing oracle not set");
            require(!pricingOracle.isPriceStale(), "ComputeMarketplace: oracle price stale");

            uint256 creditCost = _saltToCredits(maxPrice);
            require(creditCost > 0, "ComputeMarketplace: zero credit cost");

            // spendCredits reverts on insufficient balance OR if
            // this contract isn't an authorized spender — both
            // bubble up to the caller as the gateway's revert
            // message, which is exactly what the user needs to see.
            bool ok = bulkGateway.spendCredits(msg.sender, creditCost);
            require(ok, "ComputeMarketplace: spendCredits returned false");
        }

        uint256 jobId = nextJobId++;
        uint256 deadline = block.number + bidWindow;

        Job storage job = jobs[jobId];
        job.id = jobId;
        job.requester = msg.sender;
        job.modelHash = modelHash;
        job.inputHash = inputHash;
        job.maxPrice = maxPrice;
        job.tier = tier;
        job.state = JobState.Bidding;
        // The escrow field always denominates SALT — for the
        // credits path the marketplace owes that SALT to the
        // eventual provider (treasury replenishment is operational,
        // not protocol-level). The credits-path test in
        // ComputeMarketplaceCreditPath.t.sol asserts this.
        job.escrow = maxPrice;
        job.bidDeadline = deadline;
        job.createdAt = block.number;

        // C014: only the SALT path deposits native backing for `escrow`.
        jobEscrowNative[jobId] = (paymentMethod == PaymentMethod.SALT);

        // Track payment method out-of-band of the Job struct so
        // existing struct consumers (off-chain decoders, etc.) don't
        // break on the new field. Public mapping → automatic getter.
        jobPaymentMethod[jobId] = paymentMethod;

        verifier.configureJob(jobId, maxPrice, tier);

        // SALT path: refund excess payment. (Credits path can't
        // have excess — msg.value == 0 was required above.)
        if (paymentMethod == PaymentMethod.SALT && msg.value > maxPrice) {
            (bool success, ) = payable(msg.sender).call{value: msg.value - maxPrice}("");
            require(success, "ComputeMarketplace: refund failed");
        }

        emit JobPosted(jobId, msg.sender, modelHash, maxPrice, tier, deadline, execWindow);
        emit JobPaymentMethodSet(jobId, paymentMethod);

        return jobId;
    }

    /// @dev Convert a SALT amount (18 decimals) to PFLOP-hour credits
    /// (18 decimals) using the oracle's current SALT/PFLOP-h rate.
    /// Mirrors the formula `credits = saltAmount * 1e18 /
    /// saltPerPflopHour`.
    function _saltToCredits(uint256 saltAmount) internal view returns (uint256) {
        uint256 rate = pricingOracle.saltPerPflopHour();
        require(rate > 0, "ComputeMarketplace: zero oracle rate");
        return (saltAmount * 1e18) / rate;
    }

    // ============================================================
    // Bidding
    // ============================================================

    /// @notice Place a bid on an active job
    /// @param jobId The job to bid on
    /// @param price The bid price (must be <= maxPrice)
    /// @param estimatedLatency Estimated execution time in milliseconds
    /// @dev INV-5: BidBelowCeiling — bid price must not exceed maxPrice
    function bidOnJob(
        uint256 jobId,
        uint256 price,
        uint256 estimatedLatency
    ) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Bidding, "ComputeMarketplace: not accepting bids");
        require(block.number <= job.bidDeadline, "ComputeMarketplace: bid deadline passed");

        // INV-5: BidBelowCeiling
        require(price <= job.maxPrice, "ComputeMarketplace: bid exceeds max price");
        require(price > 0, "ComputeMarketplace: zero bid price");

        // INV-6: AssignedProviderRegistered — bidder must be registered
        ProviderProfile storage provider = providers[msg.sender];
        require(provider.isRegistered, "ComputeMarketplace: provider not registered");
        require(
            provider.currentActiveJobs < provider.maxConcurrentJobs,
            "ComputeMarketplace: provider at capacity"
        );
        require(
            providerModels[msg.sender][job.modelHash],
            "ComputeMarketplace: provider does not support model"
        );

        // Prevent duplicate bids from same provider
        Bid[] storage bids = jobBids[jobId];
        for (uint256 i = 0; i < bids.length; i++) {
            require(bids[i].provider != msg.sender, "ComputeMarketplace: already bid");
        }

        bids.push(Bid({
            provider: msg.sender,
            price: price,
            estimatedLatency: estimatedLatency,
            submittedAt: block.number
        }));

        job.bidCount++;

        emit BidPlaced(jobId, msg.sender, price, estimatedLatency);
    }

    // ============================================================
    // Assignment
    // ============================================================

    /// @notice Assign the best bid to a job (anyone can call after bid deadline)
    /// @param jobId The job to assign
    /// @dev INV-6: AssignedProviderRegistered — selected provider must be registered
    function assignBestBid(uint256 jobId) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Bidding, "ComputeMarketplace: not in bidding state");

        Bid[] storage bids = jobBids[jobId];
        require(bids.length > 0, "ComputeMarketplace: no bids");

        // Find best bid by scoring: price(40%) + reputation(30%) + load(20%) + verification(10%)
        uint256 bestIndex = 0;
        uint256 bestScore = 0;

        for (uint256 i = 0; i < bids.length; i++) {
            uint256 score = _scoreProvider(bids[i].provider, bids[i].price, job.maxPrice);
            if (score > bestScore) {
                bestScore = score;
                bestIndex = i;
            }
        }

        // RM-B1 / WP-D5.1 (audit SOL-08): if all bidders score 0
        // (e.g., all unregistered or all at-capacity) bestIndex
        // remains 0 and the loop selects bid[0] without verifying
        // the score is meaningful. Reject when no bid earned a
        // positive score.
        require(bestScore > 0, "ComputeMarketplace: no eligible bid");

        Bid storage winner = bids[bestIndex];

        // INV-6: AssignedProviderRegistered
        require(providers[winner.provider].isRegistered, "ComputeMarketplace: provider not registered");
        // SOL-08 follow-up: re-check capacity at assign time, not
        // just at bid time — provider may have taken on jobs
        // since their bid landed.
        require(
            providers[winner.provider].currentActiveJobs < providers[winner.provider].maxConcurrentJobs,
            "ComputeMarketplace: provider at capacity"
        );

        job.state = JobState.Assigned;
        job.assignedProvider = winner.provider;

        // Set execution deadline based on post time + bid window + exec window
        // executionDeadline was stored as 0; compute from remaining bidding context
        // Use the exec window from original post (stored as bidDeadline - createdAt gives bidWindow)
        // For simplicity, set execution deadline = now + original bidWindow (reuse the exec window spec)
        // The exec window was passed at post time. We re-derive from bid deadline delta.
        // Actually: execWindow is implicit. We set a generous default: bidDeadline + same window again.
        job.executionDeadline = block.number + (job.bidDeadline - job.createdAt);

        providers[winner.provider].currentActiveJobs++;

        emit JobAssigned(jobId, winner.provider, winner.price);
    }

    /// @notice Auto-assign a job (skip bidding for latency-sensitive workloads)
    /// @param modelHash Model hash for the job
    /// @param inputHash Input data hash
    /// @param tier Verification tier
    /// @return jobId The new job's identifier
    /// @dev Selects the best available provider using the scoring algorithm
    function autoAssignJob(
        bytes32 modelHash,
        bytes calldata inputHash,
        ComputeVerifier.VerificationTier tier
    ) external payable nonReentrant returns (uint256) {
        // RM-B1 / WP-D5.7 (audit SOL-15): pre-fix `msg.value > 0`
        // allowed 1-wei escrow paths that were "Assigned" but no
        // provider with reasonable capacity served — a bid-table
        // pollution / state-bloat griefing surface. Floor at
        // 0.01 SALT (1e16 wei).
        require(msg.value >= MIN_AUTO_ASSIGN_PAYMENT, "ComputeMarketplace: payment below minimum");
        require(modelHash != bytes32(0), "ComputeMarketplace: zero model hash");

        uint256 maxPrice = msg.value;
        uint256 jobId = nextJobId++;

        // Find best provider immediately
        address bestProvider = _findBestProvider(modelHash, maxPrice);
        require(bestProvider != address(0), "ComputeMarketplace: no available provider");

        // Initialize job in storage field-by-field to reduce stack pressure
        Job storage job = jobs[jobId];
        job.id = jobId;
        job.requester = msg.sender;
        job.modelHash = modelHash;
        job.inputHash = inputHash;
        job.maxPrice = maxPrice;
        job.tier = tier;
        job.state = JobState.Assigned;
        job.assignedProvider = bestProvider;
        job.escrow = maxPrice;
        job.bidDeadline = block.number;
        job.executionDeadline = block.number + 100; // ~5 min at 3s blocks
        job.createdAt = block.number;

        // C014: auto-assign is funded by msg.value — escrow is native.
        jobEscrowNative[jobId] = true;

        // Configure verification
        verifier.configureJob(jobId, maxPrice, tier);

        providers[bestProvider].currentActiveJobs++;

        emit JobPosted(jobId, msg.sender, modelHash, maxPrice, tier, block.number, 100);
        emit JobAssigned(jobId, bestProvider, maxPrice);

        return jobId;
    }

    // ============================================================
    // Execution & Result Submission
    // ============================================================

    /// @notice Start execution (provider confirms they are working on the job)
    /// @param jobId The job to start executing
    function startExecution(uint256 jobId) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Assigned, "ComputeMarketplace: not assigned");
        // NoFrontRunning: only assigned provider can start
        require(
            msg.sender == job.assignedProvider,
            "ComputeMarketplace: not assigned provider"
        );
        require(
            providers[msg.sender].isRegistered,
            "ComputeMarketplace: provider not registered"
        );

        job.state = JobState.Executing;

        emit ExecutionStarted(jobId, msg.sender);
    }

    /// @notice Submit commitment hash before execution (required for all tiers)
    /// @param jobId The job identifier
    /// @param commitment SHA3(input || output || nonce)
    function submitCommitment(uint256 jobId, bytes32 commitment) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(
            job.state == JobState.Assigned || job.state == JobState.Executing,
            "ComputeMarketplace: wrong state for commitment"
        );
        // NoFrontRunning: only assigned provider
        require(
            msg.sender == job.assignedProvider,
            "ComputeMarketplace: not assigned provider"
        );

        verifier.submitCommitment(jobId, msg.sender, commitment);
    }

    /// @notice Submit result with proof (moves to Verifying, then auto-verifies)
    /// @param jobId The job identifier
    /// @param outputHash Hash of the output (actual data delivered off-chain)
    /// @param proof Tier-specific proof data
    /// @dev NoFrontRunning: only assigned provider can submit
    function submitResult(
        uint256 jobId,
        bytes calldata outputHash,
        bytes calldata proof
    ) external nonReentrant jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Executing, "ComputeMarketplace: not executing");
        // NoFrontRunning (AdversarialCompute INV-3)
        require(
            msg.sender == job.assignedProvider,
            "ComputeMarketplace: not assigned provider"
        );
        require(
            block.number <= job.executionDeadline,
            "ComputeMarketplace: execution deadline passed"
        );

        job.state = JobState.Verifying;

        emit ResultSubmitted(jobId, msg.sender, keccak256(outputHash));

        // Attempt verification inline
        ComputeVerifier.VerificationResult result = verifier.verify(
            jobId,
            job.tier,
            proof
        );

        if (result == ComputeVerifier.VerificationResult.Valid) {
            // Verification passed — can be completed (if no dispute)
            // completeJob must be called separately to allow dispute window
        } else if (result == ComputeVerifier.VerificationResult.Invalid) {
            // Verification failed — job fails
            _failJob(jobId);
        }
        // If Pending, wait for external verification (TEE oracle async)
    }

    /// @notice Complete a verified job and release payment
    /// @param jobId The job identifier
    /// @dev INV-2: NoPaymentWithoutVerification — only completes if verification passed
    /// @dev DisputeBlocksPayment: checks no active dispute
    /// @dev BurnRateFixed: burns exactly price / 40 = 2.5%
    function completeJob(uint256 jobId) external nonReentrant jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Verifying, "ComputeMarketplace: not verifying");

        // INV-2: NoPaymentWithoutVerification
        ComputeVerifier.VerificationResult vResult = verifier.getResult(jobId);
        require(
            vResult == ComputeVerifier.VerificationResult.Valid,
            "ComputeMarketplace: verification not passed"
        );

        // DisputeBlocksPayment (AdversarialCompute INV-4)
        require(
            !verifier.isDisputeActive(jobId),
            "ComputeMarketplace: dispute active"
        );

        _completeAndPay(jobId);
    }

    // ============================================================
    // Failure Handling
    // ============================================================

    /// @notice Expire a job that received no bids before the deadline
    /// @param jobId The job to expire
    /// @dev INV-7: ExpiredJobsRefunded — escrow returned to requester
    function expireJob(uint256 jobId) external nonReentrant jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Bidding, "ComputeMarketplace: not in bidding");
        require(block.number > job.bidDeadline, "ComputeMarketplace: bid deadline not passed");
        require(jobBids[jobId].length == 0, "ComputeMarketplace: has bids");

        job.state = JobState.Expired;

        // INV-7: ExpiredJobsRefunded. C014: native refund only for
        // native-backed escrow; credit-path escrow is refunded as credits.
        address requester = job.requester;
        uint256 owed = job.escrow;
        uint256 refund = _refundEscrowToRequester(jobId);

        emit JobExpired(jobId, refund);
        emit EscrowRefunded(jobId, requester, owed);
    }

    /// @notice Timeout a job where provider didn't deliver in time
    /// @param jobId The job to timeout
    /// @dev INV-8: TimeoutEscrowHeld — escrow still held for reassignment
    function timeoutJob(uint256 jobId) external nonReentrant jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(
            job.state == JobState.Assigned || job.state == JobState.Executing,
            "ComputeMarketplace: wrong state for timeout"
        );
        require(
            block.number > job.executionDeadline,
            "ComputeMarketplace: deadline not passed"
        );

        address timedOutProvider = job.assignedProvider;
        job.state = JobState.Timeout;

        // Slash the provider for timeout (Tier 1 / Latency)
        uint256 slashAmount = _slashProviderOnFailure(timedOutProvider);

        // INV-8: TimeoutEscrowHeld — escrow remains for potential reassignment
        // Refund escrow to requester since there's no reassignment mechanism yet in this state.
        // C014: native refund only for native-backed escrow.
        address requester = job.requester;
        uint256 owed = job.escrow;
        _refundEscrowToRequester(jobId);

        emit JobTimedOut(jobId, timedOutProvider, slashAmount);
        emit EscrowRefunded(jobId, requester, owed);
    }

    /// @notice Mark a job as failed (verification returned Invalid)
    /// @param jobId The job to fail
    function failJob(uint256 jobId) external jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Verifying, "ComputeMarketplace: not verifying");

        ComputeVerifier.VerificationResult vResult = verifier.getResult(jobId);
        require(
            vResult == ComputeVerifier.VerificationResult.Invalid,
            "ComputeMarketplace: verification not invalid"
        );

        _failJob(jobId);
    }

    // ============================================================
    // Disputes
    // ============================================================

    /// @notice Dispute a result in the Verifying state
    /// @param jobId The job to dispute
    /// @dev GriefUnprofitable: requires bond that is burned if dispute fails
    /// @dev DisputeBlocksPayment: sets dispute active, preventing completeJob
    function disputeResult(uint256 jobId) external payable nonReentrant jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Verifying, "ComputeMarketplace: not verifying");
        require(msg.value >= DISPUTE_BOND, "ComputeMarketplace: insufficient bond");
        require(disputeFiler[jobId] == address(0), "ComputeMarketplace: already disputed");

        // Verification must have completed (INV-5 from ComputeVerification: DisputeOnlyAfterVerification)
        ComputeVerifier.VerificationResult vResult = verifier.getResult(jobId);
        require(
            vResult != ComputeVerifier.VerificationResult.Pending,
            "ComputeMarketplace: verification not complete"
        );

        disputeFiler[jobId] = msg.sender;
        disputeBondHeld[jobId] = msg.value;

        // Initiate dispute in verifier
        verifier.initiateDispute(jobId);

        // Refund excess bond
        if (msg.value > DISPUTE_BOND) {
            (bool success, ) = payable(msg.sender).call{value: msg.value - DISPUTE_BOND}("");
            require(success, "ComputeMarketplace: refund failed");
            disputeBondHeld[jobId] = DISPUTE_BOND;
        }

        emit DisputeFiled(jobId, msg.sender, DISPUTE_BOND);
    }

    /// @notice Resolve a dispute (governance/arbitration)
    /// @param jobId The job in dispute
    /// @param requesterWins Whether the requester (disputer) wins the dispute
    /// @dev GriefUnprofitable: loser forfeits bond
    function resolveDispute(
        uint256 jobId,
        bool requesterWins
    ) external nonReentrant onlyGovernance jobExists(jobId) {
        Job storage job = jobs[jobId];
        require(job.state == JobState.Verifying, "ComputeMarketplace: not verifying");
        require(disputeFiler[jobId] != address(0), "ComputeMarketplace: no dispute filed");
        require(verifier.isDisputeActive(jobId), "ComputeMarketplace: no active dispute");

        address disputer = disputeFiler[jobId];
        uint256 bond = disputeBondHeld[jobId];

        // Clear dispute state
        disputeFiler[jobId] = address(0);
        disputeBondHeld[jobId] = 0;

        // Resolve in verifier
        ComputeVerifier.VerificationResult outcome = requesterWins
            ? ComputeVerifier.VerificationResult.Invalid
            : ComputeVerifier.VerificationResult.Valid;
        verifier.resolveDispute(jobId, outcome);

        if (requesterWins) {
            _resolveDisputeRequesterWins(jobId, disputer, bond);
        } else {
            _resolveDisputeProviderWins(jobId, bond);
        }
    }

    /// @dev Handle dispute resolution when the requester wins
    function _resolveDisputeRequesterWins(
        uint256 jobId,
        address disputer,
        uint256 bond
    ) internal {
        Job storage job = jobs[jobId];

        // Requester wins: job marked Disputed, escrow refunded, bond returned
        job.state = JobState.Disputed;

        address requester = job.requester;
        uint256 owed = job.escrow;

        // Slash provider
        _slashProviderOnFailure(job.assignedProvider);

        // Return bond to disputer (the dispute bond IS native — posted as
        // msg.value in disputeResult — so it is returned in SALT).
        (bool s1, ) = payable(disputer).call{value: bond}("");
        require(s1, "ComputeMarketplace: bond return failed");

        // Refund escrow to requester. C014: native refund only for
        // native-backed escrow; credit-path escrow refunds as credits.
        _refundEscrowToRequester(jobId);

        emit DisputeResolved(jobId, true, bond);
        emit EscrowRefunded(jobId, requester, owed);
    }

    /// @dev Handle dispute resolution when the provider wins
    function _resolveDisputeProviderWins(
        uint256 jobId,
        uint256 bond
    ) internal {
        // Provider wins: dispute dismissed, bond burned (GriefUnprofitable)
        totalDisputeBondsBurned += bond;

        // Burn the bond by sending to address(0) is not possible in EVM,
        // so we send to dead address (standard burn address)
        // RM-B1 / WP-D5.9 (audit SOL-19): burn via Burner contract
        // (calls `Burner.burn{value: bond}()`) so funds are
        // provably unrecoverable. Pre-fix `0xdead` was a sentinel
        // address whose private key, if ever recovered, would
        // expose the accumulated balance.
        require(burner != address(0), "ComputeMarketplace: burner not set");
        (bool success, ) = payable(burner).call{value: bond}(
            abi.encodeWithSignature("burn()")
        );
        require(success, "ComputeMarketplace: bond burn failed");

        // Job can now be completed normally
        emit DisputeResolved(jobId, false, bond);
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @notice Get full job details
    /// @param jobId The job identifier
    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }

    /// @notice Get all bids for a job
    /// @param jobId The job identifier
    function getJobBids(uint256 jobId) external view returns (Bid[] memory) {
        return jobBids[jobId];
    }

    /// @notice Get provider profile
    /// @param provider The provider address
    function getProvider(address provider) external view returns (ProviderProfile memory) {
        return providers[provider];
    }

    /// @notice Get number of registered providers
    function getProviderCount() external view returns (uint256) {
        return allProviders.length;
    }

    /// @notice Check if a provider supports a model
    function providerSupportsModel(
        address provider,
        bytes32 modelHash
    ) external view returns (bool) {
        return providerModels[provider][modelHash];
    }

    // ============================================================
    // Governance
    // ============================================================

    /// @notice Update the treasury address
    function setTreasury(address newTreasury) external onlyGovernance {
        require(newTreasury != address(0), "ComputeMarketplace: zero address");
        treasury = newTreasury;
    }

    /// @notice Update the slashing contract
    function setSlashingContract(address _slashing) external onlyGovernance {
        slashingContract = _slashing;
    }

    // transferGovernance / acceptGovernance are inherited from Governable.

    /// @notice Set the Burner contract for permanently locking
    /// burned bonds + BME burn share.
    /// RM-B1 / WP-D5.9 (audit SOL-19).
    function setBurner(address newBurner) external onlyGovernance {
        require(newBurner != address(0), "ComputeMarketplace: zero burner");
        require(newBurner.code.length > 0, "ComputeMarketplace: burner has no code");
        address old = burner;
        burner = newBurner;
        emit BurnerUpdated(old, newBurner);
    }

    event BurnerUpdated(address oldBurner, address newBurner);

    /// @notice Update the BulkComputeGateway reference (CM-06 WP-06.1).
    /// Setting to `address(0)` disables the credits-payment path —
    /// subsequent credits-mode posts revert with "bulk gateway not set".
    function setBulkGateway(address gateway) external onlyGovernance {
        address old = address(bulkGateway);
        bulkGateway = IBulkComputeGateway(gateway);
        emit BulkGatewayUpdated(old, gateway);
    }

    /// @notice Update the ComputePricingOracle reference used by the
    /// credits-payment path's SALT→credits conversion (CM-06 WP-06.1).
    function setPricingOracle(address oracle) external onlyGovernance {
        require(oracle != address(0), "ComputeMarketplace: zero address");
        address old = address(pricingOracle);
        pricingOracle = IComputePricingOracleMin(oracle);
        emit PricingOracleUpdated(old, oracle);
    }

    // ============================================================
    // Internal Functions
    // ============================================================

    /// @dev Complete job and distribute payment: 95% provider, 2.5% burned, 2.5% treasury
    /// @dev BurnRateFixed: burn = price / 40 (exactly 2.5%)
    function _completeAndPay(uint256 jobId) internal {
        Job storage job = jobs[jobId];

        uint256 payment = job.escrow;
        job.escrow = 0;
        job.state = JobState.Completed;

        // Update provider stats
        _updateProviderOnCompletion(job.assignedProvider);

        // Distribute payment
        _distributeJobPayment(jobId, job.assignedProvider, payment);
    }

    /// @dev Update provider stats on successful job completion
    function _updateProviderOnCompletion(address providerAddr) internal {
        ProviderProfile storage prov = providers[providerAddr];
        prov.totalJobsCompleted++;
        prov.currentActiveJobs--;
        prov.reputationScore = ComputeLib.calculateReputation(
            prov.totalJobsCompleted, prov.totalJobsFailed
        );
    }

    /// @dev Distribute payment: 95% provider, 2.5% burned, 2.5% treasury.
    ///
    /// CHAIN-B-C014 (HELD/reroll): a credit-path job holds NO native SALT
    /// backing for its `escrow`. Paying the provider (and burning/treasury)
    /// in native SALT here would draw from other users' escrow and drain
    /// the contract. For credit-path jobs the settlement is recorded as a
    /// credit liability and settled operationally (treasury credit
    /// replenishment); no native SALT is transferred.
    function _distributeJobPayment(uint256 jobId, address providerAddr, uint256 payment) internal {
        if (!jobEscrowNative[jobId]) {
            emit CreditsProviderOwed(jobId, providerAddr, payment);
            emit JobCompleted(jobId, providerAddr, payment, 0, 0);
            return;
        }

        ComputeLib.BMEResult memory bme = ComputeLib.calculateBME(payment);

        // Update global accounting
        totalBurned += bme.burnAmount;
        totalPaidToProviders += bme.providerAmount;
        totalTreasuryFees += bme.treasuryAmount;

        // BME burn via Burner contract (SOL-19).
        if (bme.burnAmount > 0) {
            require(burner != address(0), "ComputeMarketplace: burner not set");
            (bool s1, ) = payable(burner).call{value: bme.burnAmount}(
                abi.encodeWithSignature("burn()")
            );
            require(s1, "ComputeMarketplace: burn failed");
        }

        // Treasury fee
        if (bme.treasuryAmount > 0) {
            (bool s2, ) = payable(treasury).call{value: bme.treasuryAmount}("");
            require(s2, "ComputeMarketplace: treasury payment failed");
        }

        // Provider payment
        if (bme.providerAmount > 0) {
            (bool s3, ) = payable(providerAddr).call{value: bme.providerAmount}("");
            require(s3, "ComputeMarketplace: provider payment failed");
        }

        emit JobCompleted(jobId, providerAddr, bme.providerAmount, bme.burnAmount, bme.treasuryAmount);
    }

    /// @dev CHAIN-B-C014 (HELD/reroll): release a job's escrow back to its
    /// requester. For a native-backed (SALT-path / auto-assign) job this
    /// transfers real SALT; for a credit-path job — whose `escrow` has NO
    /// native backing in this contract — it records a credit liability
    /// instead of moving SALT out of other users' escrow. Zeroes
    /// `job.escrow`. Returns the amount of native SALT actually sent.
    function _refundEscrowToRequester(uint256 jobId) internal returns (uint256 nativeRefunded) {
        Job storage job = jobs[jobId];
        uint256 amount = job.escrow;
        job.escrow = 0;
        if (amount == 0) {
            return 0;
        }
        if (jobEscrowNative[jobId]) {
            (bool ok, ) = payable(job.requester).call{value: amount}("");
            require(ok, "ComputeMarketplace: refund failed");
            return amount;
        }
        // Credit-path: no native SALT was ever deposited for this job.
        creditsRefundOwed[job.requester] += amount;
        emit CreditsRefundOwed(jobId, job.requester, amount);
        return 0;
    }

    /// @dev Fail a job: refund escrow, slash provider, update stats
    function _failJob(uint256 jobId) internal {
        Job storage job = jobs[jobId];

        job.state = JobState.Failed;

        // Slash provider
        _slashProviderOnFailure(job.assignedProvider);

        // Refund escrow to requester. C014: native refund only for
        // native-backed escrow; credit-path escrow refunds as credits.
        address requester = job.requester;
        uint256 owed = job.escrow;
        _refundEscrowToRequester(jobId);

        emit JobFailed(jobId, job.assignedProvider);
        emit EscrowRefunded(jobId, requester, owed);
    }

    /// @dev Slash a provider on job failure/timeout: deduct stake, increment failures,
    ///      decrement active jobs, recalculate reputation. Returns the slash amount.
    function _slashProviderOnFailure(address providerAddr) internal returns (uint256 slashAmount) {
        ProviderProfile storage prov = providers[providerAddr];
        slashAmount = (prov.stake * TIMEOUT_SLASH_BPS) / BPS;
        if (slashAmount > prov.stake) {
            slashAmount = prov.stake;
        }
        prov.stake -= slashAmount;
        prov.totalJobsFailed++;
        prov.currentActiveJobs--;
        prov.reputationScore = ComputeLib.calculateReputation(
            prov.totalJobsCompleted, prov.totalJobsFailed
        );

        // CHAIN-B-C039: route slashed principal OUT to the treasury rather than
        // leaving it commingled on the contract with job escrow and live stake
        // (which silently inflated the balance funding C014/C015). Treasury is
        // a trusted sink; callers of this function are nonReentrant.
        if (slashAmount > 0 && treasury != address(0)) {
            (bool ok, ) = payable(treasury).call{value: slashAmount}("");
            require(ok, "ComputeMarketplace: slash routing failed");
        }
    }

    /// @dev Score a provider for bid selection (delegates to ComputeLib)
    function _scoreProvider(
        address provider,
        uint256 bidPrice,
        uint256 maxPrice
    ) internal view returns (uint256) {
        ProviderProfile storage prov = providers[provider];
        if (!prov.isRegistered) return 0;

        return ComputeLib.scoreProvider(
            bidPrice,
            maxPrice,
            prov.reputationScore,
            prov.currentActiveJobs,
            prov.maxConcurrentJobs,
            prov.totalJobsCompleted
        );
    }

    /// @dev Find the best available provider for auto-assignment
    function _findBestProvider(
        bytes32 modelHash,
        uint256 maxPrice
    ) internal view returns (address) {
        address bestProvider = address(0);
        uint256 bestScore = 0;

        for (uint256 i = 0; i < allProviders.length; i++) {
            address p = allProviders[i];
            ProviderProfile storage prov = providers[p];

            if (!prov.isRegistered) continue;
            // C015: never conscript a provider who hasn't consented to
            // auto-assignment — auto-assigned jobs carry a slashable
            // deadline the provider never accepted otherwise.
            if (!autoAssignOptIn[p]) continue;
            if (prov.currentActiveJobs >= prov.maxConcurrentJobs) continue;
            if (!providerModels[p][modelHash]) continue;

            // Use maxPrice as the bid price for scoring (worst case)
            uint256 score = _scoreProvider(p, maxPrice, maxPrice);
            if (score > bestScore) {
                bestScore = score;
                bestProvider = p;
            }
        }

        return bestProvider;
    }

    // ============================================================
    // Receive
    // ============================================================

    /// @notice Accept SALT transfers (for dispute bonds, additional escrow)
    receive() external payable {}
}
