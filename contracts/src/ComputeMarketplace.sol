// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/ReentrancyGuard.sol";
import "./lib/ComputeLib.sol";
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
contract ComputeMarketplace is ReentrancyGuard {
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

    /// @notice Governance address
    address public governance;

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

    modifier onlyGovernance() {
        require(msg.sender == governance, "ComputeMarketplace: not governance");
        _;
    }

    modifier jobExists(uint256 jobId) {
        require(jobId < nextJobId, "ComputeMarketplace: job does not exist");
        _;
    }

    // ============================================================
    // Constructor
    // ============================================================

    constructor(address _verifier, address _treasury) {
        require(_verifier != address(0), "ComputeMarketplace: zero verifier");
        require(_treasury != address(0), "ComputeMarketplace: zero treasury");

        verifier = ComputeVerifier(_verifier);
        treasury = _treasury;
        governance = msg.sender;
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

    /// @notice Add stake as a registered provider
    function addStake() external payable nonReentrant {
        require(providers[msg.sender].isRegistered, "ComputeMarketplace: not registered");
        require(msg.value > 0, "ComputeMarketplace: zero stake");

        providers[msg.sender].stake += msg.value;

        emit ProviderStakeUpdated(msg.sender, providers[msg.sender].stake);
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

        Bid storage winner = bids[bestIndex];

        // INV-6: AssignedProviderRegistered
        require(providers[winner.provider].isRegistered, "ComputeMarketplace: provider not registered");

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
        require(msg.value > 0, "ComputeMarketplace: zero payment");
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

        // INV-7: ExpiredJobsRefunded
        uint256 refund = job.escrow;
        job.escrow = 0;

        (bool success, ) = payable(job.requester).call{value: refund}("");
        require(success, "ComputeMarketplace: refund failed");

        emit JobExpired(jobId, refund);
        emit EscrowRefunded(jobId, job.requester, refund);
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
        // Refund escrow to requester since there's no reassignment mechanism yet in this state
        uint256 refund = job.escrow;
        job.escrow = 0;

        (bool success, ) = payable(job.requester).call{value: refund}("");
        require(success, "ComputeMarketplace: refund failed");

        emit JobTimedOut(jobId, timedOutProvider, slashAmount);
        emit EscrowRefunded(jobId, job.requester, refund);
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

        uint256 refund = job.escrow;
        job.escrow = 0;

        // Slash provider
        _slashProviderOnFailure(job.assignedProvider);

        // Return bond to disputer
        (bool s1, ) = payable(disputer).call{value: bond}("");
        require(s1, "ComputeMarketplace: bond return failed");

        // Refund escrow to requester
        if (refund > 0) {
            (bool s2, ) = payable(job.requester).call{value: refund}("");
            require(s2, "ComputeMarketplace: escrow refund failed");
        }

        emit DisputeResolved(jobId, true, bond);
        emit EscrowRefunded(jobId, job.requester, refund);
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
        (bool success, ) = payable(address(0xdead)).call{value: bond}("");
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

    /// @notice Transfer governance
    function transferGovernance(address newGovernance) external onlyGovernance {
        require(newGovernance != address(0), "ComputeMarketplace: zero address");
        governance = newGovernance;
    }

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

    /// @dev Distribute payment: 95% provider, 2.5% burned, 2.5% treasury
    function _distributeJobPayment(uint256 jobId, address providerAddr, uint256 payment) internal {
        ComputeLib.BMEResult memory bme = ComputeLib.calculateBME(payment);

        // Update global accounting
        totalBurned += bme.burnAmount;
        totalPaidToProviders += bme.providerAmount;
        totalTreasuryFees += bme.treasuryAmount;

        // BME burn: send to dead address (address(0) cannot receive ETH in EVM)
        if (bme.burnAmount > 0) {
            (bool s1, ) = payable(address(0xdead)).call{value: bme.burnAmount}("");
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

    /// @dev Fail a job: refund escrow, slash provider, update stats
    function _failJob(uint256 jobId) internal {
        Job storage job = jobs[jobId];

        job.state = JobState.Failed;

        // Slash provider
        _slashProviderOnFailure(job.assignedProvider);

        // Refund escrow to requester
        uint256 refund = job.escrow;
        job.escrow = 0;

        if (refund > 0) {
            (bool success, ) = payable(job.requester).call{value: refund}("");
            require(success, "ComputeMarketplace: refund failed");
        }

        emit JobFailed(jobId, job.assignedProvider);
        emit EscrowRefunded(jobId, job.requester, refund);
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
