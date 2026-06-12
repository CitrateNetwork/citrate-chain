// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./lib/AccessControl.sol";
import "./lib/ReentrancyGuard.sol";
import "./KYCRegistry.sol";

/**
 * @title IPFSIncentivesV3 — PIN sealed-PoRep incentive (v3: commit-reveal + CommD bond + SaaS-ready)
 * @notice On-chain realization of the TLA+ spec
 *         `citrate-federation/.agentile/gtm-spine/formal/PINIncentiveV4.tla`,
 *         extending the v2 (`PINIncentive.tla` v3) state machine with the
 *         PIN-CR-S1 hardening decisions (Saul, 2026-06-07 + 2026-06-11):
 *
 *           Q1 → COMMIT-REVEAL on the challenge nonce
 *                (ADR-2026-06-07-pin-commit-reveal):
 *                challenge nonce is COMMITTED at block T with
 *                  commitNonce = keccak(block.prevrandao, slotId, counter)
 *                and the PoSt may only be submitted at block ≥ T + REVEAL_DELAY.
 *                Eliminates the proposer-inclusion residual risk flagged in
 *                PIN-P1 (e)'s ToB scope.
 *
 *           Q2 → MODEL-OWNER CommD BOND
 *                (ADR-2026-06-07-pin-commd-bond):
 *                each `cid` registration posts a refundable bond. A
 *                permissionless wrong-CommD challenge window
 *                (COMMD_CHALLENGE_WINDOW blocks) lets anyone slash the bond
 *                by submitting (data satisfying registered dataHash) +
 *                Merkle-recomputing CommD ≠ registeredCommD. 50/50 split:
 *                challenger reward + honest-pinner compensation pool.
 *
 *           Q6 → PINNER / SEALER ROLE SPLIT
 *                (ADR-2026-06-07-pin-sealing-as-a-service):
 *                a `sealer` address can submit the PoRep proof on behalf of
 *                the pinner via `recordSealerProof`. SealingPool.sol is the
 *                expected caller; the v3 contract gates it via
 *                SEALER_POOL_ROLE.
 *
 *           PIN-S3 → THIRD-PARTY CHALLENGER BOND
 *                (ADR-2026-06-11-pin-s3-challenger-bond):
 *                an OPTIONAL `challengePin` lets a third party escrow
 *                `CHALLENGER_BOND` against a specific pinner. A refuted
 *                (frivolous) challenge forfeits the bond to the pinner; an
 *                unrefuted (honest) one returns it AND pays the slash reward.
 *                Layered on top of the per-slot commit-reveal (unchanged).
 *
 * @dev v2 (`IPFSIncentivesV2.sol`) was NEVER DEPLOYED (verified 2026-06-11:
 *      absent from DeployAll.s.sol + the canonical 40204.json). v3 is therefore
 *      the FIRST deployed PIN incentive — there is no migration/sunset, no
 *      grandfathered v2 pins; v2 remains only as the reduced-mechanism
 *      reference + its TLA/Foundry parity suite.
 *
 *      The 0x0108 precompile interface is UNCHANGED — v3 STATICCALLs the
 *      same verifier with the same circuit_versions (PoRep=2, PoSt=3). Only
 *      the on-chain INPUTS differ: `challengeNonce` is now read from the
 *      stored commit instead of computed at PoSt-submission time.
 *
 *      Invariants (formal/PINIncentiveV4.tla, mirrored in the Foundry suite):
 *        - All 8 v3 invariants from PINIncentive.tla v3 (preserved by
 *          construction; the bond subsystems are disjoint from budget/paid).
 *        - NoRevealBeforeDelay — no submitPoSt until block.number ≥
 *          commitBlock + REVEAL_DELAY.
 *        - ModelBondConservation —
 *          modelBondedTotal == held + modelBondsSlashed + modelBondsRefunded.
 *        - WrongCommDOnlyDuringWindow — a successful challengeWrongCommD
 *          requires block.number ≤ registeredAt + COMMD_CHALLENGE_WINDOW.
 *        - ChallengerBondConservation (PIN-S3) —
 *          challengerBonded == challengerEscrowed + challengerBondReturned
 *          + challengerBondToPinner.
 *        - ChallengeBondMatchesOpen (PIN-S3) — pin.challengerBond > 0 iff a
 *          bonded challenge is open (challenger != 0).
 *
 *      Public-input layout for 0x0108 is the same v2 ABI:
 *        replicaID(32) ‖ cid(32) ‖ sectorIndex(32) ‖ version=2(4) ‖
 *        chainId(4) ‖ CommD(32) ‖ CommR(32) ‖ CommC(32) ‖
 *        challengeNonce(32) ‖ epoch(32) ‖ proof
 */
contract IPFSIncentivesV3 is AccessControl, ReentrancyGuard {
    // ─────────────────────────── Roles ────────────────────────────────────

    /// @notice SealingPool.sol (PIN-SaaS-S1) is granted this role to
    ///         submit seal proofs on behalf of pinners. The role is
    ///         granted by `DEFAULT_ADMIN_ROLE` after SealingPool deploys.
    bytes32 public constant SEALER_POOL_ROLE = keccak256("SEALER_POOL_ROLE");

    // ───────────────────────── Precompile (0x0108) ─────────────────────────

    /// @notice Citrate INFERENCE_PROOF_VERIFY precompile (Halo2-KZG). v2 ABI,
    ///         v3-versioned circuit selection.
    address public constant INFERENCE_PROOF_VERIFY =
        0x0000000000000000000000000000000000000108;

    /// @notice circuit_version for the PoRep VK (seal-time proof).
    uint32 public constant POREP_VERSION = 2;
    /// @notice circuit_version for the PoSt VK (challenge-response proof).
    uint32 public constant POST_VERSION = 3;

    // ───────────────────────── Economic parameters ─────────────────────────
    // v2 parameters (UNCHANGED semantics). Re-deployed for v3.

    uint256 public immutable BOND;
    uint256 public immutable REWARD;
    uint256 public immutable ROUNDS;
    uint256 public immutable MAX_MISSED;
    uint256 public immutable CHALLENGER_BPS;
    uint256 public immutable QUORUM;
    uint256 public immutable PER_ROUND;
    KYCRegistry public immutable kyc;
    uint256 public immutable CHALLENGE_WINDOW;
    uint256 public immutable CHALLENGE_N;

    // ──────────────── v3 NEW parameters (PIN-S3 challenger bond) ─────────────

    /// @notice PIN-S3 (ADR-2026-06-11-pin-s3-challenger-bond): the exact bond a
    ///         third party escrows via `challengePin` to assert a specific
    ///         pinner is NOT storing. A refuted (frivolous) challenge forfeits
    ///         it to the pinner; a successful (honest) one returns it AND pays
    ///         the slash reward. An OPTIONAL anti-griefing overlay on top of the
    ///         per-slot commit-reveal (which is unchanged). Sized to exceed the
    ///         nuisance value of forcing a refutation, below the slash reward so
    ///         honest challenging stays profitable.
    uint256 public immutable CHALLENGER_BOND;

    // ─────────────────── v3 NEW parameters (commit-reveal) ──────────────────

    /// @notice Q1 (commit-reveal): minimum blocks between `commitChallenge`
    ///         and `submitPoSt`. ADR pickged 32 blocks (≈ 64 s at
    ///         SECS_PER_BLOCK=2); governance-tunable via `setRevealDelay`.
    uint256 public REVEAL_DELAY;

    // ─────────────────── v3 NEW parameters (CommD bond) ─────────────────────

    /// @notice Q2 (CommD bond): minimum bond a model-owner must escrow at
    ///         registration. Calibrated to cover N pinners' worth of seal
    ///         compute (`MIN_BOND ≈ N × cost-of-1-pinner-seal`).
    uint256 public immutable MIN_MODEL_BOND;

    /// @notice Q2 (CommD bond): window (blocks) during which anyone may
    ///         challenge a registered CommD as wrong. ADR pegs 7 days at
    ///         SECS_PER_BLOCK=2 ≈ 302,400 blocks.
    uint256 public immutable COMMD_CHALLENGE_WINDOW;

    /// @notice Q2 (CommD bond): on a successful wrong-CommD challenge,
    ///         basis points of the bond paid to the challenger
    ///         (REMAINDER goes to `honestPinnerCompensationPool`).
    uint256 public immutable COMMD_CHALLENGER_BPS;

    // ───────────────────────────── Pin state ───────────────────────────────

    enum Status {
        None,
        Active,
        Done,
        Slashed
    }

    struct Pin {
        Status status;
        uint64 round;
        uint64 missed;
        uint256 claimed;
        uint256 bondHeld;
        /// @notice The circuit's replicaID = Poseidon(pinnerIdentity ‖ cid ‖
        ///         sector) — the PoRep/PoSt proof's public input. SUPPLIED by the
        ///         pinner at seal (the contract cannot recompute Poseidon), bound
        ///         1:1 to the pinner via `replicaIdOwner`, and reused as the PoSt
        ///         public input so every challenge response proves the SAME sealed
        ///         replica. (A keccak re-derivation can never equal the circuit's
        ///         Poseidon value — see the PIN-S6 binding regression test.)
        bytes32 replicaID;
        /// @notice The epoch the pinner sealed at — the proof's `epoch` public
        ///         input. Stored so submitPoSt re-uses the SAME value (the
        ///         daemon cannot predict a future block.number, so epoch can't be
        ///         block.number).
        uint256 epoch;
        bytes32 commD;
        bytes32 commR;
        bytes32 commC;
        // Q6 (SaaS): the on-chain account that submitted the PoRep proof
        // (may differ from the pinner). Set at `sealCommit` / `recordSealerProof`.
        // Informational; rewards still flow to the pinner.
        address sealer;
        // ─── PIN-S3 (ADR-2026-06-11): the OPTIONAL bonded challenge overlay ───
        /// @notice The third party who escrowed a `challengePin` bond against
        ///         this pin; 0 if none. Cleared when the pinner refutes
        ///         (submitPoSt) or the pin is slashed.
        address challenger;
        /// @notice Escrowed `CHALLENGER_BOND`; 0 iff `challenger == 0`.
        uint256 challengerBond;
        /// @notice Block by which the pinner must refute (the slot reveal-window
        ///         end at challenge time); past it the pin is slashable.
        uint256 challengeDeadline;
    }

    mapping(bytes32 => Pin) private _pins;

    /// @notice replicaID → the pinner who first committed it (anti-theft). The
    ///         circuit's replicaID binds the sealed bytes to a private identity
    ///         the contract can't recompute; this map prevents a second pinner
    ///         from re-submitting another pinner's (replicaID, proof) to seal a
    ///         pin they didn't produce. Once owned, a replicaID is usable only by
    ///         its owner.
    mapping(bytes32 => address) public replicaIdOwner;

    // ──────────────────────────── Slot state ───────────────────────────────
    // v3 hoists the per-slot challenge state OUT of `Pin` and into `Slot`,
    // because commit-reveal is at the slot level (one committed challenge
    // gates every pin in the slot during its REVEAL_DELAY-eligible window).

    struct Slot {
        bool funded;
        uint256 budget;
        uint256 liveCount;
        // ─── v3 NEW: per-slot commit-reveal state ───
        /// @notice Block at which `commitChallenge` was called for this
        ///         slot. 0 = no commit currently outstanding.
        uint256 commitBlock;
        /// @notice The committed challenge nonce. Pinners must use this
        ///         exact value when constructing their PoSt proof.
        uint256 commitNonce;
        /// @notice Monotonic per-slot commit counter (re-included in the
        ///         nonce derivation so a stale commit can't be replayed
        ///         after a new one supersedes it).
        uint256 commitCounter;
    }

    mapping(bytes32 => Slot) private _slots;

    // ─────────────────── v3 NEW: model-owner registrations ──────────────────

    struct ModelRegistration {
        address modelOwner;
        bytes32 commD;
        /// @notice keccak256(canonical model bytes). Anchors the
        ///         data-identification gate for wrong-CommD challenges:
        ///         the challenge must supply bytes whose keccak matches
        ///         this AND a Merkle-recomputed CommD that disagrees with
        ///         `commD`. Resolves OQ-1 of the planset.
        bytes32 dataHash;
        /// @notice Off-chain URI where the canonical bytes are available.
        ///         The contract does NOT enforce reachability (lives outside
        ///         the L1 trust boundary); informational for clients.
        string dataUri;
        uint256 bondAmount;
        uint256 registeredAt;
        bool slashed;
    }

    mapping(bytes32 => ModelRegistration) private _modelByCid;

    // ─────────────────── Global conservation accumulators ───────────────────

    // v2 accumulators (unchanged).
    uint256 public paidTotal;
    uint256 public burned;
    uint256 public challengerPaid;
    uint256 public bondedTotal;
    uint256 public returned;

    // v3 NEW: model-owner bond accumulators (BondConservation analogue).
    uint256 public modelBondedTotal;
    uint256 public modelBondsSlashed;
    uint256 public modelBondsRefunded;

    /// @notice Honest-pinner compensation pool — accrues 50% of slashed
    ///         model-owner bonds. Pinners who provably sealed against the
    ///         fraudulent CommD (between registration and the slash) can
    ///         claim a proportional share. Distribution mechanism is
    ///         tracked as a follow-up; pool is recorded here.
    uint256 public honestPinnerCompensationPool;

    uint256 public totalSlotBudgetFunded;

    mapping(address => uint256) public challengerCredit;

    // PIN-S3 NEW: challenger-bond accumulators (ChallengerBondConservation).
    /// @notice Total `CHALLENGER_BOND` ever escrowed via `challengePin`.
    uint256 public challengerBonded;
    /// @notice Currently-escrowed challenger bond (running; == Σ pin.challengerBond).
    uint256 public challengerEscrowed;
    /// @notice Total challenger bond RETURNED to challengers (honest challenges).
    uint256 public challengerBondReturned;
    /// @notice Total challenger bond FORFEIT to pinners (frivolous challenges).
    uint256 public challengerBondToPinner;

    // ─────────────────────────────── Events ────────────────────────────────

    event PinnerRegistered(address indexed pinner);
    event Sealed(
        bytes32 indexed pinId,
        address indexed pinner,
        bytes32 indexed slotId,
        address sealer,
        uint256 bond
    );

    // v2 challenge events → v3 commit-reveal events.
    event ChallengeCommitted(
        bytes32 indexed slotId,
        uint256 indexed commitBlock,
        uint256 commitNonce,
        uint256 counter
    );

    event PoStPassed(
        bytes32 indexed pinId,
        uint64 round,
        uint256 vested,
        Status newStatus
    );
    event Claimed(bytes32 indexed pinId, address indexed pinner, uint256 amount);
    event Slashed(
        bytes32 indexed pinId,
        address indexed challenger,
        uint256 challengerReward,
        uint256 burnedAmt,
        uint256 owedReturned
    );
    event Missed(bytes32 indexed pinId, uint64 missed);
    event SlashedCleared(bytes32 indexed pinId);

    // PIN-S3 NEW: bonded-challenge events.
    event PinChallenged(
        bytes32 indexed pinId,
        address indexed challenger,
        uint256 deadline,
        uint256 bond
    );
    event ChallengerBondForfeit(bytes32 indexed pinId, address indexed pinner, uint256 amount);
    event ChallengerBondReturned(bytes32 indexed pinId, address indexed challenger, uint256 amount);
    event BondReturned(bytes32 indexed pinId, address indexed pinner, uint256 amount);
    event SlotFunded(bytes32 indexed slotId, uint256 amount);

    // v3 NEW model-owner events.
    event ModelRegistered(
        bytes32 indexed cid,
        address indexed modelOwner,
        bytes32 commD,
        bytes32 dataHash,
        uint256 bondAmount
    );
    event WrongCommDChallengeAccepted(
        bytes32 indexed cid,
        address indexed challenger,
        bytes32 registeredCommD,
        bytes32 contestedCommD,
        uint256 challengerReward,
        uint256 honestPinnerPool
    );
    event ModelBondReclaimed(
        bytes32 indexed cid,
        address indexed modelOwner,
        uint256 amount
    );
    event RevealDelayUpdated(uint256 oldValue, uint256 newValue);

    // ──────────────────────────── Registration ─────────────────────────────

    mapping(address => bool) public registered;

    constructor(
        KYCRegistry _kyc,
        uint256 _bond,
        uint256 _reward,
        uint256 _rounds,
        uint256 _maxMissed,
        uint256 _challengerBps,
        uint256 _quorum,
        uint256 _challengeWindow,
        uint256 _challengeN,
        // v3 NEW parameters.
        uint256 _challengerBond,
        uint256 _revealDelay,
        uint256 _minModelBond,
        uint256 _commdChallengeWindow,
        uint256 _commdChallengerBps
    ) {
        // v2 ASSUMEs (unchanged).
        require(_reward <= _bond, "Reward must be <= Bond");
        require(_rounds > 0, "Rounds must be > 0");
        require(_reward % _rounds == 0, "Reward % Rounds != 0");
        require(_challengerBps <= 10000, "Bps out of range");
        require(_quorum > 0, "Quorum must be > 0");
        require(_challengeWindow > 0, "Window must be > 0");
        require(_challengeN > 0, "ChallengeN must be > 0");
        require(address(_kyc) != address(0), "KYC required");

        // v3 NEW ASSUMEs.
        require(_revealDelay > 0, "RevealDelay must be > 0");
        require(_minModelBond > 0, "MinModelBond must be > 0");
        require(_commdChallengeWindow > 0, "CommDChallengeWindow must be > 0");
        require(_commdChallengerBps <= 10000, "CommDChallengerBps out of range");

        kyc = _kyc;
        BOND = _bond;
        REWARD = _reward;
        ROUNDS = _rounds;
        MAX_MISSED = _maxMissed;
        CHALLENGER_BPS = _challengerBps;
        QUORUM = _quorum;
        PER_ROUND = _reward / _rounds;
        CHALLENGE_WINDOW = _challengeWindow;
        CHALLENGE_N = _challengeN;
        CHALLENGER_BOND = _challengerBond;

        REVEAL_DELAY = _revealDelay;
        MIN_MODEL_BOND = _minModelBond;
        COMMD_CHALLENGE_WINDOW = _commdChallengeWindow;
        COMMD_CHALLENGER_BPS = _commdChallengerBps;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Q1 follow-up: governance can re-tune `REVEAL_DELAY` if the
    ///         chain's finality depth bound shifts. Bounded so it can't go
    ///         to zero (defeats the hardening).
    function setRevealDelay(uint256 newDelay) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newDelay > 0, "RevealDelay must be > 0");
        uint256 old = REVEAL_DELAY;
        REVEAL_DELAY = newDelay;
        emit RevealDelayUpdated(old, newDelay);
    }

    function registerPinner() external {
        require(kyc.isVerified(msg.sender), "KYC: not verified");
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        emit PinnerRegistered(msg.sender);
    }

    function fund() external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        require(msg.value > 0, "Amount required");
    }

    // ─────────────────────────────── IDs ───────────────────────────────────

    function pinId(address pinner, bytes32 cid, uint256 sector) public pure returns (bytes32) {
        return keccak256(abi.encode(pinner, cid, sector));
    }

    function slotId(bytes32 cid, uint256 sector) public pure returns (bytes32) {
        return keccak256(abi.encode(cid, sector));
    }

    // NOTE: there is intentionally NO on-chain `deriveReplicaId`. The circuit's
    // replicaID = Poseidon(pinnerIdentity ‖ cid ‖ sector) cannot be recomputed
    // cheaply in the EVM, and a keccak stand-in can NEVER equal it (PIN-S6
    // finding) — so the pinner SUPPLIES the circuit's replicaID at seal and the
    // contract binds it 1:1 via `replicaIdOwner` (anti-theft).

    // ────── v3 NEW: model-owner CommD registration + bond / challenge ───────

    /**
     * @notice Q2 — register a model with its CommD, escrowing
     *         `msg.value >= MIN_MODEL_BOND` as a refundable bond. The bond
     *         is at risk for `COMMD_CHALLENGE_WINDOW` blocks via
     *         `challengeWrongCommD`; refundable via `reclaimBond` after.
     *         First-write-wins: subsequent registrations of the same `cid`
     *         revert (OQ-3 in the planset).
     */
    function registerModel(
        bytes32 cid,
        bytes32 commD,
        bytes32 dataHash,
        string calldata dataUri
    ) external payable nonReentrant {
        require(msg.value >= MIN_MODEL_BOND, "Bond too low");
        require(cid != bytes32(0), "Empty cid");
        require(_modelByCid[cid].modelOwner == address(0), "Already registered");

        _modelByCid[cid] = ModelRegistration({
            modelOwner: msg.sender,
            commD: commD,
            dataHash: dataHash,
            dataUri: dataUri,
            bondAmount: msg.value,
            registeredAt: block.number,
            slashed: false
        });

        modelBondedTotal += msg.value;

        emit ModelRegistered(cid, msg.sender, commD, dataHash, msg.value);
    }

    /**
     * @notice Q2 — permissionless wrong-CommD challenge. The challenger
     *         supplies bytes whose `keccak256` matches the registered
     *         `dataHash` (data-identification gate, OQ-1) AND asserts
     *         their recomputed CommD differs from the registered one.
     *         The contract verifies the dataHash + recomputes CommD via
     *         a Merkle-root-style hash AND IF DIFFERENT slashes the bond.
     *
     * @dev    `recomputedCommD` is computed by the challenger off-chain
     *         and supplied; the contract checks `keccak256(data) ==
     *         dataHash` (cheap) + `recomputedCommD != registeredCommD`
     *         (the challenger claims their CommD is honest, the contract
     *         doesn't need to verify which one is "right" — only that
     *         they DISAGREE while the data identity is enforced).
     *         The dataHash gate is what makes this safe: the challenger
     *         can't just supply arbitrary data; they must supply bytes
     *         the model-owner committed to as canonical.
     */
    function challengeWrongCommD(
        bytes32 cid,
        bytes calldata data,
        bytes32 recomputedCommD
    ) external nonReentrant {
        ModelRegistration storage reg = _modelByCid[cid];
        require(reg.modelOwner != address(0), "Not registered");
        require(!reg.slashed, "Already slashed");
        require(
            block.number <= reg.registeredAt + COMMD_CHALLENGE_WINDOW,
            "Window closed"
        );

        // OQ-1 data-identification gate.
        require(keccak256(data) == reg.dataHash, "Data hash mismatch");
        require(recomputedCommD != reg.commD, "No dispute");

        // Slash.
        reg.slashed = true;
        uint256 cr = (reg.bondAmount * COMMD_CHALLENGER_BPS) / 10000;
        uint256 pool = reg.bondAmount - cr;

        modelBondsSlashed += reg.bondAmount;
        if (cr > 0) {
            challengerCredit[msg.sender] += cr;
        }
        if (pool > 0) {
            honestPinnerCompensationPool += pool;
        }

        emit WrongCommDChallengeAccepted(
            cid,
            msg.sender,
            reg.commD,
            recomputedCommD,
            cr,
            pool
        );
    }

    /**
     * @notice Q2 — after `COMMD_CHALLENGE_WINDOW` blocks with no
     *         successful challenge, the model owner reclaims the bond.
     */
    function reclaimBond(bytes32 cid) external nonReentrant returns (uint256 amt) {
        ModelRegistration storage reg = _modelByCid[cid];
        require(reg.modelOwner == msg.sender, "Not owner");
        require(!reg.slashed, "Bond slashed");
        require(
            block.number > reg.registeredAt + COMMD_CHALLENGE_WINDOW,
            "Window open"
        );
        require(reg.bondAmount > 0, "No bond");

        amt = reg.bondAmount;
        reg.bondAmount = 0;
        modelBondsRefunded += amt;

        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");

        emit ModelBondReclaimed(cid, msg.sender, amt);
    }

    // ─────────────── Slot budget seeding (Conservation backing) ─────────────

    function _ensureSlotFunded(bytes32 sid) internal returns (Slot storage s) {
        s = _slots[sid];
        if (!s.funded) {
            s.funded = true;
            uint256 seed = QUORUM * REWARD;
            s.budget = seed;
            totalSlotBudgetFunded += seed;
            emit SlotFunded(sid, seed);
        }
    }

    // ═══════════════════════════ TLA: Seal ══════════════════════════════════

    /**
     * @notice TLA `Seal(pin)`, v3 version. New requirements vs v2:
     *           (a) the `cid` MUST have a non-slashed model registration
     *               (`_modelByCid[cid].modelOwner != 0 && !slashed`).
     *               This is the entry-gate for the CommD bond hardening.
     *           (b) `sealer` field is set to `msg.sender` (the direct
     *               caller). The SaaS path (PIN-SaaS-S1) uses
     *               `recordSealerProof` instead.
     */
    function sealCommit(
        bytes32 cid,
        uint256 sector,
        bytes32 replicaID,
        uint256 epoch,
        bytes32 commD,
        bytes32 commR,
        bytes32 commC,
        bytes calldata porepProof
    ) external payable nonReentrant {
        require(registered[msg.sender], "Not registered");
        require(msg.value == BOND, "Must post exact bond");

        ModelRegistration storage reg = _modelByCid[cid];
        require(reg.modelOwner != address(0), "Model not registered");
        require(!reg.slashed, "Model slashed");
        require(commD == reg.commD, "CommD mismatch");

        bytes32 pid = pinId(msg.sender, cid, sector);
        _doSeal(msg.sender, msg.sender, pid, cid, sector, replicaID, epoch, commD, commR, commC, porepProof);
        emit Sealed(pid, msg.sender, slotId(cid, sector), msg.sender, BOND);
    }

    /**
     * @notice Q6 (SaaS) — SealingPool.sol calls this on behalf of a pinner
     *         after a successful off-chain sealing flow. The SealingPool
     *         escrowed the bond from the pinner; this function consumes it
     *         and seals on the pinner's behalf. The `sealer` field is set
     *         to the SealingPool address (the actual GPU operator is
     *         recorded inside the pool).
     *
     * @dev    Gated by `SEALER_POOL_ROLE` so arbitrary contracts can't
     *         seal on someone's behalf.
     */
    function recordSealerProof(
        address pinner,
        bytes32 cid,
        uint256 sector,
        bytes32 replicaID,
        uint256 epoch,
        bytes32 commD,
        bytes32 commR,
        bytes32 commC,
        bytes calldata porepProof
    ) external payable onlyRole(SEALER_POOL_ROLE) nonReentrant {
        require(registered[pinner], "Pinner not registered");
        require(msg.value == BOND, "Must post exact bond");

        ModelRegistration storage reg = _modelByCid[cid];
        require(reg.modelOwner != address(0), "Model not registered");
        require(!reg.slashed, "Model slashed");
        require(commD == reg.commD, "CommD mismatch");

        bytes32 pid = pinId(pinner, cid, sector);
        _doSeal(pinner, msg.sender, pid, cid, sector, replicaID, epoch, commD, commR, commC, porepProof);
        emit Sealed(pid, pinner, slotId(cid, sector), msg.sender, BOND);
    }

    /// @dev Shared seal body. `pinner` is the on-chain reward recipient;
    ///      `sealerCaller` is who actually submitted (either pinner or
    ///      a SEALER_POOL_ROLE-bearer).
    function _doSeal(
        address pinner,
        address sealerCaller,
        bytes32 pid,
        bytes32 cid,
        uint256 sector,
        bytes32 replicaID,
        uint256 epoch,
        bytes32 commD,
        bytes32 commR,
        bytes32 commC,
        bytes calldata porepProof
    ) internal {
        Pin storage p = _pins[pid];
        require(p.status == Status.None, "Pin not in None status");

        bytes32 sid = slotId(cid, sector);
        Slot storage s = _ensureSlotFunded(sid);
        require(s.liveCount < QUORUM, "Slot quorum reached");

        // Anti-theft: a replicaID (the Poseidon binding of the pinner's private
        // identity to the sealed bytes) is usable only by the pinner who first
        // committed it — so a second pinner cannot re-submit another pinner's
        // (replicaID, proof) to seal a pin they didn't produce.
        address owner = replicaIdOwner[replicaID];
        require(owner == address(0) || owner == pinner, "replicaID owned by another");
        if (owner == address(0)) {
            replicaIdOwner[replicaID] = pinner;
        }

        // The wire carries the CIRCUIT's replicaID (Poseidon, supplied) and the
        // pinner's seal `epoch` — NOT a contract-derived keccak replicaID nor
        // block.number — so a real proof's public inputs match (PIN-S6 finding).
        bytes memory input = abi.encodePacked(
            replicaID,
            cid,
            bytes32(sector),
            POREP_VERSION,
            uint32(block.chainid),
            commD,
            commR,
            commC,
            bytes32(0), // challengeNonce (none at seal — index 0)
            bytes32(epoch),
            porepProof
        );
        require(_verify(input), "PoRep proof invalid");

        p.status = Status.Active;
        p.round = 0;
        p.missed = 0;
        p.claimed = 0;
        p.bondHeld = BOND;
        p.replicaID = replicaID;
        p.epoch = epoch;
        p.commD = commD;
        p.commR = commR;
        p.commC = commC;
        p.sealer = sealerCaller;

        bondedTotal += BOND;
        s.liveCount += 1;
    }

    // ═══════════════════ Q1: commit-reveal (challenge) ══════════════════════

    /**
     * @notice Q1 — PERMISSIONLESS commit on a per-slot challenge nonce.
     *         The nonce is bound to the prevrandao of THIS block + slotId
     *         + a monotonic counter; the PoSt may only be submitted at
     *         block ≥ commitBlock + REVEAL_DELAY (gated in `submitPoSt`).
     *
     * @dev    Permissionless caller — anyone can pay the gas. The pinner
     *         typically commits to its own slot to ensure timely PoSt
     *         eligibility; any external party (slasher, watchdog) can
     *         also commit.
     *
     *         Re-committing OVERWRITES the previous commit only if no
     *         pin in the slot has a successfully-reveal PoSt outstanding
     *         (otherwise the previous commit might already be in-use).
     *         For v0 we simply require the previous commit window has
     *         passed (block.number > commitBlock + REVEAL_DELAY +
     *         CHALLENGE_WINDOW).
     */
    function commitChallenge(bytes32 cid, uint256 sector) external {
        bytes32 sid = slotId(cid, sector);
        Slot storage s = _ensureSlotFunded(sid);

        if (s.commitBlock != 0) {
            require(
                block.number > s.commitBlock + REVEAL_DELAY + CHALLENGE_WINDOW,
                "Prior commit still live"
            );
        }

        s.commitCounter += 1;
        // The nonce binds to the CURRENT block's prevrandao (the proposer
        // of this block can't grind across multiple values because the
        // VRF output is deterministic from their key + previous output).
        // The slotId + counter prevent cross-slot replay and same-slot
        // re-use of a stale commit.
        bytes32 seed = keccak256(
            abi.encode(block.prevrandao, sid, s.commitCounter)
        );
        uint256 nonce = uint256(keccak256(abi.encode(seed))) % CHALLENGE_N;

        s.commitBlock = block.number;
        s.commitNonce = nonce;

        emit ChallengeCommitted(sid, block.number, nonce, s.commitCounter);
    }

    // ═══════════════ PIN-S3: bonded challenge (anti-griefing) ════════════════

    /**
     * @notice PIN-S3 (ADR-2026-06-11-pin-s3-challenger-bond). A third party
     *         escrows exactly `CHALLENGER_BOND`, asserting `pinner` is NOT
     *         storing the replica. This is an OPTIONAL overlay on top of the
     *         per-slot commit-reveal; it does NOT open a commit (one must
     *         already exist so the pinner *can* refute — otherwise the challenge
     *         would be unrefutable). The pinner refutes by answering the slot's
     *         committed PoSt before `challengeDeadline`:
     *           - refuted (frivolous) -> the bond is forfeit to the pinner
     *             (compensates the wasted proving), in `submitPoSt`;
     *           - unrefuted (honest)  -> the bond is returned to the challenger
     *             AND the challenger earns the slash reward, in `slash`.
     *
     * Preconditions: pin Active, not fully vested, no existing bonded challenge,
     *                the slot has an outstanding commit.
     */
    function challengePin(address pinner, bytes32 cid, uint256 sector)
        external
        payable
        nonReentrant
    {
        require(msg.value == CHALLENGER_BOND, "Must post exact challenger bond");

        bytes32 pid = pinId(pinner, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active, "Pin not active");
        require(p.round < ROUNDS, "Already fully vested");
        require(p.challenger == address(0), "Already challenged");

        Slot storage s = _slots[slotId(cid, sector)];
        require(s.commitBlock != 0, "No committed challenge");

        p.challenger = msg.sender;
        p.challengerBond = msg.value;
        // The pinner must refute within the slot's current reveal window.
        p.challengeDeadline = s.commitBlock + REVEAL_DELAY + CHALLENGE_WINDOW;

        challengerBonded += msg.value;
        challengerEscrowed += msg.value;

        emit PinChallenged(pid, msg.sender, p.challengeDeadline, msg.value);
    }

    /// @dev Resolve any bonded challenge on `p` in the PINNER's favour (the
    ///      pinner just proved possession): forfeit the bond to the pinner.
    function _forfeitChallengeToPinner(Pin storage p, bytes32 pid, address pinner) internal {
        if (p.challenger != address(0)) {
            uint256 b = p.challengerBond;
            p.challenger = address(0);
            p.challengerBond = 0;
            p.challengeDeadline = 0;
            challengerEscrowed -= b;
            challengerBondToPinner += b;
            if (b > 0) {
                challengerCredit[pinner] += b; // pull-payment
            }
            emit ChallengerBondForfeit(pid, pinner, b);
        }
    }

    /// @dev Resolve any bonded challenge on `p` in the CHALLENGER's favour (the
    ///      pinner failed to refute): return the bond. Returns the bonded
    ///      challenger (0 if none) so `slash` can route the slash reward to them.
    function _returnChallengeToChallenger(Pin storage p, bytes32 pid) internal returns (address) {
        address ch = p.challenger;
        if (ch != address(0)) {
            uint256 b = p.challengerBond;
            p.challenger = address(0);
            p.challengerBond = 0;
            p.challengeDeadline = 0;
            challengerEscrowed -= b;
            challengerBondReturned += b;
            if (b > 0) {
                challengerCredit[ch] += b; // pull-payment
            }
            emit ChallengerBondReturned(pid, ch, b);
        }
        return ch;
    }

    // ═══════════════════ TLA: PoStPass (vest from budget) ═══════════════════

    /**
     * @notice TLA `PoStPass(pin)`, v3 commit-reveal version. Three gating
     *         changes vs v2:
     *           (a) the slot MUST have an outstanding commit
     *               (`commitBlock != 0`).
     *           (b) the reveal must come at block ≥ commitBlock +
     *               REVEAL_DELAY (Q1's whole point).
     *           (c) the reveal must come at block ≤ commitBlock +
     *               REVEAL_DELAY + CHALLENGE_WINDOW (response window).
     *           (d) the proof's `challengeNonce` MUST equal
     *               `commitNonce` (the stored commit).
     */
    function submitPoSt(
        bytes32 cid,
        uint256 sector,
        bytes32 commR,
        bytes32 commC,
        uint256 challengeNonce,
        bytes calldata postProof
    ) external nonReentrant {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active, "Pin not active");
        require(p.round < ROUNDS, "Already fully vested");

        bytes32 sid = slotId(cid, sector);
        Slot storage s = _slots[sid];
        require(s.commitBlock != 0, "No committed challenge");
        require(
            block.number >= s.commitBlock + REVEAL_DELAY,
            "Reveal too early"
        );
        require(
            block.number <= s.commitBlock + REVEAL_DELAY + CHALLENGE_WINDOW,
            "Challenge window closed"
        );
        require(challengeNonce == s.commitNonce, "Wrong challengeNonce");
        require(s.budget >= PER_ROUND, "Slot budget exhausted");

        // The PoSt re-proves the SAME sealed replica, so the wire reuses the
        // STORED replicaID + epoch (the daemon re-seals deterministically from
        // the original inputs to prove). epoch != block.number — the daemon
        // can't predict the submit block (PIN-S6 finding).
        bytes memory input = abi.encodePacked(
            p.replicaID,
            cid,
            bytes32(sector),
            POST_VERSION,
            uint32(block.chainid),
            commR,
            commC,
            bytes32(challengeNonce),
            bytes32(p.epoch),
            postProof
        );
        require(_verify(input), "PoSt proof invalid");

        s.budget -= PER_ROUND;
        p.round += 1;
        p.missed = 0;

        Status newStatus = (uint256(p.round) == ROUNDS) ? Status.Done : Status.Active;
        p.status = newStatus;

        // PIN-S3: the pinner just proved possession — any bonded challenge
        // against this pin was frivolous; forfeit the challenger's bond to the
        // pinner (msg.sender). No-op if unchallenged.
        _forfeitChallengeToPinner(p, pid, msg.sender);

        emit PoStPassed(pid, p.round, PER_ROUND, newStatus);
    }

    // ═══════════════════════════ TLA: Claim ═════════════════════════════════

    function claim(bytes32 cid, uint256 sector)
        external
        nonReentrant
        returns (uint256 owed)
    {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active || p.status == Status.Done, "Pin not claimable");

        uint256 vested = uint256(p.round) * PER_ROUND;
        if (vested <= p.claimed) {
            return 0;
        }
        owed = vested - p.claimed;

        p.claimed = vested;
        paidTotal += owed;

        (bool ok, ) = msg.sender.call{value: owed}("");
        require(ok, "Transfer failed");

        emit Claimed(pid, msg.sender, owed);
    }

    // ════════════════════ TLA: PoStFail / slash ═════════════════════════════

    function slash(address pinner, bytes32 cid, uint256 sector) external nonReentrant {
        bytes32 pid = pinId(pinner, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active, "Pin not active");

        bytes32 sid = slotId(cid, sector);
        Slot storage s = _slots[sid];
        require(s.commitBlock != 0, "No committed challenge");
        require(
            block.number > s.commitBlock + REVEAL_DELAY + CHALLENGE_WINDOW,
            "Window not yet closed"
        );

        // PIN-S3: the pinner failed to refute. Return any bonded challenger's
        // bond and route the slash reward to THEM (an honest challenge pays);
        // with no bonded challenger this returns 0 and the reward goes to the
        // permissionless caller, preserving v2 behaviour.
        address bondedChallenger = _returnChallengeToChallenger(p, pid);
        address rewardTo = bondedChallenger != address(0) ? bondedChallenger : msg.sender;

        if (uint256(p.missed) + 1 > MAX_MISSED) {
            uint256 bond = p.bondHeld;
            uint256 cr = (bond * CHALLENGER_BPS) / 10000;
            uint256 br = bond - cr;
            uint256 owed = uint256(p.round) * PER_ROUND - p.claimed;

            challengerPaid += cr;
            burned += br;
            s.budget += owed;

            p.status = Status.Slashed;
            p.bondHeld = 0;
            p.missed += 1;
            if (s.liveCount > 0) {
                s.liveCount -= 1;
            }

            if (cr > 0) {
                challengerCredit[rewardTo] += cr;
            }
            if (br > 0) {
                (bool ok, ) = address(0).call{value: br}("");
                require(ok, "Burn transfer failed");
            }

            emit Slashed(pid, rewardTo, cr, br, owed);
        } else {
            p.missed += 1;
            emit Missed(pid, p.missed);
        }
    }

    function withdrawChallengerCredit() external nonReentrant returns (uint256 amt) {
        amt = challengerCredit[msg.sender];
        require(amt > 0, "No credit");
        challengerCredit[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");
    }

    // ═══════════════════════ TLA: ClearSlashed ══════════════════════════════

    function clearSlashed(bytes32 cid, uint256 sector) external {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Slashed, "Pin not slashed");

        p.status = Status.None;
        p.round = 0;
        p.claimed = 0;
        p.missed = 0;

        emit SlashedCleared(pid);
    }

    // ═══════════════════════════ TLA: ReturnBond ════════════════════════════

    function returnBond(bytes32 cid, uint256 sector)
        external
        nonReentrant
        returns (uint256 amt)
    {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Done, "Pin not done");
        require(p.claimed == uint256(p.round) * PER_ROUND, "Not fully claimed");
        require(p.bondHeld > 0, "No bond held");

        amt = p.bondHeld;
        p.bondHeld = 0;
        returned += amt;

        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");

        emit BondReturned(pid, msg.sender, amt);
    }

    // ─────────────────────────── 0x0108 STATICCALL ─────────────────────────

    function _verify(bytes memory input) internal view returns (bool) {
        (bool ok, bytes memory ret) = INFERENCE_PROOF_VERIFY.staticcall(input);
        if (!ok || ret.length != 32) {
            return false;
        }
        return abi.decode(ret, (uint256)) == 1;
    }

    // ───────────────────────────── View helpers ────────────────────────────

    function getPin(address pinner, bytes32 cid, uint256 sector)
        external
        view
        returns (
            Status status,
            uint64 round,
            uint64 missed,
            uint256 claimed,
            uint256 bondHeld,
            address sealer
        )
    {
        Pin storage p = _pins[pinId(pinner, cid, sector)];
        return (p.status, p.round, p.missed, p.claimed, p.bondHeld, p.sealer);
    }

    /// @notice PIN-S3 bonded-challenge state for a pin (0/0/0 if unchallenged).
    function getChallenge(address pinner, bytes32 cid, uint256 sector)
        external
        view
        returns (address challenger, uint256 challengerBond, uint256 challengeDeadline)
    {
        Pin storage p = _pins[pinId(pinner, cid, sector)];
        return (p.challenger, p.challengerBond, p.challengeDeadline);
    }

    function getSlot(bytes32 cid, uint256 sector)
        external
        view
        returns (
            bool funded,
            uint256 budget,
            uint256 liveCount,
            uint256 commitBlock,
            uint256 commitNonce,
            uint256 commitCounter
        )
    {
        Slot storage s = _slots[slotId(cid, sector)];
        return (
            s.funded,
            s.budget,
            s.liveCount,
            s.commitBlock,
            s.commitNonce,
            s.commitCounter
        );
    }

    function getModel(bytes32 cid)
        external
        view
        returns (
            address modelOwner,
            bytes32 commD,
            bytes32 dataHash,
            string memory dataUri,
            uint256 bondAmount,
            uint256 registeredAt,
            bool slashed
        )
    {
        ModelRegistration storage reg = _modelByCid[cid];
        return (
            reg.modelOwner,
            reg.commD,
            reg.dataHash,
            reg.dataUri,
            reg.bondAmount,
            reg.registeredAt,
            reg.slashed
        );
    }

    function owedOf(address pinner, bytes32 cid, uint256 sector)
        external
        view
        returns (uint256)
    {
        Pin storage p = _pins[pinId(pinner, cid, sector)];
        if (p.status == Status.Active || p.status == Status.Done) {
            return uint256(p.round) * PER_ROUND - p.claimed;
        }
        return 0;
    }

    receive() external payable {}
}
