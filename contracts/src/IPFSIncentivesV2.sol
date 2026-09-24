// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/AccessControl.sol";
import "./lib/ReentrancyGuard.sol";
import "./KYCRegistry.sol";

/**
 * @title IPFSIncentivesV2 — PIN sealed-PoRep incentive (financial state machine)
 * @notice On-chain realization of the TLA+ spec
 *         `citrate-federation/.agentile/gtm-spine/formal/PINIncentive.tla` (v3,
 *         sector-indexed). A "pin" is the triple (pinner, cid, sector); a "slot"
 *         is (cid, sector). The contract mirrors the TLA actions and preserves
 *         its safety invariants:
 *
 *           Seal          -> sealCommit()       (post bond + valid PoRep -> active)
 *           PoStPass      -> submitPoSt() ok     (vest one round from slot budget)
 *           Claim         -> claim()             (withdraw owed = vested - claimed)
 *           PoStFail/slash-> slash()             (split bond -> challenger+burn, owed->budget)
 *           ClearSlashed  -> clearSlashed()      (re-seal prep; reset per-attempt counters)
 *           ReturnBond    -> returnBond()        (done + fully-claimed -> return bond)
 *
 *         Invariants (TLA): NoPayWithoutProof, PerPinRewardCap, BudgetNonNegative,
 *         QuorumRespected, Conservation, BondCoversExposure, SlashedNoBond,
 *         BondConservation. The contract enforces each by construction; the
 *         Foundry invariant suite (test/IPFSIncentivesV2Invariant.t.sol) asserts
 *         them over randomized action sequences.
 *
 * @dev Proof verification is delegated to Citrate precompile 0x0108
 *      (INFERENCE_PROOF_VERIFY, Halo2-KZG, version-multiplexed):
 *        - PoRep = circuit_version 2 (public inputs incl. CommD), used at seal.
 *        - PoSt  = circuit_version 3 (no CommD), used at each challenge response.
 *      The ZK cryptography is an oracle to this contract: a successful STATICCALL
 *      returning 1 == "valid proof" (TLA PoStPass), a revert/0 == "no proof"
 *      (TLA PoStFail). NO money moves without a 0x0108 success (NoPayWithoutProof).
 *
 *      v1 (`IPFSIncentives.sol`) is left untouched; this is a new, superseding
 *      contract for the sealed-PoRep mechanism.
 */
contract IPFSIncentivesV2 is AccessControl, ReentrancyGuard {
    // ───────────────────────── Precompile (0x0108) ─────────────────────────

    /// @notice Citrate INFERENCE_PROOF_VERIFY precompile (Halo2-KZG).
    /// @dev MUST be 0x0108 (the live verifier). 0x0104 is the D2 stub — see the
    ///      ComputeVerifier defect flagged for a separate PR; do NOT use it here.
    address public constant INFERENCE_PROOF_VERIFY =
        0x0000000000000000000000000000000000000108;

    /// @notice circuit_version for the reduced-PoRep VK (seal-time proof).
    uint32 public constant POREP_VERSION = 2;
    /// @notice circuit_version for the reduced-PoSt VK (challenge-response proof).
    uint32 public constant POST_VERSION = 3;

    // ───────────────────────── Economic parameters ─────────────────────────
    // These mirror the TLA CONSTANTS. They are immutable per deployment so the
    // invariants (which depend on Reward<=Bond, Reward%Rounds==0, etc.) hold for
    // the life of the contract. Funded == Quorum * Reward * (#slots); the contract
    // is admin-prefunded and tracks per-slot virtual budget.

    uint256 public immutable BOND;          // TLA: Bond     — escrowed per active pin
    uint256 public immutable REWARD;        // TLA: Reward   — full reward over all rounds
    uint256 public immutable ROUNDS;        // TLA: Rounds   — PoSt rounds to fully vest
    uint256 public immutable MAX_MISSED;    // TLA: MaxMissed— misses tolerated before slash
    uint256 public immutable CHALLENGER_BPS;// TLA: ChallengerBps — bp of bond to challenger
    uint256 public immutable QUORUM;        // TLA: Quorum   — max live pins per slot

    /// @notice PerRound == Reward / Rounds (TLA PerRound). Exact (Reward%Rounds==0).
    uint256 public immutable PER_ROUND;

    /// @notice KYC gate for registerPinner (anti-Sybil; one identity = one reward).
    KYCRegistry public immutable kyc;

    /// @notice Length (in blocks) of a challenge response window.
    uint256 public immutable CHALLENGE_WINDOW;

    /// @notice Number of leaf challenges N; challengeNonce = uint(keccak(seed)) % N.
    uint256 public immutable CHALLENGE_N;

    // ───────────────────────────── Pin state ───────────────────────────────

    enum Status { None, Active, Done, Slashed } // TLA: "none"/"active"/"done"/"slashed"

    struct Pin {
        Status status;
        uint64 round;      // TLA round[pin]   (0..Rounds)
        uint64 missed;     // TLA missed[pin]  (0..MaxMissed+1)
        uint256 claimed;   // TLA claimed[pin] (0..Reward)
        uint256 bondHeld;  // TLA bondHeld[pin](0..Bond)
        // replicaID binding: replicaID = Poseidon(pinner ‖ cid ‖ sector) per
        // PIN-P1-sdr-replicaid-construction.md. We bind it on chain with keccak
        // (the precompile checks the in-circuit Poseidon relation); stored to
        // re-derive the proof's public inputs and reject cross-pinner reuse.
        bytes32 replicaID;
        bytes32 commD;     // content anchor (unsealed Merkle root)
        bytes32 commR;     // sealed replica root (per-pinner)
        bytes32 commC;     // column commitment
        // Open-challenge state (challenge -> submitPoSt window):
        bool challengeOpen;
        uint256 challengeDeadline;  // block.number deadline (response window)
        uint256 challengeNonce;     // contract-derived nonce the proof must match
        uint256 challengeCounter;   // monotonic per-pin counter (seed domain sep)
    }

    /// @notice pinId = keccak(pinner, cid, sector) -> pin state.
    mapping(bytes32 => Pin) private _pins;

    // ──────────────────────────── Slot state ───────────────────────────────

    struct Slot {
        bool funded;        // budget seeded to Quorum*Reward on first touch
        uint256 budget;     // TLA budget[slot] (0..Quorum*Reward)
        uint256 liveCount;  // |LiveInSlot(slot)| — active+done pins (QuorumRespected)
    }

    /// @notice slotId = keccak(cid, sector) -> slot state.
    mapping(bytes32 => Slot) private _slots;

    // ─────────────────── Global conservation accumulators ───────────────────
    // TLA: paidTotal, burned, challengerPaid, bondedTotal, returned.

    uint256 public paidTotal;       // owed withdrawn (leaves the reward system)
    uint256 public burned;          // bond burned at slash
    uint256 public challengerPaid;  // bond paid to challengers at slash
    uint256 public bondedTotal;     // sum of all bond ever posted
    uint256 public returned;        // bond returned to pinners

    /// @notice Funds an admin has deposited to back the reward budget (the on-chain
    ///         analogue of TLA `Funded`, grown one slot at a time as slots open).
    uint256 public totalSlotBudgetFunded;

    /// @notice Withdrawable balance accrued to challengers (pull-payment).
    mapping(address => uint256) public challengerCredit;

    // ─────────────────────────────── Events ────────────────────────────────

    event PinnerRegistered(address indexed pinner);
    event Sealed(bytes32 indexed pinId, address indexed pinner, bytes32 indexed slotId, uint256 bond);
    event Challenged(bytes32 indexed pinId, uint256 challengeNonce, uint256 deadline, uint256 counter);
    event PoStPassed(bytes32 indexed pinId, uint64 round, uint256 vested, Status newStatus);
    event Claimed(bytes32 indexed pinId, address indexed pinner, uint256 amount);
    event Slashed(bytes32 indexed pinId, address indexed challenger, uint256 challengerReward, uint256 burnedAmt, uint256 owedReturned);
    event Missed(bytes32 indexed pinId, uint64 missed);
    event SlashedCleared(bytes32 indexed pinId);
    event BondReturned(bytes32 indexed pinId, address indexed pinner, uint256 amount);
    event SlotFunded(bytes32 indexed slotId, uint256 amount);

    // ──────────────────────────── Registration ─────────────────────────────

    /// @notice Pinners that have registered (KYC-gated). Anti-Sybil per decision.
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
        uint256 _challengeN
    ) {
        // TLA ASSUMEs, enforced at deploy so the invariants are well-formed:
        require(_reward <= _bond, "Reward must be <= Bond");        // RewardBounded
        require(_rounds > 0, "Rounds must be > 0");                  // RoundsPos
        require(_reward % _rounds == 0, "Reward % Rounds != 0");     // RewardDivides
        require(_challengerBps <= 10000, "Bps out of range");        // BpsRange
        require(_quorum > 0, "Quorum must be > 0");                  // QuorumPos
        require(_challengeWindow > 0, "Window must be > 0");
        require(_challengeN > 0, "ChallengeN must be > 0");
        require(address(_kyc) != address(0), "KYC required");

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

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Register as a pinner. KYC-gated (TLA does not model this; it is the
     *         anti-Sybil precondition for the whole machine — one verified identity
     *         is required before any Seal). Reverts if the caller is not currently
     *         KYC-verified in the registry.
     */
    function registerPinner() external {
        require(kyc.isVerified(msg.sender), "KYC: not verified");
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        emit PinnerRegistered(msg.sender);
    }

    /**
     * @notice Admin pre-funds the contract so reward budgets can be paid out.
     *         The contract must hold >= (outstanding owed + outstanding bond) at
     *         all times; this seeds that backing.
     */
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

    /// @notice replicaID binding = Poseidon(pinner ‖ cid ‖ sector) in-circuit; we
    ///         mirror the binding on chain with keccak. The contract stores it and
    ///         requires the proof's replicaID public input to equal this, so a
    ///         pinner cannot present another pinner's sealed bytes.
    function deriveReplicaId(address pinner, bytes32 cid, uint256 sector) public pure returns (bytes32) {
        return keccak256(abi.encode("PIN-replicaID", pinner, cid, sector));
    }

    // ─────────────── Slot budget seeding (Conservation backing) ─────────────

    function _ensureSlotFunded(bytes32 sid) internal returns (Slot storage s) {
        s = _slots[sid];
        if (!s.funded) {
            s.funded = true;
            // TLA Init: budget[slot] = Quorum * Reward.
            uint256 seed = QUORUM * REWARD;
            s.budget = seed;
            totalSlotBudgetFunded += seed;
            emit SlotFunded(sid, seed);
        }
    }

    // ═══════════════════════════ TLA: Seal ══════════════════════════════════

    /**
     * @notice TLA `Seal(pin)`. Post `BOND` (msg.value) and a VALID PoRep proof
     *         (0x0108 circuit_version=2) to make the pin active. Replication cap:
     *         the slot must have < QUORUM live pins.
     *
     * Preconditions (mirror TLA): status==None, |LiveInSlot| < Quorum.
     * Effects: status=Active, bondHeld=Bond, bondedTotal+=Bond, liveCount++.
     */
    function sealCommit(
        bytes32 cid,
        uint256 sector,
        bytes32 commD,
        bytes32 commR,
        bytes32 commC,
        bytes calldata porepProof
    ) external payable nonReentrant {
        require(registered[msg.sender], "Not registered");
        require(msg.value == BOND, "Must post exact bond");

        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.None, "Pin not in None status");

        bytes32 sid = slotId(cid, sector);
        Slot storage s = _ensureSlotFunded(sid);
        require(s.liveCount < QUORUM, "Slot quorum reached"); // QuorumRespected

        bytes32 replicaID = deriveReplicaId(msg.sender, cid, sector);

        // 0x0108 PoRep (v2) STATICCALL. Public-input layout per verify.rs:
        //   32B replicaID | 32B cid | 32B sectorIndex | 4B version=2 | 4B chainId
        //   | 32B CommD | 32B CommR | 32B CommC | 32B challengeNonce | 32B epoch | proof
        // At seal there is no live challenge; challengeNonce=0, epoch=block.number.
        bytes memory input = abi.encodePacked(
            replicaID,
            cid,
            bytes32(sector),
            POREP_VERSION,
            uint32(block.chainid),
            commD,
            commR,
            commC,
            bytes32(0),               // challengeNonce (none at seal)
            bytes32(block.number),    // epoch
            porepProof
        );
        require(_verify(input), "PoRep proof invalid"); // NoPayWithoutProof gate

        // Effects.
        p.status = Status.Active;
        p.round = 0;
        p.missed = 0;
        p.claimed = 0;
        p.bondHeld = BOND;
        p.replicaID = replicaID;
        p.commD = commD;
        p.commR = commR;
        p.commC = commC;
        p.challengeOpen = false;

        bondedTotal += BOND;
        s.liveCount += 1;

        emit Sealed(pid, msg.sender, sid, BOND);
    }

    // ═══════════════════════ challenge (open window) ════════════════════════

    /**
     * @notice Open a PoSt challenge for one's own active pin. Derives the leaf
     *         challenge from `block.prevrandao` (the consensus ECVRF beacon,
     *         surfaced by PIN-P1(d)) plus (cid, sector, pinner, a per-pin counter),
     *         and fixes a response window (in blocks). The required public input
     *         is `challengeNonce = uint(keccak(seed)) % CHALLENGE_N`.
     *
     * @dev GRIND-RESISTANCE LIMITATION (documented, not silently ignored):
     *      `block.prevrandao` carries the RFC-9381 ECVRF output of the CURRENT
     *      block (see node/src/producer.rs / PIN-P1(d)). It is unpredictable and
     *      unbiasable by ordinary parties, which defeats challenger/pinner *seed
     *      grinding*. The RESIDUAL vector is **proposer inclusion**: the block
     *      proposer learns its own VRF output before sealing the block and can
     *      choose to withhold/reorder the `challenge` tx within its block to get a
     *      (marginally) more favorable leaf set for a pin it controls. Closing this
     *      fully requires committing to a FUTURE block's beacon (commit-reveal /
     *      future-block randomness), tracked as a follow-up hardening. We bind the
     *      counter so a single proposer cannot replay the same favorable seed, but
     *      the proposer-inclusion bias is a KNOWN, BOUNDED limitation here.
     */
    function challenge(bytes32 cid, uint256 sector) external {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active, "Pin not active");
        require(p.round < ROUNDS, "Already fully vested");
        require(!p.challengeOpen, "Challenge already open");

        p.challengeCounter += 1;
        // Seed from the consensus VRF beacon + binding fields + monotonic counter.
        bytes32 seed = keccak256(
            abi.encode(block.prevrandao, cid, sector, msg.sender, p.challengeCounter)
        );
        uint256 nonce = uint256(keccak256(abi.encode(seed))) % CHALLENGE_N;

        p.challengeOpen = true;
        p.challengeDeadline = block.number + CHALLENGE_WINDOW;
        p.challengeNonce = nonce;

        emit Challenged(pid, nonce, p.challengeDeadline, p.challengeCounter);
    }

    // ═══════════════════ TLA: PoStPass (vest from budget) ═══════════════════

    /**
     * @notice TLA `PoStPass(pin)`. Respond to the open challenge within the window
     *         with a VALID PoSt proof (0x0108 circuit_version=3). The proof's
     *         `challengeNonce` public input MUST equal the contract-derived nonce.
     *         On success, vest one round drawn from the SLOT budget (caps farming),
     *         reset missed, and mark Done on the final round.
     *
     * Preconditions (TLA): status==Active, round<Rounds, budget[slot] >= PerRound.
     * Effects: round+1, missed=0, budget-=PerRound, status=(Done if last else Active).
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
        require(p.challengeOpen, "No open challenge");
        require(block.number <= p.challengeDeadline, "Challenge window closed");
        // Bind the proof to the contract-derived nonce (anti-replay; finding 3.1).
        require(challengeNonce == p.challengeNonce, "Wrong challengeNonce");

        bytes32 sid = slotId(cid, sector);
        Slot storage s = _slots[sid];
        require(s.budget >= PER_ROUND, "Slot budget exhausted"); // BudgetNonNegative

        // 0x0108 PoSt (v3) STATICCALL. Layout per verify.rs:
        //   32B replicaID | 32B cid | 32B sectorIndex | 4B version=3 | 4B chainId
        //   | 32B CommR | 32B CommC | 32B challengeNonce | 32B epoch | proof
        bytes memory input = abi.encodePacked(
            p.replicaID,
            cid,
            bytes32(sector),
            POST_VERSION,
            uint32(block.chainid),
            commR,
            commC,
            bytes32(challengeNonce),
            bytes32(block.number),    // epoch
            postProof
        );
        require(_verify(input), "PoSt proof invalid"); // NoPayWithoutProof gate

        // Effects (vest from slot budget).
        s.budget -= PER_ROUND;
        p.round += 1;
        p.missed = 0;
        p.challengeOpen = false;

        Status newStatus = (uint256(p.round) == ROUNDS) ? Status.Done : Status.Active;
        p.status = newStatus;

        emit PoStPassed(pid, p.round, PER_ROUND, newStatus);
    }

    // ═══════════════════════════ TLA: Claim ═════════════════════════════════

    /**
     * @notice TLA `Claim(pin)`. Withdraw entitled-but-unwithdrawn reward
     *         (owed = round*PerRound - claimed). owed leaves the reward system
     *         (paidTotal += owed); double-claim is a no-op (returns 0).
     *
     * Preconditions (TLA): status in {Active,Done}, claimed < round*PerRound.
     */
    function claim(bytes32 cid, uint256 sector) external nonReentrant returns (uint256 owed) {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active || p.status == Status.Done, "Pin not claimable");

        uint256 vested = uint256(p.round) * PER_ROUND;
        if (vested <= p.claimed) {
            return 0; // double-claim / nothing-owed no-op
        }
        owed = vested - p.claimed;

        // Effects before interaction.
        p.claimed = vested;       // claimed' = round*PerRound (TLA)
        paidTotal += owed;

        (bool ok, ) = msg.sender.call{value: owed}("");
        require(ok, "Transfer failed");

        emit Claimed(pid, msg.sender, owed);
    }

    // ════════════════════ TLA: PoStFail / slash ═════════════════════════════

    /**
     * @notice TLA `PoStFail(pin)`. Permissionless: anyone may call after the
     *         challenge window lapses with no valid PoSt. Increments `missed`;
     *         once missed+1 > MaxMissed, SLASH: split the bond into a challenger
     *         reward (ChallengerBps) + burn (remainder), return the forfeited owed
     *         to the slot budget (no money created), and mark the pin Slashed.
     *
     * Preconditions (TLA): status==Active, and either a window exists that has
     *         lapsed, or none is open (a miss is recordable). We require an open,
     *         expired challenge so misses correspond to real un-answered challenges.
     */
    function slash(address pinner, bytes32 cid, uint256 sector) external nonReentrant {
        bytes32 pid = pinId(pinner, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Active, "Pin not active");
        require(p.challengeOpen, "No open challenge");
        require(block.number > p.challengeDeadline, "Window not yet closed");

        // The unanswered challenge is consumed regardless.
        p.challengeOpen = false;

        if (uint256(p.missed) + 1 > MAX_MISSED) {
            // ── SLASH branch (TLA PoStFail, missed+1 > MaxMissed) ──
            bytes32 sid = slotId(cid, sector);
            Slot storage s = _slots[sid];

            uint256 bond = p.bondHeld;
            uint256 cr = (bond * CHALLENGER_BPS) / 10000; // challenger reward
            uint256 br = bond - cr;                        // burn remainder
            uint256 owed = uint256(p.round) * PER_ROUND - p.claimed; // forfeited owed

            // Accounting (BondConservation: bondedTotal == held+burned+challenger+returned).
            challengerPaid += cr;
            burned += br;
            // Forfeited owed returns to the slot budget — Conservation preserved.
            s.budget += owed;

            p.status = Status.Slashed;
            p.bondHeld = 0;             // SlashedNoBond
            p.missed += 1;
            // liveCount: the pin is no longer active/done -> leaves LiveInSlot.
            if (s.liveCount > 0) {
                s.liveCount -= 1;
            }

            // Challenger reward via pull-payment; burn by sending to address(0).
            if (cr > 0) {
                challengerCredit[msg.sender] += cr;
            }
            if (br > 0) {
                (bool ok, ) = address(0).call{value: br}("");
                require(ok, "Burn transfer failed");
            }

            emit Slashed(pid, msg.sender, cr, br, owed);
        } else {
            // ── miss-but-not-yet-slashed branch (TLA PoStFail, missed+1 <= MaxMissed) ──
            p.missed += 1;
            emit Missed(pid, p.missed);
        }
    }

    /// @notice Withdraw accrued challenger rewards (pull-payment).
    function withdrawChallengerCredit() external nonReentrant returns (uint256 amt) {
        amt = challengerCredit[msg.sender];
        require(amt > 0, "No credit");
        challengerCredit[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");
    }

    // ═══════════════════════ TLA: ClearSlashed ══════════════════════════════

    /**
     * @notice TLA `ClearSlashed(pin)`. Free a slashed (pinner,cid,sector) so it
     *         can be RE-SEALED fresh. Accounting was settled at slash; reset only
     *         the per-attempt counters (status->None, round/claimed/missed->0).
     *         The slot budget is unchanged, so re-seal farming cannot exceed it.
     *
     * Preconditions (TLA): status==Slashed.
     */
    function clearSlashed(bytes32 cid, uint256 sector) external {
        bytes32 pid = pinId(msg.sender, cid, sector);
        Pin storage p = _pins[pid];
        require(p.status == Status.Slashed, "Pin not slashed");

        p.status = Status.None;
        p.round = 0;
        p.claimed = 0;
        p.missed = 0;
        // bondHeld already 0 (SlashedNoBond); replicaID/commitments left for re-seal.

        emit SlashedCleared(pid);
    }

    // ═══════════════════════════ TLA: ReturnBond ════════════════════════════

    /**
     * @notice TLA `ReturnBond(pin)`. Once a pin is Done and fully claimed, return
     *         its remaining bond to the pinner.
     *
     * Preconditions (TLA): status==Done, claimed==round*PerRound, bondHeld>0.
     */
    function returnBond(bytes32 cid, uint256 sector) external nonReentrant returns (uint256 amt) {
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

    /// @dev STATICCALL the live 0x0108 verifier. Returns true iff the precompile
    ///      succeeds AND returns 32 bytes BE == 1. A revert or a 0 verdict => false
    ///      (the TLA "no proof" oracle). NO state changes here (view).
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
            bool challengeOpen,
            uint256 challengeDeadline,
            uint256 challengeNonce
        )
    {
        Pin storage p = _pins[pinId(pinner, cid, sector)];
        return (
            p.status,
            p.round,
            p.missed,
            p.claimed,
            p.bondHeld,
            p.challengeOpen,
            p.challengeDeadline,
            p.challengeNonce
        );
    }

    function getSlot(bytes32 cid, uint256 sector)
        external
        view
        returns (bool funded, uint256 budget, uint256 liveCount)
    {
        Slot storage s = _slots[slotId(cid, sector)];
        return (s.funded, s.budget, s.liveCount);
    }

    /// @notice owed(pin) = round*PerRound - claimed for active/done, else 0 (TLA Owed).
    function owedOf(address pinner, bytes32 cid, uint256 sector) external view returns (uint256) {
        Pin storage p = _pins[pinId(pinner, cid, sector)];
        if (p.status == Status.Active || p.status == Status.Done) {
            return uint256(p.round) * PER_ROUND - p.claimed;
        }
        return 0;
    }

    receive() external payable {}
}
