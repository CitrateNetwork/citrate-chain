// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @title Sortition — verifiable committee selection
/// @notice citrate-quorum QRM-S6.8. Planset `03_GOVERNANCE_CONTRACTS.md` §5.
/// Formal spec: `specs/tla/contracts/Sortition.tla` (SO-1…SO-3).
///
/// Review panels, audit juries, random spot-checks of agent work, rotating
/// meeting chairs. Anyone can recompute a completed draw from public data and
/// get the same committee.
///
/// ## The honest problem this is built around
///
/// `block.prevrandao` on chain 40204 is the consensus VRF output, and a
/// VRF-elected proposer **knows its own output before publishing**. So a
/// proposer can withhold a block to bias a draw. That is fine for a tie-break
/// and not fine for choosing who audits a $50M program.
///
/// The defence is commit-reveal: participants commit entropy before the target
/// block and reveal after, and the seed mixes their contributions with the
/// chain's. **SO-2: one honest contributor makes the draw unbiasable**, because
/// the proposer would have to know a value that was committed before it chose
/// its block.
///
/// ## One deviation from the planset, and what it costs
///
/// The planset writes `seed = keccak256(prevrandao(targetBlock) ‖ …)`. **The EVM
/// cannot do that.** `block.prevrandao` is readable only for the block currently
/// executing; there is no way to read a past block's. This uses
/// `blockhash(targetBlock)` instead, which *is* readable retroactively.
///
/// What that costs: the block hash commits to the header, which commits to the
/// same VRF output — so a proposer's influence is identical in kind, and SO-2 is
/// still what neutralises it. What it adds is a hard deadline: `blockhash`
/// returns zero beyond 256 blocks, so a draw not finalized inside that horizon
/// **cannot** be finalized. Rather than fight that, this makes it SO-3: such a
/// draw is `Void`, and voiding is a state anyone can trigger and everyone can
/// see. The EVM enforces the invariant the planset asked for.
///
/// ## The last-revealer problem, stated rather than papered over
///
/// Reveals happen after `targetBlock`, when the block hash is already public.
/// A participant can therefore compute the outcome before revealing and decide
/// not to. **Finalization requires every commitment to be revealed**, so that
/// choice does not steer the draw — it kills it. Bias is converted into denial
/// of service, which is the standard trade for commit-reveal and is the right
/// one here: a void draw is visible, re-runnable, and names who failed to
/// reveal, whereas a steered draw looks exactly like a fair one.
///
/// ## Documented limitation
///
/// **If nobody commits, the draw degrades to proposer-influenceable.** It still
/// completes, and [`drawOf`] reports `commitCount == 0` so the app can say so
/// out loud. A sortition with no entropy contributors is a coin the proposer
/// flipped.
contract Sortition {
    enum State {
        None,
        Open,
        /// Seed fixed, committee computable.
        Final,
        /// Never reached finality inside its window (SO-3).
        Void
    }

    struct Draw {
        bytes32 poolRoot;
        uint32 poolSize;
        uint32 k;
        uint64 targetBlock;
        bytes32 seed;
        uint32 commitCount;
        uint32 revealCount;
        /// XOR accumulator over revealed contributions.
        bytes32 revealedXor;
        State state;
        address opener;
    }

    /// Minimum distance from `openDraw` to `targetBlock`: two checkpoint
    /// intervals of 50, so the target is BFT-finalized before it is used and
    /// nobody can open a draw against a block they are about to propose.
    uint64 public constant MIN_DELTA = 100;
    /// How long after `targetBlock` before the seed may be fixed. Same two
    /// intervals, applied on the other side.
    uint64 public constant FINALITY_DELAY = 100;
    /// `blockhash` returns zero beyond this. The hard edge that makes SO-3 real
    /// rather than aspirational.
    uint64 public constant BLOCKHASH_HORIZON = 256;

    mapping(bytes32 => Draw) private _draws;
    /// draw → contributor → commitment (zero when none).
    mapping(bytes32 => mapping(address => bytes32)) public commitmentOf;
    /// draw → contributor → revealed.
    mapping(bytes32 => mapping(address => bool)) public revealedBy;

    error DrawExists(bytes32 drawId);
    error UnknownDraw(bytes32 drawId);
    error TargetTooSoon(uint64 targetBlock, uint64 earliest);
    error EmptyPool();
    error CommitteeLargerThanPool(uint32 k, uint32 poolSize);
    error ZeroCommittee();
    error ZeroPoolRoot();
    error NotOpen(bytes32 drawId, State state);
    error CommitWindowClosed(uint64 targetBlock);
    error AlreadyCommitted(bytes32 drawId, address who);
    error ZeroCommitment();
    /// CHAIN-B-C022: the caller did not prove membership of the draw's pool.
    error NotPoolMember(bytes32 drawId, address who);
    error NothingCommitted(bytes32 drawId, address who);
    error AlreadyRevealed(bytes32 drawId, address who);
    error RevealTooEarly(uint64 targetBlock);
    error BadReveal(bytes32 drawId, address who);
    error TooEarlyToFinalize(uint64 earliest);
    error BeyondBlockhashHorizon(uint64 targetBlock, uint64 deadline);
    error UnreadableAnchor(uint64 targetBlock);
    error UnrevealedCommitments(uint32 committed, uint32 revealed);
    error NotFinal(bytes32 drawId, State state);
    error StillFinalizable(bytes32 drawId);
    error IndexOutOfRange(uint32 index, uint32 k);

    event DrawOpened(
        bytes32 indexed drawId, bytes32 indexed poolRoot, uint32 poolSize, uint32 k, uint64 targetBlock, address opener
    );
    event EntropyCommitted(bytes32 indexed drawId, address indexed who, bytes32 commitment);
    event EntropyRevealed(bytes32 indexed drawId, address indexed who);
    event DrawFinalized(bytes32 indexed drawId, bytes32 seed, uint32 commitCount);
    event DrawVoided(bytes32 indexed drawId, uint32 committed, uint32 revealed);

    // ── Opening ─────────────────────────────────────────────────────

    function openDraw(bytes32 drawId, bytes32 poolRoot, uint32 poolSize, uint32 k, uint64 targetBlock) external {
        if (_draws[drawId].state != State.None) revert DrawExists(drawId);
        if (poolRoot == bytes32(0)) revert ZeroPoolRoot();
        if (poolSize == 0) revert EmptyPool();
        if (k == 0) revert ZeroCommittee();
        if (k > poolSize) revert CommitteeLargerThanPool(k, poolSize);

        uint64 earliest = uint64(block.number) + MIN_DELTA;
        // Without this, an opener who is about to propose could target a block
        // whose VRF output it already knows.
        if (targetBlock < earliest) revert TargetTooSoon(targetBlock, earliest);

        Draw storage d = _draws[drawId];
        d.poolRoot = poolRoot;
        d.poolSize = poolSize;
        d.k = k;
        d.targetBlock = targetBlock;
        d.state = State.Open;
        d.opener = msg.sender;

        emit DrawOpened(drawId, poolRoot, poolSize, k, targetBlock, msg.sender);
    }

    // ── Commit / reveal ─────────────────────────────────────────────

    /// `commitment = keccak256(abi.encode(r, salt))`. One per address.
    ///
    /// CHAIN-B-C022 (audit 2026-09-02): `commit` USED to be permissionless and
    /// costless beyond gas. Because `finalize` requires `revealCount ==
    /// commitCount`, any address with no stake and no relationship to the pool
    /// could commit junk to every open draw and never reveal, guaranteeing the
    /// draw voids — an unbounded, unslashable DoS on committee selection. The
    /// caller must now prove membership of the draw's committed pool with a
    /// Merkle inclusion proof of its OWN leaf, so only actual pool members can
    /// contribute entropy (and a griefing member is a named, bounded party, the
    /// inherent last-revealer trade this contract already documents).
    ///
    /// The proven leaf is `keccak256(abi.encode(msg.sender))`; pool roots MUST
    /// be built over that leaf encoding (OWNER/reroll pool-provisioning note).
    /// `index` is the caller's position in the committed pool and `proof` its
    /// Merkle authentication path.
    function commit(bytes32 drawId, bytes32 commitment, uint32 index, bytes32[] calldata proof) external {
        Draw storage d = _open(drawId);
        // A commitment made at or after the target block could be chosen with
        // the block hash in hand, which is the whole thing this defends against.
        if (block.number >= d.targetBlock) revert CommitWindowClosed(d.targetBlock);
        if (commitment == bytes32(0)) revert ZeroCommitment();
        // CHAIN-B-C022: bind the commit to a real pool member. The leaf is
        // derived from msg.sender, so an outsider cannot forge membership and
        // cannot commit on another member's behalf.
        if (!_isPoolMember(d, index, keccak256(abi.encode(msg.sender)), proof)) {
            revert NotPoolMember(drawId, msg.sender);
        }
        if (commitmentOf[drawId][msg.sender] != bytes32(0)) revert AlreadyCommitted(drawId, msg.sender);

        commitmentOf[drawId][msg.sender] = commitment;
        d.commitCount += 1;
        emit EntropyCommitted(drawId, msg.sender, commitment);
    }

    /// Merkle inclusion check of `leaf` at `index` against the draw's pool
    /// root. Same authentication-path convention as {verifyMember}.
    function _isPoolMember(Draw storage d, uint32 index, bytes32 leaf, bytes32[] calldata proof)
        private
        view
        returns (bool)
    {
        if (index >= d.poolSize) return false;
        bytes32 node = leaf;
        uint256 path = index;
        for (uint256 i = 0; i < proof.length; ++i) {
            node = path & 1 == 0 ? keccak256(abi.encode(node, proof[i])) : keccak256(abi.encode(proof[i], node));
            path >>= 1;
        }
        return node == d.poolRoot;
    }

    function reveal(bytes32 drawId, bytes32 r, bytes32 salt) external {
        Draw storage d = _open(drawId);
        if (block.number <= d.targetBlock) revert RevealTooEarly(d.targetBlock);

        bytes32 c = commitmentOf[drawId][msg.sender];
        if (c == bytes32(0)) revert NothingCommitted(drawId, msg.sender);
        if (revealedBy[drawId][msg.sender]) revert AlreadyRevealed(drawId, msg.sender);
        if (keccak256(abi.encode(r, salt)) != c) revert BadReveal(drawId, msg.sender);

        revealedBy[drawId][msg.sender] = true;
        d.revealedXor ^= r;
        d.revealCount += 1;
        emit EntropyRevealed(drawId, msg.sender);
    }

    /// The commitment for a contribution, so a contributor computes it the same
    /// way this contract will check it.
    function commitmentFor(bytes32 r, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encode(r, salt));
    }

    // ── Finalize / void ─────────────────────────────────────────────

    /// Fix the seed. Callable by anyone — the draw belongs to whoever is
    /// waiting on it, not to whoever opened it.
    function finalize(bytes32 drawId) external {
        Draw storage d = _open(drawId);

        uint64 earliest = d.targetBlock + FINALITY_DELAY;
        if (block.number < earliest) revert TooEarlyToFinalize(earliest);
        // SO-3, enforced by the EVM rather than promised: past the horizon there
        // is no block hash to read, so there is nothing to finalize.
        if (block.number > d.targetBlock + BLOCKHASH_HORIZON) {
            revert BeyondBlockhashHorizon(d.targetBlock, d.targetBlock + BLOCKHASH_HORIZON);
        }
        // Every commitment must be revealed. A participant who dislikes the
        // outcome can kill the draw but cannot steer it.
        if (d.revealCount != d.commitCount) revert UnrevealedCommitments(d.commitCount, d.revealCount);

        // The horizon check above should make this unreachable on a live chain,
        // but `blockhash` returning zero is how the EVM says "I cannot tell
        // you", and a seed built on a zero is a draw the chain contributed
        // nothing to. Refusing is the same rule this contract applies
        // everywhere else: an unreadable input is a refusal, not a default.
        bytes32 anchor = blockhash(d.targetBlock);
        if (anchor == bytes32(0)) revert UnreadableAnchor(d.targetBlock);

        // C038: `drawId` is caller-chosen at `openDraw` and must NOT enter the
        // seed. Mixing it in let an opener grind — open M draws over one pool
        // with different ids and finalize only the favourable committee. The
        // seed now depends solely on the chain anchor, the revealed entropy and
        // the (committed) pool root, so distinct ids over the same pool/target
        // yield the same committee and the id is no longer an entropy knob.
        d.seed = keccak256(abi.encode(anchor, d.revealedXor, d.poolRoot));
        d.state = State.Final;

        emit DrawFinalized(drawId, d.seed, d.commitCount);
    }

    /// Mark a draw that missed its window. SO-3: void, not best-effort.
    ///
    /// Anyone may call it, and it is the only terminal state a stalled draw can
    /// reach — there is no path that produces a committee from a draw whose seed
    /// was never fixed.
    function void(bytes32 drawId) external {
        Draw storage d = _open(drawId);
        // While it can still be finalized, voiding it would be a way to cancel a
        // draw somebody is about to lose.
        if (block.number <= d.targetBlock + BLOCKHASH_HORIZON) revert StillFinalizable(drawId);

        d.state = State.Void;
        emit DrawVoided(drawId, d.commitCount, d.revealCount);
    }

    // ── The committee ───────────────────────────────────────────────
    /// The selected pool indices, in selection order. SO-1: pure function of the
    /// fixed seed, so anyone recomputes the same committee from public data.
    ///
    /// Sampling is rejection-free: index `i` is drawn from the remaining pool by
    /// a partial Fisher-Yates over a virtual array, so the k results are always
    /// distinct and the cost is O(k²) rather than unbounded. `k` is a committee,
    /// not a population, so that is the right trade.
    function selection(bytes32 drawId) public view returns (uint32[] memory picks) {
        Draw storage d = _draws[drawId];
        if (d.state != State.Final) revert NotFinal(drawId, d.state);

        picks = new uint32[](d.k);
        // The picks so far, kept ascending. Sampling without replacement from a
        // virtual identity array: draw r in [0, remaining) and walk it up past
        // every already-taken index at or below it, which lands on the r-th
        // still-free slot. A real array of `poolSize` would be unaffordable for
        // a large pool, and rejection sampling would be unbounded.
        uint32[] memory sorted = new uint32[](d.k);

        for (uint32 i = 0; i < d.k; ++i) {
            uint32 r = uint32(uint256(keccak256(abi.encode(d.seed, i))) % (d.poolSize - i));
            uint32 pick = r;
            for (uint32 j = 0; j < i; ++j) {
                if (sorted[j] <= pick) pick += 1;
            }
            picks[i] = pick;

            uint32 pos = i;
            while (pos > 0 && sorted[pos - 1] > pick) {
                sorted[pos] = sorted[pos - 1];
                pos -= 1;
            }
            sorted[pos] = pick;
        }
    }

    /// Verify a pool member is the one at `index` in the committed pool.
    ///
    /// The pool itself is off chain — only its root is committed — so this is how
    /// a name is attached to a selected index without ever putting the
    /// membership list on a public ledger (planset D6).
    function verifyMember(bytes32 drawId, uint32 index, bytes32 leaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        Draw storage d = _draws[drawId];
        if (d.state == State.None) revert UnknownDraw(drawId);
        if (index >= d.poolSize) return false;

        bytes32 node = leaf;
        uint256 path = index;
        for (uint256 i = 0; i < proof.length; ++i) {
            node = path & 1 == 0 ? keccak256(abi.encode(node, proof[i])) : keccak256(abi.encode(proof[i], node));
            path >>= 1;
        }
        return node == d.poolRoot;
    }

    // ── Views ───────────────────────────────────────────────────────

    function drawOf(bytes32 drawId) external view returns (Draw memory) {
        Draw storage d = _draws[drawId];
        if (d.state == State.None) revert UnknownDraw(drawId);
        return d;
    }

    /// Did anyone contribute entropy? `false` is the documented degraded state:
    /// the draw is proposer-influenceable, and the app must say so rather than
    /// present it as a fair sortition.
    function hasEntropyContributors(bytes32 drawId) external view returns (bool) {
        return _draws[drawId].commitCount > 0;
    }

    function stateOf(bytes32 drawId) external view returns (State) {
        return _draws[drawId].state;
    }

    function _open(bytes32 drawId) private view returns (Draw storage d) {
        d = _draws[drawId];
        if (d.state == State.None) revert UnknownDraw(drawId);
        if (d.state != State.Open) revert NotOpen(drawId, d.state);
    }
}
