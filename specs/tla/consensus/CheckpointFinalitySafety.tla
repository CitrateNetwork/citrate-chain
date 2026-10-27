----------------------- MODULE CheckpointFinalitySafety -----------------------
EXTENDS Naturals, FiniteSets, TLC

\* WP-S.3 Stage 2 (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §5, §8.4).
\* Safety of committee-BFT checkpoint finality, end to end across nodes:
\*
\*   S1 (NoConflictingFinality): two nodes never finalize different blocks at
\*      the same checkpoint height while fewer than 1/3 of the committee is
\*      Byzantine.
\*   S2 (FloorBlockIsFinalized): the reorg floor of a node only ever protects
\*      the block its certificate finalized, and a reorg never changes a block
\*      at or below the floor.
\*
\* Companion to CheckpointVoteSafety.tla (vote admission, H-01 / H-02), which
\* models one manager's vote bookkeeping; this module models the multi-node
\* protocol built on it in Stage 1a/1c.
\*
\* Rust counterpart, action by action (the conformance test
\* core/consensus/tests/finality_tla_conformance.rs checks these names and the
\* constants below against the code):
\*
\*   Propose      FinalityGadget::on_buried_checkpoint -> CheckpointManager::ensure_proposed
\*                (node/src/finality_driver.rs reports the canonical block at H)
\*   SignVote     FinalityGadget::sign_own_vote: durable signed-vote record
\*                (one hash per height per key, across restarts) + safety-stop gate
\*   Finalize     CheckpointManager::submit_vote / finalize_checkpoint (derived quorum,
\*                committee >= MIN_FINALITY_COMMITTEE). With SyncFloor, the same step
\*                runs the node's FinalizationGuard (FloorVerifier::on_finalize) before
\*                the finalization is visible: raise the floor if the certified block
\*                is canonical here, else engage the safety stop; either way register
\*                the certificate (CanonicalApplicator::register_certified)
\*   VerifyFloor  node/src/finality_floor.rs FloorVerifier::tick (Enforced): raise the
\*                floor only if the certified block is canonical here, else safety stop;
\*                a mismatch stop clears once the certified block is canonical again
\*   Reorg        node/src/canonical_apply.rs reorg_to: Rejected when the fork point is
\*                below the floor (I4); the floor is first raised to a registered
\*                certificate whose block is canonical (effective_floor)
\*   Restart      process restart: pending checkpoints, the floor (an in-memory atomic),
\*                the registered certificates and the verifier state are lost; certificates
\*                and the signed-vote record persist; FloorVerifier::boot_check runs before
\*                any block is admitted (Reorg is disabled while booting). The boot check
\*                (VerifyFloor while booting) consults the stored certificates highest
\*                first (FloorVerifier::restore_certified_floor), raises the floor to the
\*                highest whose block is canonical here and registers every one above it.
\*                The code consults ALL of them (BootRegLimit >= Cardinality(Heights));
\*                a smaller BootRegLimit models a truncated boot registration
\*
\* Votes are modeled as a global set of sent votes. Delivery order and loss do
\* not matter for safety (a node can only count votes that were sent), so
\* Finalize may count any sent vote; Byzantine voters are assumed to have sent
\* every possible vote.
\*
\* Committees are PER CANDIDATE: FinalityGadget::committee_for seeds
\* CommitteeSelector::select with the candidate block's own VRF output, so
\* sibling candidates at one height can get different committees once the
\* validator set is larger than committee_size. `comm[<<h, x>>]` is that
\* committee, chosen arbitrarily (any CommitteeSize-subset of Voters) at Init
\* and fixed thereafter; only its members' votes count toward the candidate's
\* quorum, and an honest node signs only as a member. With CommitteeSize =
\* Cardinality(Voters) every candidate has the same committee (the full set).
\*
\* Configs:
\*   CheckpointFinalitySafety.cfg         f = 1 of 4 voters, committee = all 4: every
\*                                        invariant holds (gating).
\*   CheckpointFinalitySafety_byz2.cfg    f = 2 of 4 (>= 1/3): TLC MUST find an S1
\*                                        violation (the model has teeth).
\*   CheckpointFinalitySafety_norecord.cfg no durable signed-vote record: TLC MUST find an
\*                                        equivocation and an S1 violation.
\*   CheckpointFinalitySafety_strict.cfg  §5 S2 as written ("committed state is never
\*                                        reverted below latest_finalized_height()"):
\*                                        FinalizedNeverReverted + FinalizedStaysCanonical,
\*                                        with the floor raised at finalization
\*                                        (SyncFloor). Must hold.
\*   CheckpointFinalitySafety_pollonly.cfg the same check with SyncFloor = FALSE (the floor
\*                                        follows only the verifier's poll, the Stage 2
\*                                        design): TLC MUST find Finalize -> Reorg below
\*                                        the new certificate -> VerifyFloor halts.
\*   CheckpointFinalitySafety_restart.cfg one node, three Byzantine voters, two heights:
\*                                        S2 across restarts with the boot check consulting
\*                                        every stored certificate (BootRegLimit = 2). Must
\*                                        hold.
\*   CheckpointFinalitySafety_bootlimit.cfg the same with BootRegLimit = 1 (only the latest
\*                                        stored certificate consulted at boot — the bounded
\*                                        registration reviewed on #335 @ 5236d2b): TLC MUST
\*                                        find Restart -> boot -> Reorg reverting an older
\*                                        finalized, canonical block.
\*   CheckpointFinalitySafety_committees.cfg 5 voters (f = 1), committees of 4 per
\*                                        candidate: TLC MUST find an S1 violation with no
\*                                        honest equivocation — two siblings finalized by
\*                                        different committees (open finding, review of
\*                                        #333 @ 0286eff; see the spec doc §8).

CONSTANTS
    Nodes,          \* honest nodes; each is also a committee voter with its own chain
    Byz,            \* Byzantine committee voters (no chain of their own)
    Heights,        \* checkpoint heights, e.g. 1..2
    Hashes,         \* candidate blocks per height (siblings), e.g. {a, b}
    None,           \* "no block / no value"
    DurableRecord,  \* TRUE: the Stage 1a signed-vote record is in force
    CommitteeSize,  \* committee size per candidate (config.committee_size)
    SyncFloor,      \* TRUE: the floor is raised / finality halted AT finalization
                    \* (FinalizationGuard); FALSE: only by the verifier's poll
    BootRegLimit    \* how many stored certificates (highest first) the boot check
                    \* consults; the code consults all (>= Cardinality(Heights))

Voters == Nodes \cup Byz

\* Rust: checkpoint::MIN_FINALITY_COMMITTEE
MinCommittee == 4

\* Rust: checkpoint::derived_quorum(n) = floor(2n/3) + 1
Quorum == (2 * CommitteeSize) \div 3 + 1

ASSUME Nodes \cap Byz = {}
ASSUME Cardinality(Voters) >= MinCommittee
ASSUME CommitteeSize \in MinCommittee..Cardinality(Voters)
ASSUME Heights \subseteq Nat /\ 0 \notin Heights
ASSUME None \notin Hashes
ASSUME DurableRecord \in BOOLEAN
ASSUME SyncFloor \in BOOLEAN
ASSUME BootRegLimit \in Nat \ {0}

VARIABLES
    canon,      \* canon[n][h]: the block at height h on node n's applied chain
    sent,       \* set of honest votes <<voter, height, hash>> ever signed and sent
    pending,    \* pending[n][h]: the hash node n is collecting votes for at h, or None
    fin,        \* fin[n][h]: the hash node n finalized at h (persisted certificate), or None
    floor,      \* floor[n]: node n's reorg floor (0 = none)
    halted,     \* halted[n]: node n's finality safety stop is engaged
    booting,    \* booting[n]: restarted, boot check not run yet
    comm,       \* comm[<<h, x>>]: the committee of candidate x at h (fixed at Init)
    reg         \* reg[n]: heights of the certificates registered with node n's
                \* applicator (CanonicalApplicator::register_certified)

vars == <<canon, sent, pending, fin, floor, halted, booting, comm, reg>>

\* Every committee the selector could return.
Committees == {S \in SUBSET Voters : Cardinality(S) = CommitteeSize}

Committee(h, x) == comm[<<h, x>>]

ByzVotes == Byz \X Heights \X Hashes
AllVotes == sent \cup ByzVotes

\* Highest height node n holds a certificate for (0 = none).
LatestFin(n) ==
    LET hs == {h \in Heights : fin[n][h] # None}
    IN IF hs = {} THEN 0 ELSE CHOOSE m \in hs : \A k \in hs : k <= m

\* Votes that count toward candidate x at h: from its committee only.
Supporters(h, x) == {v \in Committee(h, x) : <<v, h, x>> \in AllVotes}

Max(a, b) == IF a > b THEN a ELSE b

\* The floor a reorg is judged against (CanonicalApplicator::effective_floor):
\* the raised floor, or the highest registered certificate whose block is
\* canonical here.
EffFloor(n) ==
    LET hs == {h \in reg[n] : fin[n][h] # None /\ canon[n][h] = fin[n][h]}
             \cup {floor[n]}
    IN CHOOSE m \in hs : \A k \in hs : k <= m

\* Heights node n holds a stored certificate for.
Stored(n) == {k \in Heights : fin[n][k] # None}

\* The stored certificates the boot check consults: the BootRegLimit highest.
BootConsulted(n) ==
    {k \in Stored(n) : Cardinality({j \in Stored(n) : j > k}) < BootRegLimit}

\* The floor the boot check restores (FloorVerifier::restore_certified_floor):
\* the highest consulted certificate whose block is canonical here, else 0.
BootFloor(n) ==
    LET hs == {k \in BootConsulted(n) : canon[n][k] = fin[n][k]} \cup {0}
    IN CHOOSE m \in hs : \A k \in hs : k <= m

\* ---- Init ----

Init ==
    /\ canon \in [Nodes -> [Heights -> Hashes]]
    /\ sent = {}
    /\ pending = [n \in Nodes |-> [h \in Heights |-> None]]
    /\ fin = [n \in Nodes |-> [h \in Heights |-> None]]
    /\ floor = [n \in Nodes |-> 0]
    /\ halted = [n \in Nodes |-> FALSE]
    /\ booting = [n \in Nodes |-> FALSE]
    /\ comm \in [Heights \X Hashes -> Committees]
    /\ reg = [n \in Nodes |-> {}]

\* ---- Actions ----

\* The canonical block at h is buried; propose it (idempotent, never re-opens a
\* finalized height, never replaces a different pending hash).
Propose(n, h) ==
    /\ ~halted[n]
    /\ ~booting[n]
    /\ h > LatestFin(n)
    /\ fin[n][h] = None
    /\ pending[n][h] = None
    /\ pending' = [pending EXCEPT ![n][h] = canon[n][h]]
    /\ UNCHANGED <<canon, sent, fin, floor, halted, booting, reg>>

\* Sign this node's own vote for its pending hash. With the durable record, a
\* key that already signed a different hash at h refuses (SignRefusal::Conflicting).
SignVote(n, h) ==
    LET x == pending[n][h] IN
    /\ ~halted[n]
    /\ ~booting[n]
    /\ x # None
    /\ n \in Committee(h, x)
    /\ <<n, h, x>> \notin sent
    /\ DurableRecord => \A y \in Hashes : <<n, h, y>> \in sent => y = x
    /\ sent' = sent \cup {<<n, h, x>>}
    /\ UNCHANGED <<canon, pending, fin, floor, halted, booting, reg>>

\* Quorum of votes for the pending hash: finalize and persist the certificate.
\* SyncFloor: in the same step (the guard runs before the finalization is
\* visible) the floor is raised if the certified block is canonical here, else
\* the safety stop is engaged; the certificate is registered either way.
\* (The pending hash was canonical when proposed; a Reorg since may have
\* replaced it, which is the mismatch case.)
Finalize(n, h) ==
    LET x == pending[n][h] IN
    /\ x # None
    /\ Cardinality(Supporters(h, x)) >= Quorum
    /\ fin' = [fin EXCEPT ![n][h] = x]
    /\ pending' = [pending EXCEPT ![n][h] = None]
    /\ IF SyncFloor
       THEN /\ reg' = [reg EXCEPT ![n] = @ \cup {h}]
            /\ IF canon[n][h] = x
               THEN /\ floor' = [floor EXCEPT ![n] = Max(@, h)]
                    /\ UNCHANGED halted
               ELSE /\ halted' = [halted EXCEPT ![n] = TRUE]
                    /\ UNCHANGED floor
       ELSE UNCHANGED <<floor, halted, reg>>
    /\ UNCHANGED <<canon, sent, booting>>

\* Floor verifier pass (Enforced mode) on the latest certificate. While
\* booting (SyncFloor), the boot check also restores the floor from the older
\* stored certificates and registers them (FloorVerifier::boot_check).
VerifyFloor(n) ==
    LET h == LatestFin(n)
        ok == canon[n][h] = fin[n][h]
        fromLatest == IF ok THEN Max(floor[n], h) ELSE floor[n]
        fromBoot == IF booting[n] /\ SyncFloor THEN BootFloor(n) ELSE 0
    IN
    /\ h > 0
    /\ floor' = [floor EXCEPT ![n] = Max(fromLatest, fromBoot)]
    /\ halted' = [halted EXCEPT ![n] = ~ok]
    /\ reg' = IF SyncFloor
              THEN [reg EXCEPT ![n] = @ \cup {h}
                       \cup (IF booting[n] THEN BootConsulted(n) ELSE {})]
              ELSE reg
    /\ booting' = [booting EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<canon, sent, pending, fin>>

\* Boot with nothing finalized: the boot check finds no certificate.
BootNoCertificate(n) ==
    /\ booting[n]
    /\ LatestFin(n) = 0
    /\ booting' = [booting EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<canon, sent, pending, fin, floor, halted, reg>>

\* Fork choice moves node n to a branch that keeps every block below h0 and may
\* replace the blocks from h0 up. The fork point (h0 - 1) must not be below the
\* floor (reorg_to: "fork point height below finalized height" -> Rejected),
\* judged after raising it to a registered certificate whose block is canonical.
Reorg(n, h0, c) ==
    /\ ~booting[n]
    /\ h0 \in Heights
    /\ h0 - 1 >= EffFloor(n)
    /\ \A h \in Heights : h < h0 => c[h] = canon[n][h]
    /\ c # canon[n]
    /\ canon' = [canon EXCEPT ![n] = c]
    /\ floor' = [floor EXCEPT ![n] = EffFloor(n)]
    /\ UNCHANGED <<sent, pending, fin, halted, booting, reg>>

\* Process restart: memory is lost, persisted records are kept.
Restart(n) ==
    /\ pending' = [pending EXCEPT ![n] = [h \in Heights |-> None]]
    /\ floor' = [floor EXCEPT ![n] = 0]
    /\ halted' = [halted EXCEPT ![n] = FALSE]
    /\ booting' = [booting EXCEPT ![n] = TRUE]
    /\ reg' = [reg EXCEPT ![n] = {}]
    /\ UNCHANGED <<canon, sent, fin>>

\* The committees never change (comm is fixed at Init).
Next ==
    /\ UNCHANGED comm
    /\ \E n \in Nodes :
        \/ \E h \in Heights : Propose(n, h) \/ SignVote(n, h) \/ Finalize(n, h)
        \/ VerifyFloor(n)
        \/ BootNoCertificate(n)
        \/ \E h0 \in Heights, c \in [Heights -> Hashes] : Reorg(n, h0, c)
        \/ Restart(n)

Spec == Init /\ [][Next]_vars

\* Honest nodes are interchangeable (TLC symmetry reduction).
NodeSymmetry == Permutations(Nodes)

\* ---- Invariants ----

TypeOK ==
    /\ canon \in [Nodes -> [Heights -> Hashes]]
    /\ sent \subseteq (Nodes \X Heights \X Hashes)
    /\ pending \in [Nodes -> [Heights -> Hashes \cup {None}]]
    /\ fin \in [Nodes -> [Heights -> Hashes \cup {None}]]
    /\ floor \in [Nodes -> Heights \cup {0}]
    /\ halted \in [Nodes -> BOOLEAN]
    /\ booting \in [Nodes -> BOOLEAN]
    /\ comm \in [Heights \X Hashes -> Committees]
    /\ reg \in [Nodes -> SUBSET Heights]

\* S1: no two nodes finalize different blocks at one height.
NoConflictingFinality ==
    \A n1, n2 \in Nodes, h \in Heights :
        (fin[n1][h] # None /\ fin[n2][h] # None) => fin[n1][h] = fin[n2][h]

\* An honest key never signs two hashes at one height (durable record).
HonestNoEquivocation ==
    \A v \in Nodes, h \in Heights, x, y \in Hashes :
        (<<v, h, x>> \in sent /\ <<v, h, y>> \in sent) => x = y

\* S2: the floor protects exactly the finalized block, and that block is still
\* canonical on the node (a reorg never changes a block at or below the floor).
FloorBlockIsFinalized ==
    \A n \in Nodes :
        floor[n] > 0 => /\ fin[n][floor[n]] # None
                        /\ canon[n][floor[n]] = fin[n][floor[n]]

\* Every finalized block had a quorum of signed votes.
FinalizedHasQuorum ==
    \A n \in Nodes, h \in Heights :
        fin[n][h] # None => Cardinality(Supporters(h, fin[n][h])) >= Quorum

\* A halted node signs nothing (checked as an action property below).
HaltedSignsNothing ==
    [][\A n \in Nodes : halted[n] =>
          \A h \in Heights, x \in Hashes :
              (<<n, h, x>> \in sent') => (<<n, h, x>> \in sent)]_vars

\* The floor only moves up, except on a restart (it is re-raised by the boot
\* check before any block is admitted).
FloorMonotone ==
    [][\A n \in Nodes : floor'[n] >= floor[n] \/ booting'[n]]_vars

\* §5 S2 as written: a finalized block that is on a node's chain is never
\* reverted there (checked by the _strict config; violated with SyncFloor =
\* FALSE, the poll-only design — the _pollonly config).
FinalizedNeverReverted ==
    [][\A n \in Nodes, h \in Heights :
          (fin[n][h] # None /\ canon[n][h] = fin[n][h]) => canon'[n][h] = fin[n][h]]_vars

\* A node holding a certificate for a block that is not on its chain is in the
\* safety stop (proposes and signs nothing), or restarting before its boot
\* check. A certificate can finalize a block this node had already reorged
\* away from before the votes arrived; that is not a revert, and the node must
\* then be halted at once, not at the next poll.
FinalizedStaysCanonical ==
    \A n \in Nodes, h \in Heights :
        fin[n][h] # None => canon[n][h] = fin[n][h] \/ halted[n] \/ booting[n]

=============================================================================
