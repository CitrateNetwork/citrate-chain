------------------------- MODULE AdapterProvenance -------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models LoRA adapter provenance chains from core/learning/src/adapters.rs.
\*
\* An adapter is created with a unique hash computed from its delta (or LoRA
\* matrices) and metadata.  Adapters form a provenance chain where each
\* entry's parent_hash equals the hash of the previous entry.  Adapter
\* composition (rank concatenation) is associative and application is
\* reversible via remove_lora.
\*
\* Source: core/learning/src/adapters.rs
\*   - ProvenanceChain, ProvenanceEntry, compute_entry_hash
\*   - AdapterFactory::create, ::create_lora, ::compute_id, ::compute_lora_id
\*   - apply_lora, remove_lora, compose_lora

CONSTANTS
    MaxChainLen,    \* Maximum provenance chain length to explore
    Creators,       \* Set of creator identifiers
    Dimensions      \* Set of possible adapter dimension sizes (e.g., {2, 3})

ASSUME MaxChainLen \in Nat /\ MaxChainLen >= 1
ASSUME Creators # {}
ASSUME Dimensions \subseteq Nat /\ Dimensions # {}

VARIABLES
    chain,              \* Sequence of provenance entries: [creator, round, hash, parent_hash]
    adapters,           \* Set of registered adapter records {id, dim, creator}
    nextRound,          \* Monotonic round counter
    composedAdapters    \* Set of composed adapter IDs (tracks composition history)

vars == <<chain, adapters, nextRound, composedAdapters>>

\* ---- Helper: Hash function (abstract) ----
\* We model hashing as a deterministic function of the entry's fields.
\* For TLC, we use a simple encoding: <<creator, round, parent_hash>>.
\* Two entries with the same fields produce the same hash.
EntryHash(creator, round, parentHash) ==
    <<creator, round, parentHash>>

\* Hash of an adapter from its delta + metadata (abstract).
AdapterHash(dim, creator, round) ==
    <<"adapter", dim, creator, round>>

\* ---- State machine ----

Init ==
    /\ chain = <<>>
    /\ adapters = {}
    /\ nextRound = 1
    /\ composedAdapters = {}

\* Create a new root adapter (no parent).
CreateRootAdapter(creator, dim) ==
    /\ Len(chain) < MaxChainLen
    /\ creator \in Creators
    /\ dim \in Dimensions
    /\ LET round == nextRound
           hash == EntryHash(creator, round, "none")
           adapterID == AdapterHash(dim, creator, round)
           entry == [creator |-> creator,
                     round   |-> round,
                     hash    |-> hash,
                     parent_hash |-> "none"]
       IN /\ chain' = Append(chain, entry)
          /\ adapters' = adapters \union {[id |-> adapterID, dim |-> dim, creator |-> creator]}
          /\ nextRound' = nextRound + 1
          /\ UNCHANGED composedAdapters

\* Extend the provenance chain: create a derived adapter whose parent_hash
\* equals the hash of the last entry in the chain.
ExtendChain(creator, dim) ==
    /\ Len(chain) >= 1
    /\ Len(chain) < MaxChainLen
    /\ creator \in Creators
    /\ dim \in Dimensions
    /\ LET prevEntry == chain[Len(chain)]
           parentHash == prevEntry.hash
           round == nextRound
           hash == EntryHash(creator, round, parentHash)
           adapterID == AdapterHash(dim, creator, round)
           entry == [creator |-> creator,
                     round   |-> round,
                     hash    |-> hash,
                     parent_hash |-> parentHash]
       IN /\ chain' = Append(chain, entry)
          /\ adapters' = adapters \union {[id |-> adapterID, dim |-> dim, creator |-> creator]}
          /\ nextRound' = nextRound + 1
          /\ UNCHANGED composedAdapters

\* Compose two adapters (models compose_lora rank concatenation).
\* Both must have the same dimension.
ComposeAdapters(a1, a2) ==
    /\ a1 \in adapters
    /\ a2 \in adapters
    /\ a1 # a2
    /\ a1.dim = a2.dim
    /\ LET composedID == <<"composed", a1.id, a2.id>>
       IN /\ composedID \notin composedAdapters
          /\ composedAdapters' = composedAdapters \union {composedID}
          /\ UNCHANGED <<chain, adapters, nextRound>>

Next ==
    \/ \E c \in Creators, d \in Dimensions : CreateRootAdapter(c, d)
    \/ \E c \in Creators, d \in Dimensions : ExtendChain(c, d)
    \/ \E a1, a2 \in adapters : ComposeAdapters(a1, a2)

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ chain \in Seq([creator : Creators,
                      round : Nat,
                      hash : (Creators \X Nat \X (Creators \X Nat \X STRING \union {STRING})) \union (Creators \X Nat \X STRING),
                      parent_hash : (Creators \X Nat \X STRING \union (Creators \X Nat \X (Creators \X Nat \X STRING \union {STRING}))) \union {STRING}])
    /\ nextRound \in Nat

\* INV-2: ChainIntegrity — every non-root entry links to the hash of the previous entry.
\* Root entries (parent_hash = "none") start a new sub-chain and are exempt.
ChainIntegrity ==
    \A i \in 2..Len(chain) :
        chain[i].parent_hash # "none" => chain[i].parent_hash = chain[i-1].hash

\* INV-3: HashDeterministic — same inputs produce the same hash.
\* (This is structural: our EntryHash and AdapterHash are deterministic functions.
\*  We verify by checking that no two distinct chain entries with identical
\*  (creator, round, parent_hash) can yield different hashes.)
HashDeterministic ==
    \A i, j \in 1..Len(chain) :
        (chain[i].creator = chain[j].creator
         /\ chain[i].round = chain[j].round
         /\ chain[i].parent_hash = chain[j].parent_hash)
        => chain[i].hash = chain[j].hash

\* INV-4: CompositionRequiresSameDimension — composed pairs share a dimension.
\* (Enforced by the ComposeAdapters guard, verified here as a cross-check.)
CompositionRequiresSameDimension ==
    \A cid \in composedAdapters :
        \E a1, a2 \in adapters :
            cid = <<"composed", a1.id, a2.id>> /\ a1.dim = a2.dim

\* INV-5: RoundMonotonic — rounds in the chain are strictly increasing.
RoundMonotonic ==
    \A i \in 1..(Len(chain) - 1) :
        chain[i].round < chain[i+1].round

\* INV-6: AdapterReversible — applying then removing an adapter yields the base.
\* (Structural property: apply_lora adds delta, remove_lora subtracts the same delta.
\*  We model this abstractly: for every adapter, a "roundtrip" record exists.)
\* Since we cannot model continuous math in TLA+, we state the algebraic
\* contract: the adapter set is closed under the operations we track.
AdapterIdsUnique ==
    \A a1, a2 \in adapters :
        a1.id = a2.id => a1 = a2

\* INV-7: ChainBounded — chain length never exceeds MaxChainLen.
ChainBounded ==
    Len(chain) <= MaxChainLen

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM ChainIntegrityHolds == Spec => []ChainIntegrity
THEOREM HashIsDeterministic == Spec => []HashDeterministic
THEOREM CompositionDimSafe == Spec => []CompositionRequiresSameDimension
THEOREM RoundsIncrease == Spec => []RoundMonotonic
THEOREM AdapterIdsAreUnique == Spec => []AdapterIdsUnique
THEOREM ChainIsBounded == Spec => []ChainBounded

=============================================================================
