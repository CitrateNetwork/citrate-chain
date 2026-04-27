--------------------- MODULE PrecompileDispatchInjective ---------------------
EXTENDS Naturals, FiniteSets, TLC

\* RM-M2 WP-M2.2 — precompile dispatch table is injective.
\*
\* Source: core/execution/src/precompiles/{compute,verify,inference}.rs
\* dispatch and core/execution/src/precompiles/mod.rs::execute.
\*
\* Statement:
\*   The mapping `address -> op` is injective. Every Citrate AI
\*   precompile address (0x0100..0x010F) maps to AT MOST one op
\*   semantics. Once allocated, an address never gets reused for
\*   a different op — old contracts continue to invoke the same
\*   precompile they were written against.
\*
\* This is the parallel of `Halo2VerifierVersionMonotonic.tla`
\* but for the COMPILE-TIME address allocation instead of the
\* runtime VK registry.
\*
\* Domain:
\*   Addresses    = 0x0100..0x010F (model as 0..15)
\*   Ops          = the named operations RM-M2 ships
\*
\* Action: allocate(address, op). Only succeeds if address is
\* currently unmapped. Once mapped, never remaps.

CONSTANTS
    Addresses,          \* e.g. {0..15} for the AI address-space lower 5 bits
    Ops                 \* names: {Inference, BatchInference, ..., Matmul, Dot, ...}

ASSUME Addresses # {} /\ Ops # {}

VARIABLES
    allocation,         \* Function: Addresses -> Ops \cup {"unallocated"}
    history             \* Same shape — one-shot recorder; once set, never changes.

vars == <<allocation, history>>

\* ---- Helpers ----

IsAllocated(a) == allocation[a] # "unallocated"

\* ---- State machine ----

Init ==
    /\ allocation = [a \in Addresses |-> "unallocated"]
    /\ history    = [a \in Addresses |-> "unallocated"]

\* Allocate an address to an op. Mirrors the compile-time
\* guarantee: each `pub const ADDR: [u8; 20] = [...]` constant
\* in addresses::* maps to exactly one dispatcher arm — AND each
\* op has its own dedicated address (no double-allocation).
Allocate(a, op) ==
    /\ a \in Addresses
    /\ op \in Ops
    /\ ~IsAllocated(a)
    /\ \A other \in Addresses :
         IsAllocated(other) => allocation[other] # op
    /\ allocation' = [allocation EXCEPT ![a] = op]
    /\ history'    = [history    EXCEPT ![a] = op]

\* Stutter to keep behavior trivially fair under TLC.
Stutter == UNCHANGED vars

Next ==
    \/ \E a \in Addresses, op \in Ops : Allocate(a, op)
    \/ Stutter

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----

\* Type invariant.
TypeOK ==
    /\ allocation \in [Addresses -> Ops \cup {"unallocated"}]
    /\ history    \in [Addresses -> Ops \cup {"unallocated"}]

\* Injective: distinct addresses map to distinct ops.
\* (Two addresses may share the SAME op only if both are
\* "unallocated"; once allocated, ops must differ.)
DispatchInjective ==
    \A a, b \in Addresses :
        (a # b /\ IsAllocated(a) /\ IsAllocated(b))
            => allocation[a] # allocation[b]

\* Once allocated, never reassigned: history pin matches current.
AllocationImmutable ==
    \A a \in Addresses :
        IsAllocated(a) => allocation[a] = history[a]

\* If history was set, allocation must still match it (no resets).
HistoryNeverDropped ==
    \A a \in Addresses :
        history[a] # "unallocated" => allocation[a] = history[a]

\* The full safety invariant.
SafetyInvariant ==
    /\ TypeOK
    /\ DispatchInjective
    /\ AllocationImmutable
    /\ HistoryNeverDropped

============================================================================
