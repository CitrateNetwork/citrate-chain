------------------------- MODULE AgentPrecompileFork -------------------------
(***************************************************************************)
(* HUP-S7.2 (federation F-2 / F-3): the agent precompile fork.            *)
(*                                                                         *)
(* Code: core/execution/src/agent_fork.rs (resolution + store),            *)
(*       core/execution/src/revm_adapter.rs (register_citrate_precompiles). *)
(* Spec: docs/precompiles/AGENT_PRECOMPILES.md                              *)
(*                                                                         *)
(* WHAT IS MODELLED                                                         *)
(*   1. Start-up resolution. Each node of one chain picks a local value     *)
(*      (none / off / a height) from its env or config. `Resolve` turns the *)
(*      release pin plus that value into a running height, or a refusal to *)
(*      start (agent_fork::resolve).                                        *)
(*   2. Execution. Every started node executes heights 0..MaxHeight and, at *)
(*      each height, registers a precompile SET with REVM: the pure set,     *)
(*      the reserved set once the PBA height is active (minus the fork      *)
(*      addresses once the fork is active), and the fork addresses once the *)
(*      fork is active (register_citrate_precompiles).                      *)
(*                                                                         *)
(* PROPERTIES                                                               *)
(*   AgreeOnSet       every two started nodes register the same set at      *)
(*                    every height (no fork between honest nodes).          *)
(*   LegacyBelow      below the fork height, or with the fork unset, the     *)
(*                    registered set is exactly the pre-fork set.           *)
(*   GenesisUntouched height 0 never has the fork active.                   *)
(*   ForkAddrsLive    at and after the fork, every fork address is          *)
(*                    registered as live and none as reserved.              *)
(*                                                                         *)
(* MUTATION (AgentPrecompileFork_buggy.cfg): RefuseUnpinned = FALSE lets a  *)
(* release-network node schedule the fork from its own env/config while the *)
(* release pins nothing. TLC must find an AgreeOnSet counterexample.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,          \* nodes of one release network
    MaxHeight,      \* heights 0..MaxHeight are executed
    PbaHeight,      \* the PBA hardening height (pinned for the network)
    Pin,            \* the release pin for the fork: a height, or NoPin
    NoPin,          \* model value: the release pins no fork height
    None, Off,      \* model values: no local value / explicit `off`
    Refuse,         \* model value: the node refuses to start
    LocalChoices,   \* heights a node operator might configure
    RefuseUnpinned  \* TRUE = the shipped rule; FALSE = the mutation

ASSUME Pin \in (0..MaxHeight) \cup {NoPin}
ASSUME LocalChoices \subseteq 0..MaxHeight

\* Address classes (abstract): pure bridged, unassigned reserved, fork.
Pure     == {"p0110", "p010D"}
Unassign == {"r0114", "r0104"}
Fork     == {"f0112", "f0113", "f0121", "f0122"}
\* Pre-fork, the fork addresses are reserved like any unassigned slot.
Reserved == Unassign \cup Fork

LocalValues == {None, Off} \cup LocalChoices

\* agent_fork::resolve on a release network. Result: a height, None (not
\* activated) or Refuse.
Resolve(local) ==
    IF Pin # NoPin
    THEN IF local \in {None} \/ local = Pin THEN Pin ELSE Refuse
    ELSE IF local \in {None, Off} THEN None
         ELSE IF RefuseUnpinned THEN Refuse ELSE local

ActiveAt(act, h) == act \notin {None, Refuse} /\ h > 0 /\ h >= act
PbaActive(h) == h > 0 /\ h >= PbaHeight

\* register_citrate_precompiles: (live, reserved) sets at height h.
Registered(act, h) ==
    LET agent == ActiveAt(act, h)
        live  == Pure \cup (IF agent THEN Fork ELSE {})
        res   == IF PbaActive(h)
                 THEN IF agent THEN Reserved \ Fork ELSE Reserved
                 ELSE {}
    IN  [live |-> live, reserved |-> res]

LegacyRegistered(h) ==
    [live |-> Pure, reserved |-> IF PbaActive(h) THEN Reserved ELSE {}]

VARIABLES local, act, started, height

vars == <<local, act, started, height>>

Init ==
    /\ local \in [Nodes -> LocalValues]
    /\ act = [n \in Nodes |-> None]
    /\ started = {}
    /\ height = 0

Start(n) ==
    /\ n \notin started
    /\ Resolve(local[n]) # Refuse
    /\ act' = [act EXCEPT ![n] = Resolve(local[n])]
    /\ started' = started \cup {n}
    /\ UNCHANGED <<local, height>>

Advance ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<local, act, started>>

\* The chain has reached MaxHeight: the run is over (an explicit stutter, so a
\* finished run is not reported as a deadlock).
Done ==
    /\ height = MaxHeight
    /\ UNCHANGED vars

Next == (\E n \in Nodes : Start(n)) \/ Advance \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ local \in [Nodes -> LocalValues]
    /\ started \subseteq Nodes
    /\ height \in 0..MaxHeight

AgreeOnSet ==
    \A n, m \in started : \A h \in 0..height :
        Registered(act[n], h) = Registered(act[m], h)

LegacyBelow ==
    \A n \in started : \A h \in 0..height :
        ~ActiveAt(act[n], h) => Registered(act[n], h) = LegacyRegistered(h)

GenesisUntouched == \A n \in started : ~ActiveAt(act[n], 0)

ForkAddrsLive ==
    \A n \in started : \A h \in 0..height :
        ActiveAt(act[n], h) =>
            /\ Fork \subseteq Registered(act[n], h).live
            /\ Fork \cap Registered(act[n], h).reserved = {}

\* Static: the pure set and the fork set never overlap.
Disjoint == Pure \cap Fork = {}
=============================================================================
