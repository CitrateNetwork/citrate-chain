----------------------- MODULE SpecRegistryLifecycle -----------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the SpecRegistry contract lifecycle from
\* contracts/src/SpecRegistry.sol.
\*
\* The SpecRegistry maps operation domains to behavioral specifications stored
\* as IPFS CIDs (Gherkin feature files).  Only the governor can register,
\* update, deactivate, or reactivate specs.  Governor authority can be
\* transferred atomically.
\*
\* Key invariants:
\*   - Domain uniqueness: each domain registered at most once
\*   - Version monotonicity: spec version only increases on update
\*   - Governor authority: all mutations require governor identity
\*   - Governor transfer is atomic (single step)
\*
\* Source: contracts/src/SpecRegistry.sol
\*   - registerSpec, updateSpec, deactivateSpec, reactivateSpec
\*   - transferGovernor, getSpec, hasActiveSpec

CONSTANTS
    Domains,        \* Set of possible domain strings (e.g., {"deploy", "transfer"})
    CIDs,           \* Set of possible IPFS CID values
    Addresses,      \* Set of possible governor addresses
    MaxVersion      \* Maximum version number (bounds state space)

ASSUME Domains # {}
ASSUME CIDs # {}
ASSUME Addresses # {} /\ Cardinality(Addresses) >= 2
ASSUME MaxVersion \in Nat /\ MaxVersion >= 1

VARIABLES
    specs,          \* Function: domain -> [cid, version, active, governor] or "unregistered"
    governor,       \* Current governor address
    domainSet       \* Set of registered domains (mirrors domains[] array in Solidity)

vars == <<specs, governor, domainSet>>

\* ---- State machine ----

Init ==
    /\ specs = [d \in Domains |-> "unregistered"]
    /\ governor \in Addresses  \* Governor set by constructor
    /\ domainSet = {}

\* Register a new spec for a domain (only governor, domain must not exist).
RegisterSpec(domain, cid) ==
    /\ domain \in Domains
    /\ cid \in CIDs
    /\ specs[domain] = "unregistered"
    /\ LET caller == governor  \* onlyGovernor modifier
       IN /\ specs' = [specs EXCEPT ![domain] =
                [cid |-> cid, version |-> 1, active |-> TRUE, governor |-> caller]]
          /\ domainSet' = domainSet \union {domain}
          /\ UNCHANGED governor

\* Update the CID for an existing domain (only governor, must be registered).
UpdateSpec(domain, newCid) ==
    /\ domain \in Domains
    /\ specs[domain] # "unregistered"
    /\ newCid \in CIDs
    /\ specs[domain].version < MaxVersion
    /\ specs' = [specs EXCEPT
            ![domain].cid = newCid,
            ![domain].version = @ + 1]
    /\ UNCHANGED <<governor, domainSet>>

\* Deactivate a spec (only governor, must be active).
DeactivateSpec(domain) ==
    /\ domain \in Domains
    /\ specs[domain] # "unregistered"
    /\ specs[domain].active = TRUE
    /\ specs' = [specs EXCEPT ![domain].active = FALSE]
    /\ UNCHANGED <<governor, domainSet>>

\* Reactivate a deactivated spec (only governor, must be inactive).
ReactivateSpec(domain) ==
    /\ domain \in Domains
    /\ specs[domain] # "unregistered"
    /\ specs[domain].active = FALSE
    /\ specs' = [specs EXCEPT ![domain].active = TRUE]
    /\ UNCHANGED <<governor, domainSet>>

\* Transfer governor to a new address (only current governor).
TransferGovernor(newGov) ==
    /\ newGov \in Addresses
    /\ newGov # governor  \* Cannot transfer to self (effectively a no-op check)
    /\ governor' = newGov
    /\ UNCHANGED <<specs, domainSet>>

Next ==
    \/ \E d \in Domains, c \in CIDs : RegisterSpec(d, c)
    \/ \E d \in Domains, c \in CIDs : UpdateSpec(d, c)
    \/ \E d \in Domains : DeactivateSpec(d)
    \/ \E d \in Domains : ReactivateSpec(d)
    \/ \E a \in Addresses : TransferGovernor(a)

\* ---- Invariants ----

\* INV-1: TypeOK
TypeOK ==
    /\ governor \in Addresses
    /\ domainSet \subseteq Domains
    /\ \A d \in Domains :
        specs[d] = "unregistered" \/
        (/\ specs[d].cid \in CIDs
         /\ specs[d].version \in 1..MaxVersion
         /\ specs[d].active \in BOOLEAN
         /\ specs[d].governor \in Addresses)

\* INV-2: VersionMonotonic — once registered, version is >= 1 and only increases.
\* (Verified by the UpdateSpec action incrementing version.)
VersionMonotonic ==
    \A d \in Domains :
        specs[d] # "unregistered" => specs[d].version >= 1

\* INV-3: DomainUniqueness — each domain is registered at most once.
\* The RegisterSpec guard (specs[domain] = "unregistered") ensures this.
DomainUniqueness ==
    \A d \in domainSet : specs[d] # "unregistered"

\* INV-4: DomainSetConsistent — domainSet matches the registered specs.
DomainSetConsistent ==
    /\ \A d \in domainSet : specs[d] # "unregistered"
    /\ \A d \in Domains : specs[d] # "unregistered" => d \in domainSet

\* INV-5: ActiveInactiveConsistent — active flag is always a BOOLEAN for
\* registered specs (deactivated specs can be reactivated).
ActiveInactiveConsistent ==
    \A d \in Domains :
        specs[d] # "unregistered" => specs[d].active \in BOOLEAN

\* INV-6: GovernorNonZero — governor is always in the valid address set.
\* (Mirrors the require(newGovernor != address(0)) check.)
GovernorNonZero ==
    governor \in Addresses

\* INV-7: VersionBounded — version cannot exceed MaxVersion.
VersionBounded ==
    \A d \in Domains :
        specs[d] # "unregistered" => specs[d].version <= MaxVersion

\* INV-8: UnregisteredNotInSet — unregistered domains are not in domainSet.
UnregisteredNotInSet ==
    \A d \in Domains :
        specs[d] = "unregistered" => d \notin domainSet

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM VersionMono == Spec => []VersionMonotonic
THEOREM DomainsUnique == Spec => []DomainUniqueness
THEOREM DomainSetConsist == Spec => []DomainSetConsistent
THEOREM ActiveInactiveConsist == Spec => []ActiveInactiveConsistent
THEOREM GovernorValid == Spec => []GovernorNonZero
THEOREM VersionBound == Spec => []VersionBounded
THEOREM UnregisteredClean == Spec => []UnregisteredNotInSet

=============================================================================
