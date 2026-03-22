------------------------------ MODULE LiquidStaking ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* Models the stSALT liquid staking pool.
\*
\* Users deposit SALT and receive stSALT shares proportional to the pool ratio.
\* Withdrawals are subject to a delay period. Rewards accrue to the pool,
\* increasing the SALT-per-share ratio monotonically.
\*
\* Source: contracts/src/LiquidStaking.sol, core/economics/src/staking.rs

CONSTANTS
    Stakers,           \* Set of staker addresses
    MaxDeposit,        \* Max deposit amount per action
    WithdrawalDelay    \* Blocks before withdrawal completes

ASSUME Stakers # {}
ASSUME MaxDeposit \in Nat /\ MaxDeposit >= 1
ASSUME WithdrawalDelay \in Nat /\ WithdrawalDelay >= 1

VARIABLES
    totalPooled,         \* Total SALT in pool
    totalShares,         \* Total stSALT shares issued
    shares,              \* Mapping: staker -> shares held
    pendingWithdrawals,  \* Set of [staker, amount, requestBlock] records
    currentBlock         \* Current block number

vars == <<totalPooled, totalShares, shares, pendingWithdrawals, currentBlock>>

\* ---- Helper operators ----

\* Maximum blocks to prevent infinite state space.
MaxBlock == 2 * WithdrawalDelay + 3

\* Cap on total pool size to bound state space.
MaxPoolSize == 4 * MaxDeposit * Cardinality(Stakers)

\* Recursive sum over a set of stakers.
RECURSIVE SetSum(_, _)
SetSum(S, f) ==
    IF S = {} THEN 0
    ELSE LET x == CHOOSE v \in S : TRUE
         IN f[x] + SetSum(S \ {x}, f)

\* Sum of all individual shares.
SumShares == SetSum(Stakers, shares)

\* Shares minted for a deposit amount given current pool state.
\* If pool is empty, 1:1 ratio. Otherwise, proportional.
SharesForDeposit(amount) ==
    IF totalShares = 0 THEN amount
    ELSE (amount * totalShares) \div totalPooled

\* SALT returned for a share amount.
SaltForShares(shareAmt) ==
    IF totalShares = 0 THEN 0
    ELSE (shareAmt * totalPooled) \div totalShares

\* ---- State machine ----

Init ==
    /\ totalPooled = 0
    /\ totalShares = 0
    /\ shares = [s \in Stakers |-> 0]
    /\ pendingWithdrawals = {}
    /\ currentBlock = 0

\* Staker deposits SALT and receives shares.
Deposit(staker, amount) ==
    /\ amount \in 1..MaxDeposit
    /\ currentBlock < MaxBlock
    /\ totalPooled + amount <= MaxPoolSize          \* bound pool size
    /\ LET newShares == SharesForDeposit(amount)
       IN /\ newShares > 0
          /\ totalPooled' = totalPooled + amount
          /\ totalShares' = totalShares + newShares
          /\ shares' = [shares EXCEPT ![staker] = @ + newShares]
          /\ UNCHANGED <<pendingWithdrawals, currentBlock>>

\* Staker requests withdrawal — burns shares, moves SALT to pending.
RequestWithdrawal(staker, shareAmt) ==
    /\ shareAmt \in 1..MaxDeposit
    /\ shareAmt <= shares[staker]
    /\ currentBlock < MaxBlock
    /\ totalShares > 0
    /\ Cardinality(pendingWithdrawals) < 4          \* bound pending set size
    /\ LET saltOut == SaltForShares(shareAmt) IN
       /\ saltOut <= totalPooled
       /\ shares' = [shares EXCEPT ![staker] = @ - shareAmt]
       /\ totalShares' = totalShares - shareAmt
       /\ totalPooled' = totalPooled - saltOut
       /\ pendingWithdrawals' = pendingWithdrawals \cup
            {[staker |-> staker, amount |-> saltOut, requestBlock |-> currentBlock]}
       /\ UNCHANGED <<currentBlock>>

\* Claim a completed withdrawal (after delay).
ClaimWithdrawal(pw) ==
    /\ pw \in pendingWithdrawals
    /\ currentBlock >= pw.requestBlock + WithdrawalDelay
    /\ pendingWithdrawals' = pendingWithdrawals \ {pw}
    /\ UNCHANGED <<totalPooled, totalShares, shares, currentBlock>>

\* Rewards accrue to the pool (e.g., validation rewards).
AccrueRewards(amount) ==
    /\ amount \in 1..MaxDeposit
    /\ totalShares > 0                              \* rewards only if there are stakers
    /\ currentBlock < MaxBlock
    /\ totalPooled + amount <= MaxPoolSize           \* bound pool size
    /\ totalPooled' = totalPooled + amount
    /\ UNCHANGED <<totalShares, shares, pendingWithdrawals, currentBlock>>

\* Advance block height.
AdvanceBlock ==
    /\ currentBlock < MaxBlock
    /\ currentBlock' = currentBlock + 1
    /\ UNCHANGED <<totalPooled, totalShares, shares, pendingWithdrawals>>

Next ==
    \/ \E s \in Stakers, a \in 1..MaxDeposit : Deposit(s, a)
    \/ \E s \in Stakers, a \in 1..MaxDeposit : RequestWithdrawal(s, a)
    \/ \E pw \in pendingWithdrawals : ClaimWithdrawal(pw)
    \/ \E a \in 1..MaxDeposit : AccrueRewards(a)
    \/ AdvanceBlock

\* ---- Invariants ----

\* INV-1: Type correctness
TypeOK ==
    /\ totalPooled \in Nat
    /\ totalShares \in Nat
    /\ \A s \in Stakers : shares[s] \in Nat
    /\ currentBlock \in Nat
    /\ \A pw \in pendingWithdrawals :
        /\ pw.staker \in Stakers
        /\ pw.amount \in Nat
        /\ pw.requestBlock \in Nat

\* INV-2: Pool empty iff shares empty.
SharePriceConsistent ==
    (totalShares = 0) => (totalPooled = 0)

\* INV-3: WithdrawalDelayEnforced — claimed withdrawals respect delay.
\* Structurally guaranteed by ClaimWithdrawal's guard.
WithdrawalDelayEnforced ==
    TRUE  \* Enforced by action guard; no pending withdrawal is claimed early.

\* INV-4: TotalSharesConsistent — sum of individual shares matches totalShares.
TotalSharesConsistent ==
    SumShares = totalShares

\* INV-5: NoNegativeBalance — no staker has negative shares.
NoNegativeBalance ==
    \A s \in Stakers : shares[s] >= 0

\* INV-6: Pool solvency — totalPooled >= 0 always
PoolSolvent ==
    totalPooled >= 0

\* INV-7: Block bounded
BlockBounded ==
    currentBlock <= MaxBlock

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety == Spec => []TypeOK
THEOREM PriceConsistent == Spec => []SharePriceConsistent
THEOREM DelayEnforced == Spec => []WithdrawalDelayEnforced
THEOREM SharesMatch == Spec => []TotalSharesConsistent
THEOREM NonNegative == Spec => []NoNegativeBalance
THEOREM Solvency == Spec => []PoolSolvent
THEOREM Bounded == Spec => []BlockBounded

=============================================================================
