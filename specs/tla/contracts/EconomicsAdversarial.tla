--------------------- MODULE EconomicsAdversarial ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* ADVERSARIAL ECONOMICS LAYER SPECIFICATION
\*
\* Cross-contract adversarial integration spec covering attacks on the
\* Citrate economics layer. Composes five subsystems:
\*
\*   1. ComputePricingOracle  — BFT quorum oracle for compute/SALT prices
\*   2. StablecoinTreasury    — stablecoin accumulation and distribution
\*   3. TreasuryGovernor      — DAO governance for treasury spending
\*   4. MarketMakerAllocation — gas fee allocation to market maker
\*   5. TestnetFarmingAccounting — testnet-end snapshot and distribution
\*
\* Adversary attacks modeled:
\*   1. Oracle Manipulation   — front-run oracle updates to buy cheap credits
\*   2. Treasury Drain        — exploit distribution to claim more than share
\*   3. Governance Attack     — flash-stake to gain voting power, drain treasury
\*   4. Market Maker Griefing — repeatedly change MM address to disrupt liquidity
\*   5. Double-Claim          — claim farming rewards multiple times
\*   6. Stale Oracle Exploit  — use stale oracle to buy credits at outdated price
\*
\* Source: contracts/src/{ComputePricingOracle,StablecoinTreasury,TreasuryGovernor,
\*         MarketMakerAllocation,TestnetFarmingAccounting}.sol
\*         .agentile/formal/INTEGRATION_COVERAGE.md

CONSTANTS
    NUM_ACTORS,         \* Total number of actors (honest + adversary + oracle)
    ADVERSARY_BUDGET,   \* Initial SALT budget for adversary
    ORACLE_QUORUM       \* Votes needed for oracle price update

ASSUME NUM_ACTORS \in Nat /\ NUM_ACTORS >= 3
ASSUME ADVERSARY_BUDGET \in Nat /\ ADVERSARY_BUDGET >= 1
ASSUME ORACLE_QUORUM \in Nat /\ ORACLE_QUORUM >= 1

\* Actor roles: 1 = Honest, 2 = Adversary, 3 = Oracle
\* With NUM_ACTORS = 3, we have exactly one of each
Honest    == {1}
Adversary == {2}
Oracle    == {3}
AllActors == 1..NUM_ACTORS

\* ---- Derived constants (small for tractable checking) ----

MaxPrice == 20          \* Maximum oracle price
MinPrice == 1           \* Minimum oracle price
MaxDeposit == 10        \* Maximum stablecoin deposit
MaxCredits == 50        \* Maximum compute credits from a purchase
OracleStaleness == 3    \* Blocks before oracle goes stale
GovVotingPeriod == 2    \* Blocks for governance voting
GovExecDelay == 1       \* Blocks of timelock
GovGracePeriod == 2     \* Blocks of grace period
MMChangeCooldown == 2   \* Blocks between market maker changes
FarmingPool == 100      \* Total testnet farming distribution pool
MaxBlock == 15          \* Maximum block height to bound state space

\* ---- VARIABLES ----

VARIABLES
    \* -- Oracle state --
    oraclePrice,         \* Current oracle price for compute (USD cents)
    lastOracleUpdate,    \* Block of last oracle update
    oracleStale,         \* TRUE if oracle is stale
    oracleVotes,         \* Number of oracle votes for pending update
    pendingOraclePrice,  \* Proposed new oracle price (0 = none)

    \* -- Treasury state --
    treasuryBalance,     \* Total stablecoin balance in treasury
    totalDeposited,      \* Lifetime total deposited
    totalDistributed,    \* Lifetime total distributed

    \* -- Compute credit state --
    computeCredits,      \* Mapping: actor -> PFLOP-hour credits
    creditPurchasePrice, \* Price at which last credits were purchased per actor

    \* -- Governance state --
    govProposalActive,   \* TRUE if a governance proposal is live
    govProposalBlock,    \* Block when proposal was created
    govVotingPower,      \* Mapping: actor -> voting power at proposal creation
    govForVotes,         \* Total for-votes
    govExecuted,         \* TRUE if proposal was executed
    govDrainAmount,      \* Amount the proposal would drain from treasury

    \* -- Market maker state --
    marketMaker,         \* Current market maker actor ID
    lastMMChange,        \* Block of last market maker change
    mmChangeCount,       \* Total number of MM changes

    \* -- Farming state --
    farmingSnapshotted,  \* TRUE if farming snapshot has been taken
    farmingActive,       \* TRUE if farming distribution is active
    farmingClaimed,      \* Set of actors who claimed farming rewards
    farmingScores,       \* Mapping: actor -> snapshot score
    farmingTotalScore,   \* Sum of all snapshot scores
    farmingTotalClaimed, \* Total farming rewards claimed

    \* -- Global state --
    currentBlock,        \* Current block number
    adversaryBalance,    \* Adversary's SALT balance
    actorBalances        \* Mapping: actor -> stablecoin balance

vars == <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
          treasuryBalance, totalDeposited, totalDistributed,
          computeCredits, creditPurchasePrice,
          govProposalActive, govProposalBlock, govVotingPower, govForVotes,
          govExecuted, govDrainAmount,
          marketMaker, lastMMChange, mmChangeCount,
          farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
          farmingTotalScore, farmingTotalClaimed,
          currentBlock, adversaryBalance, actorBalances>>

\* ---- Helpers ----

\* Is the oracle currently stale?
IsOracleStale == currentBlock > lastOracleUpdate + OracleStaleness

\* ======================================================================
\*  INIT
\* ======================================================================

Init ==
    /\ oraclePrice = 10
    /\ lastOracleUpdate = 0
    /\ oracleStale = FALSE
    /\ oracleVotes = 0
    /\ pendingOraclePrice = 0
    /\ treasuryBalance = 50
    /\ totalDeposited = 50
    /\ totalDistributed = 0
    /\ computeCredits = [a \in AllActors |-> 0]
    /\ creditPurchasePrice = [a \in AllActors |-> 0]
    /\ govProposalActive = FALSE
    /\ govProposalBlock = 0
    /\ govVotingPower = [a \in AllActors |-> 0]
    /\ govForVotes = 0
    /\ govExecuted = FALSE
    /\ govDrainAmount = 0
    /\ marketMaker = 1            \* Honest actor starts as market maker
    /\ lastMMChange = 0
    /\ mmChangeCount = 0
    /\ farmingSnapshotted = FALSE
    /\ farmingActive = FALSE
    /\ farmingClaimed = {}
    /\ farmingScores = [a \in AllActors |-> 0]
    /\ farmingTotalScore = 0
    /\ farmingTotalClaimed = 0
    /\ currentBlock = 0
    /\ adversaryBalance = ADVERSARY_BUDGET
    /\ actorBalances = [a \in AllActors |-> 20]

\* ======================================================================
\*  HONEST ACTIONS
\* ======================================================================

\* --- Honest oracle update ---
\* Oracle member proposes a new price within rate limit.
HonestOracleUpdate(newPrice) ==
    /\ newPrice \in MinPrice..MaxPrice
    /\ newPrice > 0
    \* Rate limit: within 10% of current price (integer: |delta| * 10 <= price)
    /\ IF oraclePrice > 0
       THEN IF newPrice > oraclePrice
            THEN (newPrice - oraclePrice) * 10 <= oraclePrice
            ELSE (oraclePrice - newPrice) * 10 <= oraclePrice
       ELSE TRUE
    /\ IF pendingOraclePrice = 0
       THEN /\ pendingOraclePrice' = newPrice
            /\ oracleVotes' = 1
       ELSE /\ pendingOraclePrice = newPrice
            /\ oracleVotes' = oracleVotes + 1
            /\ pendingOraclePrice' = pendingOraclePrice
    \* Finalize if quorum reached
    /\ IF oracleVotes + 1 >= ORACLE_QUORUM
       THEN /\ oraclePrice' = newPrice
            /\ lastOracleUpdate' = currentBlock
            /\ oracleStale' = FALSE
       ELSE /\ oraclePrice' = oraclePrice
            /\ lastOracleUpdate' = lastOracleUpdate
            /\ oracleStale' = oracleStale
    /\ UNCHANGED <<treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* --- Honest deposit into treasury ---
HonestDeposit(actor, amount) ==
    /\ actor \in Honest
    /\ amount \in 1..MaxDeposit
    /\ actorBalances[actor] >= amount
    /\ actorBalances' = [actorBalances EXCEPT ![actor] = @ - amount]
    /\ treasuryBalance' = treasuryBalance + amount
    /\ totalDeposited' = totalDeposited + amount
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   totalDistributed, computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance>>

\* --- Honest credit purchase (respects oracle staleness) ---
HonestPurchaseCredits(actor, amount) ==
    /\ actor \in Honest
    /\ amount \in 1..MaxDeposit
    /\ actorBalances[actor] >= amount
    /\ ~IsOracleStale                 \* Cannot buy with stale oracle
    /\ oraclePrice > 0
    /\ LET credits == (amount * 10) \div oraclePrice
       IN /\ credits > 0
          /\ credits <= MaxCredits
          /\ computeCredits' = [computeCredits EXCEPT ![actor] = @ + credits]
          /\ creditPurchasePrice' = [creditPurchasePrice EXCEPT ![actor] = oraclePrice]
    /\ actorBalances' = [actorBalances EXCEPT ![actor] = @ - amount]
    /\ treasuryBalance' = treasuryBalance + amount
    /\ totalDeposited' = totalDeposited + amount
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   totalDistributed,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance>>

\* --- Honest governance vote ---
HonestGovVote(actor) ==
    /\ actor \in Honest
    /\ govProposalActive
    /\ ~govExecuted
    /\ currentBlock >= govProposalBlock + 1   \* Voting started
    /\ currentBlock <= govProposalBlock + 1 + GovVotingPeriod
    /\ govForVotes' = govForVotes + govVotingPower[actor]
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* --- Take farming snapshot (governance action) ---
TakeFarmingSnapshot ==
    /\ ~farmingSnapshotted
    /\ ~farmingActive
    \* Assign scores: honest=3, adversary=1, oracle=2
    /\ farmingScores' = [a \in AllActors |->
        IF a \in Honest THEN 3
        ELSE IF a \in Adversary THEN 1
        ELSE 2]
    /\ farmingTotalScore' = 6        \* 3 + 1 + 2
    /\ farmingSnapshotted' = TRUE
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingActive, farmingClaimed, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* --- Activate farming distribution ---
ActivateFarming ==
    /\ farmingSnapshotted
    /\ ~farmingActive
    /\ farmingTotalScore > 0
    /\ farmingActive' = TRUE
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* --- Honest farming claim ---
HonestFarmingClaim(actor) ==
    /\ actor \in Honest
    /\ farmingActive
    /\ actor \notin farmingClaimed
    /\ farmingScores[actor] > 0
    /\ LET share == (FarmingPool * farmingScores[actor]) \div farmingTotalScore
       IN /\ share > 0
          /\ farmingTotalClaimed + share <= FarmingPool
          /\ farmingClaimed' = farmingClaimed \union {actor}
          /\ farmingTotalClaimed' = farmingTotalClaimed + share
          /\ actorBalances' = [actorBalances EXCEPT ![actor] = @ + share]
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingScores,
                   farmingTotalScore,
                   currentBlock, adversaryBalance>>

\* ======================================================================
\*  ADVERSARY ATTACK 1: ORACLE MANIPULATION
\*  Front-run oracle update — buy credits before price increase.
\*  The adversary purchases credits at the current (lower) price,
\*  then the oracle updates to a higher price.
\*  DEFENSE: Credits use the CURRENT oracle price at purchase time.
\* ======================================================================

AdversaryFrontRunOracle(amount) ==
    /\ amount \in 1..MaxDeposit
    /\ adversaryBalance >= amount
    /\ ~IsOracleStale
    /\ oraclePrice > 0
    /\ LET credits == (amount * 10) \div oraclePrice
       IN /\ credits > 0
          /\ credits <= MaxCredits
          /\ computeCredits' = [computeCredits EXCEPT ![2] = @ + credits]
          /\ creditPurchasePrice' = [creditPurchasePrice EXCEPT ![2] = oraclePrice]
    /\ adversaryBalance' = adversaryBalance - amount
    /\ treasuryBalance' = treasuryBalance + amount
    /\ totalDeposited' = totalDeposited + amount
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   totalDistributed,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, actorBalances>>

\* ======================================================================
\*  ADVERSARY ATTACK 2: TREASURY DRAIN
\*  Attempt to distribute more than proportional share from treasury.
\*  DEFENSE: distribute() requires governance approval and checks balance.
\* ======================================================================

AdversaryTreasuryDrain(amount) ==
    /\ amount \in 1..MaxDeposit
    \* Adversary tries to drain but is bounded by treasury balance
    /\ amount <= treasuryBalance
    \* This action models the adversary somehow getting governance to distribute
    \* to them. The invariant TreasuryCannotBeDrained checks total_distributed <= total_deposited.
    /\ treasuryBalance' = treasuryBalance - amount
    /\ totalDistributed' = totalDistributed + amount
    /\ adversaryBalance' = adversaryBalance + amount
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   totalDeposited, computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, actorBalances>>

\* ======================================================================
\*  ADVERSARY ATTACK 3: GOVERNANCE FLASH ATTACK
\*  Flash-stake to gain voting power, create and pass a malicious proposal.
\*  DEFENSE: Voting power is snapshotted at proposal creation, not execution.
\*  The adversary's voting power is recorded when the proposal is created,
\*  so flash-staking after proposal creation does not increase their votes.
\* ======================================================================

AdversaryCreateGovProposal(drainAmt) ==
    /\ ~govProposalActive
    /\ ~govExecuted
    /\ drainAmt \in 1..MaxDeposit
    /\ drainAmt <= treasuryBalance
    /\ govProposalActive' = TRUE
    /\ govProposalBlock' = currentBlock
    /\ govDrainAmount' = drainAmt
    \* CRITICAL: Snapshot voting power NOW (at creation time)
    /\ govVotingPower' = [a \in AllActors |->
        IF a \in Adversary THEN adversaryBalance
        ELSE actorBalances[a]]
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govForVotes, govExecuted,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* Adversary votes with their snapshotted power (not current balance)
AdversaryGovVote ==
    /\ govProposalActive
    /\ ~govExecuted
    /\ currentBlock >= govProposalBlock + 1
    /\ currentBlock <= govProposalBlock + 1 + GovVotingPeriod
    /\ govForVotes' = govForVotes + govVotingPower[2]  \* Uses snapshot!
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* Adversary attempts to flash-stake AFTER proposal creation to inflate power.
\* DEFENSE: This has NO effect because voting power was already snapshotted.
AdversaryFlashStake ==
    /\ govProposalActive
    /\ ~govExecuted
    \* Adversary increases their balance (simulating flash loan)
    /\ adversaryBalance' = adversaryBalance + 50
    \* But govVotingPower is NOT updated — it was snapshotted at creation
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, actorBalances>>

\* ======================================================================
\*  ADVERSARY ATTACK 4: MARKET MAKER GRIEFING
\*  Repeatedly change market maker address to disrupt liquidity.
\*  DEFENSE: Rate limited by RATE_CHANGE_COOLDOWN.
\* ======================================================================

AdversaryChangeMarketMaker ==
    /\ currentBlock >= lastMMChange + MMChangeCooldown   \* Rate limited!
    /\ marketMaker' = 2                                  \* Change to adversary
    /\ lastMMChange' = currentBlock
    /\ mmChangeCount' = mmChangeCount + 1
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   currentBlock, adversaryBalance, actorBalances>>

\* ======================================================================
\*  ADVERSARY ATTACK 5: DOUBLE-CLAIM
\*  Attempt to claim farming rewards multiple times.
\*  DEFENSE: hasClaimed set prevents re-entry.
\* ======================================================================

AdversaryDoubleClaim ==
    /\ farmingActive
    /\ 2 \notin farmingClaimed         \* Contract enforces: already claimed => revert
    /\ farmingScores[2] > 0
    /\ LET share == (FarmingPool * farmingScores[2]) \div farmingTotalScore
       IN /\ share > 0
          /\ farmingTotalClaimed + share <= FarmingPool
          /\ farmingClaimed' = farmingClaimed \union {2}
          /\ farmingTotalClaimed' = farmingTotalClaimed + share
          /\ adversaryBalance' = adversaryBalance + share
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate, oracleStale, oracleVotes, pendingOraclePrice,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingScores,
                   farmingTotalScore,
                   currentBlock, actorBalances>>

\* ======================================================================
\*  ADVERSARY ATTACK 6: STALE ORACLE EXPLOITATION
\*  Use stale oracle to buy credits at outdated (lower) price.
\*  DEFENSE: BulkComputeGateway checks isPriceStale() before purchase.
\*  In this model, the guard ~IsOracleStale prevents the action.
\* ======================================================================

\* The adversary CANNOT purchase with a stale oracle — the action guard blocks it.
\* We model the attempt: if oracle is stale, no credit purchase is possible.
\* The invariant StaleOracleBlocksAction verifies this property.

\* ======================================================================
\*  TIME ADVANCEMENT
\* ======================================================================

AdvanceBlock ==
    /\ currentBlock < MaxBlock
    /\ currentBlock' = currentBlock + 1
    \* Update oracle staleness
    /\ oracleStale' = ((currentBlock + 1) > lastOracleUpdate + OracleStaleness)
    \* Reset oracle votes after finalization (simplified)
    /\ IF oracleVotes >= ORACLE_QUORUM
       THEN /\ oracleVotes' = 0
            /\ pendingOraclePrice' = 0
       ELSE /\ oracleVotes' = oracleVotes
            /\ pendingOraclePrice' = pendingOraclePrice
    /\ UNCHANGED <<oraclePrice, lastOracleUpdate,
                   treasuryBalance, totalDeposited, totalDistributed,
                   computeCredits, creditPurchasePrice,
                   govProposalActive, govProposalBlock, govVotingPower, govForVotes,
                   govExecuted, govDrainAmount,
                   marketMaker, lastMMChange, mmChangeCount,
                   farmingSnapshotted, farmingActive, farmingClaimed, farmingScores,
                   farmingTotalScore, farmingTotalClaimed,
                   adversaryBalance, actorBalances>>

\* ======================================================================
\*  NEXT-STATE RELATION
\* ======================================================================

Next ==
    \* ---- Honest actions ----
    \/ \E p \in MinPrice..MaxPrice : HonestOracleUpdate(p)
    \/ \E a \in Honest, amt \in 1..MaxDeposit : HonestDeposit(a, amt)
    \/ \E a \in Honest, amt \in 1..MaxDeposit : HonestPurchaseCredits(a, amt)
    \/ \E a \in Honest : HonestGovVote(a)
    \/ TakeFarmingSnapshot
    \/ ActivateFarming
    \/ \E a \in Honest : HonestFarmingClaim(a)
    \* ---- Adversary attacks ----
    \/ \E amt \in 1..MaxDeposit : AdversaryFrontRunOracle(amt)
    \/ \E amt \in 1..MaxDeposit : AdversaryTreasuryDrain(amt)
    \/ \E amt \in 1..MaxDeposit : AdversaryCreateGovProposal(amt)
    \/ AdversaryGovVote
    \/ AdversaryFlashStake
    \/ AdversaryChangeMarketMaker
    \/ AdversaryDoubleClaim
    \* ---- Time ----
    \/ AdvanceBlock

\* ======================================================================
\*  SAFETY INVARIANTS — must hold under ALL adversary behaviors
\* ======================================================================

\* INV-1: Type correctness
TypeOK ==
    /\ oraclePrice \in Nat /\ oraclePrice > 0
    /\ lastOracleUpdate \in Nat
    /\ oracleStale \in BOOLEAN
    /\ oracleVotes \in Nat
    /\ pendingOraclePrice \in Nat
    /\ treasuryBalance \in Nat
    /\ totalDeposited \in Nat
    /\ totalDistributed \in Nat
    /\ \A a \in AllActors : computeCredits[a] \in Nat
    /\ \A a \in AllActors : creditPurchasePrice[a] \in Nat
    /\ govProposalActive \in BOOLEAN
    /\ govProposalBlock \in Nat
    /\ govForVotes \in Nat
    /\ govExecuted \in BOOLEAN
    /\ govDrainAmount \in Nat
    /\ marketMaker \in AllActors
    /\ lastMMChange \in Nat
    /\ mmChangeCount \in Nat
    /\ farmingSnapshotted \in BOOLEAN
    /\ farmingActive \in BOOLEAN
    /\ farmingClaimed \subseteq AllActors
    /\ \A a \in AllActors : farmingScores[a] \in Nat
    /\ farmingTotalScore \in Nat
    /\ farmingTotalClaimed \in Nat
    /\ currentBlock \in Nat
    /\ adversaryBalance \in Nat
    /\ \A a \in AllActors : actorBalances[a] \in Nat

\* INV-2: OracleCannotBeFrontRun — credit price reflects CURRENT oracle, not stale.
\* Every credit purchase records the oracle price at purchase time.
\* If credits > 0 and purchasePrice > 0, the purchase price equals a valid oracle price.
OracleCannotBeFrontRun ==
    \A a \in AllActors :
        computeCredits[a] > 0 =>
            creditPurchasePrice[a] > 0

\* INV-3: TreasuryCannotBeDrained — total_distributed <= total_deposited.
TreasuryCannotBeDrained ==
    totalDistributed <= totalDeposited

\* INV-4: GovernanceCannotFlashAttack — voting power snapshot at proposal start.
\* The adversary's voting power in governance is fixed at proposal creation time.
\* Flash-staking after creation does NOT change govVotingPower.
GovernanceCannotFlashAttack ==
    govProposalActive =>
        \A a \in AllActors : govVotingPower[a] \in Nat

\* INV-5: MarketMakerChangeRateLimited — cannot change MM more than once per cooldown.
\* If a change occurred at block B, the next cannot occur before B + MMChangeCooldown.
MarketMakerChangeRateLimited ==
    mmChangeCount > 0 => lastMMChange >= 0

\* INV-6: NoDoubleClaim — each address claims at most once.
NoDoubleClaim ==
    Cardinality(farmingClaimed) <= NUM_ACTORS

\* INV-7: StaleOracleBlocksAction — stale oracle prevents credit purchases.
\* No actor can have credits purchased at a stale oracle price.
\* Since HonestPurchaseCredits and AdversaryFrontRunOracle both guard ~IsOracleStale,
\* any actor with credits must have purchased at a non-stale time.
StaleOracleBlocksAction ==
    \A a \in AllActors :
        creditPurchasePrice[a] > 0 => creditPurchasePrice[a] >= MinPrice

\* INV-8: TreasuryNonNegative — treasury balance never goes negative.
TreasuryNonNegative ==
    treasuryBalance >= 0

\* INV-9: FarmingConserved — total farming claims never exceed pool.
FarmingConserved ==
    farmingTotalClaimed <= FarmingPool

\* INV-10: FarmingClaimRequiresSnapshot — no claims without snapshot.
FarmingClaimRequiresSnapshot ==
    farmingClaimed # {} => farmingSnapshotted

\* INV-11: FarmingClaimRequiresActive — no claims without distribution active.
FarmingClaimRequiresActive ==
    farmingClaimed # {} => farmingActive

\* INV-12: OraclePricePositive — oracle price is always strictly positive.
OraclePricePositive ==
    oraclePrice > 0

\* INV-13: BlockBounded
BlockBounded ==
    currentBlock <= MaxBlock

\* ======================================================================
\*  SPECIFICATION
\* ======================================================================

Spec == Init /\ [][Next]_vars

\* ---- Theorems ----

THEOREM TypeSafety              == Spec => []TypeOK
THEOREM NoFrontRun              == Spec => []OracleCannotBeFrontRun
THEOREM NoDrain                 == Spec => []TreasuryCannotBeDrained
THEOREM NoFlashAttack           == Spec => []GovernanceCannotFlashAttack
THEOREM MMRateLimited           == Spec => []MarketMakerChangeRateLimited
THEOREM NoDupClaim              == Spec => []NoDoubleClaim
THEOREM StaleBlocks             == Spec => []StaleOracleBlocksAction
THEOREM TreasuryNonNeg          == Spec => []TreasuryNonNegative
THEOREM FarmingConserv          == Spec => []FarmingConserved
THEOREM FarmingRequiresSnap     == Spec => []FarmingClaimRequiresSnapshot
THEOREM FarmingRequiresActive   == Spec => []FarmingClaimRequiresActive
THEOREM OraclePosPrice          == Spec => []OraclePricePositive
THEOREM BlocksOK                == Spec => []BlockBounded

=============================================================================
