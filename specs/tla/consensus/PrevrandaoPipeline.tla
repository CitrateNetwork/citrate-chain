------------------------------ MODULE PrevrandaoPipeline ------------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Models the end-to-end PREVRANDAO pipeline: ECVRF proof generation in the block
\* producer, VRF output threading into BlockContext, and delivery to the EVM
\* execution layer so that Solidity contracts receive verifiable randomness via
\* the PREVRANDAO opcode (EIP-4399, opcode 0x44).
\*
\* Source files:
\*   node/src/producer.rs          — generate_block_vrf() with ecvrf::prove()
\*   core/execution/src/executor.rs — set_block_context() / get_block_context()
\*   core/execution/src/revm_adapter.rs — BlockContext { prevrandao, coinbase, block_hashes }
\*   core/api/src/eth_rpc.rs       — eth_call inherits executor's BlockContext
\*
\* The spec verifies 8 safety invariants covering the full pipeline.

CONSTANTS
    Validators,       \* Set of validator IDs
    MaxBlocks,        \* Maximum number of blocks (bounds state space)
    MaxContracts      \* Maximum number of contract calls

ASSUME Validators # {}
ASSUME MaxBlocks \in Nat /\ MaxBlocks >= 2
ASSUME MaxContracts \in Nat /\ MaxContracts >= 1

\* Block IDs: 0 = genesis, 1..MaxBlocks = producible blocks
BlockIds == 0..MaxBlocks

VARIABLES
    blocks,            \* Function: block ID -> record [producer, parentId, vrfOutput, proofLen]
    blockContext,      \* Current BlockContext: [prevrandao: Nat, coinbase: validator, blockId: Nat]
    contractCalls,     \* Set of contract call records: [blockId, prevrandaoSeen]
    nextBlockId,       \* Next block ID to assign
    executedBlocks     \* Set of block IDs whose transactions have been executed

vars == <<blocks, blockContext, contractCalls, nextBlockId, executedBlocks>>

\* ---- Helper operators ----

\* ECVRF output: deterministic function of (validator, parentVRF)
\* Modeled as a unique natural per (validator, parentVRF) pair
RECURSIVE ValidatorIndex(_, _)
ValidatorIndex(v, vs) ==
    IF vs = {} THEN 0
    ELSE LET w == CHOOSE x \in vs : TRUE IN
         IF v = w THEN 1
         ELSE 1 + ValidatorIndex(v, vs \ {w})

ComputeECVRFOutput(v, parentVRF) ==
    ValidatorIndex(v, Validators) * (MaxBlocks + 1) + parentVRF + 1

\* Genesis VRF output
GenesisVRFOutput == 0

\* ECVRF proof length: 114 bytes (pk_p256=33 + Gamma=33 + c=16 + s=32)
ECVRFProofLen == 114

\* Legacy SHA3 proof length
LegacySHA3ProofLen == 32

\* ---- State machine ----

Init ==
    /\ blocks = [bid \in {0} |-> [
            producer   |-> CHOOSE v \in Validators : TRUE,
            parentId   |-> 0,
            vrfOutput  |-> GenesisVRFOutput,
            proofLen   |-> LegacySHA3ProofLen  \* Genesis uses legacy format
       ]]
    /\ blockContext = [prevrandao |-> 0, coinbase |-> CHOOSE v \in Validators : TRUE, blockId |-> 0]
    /\ contractCalls = {}
    /\ nextBlockId = 1
    /\ executedBlocks = {}

\* Step 1: A validator produces a block with a real ECVRF proof
\* This models producer.rs: generate_block_vrf() calling ecvrf::prove()
ProduceBlock(v) ==
    /\ v \in Validators
    /\ nextBlockId <= MaxBlocks
    /\ \E parentId \in DOMAIN blocks :
        LET
            parentVRF  == blocks[parentId].vrfOutput
            vrfOut     == ComputeECVRFOutput(v, parentVRF)
            newId      == nextBlockId
        IN
            \* VRF output must be fresh (no replay)
            /\ \A bid \in DOMAIN blocks : blocks[bid].vrfOutput # vrfOut
            /\ blocks' = [bid \in DOMAIN blocks \cup {newId} |->
                IF bid = newId
                THEN [
                    producer   |-> v,
                    parentId   |-> parentId,
                    vrfOutput  |-> vrfOut,
                    proofLen   |-> ECVRFProofLen  \* Real ECVRF: 114 bytes
                ]
                ELSE blocks[bid]]
            /\ nextBlockId' = nextBlockId + 1
            /\ UNCHANGED <<blockContext, contractCalls, executedBlocks>>

\* Step 2: Set BlockContext before transaction execution
\* This models executor.set_block_context(BlockContext { prevrandao: vrf_output, ... })
SetBlockContext(blockId) ==
    /\ blockId \in DOMAIN blocks
    /\ blockId # 0                             \* Don't re-set for genesis
    /\ blockId \notin executedBlocks            \* Not yet executed
    /\ blockContext' = [
            prevrandao |-> blocks[blockId].vrfOutput,
            coinbase   |-> blocks[blockId].producer,
            blockId    |-> blockId
       ]
    /\ executedBlocks' = executedBlocks \cup {blockId}
    /\ UNCHANGED <<blocks, contractCalls, nextBlockId>>

\* Step 3: A contract reads block.prevrandao during execution
\* This models the REVM opcode 0x44 returning block.prevrandao from BlockContext
ContractReadsPrevrandao ==
    /\ blockContext.blockId # 0                \* Must be executing a real block
    /\ Cardinality(contractCalls) < MaxContracts * MaxBlocks
    /\ contractCalls' = contractCalls \cup {[
            blockId        |-> blockContext.blockId,
            prevrandaoSeen |-> blockContext.prevrandao
       ]}
    /\ UNCHANGED <<blocks, blockContext, nextBlockId, executedBlocks>>

\* Step 4: RPC eth_call reads prevrandao from current BlockContext
\* This models eth_rpc.rs where eth_call inherits the executor's BlockContext
RPCEthCall ==
    /\ blockContext.prevrandao # 0             \* Only after at least one real block
    /\ Cardinality(contractCalls) < MaxContracts * MaxBlocks
    /\ contractCalls' = contractCalls \cup {[
            blockId        |-> blockContext.blockId,
            prevrandaoSeen |-> blockContext.prevrandao
       ]}
    /\ UNCHANGED <<blocks, blockContext, nextBlockId, executedBlocks>>

Next ==
    \/ \E v \in Validators : ProduceBlock(v)
    \/ \E bid \in BlockIds : SetBlockContext(bid)
    \/ ContractReadsPrevrandao
    \/ RPCEthCall

\* ---- Invariants ----

\* INV-1: TypeInv — well-formed state
TypeInv ==
    /\ DOMAIN blocks \subseteq BlockIds
    /\ 0 \in DOMAIN blocks
    /\ \A bid \in DOMAIN blocks :
        /\ blocks[bid].producer \in Validators
        /\ blocks[bid].parentId \in DOMAIN blocks
        /\ blocks[bid].vrfOutput \in Nat
        /\ blocks[bid].proofLen \in Nat
    /\ blockContext.prevrandao \in Nat
    /\ blockContext.coinbase \in Validators
    /\ blockContext.blockId \in Nat
    /\ contractCalls \subseteq [blockId: Nat, prevrandaoSeen: Nat]
    /\ nextBlockId \in Nat
    /\ executedBlocks \subseteq Nat

\* INV-2: ECVRFProofFormat — all non-genesis blocks use 114-byte ECVRF proofs
ECVRFProofFormat ==
    \A bid \in DOMAIN blocks :
        bid # 0 => blocks[bid].proofLen = ECVRFProofLen

\* INV-3: VRFChainContinuity — each block's VRF output is derived from parent's VRF output
\* This ensures the VRF chain is unbroken: alpha includes parent VRF output
VRFChainContinuity ==
    \A bid \in DOMAIN blocks :
        bid # 0 =>
            blocks[bid].vrfOutput = ComputeECVRFOutput(
                blocks[bid].producer,
                blocks[blocks[bid].parentId].vrfOutput
            )

\* INV-4: NoVRFReplay — no two blocks share the same VRF output
NoVRFReplay ==
    \A b1, b2 \in DOMAIN blocks :
        (b1 # b2 /\ b1 # 0 /\ b2 # 0) =>
            blocks[b1].vrfOutput # blocks[b2].vrfOutput

\* INV-5: BlockContextMatchesVRF — the current BlockContext.prevrandao
\* always equals the VRF output of the block being executed
BlockContextMatchesVRF ==
    blockContext.blockId \in DOMAIN blocks =>
        blockContext.prevrandao = blocks[blockContext.blockId].vrfOutput

\* INV-6: ContractSeesCorrectPrevrandao — every contract call sees the
\* correct prevrandao value matching the block's VRF output
ContractSeesCorrectPrevrandao ==
    \A call \in contractCalls :
        call.blockId \in DOMAIN blocks =>
            call.prevrandaoSeen = blocks[call.blockId].vrfOutput

\* INV-7: PrevrandaoNonZeroAfterFirstBlock — once any non-genesis block is
\* produced and executed, prevrandao is never zero
PrevrandaoNonZeroAfterFirstBlock ==
    \A call \in contractCalls :
        call.blockId # 0 => call.prevrandaoSeen # 0

\* INV-8: ExecutionPrecedesContractAccess — a contract can only see
\* prevrandao for blocks that have been through SetBlockContext
ExecutionPrecedesContractAccess ==
    \A call \in contractCalls :
        call.blockId \in executedBlocks \/ call.blockId = 0

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafety          == Spec => []TypeInv
THEOREM ProofFormat          == Spec => []ECVRFProofFormat
THEOREM ChainContinuity      == Spec => []VRFChainContinuity
THEOREM NoReplay             == Spec => []NoVRFReplay
THEOREM ContextMatchesVRF    == Spec => []BlockContextMatchesVRF
THEOREM ContractCorrectness  == Spec => []ContractSeesCorrectPrevrandao
THEOREM NonZeroRandomness    == Spec => []PrevrandaoNonZeroAfterFirstBlock
THEOREM ExecutionOrdering    == Spec => []ExecutionPrecedesContractAccess

=============================================================================
