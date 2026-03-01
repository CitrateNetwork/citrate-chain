# Paraconsensus Architecture Document

**Source**: Gradient Papers No. II — *Paraconsistent Consensus: Federated Meta-Learning Over BlockDAG Finality Checkpoints*
**Author**: Larry Klosowski (Cnidarian Foundation / Labs)
**Architecture Version**: 1.0
**Last Updated**: 2026-03-01
**Implementation Crate**: `citrate-learning` (`core/learning/`)
**Test Baseline**: 81 tests passing (foundation scaffold)

---

## 1. Executive Summary

Paraconsistent Consensus unifies BlockDAG consensus and federated meta-learning into a single protocol. The core innovation is a formal aggregation function grounded in Belnap's four-valued logic (FOUR) that classifies each node's model output into one of four epistemic states — relevant (T), irrelevant (F), contradictory (B), or unknown (N) — and preserves all four states through aggregation rather than collapsing them via averaging.

The framework operates **on top of** Citrate's existing GhostDAG consensus with BFT finality checkpoints (Paper I), extending checkpoint commitments to include learning state. Learning never modifies consensus — this is the critical safety invariant.

**Implementation Status**: `[Specified]` — designed but not yet integrated with the consensus layer. The `core/learning/` crate contains foundation types and algorithms (81 tests) but is not yet wired into the node binary.

---

## 2. Canonical Protocol Parameters

From Paper 0 (Series Index, Table 2) and Paper II (Appendix A2). Any implementation that deviates from these values is a bug.

### 2.1 Consensus Parameters (Inherited from Paper I)

| Parameter | Value | Source |
|-----------|-------|--------|
| Block time | ~0.5s (2 BPS) | Paper I §2.2 |
| k parameter (GhostDAG) | 18 | Paper I §2.2 |
| Max parents per block | 10 (1 selected + 9 merge) | Paper I §2.2 |
| BFT committee size | 100 validators | Paper I §2.3 |
| BFT signature threshold | 67 (2/3+1) | Paper I §2.3 |
| Checkpoint interval | 10 blocks (~5 seconds) | Paper I §2.3 |
| Fraud proof window | 100 blocks (~50 seconds) | Paper I §3.3 |
| Max block size | 10 MB | Paper I Appendix A |
| SALT total supply | 1,000,000,000 | Paper I §5 |
| Minimum validator stake | 10,000 SALT | Paper I §5 |

### 2.2 Learning Protocol Parameters (Paper II, Table A2)

| Parameter | Value | Rationale | Config Field |
|-----------|-------|-----------|-------------|
| Embedding dimension (d) | 768, configurable | Common transformer hidden size | `embedding_dimensions` |
| Embedding precision | float32 (default), float16 optional | Fidelity vs bandwidth | — |
| Per-block embedding overhead | ~3 KB (d=768, float32) | Within 10 MB block limit | — |
| Per-block confidence overhead | ~3 KB (d=768, float32) | Same as embedding | — |
| Total per-block overhead | ~6-7 KB | Embedding + confidence vectors | — |
| Routing model size | 100K–500K parameters | Must retrain at checkpoint interval (~5s) | — |
| Belnap threshold θ_high | 0.8 (proposed) | Requires testnet calibration | `belnap_high_threshold` |
| Belnap threshold θ_low | 0.3 (proposed) | Requires testnet calibration | `belnap_low_threshold` |
| Temperature τ | 1.0 (default) | Controls blue-score trust concentration | — |
| LoRA adapter rank (r) | 16, configurable | Standard LoRA configuration | — |
| Adapter consolidation interval | Every 1,000 checkpoints (~83 min) | Balance freshness vs interference | — |
| Slashing: embedding manipulation | 10% of stake | Detected via random spot-checks | — |

### 2.3 Current Config Implementation vs Paper

**`core/learning/src/config.rs`** (`LearningConfig`):

| Config Field | Current Default | Paper II Value | Status |
|---|---|---|---|
| `embedding_dimensions` | **128** | **768** | **MISMATCH** — must update to 768 |
| `min_participants` | 3 | Not specified (inferred from BFT: ≥4 for f<n/3) | OK |
| `max_participants` | 1000 | Not specified | OK |
| `phase_timeout_ms` | 30000 (30s) | Not specified (checkpoint is ~5s) | REVIEW — may be too long |
| `belnap_high_threshold` | 0.8 | 0.8 | MATCH |
| `belnap_low_threshold` | 0.3 | 0.3 | MATCH |
| `byzantine_threshold` | 0.33 | f < n/3 ≈ 0.33 | MATCH |
| `max_byzantine_flags` | 3 | Not specified | OK |
| `cooldown_rounds` | 10 | Not specified | OK |
| `router_hidden_dim` | 64 | Not specified (100K-500K params total) | REVIEW |
| `router_learning_rate` | 0.01 | Not specified | OK |
| `router_num_destinations` | 8 | Not specified | OK |

**Action Items**:
1. Change `embedding_dimensions` default from 128 to 768
2. Review `phase_timeout_ms` — Paper II specifies checkpoint every ~5s; phase timeout of 30s means 6 checkpoints could pass during one phase cycle
3. Review router architecture — with d=768, hidden_dim=64, num_destinations=8: param count = 768×64 + 64 + 64×8 + 8 = 49,736. Paper says 100K-500K. May need hidden_dim=256 or larger.

---

## 3. Formal Definitions (Paper II §3)

### Definition 1: Belnap FOUR Bilattice

Four epistemic states with two partial orderings:

```
Truth ordering (≤_t):     F ≤ N ≤ T,  F ≤ B ≤ T
Knowledge ordering (≤_k): N ≤ T ≤ B,  N ≤ F ≤ B
```

**Lattice Diagram (knowledge ordering)**:
```
        B (Both)
       / \
      T   F
       \ /
        N (Neither)
```

**Operations**:
- `join(a, b)`: Least upper bound in knowledge ordering (combines information)
- `meet(a, b)`: Greatest lower bound (consensus)
- `negation(T) = F`, `negation(F) = T`, `negation(B) = B`, `negation(N) = N`

**Implementation**: `core/learning/src/belnap.rs` — `BelnapValue` enum with all 16 join/meet combinations verified by property tests (commutative, associative, idempotent, absorption, double negation). **COMPLETE**.

### Definition 2: Embedding Space

A d-dimensional vector `eᵢ ∈ ℝᵈ` produced by passing a shared reference input through node i's local model.

**Implementation**: `core/learning/src/embeddings.rs` — `EmbeddingVector` with NaN/Inf validation, normalization, similarity metrics. **COMPLETE**.

### Definition 3: Similarity Metric

Cosine similarity and Euclidean distance for comparing embeddings.

**Implementation**: `core/learning/src/embeddings.rs` — `cosine_similarity()`, `euclidean_distance()`. **COMPLETE**.

### Definition 4: Knowledge State

Per-node state combining embedding with Belnap confidence per dimension:
```
KnowledgeState = (embedding: EmbeddingVector, confidence: Vec<BelnapValue>)
```

**Implementation**: `core/learning/src/knowledge.rs` — `KnowledgeState` with `merge()` using Belnap join. **COMPLETE**.

### Definition 5: Classification Function φ (Paper II §3.1)

Maps each node's embedding to a Belnap state relative to the current query, **dimension-wise**:

```
φ(eᵢ, query) → {T, F, B, N}^d

For each dimension j:
  T: cᵢⱼ > θ_high AND eᵢⱼ directionally consistent with blue-score-weighted majority
  F: cᵢⱼ > θ_high AND eᵢⱼ directionally inconsistent with majority
  B: Multiple nodes with comparable blue scores produce inconsistent embeddings
  N: cᵢⱼ < θ_low (uncertain)
```

**Implementation Status**: **NOT IMPLEMENTED**. The `belnap.rs` module has the FOUR values but the classification function φ that maps embeddings to Belnap states relative to a query/majority is missing. This is the core paper contribution — it MUST be implemented.

**Sprint Gap**: Sprint L covers Belnap values (WP-L.2) and Sprint M covers aggregation (WP-M.1), but **neither sprint explicitly plans the φ classification function** that maps node embeddings to Belnap states. This classification is the bridge between embeddings and Belnap — without it, the aggregation is just weighted averaging, not paraconsistent.

### Definition 6: Aggregation Rule (Paper II §3.2)

Produces TWO outputs:
1. **Aggregated embedding**: `e_agg[j] = Σᵢ(wᵢ · eᵢ[j]) / Σᵢ wᵢ` where `wᵢ = cᵢ[j] · softmax(bᵢ / τ)`
2. **State vector**: `s ∈ {T, F, B, N}^d` computed INDEPENDENTLY of e_agg via φ

**Critical**: The state vector s is computed independently of the aggregated embedding. Even when e_agg produces a reasonable weighted average, s[j] = B signals contradictory evidence. The routing model receives BOTH e_agg AND s as input.

**Implementation Status**: **PARTIAL**. `WeightedMeanAggregator` computes e_agg (weighted mean) but does NOT compute the Belnap state vector s. The aggregator must produce both.

**Sprint Gap**: WP-M.1 implements weighted mean aggregation but does not mention the dual-output requirement (e_agg + state vector s). The state vector is the entire point of paraconsistent aggregation.

### Definition 7: Routing Function (Paper II §4.2)

Input: `(query_embedding, e_agg, state_vector_s, per_node_capability_profiles)`
Output: `routing_weights ∈ ℝ^N` (one weight per node)

The routing model is an MLP or single-layer attention with 100K-500K parameters that takes the Belnap state vector as input, enabling routing decisions informed by agreement structure, not just aggregated values.

**Implementation Status**: **PARTIAL**. `MlpRouter` exists but takes only an embedding as input — it does NOT take the Belnap state vector s. The entire routing advantage of paraconsistency is that the router sees WHERE the network disagrees.

**Sprint Gap**: WP-N.1 implements MLP routing but the router signature should be `route(query, e_agg, state_vector) → weights`, not just `route(embedding) → weights`.

---

## 4. Algorithms (Paper II §3-5)

### Algorithm 1: Paraconsistent Aggregation

```
function aggregate(participants, blue_scores, temperature):
    // Step 1: Compute trust weights from blue scores
    weights = softmax(blue_scores / temperature)

    // Step 2: For each dimension j, classify each node via φ
    state_vector = new {T,F,B,N}[d]
    for j in 0..d:
        states_j = [φ(participants[i].embedding, j) for i in participants]
        state_vector[j] = combine_belnap_states(states_j)

    // Step 3: Compute weighted embedding
    e_agg = zeros(d)
    for i in participants:
        w_i = weights[i] * participants[i].confidence
        e_agg += w_i * participants[i].embedding
    e_agg /= sum(effective_weights)

    // Step 4: Return BOTH outputs
    return (e_agg, state_vector)
```

**Implementation**: `core/learning/src/aggregation.rs` — Only Step 3 exists. Steps 1-2 and dual return are missing.

### Algorithm 2: Routing

```
function route(query_embedding, e_agg, state_vector, node_profiles):
    input = concat(query_embedding, e_agg, encode_belnap(state_vector), node_profiles)
    hidden = relu(W1 @ input + b1)
    routing_weights = softmax(W2 @ hidden + b2)
    return routing_weights
```

The Belnap state vector is encoded as 2 bits per dimension (truth ordering bit + information ordering bit), adding 2d bits = d/4 bytes to the routing input.

**Implementation**: `core/learning/src/routing.rs` — MlpRouter exists but only takes a single embedding input, not the full (query, e_agg, state_vector, profiles) tuple.

### Algorithm 3: Three-Phase Learning Protocol (Paper II §4.3)

**Phase 1 — Embedding Collection**: Nodes include embeddings in blocks (~3KB overhead per block). No adapters generated. System learns which nodes are reliable.

**Phase 2 — Routing Activation**: Once routing model achieves confidence threshold (measured by entropy reduction over successive checkpoints), inference queries use learned routing instead of uniform distribution.

**Phase 3 — Adapter Generation**: Routing model identifies node weaknesses and generates targeted LoRA adapters. Adapters registered on-chain via LoRAFactory precompile (0x1003), distributed via IPFS.

**Implementation Note**: Sprint N maps this as OODA (Observe/Orient/Decide/Act), which is a reasonable operational mapping but NOT the paper's terminology. Paper II uses Phase 1/2/3 with specific meanings:
- Phase 1 = Pure data collection (no routing)
- Phase 2 = Routing active (no adapters)
- Phase 3 = Full system (routing + adapters)

The OODA cycle operates WITHIN each phase. This is a subtle but important distinction. The phases are long-lived states (days/weeks); OODA cycles happen per checkpoint (~5s).

**Sprint Gap**: Sprint N conflates the paper's 3 macro-phases with the per-checkpoint OODA micro-cycle. Both should be implemented but as separate state machines.

### Algorithm 4: Adapter Creation (Paper II §5)

LoRA adapters with rank r=16 default:
- `ΔW = B × A` where B ∈ ℝ^(d×r), A ∈ ℝ^(r×d)
- Bounded perturbation: `‖ΔW‖_s ≤ ‖B‖_s × ‖A‖_s`
- Clean rollback: remove adapter by setting ΔW = 0

**Implementation**: `core/learning/src/adapters.rs` — Current implementation uses embedding-level deltas, NOT actual LoRA matrices. The paper specifies LoRA (low-rank weight matrices), but the crate implements additive embedding deltas. This is a simplification that should be documented as such.

**Sprint Gap**: The sprint plans don't distinguish between embedding-level adapter deltas (what's implemented) and LoRA weight-matrix adapters (what the paper specifies). For testnet, embedding deltas may suffice, but the architecture should acknowledge this as a simplification.

### Algorithm 5: Adapter Verification

Verify adapter provenance chain and hash integrity.

**Implementation**: `core/learning/src/adapters.rs` — ProvenanceChain with validation. **COMPLETE** for the current abstraction level.

---

## 5. Theorems

### Theorem 1: Bounded Regression Under Perfect Routing (Paper II §5.3)

> If routing achieves perfect specialization (each query → exactly one adapter, no out-of-distribution application), max regression bounded by `‖ΔWᵢ‖_s × L` where L is the Lipschitz constant. Under imperfect routing with bounded error ε: `O(ε × maxᵢ ‖ΔWᵢ‖_s × L)`.

**Status**: `[Hypothesis]` — stated as a theorem but relies on perfect routing assumption. Degrades with routing error.

**Implementation**: Not directly testable until real LoRA adapters exist. The current embedding-delta system can verify a weaker version: adapter application doesn't increase embedding distance by more than `‖delta‖`.

### Theorem 2: Adapter Composition (Paper II §5.2)

> `compose(adapter_A, adapter_B)` produces a combined adapter. Composition is associative but NOT commutative.

**Implementation**: `core/learning/src/adapters.rs` — `compose_adapters()` adds deltas. **COMPLETE** for embedding-level. For LoRA, composition is more complex (TIES-Merging, KnOTS).

### Theorem 3: Safety Invariant (Paper II §7.1)

> For any block B, the state root after executing transactions is identical regardless of whether the learning pipeline is active.

**This is the most critical invariant.** Learning operates ON TOP of consensus; it NEVER modifies transaction execution, block ordering, or state transitions.

**Implementation**: `core/learning/src/safety.rs` — `SafetyGuard` with `verify_state_invariant()` and `LearningMode` enum. Mode defaults to Disabled. **COMPLETE** at interface level; integration test against real executor needed.

---

## 6. Extended Block & Checkpoint Structure (Paper II §6.1, §4.1)

### 6.1 Extended Block Fields (Optional)

Three new optional fields per block for learning-participating nodes:

| Field | Type | Size (d=768) | Purpose |
|-------|------|-------------|---------|
| `embedding` | `Vec<f32>` (d dimensions) | ~3 KB | Node's model output on reference input |
| `confidence` | `Vec<f32>` (d dimensions) | ~3 KB | Per-dimension softmax entropy confidence |
| `gradient_commitment` | `Hash` (32 bytes) | 32 B | SHA3 of gradient update (revealed next block) |

**Not yet in Block struct**: `core/consensus/src/types.rs` — The Block struct does NOT have these fields. They need to be added as Optional fields for backward compatibility.

### 6.2 Extended Checkpoint Fields

Three new fields at BFT finality checkpoints:

| Field | Type | Purpose |
|-------|------|---------|
| `routing_weights_hash` | `Hash` | Merkle root of routing model weights |
| `adapter_registry_hash` | `Hash` | Merkle root of active adapter registry |
| `performance_profile_hash` | `Hash` | Merkle root of per-node performance metrics |

**Not yet in Checkpoint struct**: These need to be added to the finality checkpoint structure.

**Backward compatibility**: Non-learning nodes ignore these fields. Consensus treats learning and non-learning nodes identically for ordering.

---

## 7. Integration Points with Existing Codebase

### 7.1 Consensus → Learning (Read-Only)

| What | Where | How |
|------|-------|-----|
| Blue scores | `core/consensus/src/ghostdag.rs` | `get_blue_score(&block_hash)` → trust weights |
| Finality events | `core/consensus/src/finality.rs` | Checkpoint event → trigger aggregation |
| Block embeddings | `core/consensus/src/types.rs` (new field) | Extract embeddings from finalized blocks |

### 7.2 Learning → Consensus (Write — Must Preserve Safety)

| What | Where | Constraint |
|------|-------|-----------|
| Embedding inclusion in blocks | `node/src/producer.rs` | Optional field; block valid without it |
| Checkpoint extension fields | `core/consensus/src/finality.rs` | Optional; checkpoint valid without them |
| Adapter registration | `core/execution/src/executor.rs` | Standard transaction; no special treatment |

### 7.3 Learning → Node (Integration)

| What | Where | How |
|------|-------|-----|
| Learning loop | `node/src/main.rs` or new `node/src/learning.rs` | Background task started after node init |
| Configuration | `node/config/` | New `[learning]` section in node TOML |
| RPC methods | `core/api/src/eth_rpc.rs` | New `citrate_learning*` methods |

---

## 8. Sprint Plan Cross-Check

### 8.1 Gaps Identified

| ID | Gap | Paper Section | Severity | Affected Sprint |
|----|-----|---------------|----------|----------------|
| GAP-1 | **φ classification function missing** — no function maps embeddings to Belnap states relative to query/majority | §3.1 (Definition 5) | **CRITICAL** — this is the core contribution | L or M |
| GAP-2 | **Aggregation outputs only e_agg, not state vector s** — weighted mean is standard FedAvg, not paraconsistent | §3.2 | **CRITICAL** — without state vector, system is just weighted averaging | M |
| GAP-3 | **Router doesn't take Belnap state vector as input** — loses all paraconsistent routing advantage | §4.2 | **HIGH** — routing without state vector = standard MoE | N |
| GAP-4 | **Embedding dimension default is 128, paper specifies 768** | Appendix A2 | **MEDIUM** — affects all downstream computations | L |
| GAP-5 | **Paper's 3 macro-phases conflated with OODA micro-cycle** — phases are long-lived network states, OODA operates per checkpoint | §4.3 | **MEDIUM** — architectural confusion if not separated | N |
| GAP-6 | **Block struct missing optional learning fields** — embedding, confidence, gradient_commitment | §6.1 | **HIGH** — required for any node-level integration | M or N |
| GAP-7 | **Checkpoint struct missing learning extension fields** — routing_weights_hash, adapter_registry_hash, performance_profile_hash | §4.1 | **HIGH** — required for learning synchronization | M |
| GAP-8 | **Adapters use embedding deltas, paper specifies LoRA matrices** — simplification not documented | §5 | **LOW** — acceptable for testnet if documented | O |
| GAP-9 | **No softmax(blue_score/τ) temperature parameter** — aggregation weights don't use temperature-controlled trust concentration | §3.2 | **MEDIUM** — affects trust distribution shape | M |
| GAP-10 | **No confidence vector (per-dimension softmax entropy)** in block or aggregation | §3.1, §6.1 | **HIGH** — φ classification requires per-dimension confidence | M |

### 8.2 Sprint-by-Sprint Validation

#### Sprint L: Paraconsensus Foundation (44 pts)

| WP | Paper Alignment | Status |
|----|----------------|--------|
| WP-L.1: Crate skeleton | OK — created | **DONE** (81 tests) |
| WP-L.2: Belnap FOUR | OK — complete | **DONE** |
| WP-L.3: Embeddings | OK — complete | **DONE** |
| WP-L.4: Knowledge state & types | OK — complete | **DONE** |
| WP-L.5: Error types & metrics | OK — complete | **DONE** |
| WP-L.6: Safety module | OK — complete | **DONE** |

**Verdict**: Sprint L is **COMPLETE** but with GAP-4 (dimension default).

#### Sprint M: Aggregation & Checkpoints (37 pts)

| WP | Paper Alignment | Issue |
|----|----------------|-------|
| WP-M.1: Weighted mean aggregation | **PARTIAL** — GAP-1, GAP-2, GAP-9, GAP-10 | Aggregation must output (e_agg, state_vector), not just e_agg |
| WP-M.2: Checkpoint integration | Missing GAP-7 | Checkpoint struct needs learning extension fields |
| WP-M.3: Embedding storage index | OK | **DONE** (in scaffold) |
| WP-M.4: Property-based tests | OK | Needs tests for dual-output aggregation |
| WP-M.5: Blue score normalization | Missing GAP-9 | Needs softmax(b/τ) with temperature parameter |

**Required additions to Sprint M**:
1. Implement φ classification function (GAP-1)
2. Make aggregation return `(e_agg, state_vector)` (GAP-2)
3. Add softmax temperature to weight computation (GAP-9)
4. Add per-dimension confidence vector to block/participant data (GAP-10)
5. Extend checkpoint struct with 3 learning hash fields (GAP-7)

#### Sprint N: Routing & Phase Transitions (44 pts)

| WP | Paper Alignment | Issue |
|----|----------------|-------|
| WP-N.1: MLP routing model | **PARTIAL** — GAP-3 | Router must accept (query, e_agg, state_vector, profiles) |
| WP-N.2: OODA phase transitions | **PARTIAL** — GAP-5 | Need separate macro-phase state machine (Phases 1/2/3) |
| WP-N.3: Byzantine detection | OK | Scaffold exists |
| WP-N.4: Phase persistence | OK | — |
| WP-N.5: Router-aggregation integration | **PARTIAL** | Must pipe state vector s to router |

**Required additions to Sprint N**:
1. Router input signature: `route(query, e_agg, state_vector, profiles)` (GAP-3)
2. Belnap state encoding: 2 bits per dimension → d/4 bytes (GAP-3)
3. Separate `NetworkPhase` (1/2/3) from `OodaPhase` (O/O/D/A) (GAP-5)
4. Phase transition criteria from paper: confidence threshold for Phase 1→2, adapter threshold for Phase 2→3

#### Sprint O: Adapters & Verification (55 pts)

| WP | Paper Alignment | Issue |
|----|----------------|-------|
| WP-O.1: Adapter creation | **PARTIAL** — GAP-8 | Using embedding deltas, not LoRA matrices — document as simplification |
| WP-O.2: Adapter composition | **PARTIAL** — GAP-8 | Same; paper discusses LoRA interference mitigations |
| WP-O.3: Provenance chain | OK | **DONE** (in scaffold) |
| WP-O.4: On-chain registration | OK | Needs LoRAFactory precompile (0x1003) integration |
| WP-O.5: E2E pipeline | Needs update | Pipeline must include φ + state vector + router with state vector |
| WP-O.6: Safety invariant | OK | Core safety test |

**Required additions to Sprint O**:
1. Document embedding-delta adapter as Phase 1 simplification (GAP-8)
2. Add adapter interference mitigation strategies from Paper II §5.3
3. E2E pipeline must test full φ → (e_agg, s) → route(query, e_agg, s) → adapt flow

---

## 9. Recommended Sprint Amendments

### Amendment 1: Add WP-L.7 — Belnap Classification Function φ (3 pts) ✅ APPLIED

**Status**: Applied to Sprint L as WP-L.7. Function `classify_belnap()` in `belnap.rs`. 6 new test cases (PC-T12a through PC-T12f).

### Amendment 2: Extend WP-M.1 — Dual-Output Aggregation (3 pts) ✅ APPLIED

**Status**: Applied to Sprint M. WP-M.1 now returns `AggregationResult { embedding, state_vector, confidence }`. 3 new test cases (PC-T13a through PC-T13c).

### Amendment 3: Add WP-M.2b — Block & Checkpoint Learning Fields (5 pts) ✅ APPLIED

**Status**: Applied to Sprint M as WP-M.2b. 3 new test cases (PC-T16a through PC-T16c).

### Amendment 4: Extend WP-N.1 — Router Takes State Vector (3 pts) ✅ APPLIED

**Status**: Applied to Sprint N. WP-N.1 signature: `route(query, e_agg, state_vector)`. 2 new test cases (PC-T23a, PC-T23b).

### Amendment 5: Add WP-N.2b — Macro-Phase State Machine (3 pts) ✅ APPLIED

**Status**: Applied to Sprint N as WP-N.2b. `NetworkLearningPhase { Collection, RoutingActive, FullSystem }`. 2 new test cases (PC-T29a, PC-T29b).

### Amendment 6: Fix Config Default (0 pts — trivial) ✅ APPLIED

**Status**: Applied directly to `core/learning/src/config.rs`. Default changed from 128 to 768. New fields added: `belnap_high_threshold`, `belnap_low_threshold`, `temperature`, `lora_rank`, `adapter_consolidation_interval`. 3 new config validation tests.

### LoRA + Confidence Gating (GAP-8 + additional) ✅ APPLIED

**Status**: Applied to Sprint O. WP-O.1 now specifies LoRA matrices instead of embedding deltas, with confidence-gated application. 4 new test cases (PC-T35a through PC-T35c, PC-T47).

**Total Additional Points**: 22 pts across Sprints L (+3), M (+11), N (+6), O (+5). Total program: 434 → 456 pts.

---

## 10. Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Per-Checkpoint Cycle (~5s)                     │
│                                                                   │
│  ┌──────────┐    ┌───────────────┐    ┌──────────────────────┐  │
│  │ OBSERVE   │    │ ORIENT         │    │ DECIDE                │  │
│  │           │    │                │    │                      │  │
│  │ Extract   │───▶│ 1. φ classify  │───▶│ Route(query,         │  │
│  │ embeddings│    │    each node   │    │       e_agg,         │  │
│  │ from      │    │ 2. Aggregate   │    │       state_vector,  │  │
│  │ finalized │    │    → (e_agg, s)│    │       profiles)      │  │
│  │ blocks    │    │ 3. Update      │    │    → routing weights │  │
│  │           │    │    state_vector│    │                      │  │
│  └──────────┘    └───────────────┘    └──────────┬───────────┘  │
│                                                    │              │
│  ┌──────────────────────────────────────────────┐ │              │
│  │ ACT                                           │◀┘              │
│  │                                               │                │
│  │ If Phase 3: Generate LoRA adapters           │                │
│  │ Register on-chain (LoRAFactory 0x1003)        │                │
│  │ Distribute via IPFS                           │                │
│  │ Update routing model weights at checkpoint    │                │
│  └──────────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────┘

Macro-Phase Transitions:
  Phase 1 (Collection) ──[confidence threshold]──▶ Phase 2 (Routing Active)
  Phase 2 ──[adapter threshold]──▶ Phase 3 (Full System with LoRA)
```

---

## 11. Safety Architecture

### 11.1 Critical Invariant

**Learning NEVER modifies**:
- Block ordering (GhostDAG blue/red classification)
- Transaction execution (LVM state transitions)
- State root computation
- Finality determination

**Learning ONLY reads from consensus**:
- Blue scores (for trust weights)
- Finality checkpoints (for synchronization)
- Block embeddings (for aggregation)

### 11.2 Defense in Depth

| Layer | Mechanism | Implementation |
|-------|-----------|----------------|
| Mode | `LearningMode::Disabled` by default | `safety.rs` |
| State isolation | Learning state separate from execution state | `safety.rs:verify_state_invariant()` |
| Slashing | 10% stake for embedding manipulation | `verification.rs` |
| Byzantine detection | 3σ outlier + Belnap inconsistency + repeated divergence | `verification.rs` |
| Adapter bounds | Spectral norm bound `‖ΔW‖_s` | Theorem 1 |
| Rollback | Adapters removable by subtraction | LoRA structural property |

### 11.3 Failure Modes

| Failure | Impact | Mitigation |
|---------|--------|------------|
| Routing model poorly trained | System degrades to weighted averaging (safe) | Paper II §3.3 |
| Byzantine >1/3 embedding manipulation | Learning results corrupted, consensus unaffected | Blue-score down-weighting + slashing |
| Adapter interference | Model performance degrades | Consolidation + retirement (Paper II §5.3) |
| Learning fields missing from blocks | System operates as vanilla GhostDAG (safe) | Backward compatibility |

---

## 12. File Map

| File | Paper Element | Status |
|------|--------------|--------|
| `belnap.rs` | Def 1: Belnap FOUR | COMPLETE |
| `embeddings.rs` | Def 2-3: Embedding space, similarity | COMPLETE |
| `knowledge.rs` | Def 4: Knowledge state | COMPLETE |
| `aggregation.rs` | Algorithm 1: Aggregation (partial — needs φ + dual output) | PARTIAL |
| `routing.rs` | Algorithm 2: Routing (partial — needs state vector input) | PARTIAL |
| `phases.rs` | Algorithm 3: Phase transitions (needs macro-phase separation) | PARTIAL |
| `adapters.rs` | Algorithm 4-5: Adapter creation/verification | COMPLETE (embedding-level) |
| `verification.rs` | Byzantine detection | COMPLETE |
| `checkpoint.rs` | Checkpoint structure (needs extension fields) | PARTIAL |
| `safety.rs` | Theorem 3: Safety invariant | COMPLETE (interface) |
| `config.rs` | Parameters (needs dimension fix) | NEEDS UPDATE |
| `types.rs` | Data structures 1-2 | COMPLETE |
| `storage.rs` | Data structure 4: Embedding index | COMPLETE |
| `metrics.rs` | Prometheus metrics | COMPLETE |
| `errors.rs` | Error types | COMPLETE |

---

## 13. Verification Plan

### 13.1 Test Categories

| Category | Count | Source |
|----------|-------|--------|
| Belnap lattice axioms (property) | 8 | Sprint L (done) |
| Embedding operations (unit) | 12 | Sprint L (done) |
| Config/types (unit) | 10 | Sprint L (done) |
| Aggregation (unit + property) | 10 | Sprint M |
| **φ classification (unit + property)** | **6** | **NEW — Amendment 1** |
| Routing (unit + performance) | 8 | Sprint N |
| Phase transitions (unit + integration) | 8 | Sprint N |
| Byzantine detection (adversarial) | 4 | Sprint N |
| Adapter lifecycle (unit + integration) | 8 | Sprint O |
| Safety invariant (safety) | 4 | Sprint O |
| E2E pipeline (integration) | 2 | Sprint O |
| Performance benchmarks | 2 | Sprint O |

**Total**: ~82 existing + ~6 new φ tests = ~88 test cases

### 13.2 Experimental Hypotheses (Paper II §8)

These are NOT sprint deliverables but future testnet validation:

1. **H1**: Paraconsistent aggregation outperforms weighted averaging on heterogeneous network (N=50-100 nodes)
2. **H2**: LoRA adapters improve weak domains without bounded regression over 10,000 checkpoints
3. **H3**: Learning converges under f<n/3 Byzantine nodes with adversarial embeddings

---

*This document is the authoritative architectural reference for the Paraconsensus implementation. All sprint plans (L-O) should be validated against this document. Any discrepancy between a sprint plan and this document is an error in the sprint plan.*
