//! Adapter creation and composition.
//!
//! Implements Algorithm 4, Definition 8-9, and Theorem 2 from Gradient Papers No. II.
//! Supports both legacy delta-based adapters and LoRA (Low-Rank Adaptation) adapters.

use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::types::{Hash, PublicKey, Signature};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A learning adapter — a lightweight delta with provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningAdapter {
    /// Unique identifier (hash of delta + metadata).
    pub id: Hash,
    /// The embedding delta.
    pub delta: EmbeddingVector,
    /// Adapter metadata.
    pub metadata: AdapterMetadata,
    /// Creator's public key.
    pub creator: PublicKey,
    /// Checkpoint height at which this adapter was produced.
    pub checkpoint_height: u64,
    /// Provenance chain.
    pub provenance: ProvenanceChain,
}

/// Adapter metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetadata {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Learning round that produced this adapter.
    pub round: u64,
    /// Number of participants in the aggregation.
    pub participant_count: usize,
    /// Creation timestamp.
    pub created_at: u64,
}

/// A provenance chain linking an adapter to its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceChain {
    /// Ordered list of provenance entries.
    pub entries: Vec<ProvenanceEntry>,
}

/// A single provenance entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    /// Creator of this entry.
    pub creator: PublicKey,
    /// Learning round.
    pub round: u64,
    /// Checkpoint height.
    pub checkpoint_height: u64,
    /// Hash of the parent adapter (None for root).
    pub parent_adapter_hash: Option<Hash>,
    /// Timestamp.
    pub timestamp: u64,
    /// Signature over this entry.
    pub signature: Signature,
}

impl ProvenanceChain {
    /// Create a new provenance chain with a single root entry.
    pub fn new(entry: ProvenanceEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Append an entry to the chain.
    pub fn append(&mut self, entry: ProvenanceEntry) {
        self.entries.push(entry);
    }

    /// Validate the chain: each entry must link to the previous.
    pub fn validate(&self) -> LearningResult<()> {
        for i in 1..self.entries.len() {
            let prev_hash = compute_entry_hash(&self.entries[i - 1]);
            match &self.entries[i].parent_adapter_hash {
                Some(h) if *h == prev_hash => {}
                Some(_) => {
                    return Err(LearningError::AdapterError {
                        reason: format!("broken provenance chain at entry {}", i),
                    });
                }
                None => {
                    return Err(LearningError::AdapterError {
                        reason: format!("missing parent hash at entry {}", i),
                    });
                }
            }
        }
        Ok(())
    }

    /// Get the length of the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the hash of a provenance entry.
fn compute_entry_hash(entry: &ProvenanceEntry) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(entry.creator);
    hasher.update(entry.round.to_le_bytes());
    hasher.update(entry.checkpoint_height.to_le_bytes());
    if let Some(ref parent) = entry.parent_adapter_hash {
        hasher.update(parent);
    }
    hasher.update(entry.timestamp.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Factory for creating learning adapters.
pub struct AdapterFactory;

impl AdapterFactory {
    /// Create a new adapter from an aggregated embedding.
    pub fn create(
        delta: EmbeddingVector,
        metadata: AdapterMetadata,
        creator: PublicKey,
        checkpoint_height: u64,
        signature: Signature,
    ) -> LearningResult<LearningAdapter> {
        let id = Self::compute_id(&delta, &metadata);

        let provenance = ProvenanceChain::new(ProvenanceEntry {
            creator,
            round: metadata.round,
            checkpoint_height,
            parent_adapter_hash: None,
            timestamp: metadata.created_at,
            signature,
        });

        Ok(LearningAdapter {
            id,
            delta,
            metadata,
            creator,
            checkpoint_height,
            provenance,
        })
    }

    /// Compute the unique ID for an adapter.
    pub fn compute_id(delta: &EmbeddingVector, metadata: &AdapterMetadata) -> Hash {
        let mut hasher = Sha3_256::new();
        for v in &delta.data {
            hasher.update(v.to_le_bytes());
        }
        hasher.update(metadata.name.as_bytes());
        hasher.update(metadata.round.to_le_bytes());
        hasher.update(metadata.created_at.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify an adapter's hash matches its content.
    pub fn verify_hash(adapter: &LearningAdapter) -> bool {
        let expected = Self::compute_id(&adapter.delta, &adapter.metadata);
        adapter.id == expected
    }
}

/// Apply an adapter to a base embedding.
pub fn apply_adapter(
    base: &EmbeddingVector,
    adapter: &LearningAdapter,
) -> LearningResult<EmbeddingVector> {
    base.add(&adapter.delta)
}

/// Compose two adapters sequentially.
///
/// Theorem 2: compose(A, B) produces a new adapter whose delta
/// is the sum of A's and B's deltas.
pub fn compose_adapters(
    first: &LearningAdapter,
    second: &LearningAdapter,
) -> LearningResult<EmbeddingVector> {
    first.delta.add(&second.delta)
}

// ---------------------------------------------------------------------------
// LoRA (Low-Rank Adaptation) Adapters — Paper II Algorithm 4, Theorem 2
// ---------------------------------------------------------------------------

/// A LoRA adapter — a low-rank factorization ΔW = A × B with provenance.
///
/// Paper II specifies LoRA because:
/// 1. Bounded by spectral norm (Theorem 2)
/// 2. Cleanly removable (subtract = rollback)
/// 3. Well-understood interference properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraAdapter {
    /// Unique identifier (hash of A, B matrices + metadata).
    pub id: Hash,
    /// Low-rank factor A ∈ R^(d×r). Outer dimensions: d rows, r columns.
    pub matrix_a: Vec<Vec<f32>>,
    /// Low-rank factor B ∈ R^(r×d). Outer dimensions: r rows, d columns.
    pub matrix_b: Vec<Vec<f32>>,
    /// Rank of the factorization.
    pub rank: usize,
    /// Embedding dimensionality.
    pub dim: usize,
    /// Adapter metadata.
    pub metadata: AdapterMetadata,
    /// Creator's public key.
    pub creator: PublicKey,
    /// Checkpoint height at which this adapter was produced.
    pub checkpoint_height: u64,
    /// Provenance chain.
    pub provenance: ProvenanceChain,
}

impl AdapterFactory {
    /// Create a LoRA adapter from an aggregated embedding.
    ///
    /// Initializes A and B matrices from the embedding vector:
    /// - A[:,j] = embedding * scale_factor (for each rank column)
    /// - B[j,:] = uniform 1/d (for each rank row)
    ///
    /// This ensures the initial ΔW = A×B approximates a scaled outer product
    /// of the embedding, providing a meaningful starting point for adaptation.
    #[allow(clippy::needless_range_loop)]
    pub fn create_lora(
        embedding: &EmbeddingVector,
        rank: usize,
        metadata: AdapterMetadata,
        creator: PublicKey,
        checkpoint_height: u64,
        signature: Signature,
    ) -> LearningResult<LoraAdapter> {
        let dim = embedding.dim();
        if rank == 0 || rank > dim {
            return Err(LearningError::AdapterError {
                reason: format!("invalid rank {}: must be in [1, {}]", rank, dim),
            });
        }

        // Initialize A: d × r matrix
        // Each column is a scaled version of the embedding
        let scale = 1.0 / (rank as f32).sqrt();
        let mut matrix_a = vec![vec![0.0f32; rank]; dim];
        for i in 0..dim {
            for j in 0..rank {
                matrix_a[i][j] = embedding.data[i] * scale * ((j + 1) as f32 / rank as f32);
            }
        }

        // Initialize B: r × d matrix
        // Each row is uniform 1/d to start (low-magnitude)
        let b_val = 1.0 / dim as f32;
        let mut matrix_b = vec![vec![0.0f32; dim]; rank];
        for j in 0..rank {
            for i in 0..dim {
                matrix_b[j][i] = b_val * ((j + 1) as f32 / rank as f32);
            }
        }

        let id = Self::compute_lora_id(&matrix_a, &matrix_b, &metadata, &creator, checkpoint_height);

        let provenance = ProvenanceChain::new(ProvenanceEntry {
            creator,
            round: metadata.round,
            checkpoint_height,
            parent_adapter_hash: None,
            timestamp: metadata.created_at,
            signature,
        });

        Ok(LoraAdapter {
            id,
            matrix_a,
            matrix_b,
            rank,
            dim,
            metadata,
            creator,
            checkpoint_height,
            provenance,
        })
    }

    /// Compute the unique ID for a LoRA adapter.
    pub fn compute_lora_id(
        matrix_a: &[Vec<f32>],
        matrix_b: &[Vec<f32>],
        metadata: &AdapterMetadata,
        creator: &PublicKey,
        checkpoint_height: u64,
    ) -> Hash {
        let mut hasher = Sha3_256::new();
        for row in matrix_a {
            for v in row {
                hasher.update(v.to_le_bytes());
            }
        }
        for row in matrix_b {
            for v in row {
                hasher.update(v.to_le_bytes());
            }
        }
        hasher.update(metadata.name.as_bytes());
        hasher.update(metadata.round.to_le_bytes());
        hasher.update(metadata.created_at.to_le_bytes());
        // Bind creator + checkpoint into the identity so an attacker cannot take
        // a victim's adapter, rewrite `creator`, and still pass hash verification.
        hasher.update(creator);
        hasher.update(checkpoint_height.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify a LoRA adapter's hash matches its content.
    pub fn verify_lora_hash(adapter: &LoraAdapter) -> bool {
        let expected = Self::compute_lora_id(&adapter.matrix_a, &adapter.matrix_b, &adapter.metadata, &adapter.creator, adapter.checkpoint_height);
        adapter.id == expected
    }
}

/// Compute (A × B) · v efficiently as A · (B · v).
///
/// A: d×r, B: r×d, v: d-dimensional → result: d-dimensional
#[allow(clippy::needless_range_loop)]
fn matmul_ab_vector(a: &[Vec<f32>], b: &[Vec<f32>], v: &[f32]) -> Vec<f32> {
    let rank = b.len();
    let dim = v.len();

    // Step 1: Bv = B · v (r-dimensional)
    let mut bv = vec![0.0f32; rank];
    for j in 0..rank {
        let mut sum = 0.0f32;
        for i in 0..dim {
            sum += b[j][i] * v[i];
        }
        bv[j] = sum;
    }

    // Step 2: A · Bv (d-dimensional)
    let mut result = vec![0.0f32; dim];
    for i in 0..dim {
        let mut sum = 0.0f32;
        for j in 0..rank {
            sum += a[i][j] * bv[j];
        }
        result[i] = sum;
    }

    result
}

/// Apply a LoRA adapter to a base embedding: W' = W + (A×B)·W
///
/// In practice, since W is a vector (not a matrix), this computes
/// base + (A × B) · base.
pub fn apply_lora(
    base: &EmbeddingVector,
    adapter: &LoraAdapter,
) -> LearningResult<EmbeddingVector> {
    if base.dim() != adapter.dim {
        return Err(LearningError::DimensionMismatch {
            expected: adapter.dim,
            got: base.dim(),
        });
    }

    let delta = matmul_ab_vector(&adapter.matrix_a, &adapter.matrix_b, &base.data);
    let mut result = base.data.clone();
    for i in 0..result.len() {
        result[i] += delta[i];
    }

    EmbeddingVector::new(result)
}

/// Remove a LoRA adapter from a modified embedding: W = W' - (A×B)·W_base
///
/// Requires the original base to compute the exact delta that was added.
pub fn remove_lora(
    modified: &EmbeddingVector,
    base: &EmbeddingVector,
    adapter: &LoraAdapter,
) -> LearningResult<EmbeddingVector> {
    if modified.dim() != adapter.dim || base.dim() != adapter.dim {
        return Err(LearningError::DimensionMismatch {
            expected: adapter.dim,
            got: modified.dim(),
        });
    }

    let delta = matmul_ab_vector(&adapter.matrix_a, &adapter.matrix_b, &base.data);
    let mut result = modified.data.clone();
    for i in 0..result.len() {
        result[i] -= delta[i];
    }

    EmbeddingVector::new(result)
}

/// Apply a LoRA adapter with confidence gating.
///
/// Only applies the adapter delta at dimensions where confidence[j] > threshold.
/// Dimensions below the threshold retain their original base value.
pub fn apply_lora_confidence_gated(
    base: &EmbeddingVector,
    adapter: &LoraAdapter,
    confidence: &[f32],
    threshold: f32,
) -> LearningResult<EmbeddingVector> {
    if base.dim() != adapter.dim {
        return Err(LearningError::DimensionMismatch {
            expected: adapter.dim,
            got: base.dim(),
        });
    }
    if confidence.len() != adapter.dim {
        return Err(LearningError::DimensionMismatch {
            expected: adapter.dim,
            got: confidence.len(),
        });
    }

    let delta = matmul_ab_vector(&adapter.matrix_a, &adapter.matrix_b, &base.data);
    let mut result = base.data.clone();
    for i in 0..result.len() {
        if confidence[i] > threshold {
            result[i] += delta[i];
        }
    }

    EmbeddingVector::new(result)
}

/// Compute the Frobenius norm of A×B as an upper bound on spectral norm.
///
/// ‖A×B‖_F = sqrt(Σ_ij (A×B)_ij²)
///
/// This is an upper bound on the spectral norm ‖A×B‖_s, which is
/// sufficient for Theorem 2 bound checking.
#[allow(clippy::needless_range_loop)]
pub fn spectral_norm_bound(adapter: &LoraAdapter) -> f32 {
    let dim = adapter.dim;
    let rank = adapter.rank;

    // Compute (A×B) explicitly and accumulate Frobenius norm
    let mut frobenius_sq = 0.0f32;
    for i in 0..dim {
        for k in 0..dim {
            let mut val = 0.0f32;
            for j in 0..rank {
                val += adapter.matrix_a[i][j] * adapter.matrix_b[j][k];
            }
            frobenius_sq += val * val;
        }
    }

    frobenius_sq.sqrt()
}

/// Compose two LoRA adapters via rank concatenation.
///
/// Given adapter1 with (A1: d×r1, B1: r1×d) and adapter2 with (A2: d×r2, B2: r2×d),
/// produces a new adapter with A_new = [A1 | A2] (d × (r1+r2)) and
/// B_new = [B1; B2] ((r1+r2) × d).
///
/// This ensures: A_new × B_new = A1×B1 + A2×B2
#[allow(clippy::needless_range_loop)]
pub fn compose_lora(
    first: &LoraAdapter,
    second: &LoraAdapter,
    metadata: AdapterMetadata,
    creator: PublicKey,
    checkpoint_height: u64,
    _signature: Signature,
) -> LearningResult<LoraAdapter> {
    if first.dim != second.dim {
        return Err(LearningError::DimensionMismatch {
            expected: first.dim,
            got: second.dim,
        });
    }

    let dim = first.dim;
    let new_rank = first.rank + second.rank;

    // A_new = [A1 | A2]: d × (r1+r2)
    let mut matrix_a = vec![vec![0.0f32; new_rank]; dim];
    for i in 0..dim {
        for j in 0..first.rank {
            matrix_a[i][j] = first.matrix_a[i][j];
        }
        for j in 0..second.rank {
            matrix_a[i][first.rank + j] = second.matrix_a[i][j];
        }
    }

    // B_new = [B1; B2]: (r1+r2) × d
    let mut matrix_b = vec![vec![0.0f32; dim]; new_rank];
    for j in 0..first.rank {
        for i in 0..dim {
            matrix_b[j][i] = first.matrix_b[j][i];
        }
    }
    for j in 0..second.rank {
        for i in 0..dim {
            matrix_b[first.rank + j][i] = second.matrix_b[j][i];
        }
    }

    let id = AdapterFactory::compute_lora_id(&matrix_a, &matrix_b, &metadata, &creator, checkpoint_height);

    let mut provenance = first.provenance.clone();
    for entry in &second.provenance.entries {
        provenance.append(entry.clone());
    }

    Ok(LoraAdapter {
        id,
        matrix_a,
        matrix_b,
        rank: new_rank,
        dim,
        metadata,
        creator,
        checkpoint_height,
        provenance,
    })
}

/// Compose a chain of LoRA adapters via sequential rank concatenation.
pub fn compose_lora_chain(
    adapters: &[&LoraAdapter],
    metadata: AdapterMetadata,
    creator: PublicKey,
    checkpoint_height: u64,
    signature: Signature,
) -> LearningResult<LoraAdapter> {
    if adapters.is_empty() {
        return Err(LearningError::AdapterError {
            reason: "empty adapter chain".to_string(),
        });
    }
    if adapters.len() == 1 {
        return Ok(adapters[0].clone());
    }

    let mut result = compose_lora(
        adapters[0],
        adapters[1],
        metadata.clone(),
        creator,
        checkpoint_height,
        signature,
    )?;

    for adapter in &adapters[2..] {
        result = compose_lora(
            &result,
            adapter,
            metadata.clone(),
            creator,
            checkpoint_height,
            vec![0u8; 64],
        )?;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Adapter Registry — DashMap-backed in-memory store (WP-O.4)
// ---------------------------------------------------------------------------

/// Thread-safe adapter registry for LoRA adapters.
///
/// Provides registration, lookup, and query by creator.
/// In-memory store using DashMap for concurrent access.
pub struct AdapterRegistry {
    adapters: DashMap<Hash, LoraAdapter>,
}

impl AdapterRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            adapters: DashMap::new(),
        }
    }

    /// Register an adapter. Returns its hash.
    pub fn register(&self, adapter: LoraAdapter) -> LearningResult<Hash> {
        // Recompute the id rather than trusting the caller's self-declared
        // `adapter.id`. Keying on an unverified id let an attacker register under
        // a legitimate adapter's hash (and `insert` silently overwrote it),
        // stealing and replacing attribution for a paid contribution type.
        let expected = AdapterFactory::compute_lora_id(&adapter.matrix_a, &adapter.matrix_b, &adapter.metadata, &adapter.creator, adapter.checkpoint_height);
        if adapter.id != expected {
            return Err(LearningError::AdapterError {
                reason: "adapter id does not match its content hash".to_string(),
            });
        }
        if self.adapters.contains_key(&expected) {
            return Err(LearningError::AdapterError {
                reason: "an adapter with this id is already registered".to_string(),
            });
        }
        self.adapters.insert(expected, adapter);
        Ok(expected)
    }

    /// Query an adapter by hash.
    pub fn query(&self, hash: &Hash) -> Option<LoraAdapter> {
        self.adapters.get(hash).map(|r| r.clone())
    }

    /// List all adapters by a specific creator.
    pub fn list_by_creator(&self, creator: &PublicKey) -> Vec<LoraAdapter> {
        self.adapters
            .iter()
            .filter(|r| r.value().creator == *creator)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Number of registered adapters.
    pub fn count(&self) -> usize {
        self.adapters.len()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metadata(round: u64) -> AdapterMetadata {
        AdapterMetadata {
            name: "test-adapter".to_string(),
            description: "A test adapter".to_string(),
            round,
            participant_count: 5,
            created_at: 12345,
        }
    }

    // PC-T35: Adapter creation
    #[test]
    fn test_adapter_creation() {
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta.clone(),
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        assert_eq!(adapter.creator, [1u8; 32]);
        assert_eq!(adapter.checkpoint_height, 100);
        assert_eq!(adapter.provenance.len(), 1);
    }

    // PC-T36: Adapter application
    #[test]
    fn test_adapter_application() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta,
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        let result = apply_adapter(&base, &adapter).unwrap();
        assert!((result.data[0] - 1.1).abs() < 1e-6);
        assert!((result.data[1] - 1.8).abs() < 1e-6);
        assert!((result.data[2] - 3.3).abs() < 1e-6);
    }

    // PC-T37: Adapter hash verification
    #[test]
    fn test_hash_verification() {
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta,
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        assert!(AdapterFactory::verify_hash(&adapter));

        // Tamper with adapter
        let mut tampered = adapter.clone();
        tampered.delta.data[0] = 999.0;
        assert!(!AdapterFactory::verify_hash(&tampered));
    }

    // PC-T38: Adapter composition
    #[test]
    fn test_adapter_composition() {
        let delta1 = EmbeddingVector::new(vec![0.1, 0.2]).unwrap();
        let delta2 = EmbeddingVector::new(vec![0.3, -0.1]).unwrap();

        let a1 = AdapterFactory::create(delta1, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();
        let a2 = AdapterFactory::create(delta2, test_metadata(2), [2u8; 32], 200, vec![0u8; 64]).unwrap();

        let composed = compose_adapters(&a1, &a2).unwrap();
        assert!((composed.data[0] - 0.4).abs() < 1e-6);
        assert!((composed.data[1] - 0.1).abs() < 1e-6);
    }

    // PC-T39: Provenance chain
    #[test]
    fn test_provenance_chain() {
        let entry = ProvenanceEntry {
            creator: [1u8; 32],
            round: 1,
            checkpoint_height: 100,
            parent_adapter_hash: None,
            timestamp: 12345,
            signature: vec![0u8; 64],
        };

        let chain = ProvenanceChain::new(entry);
        assert_eq!(chain.len(), 1);
        assert!(chain.validate().is_ok());
    }

    // PC-T41: Adapter theft rejection
    #[test]
    fn test_provenance_chain_broken() {
        let entry1 = ProvenanceEntry {
            creator: [1u8; 32],
            round: 1,
            checkpoint_height: 100,
            parent_adapter_hash: None,
            timestamp: 12345,
            signature: vec![0u8; 64],
        };

        let entry2 = ProvenanceEntry {
            creator: [2u8; 32],
            round: 2,
            checkpoint_height: 200,
            parent_adapter_hash: Some([0xff; 32]), // Wrong parent hash
            timestamp: 12346,
            signature: vec![0u8; 64],
        };

        let mut chain = ProvenanceChain::new(entry1);
        chain.append(entry2);
        assert!(chain.validate().is_err());
    }

    // ========================================================================
    // LoRA Adapter Tests (Sprint O)
    // ========================================================================

    fn create_test_lora(dim: usize, rank: usize, round: u64) -> LoraAdapter {
        let embedding = EmbeddingVector::new(vec![1.0; dim]).unwrap();
        AdapterFactory::create_lora(
            &embedding,
            rank,
            test_metadata(round),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap()
    }

    // PC-T35: LoRA adapter creation
    #[test]
    fn test_lora_adapter_creation() {
        let dim = 4;
        let rank = 2;
        let embedding = EmbeddingVector::new(vec![1.0, 0.5, -0.3, 0.8]).unwrap();
        let adapter = AdapterFactory::create_lora(
            &embedding,
            rank,
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        assert_eq!(adapter.dim, dim);
        assert_eq!(adapter.rank, rank);
        assert_eq!(adapter.matrix_a.len(), dim); // d rows
        assert_eq!(adapter.matrix_a[0].len(), rank); // r columns
        assert_eq!(adapter.matrix_b.len(), rank); // r rows
        assert_eq!(adapter.matrix_b[0].len(), dim); // d columns
        assert_eq!(adapter.creator, [1u8; 32]);
        assert_eq!(adapter.checkpoint_height, 100);
        assert_eq!(adapter.provenance.len(), 1);
        assert!(AdapterFactory::verify_lora_hash(&adapter));
    }

    // PC-T35a: LoRA removal restores base weights
    #[test]
    fn test_lora_removal_restores_base() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let adapter = create_test_lora(4, 2, 1);

        let modified = apply_lora(&base, &adapter).unwrap();
        // Modified should differ from base
        assert!((modified.data[0] - base.data[0]).abs() > 1e-10);

        let restored = remove_lora(&modified, &base, &adapter).unwrap();
        // Restored should equal base
        for i in 0..4 {
            assert!(
                (restored.data[i] - base.data[i]).abs() < 1e-6,
                "dim {} mismatch: {} vs {}",
                i,
                restored.data[i],
                base.data[i]
            );
        }
    }

    // PC-T35b: Spectral norm within bound
    #[test]
    fn test_lora_spectral_norm_bounded() {
        let adapter = create_test_lora(4, 2, 1);
        let norm = spectral_norm_bound(&adapter);
        // Norm should be finite and positive
        assert!(norm > 0.0, "norm should be positive");
        assert!(norm.is_finite(), "norm should be finite");
        // For our small initialization the norm should be reasonably bounded
        assert!(norm < 100.0, "norm {} should be reasonably bounded", norm);
    }

    // PC-T35c: Confidence-gated partial application
    #[test]
    fn test_lora_confidence_gated_application() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let adapter = create_test_lora(4, 2, 1);

        // High confidence on dims 0,1; low on dims 2,3
        let confidence = vec![0.9, 0.8, 0.1, 0.2];
        let threshold = 0.5;

        let result = apply_lora_confidence_gated(&base, &adapter, &confidence, threshold).unwrap();
        let full_result = apply_lora(&base, &adapter).unwrap();

        // Dims 0,1 should match full LoRA application
        assert!((result.data[0] - full_result.data[0]).abs() < 1e-6);
        assert!((result.data[1] - full_result.data[1]).abs() < 1e-6);

        // Dims 2,3 should remain at base values (gated out)
        assert!((result.data[2] - base.data[2]).abs() < 1e-6);
        assert!((result.data[3] - base.data[3]).abs() < 1e-6);
    }

    // PC-T36: LoRA application to base model
    #[test]
    fn test_lora_application() {
        let base = EmbeddingVector::new(vec![1.0, 0.5, -0.3, 0.8]).unwrap();
        let adapter = create_test_lora(4, 2, 1);

        let result = apply_lora(&base, &adapter).unwrap();
        assert_eq!(result.dim(), 4);

        // Result should differ from base (adapter applies a non-zero delta)
        let mut diff_sum = 0.0f32;
        for i in 0..4 {
            diff_sum += (result.data[i] - base.data[i]).abs();
        }
        assert!(diff_sum > 1e-10, "LoRA should modify the embedding");
    }

    // PC-T37: LoRA hash verification
    #[test]
    fn test_lora_hash_verification() {
        let adapter = create_test_lora(4, 2, 1);
        assert!(AdapterFactory::verify_lora_hash(&adapter));

        // Tamper with matrix
        let mut tampered = adapter.clone();
        tampered.matrix_a[0][0] = 999.0;
        assert!(!AdapterFactory::verify_lora_hash(&tampered));
    }

    // PC-T38: LoRA composition (stack two)
    #[test]
    fn test_lora_composition() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let a1 = create_test_lora(4, 2, 1);
        let a2 = create_test_lora(4, 2, 2);

        // Compose
        let composed = compose_lora(
            &a1, &a2, test_metadata(3), [3u8; 32], 300, vec![0u8; 64],
        )
        .unwrap();

        assert_eq!(composed.rank, 4); // r1 + r2
        assert_eq!(composed.dim, 4);
        assert_eq!(composed.matrix_a.len(), 4);
        assert_eq!(composed.matrix_a[0].len(), 4); // rank = 4
        assert_eq!(composed.matrix_b.len(), 4);

        // Verify: applying composed adapter ≈ applying both individually
        let result_composed = apply_lora(&base, &composed).unwrap();

        let result_seq = {
            // For rank-concatenation: compose(a1, a2) applied to base
            // equals a1 applied to base + a2 applied to base (both deltas from same base)
            let delta_a1 = matmul_ab_vector(&a1.matrix_a, &a1.matrix_b, &base.data);
            let delta_a2 = matmul_ab_vector(&a2.matrix_a, &a2.matrix_b, &base.data);
            let mut result = base.data.clone();
            for i in 0..4 {
                result[i] += delta_a1[i] + delta_a2[i];
            }
            EmbeddingVector::new(result).unwrap()
        };

        for i in 0..4 {
            assert!(
                (result_composed.data[i] - result_seq.data[i]).abs() < 1e-5,
                "dim {} mismatch: composed={} seq={}",
                i,
                result_composed.data[i],
                result_seq.data[i]
            );
        }
    }

    // PC-T38a: Composition associativity
    #[test]
    fn test_lora_composition_associativity() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();

        // Create 3 adapters with different embeddings
        let e1 = EmbeddingVector::new(vec![1.0, 0.0, 0.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![0.0, 1.0, 0.0]).unwrap();
        let e3 = EmbeddingVector::new(vec![0.0, 0.0, 1.0]).unwrap();

        let a = AdapterFactory::create_lora(&e1, 2, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();
        let b = AdapterFactory::create_lora(&e2, 2, test_metadata(2), [2u8; 32], 200, vec![0u8; 64]).unwrap();
        let c = AdapterFactory::create_lora(&e3, 2, test_metadata(3), [3u8; 32], 300, vec![0u8; 64]).unwrap();

        // compose(a, compose(b, c))
        let bc = compose_lora(&b, &c, test_metadata(4), [4u8; 32], 400, vec![0u8; 64]).unwrap();
        let a_bc = compose_lora(&a, &bc, test_metadata(5), [5u8; 32], 500, vec![0u8; 64]).unwrap();

        // compose(compose(a, b), c)
        let ab = compose_lora(&a, &b, test_metadata(4), [4u8; 32], 400, vec![0u8; 64]).unwrap();
        let ab_c = compose_lora(&ab, &c, test_metadata(5), [5u8; 32], 500, vec![0u8; 64]).unwrap();

        // Apply both to base — results should be identical
        let result_1 = apply_lora(&base, &a_bc).unwrap();
        let result_2 = apply_lora(&base, &ab_c).unwrap();

        for i in 0..3 {
            assert!(
                (result_1.data[i] - result_2.data[i]).abs() < 1e-5,
                "dim {} not associative: {} vs {}",
                i,
                result_1.data[i],
                result_2.data[i]
            );
        }
    }

    // PC-T40: Adapter registration + query
    #[test]
    fn test_adapter_registry() {
        let registry = AdapterRegistry::new();
        let creator1 = [1u8; 32];
        let creator2 = [2u8; 32];

        let e1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let a1 = AdapterFactory::create_lora(&e1, 1, test_metadata(1), creator1, 100, vec![0u8; 64]).unwrap();
        let a1_id = a1.id;

        let e2 = EmbeddingVector::new(vec![3.0, 4.0]).unwrap();
        let a2 = AdapterFactory::create_lora(&e2, 1, test_metadata(2), creator2, 200, vec![0u8; 64]).unwrap();

        // Register
        let hash1 = registry.register(a1).unwrap();
        let hash2 = registry.register(a2).unwrap();
        assert_eq!(registry.count(), 2);

        // Query by hash
        let found = registry.query(&hash1).unwrap();
        assert_eq!(found.id, a1_id);
        assert_eq!(found.creator, creator1);

        // Missing hash
        assert!(registry.query(&[0u8; 32]).is_none());

        // List by creator
        let by_c1 = registry.list_by_creator(&creator1);
        assert_eq!(by_c1.len(), 1);
        assert_eq!(by_c1[0].creator, creator1);

        let by_c2 = registry.list_by_creator(&creator2);
        assert_eq!(by_c2.len(), 1);
        assert_eq!(by_c2[0].id, hash2);
    }

    // PC-T40a (RC-8 inverted): duplicate registration must be REJECTED, not
    // silently overwrite. The old body asserted the overwrite that let an
    // attacker replace a registered adapter under its own hash.
    #[test]
    fn test_adapter_registry_duplicate() {
        let registry = AdapterRegistry::new();
        let e = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let adapter = AdapterFactory::create_lora(&e, 1, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();

        let _hash1 = registry.register(adapter.clone()).unwrap();
        // Second registration of an already-present id is refused.
        assert!(registry.register(adapter).is_err());
        assert_eq!(registry.count(), 1);
    }

    // F005: creator is bound into the adapter id, and register rejects an
    // adapter whose declared id does not match its recomputed content hash —
    // closing attribution theft (rewrite `creator`, keep a victim's id).
    #[test]
    fn test_creator_bound_into_id_and_register_rejects_forgery() {
        let e = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let honest =
            AdapterFactory::create_lora(&e, 1, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();
        let other_creator =
            AdapterFactory::create_lora(&e, 1, test_metadata(1), [2u8; 32], 100, vec![0u8; 64]).unwrap();

        // Same matrices/metadata, different creator ⇒ different id.
        assert_ne!(honest.id, other_creator.id);

        // Forge: keep the victim's id but rewrite the creator. register must reject.
        let mut forged = honest.clone();
        forged.creator = [9u8; 32];
        assert!(!AdapterFactory::verify_lora_hash(&forged));

        let registry = AdapterRegistry::new();
        assert!(registry.register(forged).is_err());
        assert_eq!(registry.count(), 0);
    }
}
