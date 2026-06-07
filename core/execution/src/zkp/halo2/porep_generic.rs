//! Parameterised native PoRep sealing (PIN-P1 (f.2a)).
//!
//! Generalises `porep.rs`'s reduced-fixture sealing (`N = 4`, `L = 2`,
//! single same-layer parent via the toy path graph, identity expander,
//! `K = 1` challenge) to arbitrary `(N, L, d_DRG, d_EXP, K)` driven by the
//! real DRG + expander samplers from `samplers.rs`.
//!
//! ## Scope and what's NOT here
//!
//! - **Native only.** The Halo2 in-circuit lift (the `Circuit` impl that
//!   proves the labeling + Merkle + encoding relations at arbitrary
//!   `(N, L, K)`) is the next sub-WP, tracked as **f.2b**. Native first so
//!   the in-circuit work has a concrete contract to honour and a parity
//!   target.
//! - **Reduced circuit untouched.** Per the DGX handoff
//!   (`handoffs/PIN_DGX_HANDOFF.md` §2): *the reduced circuit stays as the
//!   fast dev/test fixture.* `porep.rs`'s `SealedReplica` /
//!   `PoRepCircuit` / `seal_reduced` are not modified.
//! - **No on-chain consequences yet.** v2 (PoRep) and v3 (PoSt) VKs in
//!   `mod.rs` keep pointing at the reduced circuit until **f.6** swaps
//!   them out. Discharging TD-19 is f.6's job.
//!
//! ## Public-input shape (informative — circuit lift consumes it)
//!
//! Stays at the v2 ABI from `precompiles/verify.rs`:
//!
//! ```text
//!   replicaID(32) ‖ cid(32) ‖ sectorIndex(32) ‖ version=2(4) ‖ chain_id(4)
//!   ‖ CommD(32) ‖ CommR(32) ‖ CommC(32) ‖ challengeNonce(32) ‖ epoch(32)
//!   ‖ proof
//! ```
//!
//! `K` does NOT inflate the ABI. Per the (f.2) spec, the `K` per-challenge
//! indices are derived **in-circuit** from
//! `(challengeNonce, epoch, replicaID, sectorIndex)` via a domain-separated
//! Poseidon expansion. The native side mirrors that derivation so the
//! prover and verifier compute identical indices.
//!
//! ## Labeling relation (mirrors `PIN-P1-sdr-replicaid-construction.md`)
//!
//! For node `v` in layer `l ≥ 1` with same-layer DRG parents
//! `drg_p = [p_1, …, p_{d_DRG}]` and previous-layer expander parents
//! `exp_p = [e_1, …, e_{d_EXP}]`:
//!
//! ```text
//!   parents_same = [ label(l, p_i) for p_i in drg_p ]
//!   parents_prev = [ label(l-1, e_j) for e_j in exp_p ]   (empty for l=1)
//!   label(l, v) = Poseidon( replicaID ‖ l ‖ v
//!                        ‖ parents_same... ‖ parents_prev... )
//! ```
//!
//! For `l = 1`, layer-0 ("seed") values feed in place of `label(0, ·)`:
//! the seed-slot value is `replicaID` itself when no DRG parent exists
//! (`v = 0` or when the sampler returns the empty set at `v < d_DRG`).
//!
//! ## Encoding
//!
//! ```text
//!   R[v] = D[v] + label(L, v)   (mod p)
//! ```
//!
//! ## Commitments
//!
//! ```text
//!   CommD = MerkleRoot(D, depth = log2(N))
//!   CommR = MerkleRoot(R, depth = log2(N))
//!   CommC = MerkleRoot(columns, depth = log2(N))
//!   column(v) = Poseidon( label(1, v) ‖ label(2, v) ‖ … ‖ label(L, v) )
//! ```
//!
//! `N` is required to be a power of two so the binary Merkle tree closes
//! cleanly; this matches Filecoin SDR and the depth assumption of the
//! existing `SwapMerkleChip`.

use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::PrimeField as _;

use crate::zkp::halo2::samplers::{drg_parents, expander_parents, SamplerError};
use crate::zkp::poseidon_bn254::poseidon_hash;

/// Errors from parameterised native sealing.
#[derive(Debug)]
pub enum SealError {
    /// `N` was not a power of two.
    NotPowerOfTwo { n: usize },
    /// `N < 2` — degenerate sector.
    SectorTooSmall { n: usize },
    /// `L < 1` — at least one layer is required for the encoding step.
    LayerCountZero,
    /// `data.len() != N`.
    DataLengthMismatch { expected: usize, got: usize },
    /// `d_DRG ≥ N` or `d_EXP > N` — degrees out of range for the graph size.
    DegreeOutOfRange {
        d_drg: usize,
        d_exp: usize,
        n: usize,
    },
    /// `K == 0` — challenge count must be at least 1.
    ChallengeCountZero,
    /// Underlying sampler refused a configuration.
    Sampler(SamplerError),
}

impl From<SamplerError> for SealError {
    fn from(e: SamplerError) -> Self {
        SealError::Sampler(e)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Parameters.
// ───────────────────────────────────────────────────────────────────────────

/// Public configuration for a generic PoRep sealing instance.
#[derive(Clone, Debug)]
pub struct PoRepParams {
    /// Number of nodes in the sector. MUST be a power of two and ≥ 2.
    pub n: usize,
    /// Number of layers in the SDR labeling. ≥ 1.
    pub l: usize,
    /// Same-layer (DRG) parent count per node. Reduces to the toy
    /// path-graph at `d_drg = 1` if combined with the toy DRG sampler.
    pub d_drg: usize,
    /// Previous-layer (expander) parent count per node.
    pub d_exp: usize,
    /// Number of challenges per proof. The in-circuit derivation produces
    /// `K` distinct challenge indices in `[0, N)` from
    /// `(challengeNonce, epoch, replicaID, sectorIndex)`.
    pub k: usize,
    /// Seed for the topology samplers. Public — bound into proofs via
    /// `replicaID` and `sectorIndex` (we hash them in at the call site).
    pub graph_seed: [u8; 32],
}

impl PoRepParams {
    /// Filecoin SDR analysed parameters: `(d_DRG, d_EXP, L) = (6, 8, 11)`.
    /// Caller picks `n` (sector node count) and `k` (challenge count) per
    /// the feasibility budget.
    pub fn filecoin(n: usize, k: usize, graph_seed: [u8; 32]) -> Self {
        Self {
            n,
            l: super::samplers::L_REAL,
            d_drg: super::samplers::D_DRG,
            d_exp: super::samplers::D_EXP,
            k,
            graph_seed,
        }
    }

    /// `log2(n)`. Used as the Merkle depth.
    pub fn merkle_depth(&self) -> usize {
        // n is asserted to be a power of two during validation; trailing_zeros
        // gives log2 exactly.
        self.n.trailing_zeros() as usize
    }

    fn validate(&self) -> Result<(), SealError> {
        if self.n < 2 {
            return Err(SealError::SectorTooSmall { n: self.n });
        }
        if !self.n.is_power_of_two() {
            return Err(SealError::NotPowerOfTwo { n: self.n });
        }
        if self.l == 0 {
            return Err(SealError::LayerCountZero);
        }
        if self.d_drg >= self.n || self.d_exp > self.n {
            return Err(SealError::DegreeOutOfRange {
                d_drg: self.d_drg,
                d_exp: self.d_exp,
                n: self.n,
            });
        }
        if self.k == 0 {
            return Err(SealError::ChallengeCountZero);
        }
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Sealed replica.
// ───────────────────────────────────────────────────────────────────────────

/// Fully-sealed parameterised replica. All field values the in-circuit
/// witnesses + public inputs are derived from.
#[derive(Clone, Debug)]
pub struct GenericSealedReplica {
    pub params: PoRepParams,
    pub replica_id: Halo2Fr,
    pub cid: Halo2Fr,
    pub sector_index: Halo2Fr,
    pub epoch: Halo2Fr,

    /// Unsealed data, `params.n` elements.
    pub data: Vec<Halo2Fr>,
    /// Sealed replica, `R[v] = D[v] + label(L, v)`.
    pub replica: Vec<Halo2Fr>,
    /// Labels, indexed `labels[layer-1][v]`. Outer length `params.l`; inner
    /// length `params.n`.
    pub labels: Vec<Vec<Halo2Fr>>,
    /// Per-node column commitment, `column(v) = Poseidon(label(1, v), …, label(L, v))`.
    pub columns: Vec<Halo2Fr>,

    pub comm_d: Halo2Fr,
    pub comm_r: Halo2Fr,
    pub comm_c: Halo2Fr,
}

// ───────────────────────────────────────────────────────────────────────────
// Per-challenge witness bundle.
// ───────────────────────────────────────────────────────────────────────────

/// All siblings + parent witnesses for ONE challenge. The in-circuit lift
/// will consume `K` of these.
#[derive(Clone, Debug)]
pub struct GenericChallenge {
    /// Challenged node index `v* ∈ [0, N)`.
    pub v: usize,

    /// Data leaf `D[v*]`.
    pub data_leaf: Halo2Fr,
    /// Layer labels for `v*`: `[label(1, v*), …, label(L, v*)]`.
    pub labels_at_v: Vec<Halo2Fr>,

    /// DRG (same-layer) parent indices for `v*` — ALWAYS length `d_DRG`.
    /// Real slots (`j < drg_n_active(v*, d_DRG)`) carry honest predecessor
    /// indices; padded slots carry sentinel `0`. The companion
    /// [`drg_valid`] flag distinguishes them.
    pub drg_parent_indices: Vec<usize>,
    /// PIN-P1 `v*<d_DRG` mux: per-slot boolean — `true` for REAL DRG
    /// parent slots, `false` for PADDED slots. The in-circuit lift gates
    /// the column-inclusion check on this AND muxes `replicaID` into the
    /// labeling preimage at padded slots.
    pub drg_valid: Vec<bool>,
    /// Each entry: the column `(label(1, p), …, label(L, p))` for one DRG
    /// parent `p`. Length matches `drg_parent_indices` (= `d_DRG`).
    /// Padded slots carry zero-filled placeholder columns.
    pub drg_parent_columns: Vec<Vec<Halo2Fr>>,

    /// Expander (prev-layer) parent indices for `v*`.
    pub exp_parent_indices: Vec<usize>,
    /// Each entry: the column for one expander parent. Length matches
    /// `exp_parent_indices`. Note: at layer 1 the expander parents do not
    /// contribute to the layer-1 preimage (per the labeling spec).
    pub exp_parent_columns: Vec<Vec<Halo2Fr>>,

    /// Merkle authentication paths for the three inclusions of `v*`.
    /// Each `Vec` has length `merkle_depth = log2(N)`.
    pub sib_d: Vec<Halo2Fr>,
    pub sib_r: Vec<Halo2Fr>,
    pub sib_c: Vec<Halo2Fr>,

    /// Merkle paths for each parent's column inclusion against `CommC`.
    /// `drg_parent_sib_c[i]` is the path for `drg_parent_indices[i]`;
    /// `exp_parent_sib_c[j]` is the path for `exp_parent_indices[j]`.
    pub drg_parent_sib_c: Vec<Vec<Halo2Fr>>,
    pub exp_parent_sib_c: Vec<Vec<Halo2Fr>>,
}

// ───────────────────────────────────────────────────────────────────────────
// Native primitives — Poseidon + Merkle, depth-agnostic.
// ───────────────────────────────────────────────────────────────────────────

/// Hash arbitrary-arity `&[Halo2Fr]` via the chain's Poseidon-BN254. The
/// output is byte-identical to the in-circuit `PoseidonChip` (same routing
/// porep.rs uses).
fn native_hash(inputs: &[Halo2Fr]) -> Halo2Fr {
    use ark_bn254::Fr as ArkFr;
    use ark_ff::PrimeField as _;
    let ark_inputs: Vec<ArkFr> = inputs
        .iter()
        .map(|h| ArkFr::from_le_bytes_mod_order(h.to_repr().as_ref()))
        .collect();
    let out = poseidon_hash(&ark_inputs);
    use ark_ff::BigInteger as _;
    let mut le = out.into_bigint().to_bytes_le();
    le.resize(32, 0);
    let arr: [u8; 32] = le.try_into().expect("32 bytes");
    Option::<Halo2Fr>::from(Halo2Fr::from_repr(arr.into())).expect("canonical Fr")
}

/// Compute the root of a binary Poseidon-Merkle tree over `leaves` (length
/// must be a power of two ≥ 2). Returns the root.
pub fn merkle_root(leaves: &[Halo2Fr]) -> Halo2Fr {
    assert!(
        leaves.len() >= 2 && leaves.len().is_power_of_two(),
        "merkle_root: leaves must be a power-of-two count ≥ 2"
    );
    let mut layer: Vec<Halo2Fr> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(native_hash(&[pair[0], pair[1]]));
        }
        layer = next;
    }
    layer[0]
}

/// The authentication path (sibling VALUES) for `leaf_index` in a binary
/// Poseidon-Merkle tree over `leaves`. Returns `merkle_depth` siblings
/// from leaf level up to (but excluding) the root.
///
/// Directions ARE NOT returned — they are derived in-circuit from the
/// witnessed index bits (the index-agnostic `SwapMerkleChip` pattern).
pub fn merkle_siblings(leaves: &[Halo2Fr], leaf_index: usize) -> Vec<Halo2Fr> {
    let n = leaves.len();
    assert!(
        n >= 2 && n.is_power_of_two(),
        "merkle_siblings: leaves count must be a power-of-two ≥ 2"
    );
    assert!(leaf_index < n, "merkle_siblings: leaf_index ≥ n");

    let depth = n.trailing_zeros() as usize;
    let mut siblings = Vec::with_capacity(depth);
    let mut layer: Vec<Halo2Fr> = leaves.to_vec();
    let mut idx = leaf_index;
    for _ in 0..depth {
        // Within this layer, the sibling is the OTHER element of the pair.
        let sib_idx = idx ^ 1;
        siblings.push(layer[sib_idx]);
        // Build next layer.
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(native_hash(&[pair[0], pair[1]]));
        }
        layer = next;
        idx /= 2;
    }
    siblings
}

// ───────────────────────────────────────────────────────────────────────────
// Labeling preimage.
// ───────────────────────────────────────────────────────────────────────────

/// Build the labeling preimage for `label(l, v)` at the **padded**
/// fixed-arity shape introduced for the `v* < d_DRG` mux:
///
/// ```text
///   preimage = [ replicaID, l, v,
///                parents_same_layer[0..d_DRG]...,
///                parents_prev_layer[0..d_EXP]... ]
/// ```
///
/// `parents_same` MUST be length `d_DRG` (no special-casing the empty
/// case). When `v` has fewer than `d_DRG` strict-predecessor parents,
/// the missing slots are padded with `replicaID` (the seed-slot
/// sentinel from the spec). This makes the Poseidon arity invariant
/// across `v`, so the in-circuit gates have a single shape and the
/// `v* < d_DRG` case is handled by per-slot `valid_i` booleans in the
/// circuit (with the column-inclusion gate gated by `valid_i`).
///
/// At layer 1, `parents_prev` is empty (no expander contribution). At
/// layer ≥ 2, `parents_prev` is length `d_EXP`.
pub fn label_preimage_generic(
    replica_id: Halo2Fr,
    layer: usize,
    v: usize,
    parents_same: &[Halo2Fr],
    parents_prev: &[Halo2Fr],
) -> Vec<Halo2Fr> {
    let mut pre = Vec::with_capacity(3 + parents_same.len() + parents_prev.len());
    pre.push(replica_id);
    pre.push(Halo2Fr::from(layer as u64));
    pre.push(Halo2Fr::from(v as u64));
    pre.extend_from_slice(parents_same);
    pre.extend_from_slice(parents_prev);
    pre
}

/// Sample DRG parent indices for `v` PADDED to length `d_DRG`. The
/// first `min(v, d_DRG)` slots are honestly-sampled strict
/// predecessors; the remaining slots are `0` (sentinel — paired with
/// `replicaID` as the slot value in the preimage). The caller pairs
/// these indices with the actual slot values via [`drg_parent_slots`].
fn drg_parent_indices_padded(
    seed: &[u8; 32],
    v: usize,
    n: usize,
    d_drg: usize,
) -> Result<Vec<usize>, SealError> {
    let active = if v == 0 {
        Vec::new()
    } else {
        drg_parents(seed, v, n, d_drg.min(v))?
    };
    Ok((0..d_drg)
        .map(|j| if j < active.len() { active[j] } else { 0 })
        .collect())
}

/// Convert padded parent indices into preimage slot values: real slots
/// use `labels[layer_minus_one][p]`; padded slots use `replicaID`. The
/// boolean returned per slot says whether the slot is REAL (true) or
/// PADDED (false) — the in-circuit lift uses this as `valid_i`.
fn drg_parent_slots(
    labels_layer_minus_one: &[Halo2Fr],
    drg_p_idx_padded: &[usize],
    n_active: usize,
    replica_id: Halo2Fr,
) -> (Vec<Halo2Fr>, Vec<bool>) {
    let mut slots = Vec::with_capacity(drg_p_idx_padded.len());
    let mut valid = Vec::with_capacity(drg_p_idx_padded.len());
    for (j, &p) in drg_p_idx_padded.iter().enumerate() {
        if j < n_active {
            slots.push(labels_layer_minus_one[p]);
            valid.push(true);
        } else {
            slots.push(replica_id);
            valid.push(false);
        }
    }
    (slots, valid)
}

/// Number of REAL (non-padded) DRG parents at node `v` with degree `d_DRG`.
#[inline]
pub fn drg_n_active(v: usize, d_drg: usize) -> usize {
    if v == 0 {
        0
    } else {
        d_drg.min(v)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Sealing.
// ───────────────────────────────────────────────────────────────────────────

/// Seal a parameterised replica from `data` and the identity tuple.
///
/// `pinner_identity` is the (KYC-bound) opaque identity; the chain never
/// sees it — it's the pre-image of `replicaID`.
pub fn seal_generic(
    params: PoRepParams,
    pinner_identity: Halo2Fr,
    cid: Halo2Fr,
    sector_index: Halo2Fr,
    epoch: Halo2Fr,
    data: Vec<Halo2Fr>,
) -> Result<GenericSealedReplica, SealError> {
    params.validate()?;
    if data.len() != params.n {
        return Err(SealError::DataLengthMismatch {
            expected: params.n,
            got: data.len(),
        });
    }

    // replicaID = Poseidon(pinnerIdentity, cid, sectorIndex)
    let replica_id = native_hash(&[pinner_identity, cid, sector_index]);

    // Labeling — padded scheme: ALWAYS d_DRG parent slots in the
    // labeling preimage, with replicaID padding for missing slots at
    // v < d_DRG. The Poseidon arity is now constant across all v, so
    // the in-circuit lift has a single shape; the v* < d_DRG case is
    // handled by per-slot `valid_i` booleans in the circuit.
    let mut labels: Vec<Vec<Halo2Fr>> = vec![vec![Halo2Fr::from(0u64); params.n]; params.l];
    for layer in 1..=params.l {
        for v in 0..params.n {
            // DRG (same-layer) parents — padded to d_DRG slots.
            let drg_p_idx_padded =
                drg_parent_indices_padded(&params.graph_seed, v, params.n, params.d_drg)?;
            let n_active = drg_n_active(v, params.d_drg);
            let (parents_same, _valid) =
                drg_parent_slots(&labels[layer - 1], &drg_p_idx_padded, n_active, replica_id);

            // Expander (previous-layer) parents — only contribute at layer ≥ 2.
            // No padding needed; the sampler always returns exactly d_EXP.
            let parents_prev: Vec<Halo2Fr> = if layer >= 2 {
                let exp_p_idx = expander_parents(&params.graph_seed, v, params.n, params.d_exp)?;
                exp_p_idx.iter().map(|&e| labels[layer - 2][e]).collect()
            } else {
                Vec::new()
            };

            let pre = label_preimage_generic(replica_id, layer, v, &parents_same, &parents_prev);
            labels[layer - 1][v] = native_hash(&pre);
        }
    }

    // Encoding: R[v] = D[v] + label(L, v).
    let mut replica = vec![Halo2Fr::from(0u64); params.n];
    for v in 0..params.n {
        replica[v] = data[v] + labels[params.l - 1][v];
    }

    // Columns: column(v) = Poseidon(label(1, v), …, label(L, v)).
    let mut columns = vec![Halo2Fr::from(0u64); params.n];
    for v in 0..params.n {
        let col_pre: Vec<Halo2Fr> = (0..params.l).map(|l_idx| labels[l_idx][v]).collect();
        columns[v] = native_hash(&col_pre);
    }

    let comm_d = merkle_root(&data);
    let comm_r = merkle_root(&replica);
    let comm_c = merkle_root(&columns);

    Ok(GenericSealedReplica {
        params,
        replica_id,
        cid,
        sector_index,
        epoch,
        data,
        replica,
        labels,
        columns,
        comm_d,
        comm_r,
        comm_c,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// In-circuit challenge derivation (native mirror).
// ───────────────────────────────────────────────────────────────────────────

/// Derive `K` distinct challenge indices in `[0, N)` from
/// `(challengeNonce, epoch, replicaID, sectorIndex)`. The in-circuit
/// equivalent (f.2b) MUST produce identical outputs for the same inputs —
/// this is the contract for the index-derivation gate.
///
/// Construction: starting from a single Poseidon seed, draw `i = 0, 1, …`
/// expansions until `K` distinct indices have been produced. Each draw is
/// `Poseidon(seed, draw_index)` reduced modulo `N`. The index-distinctness
/// is critical so two challenges don't trivially collide (a soundness
/// concern for the K-fold proof system).
pub fn derive_challenge_indices(
    n: usize,
    k: usize,
    challenge_nonce: Halo2Fr,
    epoch: Halo2Fr,
    replica_id: Halo2Fr,
    sector_index: Halo2Fr,
) -> Vec<usize> {
    assert!(n > 0 && k > 0 && k <= n);
    let seed = native_hash(&[challenge_nonce, epoch, replica_id, sector_index]);
    let mut out = Vec::with_capacity(k);
    let mut draw: u64 = 0;
    while out.len() < k {
        let h = native_hash(&[seed, Halo2Fr::from(draw)]);
        // Reduce h to a usize index. Take the low 8 bytes as a u64.
        let bytes = h.to_repr();
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes.as_ref()[0..8]);
        let candidate = (u64::from_le_bytes(le) as usize) % n;
        if !out.contains(&candidate) {
            out.push(candidate);
        }
        draw = draw.wrapping_add(1);
    }
    out
}

/// PIN-P1 (f.2c.2) — simple K-index derivation WITHOUT rejection
/// sampling. Mirrors the in-circuit
/// [`super::porep_circuit_kfold_v1::PoRepCircuitKFoldV1`] derivation
/// EXACTLY (Poseidon(seed, i) reduced mod N for i in 0..K). The
/// distinctness contract is enforced IN-CIRCUIT by f.2c.2's pairwise
/// inequality gate; a colliding `challenge_nonce` is then simply
/// unprovable (the operator retries with the next block's
/// `prevrandao`).
///
/// **Why not just use [`derive_challenge_indices`] for v1?** That
/// helper rejects collisions and walks `draw` past them, producing K
/// distinct indices but at NON-CONSECUTIVE `draw` positions. The
/// in-circuit derivation uses CONSECUTIVE `draw = 0..K`, so the two
/// drift apart whenever a native rejection happens. Using
/// `_simple` for v1 keeps native and in-circuit byte-identical.
///
/// Collision probability for K=44 at N=2^25 is `K² / 2N ≈ 3×10⁻⁵`
/// per nonce — vanishingly small at production sizes.
pub fn derive_challenge_indices_simple(
    n: usize,
    k: usize,
    challenge_nonce: Halo2Fr,
    epoch: Halo2Fr,
    replica_id: Halo2Fr,
    sector_index: Halo2Fr,
) -> Vec<usize> {
    assert!(n > 0 && k > 0);
    let seed = native_hash(&[challenge_nonce, epoch, replica_id, sector_index]);
    (0..k as u64)
        .map(|draw| {
            let h = native_hash(&[seed, Halo2Fr::from(draw)]);
            let bytes = h.to_repr();
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes.as_ref()[0..8]);
            (u64::from_le_bytes(le) as usize) % n
        })
        .collect()
}

/// Build the per-challenge witness bundle for a single challenge index.
///
/// PIN-P1 v*<d_DRG mux: the DRG parent arrays are ALWAYS length `d_DRG`.
/// For `j < drg_n_active(v, d_DRG)` the slots carry the honestly-sampled
/// strict predecessor + its column + its inclusion path. For
/// `j >= drg_n_active(v, d_DRG)` the slots are PADDED — sentinel
/// `parent_index = 0`, a placeholder column (zeros), and a placeholder
/// sib path. The `drg_valid[j]` boolean tells the in-circuit lift which
/// slots are real, gating the column-inclusion check AND muxing
/// `replicaID` into the labeling preimage for padded slots.
pub fn build_challenge(
    sealed: &GenericSealedReplica,
    v: usize,
) -> Result<GenericChallenge, SealError> {
    assert!(v < sealed.params.n);

    // Labels at v: column(v) is already Poseidon(labels at v); we want the
    // raw label vector for in-circuit re-derivation of the relation.
    let labels_at_v: Vec<Halo2Fr> = (0..sealed.params.l)
        .map(|l_idx| sealed.labels[l_idx][v])
        .collect();

    // DRG parents — padded to d_DRG with sentinel index 0 for inactive
    // slots. drg_valid encodes which are real.
    let drg_parent_indices = drg_parent_indices_padded(
        &sealed.params.graph_seed,
        v,
        sealed.params.n,
        sealed.params.d_drg,
    )?;
    let n_active = drg_n_active(v, sealed.params.d_drg);
    let drg_valid: Vec<bool> = (0..sealed.params.d_drg).map(|j| j < n_active).collect();

    let drg_parent_columns: Vec<Vec<Halo2Fr>> = drg_parent_indices
        .iter()
        .enumerate()
        .map(|(j, &p)| {
            if j < n_active {
                // Real slot — the honest column at parent index p.
                (0..sealed.params.l)
                    .map(|l_idx| sealed.labels[l_idx][p])
                    .collect()
            } else {
                // Padded slot — zeros are a benign placeholder. The
                // in-circuit column-inclusion gate is gated off via
                // drg_valid[j]=false; the labeling preimage slot is
                // muxed to `replicaID`.
                vec![Halo2Fr::from(0u64); sealed.params.l]
            }
        })
        .collect();
    let drg_parent_sib_c: Vec<Vec<Halo2Fr>> = drg_parent_indices
        .iter()
        .enumerate()
        .map(|(j, &p)| {
            if j < n_active {
                merkle_siblings(&sealed.columns, p)
            } else {
                // Padded — placeholder sib path (column-inclusion gate
                // is gated off, so the values are irrelevant to soundness).
                vec![Halo2Fr::from(0u64); sealed.params.merkle_depth()]
            }
        })
        .collect();

    // Expander parents (always layer ≥ 1; at layer 1 the gate ignores them
    // in the preimage — but the column inclusion is still proven so the
    // prover can't lie about which expander parents would have been used).
    let exp_parent_indices = expander_parents(
        &sealed.params.graph_seed,
        v,
        sealed.params.n,
        sealed.params.d_exp,
    )?;
    let exp_parent_columns: Vec<Vec<Halo2Fr>> = exp_parent_indices
        .iter()
        .map(|&e| {
            (0..sealed.params.l)
                .map(|l_idx| sealed.labels[l_idx][e])
                .collect()
        })
        .collect();
    let exp_parent_sib_c: Vec<Vec<Halo2Fr>> = exp_parent_indices
        .iter()
        .map(|&e| merkle_siblings(&sealed.columns, e))
        .collect();

    let sib_d = merkle_siblings(&sealed.data, v);
    let sib_r = merkle_siblings(&sealed.replica, v);
    let sib_c = merkle_siblings(&sealed.columns, v);

    Ok(GenericChallenge {
        v,
        data_leaf: sealed.data[v],
        labels_at_v,
        drg_parent_indices,
        drg_valid,
        drg_parent_columns,
        exp_parent_indices,
        exp_parent_columns,
        sib_d,
        sib_r,
        sib_c,
        drg_parent_sib_c,
        exp_parent_sib_c,
    })
}

/// Build `K` challenges using the derived indices.
pub fn build_challenges(
    sealed: &GenericSealedReplica,
    challenge_nonce: Halo2Fr,
) -> Result<Vec<GenericChallenge>, SealError> {
    let indices = derive_challenge_indices(
        sealed.params.n,
        sealed.params.k,
        challenge_nonce,
        sealed.epoch,
        sealed.replica_id,
        sealed.sector_index,
    );
    indices
        .into_iter()
        .map(|v| build_challenge(sealed, v))
        .collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Tests.
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::bn256::Fr as Halo2Fr;

    fn seed_zero() -> [u8; 32] {
        [0u8; 32]
    }

    fn one_through(n: usize) -> Vec<Halo2Fr> {
        (1..=n as u64).map(Halo2Fr::from).collect()
    }

    // ── Parameter validation ──

    #[test]
    fn rejects_non_power_of_two_n() {
        let params = PoRepParams {
            n: 6,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let err = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(6),
        )
        .expect_err("expected NotPowerOfTwo");
        assert!(matches!(err, SealError::NotPowerOfTwo { n: 6 }));
    }

    #[test]
    fn rejects_data_length_mismatch() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let err = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(3), // wrong length
        )
        .expect_err("expected DataLengthMismatch");
        assert!(matches!(
            err,
            SealError::DataLengthMismatch {
                expected: 4,
                got: 3
            }
        ));
    }

    #[test]
    fn rejects_zero_layer_count() {
        let params = PoRepParams {
            n: 4,
            l: 0,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let err = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(4),
        )
        .expect_err("expected LayerCountZero");
        assert!(matches!(err, SealError::LayerCountZero));
    }

    #[test]
    fn rejects_zero_k() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 0,
            graph_seed: seed_zero(),
        };
        let err = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(4),
        )
        .expect_err("expected ChallengeCountZero");
        assert!(matches!(err, SealError::ChallengeCountZero));
    }

    // ── Sealing — shape ──

    #[test]
    fn seal_small_yields_consistent_shapes() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(4),
        )
        .expect("seal");
        assert_eq!(sealed.data.len(), 4);
        assert_eq!(sealed.replica.len(), 4);
        assert_eq!(sealed.labels.len(), 2);
        assert_eq!(sealed.labels[0].len(), 4);
        assert_eq!(sealed.labels[1].len(), 4);
        assert_eq!(sealed.columns.len(), 4);
        assert_eq!(sealed.params.merkle_depth(), 2);
    }

    #[test]
    fn seal_large_yields_consistent_shapes() {
        // (N=1024, L=3, K=3) — the f.2 acceptance target size for native.
        let params = PoRepParams {
            n: 1024,
            l: 3,
            d_drg: 6,
            d_exp: 8,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(1024),
        )
        .expect("seal");
        assert_eq!(sealed.data.len(), 1024);
        assert_eq!(sealed.replica.len(), 1024);
        assert_eq!(sealed.labels.len(), 3);
        for layer in &sealed.labels {
            assert_eq!(layer.len(), 1024);
        }
        assert_eq!(sealed.columns.len(), 1024);
        assert_eq!(sealed.params.merkle_depth(), 10); // log2(1024)
    }

    // ── Sealing — determinism + sensitivity ──

    #[test]
    fn seal_is_deterministic() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 2,
            graph_seed: seed_zero(),
        };
        let a = seal_generic(
            params.clone(),
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("a");
        let b = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("b");
        assert_eq!(a.comm_d, b.comm_d);
        assert_eq!(a.comm_r, b.comm_r);
        assert_eq!(a.comm_c, b.comm_c);
    }

    #[test]
    fn seal_replica_id_sensitivity() {
        // Different pinnerIdentity → different replicaID → different
        // labels → different CommR + CommC. CommD is the same (same data).
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 2,
            graph_seed: seed_zero(),
        };
        let a = seal_generic(
            params.clone(),
            Halo2Fr::from(0xAAu64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("a");
        let b = seal_generic(
            params,
            Halo2Fr::from(0xBBu64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("b");
        assert_eq!(a.comm_d, b.comm_d, "same data → same CommD");
        assert_ne!(a.comm_r, b.comm_r, "different replicaID → different CommR");
        assert_ne!(a.comm_c, b.comm_c, "different replicaID → different CommC");
        assert_ne!(a.replica_id, b.replica_id, "different replicaIDs");
    }

    #[test]
    fn seal_graph_seed_sensitivity() {
        // Different graph_seed → different topology → different labels →
        // different CommR + CommC (same CommD).
        let mut s1 = seed_zero();
        s1[0] = 0x01;
        let mut s2 = seed_zero();
        s2[0] = 0x02;
        let a = seal_generic(
            PoRepParams {
                n: 16,
                l: 3,
                d_drg: 3,
                d_exp: 3,
                k: 2,
                graph_seed: s1,
            },
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("a");
        let b = seal_generic(
            PoRepParams {
                n: 16,
                l: 3,
                d_drg: 3,
                d_exp: 3,
                k: 2,
                graph_seed: s2,
            },
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("b");
        assert_eq!(a.comm_d, b.comm_d);
        assert_ne!(a.comm_r, b.comm_r);
        assert_ne!(a.comm_c, b.comm_c);
    }

    // ── Merkle ──

    #[test]
    fn merkle_round_trip_against_seal() {
        let params = PoRepParams {
            n: 16,
            l: 2,
            d_drg: 3,
            d_exp: 3,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("seal");
        // Recompute the root from leaves; it must match the stored CommD.
        let recomputed_d = merkle_root(&sealed.data);
        assert_eq!(recomputed_d, sealed.comm_d);
        let recomputed_r = merkle_root(&sealed.replica);
        assert_eq!(recomputed_r, sealed.comm_r);
        let recomputed_c = merkle_root(&sealed.columns);
        assert_eq!(recomputed_c, sealed.comm_c);
    }

    #[test]
    fn merkle_siblings_reconstruct_root_via_pair_hash() {
        // Sanity: for any leaf, hashing the leaf with its siblings up the
        // tree (following the leaf_index bits) MUST equal the root.
        let leaves = one_through(8);
        let root = merkle_root(&leaves);
        for v in 0..8 {
            let siblings = merkle_siblings(&leaves, v);
            assert_eq!(siblings.len(), 3);
            let mut cur = leaves[v];
            let mut idx = v;
            for sib in siblings {
                cur = if idx % 2 == 0 {
                    native_hash(&[cur, sib])
                } else {
                    native_hash(&[sib, cur])
                };
                idx /= 2;
            }
            assert_eq!(cur, root, "Merkle path reconstructs root for leaf {v}");
        }
    }

    // ── Encoding ──

    #[test]
    fn encoding_relation_holds_for_every_node() {
        // R[v] = D[v] + label(L, v) must hold for every node.
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("seal");
        for v in 0..params.n {
            let expected = sealed.data[v] + sealed.labels[params.l - 1][v];
            assert_eq!(
                sealed.replica[v], expected,
                "R[{v}] ≠ D[{v}] + label(L,{v})"
            );
        }
    }

    // ── Challenge index derivation ──

    #[test]
    fn challenge_indices_distinct_and_in_range() {
        let indices = derive_challenge_indices(
            1024,
            44,
            Halo2Fr::from(0xCCu64),
            Halo2Fr::from(0xEEu64),
            Halo2Fr::from(0xAAu64),
            Halo2Fr::from(0xBBu64),
        );
        assert_eq!(indices.len(), 44);
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            assert!(w[0] < w[1], "duplicate index {} {}", w[0], w[1]);
        }
        for &i in &indices {
            assert!(i < 1024);
        }
    }

    #[test]
    fn challenge_indices_deterministic() {
        let a = derive_challenge_indices(
            1024,
            10,
            Halo2Fr::from(0xCCu64),
            Halo2Fr::from(0xEEu64),
            Halo2Fr::from(0xAAu64),
            Halo2Fr::from(0xBBu64),
        );
        let b = derive_challenge_indices(
            1024,
            10,
            Halo2Fr::from(0xCCu64),
            Halo2Fr::from(0xEEu64),
            Halo2Fr::from(0xAAu64),
            Halo2Fr::from(0xBBu64),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn challenge_indices_change_with_each_binding() {
        let base = derive_challenge_indices(
            1024,
            10,
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
        );
        assert_ne!(
            base,
            derive_challenge_indices(
                1024,
                10,
                Halo2Fr::from(99u64), // different nonce
                Halo2Fr::from(2u64),
                Halo2Fr::from(3u64),
                Halo2Fr::from(4u64),
            )
        );
        assert_ne!(
            base,
            derive_challenge_indices(
                1024,
                10,
                Halo2Fr::from(1u64),
                Halo2Fr::from(99u64), // different epoch
                Halo2Fr::from(3u64),
                Halo2Fr::from(4u64),
            )
        );
        assert_ne!(
            base,
            derive_challenge_indices(
                1024,
                10,
                Halo2Fr::from(1u64),
                Halo2Fr::from(2u64),
                Halo2Fr::from(99u64), // different replicaID
                Halo2Fr::from(4u64),
            )
        );
        assert_ne!(
            base,
            derive_challenge_indices(
                1024,
                10,
                Halo2Fr::from(1u64),
                Halo2Fr::from(2u64),
                Halo2Fr::from(3u64),
                Halo2Fr::from(99u64), // different sectorIndex
            )
        );
    }

    // ── Challenge witness bundle ──

    #[test]
    fn build_challenges_shapes_match_params() {
        let params = PoRepParams {
            n: 1024,
            l: 3,
            d_drg: 6,
            d_exp: 8,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(1024),
        )
        .expect("seal");
        let challenge_nonce = Halo2Fr::from(0xFEu64);
        let challenges = build_challenges(&sealed, challenge_nonce).expect("challenges");
        assert_eq!(challenges.len(), 3);
        for ch in &challenges {
            assert!(ch.v < params.n);
            assert_eq!(ch.labels_at_v.len(), params.l);
            assert_eq!(ch.sib_d.len(), params.merkle_depth());
            assert_eq!(ch.sib_r.len(), params.merkle_depth());
            assert_eq!(ch.sib_c.len(), params.merkle_depth());
            assert!(ch.drg_parent_indices.len() <= params.d_drg);
            assert_eq!(ch.exp_parent_indices.len(), params.d_exp);
            assert_eq!(ch.drg_parent_columns.len(), ch.drg_parent_indices.len());
            assert_eq!(ch.exp_parent_columns.len(), ch.exp_parent_indices.len());
            assert_eq!(ch.drg_parent_sib_c.len(), ch.drg_parent_indices.len());
            assert_eq!(ch.exp_parent_sib_c.len(), ch.exp_parent_indices.len());
        }
    }

    #[test]
    fn challenge_parent_columns_reconstruct_via_inclusion_paths() {
        // Per ADR-PIN-P1: every parent the sampler returns MUST be column-
        // included vs CommC at its own index. The witness bundle's parent
        // columns + sib_c paths MUST reconstruct CommC for each parent.
        // This is the *native* mirror of the in-circuit soundness gate.
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(16),
        )
        .expect("seal");
        let challenges = build_challenges(&sealed, Halo2Fr::from(0xCAu64)).expect("ch");

        for ch in &challenges {
            // For each DRG parent p_i, hash its column down via sib_c to
            // confirm it reconstructs to CommC.
            for (i, &p) in ch.drg_parent_indices.iter().enumerate() {
                let column_at_p = native_hash(&ch.drg_parent_columns[i]);
                let mut cur = column_at_p;
                let mut idx = p;
                for sib in &ch.drg_parent_sib_c[i] {
                    cur = if idx % 2 == 0 {
                        native_hash(&[cur, *sib])
                    } else {
                        native_hash(&[*sib, cur])
                    };
                    idx /= 2;
                }
                assert_eq!(
                    cur, sealed.comm_c,
                    "DRG parent {p}'s column doesn't reconstruct to CommC"
                );
            }
            // Same for expander parents.
            for (j, &e) in ch.exp_parent_indices.iter().enumerate() {
                let column_at_e = native_hash(&ch.exp_parent_columns[j]);
                let mut cur = column_at_e;
                let mut idx = e;
                for sib in &ch.exp_parent_sib_c[j] {
                    cur = if idx % 2 == 0 {
                        native_hash(&[cur, *sib])
                    } else {
                        native_hash(&[*sib, cur])
                    };
                    idx /= 2;
                }
                assert_eq!(
                    cur, sealed.comm_c,
                    "expander parent {e}'s column doesn't reconstruct to CommC"
                );
            }
        }
    }

    #[test]
    fn challenge_labels_reconstruct_via_relation() {
        // The labeling relation MUST hold for the witnessed labels_at_v
        // given the parent columns from the witness.
        //
        //   label(l, v) = Poseidon(replicaID, l, v,
        //                          drg_parent_label(l, p)...,
        //                          exp_parent_label(l-1, e)...)
        //
        // We reconstruct the preimage from the witness and confirm it
        // hashes to labels_at_v[l-1] for each layer.
        let params = PoRepParams {
            n: 32,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
            Halo2Fr::from(4u64),
            one_through(32),
        )
        .expect("seal");
        let challenges = build_challenges(&sealed, Halo2Fr::from(0xEFu64)).expect("ch");

        for ch in &challenges {
            for layer in 1..=params.l {
                // parents_same: drg parents' label at THIS layer.
                let parents_same: Vec<Halo2Fr> = ch
                    .drg_parent_columns
                    .iter()
                    .map(|col| col[layer - 1])
                    .collect();
                // parents_prev: expander parents' label at layer-1 (empty
                // at layer 1).
                let parents_prev: Vec<Halo2Fr> = if layer >= 2 {
                    ch.exp_parent_columns
                        .iter()
                        .map(|col| col[layer - 2])
                        .collect()
                } else {
                    Vec::new()
                };
                let pre = label_preimage_generic(
                    sealed.replica_id,
                    layer,
                    ch.v,
                    &parents_same,
                    &parents_prev,
                );
                let recomputed = native_hash(&pre);
                assert_eq!(
                    recomputed,
                    ch.labels_at_v[layer - 1],
                    "labeling relation fails at v={}, layer={}",
                    ch.v,
                    layer
                );
            }
        }
    }

    // ── End-to-end at the f.2 acceptance size ──

    #[test]
    fn end_to_end_at_n1024_l3_k3_with_real_samplers() {
        // The f.2 acceptance target for the native layer: (N=2^10, L=3, K=3),
        // d_DRG and d_EXP at Filecoin SDR analysed values, real samplers.
        // We seal, derive K=3 challenges, build the witness bundles, and
        // verify all the soundness reconstructions hold natively.
        let params = PoRepParams {
            n: 1024,
            l: 3,
            d_drg: 6,
            d_exp: 8,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(1024),
        )
        .expect("seal");

        // Sanity on commitments.
        assert_eq!(merkle_root(&sealed.data), sealed.comm_d);
        assert_eq!(merkle_root(&sealed.replica), sealed.comm_r);
        assert_eq!(merkle_root(&sealed.columns), sealed.comm_c);

        // Build challenges.
        let challenges = build_challenges(&sealed, Halo2Fr::from(0x42u64)).expect("ch");
        assert_eq!(challenges.len(), 3);

        // For each challenge: encoding holds, sib_d reconstructs CommD,
        // sib_r reconstructs CommR, sib_c reconstructs CommC, and the
        // labeling relation at each layer reconstructs labels_at_v.
        for ch in &challenges {
            // Encoding: R[v] = D[v] + label(L, v).
            assert_eq!(
                sealed.replica[ch.v],
                ch.data_leaf + ch.labels_at_v[params.l - 1]
            );

            // Reconstruct CommD via sib_d.
            let mut cur = ch.data_leaf;
            let mut idx = ch.v;
            for sib in &ch.sib_d {
                cur = if idx % 2 == 0 {
                    native_hash(&[cur, *sib])
                } else {
                    native_hash(&[*sib, cur])
                };
                idx /= 2;
            }
            assert_eq!(cur, sealed.comm_d);

            // Reconstruct CommR via sib_r.
            let mut cur = sealed.replica[ch.v];
            let mut idx = ch.v;
            for sib in &ch.sib_r {
                cur = if idx % 2 == 0 {
                    native_hash(&[cur, *sib])
                } else {
                    native_hash(&[*sib, cur])
                };
                idx /= 2;
            }
            assert_eq!(cur, sealed.comm_r);

            // Reconstruct CommC via sib_c. column(v) = Poseidon(labels_at_v).
            let column_at_v = native_hash(&ch.labels_at_v);
            assert_eq!(column_at_v, sealed.columns[ch.v]);
            let mut cur = column_at_v;
            let mut idx = ch.v;
            for sib in &ch.sib_c {
                cur = if idx % 2 == 0 {
                    native_hash(&[cur, *sib])
                } else {
                    native_hash(&[*sib, cur])
                };
                idx /= 2;
            }
            assert_eq!(cur, sealed.comm_c);
        }
    }
}
