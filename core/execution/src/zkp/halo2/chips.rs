// citrate/core/execution/src/zkp/halo2/chips.rs
//
// RM-M1b WP-M1b.3 — Halo2 chip implementations.
//
// **PoseidonChip** is the load-bearing chip. Its byte-level
// output must match `zkp::poseidon_bn254::poseidon_hash` for
// the same input — that's the soundness invariant tying
// 0x0107 TENSOR_COMMIT (off-chain) to 0x0108
// INFERENCE_PROOF_VERIFY (in-circuit).
//
// **Approach:** hand-rolled, no third-party gadget (per Saul
// 2026-04-27, supply-chain hygiene). The constants come from
// `zkp::poseidon_bn254::poseidon_config()` — the same ARK +
// MDS matrices the off-chain hash uses, derived once via
// `find_poseidon_ark_and_mds` over BN254 Fr. Single source of
// truth.
//
// **Layout:**
//   - 3 advice columns (state[0..3])
//   - 3 fixed columns (ark[0..3] — round constants, varies per row)
//   - 2 selectors (s_full, s_partial — round-type marker)
//   - MDS matrix as inline `Expression::Constant` in gates
//
// **Gate degree:** 5 (because of x^5 S-box). Halo2 supports
// arbitrary degree but charges per row. Acceptable for our
// circuit sizes (k=18 has plenty of room).
//
// **Initial scope:** `hash_pair(a, b)` covers the Merkle-leaf
// case `Poseidon(index, value)`. Differential test against
// off-chain `poseidon_hash([a, b])`. Generalization to N inputs
// is mechanical: chain absorb/permute/squeeze cycles.

#![allow(dead_code)]

use ark_bn254::Fr as ArkFr;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;

use crate::zkp::poseidon_bn254::{poseidon_config, poseidon_hash};

// ---------------------------------------------------------------------------
// Poseidon-2 BN254 parameters (mirror `zkp::poseidon_bn254::POSEIDON_CONFIG_BN254`).
// ---------------------------------------------------------------------------

const RATE: usize = 2;
const STATE_WIDTH: usize = RATE + 1; // = 3 (capacity = 1)
const FULL_ROUNDS: usize = 8; // 4 pre-partial + 4 post-partial
const HALF_FULL_ROUNDS: usize = FULL_ROUNDS / 2;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS; // 64

/// Convert `ark_bn254::Fr` → `halo2curves::bn256::Fr` via canonical
/// little-endian serialization. Both crates encode BN254 Fr
/// the same way at the byte level (it's the same field), but the
/// types are distinct so we go through bytes.
fn ark_to_halo2_fr(x: &ArkFr) -> Halo2Fr {
    use ark_ff::{BigInteger, PrimeField as _};
    use halo2curves::ff::PrimeField as _;
    let bigint = x.into_bigint();
    let mut bytes_le = bigint.to_bytes_le();
    bytes_le.resize(32, 0);
    let bytes_arr: [u8; 32] = bytes_le.try_into().expect("32 bytes by resize");
    let opt: Option<Halo2Fr> = Halo2Fr::from_repr(bytes_arr.into()).into();
    opt.expect("Fr from_repr should succeed for canonical bytes")
}

/// Convert `halo2curves::bn256::Fr` → `ark_bn254::Fr`. Mirror of
/// the reverse — both serialize the same little-endian Fr.
fn halo2_to_ark_fr(x: &Halo2Fr) -> ArkFr {
    use ark_ff::PrimeField as _;
    use halo2curves::ff::PrimeField as _;
    let bytes_le = x.to_repr();
    ArkFr::from_le_bytes_mod_order(bytes_le.as_ref())
}

// ---------------------------------------------------------------------------
// PoseidonChip — in-circuit Poseidon-2 over BN254 Fr.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoseidonChipConfig {
    /// State cells for the sponge: rate=2 + capacity=1 = 3 cells.
    /// Each row k carries the state at the START of round k;
    /// row TOTAL_ROUNDS carries the final permuted state.
    pub state: [Column<Advice>; STATE_WIDTH],

    /// ARK constants. Per row k, these hold ARK[k][0..3]. Different
    /// rounds need different constants — the simplest approach is
    /// to assign them to fixed cells that the gate references at
    /// `Rotation::cur()`.
    pub ark: [Column<Fixed>; STATE_WIDTH],

    /// Selector for full-round transitions (S-box on all 3 elements).
    pub s_full: Selector,
    /// Selector for partial-round transitions (S-box only on state[0]).
    pub s_partial: Selector,

    /// Selector for absorb transitions (linear add: state_next[cap..]
    /// = state_curr[cap..] + inputs). Used by hash_n for inputs
    /// longer than `rate`. Two extra advice columns hold the
    /// absorbed input pair on each absorb row.
    pub s_absorb: Selector,
    pub absorb_in: [Column<Advice>; RATE],
}

pub struct PoseidonChip;

impl PoseidonChip {
    /// Configure the chip's gates against a `ConstraintSystem`.
    /// Allocates 3 advice columns (state) + 3 fixed columns (ark)
    /// + 2 selectors. MDS coefficients are inlined into the gate
    /// expressions as `Expression::Constant`.
    ///
    /// **Gate degree: 5** (S-box is x^5). Halo2's `create_gate`
    /// accepts arbitrary-degree expressions; the verifier pays
    /// per-row cost proportional to the max gate degree across
    /// the circuit. For our k=18 inference circuit this is
    /// acceptable.
    pub fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> PoseidonChipConfig {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for col in state.iter() {
            meta.enable_equality(*col);
        }
        let ark = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let s_full = meta.selector();
        let s_partial = meta.selector();

        // Pull MDS from the off-chain Poseidon config and convert
        // to halo2 field elements. The MDS is constant across
        // rounds, so we inline it into the gate expressions
        // rather than allocating fixed cells per row.
        let cfg = poseidon_config();
        let mds: [[Halo2Fr; STATE_WIDTH]; STATE_WIDTH] = {
            let mut out = [[Halo2Fr::ZERO; STATE_WIDTH]; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    out[i][j] = ark_to_halo2_fr(&cfg.mds[i][j]);
                }
            }
            out
        };

        // ---- Full-round gate ----
        // For each i in 0..3:
        //   state_next[i] = sum_j MDS[i][j] * (state[j] + ARK[j])^5
        meta.create_gate("poseidon_full_round", |meta| {
            let s = meta.query_selector(s_full);

            // sbox[j] = (state[j] + ark[j])^5 for all j
            let mut sbox: Vec<Expression<Halo2Fr>> = Vec::with_capacity(STATE_WIDTH);
            for j in 0..STATE_WIDTH {
                let s_j = meta.query_advice(state[j], Rotation::cur());
                let a_j = meta.query_fixed(ark[j], Rotation::cur());
                let pre = s_j + a_j;
                let pre2 = pre.clone() * pre.clone();
                let pre4 = pre2.clone() * pre2;
                sbox.push(pre4 * pre);
            }

            // Constraints: state_next[i] - sum_j MDS[i][j] * sbox[j] == 0
            let mut cs = Vec::with_capacity(STATE_WIDTH);
            for i in 0..STATE_WIDTH {
                let next_i = meta.query_advice(state[i], Rotation::next());
                let mut acc = Expression::Constant(Halo2Fr::ZERO);
                for j in 0..STATE_WIDTH {
                    acc = acc + Expression::Constant(mds[i][j]) * sbox[j].clone();
                }
                cs.push(s.clone() * (next_i - acc));
            }
            cs
        });

        // ---- Partial-round gate ----
        // S-box only on state[0]; state[1..] pass through linearly.
        // For each i in 0..3:
        //   state_next[i] = MDS[i][0] * (state[0] + ARK[0])^5
        //                 + MDS[i][1] * (state[1] + ARK[1])
        //                 + MDS[i][2] * (state[2] + ARK[2])
        meta.create_gate("poseidon_partial_round", |meta| {
            let s = meta.query_selector(s_partial);

            // S-box on state[0]
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let a0 = meta.query_fixed(ark[0], Rotation::cur());
            let pre0 = s0 + a0;
            let pre0_2 = pre0.clone() * pre0.clone();
            let pre0_4 = pre0_2.clone() * pre0_2;
            let sbox0 = pre0_4 * pre0;

            // state[j] + ark[j] for j=1,2 (no S-box)
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let a1 = meta.query_fixed(ark[1], Rotation::cur());
            let lin1 = s1 + a1;

            let s2 = meta.query_advice(state[2], Rotation::cur());
            let a2 = meta.query_fixed(ark[2], Rotation::cur());
            let lin2 = s2 + a2;

            let transformed = [sbox0, lin1, lin2];

            let mut cs = Vec::with_capacity(STATE_WIDTH);
            for i in 0..STATE_WIDTH {
                let next_i = meta.query_advice(state[i], Rotation::next());
                let mut acc = Expression::Constant(Halo2Fr::ZERO);
                for j in 0..STATE_WIDTH {
                    acc = acc + Expression::Constant(mds[i][j]) * transformed[j].clone();
                }
                cs.push(s.clone() * (next_i - acc));
            }
            cs
        });

        // ---- Absorb gate ----
        // For absorb transitions in hash_n: row k+1 state =
        // row k state + [0; absorb_in[0]; absorb_in[1]] (capacity
        // unchanged; rate slots get the new inputs added).
        //
        // Constraints:
        //   state_next[0] = state[0]                           (capacity unchanged)
        //   state_next[1] = state[1] + absorb_in[0]            (rate slot 0)
        //   state_next[2] = state[2] + absorb_in[1]            (rate slot 1)
        let absorb_in = [meta.advice_column(), meta.advice_column()];
        for col in absorb_in.iter() {
            meta.enable_equality(*col);
        }
        let s_absorb = meta.selector();
        meta.create_gate("poseidon_absorb", |meta| {
            let s = meta.query_selector(s_absorb);
            let s0_curr = meta.query_advice(state[0], Rotation::cur());
            let s1_curr = meta.query_advice(state[1], Rotation::cur());
            let s2_curr = meta.query_advice(state[2], Rotation::cur());
            let s0_next = meta.query_advice(state[0], Rotation::next());
            let s1_next = meta.query_advice(state[1], Rotation::next());
            let s2_next = meta.query_advice(state[2], Rotation::next());
            let in0 = meta.query_advice(absorb_in[0], Rotation::cur());
            let in1 = meta.query_advice(absorb_in[1], Rotation::cur());
            vec![
                s.clone() * (s0_next - s0_curr),
                s.clone() * (s1_next - (s1_curr + in0)),
                s * (s2_next - (s2_curr + in1)),
            ]
        });

        PoseidonChipConfig {
            state,
            ark,
            s_full,
            s_partial,
            s_absorb,
            absorb_in,
        }
    }

    /// In-circuit hash of arbitrary-length input. Mirrors the
    /// arkworks PoseidonSponge absorb-permute-squeeze cycle:
    ///
    ///   state = [0; STATE_WIDTH]
    ///   absorb inputs in chunks of RATE; permute between chunks
    ///     (NOT after the last chunk per arkworks loop semantics)
    ///   final permute (the squeeze trigger from Absorbing mode)
    ///   output = state[capacity] = state[1]
    ///
    /// **Empty input → field zero.** Mirrors `poseidon_hash` early-out.
    ///
    /// **Differential test:** `assert_in_circuit_matches_off_chain_n`
    /// in this module verifies byte-equality with
    /// `zkp::poseidon_bn254::poseidon_hash` for several input lengths.
    pub fn hash_n(
        config: &PoseidonChipConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        inputs: &[Value<Halo2Fr>],
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        if inputs.is_empty() {
            // Match `poseidon_hash([])` = field zero by assigning
            // a constant zero cell. Use a dedicated region.
            return layouter.assign_region(
                || "poseidon_hash_n_empty",
                |mut region| {
                    let cell = region.assign_advice(
                        || "zero",
                        config.state[1],
                        0,
                        || Value::known(Halo2Fr::ZERO),
                    )?;
                    Ok(cell)
                },
            );
        }

        layouter.assign_region(
            || "poseidon_hash_n",
            |mut region| {
                let cfg = poseidon_config();
                // Walking the arkworks absorb_internal logic:
                //
                //   state := [0, 0, 0]
                //   loop:
                //     if rate_start_index + remaining.len() <= rate:
                //         add remaining to state[capacity + rate_start_index..]
                //         break out of absorb loop, mode=Absorbing
                //     else:
                //         add (rate - rate_start_index) elements to state[capacity..]
                //         permute
                //         remaining = remaining[(rate-rate_start_index)..]
                //         rate_start_index = 0
                //   squeeze: permute (transition Absorbing→Squeezing),
                //            return state[capacity]
                //
                // For our rate=2, capacity=1, every absorb chunk is
                // either the FINAL partial chunk (1 element if odd
                // length) or a full pair. Let's enumerate the
                // sequence of (absorb-pair, permute, absorb-pair,
                // permute, ..., final-absorb) and lay it out.
                let mut row = 0usize;
                // Initial state at row 0 = [0, 0, 0].
                let mut state_vals: [Value<Halo2Fr>; STATE_WIDTH] = [
                    Value::known(Halo2Fr::ZERO),
                    Value::known(Halo2Fr::ZERO),
                    Value::known(Halo2Fr::ZERO),
                ];

                // Absorb loop. Process inputs in chunks of `rate`.
                // After each non-final chunk, permute. After the
                // final chunk, do NOT permute here — the squeeze
                // step does it.
                let total_chunks = inputs.len().div_ceil(RATE);
                for chunk_idx in 0..total_chunks {
                    let chunk_start = chunk_idx * RATE;
                    let is_last_chunk = chunk_idx == total_chunks - 1;

                    // Absorb step (1 row):
                    //   row N: state = state_curr; absorb_in = [in0, in1 (or 0)]; s_absorb on
                    //   row N+1: state = state_curr + [0, in0, in1]
                    // Then if not last chunk, permutation occupies rows N+1..N+1+TOTAL_ROUNDS.
                    let in0 = inputs.get(chunk_start).copied().unwrap_or(Value::known(Halo2Fr::ZERO));
                    let in1 = if RATE >= 2 {
                        inputs
                            .get(chunk_start + 1)
                            .copied()
                            .unwrap_or(Value::known(Halo2Fr::ZERO))
                    } else {
                        Value::known(Halo2Fr::ZERO)
                    };

                    // Assign current state cells.
                    for j in 0..STATE_WIDTH {
                        region.assign_advice(
                            || format!("absorb_state[{}] r{}", j, row),
                            config.state[j],
                            row,
                            || state_vals[j],
                        )?;
                    }
                    // Assign the absorb_in cells.
                    region.assign_advice(
                        || format!("absorb_in[0] r{}", row),
                        config.absorb_in[0],
                        row,
                        || in0,
                    )?;
                    region.assign_advice(
                        || format!("absorb_in[1] r{}", row),
                        config.absorb_in[1],
                        row,
                        || in1,
                    )?;
                    // Enable absorb selector at this row.
                    config.s_absorb.enable(&mut region, row)?;

                    // Compute post-absorb state (witness):
                    let post_state: [Value<Halo2Fr>; STATE_WIDTH] = [
                        state_vals[0], // capacity unchanged
                        state_vals[1].zip(in0).map(|(s, x)| s + x),
                        state_vals[2].zip(in1).map(|(s, x)| s + x),
                    ];
                    state_vals = post_state;
                    row += 1;

                    // If not last chunk, run a permutation.
                    if !is_last_chunk {
                        state_vals = Self::assign_permutation_rows(
                            &mut region,
                            config,
                            cfg,
                            &mut row,
                            state_vals,
                        )?;
                    }
                }

                // Final permute (squeeze trigger).
                state_vals = Self::assign_permutation_rows(
                    &mut region,
                    config,
                    cfg,
                    &mut row,
                    state_vals,
                )?;

                // Assign the final state row (no selector — terminal).
                let mut output_cell: Option<AssignedCell<Halo2Fr, Halo2Fr>> = None;
                for j in 0..STATE_WIDTH {
                    let cell = region.assign_advice(
                        || format!("final[{}]", j),
                        config.state[j],
                        row,
                        || state_vals[j],
                    )?;
                    if j == 1 {
                        output_cell = Some(cell);
                    }
                }
                Ok(output_cell.expect("state[1] cell assigned"))
            },
        )
    }

    /// Helper: assign a 64-round permutation starting at the given
    /// row. Caller has already placed the input state at `*row`;
    /// this function places rows `*row..*row + TOTAL_ROUNDS`,
    /// leaving the post-permutation state in `state_vals` and
    /// advancing `*row` to where the next absorb step (or final
    /// state assignment) will go.
    ///
    /// Note: the output state is written at row `*row + TOTAL_ROUNDS`
    /// by the round-transition gate at row `*row + TOTAL_ROUNDS - 1`,
    /// but the cell is NOT assigned by this function — the caller
    /// is responsible for either assigning the next absorb's
    /// state advice or assigning the final state row.
    fn assign_permutation_rows(
        region: &mut halo2_proofs::circuit::Region<Halo2Fr>,
        config: &PoseidonChipConfig,
        cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<ArkFr>,
        row: &mut usize,
        mut state_vals: [Value<Halo2Fr>; STATE_WIDTH],
    ) -> Result<[Value<Halo2Fr>; STATE_WIDTH], ErrorFront> {
        // Pre-compute MDS as halo2 Fr.
        let mds: [[Halo2Fr; STATE_WIDTH]; STATE_WIDTH] = {
            let mut out = [[Halo2Fr::ZERO; STATE_WIDTH]; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                for j in 0..STATE_WIDTH {
                    out[i][j] = ark_to_halo2_fr(&cfg.mds[i][j]);
                }
            }
            out
        };

        for round in 0..TOTAL_ROUNDS {
            let cur_row = *row + round;
            // Assign current-row state advice cells (input to this
            // round). For round 0, the caller has already placed
            // the same values at this row — re-assigning is a copy
            // op equivalent. For round >= 1, this row was the
            // "next" row for the previous round's gate; the gate
            // constrains its values, but we still need to write
            // them so the cells are assigned.
            for j in 0..STATE_WIDTH {
                region.assign_advice(
                    || format!("state[{}] r{}", j, cur_row),
                    config.state[j],
                    cur_row,
                    || state_vals[j],
                )?;
            }
            // Assign current-row ARK fixed cells.
            for j in 0..STATE_WIDTH {
                let ark_val = ark_to_halo2_fr(&cfg.ark[round][j]);
                region.assign_fixed(
                    || format!("ark[{}] r{}", j, cur_row),
                    config.ark[j],
                    cur_row,
                    || Value::known(ark_val),
                )?;
            }
            // Selector.
            let is_full = round < HALF_FULL_ROUNDS
                || round >= HALF_FULL_ROUNDS + PARTIAL_ROUNDS;
            if is_full {
                config.s_full.enable(region, cur_row)?;
            } else {
                config.s_partial.enable(region, cur_row)?;
            }
            // Compute next state.
            let ark_round: [Halo2Fr; STATE_WIDTH] = [
                ark_to_halo2_fr(&cfg.ark[round][0]),
                ark_to_halo2_fr(&cfg.ark[round][1]),
                ark_to_halo2_fr(&cfg.ark[round][2]),
            ];
            let mut transformed: [Value<Halo2Fr>; STATE_WIDTH] =
                [Value::known(Halo2Fr::ZERO); STATE_WIDTH];
            for j in 0..STATE_WIDTH {
                let pre = state_vals[j].map(|v| v + ark_round[j]);
                if is_full || j == 0 {
                    transformed[j] = pre.map(|x| {
                        let x2 = x * x;
                        let x4 = x2 * x2;
                        x4 * x
                    });
                } else {
                    transformed[j] = pre;
                }
            }
            let mut new_state: [Value<Halo2Fr>; STATE_WIDTH] =
                [Value::known(Halo2Fr::ZERO); STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                let mut acc = Value::known(Halo2Fr::ZERO);
                for j in 0..STATE_WIDTH {
                    let mds_ij = mds[i][j];
                    acc = acc.zip(transformed[j]).map(|(a, t)| a + mds_ij * t);
                }
                new_state[i] = acc;
            }
            state_vals = new_state;
        }
        *row += TOTAL_ROUNDS;
        Ok(state_vals)
    }

    /// Convenience wrapper for the leaf-hash case (2 inputs).
    /// Equivalent to `hash_n(layouter, &[a, b])` but slightly more
    /// efficient (skips the absorb gate row since rate=2 absorbs
    /// straight into the initial state).
    pub fn hash_pair(
        config: &PoseidonChipConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        a: Value<Halo2Fr>,
        b: Value<Halo2Fr>,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        let cfg = poseidon_config();

        layouter.assign_region(
            || "poseidon_hash_pair",
            |mut region| {
                // Arkworks PoseidonSponge state layout:
                //   state[0..capacity]     = capacity slots (init zero)
                //   state[capacity..]      = rate slots
                // For our config (capacity=1, rate=2):
                //   state[0] = capacity (init 0)
                //   state[1] = rate slot 0 (= a after absorb)
                //   state[2] = rate slot 1 (= b after absorb)
                // After absorb([a, b]) without permutation:
                //   state = [0, a, b]
                // squeeze_native_field_elements transitions
                // Absorbing → permute → return state[capacity..],
                // so output is state[1] AFTER permutation.
                let mut state_vals: [Value<Halo2Fr>; STATE_WIDTH] =
                    [Value::known(Halo2Fr::ZERO), a, b];

                for round in 0..TOTAL_ROUNDS {
                    // Assign current-row state advice cells.
                    for j in 0..STATE_WIDTH {
                        region.assign_advice(
                            || format!("state[{}] r{}", j, round),
                            config.state[j],
                            round,
                            || state_vals[j],
                        )?;
                    }
                    // Assign current-row ARK fixed cells.
                    for j in 0..STATE_WIDTH {
                        let ark_val = ark_to_halo2_fr(&cfg.ark[round][j]);
                        region.assign_fixed(
                            || format!("ark[{}] r{}", j, round),
                            config.ark[j],
                            round,
                            || Value::known(ark_val),
                        )?;
                    }

                    // Determine round type and enable selector.
                    let is_full = round < HALF_FULL_ROUNDS
                        || round >= HALF_FULL_ROUNDS + PARTIAL_ROUNDS;
                    if is_full {
                        config.s_full.enable(&mut region, round)?;
                    } else {
                        config.s_partial.enable(&mut region, round)?;
                    }

                    // Compute the next-round state values (witness).
                    let ark_round: [Halo2Fr; STATE_WIDTH] = [
                        ark_to_halo2_fr(&cfg.ark[round][0]),
                        ark_to_halo2_fr(&cfg.ark[round][1]),
                        ark_to_halo2_fr(&cfg.ark[round][2]),
                    ];
                    let mds: [[Halo2Fr; STATE_WIDTH]; STATE_WIDTH] = {
                        let mut out = [[Halo2Fr::ZERO; STATE_WIDTH]; STATE_WIDTH];
                        for i in 0..STATE_WIDTH {
                            for j in 0..STATE_WIDTH {
                                out[i][j] = ark_to_halo2_fr(&cfg.mds[i][j]);
                            }
                        }
                        out
                    };

                    let mut transformed: [Value<Halo2Fr>; STATE_WIDTH] =
                        [Value::known(Halo2Fr::ZERO); STATE_WIDTH];
                    for j in 0..STATE_WIDTH {
                        let pre = state_vals[j].map(|v| v + ark_round[j]);
                        if is_full || j == 0 {
                            transformed[j] = pre.map(|x| {
                                let x2 = x * x;
                                let x4 = x2 * x2;
                                x4 * x
                            });
                        } else {
                            transformed[j] = pre;
                        }
                    }

                    let mut new_state: [Value<Halo2Fr>; STATE_WIDTH] =
                        [Value::known(Halo2Fr::ZERO); STATE_WIDTH];
                    for i in 0..STATE_WIDTH {
                        let mut acc = Value::known(Halo2Fr::ZERO);
                        for j in 0..STATE_WIDTH {
                            let mds_ij = mds[i][j];
                            acc = acc.zip(transformed[j]).map(|(a, t)| a + mds_ij * t);
                        }
                        new_state[i] = acc;
                    }
                    state_vals = new_state;
                }

                // Assign the final row (TOTAL_ROUNDS) — the squeezable
                // state. No selector is enabled here because there's
                // no "next row" to constrain.
                //
                // Output: state[capacity] = state[1] (first rate slot
                // after permutation). Arkworks `squeeze_internal`
                // returns `state[capacity..capacity+1]` for a 1-element
                // squeeze, which is state[1].
                let mut final_cell: Option<AssignedCell<Halo2Fr, Halo2Fr>> = None;
                for j in 0..STATE_WIDTH {
                    let cell = region.assign_advice(
                        || format!("final[{}]", j),
                        config.state[j],
                        TOTAL_ROUNDS,
                        || state_vals[j],
                    )?;
                    if j == 1 {
                        final_cell = Some(cell);
                    }
                }

                Ok(final_cell.expect("state[1] cell assigned"))
            },
        )
    }
}

// ---------------------------------------------------------------------------
// LinearChip — in-circuit Q16.16 linear layer: y[i] = sum_j (W[i][j] * x[j]) >> 16 + b[i].
// ---------------------------------------------------------------------------
//
// **Goal:** prove that `y` matches `precompiles::q16::ops::linear(W, x, b)`
// byte-for-byte for safe-range inputs (no Q16 saturation triggered).
// This chip is the second half of the InferenceCircuit (the first half
// being PoseidonChip, which commits the inputs/weights/outputs).
//
// **Encoding:** Q16.16 values are mapped to BN254 Fr via signed encoding:
//   - non-negative v ∈ [0, 2^31)  → Fr(v as u64)
//   - negative     v ∈ [-2^31, 0) → -Fr((-v) as u64)  (field negation)
// Off-chain `precompiles::q16::Q16` values (i32 newtypes) round-trip
// via this encoding. Field arithmetic on these encodings agrees with
// signed integer arithmetic mod 2^254 (the field modulus); for safe-range
// products this means the field product equals the signed product
// exactly (no wraparound).
//
// **Decomposition gate:** for each (i, j) product row:
//   prod = W[i][j] * x[j]            (field mul)
//   prod = hi * 2^16 + lo            (shift constraint)
//   acc_curr = acc_prev + hi         (accumulator step; init from hi at j=0)
// then on the final row of each output:
//   y[i] = acc_prev_row + b[i]
//
// **Saturation status:** this chip does NOT implement Q16 saturation
// in-circuit. The differential test only exercises safe-range inputs
// (small magnitudes that don't trigger saturation in `q16::ops::linear`).
// Adding saturation requires range-checks on `lo` (∈ [0, 2^16)) and `hi`
// (∈ [-2^31, 2^31)) via lookup tables, plus conditional clamping logic.
// That upgrade is tracked as RM-M2 follow-up; for RM-M1b's InferenceCircuit
// we constrain inputs to safe range at the prover side and document the
// limitation. The chip's structural correctness for the linear-sum
// portion is unaffected.
//
// **Soundness note:** without range checks on `lo`, a malicious prover
// could choose any `(hi', lo')` satisfying `prod = hi' * 2^16 + lo'` in
// field — infinitely many in p. For an honest prover (which this
// differential test exercises), `lo = prod mod 2^16` and `hi = prod
// floor-div 2^16` is the unique correct choice. Production InferenceCircuit
// MUST add the lookup-based range checks before mainnet. The off-chain
// witness generator embeds the correct values; the prototype trusts
// that the prover follows the witness contract.

#[derive(Clone, Debug)]
pub struct LinearChipConfig {
    /// W[i][j] cell on each product row.
    pub w: Column<Advice>,
    /// x[j] cell on each product row.
    pub x: Column<Advice>,
    /// W[i][j] * x[j] in field on each product row.
    pub prod: Column<Advice>,
    /// (W*x) >> 16 (signed Q16) on each product row.
    pub hi: Column<Advice>,
    /// (W*x) mod 2^16 (in [0, 2^16) for honest prover) on each product row.
    pub lo: Column<Advice>,
    /// Running accumulator: at row j, sum_{k <= j} hi[k].
    pub acc: Column<Advice>,
    /// b[i] cell on the output row.
    pub b: Column<Advice>,
    /// y[i] cell on the output row.
    pub y: Column<Advice>,

    /// Selector for "prod = w * x".
    pub s_prod: Selector,
    /// Selector for "prod = hi * 2^16 + lo".
    pub s_shift: Selector,
    /// Selector for "acc = hi" on the first product row.
    pub s_acc_init: Selector,
    /// Selector for "acc_curr = acc_prev + hi_curr" on subsequent product rows.
    pub s_acc_step: Selector,
    /// Selector for "y = acc_prev_row + b" on the output row.
    pub s_output: Selector,
}

pub struct LinearChip;

/// Q16-style "signed shift right 16" of a field-encoded product: returns
/// (hi, lo) where prod_signed = hi * 2^16 + lo as signed i64, with lo in
/// [0, 2^16). Both pieces are returned as halo2 Fr in signed encoding
/// (lo is naturally non-negative; hi may be negative).
fn signed_shift_decomp(prod_signed: i64) -> (Halo2Fr, Halo2Fr) {
    let lo = (prod_signed & 0xFFFF) as u64;
    let hi = prod_signed >> 16;
    (i64_to_halo2_fr(hi), Halo2Fr::from(lo))
}

/// Map a signed i64 into BN254 Fr via the standard signed-into-field
/// embedding.
fn i64_to_halo2_fr(v: i64) -> Halo2Fr {
    if v >= 0 {
        Halo2Fr::from(v as u64)
    } else {
        // (-v) as u64 is unsigned-abs; -i64::MIN would overflow, but for
        // Q16 products of i32 * i32 we never reach that bound (max
        // |prod| < 2^62 < 2^63).
        -Halo2Fr::from(v.unsigned_abs())
    }
}

/// Map an off-chain `Q16` value to halo2 Fr in signed encoding.
pub fn q16_to_halo2_fr(q: crate::precompiles::q16::Q16) -> Halo2Fr {
    i64_to_halo2_fr(q.0 as i64)
}

impl LinearChip {
    /// Configure the chip's gates.
    pub fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> LinearChipConfig {
        let w = meta.advice_column();
        let x = meta.advice_column();
        let prod = meta.advice_column();
        let hi = meta.advice_column();
        let lo = meta.advice_column();
        let acc = meta.advice_column();
        let b = meta.advice_column();
        let y = meta.advice_column();
        for col in [w, x, prod, hi, lo, acc, b, y].iter() {
            meta.enable_equality(*col);
        }

        let s_prod = meta.selector();
        let s_shift = meta.selector();
        let s_acc_init = meta.selector();
        let s_acc_step = meta.selector();
        let s_output = meta.selector();

        // Gate 1: prod = w * x
        meta.create_gate("linear_prod", |meta| {
            let s = meta.query_selector(s_prod);
            let w_v = meta.query_advice(w, Rotation::cur());
            let x_v = meta.query_advice(x, Rotation::cur());
            let p_v = meta.query_advice(prod, Rotation::cur());
            vec![s * (p_v - w_v * x_v)]
        });

        // Gate 2: prod = hi * 2^16 + lo
        meta.create_gate("linear_shift", |meta| {
            let s = meta.query_selector(s_shift);
            let p_v = meta.query_advice(prod, Rotation::cur());
            let hi_v = meta.query_advice(hi, Rotation::cur());
            let lo_v = meta.query_advice(lo, Rotation::cur());
            let two_pow_16 = Expression::Constant(Halo2Fr::from(1u64 << 16));
            vec![s * (p_v - hi_v * two_pow_16 - lo_v)]
        });

        // Gate 3: acc = hi at j=0.
        meta.create_gate("linear_acc_init", |meta| {
            let s = meta.query_selector(s_acc_init);
            let acc_v = meta.query_advice(acc, Rotation::cur());
            let hi_v = meta.query_advice(hi, Rotation::cur());
            vec![s * (acc_v - hi_v)]
        });

        // Gate 4: acc_curr = acc_prev + hi_curr (j > 0).
        meta.create_gate("linear_acc_step", |meta| {
            let s = meta.query_selector(s_acc_step);
            let acc_curr = meta.query_advice(acc, Rotation::cur());
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            let hi_curr = meta.query_advice(hi, Rotation::cur());
            vec![s * (acc_curr - acc_prev - hi_curr)]
        });

        // Gate 5: output row — y = acc_prev_row + b.
        meta.create_gate("linear_output", |meta| {
            let s = meta.query_selector(s_output);
            let y_v = meta.query_advice(y, Rotation::cur());
            let b_v = meta.query_advice(b, Rotation::cur());
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            vec![s * (y_v - acc_prev - b_v)]
        });

        LinearChipConfig {
            w, x, prod, hi, lo, acc, b, y,
            s_prod, s_shift, s_acc_init, s_acc_step, s_output,
        }
    }

    /// Synthesize the linear layer for `out_dim` outputs of `in_dim`-vector
    /// input. Each output gets its own region of `in_dim + 1` rows.
    /// `weights[i*in_dim..(i+1)*in_dim]` is the row for output i.
    ///
    /// Returns the assigned y[i] cells in order.
    pub fn linear(
        config: &LinearChipConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        weights: &[Value<Halo2Fr>],
        inputs: &[Value<Halo2Fr>],
        biases: &[Value<Halo2Fr>],
        out_dim: usize,
        in_dim: usize,
    ) -> Result<Vec<AssignedCell<Halo2Fr, Halo2Fr>>, ErrorFront> {
        debug_assert_eq!(weights.len(), out_dim * in_dim);
        debug_assert_eq!(inputs.len(), in_dim);
        debug_assert_eq!(biases.len(), out_dim);
        debug_assert!(in_dim >= 1, "in_dim must be >= 1");

        let two_pow_16_inv = {
            // Compute as field element: needed for off-circuit witness derivation
            // of (hi, lo). Not used here directly, but a helpful note.
            let _ = Halo2Fr::from(1u64 << 16);
        };
        let _ = two_pow_16_inv;

        let mut output_cells = Vec::with_capacity(out_dim);

        for i in 0..out_dim {
            let cell = layouter.assign_region(
                || format!("linear_output_{}", i),
                |mut region| {
                    // Witness running accumulator (signed i64 in field).
                    let mut acc_signed: i64 = 0;

                    for j in 0..in_dim {
                        // Assign w[i][j] and x[j].
                        region.assign_advice(
                            || format!("w[{},{}]", i, j),
                            config.w,
                            j,
                            || weights[i * in_dim + j],
                        )?;
                        region.assign_advice(
                            || format!("x[{}]", j),
                            config.x,
                            j,
                            || inputs[j],
                        )?;

                        // Compute prod, hi, lo from the witnessed values.
                        // Need to extract i64 from the Value<Halo2Fr>; the
                        // Value::map handles unknown-witness mode for
                        // halo2's verifier-only synthesis.
                        let w_val = weights[i * in_dim + j];
                        let x_val = inputs[j];
                        let prod_field = w_val.zip(x_val).map(|(w, x)| w * x);
                        region.assign_advice(
                            || format!("prod[{},{}]", i, j),
                            config.prod,
                            j,
                            || prod_field,
                        )?;

                        // Decompose prod into (hi, lo) using i64 arithmetic
                        // on the witness side. We need to extract i64 from
                        // Halo2Fr; we do this by checking the canonical
                        // representation. For safe-range inputs the field
                        // element fits in i64 (positive: low 64 bits;
                        // negative: -((p - field) low 64 bits)).
                        let (hi_v, lo_v) = w_val.zip(x_val).map(|(w_fr, x_fr)| {
                            let w_signed = halo2_fr_to_signed_i32(&w_fr) as i64;
                            let x_signed = halo2_fr_to_signed_i32(&x_fr) as i64;
                            let p_signed = w_signed * x_signed;
                            signed_shift_decomp(p_signed)
                        }).unzip();

                        region.assign_advice(
                            || format!("hi[{},{}]", i, j),
                            config.hi,
                            j,
                            || hi_v,
                        )?;
                        region.assign_advice(
                            || format!("lo[{},{}]", i, j),
                            config.lo,
                            j,
                            || lo_v,
                        )?;

                        // Update the i64 accumulator.
                        let _: Value<()> = w_val.zip(x_val).map(|(w_fr, x_fr)| {
                            let w_signed = halo2_fr_to_signed_i32(&w_fr) as i64;
                            let x_signed = halo2_fr_to_signed_i32(&x_fr) as i64;
                            let p = w_signed * x_signed;
                            acc_signed = acc_signed.wrapping_add(p >> 16);
                        });

                        let acc_fr_val = w_val.zip(x_val).map(|_| i64_to_halo2_fr(acc_signed));
                        region.assign_advice(
                            || format!("acc[{},{}]", i, j),
                            config.acc,
                            j,
                            || acc_fr_val,
                        )?;

                        // Selectors.
                        config.s_prod.enable(&mut region, j)?;
                        config.s_shift.enable(&mut region, j)?;
                        if j == 0 {
                            config.s_acc_init.enable(&mut region, j)?;
                        } else {
                            config.s_acc_step.enable(&mut region, j)?;
                        }
                    }

                    // Output row at index in_dim.
                    let out_row = in_dim;
                    region.assign_advice(
                        || format!("b[{}]", i),
                        config.b,
                        out_row,
                        || biases[i],
                    )?;
                    let y_val = biases[i].map(|b_fr| i64_to_halo2_fr(acc_signed) + b_fr);
                    let y_cell = region.assign_advice(
                        || format!("y[{}]", i),
                        config.y,
                        out_row,
                        || y_val,
                    )?;
                    config.s_output.enable(&mut region, out_row)?;

                    Ok(y_cell)
                },
            )?;
            output_cells.push(cell);
        }

        Ok(output_cells)
    }
}

/// Recover the signed i32 represented by a Q16-encoded BN254 Fr.
///
/// Mirror of `q16_to_halo2_fr`: positive values in [0, 2^31) embed as
/// themselves; negative values in [-2^31, 0) embed as p - |v| (i.e.,
/// the field negation). We detect negative by comparing against p/2.
///
/// **Saturation note:** for in-range Q16 values this is exact. For
/// Fr values outside the embedding (e.g., a malicious witness with
/// arbitrary field elements), the result is undefined — the chip
/// gates do not validate this, only the differential test contract.
fn halo2_fr_to_signed_i32(v: &Halo2Fr) -> i32 {
    use halo2curves::ff::PrimeField as _;
    let bytes_le = v.to_repr();
    let bytes_slice: &[u8] = bytes_le.as_ref();
    let bytes: &[u8; 32] = bytes_slice.try_into().expect("Fr repr is 32 bytes");
    // Check if v < (p+1)/2 → positive; else negative (p - v).
    // BN254 Fr modulus p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    // (p+1)/2 ≈ 0x18322739708d8d0...
    // Easiest: check the high bit of the canonical LE bytes — for
    // values < p/2, byte 31 < 0x18; for values > p/2, byte 31 ≥ 0x18.
    let high = bytes[31];
    if high < 0x18 {
        // Non-negative; recover low 32 bits as i32.
        let mut low4 = [0u8; 4];
        low4.copy_from_slice(&bytes[..4]);
        let u = u32::from_le_bytes(low4);
        // For values exceeding i32 range (in Q16 multiplication
        // intermediates, this only happens out-of-spec), reinterpret
        // as i32; downstream consumers handle.
        u as i32
    } else {
        // Negative; compute p - v in 4-byte low chunk.
        // p_low = 0xf0000001 (low 32 bits of p)
        // For Fr value V (with V > p/2), the represented signed value
        // is V - p. low 32 bits of (V - p) = V_low - p_low (mod 2^32).
        let mut low4 = [0u8; 4];
        low4.copy_from_slice(&bytes[..4]);
        let v_low = u32::from_le_bytes(low4);
        let p_low: u32 = 0xf0000001;
        let signed_low = v_low.wrapping_sub(p_low);
        signed_low as i32
    }
}

// ---------------------------------------------------------------------------
// Differential test against off-chain poseidon_bn254::poseidon_hash.
// ---------------------------------------------------------------------------
//
// The soundness gate. For any input pair (a, b):
//
//   in_circuit_hash_pair(a, b).bytes()
//   == off_chain_poseidon_hash([a_ark, b_ark]).bytes()
//
// If the chip's gate / selector / round-counter logic is wrong,
// this fails byte-precise. There's no fudge factor.

#[cfg(test)]
pub fn assert_in_circuit_matches_off_chain_pair(a: Halo2Fr, b: Halo2Fr) {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, ErrorFront, Instance, Column},
    };

    /// Test circuit: hashes (a, b) and exposes the result as a
    /// public input. MockProver rejects if the public input
    /// doesn't match the cell value.
    #[derive(Default, Clone)]
    struct PairCircuit {
        a: Value<Halo2Fr>,
        b: Value<Halo2Fr>,
    }

    #[derive(Clone, Debug)]
    struct PairConfig {
        poseidon: PoseidonChipConfig,
        instance: Column<Instance>,
    }

    impl Circuit<Halo2Fr> for PairCircuit {
        type Config = PairConfig;
        type FloorPlanner = SimpleFloorPlanner;

        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
            let poseidon = PoseidonChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            PairConfig { poseidon, instance }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Halo2Fr>,
        ) -> Result<(), ErrorFront> {
            let out_cell =
                PoseidonChip::hash_pair(&config.poseidon, &mut layouter, self.a, self.b)?;
            layouter.constrain_instance(out_cell.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    // Off-chain hash to compare against.
    let a_ark = halo2_to_ark_fr(&a);
    let b_ark = halo2_to_ark_fr(&b);
    let expected_ark = poseidon_hash(&[a_ark, b_ark]);
    let expected = ark_to_halo2_fr(&expected_ark);

    let circuit = PairCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };

    // k=8 = 256 rows: more than enough for 65 permutation rows
    // plus halo2 blinding. Smaller k may not fit the gate degree
    // requirement (degree 5 needs at least k where 2^k >= n_rows
    // + blinding).
    let k = 8;
    let public_inputs = vec![vec![expected]];

    let prover = MockProver::run(k, &circuit, public_inputs)
        .expect("MockProver setup");
    let r = prover.verify();
    assert_eq!(
        r,
        Ok(()),
        "PoseidonChip::hash_pair output does NOT match off-chain \
         poseidon_hash. a={:?} b={:?} expected={:?}",
        a, b, expected,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_pair_differential_zero() {
        assert_in_circuit_matches_off_chain_pair(Halo2Fr::ZERO, Halo2Fr::ZERO);
    }

    #[test]
    fn hash_pair_differential_simple() {
        let a = Halo2Fr::from(1u64);
        let b = Halo2Fr::from(2u64);
        assert_in_circuit_matches_off_chain_pair(a, b);
    }

    #[test]
    fn hash_pair_differential_order_sensitive() {
        // Sanity: chip is order-sensitive. Hash(1, 2) and Hash(2, 1)
        // both run through the differential test so the chip's
        // output matches the off-chain output for each. If the
        // chip were symmetric incorrectly, one of the two would
        // fail.
        let one = Halo2Fr::from(1u64);
        let two = Halo2Fr::from(2u64);
        assert_in_circuit_matches_off_chain_pair(one, two);
        assert_in_circuit_matches_off_chain_pair(two, one);
    }

    #[test]
    fn hash_pair_differential_large_values() {
        // Stress test with non-trivially-sized field elements
        // (still well below the modulus).
        let a = Halo2Fr::from(0xFEEDFACECAFEBEEFu64);
        let b = Halo2Fr::from(0xDEADBEEF12345678u64);
        assert_in_circuit_matches_off_chain_pair(a, b);
    }

    // ---------------------------------------------------------
    // hash_n differential tests — arbitrary input length.
    // ---------------------------------------------------------

    fn assert_hash_n_matches(inputs_h: &[Halo2Fr]) {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            dev::MockProver,
            plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
        };

        #[derive(Default, Clone)]
        struct NCircuit {
            inputs: Vec<Value<Halo2Fr>>,
        }

        #[derive(Clone, Debug)]
        struct NConfig {
            poseidon: PoseidonChipConfig,
            instance: Column<Instance>,
        }

        impl Circuit<Halo2Fr> for NCircuit {
            type Config = NConfig;
            type FloorPlanner = SimpleFloorPlanner;

            #[cfg(feature = "circuit-params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
                let poseidon = PoseidonChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                NConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Halo2Fr>,
            ) -> Result<(), ErrorFront> {
                let out = PoseidonChip::hash_n(&config.poseidon, &mut layouter, &self.inputs)?;
                layouter.constrain_instance(out.cell(), config.instance, 0)?;
                Ok(())
            }
        }

        // Compute expected via off-chain BN254 Poseidon.
        let inputs_ark: Vec<ArkFr> = inputs_h.iter().map(halo2_to_ark_fr).collect();
        let expected_ark = poseidon_hash(&inputs_ark);
        let expected = ark_to_halo2_fr(&expected_ark);

        let circuit = NCircuit {
            inputs: inputs_h.iter().map(|v| Value::known(*v)).collect(),
        };

        // k=11 = 2048 rows: enough for ~30 permutation blocks
        // (~30 × 65 ≈ 1950 rows). Larger k for very long inputs.
        // For our tests with up to ~10 inputs (= 5 perms = ~325
        // rows), k=10 suffices but we use k=11 for headroom.
        let k = 11;
        let prover =
            MockProver::run(k, &circuit, vec![vec![expected]]).expect("mockprover setup");
        let r = prover.verify();
        assert_eq!(
            r,
            Ok(()),
            "hash_n output mismatch for inputs of length {}",
            inputs_h.len()
        );
    }

    #[test]
    fn hash_n_empty() {
        // Empty input maps to field zero per arkworks early-out
        // and our chip's matching short-circuit.
        assert_hash_n_matches(&[]);
    }

    #[test]
    fn hash_n_single() {
        // L=1: one absorb (with implicit zero-pad in rate slot 1),
        // one squeeze permute. Tests the odd-length absorb path.
        assert_hash_n_matches(&[Halo2Fr::from(42u64)]);
    }

    #[test]
    fn hash_n_two_matches_hash_pair() {
        // L=2: should match hash_pair. Sanity that the two paths
        // converge.
        let a = Halo2Fr::from(7u64);
        let b = Halo2Fr::from(11u64);
        assert_hash_n_matches(&[a, b]);
    }

    #[test]
    fn hash_n_three() {
        // L=3: triggers absorb-permute cycle (1 mid-permute +
        // 1 final permute = 2 permutations).
        assert_hash_n_matches(&[
            Halo2Fr::from(1u64),
            Halo2Fr::from(2u64),
            Halo2Fr::from(3u64),
        ]);
    }

    #[test]
    fn hash_n_six() {
        // L=6: 3 chunks of rate=2; 2 mid-permutes + 1 final = 3 total.
        let v: Vec<Halo2Fr> = (1u64..=6).map(Halo2Fr::from).collect();
        assert_hash_n_matches(&v);
    }

    #[test]
    fn hash_n_ten() {
        // L=10: stress at the boundary of our k=11 budget.
        let v: Vec<Halo2Fr> = (1u64..=10).map(Halo2Fr::from).collect();
        assert_hash_n_matches(&v);
    }

    // ---------------------------------------------------------
    // TensorCommitChip — composes hash_n with the same 31-byte
    // chunking that off-chain `precompiles::verify::tensor_commit`
    // uses. The byte-level differential test below is the gate
    // that ties 0x0107 (off-chain commit) to 0x0108 (in-circuit
    // recomputation of that commit).
    // ---------------------------------------------------------

    /// Off-chip helper: chunk arbitrary bytes into BN254 Fr
    /// elements via 31-byte chunks (matching the off-chain
    /// `tensor_commit`'s pack pattern). Public so callers
    /// preparing witnesses use the same chunking the chip
    /// expects.
    pub fn chunk_bytes_into_fr(bytes: &[u8]) -> Vec<Halo2Fr> {
        use ark_ff::PrimeField as _;
        bytes
            .chunks(31)
            .map(|chunk| {
                let ark = ArkFr::from_le_bytes_mod_order(chunk);
                ark_to_halo2_fr(&ark)
            })
            .collect()
    }

    /// Differential test: prove the in-circuit commit (via
    /// hash_n on chunked Fr elements) equals the off-chain
    /// 0x0107 commit (via `precompiles::verify::tensor_commit`)
    /// byte-for-byte.
    fn assert_tensor_commit_chip_matches(canonical_input: &[u8]) {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            dev::MockProver,
            plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
        };

        // Off-chain commit (gate target).
        let off_result = crate::precompiles::verify::tensor_commit(canonical_input, 100_000_000)
            .expect("off-chain tensor_commit");
        assert_eq!(off_result.output.len(), 32);
        // The off-chain output is 32-byte big-endian Fr. Convert
        // to halo2 Fr for comparison via instance column.
        let mut be = [0u8; 32];
        be.copy_from_slice(&off_result.output);
        let mut le = be;
        le.reverse();
        let expected: Halo2Fr = {
            use halo2curves::ff::PrimeField as _;
            let opt: Option<Halo2Fr> = Halo2Fr::from_repr(le.into()).into();
            opt.expect("from_repr on hash output")
        };

        // Chunk the input the same way off-chain commit does.
        let chunks = chunk_bytes_into_fr(canonical_input);

        #[derive(Default, Clone)]
        struct CommitCircuit {
            chunks: Vec<Value<Halo2Fr>>,
        }

        #[derive(Clone, Debug)]
        struct CommitConfig {
            poseidon: PoseidonChipConfig,
            instance: Column<Instance>,
        }

        impl Circuit<Halo2Fr> for CommitCircuit {
            type Config = CommitConfig;
            type FloorPlanner = SimpleFloorPlanner;

            #[cfg(feature = "circuit-params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
                let poseidon = PoseidonChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                CommitConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Halo2Fr>,
            ) -> Result<(), ErrorFront> {
                let out =
                    PoseidonChip::hash_n(&config.poseidon, &mut layouter, &self.chunks)?;
                layouter.constrain_instance(out.cell(), config.instance, 0)?;
                Ok(())
            }
        }

        let circuit = CommitCircuit {
            chunks: chunks.iter().map(|c| Value::known(*c)).collect(),
        };

        // k=12 for headroom — small tensors fit at lower k, but
        // a few-hundred-byte tensor needs ~10-30 chunks =
        // ~5-15 permutations × 65 rows ≈ 325-975 rows. k=12
        // (4096 rows) safely covers most reference inputs.
        let k = 12;
        let prover = MockProver::run(k, &circuit, vec![vec![expected]])
            .expect("MockProver setup");
        let r = prover.verify();
        assert_eq!(
            r,
            Ok(()),
            "tensor commit chip mismatch for input of {} bytes \
             (off-chain output: 0x{})",
            canonical_input.len(),
            hex::encode(off_result.output)
        );
    }

    fn q16_tensor(shape: &[u32], values: &[i32]) -> Vec<u8> {
        use crate::precompiles::tensor_format::{encode, Dtype};
        let mut data = Vec::with_capacity(values.len() * 4);
        for &v in values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        encode(shape, Dtype::Q16_16, &data).expect("encode")
    }

    #[test]
    fn tensor_commit_chip_q16_single() {
        let bytes = q16_tensor(&[1], &[0]);
        assert_tensor_commit_chip_matches(&bytes);
    }

    #[test]
    fn tensor_commit_chip_q16_vector() {
        let bytes = q16_tensor(&[3], &[1, 2, 3]);
        assert_tensor_commit_chip_matches(&bytes);
    }

    #[test]
    fn tensor_commit_chip_q16_matrix_2x2() {
        let bytes = q16_tensor(&[2, 2], &[1, 2, 3, 4]);
        assert_tensor_commit_chip_matches(&bytes);
    }

    #[test]
    fn tensor_commit_chip_field32() {
        use crate::precompiles::tensor_format::{encode, Dtype};
        let bytes = encode(&[1], Dtype::Field32, &[0xAA; 32]).expect("encode");
        assert_tensor_commit_chip_matches(&bytes);
    }

    #[test]
    fn tensor_commit_chip_distinguishes_data() {
        // Same shape, different data → different commitments.
        // The differential test runs both round-trips; if the
        // chip were data-insensitive (or somehow incorrectly
        // wrapping), one of the two would fail.
        let a = q16_tensor(&[3], &[1, 2, 3]);
        let b = q16_tensor(&[3], &[1, 2, 4]);
        assert_tensor_commit_chip_matches(&a);
        assert_tensor_commit_chip_matches(&b);
    }

    // ---------------------------------------------------------
    // LinearChip — Q16.16 linear layer differential test.
    // ---------------------------------------------------------
    //
    // For a given (W, x, b) at safe-range Q16 magnitudes, prove that
    // the in-circuit `linear` output equals the off-chain
    // `precompiles::q16::ops::linear` output byte-for-byte.

    use crate::precompiles::q16::Q16;

    fn assert_linear_chip_matches(
        weights: &[Q16],
        inputs: &[Q16],
        biases: &[Q16],
        out_dim: usize,
        in_dim: usize,
    ) {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            dev::MockProver,
            plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
        };

        // Off-chain reference computes the truth.
        let expected_q16 =
            crate::precompiles::q16::ops::linear(weights, inputs, biases, out_dim, in_dim);
        let expected_fr: Vec<Halo2Fr> =
            expected_q16.iter().copied().map(q16_to_halo2_fr).collect();

        // Circuit witnesses (signed-into-field).
        let weights_fr: Vec<Halo2Fr> =
            weights.iter().copied().map(q16_to_halo2_fr).collect();
        let inputs_fr: Vec<Halo2Fr> = inputs.iter().copied().map(q16_to_halo2_fr).collect();
        let biases_fr: Vec<Halo2Fr> = biases.iter().copied().map(q16_to_halo2_fr).collect();

        #[derive(Default, Clone)]
        struct LinearCircuit {
            weights: Vec<Value<Halo2Fr>>,
            inputs: Vec<Value<Halo2Fr>>,
            biases: Vec<Value<Halo2Fr>>,
            out_dim: usize,
            in_dim: usize,
        }

        #[derive(Clone, Debug)]
        struct LinearTestConfig {
            linear: LinearChipConfig,
            instance: Column<Instance>,
        }

        impl Circuit<Halo2Fr> for LinearCircuit {
            type Config = LinearTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            #[cfg(feature = "circuit-params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self {
                    weights: vec![Value::unknown(); self.weights.len()],
                    inputs: vec![Value::unknown(); self.inputs.len()],
                    biases: vec![Value::unknown(); self.biases.len()],
                    out_dim: self.out_dim,
                    in_dim: self.in_dim,
                }
            }

            fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
                let linear = LinearChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                LinearTestConfig { linear, instance }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Halo2Fr>,
            ) -> Result<(), ErrorFront> {
                let outs = LinearChip::linear(
                    &config.linear,
                    &mut layouter,
                    &self.weights,
                    &self.inputs,
                    &self.biases,
                    self.out_dim,
                    self.in_dim,
                )?;
                for (i, cell) in outs.iter().enumerate() {
                    layouter.constrain_instance(cell.cell(), config.instance, i)?;
                }
                Ok(())
            }
        }

        let circuit = LinearCircuit {
            weights: weights_fr.iter().map(|v| Value::known(*v)).collect(),
            inputs: inputs_fr.iter().map(|v| Value::known(*v)).collect(),
            biases: biases_fr.iter().map(|v| Value::known(*v)).collect(),
            out_dim,
            in_dim,
        };

        // k=8 = 256 rows. Each output uses (in_dim + 1) rows. For tests
        // with out_dim ≤ 4 and in_dim ≤ 16, total ≤ 68 rows, plenty of
        // headroom.
        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![expected_fr])
            .expect("MockProver setup");
        let r = prover.verify();
        assert_eq!(
            r,
            Ok(()),
            "LinearChip output does NOT match off-chain q16::ops::linear \
             for out_dim={} in_dim={}",
            out_dim,
            in_dim
        );
    }

    #[test]
    fn linear_chip_identity_2x2() {
        // y = I · [3, 4] + [10, 20] = [13, 24]
        let w: Vec<Q16> = [1, 0, 0, 1].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = [3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [10, 20].iter().map(|&n| Q16::from_int(n)).collect();
        assert_linear_chip_matches(&w, &x, &b, 2, 2);
    }

    #[test]
    fn linear_chip_basic_row() {
        // y = [[1, 2, 3]] · [4, 5, 6] + [0] = [4 + 10 + 18] = [32]
        let w: Vec<Q16> = [1, 2, 3].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = [4, 5, 6].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = vec![Q16::ZERO];
        assert_linear_chip_matches(&w, &x, &b, 1, 3);
    }

    #[test]
    fn linear_chip_negative_weights() {
        // y = [[2, -1]] · [3, 5] + [0] = [6 - 5] = [1]
        let w: Vec<Q16> = vec![Q16::from_int(2), Q16::from_int(-1)];
        let x: Vec<Q16> = [3, 5].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = vec![Q16::ZERO];
        assert_linear_chip_matches(&w, &x, &b, 1, 2);
    }

    #[test]
    fn linear_chip_zero_input_returns_bias() {
        // y = W · 0 + b = b for any W
        let w: Vec<Q16> = [5, 7, 11, 13].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = vec![Q16::ZERO; 2];
        let b: Vec<Q16> = vec![Q16::from_int(42), Q16::from_int(-17)];
        assert_linear_chip_matches(&w, &x, &b, 2, 2);
    }

    #[test]
    fn linear_chip_3x4() {
        // 3-output, 4-input layer with mixed signs.
        let w: Vec<Q16> = [
            1, -2, 3, -4,    // row 0
            5, 6, -7, -8,    // row 1
            -9, 10, 11, -12, // row 2
        ].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = [1, 2, 3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [100, -200, 300].iter().map(|&n| Q16::from_int(n)).collect();
        assert_linear_chip_matches(&w, &x, &b, 3, 4);
    }
}
