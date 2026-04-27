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
}
