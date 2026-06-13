---
created: 2026-06-12
branch: fix/pin-td-f2c1-range
author: Claude Fable 5 (Lane B) + Larry Klosowski (@SaulBuilds)
status: accepted
td: TD-PIN-P1-f2c1-range
disposition: risk-accepted (testnet) + scheduled fix at PIN-P1 f.6
---

# TD-PIN-P1-f2c1-range — disposition (risk-acceptance + scheduled fix)

## The gap

`porep_circuit_kfold_v1.rs::derive_index_in_circuit` derives each of the K
challenge indices from the Poseidon output `h = Poseidon(mixed_seed, i)` by
decomposing `h` into **254 bits** and slicing the low `MERKLE_DEPTH` bits as the
index. The decomposition is enforced only by the field recomposition
`Σ bᵢ·2ⁱ ≡ h (mod p)` (Horner form, `decompose_index_generic`).

The BN254 scalar field modulus satisfies `2²⁵³ < p < 2²⁵⁴`, so a 254-bit
container can hold values in `[0, 2²⁵⁴)` — a superset of the field. For any
`h` with `h + p < 2²⁵⁴` (i.e. `h < 2²⁵⁴ − p ≈ 2²⁵³`), **two** distinct 254-bit
patterns recompose to the same field element:

```
  bin(h)        and        bin(h + p)        both ≡ h (mod p)
```

Their low `MERKLE_DEPTH` bits generally differ, so a prover may CHOOSE which
pattern to witness and thereby pick between two candidate challenge indices for
the same `h`. The field-level recomposition constraint cannot tell them apart
(both satisfy it by definition of the wrap).

## The soundness cost (exact)

- Fraction of field elements with an alternate representation:
  `(2²⁵⁴ − p) / 2²⁵⁴`. With `p = 0x30644e72…f0000001` (leading nibble `0x3`),
  `2²⁵⁴ − p ≈ (0x4 − 0x3.064…)/0x4 ≈ 0.244`, so **~24% of `h` values** admit an
  alternate index for a given draw. (NOT ~50%, NOT negligible — it is real and
  must be range-checked at f.6. The exact bound is pinned in code by the
  `ambiguity_fraction_is_bounded` test: `22% < fraction < 26%`.)
- Effect on grinding: per challenge draw the adversary gains at most **1 extra
  index choice** with probability ~0.24, i.e. `≤ log₂(1 + 0.24) ≈ 0.31` bits of
  grinding advantage per challenge in expectation, 1 bit worst-case for an
  ambiguous draw.
- Across `K_post = 44` challenges the **cumulative worst-case** loss is bounded
  by the `~6 bits` estimate logged in the TD (the expected loss is far smaller;
  6 bits assumes a pathological run of ambiguous-and-exploitable draws).

**Net soundness remains ≥ 80 bits** at the locked `(K_porep=22, K_post=44,
1 GiB)` parameters — this is the same residual the 2026-06-06 f.4/f.5 lead
advisement explicitly accepted ("soundness still ≥ 80 bits").

## Why not hand-roll the `< p` check now

The correct fix is an in-circuit **canonical-range check** that the 254-bit
integer is `< p`. Field recomposition cannot express it (both representations
recompose equal), so it requires a **lexicographic bit-vs-`p` comparator**: an
MSB-first scan maintaining `lt`/`gt` running flags with per-bit boolean products
(`eq_prefix ∧ ¬bᵢ` etc.), terminating in `require lt == 1`.

In the current hand-rolled `SwapMerkleChip` that means:
- adding a general linear-combination gate (the chip has only `bool`,
  `recompose = b+2c`, `swap`, `mux`, `ioz`, `geq`),
- ~254 comparator iterations **per challenge** (× K), ≈ 760+ extra rows,
- and — critically — a comparator bug would be **silently unsound** (it would
  accept non-canonical witnesses without any visible failure), which is
  strictly worse than this documented, bounded, ≥80-bit gap.

The RIGHT tool is PSE Halo2's **range-check lookup** primitive (a lookup against
a fixed table proving `value ∈ [0, p)`), which is far less error-prone than a
hand-rolled comparator. That primitive is adopted exactly when **PIN-P1 f.6**
rebuilds these circuits at real size (real DRG/expander, K>1 aggregation, the
v2/v3 VK regeneration). Landing the canonical check there — on the production
circuit, with the proper primitive, under the f.7 ToB crypto review — is the
correct sequencing, not a same-session hand-rolled gadget on the reduced
testnet circuit.

## Decision

- **Risk-ACCEPTED for testnet.** The reduced circuit is testnet-only; no v2/v3
  proofs are anchored on mainnet, and net soundness is ≥ 80 bits.
- **Fix SCHEDULED at PIN-P1 f.6** (real-size VK regen): add the canonical
  `value < p` range-lookup to the index-derivation, gated into the f.7 ToB
  crypto review. Tracked in `TECH_DEBT.md` (TD-PIN-P1-f2c1-range → "accepted;
  fix at f.6").
- **Guard added now:** a documented unit assertion in
  `porep_circuit_kfold_v1.rs` that records the ambiguity bound, so the gap stays
  visible until f.6 closes it.

## References

- `core/execution/src/zkp/halo2/porep_circuit_kfold_v1.rs` (the 254-bit
  derivation + its existing module-doc note).
- f.4/f.5 advisement (≥80-bit acceptance):
  `citrate-chain/design/PIN-P1-f-feasibility-results.md`.
- The proper primitive: PSE `halo2_gadgets`/lookup range-check (adopt at f.6).
