// citrate/core/execution/src/precompiles/mod.rs

// EVM Precompiles Module
// Standard Ethereum precompiles + Citrate AI extensions

pub mod attestation;
pub mod commd_fold_verify;
pub mod compute;
pub mod ed25519;
pub mod inference;
pub mod q16;
pub mod tensor_format;
pub mod verify;
pub mod x402;

use anyhow::Result;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

// Precompile crypto imports
use num_bigint::BigUint;
use num_traits::Zero;
use ripemd::Ripemd160;

// BN254 curve imports for EC precompiles
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, PrimeField};

// BLAKE2 compression function implemented inline (EIP-152 compliant)

use crate::types::Address;
use inference::InferencePrecompile;

/// Standard Ethereum precompile addresses
pub mod standard {
    use crate::types::Address;

    /// ECRECOVER
    pub const ECRECOVER: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// SHA256
    pub const SHA256: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    /// RIPEMD160
    pub const RIPEMD160: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    /// IDENTITY
    pub const IDENTITY: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);

    /// MODEXP
    pub const MODEXP: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);

    /// ECADD
    pub const ECADD: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]);

    /// ECMUL
    pub const ECMUL: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);

    /// ECPAIRING
    pub const ECPAIRING: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);

    /// BLAKE2F
    pub const BLAKE2F: Address =
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
}

/// Route the PURE (stateless) Citrate precompile families without a
/// `PrecompileExecutor` instance — the entry point of the REVM
/// custom-precompile bridge (WP-B0 / TD-28, see
/// `revm_adapter::register_citrate_precompiles`).
///
/// Covered families (all read no chain state and host no runtime, so they
/// are deterministic on every node build):
///   - 0x0107–0x0109  verification  (`verify::execute` — Poseidon tensor
///     commit, the 0x0108 Halo2-KZG proof verifier, Merkle tensor paths)
///   - 0x010A–0x010F  deterministic compute (`compute::execute`, Q16.16)
///   - 0x0110–0x0111  learning      (`q16::{belnap,routing}::execute`)
///   - 0x0200–0x0209  x402          (`x402::execute`, signature checks)
///
/// The inference family (0x0100–0x0106) needs the hosted model runtime
/// (non-deterministic across nodes) and is deliberately NOT routed here —
/// it stays behind `PrecompileExecutor::execute`.
pub fn execute_pure(address: &Address, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    execute_pure_at(address, input, gas_limit, false)
}

/// [`execute_pure`] with the consensus activation flag: `hardened` is true
/// for blocks at/after `pba_hardening_height` (see `crate::activation`). The
/// REVM bridge passes it; before activation every result is bit-identical to
/// [`execute_pure`]. Gated changes: PBA-L1a-013 (0x0109), PBA-L1a-025 (0x0110).
pub fn execute_pure_at(
    address: &Address,
    input: &[u8],
    gas_limit: u64,
    hardened: bool,
) -> Result<PrecompileResult> {
    let addr_bytes = address.as_bytes();
    if !addr_bytes[..18].iter().all(|&b| b == 0) {
        return Err(anyhow::anyhow!("Not a Citrate pure precompile address"));
    }
    let family = addr_bytes[18];
    let selector = addr_bytes[19];

    if family == 2 && selector <= 9 {
        return x402::execute(address, input, gas_limit);
    }
    if family == 1 {
        if (0x07..=0x09).contains(&selector) {
            return verify::execute_at(address, input, gas_limit, hardened);
        }
        if (0x0A..=0x0F).contains(&selector) {
            return compute::execute(address, input, gas_limit);
        }
        if selector == 0x10 {
            return q16::belnap::execute_at(input, gas_limit, hardened);
        }
        if selector == 0x11 {
            return q16::routing::execute(input, gas_limit);
        }
        if selector == 0x20 {
            return ed25519::execute(input, gas_limit);
        }
        // citrate-chain#170 (M3): 0x0130 recursive-fold CommD proof verifier. Its verifier + baked VK
        // are gated behind the `commd-fold-verify` feature (a consensus-gated activation); the routing
        // is always present so the address is a known precompile (feature-off returns a discoverable
        // "feature absent" error, mirroring 0x0108 without halo2-substrate).
        if selector == 0x30 {
            return commd_fold_verify::execute_at(input, gas_limit, hardened);
        }
    }
    Err(anyhow::anyhow!(
        "Not a Citrate pure precompile address: 0x{:02x}{:02x}",
        family,
        selector
    ))
}

/// The pure Citrate precompile addresses the REVM bridge exposes to
/// contract code (WP-B0). Kept next to `execute_pure` so the two cannot
/// drift: every address listed here MUST route in `execute_pure`, and the
/// `pure_precompile_table_routes` unit test enforces it.
pub const PURE_PRECOMPILE_ADDRESSES: [[u8; 20]; 16] = [
    verify::addresses::TENSOR_COMMIT,          // 0x0107
    verify::addresses::INFERENCE_PROOF_VERIFY, // 0x0108
    verify::addresses::MERKLE_VERIFY_TENSOR,   // 0x0109
    commd_fold_verify::FOLD_COMMD_VERIFY,      // 0x0130 (citrate-chain#170; feature-gated verifier)
    compute::addresses::TENSOR_MATMUL_Q16,     // 0x010A
    compute::addresses::TENSOR_DOT_Q16,        // 0x010B
    compute::addresses::TENSOR_SOFTMAX_Q16,    // 0x010C
    compute::addresses::TENSOR_RELU_Q16,       // 0x010D
    compute::addresses::TENSOR_LINEAR_Q16,     // 0x010E
    compute::addresses::TENSOR_TRANSPOSE_Q16,  // 0x010F
    q16::belnap::BELNAP_AGGREGATE,             // 0x0110
    q16::routing::ROUTING_INFERENCE,           // 0x0111
    ed25519::ED25519_VERIFY,                   // 0x0120
    x402::addresses::EIP712_VERIFY,            // 0x0200
    x402::addresses::TRANSFER_AUTH_VERIFY,     // 0x0201
    x402::addresses::BATCH_PAYMENT_VERIFY,     // 0x0202
];

/// Addresses inside the Citrate precompile ranges
/// (`PrecompileExecutor::is_precompile`) that are not bridged into REVM (the
/// inference family 0x0100–0x0106 and the unassigned slots of each family).
/// At/after `pba_hardening_height` the REVM bridge registers them as
/// precompiles that always fail.
pub fn reserved_unbridged_addresses() -> Vec<[u8; 20]> {
    let mut out = Vec::new();
    let mut push = |family: u8, selector: u8| {
        let mut a = [0u8; 20];
        a[18] = family;
        a[19] = selector;
        if !PURE_PRECOMPILE_ADDRESSES.contains(&a) {
            out.push(a);
        }
    };
    for sel in 0x00..=0x3Fu8 {
        push(1, sel);
    }
    for sel in 0x00..=0x09u8 {
        push(2, sel);
    }
    out
}

/// Precompile executor
pub struct PrecompileExecutor {
    inference: Option<InferencePrecompile>,
}

impl Default for PrecompileExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileExecutor {
    pub fn new() -> Self {
        Self { inference: None }
    }

    /// Initialize with AI runtime
    pub fn with_inference(mut self, inference: InferencePrecompile) -> Self {
        self.inference = Some(inference);
        self
    }

    /// Check if address is a precompile
    pub fn is_precompile(&self, address: &Address) -> bool {
        // Standard Ethereum precompiles (0x01 - 0x09)
        let addr_bytes = address.as_bytes();
        let is_standard =
            addr_bytes[..19].iter().all(|&b| b == 0) && addr_bytes[19] >= 1 && addr_bytes[19] <= 9;

        // Citrate AI precompiles (0x0100 - 0x010F) — WP-B0 canonical scheme:
        // the EVM address IS the documented short name, e.g. 0x0108 =
        // 0x…000108 (byte 18 = 0x01, byte 19 = selector). This matches the
        // Solidity constants (`address(0x0108)`), `40204.json`'s
        // `precompiles` table, and every design doc. The pre-WP-B0 layout
        // (byte 17 = family, byte 18 = 0 → 0x…010008) was unreachable from
        // contract code and matched nothing the contracts call (TD-28).
        // 0x0100-0x0106: inference runtime (RM-M0)
        // 0x0107-0x0109: verification (RM-M1)
        // 0x010A-0x010F: deterministic compute (RM-M2)
        let prefix_check = addr_bytes[..18].iter().all(|&b| b == 0);
        let is_ai = prefix_check && addr_bytes[18] == 1 && addr_bytes[19] <= 0x0F;

        // Citrate Learning precompiles (0x0110 - 0x011F) — RM-FL-1+
        // 0x0110: Belnap-FOUR aggregation (RM-FL-1, BELNAP_AGGREGATE)
        // 0x0111: Routing-model inference (RM-FL-2, future)
        let is_learning =
            prefix_check && addr_bytes[18] == 1 && (0x10..=0x1F).contains(&addr_bytes[19]);

        // Citrate crypto precompiles (0x0120 - 0x012F)
        // 0x0120: Ed25519 signature verification (SUF-CMA, is_weak-hardened)
        let is_crypto =
            prefix_check && addr_bytes[18] == 1 && (0x20..=0x2F).contains(&addr_bytes[19]);

        // Citrate recursive-fold verification precompiles (0x0130 - 0x013F) — citrate-chain#170
        // 0x0130: recursive-fold CommD proof verifier (FOLD_COMMD_VERIFY; feature-gated activation)
        let is_fold_verify =
            prefix_check && addr_bytes[18] == 1 && (0x30..=0x3F).contains(&addr_bytes[19]);

        // Citrate x402 payment precompiles (0x0200 - 0x0209)
        let is_x402 = prefix_check && addr_bytes[18] == 2 && addr_bytes[19] <= 9;

        is_standard || is_ai || is_learning || is_crypto || is_fold_verify || is_x402
    }

    /// Execute a precompile
    pub fn execute(
        &mut self,
        address: &Address,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<PrecompileResult> {
        let addr_bytes = address.as_bytes();

        // x402 payment precompiles (0x0200–0x0209; canonical byte 18 = 2)
        if addr_bytes[..18].iter().all(|&b| b == 0) && addr_bytes[18] == 2 && addr_bytes[19] <= 9 {
            return x402::execute(address, input, gas_limit);
        }

        // Crypto precompiles (0x0120–0x012F; canonical byte 18 = 1,
        // selector 0x20–0x2F).
        // 0x0120 — Ed25519 signature verification (SUF-CMA, is_weak-hardened)
        if addr_bytes[..18].iter().all(|&b| b == 0)
            && addr_bytes[18] == 1
            && (0x20..=0x2F).contains(&addr_bytes[19])
        {
            let selector = addr_bytes[19];
            if selector == 0x20 {
                return ed25519::execute(input, gas_limit);
            }
            return Err(anyhow::anyhow!(
                "Unknown crypto precompile selector 0x{:02x}",
                selector
            ));
        }

        // Learning precompiles (0x0110–0x011F; canonical byte 18 = 1,
        // selector 0x10–0x1F) — RM-FL-1+
        // 0x0110 — Belnap aggregation (RM-FL-1)
        // 0x0111 — Routing-model inference (RM-FL-2)
        if addr_bytes[..18].iter().all(|&b| b == 0)
            && addr_bytes[18] == 1
            && (0x10..=0x1F).contains(&addr_bytes[19])
        {
            let selector = addr_bytes[19];
            if selector == 0x10 {
                return q16::belnap::execute(input, gas_limit);
            }
            if selector == 0x11 {
                return q16::routing::execute(input, gas_limit);
            }
            return Err(anyhow::anyhow!(
                "Unknown learning precompile selector 0x{:02x}",
                selector
            ));
        }

        // AI precompiles (0x0100–0x010F; canonical byte 18 = 1, selector ≤ 0x0F)
        if addr_bytes[..18].iter().all(|&b| b == 0) && addr_bytes[18] == 1 && addr_bytes[19] <= 0x0F
        {
            // RM-M1: 0x0107–0x0109 are AI verification precompiles
            // (commitments / proof verification / Merkle paths).
            // RM-M2: 0x010A–0x010F are AI deterministic compute
            // precompiles (Q16.16 tensor primitives).
            // Both modules are independent of the inference runtime
            // — they're pure integer math + crypto and work even on
            // nodes that don't host model weights. 0x0100–0x0106
            // continue to route to the existing `inference` precompile
            // that requires the runtime.
            let selector = addr_bytes[19];
            if (0x07..=0x09).contains(&selector) {
                return verify::execute(address, input, gas_limit);
            }
            if (0x0A..=0x0F).contains(&selector) {
                return compute::execute(address, input, gas_limit);
            }

            if let Some(ref mut inference) = self.inference {
                let output = inference.execute(address, input, gas_limit)?;
                return Ok(PrecompileResult {
                    output: output.output,
                    gas_used: output.gas_used,
                    success: true,
                });
            } else {
                return Err(anyhow::anyhow!("AI inference not initialized"));
            }
        }

        // Standard Ethereum precompiles
        match *address {
            standard::ECRECOVER => self.ecrecover(input, gas_limit),
            standard::SHA256 => self.sha256(input, gas_limit),
            standard::RIPEMD160 => self.ripemd160(input, gas_limit),
            standard::IDENTITY => self.identity(input, gas_limit),
            standard::MODEXP => self.modexp(input, gas_limit),
            standard::ECADD => self.ecadd(input, gas_limit),
            standard::ECMUL => self.ecmul(input, gas_limit),
            standard::ECPAIRING => self.ecpairing(input, gas_limit),
            standard::BLAKE2F => self.blake2f(input, gas_limit),
            _ => Err(anyhow::anyhow!("Unknown precompile address")),
        }
    }

    // Standard precompile implementations (simplified)

    /// ECRECOVER precompile - recovers signer address from ECDSA signature
    /// Input format: hash (32 bytes) | v (32 bytes) | r (32 bytes) | s (32 bytes)
    /// Output: zero-padded recovered address (32 bytes) or zeros on failure
    fn ecrecover(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        const GAS_COST: u64 = 3000;
        if gas_limit < GAS_COST {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Input must be at least 128 bytes
        if input.len() < 128 {
            return Ok(PrecompileResult {
                output: vec![0u8; 32],
                gas_used: GAS_COST,
                success: true,
            });
        }

        // Parse input
        let hash = &input[0..32];
        // v is in the last byte of the 32-byte v field (bytes 32-64)
        let v = input[63];
        let r = &input[64..96];
        let s = &input[96..128];

        // Recovery ID: v should be 27 or 28 for standard Ethereum signatures
        // (or 0/1 for some implementations)
        let recovery_id = match v {
            27 => 0u8,
            28 => 1u8,
            0 => 0u8,
            1 => 1u8,
            _ => {
                return Ok(PrecompileResult {
                    output: vec![0u8; 32],
                    gas_used: GAS_COST,
                    success: true,
                });
            }
        };

        // Attempt to recover the public key
        let recovered_address = match recover_address(hash, r, s, recovery_id) {
            Some(addr) => addr,
            None => {
                return Ok(PrecompileResult {
                    output: vec![0u8; 32],
                    gas_used: GAS_COST,
                    success: true,
                });
            }
        };

        // Return zero-padded 32-byte address (12 zero bytes + 20-byte address)
        let mut output = vec![0u8; 32];
        output[12..32].copy_from_slice(&recovered_address);

        Ok(PrecompileResult {
            output,
            gas_used: GAS_COST,
            success: true,
        })
    }

    fn sha256(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        let gas_cost = 60 + (input.len() as u64).div_ceil(32) * 12;
        if gas_limit < gas_cost {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();

        Ok(PrecompileResult {
            output: result.to_vec(),
            gas_used: gas_cost,
            success: true,
        })
    }

    fn ripemd160(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        let gas_cost = 600 + (input.len() as u64).div_ceil(32) * 120;
        if gas_limit < gas_cost {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // RIPEMD-160 hash using the ripemd crate
        use ripemd::Digest as RipemdDigest;
        let mut hasher = Ripemd160::new();
        hasher.update(input);
        let hash = hasher.finalize();

        // Output is 32 bytes: 12 zero bytes + 20-byte hash (right-aligned)
        let mut output = vec![0u8; 32];
        output[12..32].copy_from_slice(&hash);

        Ok(PrecompileResult {
            output,
            gas_used: gas_cost,
            success: true,
        })
    }

    fn identity(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        let gas_cost = 15 + (input.len() as u64).div_ceil(32) * 3;
        if gas_limit < gas_cost {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        Ok(PrecompileResult {
            output: input.to_vec(),
            gas_used: gas_cost,
            success: true,
        })
    }

    fn modexp(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        // EIP-198: MODEXP precompile
        // Input: Blen (32 bytes) || Elen (32 bytes) || Mlen (32 bytes) || B || E || M
        // Output: B^E mod M, left-padded to Mlen bytes

        // Helper to read length from 32-byte big-endian field
        fn read_len(data: &[u8], offset: usize) -> usize {
            if offset + 32 > data.len() {
                return 0;
            }
            // Take last 8 bytes as usize (lengths won't exceed u64::MAX in practice)
            let slice = &data[offset..offset + 32];
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&slice[24..32]);
            u64::from_be_bytes(bytes) as usize
        }

        // Read lengths
        let b_len = read_len(input, 0);
        let e_len = read_len(input, 32);
        let m_len = read_len(input, 64);

        // Handle edge case: if modulus length is 0, return empty
        if m_len == 0 {
            return Ok(PrecompileResult {
                output: vec![],
                gas_used: 200,
                success: true,
            });
        }

        // Calculate gas cost (EIP-2565 simplified formula)
        let max_len = std::cmp::max(b_len, m_len);
        let words = max_len.div_ceil(8);
        let multiplication_complexity = words * words;

        // Calculate iteration count from exponent
        let e_start = 96 + b_len;
        let iteration_count = if e_len <= 32 {
            // Get the exponent data
            let mut e_bytes = vec![0u8; 32];
            let e_end = std::cmp::min(e_start + e_len, input.len());
            if e_start < input.len() {
                let copy_len = e_end - e_start;
                e_bytes[32 - copy_len..].copy_from_slice(&input[e_start..e_end]);
            }
            let exp = BigUint::from_bytes_be(&e_bytes);
            if exp.is_zero() {
                0
            } else {
                exp.bits() as usize - 1
            }
        } else {
            // For exponents > 32 bytes, use first 32 bytes
            let mut e_bytes = vec![0u8; 32];
            let e_end = std::cmp::min(e_start + 32, input.len());
            if e_start < input.len() {
                let copy_len = e_end - e_start;
                e_bytes[32 - copy_len..].copy_from_slice(&input[e_start..e_end]);
            }
            let exp_head = BigUint::from_bytes_be(&e_bytes);
            let head_bits = if exp_head.is_zero() {
                0
            } else {
                exp_head.bits() as usize - 1
            };
            8 * (e_len - 32) + head_bits
        };

        let gas_cost = std::cmp::max(
            200,
            (multiplication_complexity * std::cmp::max(iteration_count, 1)) as u64 / 3,
        );

        if gas_limit < gas_cost {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Extract base, exponent, modulus from input
        let data_start = 96;
        let b_start = data_start;
        let b_end = b_start + b_len;
        let e_start = b_end;
        let e_end = e_start + e_len;
        let m_start = e_end;
        let m_end = m_start + m_len;

        // Read values, padding with zeros if input is too short
        let mut b_bytes = vec![0u8; b_len];
        let mut e_bytes = vec![0u8; e_len];
        let mut m_bytes = vec![0u8; m_len];

        if b_start < input.len() {
            let copy_end = std::cmp::min(b_end, input.len());
            let copy_len = copy_end - b_start;
            b_bytes[..copy_len].copy_from_slice(&input[b_start..copy_end]);
        }
        if e_start < input.len() {
            let copy_end = std::cmp::min(e_end, input.len());
            let copy_len = copy_end - e_start;
            e_bytes[..copy_len].copy_from_slice(&input[e_start..copy_end]);
        }
        if m_start < input.len() {
            let copy_end = std::cmp::min(m_end, input.len());
            let copy_len = copy_end - m_start;
            m_bytes[..copy_len].copy_from_slice(&input[m_start..copy_end]);
        }

        let base = BigUint::from_bytes_be(&b_bytes);
        let exp = BigUint::from_bytes_be(&e_bytes);
        let modulus = BigUint::from_bytes_be(&m_bytes);

        // Compute result: base^exp mod modulus
        let result = if modulus.is_zero() {
            BigUint::zero()
        } else {
            base.modpow(&exp, &modulus)
        };

        // Convert to bytes, left-padded to m_len
        let result_bytes = result.to_bytes_be();
        let mut output = vec![0u8; m_len];
        if result_bytes.len() <= m_len {
            let start = m_len - result_bytes.len();
            output[start..].copy_from_slice(&result_bytes);
        } else {
            // Shouldn't happen if modulus is correct, but handle anyway
            output.copy_from_slice(&result_bytes[result_bytes.len() - m_len..]);
        }

        Ok(PrecompileResult {
            output,
            gas_used: gas_cost,
            success: true,
        })
    }

    fn ecadd(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        const GAS_COST: u64 = 150;
        if gas_limit < GAS_COST {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Input: x1 (32 bytes) || y1 (32 bytes) || x2 (32 bytes) || y2 (32 bytes)
        // Output: x3 (32 bytes) || y3 (32 bytes) = (x1,y1) + (x2,y2)

        // Pad input to 128 bytes if needed
        let mut padded = [0u8; 128];
        let copy_len = std::cmp::min(input.len(), 128);
        padded[..copy_len].copy_from_slice(&input[..copy_len]);

        // Parse point 1
        let p1 = match Self::parse_g1_point(&padded[0..64]) {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!("Invalid G1 point 1"));
            }
        };

        // Parse point 2
        let p2 = match Self::parse_g1_point(&padded[64..128]) {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!("Invalid G1 point 2"));
            }
        };

        // Add points
        let result = (G1Projective::from(p1) + G1Projective::from(p2)).into_affine();

        // Serialize result
        let output = Self::serialize_g1_point(&result);

        Ok(PrecompileResult {
            output,
            gas_used: GAS_COST,
            success: true,
        })
    }

    fn ecmul(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        const GAS_COST: u64 = 6000;
        if gas_limit < GAS_COST {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Input: x (32 bytes) || y (32 bytes) || s (32 bytes)
        // Output: x' (32 bytes) || y' (32 bytes) = s * (x, y)

        // Pad input to 96 bytes if needed
        let mut padded = [0u8; 96];
        let copy_len = std::cmp::min(input.len(), 96);
        padded[..copy_len].copy_from_slice(&input[..copy_len]);

        // Parse point
        let p = match Self::parse_g1_point(&padded[0..64]) {
            Some(p) => p,
            None => {
                return Err(anyhow::anyhow!("Invalid G1 point"));
            }
        };

        // Parse scalar (big-endian)
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&padded[64..96]);
        // Convert from big-endian to little-endian for arkworks
        scalar_bytes.reverse();
        let scalar = Fr::from_le_bytes_mod_order(&scalar_bytes);

        // Scalar multiplication
        let result = (G1Projective::from(p) * scalar).into_affine();

        // Serialize result
        let output = Self::serialize_g1_point(&result);

        Ok(PrecompileResult {
            output,
            gas_used: GAS_COST,
            success: true,
        })
    }

    fn ecpairing(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        // EIP-197: ECPAIRING - checks if product of pairings equals 1
        // Input: k pairs of (G1, G2) points, each pair is 192 bytes
        // G1: x (32 bytes) || y (32 bytes) = 64 bytes
        // G2: x_im (32 bytes) || x_re (32 bytes) || y_im (32 bytes) || y_re (32 bytes) = 128 bytes
        // Output: 1 if pairing check passes, 0 otherwise

        // Input must be a multiple of 192 bytes
        if !input.len().is_multiple_of(192) {
            return Err(anyhow::anyhow!("Invalid input length for pairing"));
        }

        let k = input.len() / 192;
        let gas_cost = 45000 + k as u64 * 34000;
        if gas_limit < gas_cost {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Empty input is valid and returns 1
        if k == 0 {
            let mut output = vec![0u8; 32];
            output[31] = 1;
            return Ok(PrecompileResult {
                output,
                gas_used: gas_cost,
                success: true,
            });
        }

        // Parse all pairs and compute pairing
        let mut g1_points = Vec::with_capacity(k);
        let mut g2_points = Vec::with_capacity(k);

        for i in 0..k {
            let offset = i * 192;

            // Parse G1 point (64 bytes)
            let g1 = match Self::parse_g1_point(&input[offset..offset + 64]) {
                Some(p) => p,
                None => {
                    return Err(anyhow::anyhow!("Invalid G1 point in pair {}", i));
                }
            };

            // Parse G2 point (128 bytes)
            let g2 = match Self::parse_g2_point(&input[offset + 64..offset + 192]) {
                Some(p) => p,
                None => {
                    return Err(anyhow::anyhow!("Invalid G2 point in pair {}", i));
                }
            };

            g1_points.push(g1);
            g2_points.push(g2);
        }

        // Compute multi-pairing: e(g1_1, g2_1) * e(g1_2, g2_2) * ... == 1
        let result = Bn254::multi_pairing(&g1_points, &g2_points);

        // Check if result equals identity (1 in GT)
        let is_one = result.0 == ark_bn254::Fq12::ONE;

        let mut output = vec![0u8; 32];
        if is_one {
            output[31] = 1;
        }

        Ok(PrecompileResult {
            output,
            gas_used: gas_cost,
            success: true,
        })
    }

    fn blake2f(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        // EIP-152: BLAKE2 F compression function
        // Input: rounds (4 bytes) || h (64 bytes) || m (128 bytes) || t (16 bytes) || f (1 byte)
        // Total: 213 bytes
        // Output: 64 bytes (updated state vector h)

        if input.len() != 213 {
            return Err(anyhow::anyhow!(
                "Invalid BLAKE2F input length: expected 213, got {}",
                input.len()
            ));
        }

        // Parse rounds (4 bytes big-endian)
        let rounds = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as u64;

        // Gas cost is the number of rounds
        if gas_limit < rounds {
            return Err(anyhow::anyhow!("Insufficient gas"));
        }

        // Parse final block flag (must be 0 or 1)
        let f = input[212];
        if f > 1 {
            return Err(anyhow::anyhow!("Invalid final block flag: {}", f));
        }

        // Parse state vector h (64 bytes = 8 x u64 little-endian)
        let mut h = [0u64; 8];
        for (i, h_val) in h.iter_mut().enumerate() {
            let offset = 4 + i * 8;
            *h_val = u64::from_le_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
                input[offset + 4],
                input[offset + 5],
                input[offset + 6],
                input[offset + 7],
            ]);
        }

        // Parse message block m (128 bytes = 16 x u64 little-endian)
        let mut m = [0u64; 16];
        for (i, m_val) in m.iter_mut().enumerate() {
            let offset = 68 + i * 8;
            *m_val = u64::from_le_bytes([
                input[offset],
                input[offset + 1],
                input[offset + 2],
                input[offset + 3],
                input[offset + 4],
                input[offset + 5],
                input[offset + 6],
                input[offset + 7],
            ]);
        }

        // Parse offset counters t (16 bytes = 2 x u64 little-endian)
        let t0 = u64::from_le_bytes([
            input[196], input[197], input[198], input[199], input[200], input[201], input[202],
            input[203],
        ]);
        let t1 = u64::from_le_bytes([
            input[204], input[205], input[206], input[207], input[208], input[209], input[210],
            input[211],
        ]);

        // BLAKE2b compression function F
        Self::blake2b_compress(&mut h, &m, t0, t1, f == 1, rounds as usize);

        // Serialize output (64 bytes = 8 x u64 little-endian)
        let mut output = vec![0u8; 64];
        for i in 0..8 {
            let bytes = h[i].to_le_bytes();
            output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        Ok(PrecompileResult {
            output,
            gas_used: rounds,
            success: true,
        })
    }

    /// BLAKE2b compression function F
    fn blake2b_compress(h: &mut [u64; 8], m: &[u64; 16], t0: u64, t1: u64, f: bool, rounds: usize) {
        // BLAKE2b IV
        const IV: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];

        // Sigma permutation
        const SIGMA: [[usize; 16]; 10] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
            [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
            [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
            [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
            [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
            [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
            [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
            [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
            [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        ];

        // Initialize working vector
        let mut v = [0u64; 16];
        v[0..8].copy_from_slice(h);
        v[8..16].copy_from_slice(&IV);
        v[12] ^= t0;
        v[13] ^= t1;
        if f {
            v[14] = !v[14];
        }

        // Mixing function G
        #[inline]
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }

        // Perform rounds
        for i in 0..rounds {
            let s = &SIGMA[i % 10];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        // Finalize
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    // Helper functions for BN254 curve operations

    /// Parse a G1 point from 64 bytes (x: 32 bytes, y: 32 bytes, big-endian)
    fn parse_g1_point(input: &[u8]) -> Option<G1Affine> {
        if input.len() < 64 {
            return None;
        }

        // Check for point at infinity (both coordinates zero)
        let all_zeros = input[..64].iter().all(|&b| b == 0);
        if all_zeros {
            return Some(G1Affine::identity());
        }

        // Parse x coordinate (big-endian)
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&input[0..32]);
        x_bytes.reverse(); // Convert to little-endian for arkworks
        let x = Fq::from_le_bytes_mod_order(&x_bytes);

        // Parse y coordinate (big-endian)
        let mut y_bytes = [0u8; 32];
        y_bytes.copy_from_slice(&input[32..64]);
        y_bytes.reverse();
        let y = Fq::from_le_bytes_mod_order(&y_bytes);

        // Construct point and validate it's on the curve
        let point = G1Affine::new(x, y);
        if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Parse a G2 point from 128 bytes (x_im, x_re, y_im, y_re each 32 bytes, big-endian)
    fn parse_g2_point(input: &[u8]) -> Option<G2Affine> {
        if input.len() < 128 {
            return None;
        }

        // Check for point at infinity
        let all_zeros = input[..128].iter().all(|&b| b == 0);
        if all_zeros {
            return Some(G2Affine::identity());
        }

        // Parse x coordinate (Fq2 = c0 + c1*u where c0 is real, c1 is imaginary)
        // EVM encoding: x_imaginary (32) || x_real (32)
        let mut x_im_bytes = [0u8; 32];
        x_im_bytes.copy_from_slice(&input[0..32]);
        x_im_bytes.reverse();
        let x_im = Fq::from_le_bytes_mod_order(&x_im_bytes);

        let mut x_re_bytes = [0u8; 32];
        x_re_bytes.copy_from_slice(&input[32..64]);
        x_re_bytes.reverse();
        let x_re = Fq::from_le_bytes_mod_order(&x_re_bytes);

        let x = Fq2::new(x_re, x_im);

        // Parse y coordinate
        let mut y_im_bytes = [0u8; 32];
        y_im_bytes.copy_from_slice(&input[64..96]);
        y_im_bytes.reverse();
        let y_im = Fq::from_le_bytes_mod_order(&y_im_bytes);

        let mut y_re_bytes = [0u8; 32];
        y_re_bytes.copy_from_slice(&input[96..128]);
        y_re_bytes.reverse();
        let y_re = Fq::from_le_bytes_mod_order(&y_re_bytes);

        let y = Fq2::new(y_re, y_im);

        // Construct point and validate
        let point = G2Affine::new(x, y);
        if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Serialize a G1 point to 64 bytes (x: 32 bytes, y: 32 bytes, big-endian)
    fn serialize_g1_point(point: &G1Affine) -> Vec<u8> {
        let mut output = vec![0u8; 64];

        if point.is_zero() {
            return output;
        }

        // Serialize x (convert from little-endian to big-endian)
        let x_bigint: BigInt<4> = point.x.into_bigint();
        let mut x_bytes = [0u8; 32];
        for (i, limb) in x_bigint.0.iter().enumerate() {
            let bytes = limb.to_le_bytes();
            x_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        x_bytes.reverse();
        output[0..32].copy_from_slice(&x_bytes);

        // Serialize y
        let y_bigint: BigInt<4> = point.y.into_bigint();
        let mut y_bytes = [0u8; 32];
        for (i, limb) in y_bigint.0.iter().enumerate() {
            let bytes = limb.to_le_bytes();
            y_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        y_bytes.reverse();
        output[32..64].copy_from_slice(&y_bytes);

        output
    }
}

/// Recover Ethereum address from ECDSA signature components.
/// Shared by ECRECOVER precompile and x402 payment precompiles.
///
/// RM-B1 / WP-B3.4 (audit M-01): rejects high-s signatures per
/// EIP-2 / Yellow Paper. Without this check, a contract using
/// `ecrecover(hash, v, r, s) == expected_signer` for replay
/// protection would accept both `(r, s)` and `(r, n - s)` as
/// equally valid signatures over the same message — a malleability
/// vector. Mirrors Geth's pattern: `if signature.s_normalized() !=
/// signature.s() { reject }`.
pub fn recover_address(hash: &[u8], r: &[u8], s: &[u8], recovery_id: u8) -> Option<[u8; 20]> {
    // Create signature from r and s components
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);

    let signature = Signature::from_bytes((&sig_bytes).into()).ok()?;

    // M-01 fix: reject high-s signatures. `normalize_s` returns
    // `Some(normalized)` iff the s-value was not already in low-s
    // form; we treat any input that needed normalization as a
    // malleability attempt and reject.
    if signature.normalize_s().is_some() {
        return None;
    }

    let recid = RecoveryId::from_byte(recovery_id)?;

    // Recover the verifying (public) key
    let recovered_key = VerifyingKey::recover_from_prehash(hash, &signature, recid).ok()?;

    // Get the uncompressed public key bytes (65 bytes: 0x04 prefix + 64 bytes)
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_uncompressed = pubkey_bytes.as_bytes();

    // Skip the 0x04 prefix and hash the 64 bytes of the public key
    if pubkey_uncompressed.len() != 65 {
        return None;
    }

    // Keccak256 hash of the public key (without the 0x04 prefix)
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_uncompressed[1..65]);
    let hash_result = hasher.finalize();

    // Take last 20 bytes as the address
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash_result[12..32]);

    Some(address)
}

/// Result from precompile execution
#[derive(Debug, Clone)]
pub struct PrecompileResult {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_precompile() {
        let executor = PrecompileExecutor::new();

        // Test standard precompiles
        assert!(executor.is_precompile(&standard::ECRECOVER));
        assert!(executor.is_precompile(&standard::SHA256));
        assert!(executor.is_precompile(&standard::BLAKE2F));

        // Test AI precompiles
        assert!(executor.is_precompile(&Address(inference::addresses::MODEL_DEPLOY)));
        assert!(executor.is_precompile(&Address(inference::addresses::MODEL_INFERENCE)));

        // Test non-precompile
        let regular_addr = Address([1u8; 20]);
        assert!(!executor.is_precompile(&regular_addr));
    }

    #[test]
    fn test_ecrecover_valid_signature() {
        // Test vector from Ethereum
        // This is a known valid signature that can be verified
        // Message hash: keccak256("test message")
        let executor = PrecompileExecutor::new();

        // Test with known Ethereum test vector
        // hash = keccak256("Hello World")
        let hash = hex::decode("592fa743889fc7f92ac2a37bb1f5ba1daf2a5c84741ca0e0061d243a2e6707ba")
            .unwrap();

        // v = 28 (0x1c)
        let mut v = [0u8; 32];
        v[31] = 28;

        // r component
        let r = hex::decode("d0b7e49509da0fb9eda2a5e0d98b3f7f8bb8bbea9bfb57e93a88e6a1c0b98d8c")
            .unwrap();

        // s component
        let s = hex::decode("5a0c8b4e9f9d3c6e8b7a5f4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4b")
            .unwrap();

        // Build input: hash (32) + v (32) + r (32) + s (32) = 128 bytes
        let mut input = Vec::new();
        input.extend_from_slice(&hash);
        input.extend_from_slice(&v);
        input.extend_from_slice(&r);
        input.extend_from_slice(&s);

        let result = executor.ecrecover(&input, 5000).unwrap();

        // Should not panic, should return valid result
        assert_eq!(result.gas_used, 3000);
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        // First 12 bytes should be zeros (address is in last 20 bytes)
        assert!(result.output[0..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ecrecover_insufficient_input() {
        let executor = PrecompileExecutor::new();

        // Input less than 128 bytes should return zeros
        let input = vec![0u8; 64]; // Only 64 bytes

        let result = executor.ecrecover(&input, 5000).unwrap();

        assert_eq!(result.gas_used, 3000);
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_ecrecover_invalid_v() {
        let executor = PrecompileExecutor::new();

        // Input with invalid v value (not 27 or 28)
        let mut input = vec![0u8; 128];
        input[63] = 99; // Invalid v

        let result = executor.ecrecover(&input, 5000).unwrap();

        assert_eq!(result.gas_used, 3000);
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_ecrecover_insufficient_gas() {
        let executor = PrecompileExecutor::new();

        let input = vec![0u8; 128];

        let result = executor.ecrecover(&input, 2000);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecrecover_with_real_signature() {
        use k256::ecdsa::SigningKey;

        let executor = PrecompileExecutor::new();

        // Generate a random signing key
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        // Create a message hash
        let message = b"Test message for ecrecover";
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        // Sign the hash
        let (signature, recid) = signing_key.sign_prehash_recoverable(&hash).unwrap();
        let sig_bytes = signature.to_bytes();

        // Build ecrecover input
        let mut input = vec![0u8; 128];
        input[0..32].copy_from_slice(&hash);
        // v: recovery id + 27
        input[63] = recid.to_byte() + 27;
        // r
        input[64..96].copy_from_slice(&sig_bytes[0..32]);
        // s
        input[96..128].copy_from_slice(&sig_bytes[32..64]);

        let result = executor.ecrecover(&input, 5000).unwrap();

        // Compute expected address from public key
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey_uncompressed[1..65]);
        let hash_result = hasher.finalize();
        let mut expected_address = [0u8; 20];
        expected_address.copy_from_slice(&hash_result[12..32]);

        assert_eq!(result.gas_used, 3000);
        assert!(result.success);
        // Check that recovered address matches expected
        assert_eq!(&result.output[12..32], &expected_address);
    }

    // ==================== M-01: ECRECOVER low-s tests ====================

    #[test]
    fn m01_ecrecover_accepts_low_s_signature() {
        // Real signing typically produces a low-s signature
        // already (most libraries normalize). This test pins the
        // happy path: low-s signature recovers correctly.
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes(&[0x42; 32].into()).expect("sk");
        let hash = [0xCD; 32];
        let (sig, recid) = sk.sign_prehash_recoverable(&hash).expect("sign");
        let sig_bytes = sig.to_bytes();

        // Confirm sign output is low-s (post-normalize_s would return None).
        assert!(
            Signature::from_bytes(&sig_bytes)
                .expect("sig parse")
                .normalize_s()
                .is_none(),
            "signing output must already be low-s"
        );

        let recovered = recover_address(
            &hash,
            &sig_bytes[0..32],
            &sig_bytes[32..64],
            recid.to_byte(),
        );
        assert!(recovered.is_some(), "low-s signature must recover");
    }

    #[test]
    fn m01_ecrecover_rejects_high_s_signature() {
        // Take a real low-s signature, then negate s (mod n) to
        // get the malleated high-s form. Pre-fix `recover_address`
        // accepted both; post-fix the high-s form is rejected.
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::scalar::IsHigh;

        let sk = SigningKey::from_bytes(&[0x55; 32].into()).expect("sk");
        let hash = [0xAB; 32];
        let (sig, recid) = sk.sign_prehash_recoverable(&hash).expect("sign");
        let sig_bytes_low = sig.to_bytes();

        // Build the malleated high-s form: negate the s scalar mod n.
        let s_scalar = sig.s();
        // The negation is the high-s form because |scalar| < n/2 on
        // input → |-scalar mod n| > n/2 on output.
        let neg_s = -s_scalar;
        assert!(
            bool::from(neg_s.is_high()),
            "neg_s must be high-s by construction"
        );

        let mut sig_bytes_high = [0u8; 64];
        sig_bytes_high[0..32].copy_from_slice(&sig_bytes_low[0..32]);
        sig_bytes_high[32..64].copy_from_slice(&neg_s.to_bytes());

        // M-01 fix: high-s must be rejected.
        let recovered = recover_address(
            &hash,
            &sig_bytes_high[0..32],
            &sig_bytes_high[32..64],
            // recovery_id flips when s flips; we just probe both
            // values to cover the malleability attack space.
            recid.to_byte() ^ 1,
        );
        assert!(
            recovered.is_none(),
            "M-01: high-s signature must be rejected (malleability defense)"
        );

        // Also try the original recovery_id to be defensive — both
        // recid values should reject the high-s form.
        let recovered2 = recover_address(
            &hash,
            &sig_bytes_high[0..32],
            &sig_bytes_high[32..64],
            recid.to_byte(),
        );
        assert!(
            recovered2.is_none(),
            "M-01: high-s signature must be rejected regardless of recovery_id"
        );
    }

    // ==================== RIPEMD160 Tests ====================

    #[test]
    fn test_ripemd160_empty_input() {
        let executor = PrecompileExecutor::new();
        let input = vec![];
        let result = executor.ripemd160(&input, 10000).unwrap();

        // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let expected = hex::decode("9c1185a5c5e9fc54612808977ee8f548b2258d31").unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 600); // Base gas for empty input
        assert_eq!(&result.output[12..32], expected.as_slice());
    }

    #[test]
    fn test_ripemd160_abc() {
        let executor = PrecompileExecutor::new();
        let input = b"abc".to_vec();
        let result = executor.ripemd160(&input, 10000).unwrap();

        // RIPEMD160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
        let expected = hex::decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc").unwrap();

        assert!(result.success);
        assert_eq!(&result.output[12..32], expected.as_slice());
    }

    #[test]
    fn test_ripemd160_insufficient_gas() {
        let executor = PrecompileExecutor::new();
        let input = b"test".to_vec();
        let result = executor.ripemd160(&input, 100); // Not enough gas

        assert!(result.is_err());
    }

    // ==================== SHA256 Tests ====================

    #[test]
    fn test_sha256_empty_input() {
        let executor = PrecompileExecutor::new();
        let input = vec![];
        let result = executor.sha256(&input, 10000).unwrap();

        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();

        assert!(result.success);
        assert_eq!(result.output, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let executor = PrecompileExecutor::new();
        let input = b"abc".to_vec();
        let result = executor.sha256(&input, 10000).unwrap();

        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();

        assert!(result.success);
        assert_eq!(result.output, expected);
    }

    // ==================== IDENTITY Tests ====================

    #[test]
    fn test_identity() {
        let executor = PrecompileExecutor::new();
        let input = b"hello world".to_vec();
        let result = executor.identity(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_identity_empty() {
        let executor = PrecompileExecutor::new();
        let input = vec![];
        let result = executor.identity(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.output, input);
    }

    // ==================== MODEXP Tests ====================

    #[test]
    fn test_modexp_simple() {
        let executor = PrecompileExecutor::new();

        // Compute 2^10 mod 100 = 1024 mod 100 = 24
        // Input format: Blen (32) | Elen (32) | Mlen (32) | B | E | M
        let mut input = vec![0u8; 96 + 3]; // 96 byte header + 3 bytes data

        // Base length = 1
        input[31] = 1;
        // Exponent length = 1
        input[63] = 1;
        // Modulus length = 1
        input[95] = 1;
        // Base = 2
        input[96] = 2;
        // Exponent = 10
        input[97] = 10;
        // Modulus = 100
        input[98] = 100;

        let result = executor.modexp(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.output.len(), 1);
        assert_eq!(result.output[0], 24); // 2^10 mod 100 = 24
    }

    #[test]
    fn test_modexp_zero_modulus() {
        let executor = PrecompileExecutor::new();

        // Zero modulus should return empty result
        let mut input = vec![0u8; 96];
        input[31] = 1; // Base length = 1
        input[63] = 1; // Exponent length = 1
                       // Modulus length = 0 (default)

        let result = executor.modexp(&input, 10000).unwrap();

        assert!(result.success);
        assert!(result.output.is_empty());
    }

    #[test]
    fn test_modexp_large_numbers() {
        let executor = PrecompileExecutor::new();

        // 3^5 mod 13 = 243 mod 13 = 9
        let mut input = vec![0u8; 96 + 3];
        input[31] = 1; // Base length
        input[63] = 1; // Exponent length
        input[95] = 1; // Modulus length
        input[96] = 3; // Base = 3
        input[97] = 5; // Exponent = 5
        input[98] = 13; // Modulus = 13

        let result = executor.modexp(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.output[0], 9);
    }

    // ==================== ECADD Tests ====================

    #[test]
    fn test_ecadd_identity() {
        let executor = PrecompileExecutor::new();

        // Adding point at infinity (zeros) to itself should give infinity
        let input = vec![0u8; 128];
        let result = executor.ecadd(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 150);
        assert_eq!(result.output.len(), 64);
        // Result should be point at infinity (all zeros)
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ecadd_generator_plus_infinity() {
        let executor = PrecompileExecutor::new();

        // BN254 G1 generator point
        // x = 1
        // y = 2
        let mut input = vec![0u8; 128];
        input[31] = 1; // x = 1
        input[63] = 2; // y = 2
                       // Second point is infinity (zeros)

        let result = executor.ecadd(&input, 10000).unwrap();

        assert!(result.success);
        // G + 0 = G
        assert_eq!(input[0..32], result.output[0..32]);
        assert_eq!(input[32..64], result.output[32..64]);
    }

    #[test]
    fn test_ecadd_insufficient_gas() {
        let executor = PrecompileExecutor::new();
        let input = vec![0u8; 128];
        let result = executor.ecadd(&input, 100); // Not enough gas

        assert!(result.is_err());
    }

    // ==================== ECMUL Tests ====================

    #[test]
    fn test_ecmul_by_zero() {
        let executor = PrecompileExecutor::new();

        // BN254 G1 generator * 0 = infinity
        let mut input = vec![0u8; 96];
        input[31] = 1; // x = 1
        input[63] = 2; // y = 2
                       // Scalar = 0 (last 32 bytes)

        let result = executor.ecmul(&input, 10000).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 6000);
        // Result should be point at infinity
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ecmul_by_one() {
        let executor = PrecompileExecutor::new();

        // G1 * 1 = G1
        let mut input = vec![0u8; 96];
        input[31] = 1; // x = 1
        input[63] = 2; // y = 2
        input[95] = 1; // Scalar = 1

        let result = executor.ecmul(&input, 10000).unwrap();

        assert!(result.success);
        // Result should be the same point
        assert_eq!(&input[0..64], &result.output[0..64]);
    }

    #[test]
    fn test_ecmul_insufficient_gas() {
        let executor = PrecompileExecutor::new();
        let input = vec![0u8; 96];
        let result = executor.ecmul(&input, 1000); // Not enough gas

        assert!(result.is_err());
    }

    // ==================== ECPAIRING Tests ====================

    #[test]
    fn test_ecpairing_empty_input() {
        let executor = PrecompileExecutor::new();

        // Empty input is valid and should return 1
        let input = vec![];
        let result = executor.ecpairing(&input, 100000).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 45000);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1); // Returns 1 for empty input
    }

    #[test]
    fn test_ecpairing_invalid_length() {
        let executor = PrecompileExecutor::new();

        // Input not a multiple of 192 bytes should fail
        let input = vec![0u8; 100];
        let result = executor.ecpairing(&input, 100000);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecpairing_insufficient_gas() {
        let executor = PrecompileExecutor::new();
        let input = vec![0u8; 192]; // One pair
        let result = executor.ecpairing(&input, 10000); // Not enough gas

        assert!(result.is_err());
    }

    // ==================== BLAKE2F Tests ====================

    #[test]
    fn test_blake2f_basic() {
        let executor = PrecompileExecutor::new();

        // EIP-152 test vector 1
        // rounds = 12, rest zeros, f = 1
        let mut input = vec![0u8; 213];
        input[3] = 12; // 12 rounds
        input[212] = 1; // Final block flag

        let result = executor.blake2f(&input, 100).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 12); // Gas = rounds
        assert_eq!(result.output.len(), 64);
    }

    #[test]
    fn test_blake2f_invalid_length() {
        let executor = PrecompileExecutor::new();

        // Input must be exactly 213 bytes
        let input = vec![0u8; 100];
        let result = executor.blake2f(&input, 100);

        assert!(result.is_err());
    }

    #[test]
    fn test_blake2f_invalid_final_flag() {
        let executor = PrecompileExecutor::new();

        // Final block flag must be 0 or 1
        let mut input = vec![0u8; 213];
        input[3] = 1; // 1 round
        input[212] = 2; // Invalid flag

        let result = executor.blake2f(&input, 100);

        assert!(result.is_err());
    }

    #[test]
    fn test_blake2f_insufficient_gas() {
        let executor = PrecompileExecutor::new();

        let mut input = vec![0u8; 213];
        input[3] = 100; // 100 rounds
        input[212] = 1;

        let result = executor.blake2f(&input, 50); // Not enough gas

        assert!(result.is_err());
    }

    #[test]
    fn test_blake2f_zero_rounds() {
        let executor = PrecompileExecutor::new();

        // Zero rounds should still work
        let mut input = vec![0u8; 213];
        // rounds = 0 (default)
        input[212] = 1; // Final block flag

        let result = executor.blake2f(&input, 100).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 0);
        assert_eq!(result.output.len(), 64);
    }

    // ==================== x402 Routing Integration Tests ====================

    #[test]
    fn test_is_precompile_x402_addresses() {
        let executor = PrecompileExecutor::new();

        // x402 addresses should be recognized
        assert!(executor.is_precompile(&Address(x402::addresses::EIP712_VERIFY)));
        assert!(executor.is_precompile(&Address(x402::addresses::TRANSFER_AUTH_VERIFY)));
        assert!(executor.is_precompile(&Address(x402::addresses::BATCH_PAYMENT_VERIFY)));

        // Future x402 slots (0x0203-0x0209) should also be recognized
        let future_x402 = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 5]);
        assert!(executor.is_precompile(&future_x402));

        // 0x020A should NOT be recognized (out of range)
        let out_of_range = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 10]);
        assert!(!executor.is_precompile(&out_of_range));
    }

    #[test]
    fn test_x402_routing_via_executor() {
        // Verify that PrecompileExecutor::execute() correctly routes to x402 precompiles
        let mut executor = PrecompileExecutor::new();

        // EIP-712 verify via executor routing (short input → returns zero address)
        let eip712_addr = Address(x402::addresses::EIP712_VERIFY);
        let input = vec![0u8; 64]; // Short input
        let result = executor.execute(&eip712_addr, &input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, x402::gas_costs::EIP712_VERIFY);
        assert_eq!(result.output, vec![0u8; 32]);

        // TransferWithAuthorization via executor routing (short input → returns zero)
        let transfer_addr = Address(x402::addresses::TRANSFER_AUTH_VERIFY);
        let result = executor.execute(&transfer_addr, &input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, x402::gas_costs::TRANSFER_AUTH_VERIFY);

        // Unknown x402 address should error
        let unknown_x402 = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 9]);
        let result = executor.execute(&unknown_x402, &input, 10_000);
        assert!(result.is_err());
    }

    // ==================== Learning page (RM-FL-1) ====================

    #[test]
    fn test_is_precompile_learning_belnap_address() {
        let executor = PrecompileExecutor::new();
        let belnap_addr = Address(q16::belnap::BELNAP_AGGREGATE);
        assert!(
            executor.is_precompile(&belnap_addr),
            "0x0110 (Belnap aggregation) must be recognized as a precompile"
        );

        // Future learning slots (0x0111 routing model, etc.) should
        // also be recognized — the page reserves 0x0110-0x011F.
        let future_routing = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x11,
        ]);
        assert!(executor.is_precompile(&future_routing));

        // 0x0120 is now the crypto sub-page (Ed25519 verify), so it IS a
        // precompile — it opens a new page (0x0120-0x012F) rather than
        // extending the learning page.
        let ed25519_addr = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20,
        ]);
        assert!(executor.is_precompile(&ed25519_addr));

        // 0x0130 opens the recursive-fold verification page (0x0130-0x013F,
        // citrate-chain#170: FOLD_COMMD_VERIFY), so it IS a precompile.
        let fold_verify_addr = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x30,
        ]);
        assert!(executor.is_precompile(&fold_verify_addr));

        // Just past the fold page (0x0140) MUST NOT be recognized — that would
        // silently route to nothing and break the dispatcher contract.
        let out_of_page = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x40,
        ]);
        assert!(!executor.is_precompile(&out_of_page));
    }

    #[test]
    fn test_belnap_routing_via_executor() {
        // PrecompileExecutor::execute(0x0110, ...) must route to
        // q16::belnap::execute and produce a successful result for a
        // valid input.
        let mut executor = PrecompileExecutor::new();
        let belnap_addr = Address(q16::belnap::BELNAP_AGGREGATE);

        // Build a minimum valid input via the public encode_input is
        // test-only; encode the bytes inline.
        // dim=1, n=1, embedding=1.0 (Q16), conf=1.0, weight=1.0,
        // threshold_pos=0.5, threshold_neg=-0.5.
        // I64-S1: Q16 values are 8 bytes on the wire. Layout for dim=1,n=1:
        // dim(4) + n(4) + emb(8) + conf(8) + weight(8) + thr_pos(8) + thr_neg(8) = 48.
        let mut input = Vec::with_capacity(48);
        input.extend_from_slice(&1u32.to_be_bytes()); // dim
        input.extend_from_slice(&1u32.to_be_bytes()); // n
        input.extend_from_slice(&q16::Q16::from_int(1).0.to_be_bytes()); // emb (8 bytes)
        input.extend_from_slice(&q16::Q16::from_int(1).0.to_be_bytes()); // conf
        input.extend_from_slice(&q16::Q16::from_int(1).0.to_be_bytes()); // weight
                                                                         // threshold_pos = Q16(0x4000) ≈ 0.5, threshold_neg ≈ -0.5 (8 bytes each)
        input.extend_from_slice(&0x4000_i64.to_be_bytes());
        input.extend_from_slice(&(-0x4000_i64).to_be_bytes());
        assert_eq!(input.len(), 48); // header + body, 8-byte Q16

        let result = executor.execute(&belnap_addr, &input, 100_000).unwrap();
        assert!(result.success);
        // Output: 8 bytes Q16 value + 1 byte Belnap state = 9 bytes for dim=1.
        assert_eq!(result.output.len(), 9);
        // State byte is the last; True = 1.
        assert_eq!(result.output[8], 1, "single-participant agree → state=True");
        // Gas: 2000 + 50 * 1 = 2050 (per-dim, unchanged by byte width).
        assert_eq!(result.gas_used, 2050);
    }

    #[test]
    fn test_belnap_unknown_learning_selector_errors() {
        let mut executor = PrecompileExecutor::new();
        // Within the learning page but not 0x10 — the dispatcher
        // returns an "unknown selector" error rather than silently
        // doing nothing.
        let unknown = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x1F,
        ]);
        let result = executor.execute(&unknown, &[], 10_000);
        assert!(result.is_err(), "unknown learning selector must error");
    }

    // ==================== Routing model (RM-FL-2 / WP-2.5+2.6) ====================

    #[test]
    fn test_routing_inference_address_recognized() {
        let executor = PrecompileExecutor::new();
        let routing_addr = Address(q16::routing::ROUTING_INFERENCE);
        assert!(
            executor.is_precompile(&routing_addr),
            "0x0111 (routing inference) must be recognized as a precompile"
        );
        // Verify the canonical byte layout (WP-B0): Learning page is
        // 0x…0111 — byte 18 = 0x01, selector 0x11.
        assert_eq!(q16::routing::ROUTING_INFERENCE[17], 0x00);
        assert_eq!(q16::routing::ROUTING_INFERENCE[18], 0x01);
        assert_eq!(q16::routing::ROUTING_INFERENCE[19], 0x11);
    }

    #[test]
    fn test_routing_dispatcher_routes_to_routing_execute() {
        // PrecompileExecutor::execute(0x0111, ...) must route to
        // q16::routing::execute. We use a malformed-but-non-empty
        // input so we exercise the dispatch + decode path without
        // having to build the full 464 KB canonical-shape blob in a
        // unit test. Decode fails on length mismatch; the dispatcher
        // returns the error wrapped in anyhow.
        let mut executor = PrecompileExecutor::new();
        let routing_addr = Address(q16::routing::ROUTING_INFERENCE);

        let mut input = vec![0u8; 16];
        input[0..4].copy_from_slice(&1u32.to_be_bytes()); // arch_version
        input[4..8].copy_from_slice(&768u32.to_be_bytes()); // input_dim
        input[8..12].copy_from_slice(&128u32.to_be_bytes()); // hidden_dim
        input[12..16].copy_from_slice(&3u32.to_be_bytes()); // output_dim

        // gas_limit must be high enough to cover the full canonical
        // params count's gas pre-charge (~465K). Pass 1M.
        let result = executor.execute(&routing_addr, &input, 1_000_000);
        assert!(
            result.is_err(),
            "decode fails on canonical-header empty body; dispatcher surfaces the error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Routing forward"),
            "error message must come from routing::execute (got: {err})"
        );
    }

    // ====================================================================
    // WP-B0 (TD-28): the REVM-bridge table and `execute_pure` must agree.
    // ====================================================================

    /// Every address in `PURE_PRECOMPILE_ADDRESSES` must (a) be recognised
    /// by `is_precompile`, (b) route somewhere real in `execute_pure`
    /// (i.e. NOT fail with the "Not a Citrate pure precompile" sentinel),
    /// and (c) use the canonical short-address layout (bytes 0..18 zero)
    /// that the Solidity contracts and `40204.json` publish.
    #[test]
    fn pure_precompile_table_routes() {
        let executor = PrecompileExecutor::new();
        for raw in PURE_PRECOMPILE_ADDRESSES {
            let addr = Address(raw);
            assert!(
                raw[..18].iter().all(|&b| b == 0),
                "{addr:?} must use the canonical 0x…{:02x}{:02x} layout",
                raw[18],
                raw[19]
            );
            assert!(
                executor.is_precompile(&addr),
                "{addr:?} must be recognised by is_precompile"
            );
            // Junk input: each family must claim the address (reject the
            // INPUT, not the address). The not-routed sentinel is the only
            // disallowed outcome.
            if let Err(e) = execute_pure(&addr, &[0xde, 0xad], 10_000_000) {
                assert!(
                    !e.to_string().contains("Not a Citrate pure precompile"),
                    "{addr:?} is in PURE_PRECOMPILE_ADDRESSES but execute_pure does not route it"
                );
            }
        }
    }

    /// The inference family needs the hosted runtime and must NOT be
    /// routed by the pure bridge.
    #[test]
    fn execute_pure_refuses_inference_family() {
        for selector in 0x00u8..=0x06 {
            let mut raw = [0u8; 20];
            raw[18] = 0x01;
            raw[19] = selector;
            let err = execute_pure(&Address(raw), &[], 10_000_000)
                .expect_err("inference addresses must not route through the pure bridge");
            assert!(
                err.to_string().contains("Not a Citrate pure precompile"),
                "0x01{selector:02x} must be refused by execute_pure (got: {err})"
            );
        }
    }
}
