// citrate/core/execution/src/precompiles/x402.rs
//
// x402 Payment Protocol Precompiles for EVM
// Addresses 0x0200 - 0x0202 reserved for x402 operations
//
// Implements Coinbase x402 payment verification at the precompile level (Level 2).
// These precompiles accelerate EIP-712 signature verification and EIP-3009
// transferWithAuthorization validation, reducing gas costs ~9x vs Solidity.
//
// Level 3 upgrade path (future):
//   - Validator-embedded facilitator (settlement as part of block production)
//   - Implicit x402 payments in block headers (no explicit transactions)
//   - Cross-shard x402 settlement for sharding architecture
//   See ADR-005 for full upgrade roadmap.

use anyhow::{anyhow, Result};
use sha3::{Digest, Keccak256};

use crate::types::Address;
use super::PrecompileResult;

/// Precompile addresses for x402 payment operations
pub mod addresses {
    /// 0x0200: EIP-712 Typed Data Signature Verification
    /// Recovers signer from an EIP-712 typed data signature.
    pub const EIP712_VERIFY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0];

    /// 0x0201: EIP-3009 TransferWithAuthorization Verification
    /// Verifies a transferWithAuthorization signature and checks signer == from.
    pub const TRANSFER_AUTH_VERIFY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

    /// 0x0202: Batch Payment Verification
    /// Verifies multiple transferWithAuthorization signatures in a single call.
    pub const BATCH_PAYMENT_VERIFY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2];
}

/// Gas costs for x402 operations
pub mod gas_costs {
    /// EIP-712 verify: ecrecover (3000) + 2 keccak256 (150 each) + overhead (150)
    pub const EIP712_VERIFY: u64 = 3_450;

    /// TransferWithAuthorization verify: struct hash + domain hash + ecrecover
    pub const TRANSFER_AUTH_VERIFY: u64 = 4_200;

    /// Batch payment base cost (overhead for count parsing + output assembly)
    pub const BATCH_BASE: u64 = 2_000;

    /// Per-payment cost within a batch (slightly discounted from individual)
    pub const BATCH_PER_PAYMENT: u64 = 3_800;
}

/// EIP-3009 TransferWithAuthorization type hash (constant, computed once)
/// keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
fn transfer_with_authorization_typehash() -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Route execution to the appropriate x402 precompile by address.
pub fn execute(address: &Address, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let addr = address.as_fixed_bytes();
    if addr == &addresses::EIP712_VERIFY {
        eip712_verify(input, gas_limit)
    } else if addr == &addresses::TRANSFER_AUTH_VERIFY {
        transfer_auth_verify(input, gas_limit)
    } else if addr == &addresses::BATCH_PAYMENT_VERIFY {
        batch_payment_verify(input, gas_limit)
    } else {
        Err(anyhow!("Unknown x402 precompile address"))
    }
}

/// Precompile 0x0200: EIP-712 Typed Data Signature Verification
///
/// Input format (129 bytes):
///   domain_separator (32 bytes) | struct_hash (32 bytes) | v (1 byte) | r (32 bytes) | s (32 bytes)
///
/// Output (32 bytes):
///   Zero-padded recovered address (12 zero bytes + 20-byte address), or all zeros on failure.
///
/// Gas: 3,450
fn eip712_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < gas_costs::EIP712_VERIFY {
        return Err(anyhow!("Insufficient gas for EIP-712 verify"));
    }

    if input.len() < 129 {
        // Return zero address on invalid input (mirrors ECRECOVER behavior)
        return Ok(PrecompileResult {
            output: vec![0u8; 32],
            gas_used: gas_costs::EIP712_VERIFY,
            success: true,
        });
    }

    let domain_separator = &input[0..32];
    let struct_hash = &input[32..64];
    let v = input[64];
    let r = &input[65..97];
    let s = &input[97..129];

    // Compute EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
    let mut hasher = Keccak256::new();
    hasher.update([0x19, 0x01]);
    hasher.update(domain_separator);
    hasher.update(struct_hash);
    let digest = hasher.finalize();

    // Parse recovery ID
    let recovery_id = match v {
        27 => 0u8,
        28 => 1u8,
        0 => 0u8,
        1 => 1u8,
        _ => {
            return Ok(PrecompileResult {
                output: vec![0u8; 32],
                gas_used: gas_costs::EIP712_VERIFY,
                success: true,
            });
        }
    };

    // Recover address using shared recover_address
    let recovered = match super::recover_address(&digest, r, s, recovery_id) {
        Some(addr) => addr,
        None => {
            return Ok(PrecompileResult {
                output: vec![0u8; 32],
                gas_used: gas_costs::EIP712_VERIFY,
                success: true,
            });
        }
    };

    // Return zero-padded address
    let mut output = vec![0u8; 32];
    output[12..32].copy_from_slice(&recovered);

    Ok(PrecompileResult {
        output,
        gas_used: gas_costs::EIP712_VERIFY,
        success: true,
    })
}

/// Precompile 0x0201: EIP-3009 TransferWithAuthorization Verification
///
/// Input format (233 bytes):
///   domain_separator (32) | from (20) | to (20) | value (32) |
///   validAfter (32) | validBefore (32) | nonce (32) |
///   v (1) | r (32) | s (32)
///
/// Output (32 bytes):
///   Byte 0: 1 if valid (signer == from), 0 if invalid
///   Bytes 12-31: recovered signer address (20 bytes)
///
/// Gas: 4,200
fn transfer_auth_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < gas_costs::TRANSFER_AUTH_VERIFY {
        return Err(anyhow!("Insufficient gas for TransferWithAuthorization verify"));
    }

    // domain(32) + from(20) + to(20) + value(32) + validAfter(32) + validBefore(32) + nonce(32) + v(1) + r(32) + s(32) = 265
    if input.len() < 265 {
        return Ok(PrecompileResult {
            output: vec![0u8; 32],
            gas_used: gas_costs::TRANSFER_AUTH_VERIFY,
            success: true,
        });
    }

    let domain_separator = &input[0..32];
    let from = &input[32..52];
    let to = &input[52..72];
    let value = &input[72..104];
    let valid_after = &input[104..136];
    let valid_before = &input[136..168];
    let nonce = &input[168..200];
    let v = input[200];
    let r = &input[201..233];
    let s = &input[233..265];

    // Reconstruct EIP-3009 struct hash
    // structHash = keccak256(typehash || abi.encode(from, to, value, validAfter, validBefore, nonce))
    let typehash = transfer_with_authorization_typehash();

    let mut struct_data = Vec::with_capacity(32 + 6 * 32); // typehash + 6 ABI-encoded fields
    struct_data.extend_from_slice(&typehash);

    // ABI-encode `from` as address (left-padded to 32 bytes)
    let mut from_padded = [0u8; 32];
    from_padded[12..32].copy_from_slice(from);
    struct_data.extend_from_slice(&from_padded);

    // ABI-encode `to` as address
    let mut to_padded = [0u8; 32];
    to_padded[12..32].copy_from_slice(to);
    struct_data.extend_from_slice(&to_padded);

    // value, validAfter, validBefore are already 32 bytes
    struct_data.extend_from_slice(value);
    struct_data.extend_from_slice(valid_after);
    struct_data.extend_from_slice(valid_before);

    // nonce is bytes32 (already 32 bytes)
    struct_data.extend_from_slice(nonce);

    let mut hasher = Keccak256::new();
    hasher.update(&struct_data);
    let struct_hash: [u8; 32] = hasher.finalize().into();

    // Compute EIP-712 digest
    let mut digest_hasher = Keccak256::new();
    digest_hasher.update([0x19, 0x01]);
    digest_hasher.update(domain_separator);
    digest_hasher.update(struct_hash);
    let digest = digest_hasher.finalize();

    // Parse recovery ID
    let recovery_id = match v {
        27 => 0u8,
        28 => 1u8,
        0 => 0u8,
        1 => 1u8,
        _ => {
            return Ok(PrecompileResult {
                output: vec![0u8; 32],
                gas_used: gas_costs::TRANSFER_AUTH_VERIFY,
                success: true,
            });
        }
    };

    // Recover address
    let recovered = match super::recover_address(&digest, r, s, recovery_id) {
        Some(addr) => addr,
        None => {
            return Ok(PrecompileResult {
                output: vec![0u8; 32],
                gas_used: gas_costs::TRANSFER_AUTH_VERIFY,
                success: true,
            });
        }
    };

    // Check if recovered signer == from
    let valid = recovered == <[u8; 20]>::try_from(from).unwrap_or([0u8; 20]);

    // Output: validity byte + zero-padded signer
    let mut output = vec![0u8; 32];
    output[0] = if valid { 1 } else { 0 };
    output[12..32].copy_from_slice(&recovered);

    Ok(PrecompileResult {
        output,
        gas_used: gas_costs::TRANSFER_AUTH_VERIFY,
        success: true,
    })
}

/// Precompile 0x0202: Batch Payment Verification
///
/// Input format:
///   domain_separator (32) | count (2) |
///   (from(20) | to(20) | value(32) | validAfter(32) | validBefore(32) | nonce(32) | v(1) | r(32) | s(32))[]
///   Each payment entry: 201 bytes
///
/// Output:
///   verified_count (2 bytes, big-endian) |
///   (valid(1) | signer(20))[] each zero-padded to 32 bytes
///
/// Gas: 2,000 base + 3,800 per payment
fn batch_payment_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if input.len() < 34 {
        return Err(anyhow!("Invalid batch payment input: too short"));
    }

    let domain_separator = &input[0..32];
    let count = u16::from_be_bytes([input[32], input[33]]) as usize;

    let total_gas = gas_costs::BATCH_BASE + (count as u64) * gas_costs::BATCH_PER_PAYMENT;
    if gas_limit < total_gas {
        return Err(anyhow!("Insufficient gas for batch payment verify"));
    }

    // Per-entry: from(20)+to(20)+value(32)+validAfter(32)+validBefore(32)+nonce(32)+v(1)+r(32)+s(32) = 233
    let entry_size: usize = 233;
    let expected_len = 34 + count * entry_size;
    if input.len() < expected_len {
        return Err(anyhow!("Invalid batch payment input: expected {} bytes, got {}", expected_len, input.len()));
    }

    let typehash = transfer_with_authorization_typehash();
    let mut verified_count: u16 = 0;
    let mut results = Vec::with_capacity(count * 32);

    for i in 0..count {
        let offset = 34 + i * entry_size;
        let entry = &input[offset..offset + entry_size];

        let from = &entry[0..20];
        let to = &entry[20..40];
        let value = &entry[40..72];
        let valid_after = &entry[72..104];
        let valid_before = &entry[104..136];
        let nonce = &entry[136..168];
        let v = entry[168];
        let r = &entry[169..201];
        let s = &entry[201..233];

        // Reconstruct struct hash
        let mut struct_data = Vec::with_capacity(32 + 6 * 32);
        struct_data.extend_from_slice(&typehash);

        let mut from_padded = [0u8; 32];
        from_padded[12..32].copy_from_slice(from);
        struct_data.extend_from_slice(&from_padded);

        let mut to_padded = [0u8; 32];
        to_padded[12..32].copy_from_slice(to);
        struct_data.extend_from_slice(&to_padded);

        struct_data.extend_from_slice(value);
        struct_data.extend_from_slice(valid_after);
        struct_data.extend_from_slice(valid_before);
        struct_data.extend_from_slice(nonce);

        let mut hasher = Keccak256::new();
        hasher.update(&struct_data);
        let struct_hash: [u8; 32] = hasher.finalize().into();

        // EIP-712 digest
        let mut digest_hasher = Keccak256::new();
        digest_hasher.update([0x19, 0x01]);
        digest_hasher.update(domain_separator);
        digest_hasher.update(struct_hash);
        let digest = digest_hasher.finalize();

        // Recovery ID
        let recovery_id = match v {
            27 => 0u8,
            28 => 1u8,
            0 => 0u8,
            1 => 1u8,
            _ => {
                let mut result = vec![0u8; 32];
                result[0] = 0;
                results.extend_from_slice(&result);
                continue;
            }
        };

        // Recover and verify
        let mut result = vec![0u8; 32];
        if let Some(recovered) = super::recover_address(&digest, r, s, recovery_id) {
            let valid = recovered == <[u8; 20]>::try_from(from).unwrap_or([0u8; 20]);
            result[0] = if valid { 1 } else { 0 };
            result[12..32].copy_from_slice(&recovered);
            if valid {
                verified_count += 1;
            }
        }
        results.extend_from_slice(&result);
    }

    // Construct output: verified_count (2 bytes) + results
    let mut output = Vec::with_capacity(2 + results.len());
    output.extend_from_slice(&verified_count.to_be_bytes());
    output.extend_from_slice(&results);

    Ok(PrecompileResult {
        output,
        gas_used: total_gas,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;

    /// Helper: create a deterministic test key pair and sign an EIP-712 digest
    fn create_test_eip712_signature(
        domain_separator: &[u8; 32],
        struct_hash: &[u8; 32],
    ) -> (Vec<u8>, [u8; 20]) {
        let signing_key = SigningKey::random(&mut OsRng);

        // Compute EIP-712 digest
        let mut hasher = Keccak256::new();
        hasher.update([0x19, 0x01]);
        hasher.update(domain_separator);
        hasher.update(struct_hash);
        let digest: [u8; 32] = hasher.finalize().into();

        // Sign
        let (signature, recid) = signing_key
            .sign_prehash_recoverable(&digest)
            .expect("signing should succeed");

        let sig_bytes = signature.to_bytes();
        let v = recid.to_byte() + 27; // Ethereum convention

        // Derive expected address
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey.as_bytes();
        let mut addr_hasher = Keccak256::new();
        addr_hasher.update(&pubkey_bytes[1..65]);
        let addr_hash = addr_hasher.finalize();
        let mut expected_address = [0u8; 20];
        expected_address.copy_from_slice(&addr_hash[12..32]);

        // Build input
        let mut input = Vec::with_capacity(129);
        input.extend_from_slice(domain_separator);
        input.extend_from_slice(struct_hash);
        input.push(v);
        input.extend_from_slice(&sig_bytes[..32]); // r
        input.extend_from_slice(&sig_bytes[32..]); // s

        (input, expected_address)
    }

    /// Helper: create a TransferWithAuthorization signature
    fn create_test_transfer_auth(
        domain_separator: &[u8; 32],
        from_key: &SigningKey,
        to: &[u8; 20],
        value: &[u8; 32],
        valid_after: &[u8; 32],
        valid_before: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        // Derive from address
        let verifying_key = from_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey.as_bytes();
        let mut addr_hasher = Keccak256::new();
        addr_hasher.update(&pubkey_bytes[1..65]);
        let addr_hash = addr_hasher.finalize();
        let mut from_addr = [0u8; 20];
        from_addr.copy_from_slice(&addr_hash[12..32]);

        // Build struct hash
        let typehash = transfer_with_authorization_typehash();
        let mut struct_data = Vec::with_capacity(32 + 6 * 32);
        struct_data.extend_from_slice(&typehash);
        let mut from_padded = [0u8; 32];
        from_padded[12..32].copy_from_slice(&from_addr);
        struct_data.extend_from_slice(&from_padded);
        let mut to_padded = [0u8; 32];
        to_padded[12..32].copy_from_slice(to);
        struct_data.extend_from_slice(&to_padded);
        struct_data.extend_from_slice(value);
        struct_data.extend_from_slice(valid_after);
        struct_data.extend_from_slice(valid_before);
        struct_data.extend_from_slice(nonce);

        let mut hasher = Keccak256::new();
        hasher.update(&struct_data);
        let struct_hash: [u8; 32] = hasher.finalize().into();

        // EIP-712 digest
        let mut digest_hasher = Keccak256::new();
        digest_hasher.update([0x19, 0x01]);
        digest_hasher.update(domain_separator);
        digest_hasher.update(struct_hash);
        let digest: [u8; 32] = digest_hasher.finalize().into();

        // Sign
        let (signature, recid) = from_key
            .sign_prehash_recoverable(&digest)
            .expect("signing should succeed");
        let sig_bytes = signature.to_bytes();
        let v = recid.to_byte() + 27;

        // Build full input: domain_separator(32) | from(20) | to(20) | value(32) | validAfter(32) | validBefore(32) | nonce(32) | v(1) | r(32) | s(32)
        let mut input = Vec::with_capacity(265);
        input.extend_from_slice(domain_separator);
        input.extend_from_slice(&from_addr);
        input.extend_from_slice(to);
        input.extend_from_slice(value);
        input.extend_from_slice(valid_after);
        input.extend_from_slice(valid_before);
        input.extend_from_slice(nonce);
        input.push(v);
        input.extend_from_slice(&sig_bytes[..32]);
        input.extend_from_slice(&sig_bytes[32..]);

        input
    }

    #[test]
    fn test_precompile_addresses() {
        assert_eq!(addresses::EIP712_VERIFY[17], 2);
        assert_eq!(addresses::EIP712_VERIFY[18], 0);
        assert_eq!(addresses::EIP712_VERIFY[19], 0);
        assert_eq!(addresses::TRANSFER_AUTH_VERIFY[19], 1);
        assert_eq!(addresses::BATCH_PAYMENT_VERIFY[19], 2);
    }

    #[test]
    fn test_eip712_verify_known_signature() {
        let domain_separator = [0xABu8; 32];
        let struct_hash = [0xCDu8; 32];

        let (input, expected_address) = create_test_eip712_signature(&domain_separator, &struct_hash);

        let result = eip712_verify(&input, 10_000).expect("should succeed");
        assert!(result.success);
        assert_eq!(result.gas_used, gas_costs::EIP712_VERIFY);
        assert_eq!(result.output.len(), 32);

        // Recovered address should be in bytes 12..32
        let mut expected_output = vec![0u8; 32];
        expected_output[12..32].copy_from_slice(&expected_address);
        assert_eq!(result.output, expected_output);
    }

    #[test]
    fn test_eip712_verify_bad_signature() {
        let mut input = vec![0u8; 129];
        // domain_separator
        input[0..32].copy_from_slice(&[0xAB; 32]);
        // struct_hash
        input[32..64].copy_from_slice(&[0xCD; 32]);
        // v = 27
        input[64] = 27;
        // r = all zeros (invalid)
        // s = all zeros (invalid)

        let result = eip712_verify(&input, 10_000).expect("should not error");
        assert!(result.success);
        // Should return zero address (recovery failed)
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_eip712_verify_short_input() {
        let input = vec![0u8; 64]; // Too short (need 129)
        let result = eip712_verify(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_eip712_verify_insufficient_gas() {
        let input = vec![0u8; 129];
        let result = eip712_verify(&input, 100); // Way too little gas
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_auth_verify_valid() {
        let domain_separator = [0x11u8; 32];
        let from_key = SigningKey::random(&mut OsRng);
        let to = [0x22u8; 20];
        let value = [0u8; 32]; // 0 value
        let valid_after = [0u8; 32]; // timestamp 0
        let mut valid_before = [0u8; 32];
        valid_before[31] = 0xFF; // far future
        let nonce = [0x33u8; 32];

        let input = create_test_transfer_auth(
            &domain_separator, &from_key, &to, &value, &valid_after, &valid_before, &nonce,
        );

        let result = transfer_auth_verify(&input, 10_000).expect("should succeed");
        assert!(result.success);
        assert_eq!(result.gas_used, gas_costs::TRANSFER_AUTH_VERIFY);
        // First byte should be 1 (valid)
        assert_eq!(result.output[0], 1);
        // Bytes 12..32 should be the from address
        assert_ne!(&result.output[12..32], &[0u8; 20]);
    }

    #[test]
    fn test_transfer_auth_verify_wrong_from() {
        let domain_separator = [0x11u8; 32];
        let from_key = SigningKey::random(&mut OsRng);
        let to = [0x22u8; 20];
        let value = [0u8; 32];
        let valid_after = [0u8; 32];
        let mut valid_before = [0u8; 32];
        valid_before[31] = 0xFF;
        let nonce = [0x33u8; 32];

        let mut input = create_test_transfer_auth(
            &domain_separator, &from_key, &to, &value, &valid_after, &valid_before, &nonce,
        );

        // Tamper with the `from` field (bytes 32..52) — replace with a different address
        let fake_from = [0xFFu8; 20];
        input[32..52].copy_from_slice(&fake_from);

        let result = transfer_auth_verify(&input, 10_000).expect("should succeed");
        assert!(result.success);
        // First byte should be 0 (invalid — signer doesn't match tampered from)
        assert_eq!(result.output[0], 0);
    }

    #[test]
    fn test_batch_payment_verify_all_valid() {
        let domain_separator = [0x44u8; 32];
        let to = [0x55u8; 20];
        let value = [0u8; 32];
        let valid_after = [0u8; 32];
        let mut valid_before = [0u8; 32];
        valid_before[31] = 0xFF;

        let mut input = Vec::new();
        input.extend_from_slice(&domain_separator);
        input.extend_from_slice(&3u16.to_be_bytes()); // count = 3

        // Create 3 valid payment entries
        for i in 0..3u8 {
            let from_key = SigningKey::random(&mut OsRng);
            let mut nonce = [0u8; 32];
            nonce[31] = i;

            // Build this entry's auth input (without domain_separator prefix since batch shares it)
            let full_input = create_test_transfer_auth(
                &domain_separator, &from_key, &to, &value, &valid_after, &valid_before, &nonce,
            );

            // Extract the per-entry portion (skip domain_separator)
            // full_input = domain(32) | from(20) | to(20) | value(32) | ... | s(32) = 265
            // entry = from(20) | to(20) | value(32) | ... | s(32) = 233
            input.extend_from_slice(&full_input[32..]);
        }

        let total_gas = gas_costs::BATCH_BASE + 3 * gas_costs::BATCH_PER_PAYMENT;
        let result = batch_payment_verify(&input, total_gas + 1000).expect("should succeed");
        assert!(result.success);

        // First 2 bytes = verified count
        let verified = u16::from_be_bytes([result.output[0], result.output[1]]);
        assert_eq!(verified, 3);
    }

    #[test]
    fn test_batch_payment_verify_mixed() {
        let domain_separator = [0x66u8; 32];
        let to = [0x77u8; 20];
        let value = [0u8; 32];
        let valid_after = [0u8; 32];
        let mut valid_before = [0u8; 32];
        valid_before[31] = 0xFF;

        let mut input = Vec::new();
        input.extend_from_slice(&domain_separator);
        input.extend_from_slice(&2u16.to_be_bytes()); // count = 2

        // Entry 1: valid
        let from_key1 = SigningKey::random(&mut OsRng);
        let nonce1 = [0x01u8; 32];
        let full1 = create_test_transfer_auth(
            &domain_separator, &from_key1, &to, &value, &valid_after, &valid_before, &nonce1,
        );
        input.extend_from_slice(&full1[32..]);

        // Entry 2: invalid (tamper from address)
        let from_key2 = SigningKey::random(&mut OsRng);
        let nonce2 = [0x02u8; 32];
        let mut full2 = create_test_transfer_auth(
            &domain_separator, &from_key2, &to, &value, &valid_after, &valid_before, &nonce2,
        );
        // Tamper the from field in the entry (bytes 32..52 in full input, but we're using full2[32..] so from is at offset 0..20)
        let tampered_entry_start = 32; // skip domain in full2
        full2[tampered_entry_start..tampered_entry_start + 20].copy_from_slice(&[0xDE; 20]);
        input.extend_from_slice(&full2[32..]);

        let total_gas = gas_costs::BATCH_BASE + 2 * gas_costs::BATCH_PER_PAYMENT;
        let result = batch_payment_verify(&input, total_gas + 1000).expect("should succeed");
        assert!(result.success);

        let verified = u16::from_be_bytes([result.output[0], result.output[1]]);
        assert_eq!(verified, 1); // Only first is valid
    }

    #[test]
    fn test_gas_limit_respected() {
        let input = vec![0u8; 129];
        // EIP-712 verify needs 3,450 gas
        let result = eip712_verify(&input, 3_449);
        assert!(result.is_err());

        let result = eip712_verify(&input, 3_450);
        assert!(result.is_ok());
    }
}
