// citrate/core/api/src/eth_tx_decoder.rs

use ethereum_types::{H160, H256, U256 as EthU256};
use hex;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use rlp::{DecoderError, Rlp, RlpStream};
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};
use sha3::{Digest, Keccak256};
use tracing::debug;

/// Legacy Ethereum transaction structure for RLP decoding
#[derive(Debug)]
struct LegacyTransaction {
    nonce: u64,
    gas_price: EthU256,
    gas_limit: u64,
    to: Option<H160>,
    value: EthU256,
    data: Vec<u8>,
    v: u64,
    r: H256,
    s: H256,
}

impl LegacyTransaction {
    /// Decode from RLP bytes
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // Helper to pad signature components from variable-length RLP bytes
        let pad_sig = |bytes: Vec<u8>| -> H256 {
            let mut padded = [0u8; 32];
            let start = 32 - bytes.len().min(32);
            padded[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
            H256::from(padded)
        };

        Ok(LegacyTransaction {
            nonce: rlp.val_at(0)?,
            gas_price: rlp.val_at(1)?,
            gas_limit: rlp.val_at(2)?,
            to: {
                let to_bytes: Vec<u8> = rlp.val_at(3)?;
                if to_bytes.is_empty() {
                    None
                } else if to_bytes.len() != 20 {
                    return Err(rlp::DecoderError::Custom("invalid to address length"));
                } else {
                    Some(H160::from_slice(&to_bytes))
                }
            },
            value: rlp.val_at(4)?,
            data: rlp.val_at(5)?,
            v: rlp.val_at(6)?,
            r: pad_sig(rlp.val_at(7)?),
            s: pad_sig(rlp.val_at(8)?),
        })
    }
}

/// Decode an Ethereum-style RLP transaction into Citrate transaction format.
///
/// PBA-L1a-006: the returned `hash` is the canonical id derived from the
/// signed contents (`tx_auth::authenticate`) whenever the tx authenticates —
/// the same id the mempool stores it under and block import requires — so
/// the hash RPC hands back is the one receipts are keyed by. For a
/// canonically-encoded raw Ethereum tx it equals `keccak256(raw)`; a bincode
/// native tx's client-chosen `hash` is replaced.
pub fn decode_eth_transaction(tx_bytes: &[u8]) -> Result<Transaction, String> {
    let mut tx = decode_eth_transaction_inner(tx_bytes)?;
    if let Ok(canonical) = citrate_consensus::tx_auth::authenticate(&tx) {
        tx.hash = canonical;
    }
    Ok(tx)
}

fn decode_eth_transaction_inner(tx_bytes: &[u8]) -> Result<Transaction, String> {
    debug!("Decoding {} bytes of transaction data", tx_bytes.len());
    debug!("First 20 bytes: {:?}", &tx_bytes[..tx_bytes.len().min(20)]);

    // Check if this might be an Ethereum transaction (starts with certain patterns)
    if tx_bytes.is_empty() {
        return Err("Empty transaction data".to_string());
    }

    // ALWAYS generate a proper hash from the input bytes
    let mut hasher = Keccak256::new();
    hasher.update(tx_bytes);
    let hash_result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash_result);

    debug!("Calculated transaction hash: 0x{}", hex::encode(hash_bytes));

    // Handle typed transactions (EIP-2718). 0x02 = EIP-1559, 0x01 = EIP-2930
    // Try these BEFORE bincode to prevent RLP bytes from accidentally
    // passing bincode::deserialize (which would bypass chain ID validation).
    if tx_bytes[0] == 0x02 {
        return decode_eip1559_transaction(&tx_bytes[1..]);
    }
    if tx_bytes[0] == 0x01 {
        return decode_eip2930_transaction(&tx_bytes[1..]);
    }

    // Try to decode as legacy RLP (before bincode, same reason)
    let rlp = Rlp::new(tx_bytes);

    // Check if this is a valid RLP list
    if rlp.is_list() {
        // Try to decode as legacy transaction
        if let Ok(legacy_tx) = LegacyTransaction::decode(&rlp) {
                debug!("Successfully decoded legacy Ethereum transaction");
                debug!("  Nonce: {}", legacy_tx.nonce);
                debug!("  Gas limit: {}", legacy_tx.gas_limit);
                debug!("  To: {:?}", legacy_tx.to);
                debug!("  Value: {}", legacy_tx.value);
                debug!("  Data length: {}", legacy_tx.data.len());

                // Determine chain ID and recovery ID from v value
                // EIP-155: v = chainId * 2 + 35 + {0,1}
                // Pre-EIP-155: v = 27 + {0,1}
                let (recovery_id, chain_id_opt) = if legacy_tx.v >= 35 {
                    // EIP-155 transaction
                    let chain_id = (legacy_tx.v - 35) / 2;
                    let recovery_id = ((legacy_tx.v - 35) % 2) as i32;
                    debug!(
                        "  EIP-155 transaction: chain_id={}, recovery_id={}",
                        chain_id, recovery_id
                    );
                    (recovery_id, Some(chain_id))
                } else if legacy_tx.v == 27 || legacy_tx.v == 28 {
                    // Pre-EIP-155 transaction
                    let recovery_id = (legacy_tx.v - 27) as i32;
                    debug!("  Pre-EIP-155 transaction: recovery_id={}", recovery_id);
                    (recovery_id, None)
                } else {
                    debug!("  Invalid v value: {}", legacy_tx.v);
                    return Err(format!("Invalid v value: {}", legacy_tx.v));
                };

                // Build the transaction data for signing (pre-signature)
                let mut stream = if let Some(_chain_id) = chain_id_opt {
                    // EIP-155 signing data includes chain ID
                    rlp::RlpStream::new_list(9)
                } else {
                    // Pre-EIP-155 signing data
                    rlp::RlpStream::new_list(6)
                };

                stream.append(&legacy_tx.nonce);
                stream.append(&legacy_tx.gas_price);
                stream.append(&legacy_tx.gas_limit);

                // Handle 'to' field
                if let Some(to) = legacy_tx.to {
                    stream.append(&to.as_bytes());
                } else {
                    stream.append_empty_data();
                }

                stream.append(&legacy_tx.value);
                stream.append(&legacy_tx.data);

                // For EIP-155, append chain ID and zeros
                if let Some(chain_id) = chain_id_opt {
                    stream.append(&chain_id);
                    stream.append(&0u8);
                    stream.append(&0u8);
                }

                let signable_data = stream.out().to_vec();
                let sighash = Keccak256::digest(&signable_data);
                debug!("  Signature hash: 0x{}", hex::encode(sighash));

                // Recover the sender's public key and address
                let secp = Secp256k1::new();

                // Create the recoverable signature
                let mut rs_bytes = [0u8; 64];
                rs_bytes[..32].copy_from_slice(legacy_tx.r.as_bytes());
                rs_bytes[32..].copy_from_slice(legacy_tx.s.as_bytes());

                debug!("  Signature R: 0x{}", hex::encode(&rs_bytes[..32]));
                debug!("  Signature S: 0x{}", hex::encode(&rs_bytes[32..]));

                // SECREM-01 EXEC-1: enforce EIP-2 low-s. This legacy decode
                // path uses `secp256k1` recovery, which (unlike the
                // precompile's `recover_address`) does NOT reject high-s
                // signatures — so `(r, s)` and `(r, n−s)` both recover the
                // same signer, yielding two valid encodings (two tx hashes)
                // for one transaction: malleability that breaks receipt
                // polling. Reject high-s before recovery.
                if is_high_s(&rs_bytes[32..]) {
                    return Err(
                        "EIP-2 violation: signature s-value is not in the low half-order \
                         (malleable signature rejected)"
                            .into(),
                    );
                }

                // Recover the sender address from signature (fail-closed: C-03).
                // Any failure in the recovery chain returns Err — never fabricate fallback addresses.
                let recid = RecoveryId::from_i32(recovery_id)
                    .map_err(|e| format!("Invalid recovery ID {}: {}", recovery_id, e))?;
                let recsig = RecoverableSignature::from_compact(&rs_bytes, recid)
                    .map_err(|e| format!("Invalid recoverable signature: {}", e))?;
                let msg = Message::from_slice(&sighash)
                    .map_err(|e| format!("Invalid signature hash: {}", e))?;
                let pubkey = secp.recover_ecdsa(&msg, &recsig)
                    .map_err(|e| format!("ECDSA recovery failed: {}", e))?;

                // Get uncompressed public key (65 bytes: 0x04 + x + y)
                let uncompressed = pubkey.serialize_uncompressed();

                // Hash the public key (excluding the 0x04 prefix)
                let mut hasher = Keccak256::new();
                hasher.update(&uncompressed[1..]);
                let hash = hasher.finalize();

                // Take the last 20 bytes as the address
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&hash[12..]);
                let from_addr = H160::from_slice(&addr_bytes);
                debug!(
                    "  Recovered address: 0x{}",
                    hex::encode(from_addr.as_bytes())
                );
                debug!("  From address: 0x{}", hex::encode(from_addr.as_bytes()));

                // Convert addresses to PublicKey format by embedding 20 bytes in 32-byte field
                let mut from_pk_bytes = [0u8; 32];
                from_pk_bytes[..20].copy_from_slice(from_addr.as_bytes());
                let from_pk = PublicKey::new(from_pk_bytes);

                let to_pk = legacy_tx.to.map(|addr| {
                    let mut pk_bytes = [0u8; 32];
                    pk_bytes[..20].copy_from_slice(addr.as_bytes());
                    PublicKey::new(pk_bytes)
                });

                // Convert gas price (wei to gwei for our system)
                let gas_price = if legacy_tx.gas_price > EthU256::from(u64::MAX) {
                    u64::MAX
                } else {
                    legacy_tx.gas_price.as_u64()
                };

                // Convert value to u128
                let value = if legacy_tx.value > EthU256::from(u128::MAX) {
                    u128::MAX
                } else {
                    legacy_tx.value.as_u128()
                };

                // Create signature from r, s (compact)
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(legacy_tx.r.as_bytes());
                sig_bytes[32..].copy_from_slice(legacy_tx.s.as_bytes());

                let mut tx = Transaction {
                    hash: Hash::new(hash_bytes), // Use the calculated hash
                    from: from_pk,
                    to: to_pk,
                    value,
                    data: legacy_tx.data.clone(),
                    nonce: legacy_tx.nonce,
                    gas_price,
                    gas_limit: legacy_tx.gas_limit,
                    signature: Signature::new(sig_bytes),
                    tx_type: None,
                    eth_tx_type: 0,
                    chain_id: chain_id_opt,
                    ecdsa_verified: true, // ECDSA signature was cryptographically verified during recovery above
                    ..Default::default()
                };

                // Determine transaction type from data
                tx.determine_type();

                debug!("Successfully converted to Citrate transaction format");
                debug!(
                    "Final transaction hash: 0x{}",
                    hex::encode(tx.hash.as_bytes())
                );
                return Ok(tx);
        } else {
            debug!("Failed to decode as legacy RLP, falling back to bincode");
        }
    }
    // Fall through: either !is_list() or RLP decode failed — try bincode
    {
        // Last resort: try bincode for Citrate native transactions.
        // This is done AFTER RLP to prevent Ethereum RLP bytes from
        // accidentally deserializing as bincode (which would skip chain ID validation).
        // PT-04: Limit bincode deserialization to prevent OOM from crafted length prefixes
        if tx_bytes.len() > 256 * 1024 {
            return Err("Transaction too large for bincode path (max 256KB)".to_string());
        }
        // SECURITY (PT-05): Signature verification is enforced downstream in
        // mempool.rs (ecdsa_verified gate). The mempool rejects any EVM-shaped
        // transaction with ecdsa_verified=false. The flag is forced false on the
        // next line. See test_k1_forged_ecdsa_verified_rejected() for regression test.
        if let Ok(mut tx) = bincode::deserialize::<Transaction>(tx_bytes) {
            // WP-K.1: SECURITY — never trust wire-serialized ecdsa_verified flag.
            // A malicious client could craft a bincode payload with ecdsa_verified=true
            // to bypass ECDSA recovery. Force it to false so the mempool/verifier
            // must independently verify the signature.
            tx.ecdsa_verified = false;
            debug!("Successfully decoded as Citrate native transaction (bincode fallback)");
            if tx.hash == Hash::default() {
                tx.hash = Hash::new(hash_bytes);
            }
            return Ok(tx);
        }
        debug!("Not a valid RLP list, cannot decode transaction");
        Err("Invalid RLP: expected a list for legacy transaction".to_string())
    }
}

/// Decode EIP-1559 (type-0x02) transaction
fn decode_eip1559_transaction(rlp_bytes: &[u8]) -> Result<Transaction, String> {
    debug!("Decoding EIP-1559 typed transaction (0x02)");
    let rlp = Rlp::new(rlp_bytes);
    if !rlp.is_list() {
        return Err("Invalid EIP-1559 RLP payload".into());
    }

    // Per EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]
    let chain_id_u256: EthU256 = rlp.val_at(0).map_err(|e| format!("chainId: {:?}", e))?;
    let nonce: u64 = rlp.val_at(1).map_err(|e| format!("nonce: {:?}", e))?;
    let max_priority_fee: EthU256 = rlp.val_at(2).map_err(|e| format!("maxPrioFee: {:?}", e))?;
    let max_fee: EthU256 = rlp.val_at(3).map_err(|e| format!("maxFee: {:?}", e))?;
    let gas_limit: u64 = rlp.val_at(4).map_err(|e| format!("gasLimit: {:?}", e))?;

    // to is bytes (empty for create), else 20 bytes
    let to_opt: Option<H160> = {
        let tb: Vec<u8> = rlp.val_at(5).map_err(|e| format!("to: {:?}", e))?;
        if tb.is_empty() {
            None
        } else if tb.len() != 20 {
            return Err("invalid to address length (expected 20 bytes)".to_string());
        } else {
            Some(H160::from_slice(&tb))
        }
    };
    let value_u256: EthU256 = rlp.val_at(6).map_err(|e| format!("value: {:?}", e))?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|e| format!("data: {:?}", e))?;

    // Parse access list at index 8
    let access_list = parse_access_list(&rlp, 8)?;
    debug!("  Access list entries: {}", access_list.len());

    let y_parity: u64 = rlp.val_at(9).map_err(|e| format!("yParity: {:?}", e))?;

    // Pad signature components from variable-length RLP bytes
    let r_bytes: Vec<u8> = rlp.val_at(10).map_err(|e| format!("r: {:?}", e))?;
    let mut r_padded = [0u8; 32];
    let r_start = 32 - r_bytes.len().min(32);
    r_padded[r_start..].copy_from_slice(&r_bytes[..r_bytes.len().min(32)]);
    let r_h = H256::from(r_padded);

    let s_bytes: Vec<u8> = rlp.val_at(11).map_err(|e| format!("s: {:?}", e))?;
    let mut s_padded = [0u8; 32];
    let s_start = 32 - s_bytes.len().min(32);
    s_padded[s_start..].copy_from_slice(&s_bytes[..s_bytes.len().min(32)]);
    let s_h = H256::from(s_padded);

    // Build the signing payload per EIP-1559 (without yParity,r,s)
    let mut s = RlpStream::new_list(9);
    s.append(&chain_id_u256);
    s.append(&nonce);
    s.append(&max_priority_fee);
    s.append(&max_fee);
    s.append(&gas_limit);
    if let Some(to) = to_opt {
        s.append(&to.as_bytes());
    } else {
        s.append_empty_data();
    }
    s.append(&value_u256);
    s.append(&data.as_slice());

    // Encode access list properly
    encode_access_list(&mut s, &access_list);

    let payload = s.out().to_vec();

    // Calculate typed sighash: keccak256(0x02 || rlp)
    let sighash = {
        let mut k = Keccak256::new();
        k.update([0x02]);
        k.update(&payload);
        let b = k.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        out
    };

    // Recover address using yParity as recovery id
    let from_addr = {
        let recid = secp256k1::ecdsa::RecoveryId::from_i32((y_parity & 0x01) as i32)
            .map_err(|e| format!("bad recid: {}", e))?;
        // SECREM-01 EXEC-1: enforce EIP-2 low-s on the typed-tx path too.
        if is_high_s(s_h.as_bytes()) {
            return Err("EIP-2 violation: high-s signature rejected".into());
        }
        let recsig = secp256k1::ecdsa::RecoverableSignature::from_compact(
            &{
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(r_h.as_bytes());
                rs[32..].copy_from_slice(s_h.as_bytes());
                rs
            },
            recid,
        )
        .map_err(|e| format!("bad recsig: {}", e))?;
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&sighash).map_err(|e| format!("msg: {}", e))?;
        let pubkey = secp
            .recover_ecdsa(&msg, &recsig)
            .map_err(|e| format!("recover: {}", e))?;
        let uncompressed = pubkey.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]);
        let h = hasher.finalize();
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        H160::from_slice(&a)
    };

    // Build Citrate Transaction
    let mut from_pk_bytes = [0u8; 32];
    from_pk_bytes[..20].copy_from_slice(from_addr.as_bytes());
    let from_pk = PublicKey::new(from_pk_bytes);
    let to_pk = to_opt.map(|t| {
        let mut b = [0u8; 32];
        b[..20].copy_from_slice(t.as_bytes());
        PublicKey::new(b)
    });

    // Use maxFeePerGas as gas_price proxy; saturate types
    let gas_price = if max_fee > EthU256::from(u64::MAX) {
        u64::MAX
    } else {
        max_fee.as_u64()
    };
    let value = if value_u256 > EthU256::from(u128::MAX) {
        u128::MAX
    } else {
        value_u256.as_u128()
    };

    // Compute tx hash from original bytes
    let mut hasher = Keccak256::new();
    hasher.update([0x02]);
    hasher.update(rlp_bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hasher.finalize());

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r_h.as_bytes());
    sig_bytes[32..].copy_from_slice(s_h.as_bytes());

    // Convert access list to Transaction field format
    let al: Vec<(Vec<u8>, Vec<Vec<u8>>)> = access_list
        .iter()
        .map(|e| {
            let addr = e.address.as_bytes().to_vec();
            let keys = e.storage_keys.iter().map(|k| k.as_bytes().to_vec()).collect();
            (addr, keys)
        })
        .collect();

    let max_fee_val = if max_fee > EthU256::from(u64::MAX) { u64::MAX } else { max_fee.as_u64() };
    let max_prio_val = if max_priority_fee > EthU256::from(u64::MAX) { u64::MAX } else { max_priority_fee.as_u64() };
    let decoded_chain_id = if chain_id_u256 > EthU256::from(u64::MAX) { None } else { Some(chain_id_u256.as_u64()) };

    let mut tx = Transaction {
        hash: Hash::new(hash_bytes),
        from: from_pk,
        to: to_pk,
        value,
        gas_limit,
        gas_price,
        data,
        nonce,
        signature: Signature::new(sig_bytes),
        tx_type: None,
        eth_tx_type: 2,
        max_fee_per_gas: Some(max_fee_val),
        max_priority_fee_per_gas: Some(max_prio_val),
        access_list: if al.is_empty() { None } else { Some(al) },
        chain_id: decoded_chain_id,
        ecdsa_verified: true, // ECDSA signature was cryptographically verified during recovery above
    };
    tx.determine_type();
    Ok(tx)
}

/// Access list entry structure
#[derive(Debug, Clone)]
struct AccessListEntry {
    address: H160,
    storage_keys: Vec<H256>,
}

/// Hard cap on access-list entries to prevent CPU/memory exhaustion
/// via attacker-supplied huge access lists. RM-B1 / WP-C1.2 (audit
/// H-API-02). Geth's effective limit is around 100s; 1024 is a
/// generous upper bound.
const MAX_ACCESS_LIST_ENTRIES: usize = 1024;
/// Hard cap on storage keys per access-list entry. Same rationale.
const MAX_STORAGE_KEYS_PER_ENTRY: usize = 1024;

/// Parse access list from RLP at given index.
///
/// RM-B1 / WP-C1.2 (audit H-API-02): pre-fix this function called
/// `H160::from_slice(&address_bytes)` and `H256::from_slice(&key_bytes)`
/// without checking the slice length. Both panic on length mismatch.
/// A crafted EIP-1559 / EIP-2930 tx posted to `eth_sendRawTransaction`
/// could panic the RPC worker thread by supplying a 19-byte address
/// or a 31-byte storage key. Post-fix, length checks return `Err`
/// instead, and the entry/key counts are capped to prevent DoS via
/// huge access lists.
fn parse_access_list(rlp: &Rlp, index: usize) -> Result<Vec<AccessListEntry>, String> {
    let access_list_rlp = rlp.at(index).map_err(|e| format!("access_list: {:?}", e))?;
    let item_count = access_list_rlp.item_count().unwrap_or(0);
    if item_count > MAX_ACCESS_LIST_ENTRIES {
        return Err(format!(
            "H-API-02: access list has {} entries; max is {}",
            item_count, MAX_ACCESS_LIST_ENTRIES
        ));
    }

    let mut access_list = Vec::with_capacity(item_count);

    for i in 0..item_count {
        let entry_rlp = access_list_rlp.at(i).map_err(|e| format!("access_entry[{}]: {:?}", i, e))?;

        let address_bytes: Vec<u8> = entry_rlp.val_at(0).map_err(|e| format!("address: {:?}", e))?;
        if address_bytes.len() != 20 {
            return Err(format!(
                "H-API-02: access list address[{}] is {} bytes; expected 20",
                i,
                address_bytes.len()
            ));
        }
        let address = H160::from_slice(&address_bytes);

        let storage_keys_rlp = entry_rlp.at(1).map_err(|e| format!("storage_keys: {:?}", e))?;
        let key_count = storage_keys_rlp.item_count().unwrap_or(0);
        if key_count > MAX_STORAGE_KEYS_PER_ENTRY {
            return Err(format!(
                "H-API-02: access list entry[{}] has {} storage keys; max is {}",
                i, key_count, MAX_STORAGE_KEYS_PER_ENTRY
            ));
        }
        let mut storage_keys = Vec::with_capacity(key_count);

        for j in 0..key_count {
            let key_bytes: Vec<u8> = storage_keys_rlp.val_at(j).map_err(|e| format!("storage_key[{}]: {:?}", j, e))?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "H-API-02: access list entry[{}].storage_key[{}] is {} bytes; expected 32",
                    i,
                    j,
                    key_bytes.len()
                ));
            }
            storage_keys.push(H256::from_slice(&key_bytes));
        }

        access_list.push(AccessListEntry {
            address,
            storage_keys,
        });
    }

    Ok(access_list)
}

/// Encode access list into RLP stream
fn encode_access_list(stream: &mut RlpStream, access_list: &[AccessListEntry]) {
    stream.begin_list(access_list.len());
    for entry in access_list {
        stream.begin_list(2);
        stream.append(&entry.address.as_bytes());
        stream.begin_list(entry.storage_keys.len());
        for key in &entry.storage_keys {
            stream.append(&key.as_bytes());
        }
    }
}

/// Decode EIP-2930 (type-0x01) transaction with access lists
fn decode_eip2930_transaction(rlp_bytes: &[u8]) -> Result<Transaction, String> {
    debug!("Decoding EIP-2930 typed transaction (0x01)");
    let rlp = Rlp::new(rlp_bytes);
    if !rlp.is_list() {
        return Err("Invalid EIP-2930 RLP payload".into());
    }

    // Per EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
    let chain_id_u256: EthU256 = rlp.val_at(0).map_err(|e| format!("chainId: {:?}", e))?;
    let nonce: u64 = rlp.val_at(1).map_err(|e| format!("nonce: {:?}", e))?;
    let gas_price: EthU256 = rlp.val_at(2).map_err(|e| format!("gasPrice: {:?}", e))?;
    let gas_limit: u64 = rlp.val_at(3).map_err(|e| format!("gasLimit: {:?}", e))?;

    // to is bytes (empty for create), else 20 bytes
    let to_opt: Option<H160> = {
        let tb: Vec<u8> = rlp.val_at(4).map_err(|e| format!("to: {:?}", e))?;
        if tb.is_empty() {
            None
        } else if tb.len() != 20 {
            return Err("invalid to address length (expected 20 bytes)".to_string());
        } else {
            Some(H160::from_slice(&tb))
        }
    };
    let value_u256: EthU256 = rlp.val_at(5).map_err(|e| format!("value: {:?}", e))?;
    let data: Vec<u8> = rlp.val_at(6).map_err(|e| format!("data: {:?}", e))?;

    // Parse access list at index 7
    let access_list = parse_access_list(&rlp, 7)?;
    debug!("  Access list entries: {}", access_list.len());

    let y_parity: u64 = rlp.val_at(8).map_err(|e| format!("yParity: {:?}", e))?;

    // Pad signature components from variable-length RLP bytes
    let r_bytes: Vec<u8> = rlp.val_at(9).map_err(|e| format!("r: {:?}", e))?;
    let mut r_padded = [0u8; 32];
    let r_start = 32 - r_bytes.len().min(32);
    r_padded[r_start..].copy_from_slice(&r_bytes[..r_bytes.len().min(32)]);
    let r_h = H256::from(r_padded);

    let s_bytes: Vec<u8> = rlp.val_at(10).map_err(|e| format!("s: {:?}", e))?;
    let mut s_padded = [0u8; 32];
    let s_start = 32 - s_bytes.len().min(32);
    s_padded[s_start..].copy_from_slice(&s_bytes[..s_bytes.len().min(32)]);
    let s_h = H256::from(s_padded);

    // Build the signing payload per EIP-2930 (without yParity,r,s)
    let mut s = RlpStream::new_list(8);
    s.append(&chain_id_u256);
    s.append(&nonce);
    s.append(&gas_price);
    s.append(&gas_limit);
    if let Some(to) = to_opt {
        s.append(&to.as_bytes());
    } else {
        s.append_empty_data();
    }
    s.append(&value_u256);
    s.append(&data.as_slice());

    // Encode access list properly
    encode_access_list(&mut s, &access_list);

    let payload = s.out().to_vec();

    // Calculate typed sighash: keccak256(0x01 || rlp)
    let sighash = {
        let mut k = Keccak256::new();
        k.update([0x01]);
        k.update(&payload);
        let b = k.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        out
    };

    // Recover address using yParity as recovery id
    let from_addr = {
        let recid = secp256k1::ecdsa::RecoveryId::from_i32((y_parity & 0x01) as i32)
            .map_err(|e| format!("bad recid: {}", e))?;
        // SECREM-01 EXEC-1: enforce EIP-2 low-s on the typed-tx path too.
        if is_high_s(s_h.as_bytes()) {
            return Err("EIP-2 violation: high-s signature rejected".into());
        }
        let recsig = secp256k1::ecdsa::RecoverableSignature::from_compact(
            &{
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(r_h.as_bytes());
                rs[32..].copy_from_slice(s_h.as_bytes());
                rs
            },
            recid,
        )
        .map_err(|e| format!("bad recsig: {}", e))?;
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&sighash).map_err(|e| format!("msg: {}", e))?;
        let pubkey = secp
            .recover_ecdsa(&msg, &recsig)
            .map_err(|e| format!("recover: {}", e))?;
        let uncompressed = pubkey.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]);
        let h = hasher.finalize();
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        H160::from_slice(&a)
    };

    // Build Citrate Transaction
    let mut from_pk_bytes = [0u8; 32];
    from_pk_bytes[..20].copy_from_slice(from_addr.as_bytes());
    let from_pk = PublicKey::new(from_pk_bytes);
    let to_pk = to_opt.map(|t| {
        let mut b = [0u8; 32];
        b[..20].copy_from_slice(t.as_bytes());
        PublicKey::new(b)
    });

    // Saturate types
    let gas_price = if gas_price > EthU256::from(u64::MAX) {
        u64::MAX
    } else {
        gas_price.as_u64()
    };
    let value = if value_u256 > EthU256::from(u128::MAX) {
        u128::MAX
    } else {
        value_u256.as_u128()
    };

    // Compute tx hash from original bytes
    let mut hasher = Keccak256::new();
    hasher.update([0x01]);
    hasher.update(rlp_bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hasher.finalize());

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r_h.as_bytes());
    sig_bytes[32..].copy_from_slice(s_h.as_bytes());

    // Convert access list to Transaction field format
    let al: Vec<(Vec<u8>, Vec<Vec<u8>>)> = access_list
        .iter()
        .map(|e| {
            let addr = e.address.as_bytes().to_vec();
            let keys = e.storage_keys.iter().map(|k| k.as_bytes().to_vec()).collect();
            (addr, keys)
        })
        .collect();

    let decoded_chain_id = if chain_id_u256 > EthU256::from(u64::MAX) { None } else { Some(chain_id_u256.as_u64()) };

    let mut tx = Transaction {
        hash: Hash::new(hash_bytes),
        from: from_pk,
        to: to_pk,
        value,
        gas_limit,
        gas_price,
        data,
        nonce,
        signature: Signature::new(sig_bytes),
        tx_type: None,
        eth_tx_type: 1,
        access_list: if al.is_empty() { None } else { Some(al) },
        chain_id: decoded_chain_id,
        ecdsa_verified: true, // ECDSA signature was cryptographically verified during recovery above
        ..Default::default()
    };
    tx.determine_type();

    debug!("Successfully decoded EIP-2930 transaction");
    debug!("  From: 0x{}", hex::encode(from_addr.as_bytes()));
    debug!("  To: {:?}", to_opt.map(|t| format!("0x{}", hex::encode(t.as_bytes()))));
    debug!("  Nonce: {}", nonce);
    debug!("  Access list entries: {}", access_list.len());

    Ok(tx)
}

// Note: Mock transaction creation has been removed for security reasons.
// All transaction decoding must succeed or return an error.
// Invalid transactions should never be fabricated and added to the mempool.

/// SECREM-01 EXEC-1: EIP-2 low-s check. Returns true if the 32-byte
/// big-endian `s` value is greater than half the secp256k1 curve order
/// `n/2` — i.e. a malleable "high-s" signature that the Yellow Paper /
/// EIP-2 require nodes to reject. The `secp256k1` recovery API does not
/// enforce this (unlike the precompile's `recover_address`), so the
/// transaction decoder must.
fn is_high_s(s_be: &[u8]) -> bool {
    // secp256k1 n/2 (half curve order), big-endian.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    if s_be.len() != 32 {
        // Defensive: a non-canonical length can't be proven low-s; treat
        // as high-s (reject) rather than silently accept.
        return true;
    }
    // Lexicographic compare of equal-length big-endian integers == numeric
    // compare. s > n/2 ⇒ high-s.
    s_be > &HALF_N[..]
}

#[cfg(test)]
mod secrem01_exec1_tests {
    use super::is_high_s;

    // secp256k1 n/2 big-endian.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    #[test]
    fn low_s_accepted_high_s_rejected() {
        // s = 1 → low.
        let mut low = [0u8; 32];
        low[31] = 1;
        assert!(!is_high_s(&low));

        // s = n/2 exactly → low (boundary is inclusive of n/2).
        assert!(!is_high_s(&HALF_N));

        // s = n/2 + 1 → high.
        let mut high = HALF_N;
        high[31] = high[31].wrapping_add(1);
        assert!(is_high_s(&high));

        // s = all 0xff (≈ n, definitely high).
        assert!(is_high_s(&[0xffu8; 32]));

        // Wrong length → reject (treated high).
        assert!(is_high_s(&[0u8; 31]));
    }
}
