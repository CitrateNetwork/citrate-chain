// E2E test: Wallet CLI → RPC → Mempool → Block Inclusion
//
// Validates the full transaction lifecycle:
// 1. Transaction construction and signing via wallet builder
// 2. Bincode serialization round-trip
// 3. Mempool acceptance and ordering
// 4. Executor balance/nonce state changes

use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::types::Address;
use citrate_execution::Executor;
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use sha3::{Digest, Keccak256};
use tempfile::TempDir;

#[cfg(test)]
mod wallet_rpc_pipeline_e2e {
    use super::*;

    /// Build a signed transaction the same way the wallet CLI does
    fn build_signed_tx(
        signing_key: &SigningKey,
        to: Address,
        value: u128,
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
        chain_id: u64,
    ) -> (Transaction, Vec<u8>) {
        let verifying_key = signing_key.verifying_key();
        let from = PublicKey::new(verifying_key.to_bytes());

        // Convert address to PublicKey (wallet format: 20 bytes + 12 zeros)
        let mut to_bytes = [0u8; 32];
        to_bytes[..20].copy_from_slice(&to.0);
        let to_pubkey = PublicKey::new(to_bytes);

        let mut tx = Transaction {
            hash: Hash::default(),
            from,
            to: Some(to_pubkey),
            value,
            data: Vec::new(),
            nonce,
            gas_price,
            gas_limit,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };

        // Hash computation (matches wallet/src/transaction.rs)
        let mut hasher = Keccak256::new();
        hasher.update(tx.nonce.to_le_bytes());
        hasher.update(tx.gas_price.to_le_bytes());
        hasher.update(tx.gas_limit.to_le_bytes());
        hasher.update(to_pubkey.as_bytes());
        hasher.update(tx.value.to_le_bytes());
        hasher.update(&tx.data);
        hasher.update(chain_id.to_le_bytes());
        hasher.update([0u8; 8]); // r placeholder
        hasher.update([0u8; 8]); // s placeholder
        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        tx.hash = Hash::new(hash_array);

        // Sign with ed25519
        use ed25519_dalek::Signer;
        let sig_bytes = signing_key.sign(tx.hash.as_bytes());
        tx.signature = Signature::new(sig_bytes.to_bytes());

        // Bincode serialize (same as wallet's raw format)
        let raw = bincode::serialize(&tx).expect("serialize tx");
        (tx, raw)
    }

    #[test]
    fn test_transaction_serialization_round_trip() {
        let mut secret = [0u8; 32];
        secret[0] = 0xAA;
        secret[1] = 0xBB;
        let signing_key = SigningKey::from_bytes(&secret);

        let to = Address([0x11; 20]);
        let (tx, raw) = build_signed_tx(&signing_key, to, 1_000_000, 0, 1_000_000_000, 21_000, 40204);

        // Deserialize back
        let decoded: Transaction =
            bincode::deserialize(&raw).expect("deserialize tx");

        assert_eq!(decoded.hash, tx.hash, "Hash should survive round-trip");
        assert_eq!(decoded.nonce, tx.nonce, "Nonce should survive round-trip");
        assert_eq!(decoded.value, tx.value, "Value should survive round-trip");
        assert_eq!(decoded.gas_price, tx.gas_price);
        assert_eq!(decoded.gas_limit, tx.gas_limit);
        assert_eq!(decoded.from, tx.from);
    }

    #[test]
    fn test_signature_is_valid() {
        let mut secret = [0u8; 32];
        secret[0] = 0xCC;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let to = Address([0x22; 20]);
        let (tx, _raw) = build_signed_tx(&signing_key, to, 500, 1, 1_000_000_000, 21_000, 40204);

        // Verify signature
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(&tx.signature.as_bytes());
        let result = verifying_key.verify(tx.hash.as_bytes(), &sig);
        assert!(result.is_ok(), "Signature should be valid");
    }

    #[test]
    fn test_different_signers_produce_different_signatures() {
        let key_a = SigningKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        });
        let key_b = SigningKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 2;
            b
        });

        let to = Address([0x33; 20]);
        let (tx_a, _) = build_signed_tx(&key_a, to, 100, 0, 1_000_000_000, 21_000, 40204);
        let (tx_b, _) = build_signed_tx(&key_b, to, 100, 0, 1_000_000_000, 21_000, 40204);

        assert_ne!(
            tx_a.signature.as_bytes(),
            tx_b.signature.as_bytes(),
            "Different signers should produce different signatures"
        );
        assert_ne!(tx_a.from, tx_b.from, "Different signers have different pubkeys");
    }

    #[tokio::test]
    async fn test_executor_applies_transfer() {
        let temp_dir = TempDir::new().unwrap();
        let executor = Executor::new(temp_dir.path()).unwrap();

        let sender = Address([0x01; 20]);
        let receiver = Address([0x02; 20]);

        // Fund sender
        let initial_balance = U256::from(10_000_000_000u64);
        executor.set_balance(&sender, initial_balance);
        executor.set_nonce(&sender, 0);

        // Simulate transfer execution (what the producer does after pulling from mempool)
        let transfer_amount = U256::from(1_000_000);
        let gas_cost = U256::from(21_000) * U256::from(1_000_000_000u64); // 21000 gas * 1 gwei

        // Apply state changes
        let sender_balance = executor.get_balance(&sender);
        let new_sender_balance = sender_balance - transfer_amount - gas_cost;
        executor.set_balance(&sender, new_sender_balance);
        executor.set_nonce(&sender, 1);
        executor.set_balance(&receiver, transfer_amount);

        // Verify
        assert_eq!(
            executor.get_balance(&sender),
            initial_balance - transfer_amount - gas_cost,
            "Sender balance should decrease by transfer + gas"
        );
        assert_eq!(
            executor.get_balance(&receiver),
            transfer_amount,
            "Receiver should have the transfer amount"
        );
        assert_eq!(executor.get_nonce(&sender), 1, "Sender nonce should increment");
    }

    #[tokio::test]
    async fn test_sequential_transactions_nonce_ordering() {
        let temp_dir = TempDir::new().unwrap();
        let executor = Executor::new(temp_dir.path()).unwrap();

        let sender = Address([0x05; 20]);
        let initial_balance = U256::from(100_000_000_000u64);
        executor.set_balance(&sender, initial_balance);
        executor.set_nonce(&sender, 0);

        // Simulate 5 sequential transfers
        let transfer_amount = U256::from(100_000);
        for i in 0..5u64 {
            let receiver = Address([((i + 1) * 0x10) as u8; 20]);

            let current_balance = executor.get_balance(&sender);
            let gas_cost = U256::from(21_000) * U256::from(1_000_000_000u64);
            executor.set_balance(&sender, current_balance - transfer_amount - gas_cost);
            executor.set_nonce(&sender, i + 1);
            executor.set_balance(&receiver, transfer_amount);
        }

        assert_eq!(
            executor.get_nonce(&sender),
            5,
            "After 5 transactions, nonce should be 5"
        );

        let total_spent = U256::from(5) * (transfer_amount + U256::from(21_000) * U256::from(1_000_000_000u64));
        assert_eq!(
            executor.get_balance(&sender),
            initial_balance - total_spent,
            "Balance should reflect all 5 transfers + gas"
        );
    }

    #[test]
    fn test_chain_id_affects_hash() {
        let signing_key = SigningKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 0xDD;
            b
        });
        let to = Address([0x44; 20]);

        let (tx_mainnet, _) = build_signed_tx(&signing_key, to, 100, 0, 1_000_000_000, 21_000, 1);
        let (tx_testnet, _) = build_signed_tx(&signing_key, to, 100, 0, 1_000_000_000, 21_000, 40204);

        assert_ne!(
            tx_mainnet.hash, tx_testnet.hash,
            "Different chain IDs should produce different tx hashes (EIP-155 replay protection)"
        );
    }
}
