// STOR-EAR: integration tests for encryption at rest through the full
// storage stack (StorageManager -> stores -> RocksDB access layer).
//
// Covers the acceptance criteria of the encryption-at-rest work package:
//   1. roundtrip across close/reopen (same key decrypts after restart)
//   2. wrong-key rejection at open (clean, explicit error)
//   3. iterator and batch paths produce/consume encrypted values
//   4. password salt persistence (same password re-derives across restarts)
//   5. plaintext-db-vs-encrypted-open mismatch errors (both directions)
//   6. on-disk bytes are actually ciphertext (verified by reading the
//      closed RocksDB directly with the raw rocksdb crate)
//   7. default (off) mode stores plaintext and writes no encryption.meta

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::types::{AccountState, Address};
use citrate_storage::crypto::at_rest::{
    AtRestError, EncryptionAtRestConfig, EncryptionKey, ENCRYPTION_META_FILE,
};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::{StorageConfig, StorageManager};
use primitive_types::U256;
use std::path::Path;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_KEY: [u8; 32] = [0xA5; 32];
const WRONG_KEY: [u8; 32] = [0x5A; 32];

fn encrypted_config() -> StorageConfig {
    StorageConfig::default().with_encryption(EncryptionAtRestConfig::with_raw_key(TEST_KEY))
}

fn open_encrypted(path: &Path) -> StorageManager {
    StorageManager::with_config(path, encrypted_config()).expect("encrypted open should succeed")
}

/// Open with the given config and expect failure, returning the error
/// (StorageManager has no Debug impl, so `expect_err` cannot be used).
fn open_must_fail(path: &Path, config: StorageConfig, why: &str) -> anyhow::Error {
    match StorageManager::with_config(path, config) {
        Ok(_) => panic!("open unexpectedly succeeded: {why}"),
        Err(e) => e,
    }
}

fn make_block(num: u8, height: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([num; 32]))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height * 10)
        .blue_work(height as u128 * 100)
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

fn make_tx(nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([nonce as u8; 32]),
        nonce,
        from: PublicKey::new([1; 32]),
        to: Some(PublicKey::new([2; 32])),
        value: 1000 + nonce as u128,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: b"sensitive calldata payload".to_vec(),
        signature: Signature::new([nonce as u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn make_account(nonce: u64, balance: u128) -> AccountState {
    AccountState {
        nonce,
        balance: U256::from(balance),
        storage_root: Hash::default(),
        code_hash: Hash::default(),
        model_permissions: vec![],
    }
}

/// Read raw stored bytes from a CLOSED database directory using the
/// rocksdb crate directly (read-only, bypassing the encryption layer).
fn raw_read(path: &Path, cf: &str, key: &[u8]) -> Option<Vec<u8>> {
    let cfs = ["default", cf];
    let db = rocksdb::DB::open_cf_for_read_only(&rocksdb::Options::default(), path, cfs, false)
        .expect("raw read-only open should succeed");
    let handle = db.cf_handle(cf).expect("cf handle should exist");
    db.get_cf(&handle, key).expect("raw get should succeed")
}

/// The at-rest envelope prefix: QSSP magic + version 2.
fn is_sealed(raw: &[u8]) -> bool {
    raw.len() >= 34 && &raw[0..4] == b"QSSP" && raw[4] == 2
}

// ---------------------------------------------------------------------------
// 1. Roundtrip across close/reopen + batch write paths
// ---------------------------------------------------------------------------

#[test]
fn encrypted_roundtrip_across_reopen() {
    let tmp = TempDir::new().expect("tempdir");
    let addr = Address([0xAA; 20]);

    // Write through the batch paths (put_block/put_transaction use
    // batch_put_cf + write_batch_sync) and the direct put path.
    {
        let mgr = open_encrypted(tmp.path());
        assert!(mgr.is_encryption_enabled());

        mgr.blocks
            .put_block(&make_block(1, 1, Hash::default()))
            .expect("put_block should succeed");
        mgr.transactions
            .put_transaction(&make_tx(7))
            .expect("put_transaction should succeed");
        mgr.state
            .put_account(&addr, &make_account(3, 12345))
            .expect("put_account should succeed");
        mgr.flush().expect("flush should succeed");

        let stats = mgr.get_encryption_stats().expect("stats should exist");
        assert!(stats.encryptions > 0, "writes must go through the cipher");
    }

    // encryption.meta must exist next to the RocksDB files.
    assert!(tmp.path().join(ENCRYPTION_META_FILE).exists());

    // Reopen with the same key: everything decrypts.
    {
        let mgr = open_encrypted(tmp.path());
        let block = mgr
            .blocks
            .get_block(&Hash::new([1; 32]))
            .expect("get_block should succeed")
            .expect("block should exist");
        assert_eq!(block.header.height, 1);

        let tx = mgr
            .transactions
            .get_transaction(&Hash::new([7; 32]))
            .expect("get_transaction should succeed")
            .expect("tx should exist");
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.data, b"sensitive calldata payload".to_vec());

        let account = mgr
            .state
            .get_account(&addr)
            .expect("get_account should succeed")
            .expect("account should exist");
        assert_eq!(account.nonce, 3);
        assert_eq!(account.balance, U256::from(12345u64));
    }
}

// ---------------------------------------------------------------------------
// 2. On-disk bytes are ciphertext (put + batch paths)
// ---------------------------------------------------------------------------

#[test]
fn on_disk_values_are_ciphertext() {
    let tmp = TempDir::new().expect("tempdir");
    let addr = Address([0xBB; 20]);
    let plaintext_account = bincode::serialize(&make_account(9, 777)).expect("serialize");

    {
        let mgr = open_encrypted(tmp.path());
        // Direct put path.
        mgr.state
            .put_account(&addr, &make_account(9, 777))
            .expect("put_account should succeed");
        // Batch path (block goes through batch_put_cf + write_batch_sync).
        mgr.blocks
            .put_block(&make_block(2, 5, Hash::default()))
            .expect("put_block should succeed");
        mgr.flush().expect("flush should succeed");
    }

    // Raw bytes for the account: sealed envelope, not the bincode plaintext.
    let raw_account = raw_read(tmp.path(), "accounts", &addr.0).expect("raw account bytes");
    assert!(is_sealed(&raw_account), "account value must carry the envelope prefix");
    assert_ne!(raw_account, plaintext_account);
    // Ciphertext must not embed the plaintext.
    assert!(!raw_account
        .windows(plaintext_account.len().min(16))
        .any(|w| w == &plaintext_account[..plaintext_account.len().min(16)]));

    // Raw bytes for the block written via the batch path: also sealed.
    let raw_block =
        raw_read(tmp.path(), "blocks", Hash::new([2; 32]).as_bytes()).expect("raw block bytes");
    assert!(is_sealed(&raw_block), "batch-written value must carry the envelope prefix");
}

// ---------------------------------------------------------------------------
// 3. Iterator paths decrypt
// ---------------------------------------------------------------------------

#[test]
fn iterators_decrypt_values() {
    let tmp = TempDir::new().expect("tempdir");
    let mgr = open_encrypted(tmp.path());

    for i in 1u8..=5 {
        mgr.state
            .put_account(&Address([i; 20]), &make_account(i as u64, 100 * i as u128))
            .expect("put_account should succeed");
    }

    // StateStore::get_all_accounts drives RocksDB::iter_cf over CF_ACCOUNTS;
    // values must come back as valid decrypted bincode.
    let accounts = mgr
        .state
        .get_all_accounts()
        .expect("get_all_accounts should succeed");
    assert_eq!(accounts.len(), 5);
    let total: u128 = accounts
        .iter()
        .map(|(_, a)| a.balance.as_u128())
        .sum();
    assert_eq!(total, 100 + 200 + 300 + 400 + 500);

    // Raw iter_cf on the wrapper also yields decrypted values.
    let mut n = 0;
    for (_key, value) in mgr.db.iter_cf("accounts").expect("iter_cf should succeed") {
        let account: AccountState =
            bincode::deserialize(&value).expect("iterated value must be decrypted bincode");
        assert!(account.nonce >= 1);
        n += 1;
    }
    assert_eq!(n, 5);

    // Prefix iterator path.
    let items: Vec<_> = mgr
        .db
        .prefix_iter_cf("accounts", &[3u8])
        .expect("prefix_iter_cf should succeed")
        .collect();
    assert!(!items.is_empty());
    for (_k, v) in items {
        bincode::deserialize::<AccountState>(&v).expect("prefix-iterated value must decrypt");
    }
}

// ---------------------------------------------------------------------------
// 4. Wrong key rejected at open (raw key + password paths)
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_rejected_at_open() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let mgr = open_encrypted(tmp.path());
        mgr.state
            .put_account(&Address([1; 20]), &make_account(1, 1))
            .expect("put_account should succeed");
    }

    let wrong = StorageConfig::default()
        .with_encryption(EncryptionAtRestConfig::with_raw_key(WRONG_KEY));
    let err = open_must_fail(tmp.path(), wrong, "wrong key must be rejected at open");
    let at_rest = err
        .downcast_ref::<AtRestError>()
        .expect("error should be an AtRestError");
    assert!(matches!(at_rest, AtRestError::WrongKey));
    assert!(err.to_string().contains("wipe the data directory"));
}

#[test]
fn password_salt_persists_and_wrong_password_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let config = || {
        StorageConfig::default()
            .with_encryption(EncryptionAtRestConfig::with_password("desktop-beta-passphrase"))
    };

    {
        let mgr = StorageManager::with_config(tmp.path(), config())
            .expect("password open should succeed");
        mgr.state
            .put_account(&Address([2; 20]), &make_account(4, 44))
            .expect("put_account should succeed");
    }

    // Same password reopens: the Argon2id salt persisted in encryption.meta
    // re-derives the same key.
    {
        let mgr = StorageManager::with_config(tmp.path(), config())
            .expect("password reopen should succeed");
        let account = mgr
            .state
            .get_account(&Address([2; 20]))
            .expect("get_account should succeed")
            .expect("account should exist");
        assert_eq!(account.balance, U256::from(44u64));
    }

    // Wrong password → WrongKey at open.
    let wrong = StorageConfig::default()
        .with_encryption(EncryptionAtRestConfig::with_password("not-the-passphrase"));
    let err = open_must_fail(tmp.path(), wrong, "wrong password must be rejected");
    assert!(matches!(
        err.downcast_ref::<AtRestError>(),
        Some(AtRestError::WrongKey)
    ));
}

// ---------------------------------------------------------------------------
// 5. Plaintext/encrypted mismatch errors (both directions, no migration)
// ---------------------------------------------------------------------------

#[test]
fn plaintext_db_opened_with_encryption_fails() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let mgr = StorageManager::new(tmp.path(), PruningConfig::default())
            .expect("plaintext open should succeed");
        mgr.state
            .put_account(&Address([3; 20]), &make_account(1, 1))
            .expect("put_account should succeed");
    }

    let err = open_must_fail(
        tmp.path(),
        encrypted_config(),
        "plaintext db must not open with encryption enabled",
    );
    let at_rest = err
        .downcast_ref::<AtRestError>()
        .expect("error should be an AtRestError");
    assert!(matches!(
        at_rest,
        AtRestError::PlaintextDbWithEncryptionEnabled(_)
    ));
    assert!(err.to_string().contains("wipe the data directory"));
}

#[test]
fn encrypted_db_opened_without_encryption_fails() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let mgr = open_encrypted(tmp.path());
        mgr.state
            .put_account(&Address([4; 20]), &make_account(1, 1))
            .expect("put_account should succeed");
    }

    let err = open_must_fail(
        tmp.path(),
        StorageConfig::default(),
        "encrypted db must not open without encryption",
    );
    let at_rest = err
        .downcast_ref::<AtRestError>()
        .expect("error should be an AtRestError");
    assert!(matches!(
        at_rest,
        AtRestError::EncryptedDbWithoutEncryption(_)
    ));
}

#[test]
fn encrypted_db_with_deleted_meta_detected_by_probe() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let mgr = open_encrypted(tmp.path());
        mgr.blocks
            .put_block(&make_block(3, 3, Hash::default()))
            .expect("put_block should succeed");
        mgr.transactions
            .put_transaction(&make_tx(3))
            .expect("put_transaction should succeed");
        mgr.flush().expect("flush should succeed");
    }

    // Simulate out-of-band loss of the marker file.
    std::fs::remove_file(tmp.path().join(ENCRYPTION_META_FILE)).expect("remove meta");

    let err = open_must_fail(
        tmp.path(),
        StorageConfig::default(),
        "probe must detect sealed values without meta",
    );
    assert!(matches!(
        err.downcast_ref::<AtRestError>(),
        Some(AtRestError::EncryptedValuesWithoutMeta(_))
    ));
}

// ---------------------------------------------------------------------------
// 6. Default (off) mode unchanged
// ---------------------------------------------------------------------------

#[test]
fn default_mode_stores_plaintext_and_no_meta() {
    let tmp = TempDir::new().expect("tempdir");
    let addr = Address([0xCC; 20]);
    let plaintext = bincode::serialize(&make_account(8, 888)).expect("serialize");

    {
        let mgr = StorageManager::new(tmp.path(), PruningConfig::default())
            .expect("plaintext open should succeed");
        assert!(!mgr.is_encryption_enabled());
        assert!(mgr.get_encryption_stats().is_none());
        mgr.state
            .put_account(&addr, &make_account(8, 888))
            .expect("put_account should succeed");
        mgr.flush().expect("flush should succeed");
    }

    assert!(!tmp.path().join(ENCRYPTION_META_FILE).exists());
    let raw = raw_read(tmp.path(), "accounts", &addr.0).expect("raw bytes");
    assert_eq!(raw, plaintext, "default mode must store raw plaintext");
}

// ---------------------------------------------------------------------------
// 7. EncryptionKey convenience surface used by the GUI
// ---------------------------------------------------------------------------

#[test]
fn generated_key_roundtrips_via_with_key() {
    let tmp = TempDir::new().expect("tempdir");
    let key = EncryptionKey::generate();

    {
        let config =
            StorageConfig::default().with_encryption(EncryptionAtRestConfig::with_key(key.clone()));
        let mgr = StorageManager::with_config(tmp.path(), config).expect("open should succeed");
        mgr.state
            .put_account(&Address([5; 20]), &make_account(6, 66))
            .expect("put_account should succeed");
    }

    let config = StorageConfig::default().with_encryption(EncryptionAtRestConfig::with_key(key));
    let mgr = StorageManager::with_config(tmp.path(), config).expect("reopen should succeed");
    let account = mgr
        .state
        .get_account(&Address([5; 20]))
        .expect("get_account should succeed")
        .expect("account should exist");
    assert_eq!(account.balance, U256::from(66u64));
}

// ---------------------------------------------------------------------------
// 8. Manual benchmark: encrypted-mode overhead (run with --ignored)
// ---------------------------------------------------------------------------

/// Not a pass/fail benchmark — prints raw-vs-encrypted put/get throughput
/// for the overhead report. Run:
/// `cargo test -p citrate-storage --test encryption_at_rest --release -- --ignored --nocapture`
#[test]
#[ignore = "manual benchmark; run with --ignored --nocapture in release mode"]
fn bench_encrypted_vs_raw_overhead() {
    use std::time::Instant;

    const N: usize = 20_000;
    const VALUE_SIZE: usize = 256;

    let run = |mgr: &StorageManager, label: &str| {
        let value = vec![0xABu8; VALUE_SIZE];

        let start = Instant::now();
        for i in 0..N {
            let key = (i as u64).to_be_bytes();
            mgr.db
                .put_cf("state", &key, &value)
                .expect("put should succeed");
        }
        let put_elapsed = start.elapsed();

        let start = Instant::now();
        for i in 0..N {
            let key = (i as u64).to_be_bytes();
            let v = mgr
                .db
                .get_cf("state", &key)
                .expect("get should succeed")
                .expect("value should exist");
            assert_eq!(v.len(), VALUE_SIZE);
        }
        let get_elapsed = start.elapsed();

        let start = Instant::now();
        let mut count = 0usize;
        for _ in mgr.db.iter_cf("state").expect("iter should succeed") {
            count += 1;
        }
        let iter_elapsed = start.elapsed();
        assert!(count >= N);

        println!(
            "{label}: put {N} x {VALUE_SIZE}B in {put_elapsed:?} ({:.0} ops/s), \
             get in {get_elapsed:?} ({:.0} ops/s), full-iter in {iter_elapsed:?}",
            N as f64 / put_elapsed.as_secs_f64(),
            N as f64 / get_elapsed.as_secs_f64(),
        );
        (
            put_elapsed.as_secs_f64(),
            get_elapsed.as_secs_f64(),
            iter_elapsed.as_secs_f64(),
        )
    };

    let raw_dir = TempDir::new().expect("tempdir");
    let raw_mgr =
        StorageManager::new(raw_dir.path(), PruningConfig::default()).expect("raw open");
    let (raw_put, raw_get, raw_iter) = run(&raw_mgr, "raw      ");

    let enc_dir = TempDir::new().expect("tempdir");
    let enc_mgr = open_encrypted(enc_dir.path());
    let (enc_put, enc_get, enc_iter) = run(&enc_mgr, "encrypted");

    println!(
        "overhead: put {:+.1}%, get {:+.1}%, iter {:+.1}%",
        (enc_put / raw_put - 1.0) * 100.0,
        (enc_get / raw_get - 1.0) * 100.0,
        (enc_iter / raw_iter - 1.0) * 100.0,
    );
}
