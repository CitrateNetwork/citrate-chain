//! zstd upgrade compatibility goldens (zstd 0.13 -> 0.14, zstd-sys 2.0 -> 2.1).
//!
//! The fixtures under `tests/fixtures/zstd_v013/` were produced by the
//! pre-upgrade build (main @ 253d3287: zstd 0.13.3, zstd-safe 7.2.4,
//! zstd-sys 2.0.16+zstd.1.5.7, rocksdb 0.22) with
//!
//! ```text
//! unshare --user --map-root-user --uts sh -c 'hostname fixture-host && \
//!   ZSTD_COMPAT_FIXTURE_OUT=<dir> cargo test -p citrate-storage --test zstd_compat \
//!     -- --ignored regenerate_zstd_v013_fixtures'
//! ```
//!
//! (RocksDB records the writer's hostname in SST table properties; the UTS
//! namespace keeps the build machine's name out of the committed files.)
//!
//! and are committed as-is. They pin three properties across the upgrade:
//!
//! 1. Frames written by the old build (both `zstd::encode_all`, used by the
//!    IPFS chunk store, and `zstd::bulk::compress`, used by the database value
//!    envelope) decode byte-identically under the new build.
//! 2. The new build's compressor output is byte-identical to the old one for
//!    the same inputs and level, so nothing derived from compressed bytes
//!    changes.
//! 3. A RocksDB directory written by the old build (zstd-compressed SSTs)
//!    opens through `StorageManager::new` and reads back the same blocks,
//!    accounts and raw values.
//!
//! Do not regenerate the fixtures from a post-upgrade build: that would turn
//! the goldens into a self-comparison.

use std::fs;
use std::path::{Path, PathBuf};

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::types::{AccountState, Address};
use citrate_storage::db::column_families::{all_column_families, CF_METADATA};
use citrate_storage::{pruning::PruningConfig, StorageManager};
use primitive_types::U256;

const LEVEL: i32 = 3;
const BLOCK_COUNT: u8 = 24;
const ACCOUNT_COUNT: u8 = 16;
const RAW_KV_COUNT: u32 = 64;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zstd_v013")
}

// ---------------------------------------------------------------------------
// Deterministic, real-shaped payloads (shared by the generator and the checks)
// ---------------------------------------------------------------------------

fn rich_block(n: u8) -> Block {
    let h = |tag: u8| {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1] = n;
        b[31] = n.wrapping_mul(7);
        Hash::new(b)
    };
    let txs: Vec<Transaction> = (0..(n % 5 + 1))
        .map(|i| Transaction {
            hash: h(0x40 + i),
            nonce: u64::from(i),
            from: PublicKey::new([n; 32]),
            to: Some(PublicKey::new([i; 32])),
            value: 1_000_000_000_000_000_000u128 * u128::from(i + 1),
            gas_limit: 21_000 + u64::from(i) * 1_000,
            gas_price: 1_000_000_000,
            data: (0..u16::from(i) * 37).map(|x| (x % 251) as u8).collect(),
            signature: Signature::new([n ^ i; 64]),
            eth_tx_type: 2,
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000),
            chain_id: Some(40204),
            ..Default::default()
        })
        .collect();
    BlockBuilder::new()
        .hash(h(0x01))
        .parent(h(0x02))
        .merge_parents(vec![h(0x03), h(0x04)])
        .height(u64::from(n))
        .timestamp(1_760_000_000 + u64::from(n) * 2)
        .blue_score(u64::from(n) * 10)
        .blue_work(u128::from(n) * 1000)
        .proposer(PublicKey::new([0xAB; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![n; 80],
            output: h(0x05),
        })
        .state_root(h(0x06))
        .tx_root(h(0x07))
        .receipt_root(h(0x08))
        .gas_used(21_000 * u64::from(n % 5 + 1))
        .gas_limit(30_000_000)
        .base_fee_per_gas(1_000_000_000)
        .transactions(txs)
        .signature(Signature::new([n; 64]))
        .build_unhashed()
}

fn account(n: u8) -> (Address, AccountState) {
    let mut addr = [0u8; 20];
    addr[0] = 0xAC;
    addr[19] = n;
    let mut code = [0u8; 32];
    code[0] = n;
    let state = AccountState {
        nonce: u64::from(n) * 3,
        balance: U256::from(10u64).pow(U256::from(18u64)) * U256::from(u64::from(n) + 1),
        code_hash: Hash::new(code),
        ..Default::default()
    };
    (Address(addr), state)
}

fn raw_kv(i: u32) -> (Vec<u8>, Vec<u8>) {
    let key = format!("zstd-compat/{i:04}").into_bytes();
    let value = format!("value {i} ")
        .repeat(1 + (i as usize % 40))
        .into_bytes();
    (key, value)
}

/// 1.5 MiB of real block encodings: spans many 128 KiB zstd blocks
/// (multi-block frames) while staying small as a fixture.
fn large_blocks() -> Vec<u8> {
    const LEN: usize = 3 * 512 * 1024;
    let mut out = Vec::with_capacity(LEN + 4096);
    let mut n: u8 = 0;
    while out.len() < LEN {
        out.extend(bincode::serialize(&rich_block(n)).expect("serialize block"));
        n = n.wrapping_add(1);
    }
    out.truncate(LEN);
    out
}

fn incompressible(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// (name, bytes). Every entry has `<name>.encode_all.zst` and `<name>.bulk.zst`
/// fixtures.
fn payloads() -> Vec<(&'static str, Vec<u8>)> {
    let block = bincode::serialize(&rich_block(7)).expect("serialize block");
    let blocks: Vec<u8> = (0..BLOCK_COUNT)
        .flat_map(|n| bincode::serialize(&rich_block(n)).expect("serialize block"))
        .collect();
    let accounts: Vec<u8> = (0..ACCOUNT_COUNT)
        .flat_map(|n| bincode::serialize(&account(n).1).expect("serialize account"))
        .collect();
    vec![
        ("empty", Vec::new()),
        ("one_byte", vec![0x02]),
        (
            "small_text",
            b"Hello, this is a test of zstd compression in Citrate storage!".to_vec(),
        ),
        ("block_bincode", block),
        ("blocks_batch_bincode", blocks),
        ("accounts_bincode", accounts),
        ("incompressible_16k", incompressible(16 * 1024)),
        ("large_blocks_1_5m", large_blocks()),
    ]
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst");
    for entry in fs::read_dir(src).expect("read src") {
        let entry = entry.expect("dir entry");
        fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy fixture file");
    }
}

// ---------------------------------------------------------------------------
// Checks against the committed pre-upgrade fixtures
// ---------------------------------------------------------------------------

#[test]
fn v013_frames_decode_byte_identical() {
    for (name, raw) in payloads() {
        let framed = read_fixture(&format!("{name}.encode_all.zst"));
        let decoded = zstd::decode_all(std::io::Cursor::new(&framed)).expect("decode_all");
        assert_eq!(decoded, raw, "{name}: encode_all frame decoded differently");

        let bulk = read_fixture(&format!("{name}.bulk.zst"));
        let decoded = zstd::stream::decode_all(bulk.as_slice()).expect("stream::decode_all");
        assert_eq!(decoded, raw, "{name}: bulk frame decoded differently");
        let decoded = zstd::bulk::decompress(&bulk, raw.len().max(1)).expect("bulk::decompress");
        assert_eq!(decoded, raw, "{name}: bulk::decompress differs");
    }
}

#[test]
fn compressor_output_byte_identical_to_v013() {
    for (name, raw) in payloads() {
        let framed = zstd::encode_all(std::io::Cursor::new(&raw), LEVEL).expect("encode_all");
        assert_eq!(
            framed,
            read_fixture(&format!("{name}.encode_all.zst")),
            "{name}: encode_all output changed across the upgrade"
        );
        let bulk = zstd::bulk::compress(&raw, LEVEL).expect("bulk::compress");
        assert_eq!(
            bulk,
            read_fixture(&format!("{name}.bulk.zst")),
            "{name}: bulk::compress output changed across the upgrade"
        );
    }
}

/// Negative control: the golden comparison must notice a changed frame.
#[test]
fn golden_check_detects_a_changed_frame() {
    let (name, raw) = ("blocks_batch_bincode", payloads().swap_remove(4).1);
    let mut framed = read_fixture(&format!("{name}.encode_all.zst"));
    let mid = framed.len() / 2;
    framed[mid] ^= 0x5A;
    // A format/checksum error is the expected outcome; if it does decode, it
    // must not reproduce the original bytes.
    if let Ok(decoded) = zstd::decode_all(std::io::Cursor::new(&framed)) {
        assert_ne!(decoded, raw, "corrupted frame decoded to the original");
    }
    let fresh = zstd::encode_all(std::io::Cursor::new(&raw), LEVEL).expect("encode_all");
    assert_ne!(
        fresh, framed,
        "byte comparison failed to see the flipped byte"
    );
}

#[test]
fn rocksdb_written_by_v013_build_opens_and_reads() {
    let src = fixture_dir().join("rocksdb");
    // Precondition: the fixture really exercises RocksDB's zstd path.
    let mut zstd_ssts = 0;
    for entry in fs::read_dir(&src).expect("rocksdb fixture dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "sst") {
            let bytes = fs::read(&path).expect("read sst");
            if bytes.windows(4).any(|w| w == b"ZSTD") {
                zstd_ssts += 1;
            }
        }
    }
    assert!(zstd_ssts > 0, "rocksdb fixture has no zstd-compressed SST");

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path().join("db");
    copy_dir(&src, &dir);

    let storage = StorageManager::new(&dir, PruningConfig::default()).expect("open v013 db");
    for n in 0..BLOCK_COUNT {
        let want = rich_block(n);
        let got = storage
            .blocks
            .get_block(&want.hash())
            .expect("get_block")
            .unwrap_or_else(|| panic!("block {n} missing"));
        assert_eq!(
            bincode::serialize(&got).expect("ser"),
            bincode::serialize(&want).expect("ser"),
            "block {n} differs"
        );
    }
    for n in 0..ACCOUNT_COUNT {
        let (addr, want) = account(n);
        let got = storage
            .state
            .get_account(&addr)
            .expect("get_account")
            .unwrap_or_else(|| panic!("account {n} missing"));
        assert_eq!(
            bincode::serialize(&got).expect("ser"),
            bincode::serialize(&want).expect("ser"),
            "account {n} differs"
        );
    }
    for i in 0..RAW_KV_COUNT {
        let (k, v) = raw_kv(i);
        assert_eq!(
            storage.db.get_cf(CF_METADATA, &k).expect("get_cf"),
            Some(v),
            "raw kv {i} differs"
        );
    }
}

// ---------------------------------------------------------------------------
// Generator (run only on the pre-upgrade build; see the module docs)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "fixture generator: run on the pre-upgrade build with ZSTD_COMPAT_FIXTURE_OUT set"]
fn regenerate_zstd_v013_fixtures() {
    let out = PathBuf::from(
        std::env::var("ZSTD_COMPAT_FIXTURE_OUT").expect("set ZSTD_COMPAT_FIXTURE_OUT"),
    );
    assert!(
        !out.starts_with(env!("CARGO_MANIFEST_DIR")),
        "write fixtures outside the source tree, then copy them in"
    );
    fs::create_dir_all(&out).expect("create out dir");

    for (name, raw) in payloads() {
        let framed = zstd::encode_all(std::io::Cursor::new(&raw), LEVEL).expect("encode_all");
        fs::write(out.join(format!("{name}.encode_all.zst")), framed).expect("write");
        let bulk = zstd::bulk::compress(&raw, LEVEL).expect("bulk::compress");
        fs::write(out.join(format!("{name}.bulk.zst")), bulk).expect("write");
    }

    // RocksDB: write through the production path, then reopen with zstd on
    // every column family so recovery and flush emit zstd-compressed SSTs.
    let db_dir = out.join("rocksdb");
    {
        let storage = StorageManager::new(&db_dir, PruningConfig::default()).expect("open");
        for n in 0..BLOCK_COUNT {
            storage.blocks.put_block(&rich_block(n)).expect("put_block");
        }
        for n in 0..ACCOUNT_COUNT {
            let (addr, state) = account(n);
            storage
                .state
                .put_account(&addr, &state)
                .expect("put_account");
        }
    }
    {
        let mut opts = rocksdb::Options::default();
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        let cfs: Vec<rocksdb::ColumnFamilyDescriptor> = all_column_families()
            .into_iter()
            .map(|name| {
                let mut cf = rocksdb::Options::default();
                cf.set_compression_type(rocksdb::DBCompressionType::Zstd);
                rocksdb::ColumnFamilyDescriptor::new(name, cf)
            })
            .collect();
        let db = rocksdb::DB::open_cf_descriptors(&opts, &db_dir, cfs).expect("reopen raw");
        let meta = db.cf_handle(CF_METADATA).expect("metadata cf");
        for i in 0..RAW_KV_COUNT {
            let (k, v) = raw_kv(i);
            db.put_cf(&meta, k, v).expect("put_cf");
        }
        for name in all_column_families() {
            let cf = db.cf_handle(name).expect("cf");
            db.flush_cf(&cf).expect("flush");
            db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
        }
    }
    // Drop runtime-only files: the WAL is empty after the flush, and only the
    // newest OPTIONS file is kept (RocksDB does not need OPTIONS to open).
    let mut options: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&db_dir).expect("read db dir") {
        let path = entry.expect("entry").path();
        let file = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        if file == "LOCK" || file.starts_with("LOG") || file.ends_with(".log") {
            fs::remove_file(&path).expect("remove runtime file");
        } else if file.starts_with("OPTIONS-") {
            options.push(path);
        }
    }
    options.sort();
    options.pop();
    for stale in options {
        fs::remove_file(&stale).expect("remove stale OPTIONS");
    }
}
