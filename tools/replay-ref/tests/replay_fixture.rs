//! The harness on a small fixture: a node-like store built by applying a
//! chain of transfer blocks with the persisting executor, recorded from its
//! data dir read-only and replayed. An untouched recording replays with zero
//! divergence; a recording with one block's transaction changed, or one
//! committed root changed, is reported at exactly that height.

use std::sync::Arc;

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::types::{Address, ExecutionError, TransactionReceipt};
use citrate_execution::{Executor, StateDB};
use citrate_replay_ref::{
    record_data_dir, reference_reward_config, replay, Field, Recording, ReplayConfig, SelectedChain,
};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;

const CHAIN_ID: u64 = 40204;
const ALICE: [u8; 20] = [0xA1; 20];
const CB: [u8; 20] = [0xCB; 20];
const FUND: u128 = 1_000_000_000_000_000_000;
const N: u64 = 30;

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

fn transfer(to: [u8; 20], value: u128, nonce: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&nonce.to_be_bytes());
    h[8..28].copy_from_slice(&to);
    h[31] = 0x7F;
    Transaction {
        hash: Hash::new(h),
        nonce,
        from: embedded(ALICE),
        to: Some(embedded(to)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        signature: Signature::new([1; 64]),
        chain_id: Some(CHAIN_ID),
        ..Default::default()
    }
}

fn block(height: u64, parent: Hash, root: Hash, txs: Vec<Transaction>) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(height)
        .parent(parent)
        .coinbase(CB)
        .timestamp(1_000 + height)
        .vrf_reveal(VrfProof {
            proof: vec![],
            output: Hash::new([0x5A; 32]),
        })
        .transactions(txs)
        .state_root(root)
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

fn reward(b: &Block, r: &[TransactionReceipt]) -> Result<Vec<(Address, U256)>, ExecutionError> {
    let calc = citrate_economics::rewards::RewardCalculator::new(reference_reward_config());
    let rw = calc
        .calculate_block_reward(b, r, false)
        .map_err(|e| ExecutionError::RewardSettlement(e.to_string()))?;
    Ok(vec![
        (Address(b.header.coinbase), rw.validator_reward),
        (
            reference_reward_config().treasury_address,
            rw.treasury_reward,
        ),
    ])
}

fn config() -> ReplayConfig {
    let mut c = ReplayConfig::from_process(CHAIN_ID);
    c.pba_hardening_height = None;
    c.supply_hardening_height = None;
    let mut fund = [0u8; 32];
    U256::from(FUND).to_big_endian(&mut fund);
    c.genesis_alloc = vec![(ALICE, fund)];
    c
}

/// A data dir with genesis and `N` applied transfer blocks (plus one stored
/// side block that never became applied), as a node leaves it.
async fn node_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    {
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let exec = Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        );
        exec.set_balance(&Address(ALICE), U256::from(FUND));
        exec.persist_state_changes().await.expect("genesis state");
        let genesis = block(0, Hash::default(), exec.calculate_state_root(), vec![]);
        storage.blocks.put_block(&genesis).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&genesis.header.block_hash, 0)
            .expect("tip");
        // A mirror computes each block's root, as a producer does.
        let mirror = Executor::with_chain_id(Arc::new(StateDB::new()), CHAIN_ID);
        mirror.set_balance(&Address(ALICE), U256::from(FUND));
        let mut parent = genesis.header.block_hash;
        for h in 1..=N {
            let mut to = [0u8; 20];
            to[19] = h as u8;
            let txs = vec![transfer(to, 1_000 + u128::from(h), h - 1)];
            let tmpl = block(h, parent, Hash::default(), txs.clone());
            let root = match mirror
                .apply_block_no_persist_with_receipts(&tmpl, CB, &reward)
                .await
            {
                Err(ExecutionError::StateRootMismatch { got, .. }) => got,
                other => panic!("fixture: template apply {other:?}"),
            };
            let b = block(h, parent, root, txs);
            mirror
                .apply_block_no_persist_with_receipts(&b, CB, &reward)
                .await
                .expect("mirror applies");
            storage.blocks.put_block(&b).expect("put");
            let got = exec
                .apply_block(&b, CB, &reward)
                .await
                .expect("node applies");
            storage
                .state
                .put_state_root(&b.header.block_hash, &got)
                .expect("root");
            storage
                .blocks
                .put_applied_tip(&b.header.block_hash, h)
                .expect("tip");
            if h == 10 {
                let side = block(11, b.header.block_hash, Hash::new([0x5D; 32]), vec![]);
                storage.blocks.put_block(&side).expect("side");
            }
            parent = b.header.block_hash;
        }
    }
    dir
}

#[tokio::test]
async fn an_untouched_recording_replays_with_zero_divergence() {
    let dir = node_dir().await;
    let rec = record_data_dir(dir.path(), config()).expect("record");
    assert_eq!(rec.chain.len() as u64, N + 1, "genesis..=tip");
    assert_eq!(rec.blocks.len() as u64, N + 2, "chain + the side block");
    assert_eq!(rec.applied_tip.1, N);
    let report = replay(&rec, &SelectedChain).await.expect("replay");
    assert_eq!(report.divergence, None, "{report:?}");
    assert_eq!(report.matched, N);
    assert_eq!(report.committed_compared, N);
    // The file round trip keeps it replayable.
    let bytes = rec.to_bytes().expect("encode");
    let back = Recording::from_bytes(&bytes).expect("decode");
    let again = replay(&back, &SelectedChain).await.expect("replay");
    assert_eq!(again, report);
    println!(
        "replay fixture: {} blocks, {} bytes recorded",
        back.blocks.len(),
        bytes.len()
    );
}

#[tokio::test]
async fn a_changed_transaction_is_reported_at_its_height() {
    let dir = node_dir().await;
    let mut rec = record_data_dir(dir.path(), config()).expect("record");
    let k = 17;
    let b = rec.chain_block_mut(k).expect("block k");
    b.transactions[0].value += 1;
    let report = replay(&rec, &SelectedChain).await.expect("replay");
    let d = report.divergence.expect("a divergence");
    assert_eq!(d.height, k, "{d}");
    assert_eq!(d.field, Field::HeaderStateRoot, "{d}");
    assert_eq!(report.matched, k - 1);
}

#[tokio::test]
async fn a_wrong_committed_root_is_reported_at_its_height() {
    let dir = node_dir().await;
    let mut rec = record_data_dir(dir.path(), config()).expect("record");
    let k = 23;
    let entry = rec
        .chain
        .iter_mut()
        .find(|e| e.height == k)
        .expect("entry k");
    entry.committed_root = Some(Hash::new([0xEE; 32]));
    let report = replay(&rec, &SelectedChain).await.expect("replay");
    let d = report.divergence.expect("a divergence");
    assert_eq!(
        (d.height, d.field.clone()),
        (k, Field::CommittedStateRoot),
        "{d}"
    );
    assert_eq!(d.node, format!("0x{}", hex::encode([0xEE; 32])));
}

#[tokio::test]
async fn a_chain_that_misses_its_genesis_allocation_diverges_at_block_one() {
    let dir = node_dir().await;
    let mut cfg = config();
    cfg.genesis_alloc.clear();
    let rec = record_data_dir(dir.path(), cfg).expect("record");
    let report = replay(&rec, &SelectedChain).await.expect("replay");
    let d = report.divergence.expect("a divergence");
    assert_eq!(d.height, 1, "{d}");
}

#[test]
fn the_recorder_never_writes_the_data_dir() {
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let dir = rt.block_on(node_dir());
    let before: Vec<(String, u64)> = {
        let mut v: Vec<(String, u64)> = std::fs::read_dir(dir.path())
            .expect("ls")
            .map(|e| {
                let e = e.expect("entry");
                (
                    e.file_name().to_string_lossy().into_owned(),
                    e.metadata().expect("meta").len(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let _ = record_data_dir(dir.path(), config()).expect("record");
    let mut after: Vec<(String, u64)> = std::fs::read_dir(dir.path())
        .expect("ls")
        .map(|e| {
            let e = e.expect("entry");
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().expect("meta").len(),
            )
        })
        .collect();
    after.sort();
    assert_eq!(before, after, "the recorder changed the data dir");
}

/// The two CLIs end to end: `replay-record` on the data dir (with the
/// genesis allocation as a file), `replay-diff` on the recording (exit 0),
/// and on a copy with one block changed (exit 1, the height printed).
#[test]
fn the_clis_record_and_report_the_first_divergence() {
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let dir = rt.block_on(node_dir());
    let work = tempfile::tempdir().expect("work");
    let alloc = work.path().join("alloc.json");
    std::fs::write(
        &alloc,
        format!("{{\"0x{}\": \"{FUND}\"}}", hex::encode(ALICE)),
    )
    .expect("alloc");
    let rec_path = work.path().join("node.replay");
    let srh = citrate_execution::storage_root_hardening::storage_root_hardening_height();
    let mut record = std::process::Command::new(env!("CARGO_BIN_EXE_replay-record"));
    record
        .arg(dir.path())
        .arg(&rec_path)
        .arg("--genesis-alloc")
        .arg(&alloc);
    if let Some(h) = srh {
        record.arg("--storage-root-hardening").arg(h.to_string());
    }
    let out = record.output().expect("replay-record runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_replay-diff"))
        .arg(&rec_path)
        .output()
        .expect("replay-diff runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("{stdout}");
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("no divergence"), "{stdout}");

    let mut rec = Recording::read_from(&rec_path).expect("read");
    rec.chain_block_mut(17).expect("block 17").transactions[0].value += 1;
    let bad = work.path().join("bad.replay");
    rec.write_to(&bad).expect("write");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_replay-diff"))
        .arg(&bad)
        .output()
        .expect("replay-diff runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("{stdout}");
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("FIRST DIVERGENCE: height 17 "), "{stdout}");
}

/// CV-14 (b): the same fixture under the MPT state root (an r1007 genesis
/// rule). The node's roots are incremental; the replay recomputes every chain
/// block's root FROM SCRATCH and diffs it against the incremental root of the
/// same state and against the node's committed root. Untouched: zero
/// divergence, every block compared from scratch. A wrong committed root is
/// still reported at its height. The rule is process-wide, so this runs in a
/// child process (no other test in this binary sees it).
#[test]
fn mpt_state_root_replays_and_diffs_from_scratch_roots() {
    const CHILD: &str = "CITRATE_REPLAY_MPT_CHILD";
    const NAME: &str = "mpt_state_root_replays_and_diffs_from_scratch_roots";
    if std::env::var(CHILD).is_err() {
        let out = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("spawn child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let dir = rt.block_on(node_dir());
    let rec = record_data_dir(dir.path(), config()).expect("record");
    assert_eq!(rec.config.mpt_state_root_height, Some(0));
    let report = rt.block_on(replay(&rec, &SelectedChain)).expect("replay");
    assert_eq!(report.divergence, None, "{report:?}");
    assert_eq!(report.matched, N);
    assert_eq!(
        report.from_scratch_compared, N,
        "every block compared from scratch"
    );
    assert_eq!(report.committed_compared, N);

    // The node's committed roots are MPT roots (they differ from the legacy root
    // of the same state) and its store holds the trie nodes of the applied tip.
    {
        use citrate_execution::executor::StateStoreTrait;
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let root = storage
            .state
            .trie_root_at(N)
            .expect("record")
            .expect("tip root");
        assert_eq!(Some(root), rec.chain.last().and_then(|e| e.committed_root));
        let source = |h: &[u8; 32]| storage.state.get_trie_node(h).ok().flatten();
        let trie = citrate_execution::state::mpt::Mpt::load(root.as_bytes(), &source)
            .expect("the applied tip's trie loads from the node store");
        assert!(
            trie.len() >= 3,
            "alice, the coinbase, the treasury and the recipients"
        );
    }

    let mut bad = rec.clone();
    let k = 9;
    bad.chain
        .iter_mut()
        .find(|e| e.height == k)
        .expect("entry k")
        .committed_root = Some(Hash::new([0xEE; 32]));
    let report = rt.block_on(replay(&bad, &SelectedChain)).expect("replay");
    let d = report.divergence.expect("a divergence");
    assert_eq!(
        (d.height, d.field.clone()),
        (k, Field::CommittedStateRoot),
        "{d}"
    );
}
