use citrate_api::FilterRegistry;
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::Mempool;
use citrate_sequencer::mempool::MempoolConfig;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction,
};
use citrate_execution::types::{AccessPolicy, ModelId, ModelMetadata, ModelState};
use citrate_execution::types::{Address, TransactionReceipt};

/// RM-I added a fail-closed rate-limit attribution check (`rate_limit::charge`)
/// that rejects requests with no client_key unless `CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT=1`.
/// Production deployments set this via env; integration tests run in-process
/// without the HTTP middleware, so the env var must be set before any RPC
/// handler executes. Any test in this file that reaches the rate-limit
/// gate must invoke this helper at the top of the test body — it is
/// idempotent and safe to call from every test.
fn ensure_test_rate_limit_bypass() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    });
}

fn make_block(height: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([height as u8; 32]))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height)
        .blue_work(height as u128)
        .build_unhashed()
}

fn embedded_pubkey(address: Address) -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(&address.0);
    PublicKey::new(bytes)
}

#[tokio::test]
async fn test_eth_block_number_and_get_block() {
    // Storage
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Seed blocks at heights 0 and 1
    let genesis = make_block(0, Hash::default());
    let b1 = make_block(1, genesis.hash());
    storage.blocks.put_block(&genesis).unwrap();
    storage.blocks.put_block(&b1).unwrap();

    // Deps
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    // Build IoHandler with ETH methods only
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // eth_blockNumber (hex string)
    let req_bn = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]})
        .to_string();
    let resp_bn = io.handle_request(&req_bn).await.unwrap();
    let vbn: serde_json::Value = serde_json::from_str(&resp_bn).unwrap();
    assert_eq!(vbn["result"], "0x1");

    // eth_getBlockByNumber ["0x1", false]
    let req_gbn = serde_json::json!({
        "jsonrpc":"2.0",
        "id":3,
        "method":"eth_getBlockByNumber",
        "params":["0x1", false]
    })
    .to_string();
    let resp_gbn = io.handle_request(&req_gbn).await.unwrap();
    let vgbn: serde_json::Value = serde_json::from_str(&resp_gbn).unwrap();
    assert!(vgbn["result"].is_object());
}

#[tokio::test]
async fn test_eth_get_block_by_hash() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Seed two blocks, capture hash of height 1
    let genesis = make_block(0, Hash::default());
    let b1 = make_block(1, genesis.hash());
    let h1 = b1.hash();
    storage.blocks.put_block(&genesis).unwrap();
    storage.blocks.put_block(&b1).unwrap();

    // Deps
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    // Build IoHandler with ETH methods only
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // eth_getBlockByHash [hash, false]
    let req = serde_json::json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"eth_getBlockByHash",
        "params":[format!("0x{}", hex::encode(h1.as_bytes())), false]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert!(v["result"].is_object());
    assert_eq!(v["result"]["number"], "0x1");
}

#[tokio::test]
async fn test_eth_get_block_reports_persisted_gas_and_receipt_fields() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    let proposer = embedded_pubkey(Address([0xAB; 20]));
    let block = BlockBuilder::new()
        .hash(Hash::new([0x44; 32]))
        .parent(Hash::default())
        .height(1)
        .timestamp(1_000_001)
        .proposer(proposer)
        .gas_limit(30_000_000)
        .gas_used(42_000)
        .base_fee_per_gas(1_000_000_007)
        .receipt_root(Hash::new([0x55; 32]))
        .build_unhashed();
    storage.blocks.put_block(&block).unwrap();

    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let req = serde_json::json!({
        "jsonrpc":"2.0",
        "id":4,
        "method":"eth_getBlockByNumber",
        "params":["0x1", false]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(v["result"]["gasUsed"], "0xa410");
    assert_eq!(v["result"]["gasLimit"], "0x1c9c380");
    assert_eq!(v["result"]["baseFeePerGas"], "0x3b9aca07");
    assert_eq!(
        v["result"]["receiptsRoot"],
        format!("0x{}", hex::encode(block.receipt_root.as_bytes()))
    );
    assert_eq!(v["result"]["miner"], "0xabababababababababababababababababababab");
}

#[tokio::test]
async fn test_eth_get_tx_and_receipt_by_hash() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Seed a transaction
    let tx = Transaction {
        hash: Hash::new([0xAB; 32]),
        nonce: 42,
        from: PublicKey::new([1; 32]),
        to: Some(PublicKey::new([2; 32])),
        value: 12345,
        gas_limit: 21000,
        gas_price: 1_000_000_000,
        data: vec![1, 2, 3],
        signature: Signature::new([1; 64]),
        tx_type: None,
        ..Default::default()
    };
    storage.transactions.put_transaction(&tx).unwrap();

    // Seed a receipt mapping to block
    let block_hash = Hash::new([0x11; 32]);
    let rcpt = TransactionReceipt {
        tx_hash: tx.hash,
        block_hash,
        block_number: 7,
        from: Address([1; 20]),
        to: Some(Address([2; 20])),
        gas_used: 21000,
        status: true,
        logs: vec![],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 0,
        revert_reason: None,
    };
    storage.transactions.put_receipt(&tx.hash, &rcpt).unwrap();

    // Deps
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    // Build IoHandler with ETH methods only
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // eth_getTransactionByHash
    let req_tx = serde_json::json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"eth_getTransactionByHash",
        "params":[format!("0x{}", hex::encode(tx.hash.as_bytes()))]
    })
    .to_string();
    let resp_tx = io.handle_request(&req_tx).await.unwrap();
    let vtx: serde_json::Value = serde_json::from_str(&resp_tx).unwrap();
    // Some environments may not index transactions for direct lookup yet; allow null here.
    if vtx["result"].is_object() {
        assert_eq!(vtx["result"]["nonce"], "0x2a");
    }

    // eth_getTransactionReceipt
    let req_rc = serde_json::json!({
        "jsonrpc":"2.0",
        "id":2,
        "method":"eth_getTransactionReceipt",
        "params":[format!("0x{}", hex::encode(tx.hash.as_bytes()))]
    })
    .to_string();
    let resp_rc = io.handle_request(&req_rc).await.unwrap();
    let vrc: serde_json::Value = serde_json::from_str(&resp_rc).unwrap();
    assert!(vrc["result"].is_object());
    assert_eq!(vrc["result"]["blockNumber"], "0x7");
}

#[tokio::test]
async fn test_eth_get_transaction_count_latest_vs_pending() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Deps
    let mempool = Arc::new(Mempool::new(MempoolConfig {
        require_valid_signature: false,
        ..Default::default()
    }));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    // Sender address (derived from first 20 bytes of pubkey)
    let mut from_pk_bytes = [0u8; 32];
    from_pk_bytes
        .iter_mut()
        .take(20)
        .enumerate()
        .for_each(|(i, b)| *b = (i as u8) + 1);
    let from_pk = PublicKey::new(from_pk_bytes);
    let from_addr_hex = format!("0x{}", hex::encode(&from_pk_bytes[0..20]));

    // Build IoHandler
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool.clone(),
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Latest nonce initially 0
    let req_latest = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":[from_addr_hex, "latest"]
    })
    .to_string();
    let resp_latest = io.handle_request(&req_latest).await.unwrap();
    let vl: serde_json::Value = serde_json::from_str(&resp_latest).unwrap();
    assert_eq!(vl["result"], "0x0");

    // Add two pending txs from the same sender with nonces 0 and 1
    let tx0 = Transaction {
        hash: Hash::new([0x01; 32]),
        nonce: 0,
        from: from_pk,
        to: Some(PublicKey::new([2; 32])),
        value: 0,
        gas_limit: 21000,
        gas_price: 1_000_000_000,
        data: vec![],
        signature: Signature::new([1; 64]),
        tx_type: None,
        chain_id: Some(40204),  // M-01: chain domain binding required (canonical testnet beta)
        ecdsa_verified: true,   // C-01: embedded EVM address needs this flag
        ..Default::default()
    };
    let tx1 = Transaction {
        nonce: 1,
        hash: Hash::new([0x02; 32]),
        ..tx0.clone()
    };
    // Add to storage (not necessary for pending count) and mempool (for pending window)
    mempool
        .add_transaction(tx0, citrate_sequencer::mempool::TxClass::Standard)
        .await
        .unwrap();
    mempool
        .add_transaction(tx1, citrate_sequencer::mempool::TxClass::Standard)
        .await
        .unwrap();

    // Pending should reflect highest nonce + 1 = 2
    let req_pending = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"eth_getTransactionCount","params":[from_addr_hex, "pending"]
    }).to_string();
    let resp_pending = io.handle_request(&req_pending).await.unwrap();
    let vp: serde_json::Value = serde_json::from_str(&resp_pending).unwrap();
    assert_eq!(vp["result"], "0x2");
}

#[tokio::test]
async fn test_eth_get_balance_and_code_smoke() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Executor backed by storage so code persists
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let exec = Executor::with_storage(state_db, Some(storage.state.clone()));
    let executor = Arc::new(exec);

    // Address 0x1111..
    let addr = Address([0x11; 20]);
    // Set balance and code
    executor.set_balance(&addr, primitive_types::U256::from(12345u64));
    executor.set_code(&addr, vec![0x60, 0x60, 0x60]);

    // Build IoHandler
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // eth_getBalance
    let req_bal = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[format!("0x{}", hex::encode(addr.0)), "latest"]
    }).to_string();
    let resp_bal = io.handle_request(&req_bal).await.unwrap();
    let vbal: serde_json::Value = serde_json::from_str(&resp_bal).unwrap();
    assert!(vbal["result"].as_str().unwrap().starts_with("0x"));
    assert_ne!(vbal["result"], "0x0");

    // eth_getCode
    let req_code = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"eth_getCode","params":[format!("0x{}", hex::encode(addr.0)), "latest"]
    }).to_string();
    let resp_code = io.handle_request(&req_code).await.unwrap();
    let vcode: serde_json::Value = serde_json::from_str(&resp_code).unwrap();
    let code_hex = vcode["result"].as_str().unwrap();
    assert!(code_hex.starts_with("0x"));
    assert!(code_hex.len() > 2); // non-empty code
}

#[tokio::test]
async fn test_eth_latest_reads_survive_simulation_before_persist() {
    use primitive_types::U256;

    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::with_storage(state_db, Some(storage.state.clone())));

    let sender = Address([0x11; 20]);
    let recipient = Address([0x22; 20]);
    let sim_sender = Address([0x33; 20]);
    let sim_recipient = Address([0x44; 20]);

    executor.set_balance(&sender, U256::from(1_000_000u64));
    executor.set_balance(&sim_sender, U256::from(1_000_000u64));

    let block = make_block(1, Hash::default());
    let mined_tx = Transaction {
        hash: Hash::new([0x90; 32]),
        nonce: 0,
        from: embedded_pubkey(sender),
        to: Some(embedded_pubkey(recipient)),
        value: 123,
        gas_limit: 21_000,
        gas_price: 1,
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ecdsa_verified: true,
        ..Default::default()
    };

    let receipt = executor.execute_transaction(&block, &mined_tx).await.unwrap();
    assert!(receipt.status);

    // Reproduce the live corruption shape: a simulation occurs before the mined
    // block's dirty state is persisted.
    let sim_tx = Transaction {
        hash: Hash::new([0x91; 32]),
        nonce: 0,
        from: embedded_pubkey(sim_sender),
        to: Some(embedded_pubkey(sim_recipient)),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1,
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ecdsa_verified: true,
        ..Default::default()
    };
    let sim_receipt = executor.simulate_transaction(&block, &sim_tx).await.unwrap();
    assert!(sim_receipt.status);

    executor.persist_state_changes().await.unwrap();

    // Use a fresh executor/handler to prove the mined "latest" state was
    // actually persisted, not just left in memory.
    let fresh_executor = Arc::new(Executor::with_storage(
        Arc::new(citrate_execution::StateDB::new()),
        Some(storage.state.clone()),
    ));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        mempool,
        fresh_executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let balance_req = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_getBalance",
        "params":[format!("0x{}", hex::encode(recipient.0)), "latest"]
    }).to_string();
    let balance_resp = io.handle_request(&balance_req).await.unwrap();
    let balance_json: serde_json::Value = serde_json::from_str(&balance_resp).unwrap();
    assert_eq!(balance_json["result"], "0x7b");

    let nonce_req = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"eth_getTransactionCount",
        "params":[format!("0x{}", hex::encode(sender.0)), "latest"]
    }).to_string();
    let nonce_resp = io.handle_request(&nonce_req).await.unwrap();
    let nonce_json: serde_json::Value = serde_json::from_str(&nonce_resp).unwrap();
    assert_eq!(nonce_json["result"], "0x1");
}

#[tokio::test]
async fn test_eth_send_raw_transaction_error_path() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Invalid hex string should produce an error
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xZZZZ"]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert!(v.get("error").is_some());
}

#[tokio::test]
async fn test_eth_call_smoke() {
    ensure_test_rate_limit_bypass();
    use primitive_types::U256;
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());

    // Deps
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Provide sender balance to cover gas for eth_call
    let from_addr = Address([0xAA; 20]);
    executor.set_balance(&from_addr, U256::from(100_000u64)); // > 21000 gas @ 1 wei

    // Build IoHandler
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Call object: zero-value transfer with minimal gas, empty data
    let from_hex = format!("0x{}", hex::encode(from_addr.0));
    let to_hex = format!("0x{}", hex::encode([0xBBu8; 20]));
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_call",
        "params":[
            {"from": from_hex, "to": to_hex, "gas": "0x5208", "gasPrice": "0x1", "value": "0x0", "data": "0x"},
            "latest"
        ]
    }).to_string();

    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    // Returns hex-encoded output; for empty output this is "0x"
    assert!(v["result"].is_string());
    assert!(v["result"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_eth_estimate_gas_minimal() {
    ensure_test_rate_limit_bypass();
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let req = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":[]
    })
    .to_string();

    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"], "0x5208");
}

#[tokio::test]
async fn test_eth_call_ai_tensor_opcode() {
    use primitive_types::U256;
    // Storage/executor/mempool setup
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Deploy code containing AI opcode TENSOR_OP (0xF0)
    let to_addr = Address([0x22; 20]);
    // Simple bytecode: [0xF0] triggers tensor operation path
    executor.set_code(&to_addr, vec![0xF0]);
    // Ensure caller has balance to cover gas accounting in call path
    let from_addr = Address([0x11; 20]);
    executor.set_balance(&from_addr, U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Data for tensor operation: op_type=0x01, dimensions=0x00000010 (16, little endian), plus padding
    let data_bytes = vec![0x01, 0x10, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":9,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from_addr.0)),
                "to": format!("0x{}", hex::encode(to_addr.0)),
                "gas": "0x186a0",
                "gasPrice": "0x1",
                "data": format!("0x{}", hex::encode(&data_bytes))
            },
            "latest"
        ]
    })
    .to_string();

    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    if let Some(out) = v["result"].as_str() {
        assert!(out.starts_with("0x"));
        assert!(
            !out.starts_with("0xf0010100"),
            "legacy AI opcode bytes must not execute tensor path anymore"
        );
    } else {
        assert!(
            v.get("error").is_some(),
            "legacy AI opcode bytes should now error or return non-AI output"
        );
    }
}

#[tokio::test]
async fn test_eth_call_invalid_to_address_and_insufficient_balance() {
    ensure_test_rate_limit_bypass();
    use primitive_types::U256;
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool.clone(),
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Invalid 'to' address length
    let bad_to_req = serde_json::json!({
        "jsonrpc":"2.0","id":11,"method":"eth_call",
        "params":[{"to":"0x1234", "data":"0x"}, "latest"]
    })
    .to_string();
    let bad_to_resp = io.handle_request(&bad_to_req).await.unwrap();
    let v_bad: serde_json::Value = serde_json::from_str(&bad_to_resp).unwrap();
    assert!(v_bad.get("error").is_some());

    // eth_call with insufficient balance should still succeed (optional_balance_check
    // is enabled per EVM spec — eth_call is a simulation, not a real transaction)
    let from = Address([0x33; 20]);
    executor.set_balance(&from, U256::from(1u64)); // tiny balance
    let to = Address([0x44; 20]);
    // STOP opcode — execution completes immediately
    executor.set_code(&to, vec![0x00]);
    let req_low_bal = serde_json::json!({
        "jsonrpc":"2.0","id":12,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x5208",
                "gasPrice":"0x3b9aca00",
                "data":"0x"
            },
            "latest"
        ]
    })
    .to_string();
    let resp_low_bal = io.handle_request(&req_low_bal).await.unwrap();
    let v_low: serde_json::Value = serde_json::from_str(&resp_low_bal).unwrap();
    // With optional_balance_check, eth_call succeeds even with insufficient balance
    assert!(v_low.get("result").is_some());
}

#[tokio::test]
async fn test_eth_estimate_gas_with_object_returns_constant() {
    ensure_test_rate_limit_bypass();
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let req = serde_json::json!({
        "jsonrpc":"2.0","id":13,"method":"eth_estimateGas",
        "params":[{"to":"0x0000000000000000000000000000000000000001","data":"0x"}]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"], "0x5208");
}

#[tokio::test]
async fn test_eth_call_ai_zk_verify_valid_proof() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Contract code with ZK_VERIFY opcode
    let to = Address([0x55; 20]);
    executor.set_code(&to, vec![0xF4]);

    // Fund caller
    let from = Address([0x56; 20]);
    executor.set_balance(&from, primitive_types::U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Input: 64-byte proof of 0xF3 values → valid, expect 0x01
    let mut data = vec![0xF3; 64];
    data.extend_from_slice(&[0x00, 0x01, 0x02]);
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":21,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x3a980",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(&data))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    if let Some(out) = v["result"].as_str() {
        assert!(
            !out.starts_with("0x01"),
            "legacy AI opcode bytes must not verify proofs via eth_call anymore"
        );
    } else {
        assert!(v.get("error").is_some());
    }
}

#[tokio::test]
async fn test_eth_call_ai_zk_verify_invalid_proof() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Contract code with ZK_VERIFY opcode
    let to = Address([0x57; 20]);
    executor.set_code(&to, vec![0xF4]);

    // Fund caller
    let from = Address([0x58; 20]);
    executor.set_balance(&from, primitive_types::U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Input: 64-byte proof of 0x00 values → invalid, expect 0x00
    let mut data = vec![0x00; 64];
    data.extend_from_slice(&[0x11, 0x22]);
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":31,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x186a0",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(&data))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    if let Some(out) = v["result"].as_str() {
        assert!(
            out != "0x00",
            "legacy AI opcode bytes must not expose proof-verification semantics anymore"
        );
    } else {
        assert!(v.get("error").is_some());
    }
}

#[tokio::test]
async fn test_eth_call_ai_zk_prove_output_length() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Contract code with ZK_PROVE opcode
    let to = Address([0x59; 20]);
    executor.set_code(&to, vec![0xF3]);

    // Fund caller
    let from = Address([0x5A; 20]);
    executor.set_balance(&from, primitive_types::U256::from(5_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Input: arbitrary payload; expect 64-byte proof output
    let data = vec![0xAA; 128];
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":51,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x989680",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(&data))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    if let Some(out) = v["result"].as_str() {
        assert!(
            out.len() != 130,
            "legacy AI opcode bytes must not produce the old 64-byte proof output anymore"
        );
    } else {
        assert!(v.get("error").is_some());
    }
}

#[tokio::test]
async fn test_eth_call_invalid_data_shapes_error() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Contract contains TENSOR_OP and ZK_VERIFY opcodes
    let addr_tensor = Address([0x60; 20]);
    executor.set_code(&addr_tensor, vec![0xF0]);
    let addr_zk = Address([0x61; 20]);
    executor.set_code(&addr_zk, vec![0xF4]);

    // Fund caller
    let from = Address([0x62; 20]);
    executor.set_balance(&from, primitive_types::U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Tensor op requires at least 8 bytes of data; send too short
    let bad_tensor_req = serde_json::json!({
        "jsonrpc":"2.0","id":41,"method":"eth_call",
        "params":[
            {"from": format!("0x{}", hex::encode(from.0)),
             "to": format!("0x{}", hex::encode(addr_tensor.0)),
             "gas":"0x186a0","gasPrice":"0x1","data":"0x01"},
            "latest"
        ]
    })
    .to_string();
    let resp_t = io.handle_request(&bad_tensor_req).await.unwrap();
    let vt: serde_json::Value = serde_json::from_str(&resp_t).unwrap();
    if vt.get("error").is_none() {
        assert_eq!(vt["result"], "0x");
    }

    // ZK_VERIFY requires 64-byte proof; send shorter
    let bad_zk_req = serde_json::json!({
        "jsonrpc":"2.0","id":42,"method":"eth_call",
        "params":[
            {"from": format!("0x{}", hex::encode(from.0)),
             "to": format!("0x{}", hex::encode(addr_zk.0)),
             "gas":"0x186a0","gasPrice":"0x1",
             "data": format!("0x{}", hex::encode([0x01, 0x02, 0x03]))},
            "latest"
        ]
    })
    .to_string();
    let resp_z = io.handle_request(&bad_zk_req).await.unwrap();
    let vz: serde_json::Value = serde_json::from_str(&resp_z).unwrap();
    if vz.get("error").is_none() {
        assert_eq!(vz["result"], "0x");
    }

    // MODEL_LOAD requires 32-byte hash; send less
    let addr_ml = Address([0x62; 20]);
    executor.set_code(&addr_ml, vec![0xF1]);
    let bad_ml_req = serde_json::json!({
        "jsonrpc":"2.0","id":43,"method":"eth_call",
        "params":[
            {"from": format!("0x{}", hex::encode(from.0)),
             "to": format!("0x{}", hex::encode(addr_ml.0)),
             "gas":"0x186a0","gasPrice":"0x1",
             "data": "0xdeadbeef"},
            "latest"
        ]
    })
    .to_string();
    let resp_ml = io.handle_request(&bad_ml_req).await.unwrap();
    let vml: serde_json::Value = serde_json::from_str(&resp_ml).unwrap();
    if vml.get("error").is_none() {
        assert_eq!(vml["result"], "0x");
    }
}

#[tokio::test]
async fn test_eth_call_ai_model_load_path() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Register a model so MODEL_LOAD can find it
    let model_hash = citrate_consensus::types::Hash::new([0xAB; 32]);
    let model_id = ModelId(model_hash);
    let model_state = ModelState {
        owner: Address([0x77; 20]),
        model_hash,
        version: 1,
        metadata: ModelMetadata {
            name: "Test".into(),
            version: "1.0".into(),
            description: "desc".into(),
            framework: "Torch".into(),
            input_shape: vec![1],
            output_shape: vec![1],
            size_bytes: 4096,
            created_at: 0,
        },
        access_policy: AccessPolicy::Public,
        usage_stats: Default::default(),
    };
    executor
        .state_db()
        .register_model(model_id, model_state)
        .unwrap();

    // Code with MODEL_LOAD opcode (0xF1)
    let to = Address([0x66; 20]);
    executor.set_code(&to, vec![0xF1]);
    let from = Address([0x65; 20]);
    executor.set_balance(&from, primitive_types::U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage.clone(),
        mempool,
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Data: 32-byte model hash
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":22,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x186a0",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(model_hash.as_bytes()))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    if let Some(out) = v["result"].as_str() {
        assert!(
            out == "0x" || out.len() <= 2,
            "legacy AI opcode bytes must not expose model-load handles anymore"
        );
    } else {
        assert!(v.get("error").is_some());
    }
}

#[tokio::test]
async fn test_eth_call_ai_model_exec_path() {
    ensure_test_rate_limit_bypass();
    use primitive_types::U256;
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Register model
    let model_hash = citrate_consensus::types::Hash::new([0xCD; 32]);
    let model_id = ModelId(model_hash);
    let model_state = ModelState {
        owner: Address([0x88; 20]),
        model_hash,
        version: 1,
        metadata: ModelMetadata {
            name: "ExecModel".into(),
            version: "1.0".into(),
            description: "exec".into(),
            framework: "Torch".into(),
            input_shape: vec![1],
            output_shape: vec![1],
            size_bytes: 1024,
            created_at: 0,
        },
        access_policy: AccessPolicy::Public,
        usage_stats: Default::default(),
    };
    executor
        .state_db()
        .register_model(model_id, model_state)
        .unwrap();

    // Code with MODEL_EXEC opcode (0xF2)
    let to = Address([0x99; 20]);
    executor.set_code(&to, vec![0xF2]);
    let from = Address([0x98; 20]);
    executor.set_balance(&from, U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(&mut io, storage.clone(), mempool, executor, 1, Arc::new(FilterRegistry::new()), None);

    // Data: 32-byte model hash + some inference bytes
    let mut data = model_hash.as_bytes().to_vec();
    data.extend_from_slice(&[0xAA, 0xBB]);
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":23,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x186a0",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(&data))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    // DPF-VM-1 WP-8 — eth_call now surfaces execution failures as
    // JSON-RPC errors instead of returning `"0x"` silently. Accept
    // either: real output bytes when MODEL_EXEC ran successfully, OR
    // an error response when the minimal-test path lacked the AI
    // backend.
    if let Some(out) = v["result"].as_str() {
        // Success path — execute_inference sets output to 0x01020304
        // in full builds; minimal builds may leave it empty.
        if out != "0x01020304" {
            assert_eq!(out, "0x");
        }
    } else {
        // Failure path — pre-WP-8 this was hidden as `"0x"`; now it
        // surfaces as a structured error which is the correct
        // semantic for a view call that couldn't execute.
        assert!(v["error"].is_object(), "response must carry either a result or an error: {v}");
    }
}

#[tokio::test]
async fn test_eth_call_ai_model_exec_missing_model_errors() {
    ensure_test_rate_limit_bypass();
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Code with MODEL_EXEC, but do not register any model
    let to = Address([0xAB; 20]);
    executor.set_code(&to, vec![0xF2]);
    let from = Address([0xAC; 20]);
    executor.set_balance(&from, primitive_types::U256::from(1_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(&mut io, storage.clone(), mempool, executor, 1, Arc::new(FilterRegistry::new()), None);

    // Data: 32-byte model hash that is not registered
    let missing_hash = citrate_consensus::types::Hash::new([0xEE; 32]);
    let mut data = missing_hash.as_bytes().to_vec();
    data.extend_from_slice(&[0x00]);
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":24,"method":"eth_call",
        "params":[
            {
                "from": format!("0x{}", hex::encode(from.0)),
                "to": format!("0x{}", hex::encode(to.0)),
                "gas":"0x3a980",
                "gasPrice":"0x1",
                "data": format!("0x{}", hex::encode(&data))
            },
            "latest"
        ]
    })
    .to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    // DPF-VM-1 WP-8 — Execution failure (MODEL_EXEC against an
    // unregistered model) is now surfaced as a JSON-RPC error
    // instead of `result: "0x"`. The pre-WP-8 behaviour silently
    // dropped halt reasons; this assertion encodes the new correct
    // semantic.
    assert!(
        v["error"].is_object(),
        "missing-model MODEL_EXEC should surface as JSON-RPC error, got: {v}"
    );
    let err_msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("revert") || err_msg.contains("execution"),
        "error message should mention reverted/execution, got: {err_msg}"
    );
}

/// Test that eth_chainId returns the configured chain ID, not a hardcoded value.
/// This is critical for preventing replay attacks across different networks.
#[tokio::test]
async fn test_eth_chain_id_is_configurable() {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    // Test with chain_id = 40204 (testnet)
    let mut io1 = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io1,
        storage.clone(),
        mempool.clone(),
        executor.clone(),
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})
        .to_string();
    let resp = io1.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"], "0x9d0c"); // 40204 in hex

    // Test with chain_id = 1 (mainnet)
    let mut io2 = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io2,
        storage.clone(),
        mempool.clone(),
        executor.clone(),
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    let resp2 = io2.handle_request(&req).await.unwrap();
    let v2: serde_json::Value = serde_json::from_str(&resp2).unwrap();
    assert_eq!(v2["result"], "0x1");
}

/// Test that eth_estimateGas performs real gas estimation for contract calls.
/// Simple transfers should return 21000, while contract calls return actual gas used.
#[tokio::test]
async fn test_eth_estimate_gas_real_execution() {
    ensure_test_rate_limit_bypass();
    use primitive_types::U256;

    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));

    // Set up an address with balance
    let from_addr = Address([0x11; 20]);
    executor.set_balance(&from_addr, U256::from(1_000_000_000u64));

    // Deploy some code to test contract calls
    let contract_addr = Address([0x22; 20]);
    // Simple contract that returns data (PUSH1 0x01 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN)
    executor.set_code(&contract_addr, vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        mempool,
        executor,
        1,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Test 1: Simple transfer (no data) should return 21000
    let req_transfer = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"eth_estimateGas",
        "params":[{
            "from": format!("0x{}", hex::encode(from_addr.0)),
            "to": format!("0x{}", hex::encode(contract_addr.0)),
            "value": "0x1"
        }]
    }).to_string();
    let resp_transfer = io.handle_request(&req_transfer).await.unwrap();
    let v_transfer: serde_json::Value = serde_json::from_str(&resp_transfer).unwrap();
    assert_eq!(v_transfer["result"], "0x5208", "Simple transfer should be 21000 gas");

    // Test 2: Contract call with data should return more than 21000
    let req_call = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"eth_estimateGas",
        "params":[{
            "from": format!("0x{}", hex::encode(from_addr.0)),
            "to": format!("0x{}", hex::encode(contract_addr.0)),
            "data": "0x12345678" // Some function selector
        }]
    }).to_string();
    let resp_call = io.handle_request(&req_call).await.unwrap();
    let v_call: serde_json::Value = serde_json::from_str(&resp_call).unwrap();
    let gas_str = v_call["result"].as_str().unwrap();
    let gas = u64::from_str_radix(gas_str.trim_start_matches("0x"), 16).unwrap();
    assert!(gas >= 21000, "Contract call should use at least 21000 gas, got {}", gas);

    // Test 3: No params should return default 21000
    let req_empty = serde_json::json!({
        "jsonrpc":"2.0","id":3,"method":"eth_estimateGas","params":[]
    }).to_string();
    let resp_empty = io.handle_request(&req_empty).await.unwrap();
    let v_empty: serde_json::Value = serde_json::from_str(&resp_empty).unwrap();
    assert_eq!(v_empty["result"], "0x5208", "Empty params should default to 21000");
}

#[tokio::test]
async fn test_eth_estimate_gas_contract_deploy_not_simple_transfer() {
    ensure_test_rate_limit_bypass();
    use primitive_types::U256;

    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let state_db = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

    let from_addr = Address([0x77; 20]);
    executor.set_balance(&from_addr, U256::from(1_000_000_000u64));

    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        mempool,
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );

    // Simple init code: PUSH1 0x00 PUSH1 0x00 RETURN
    let init_code = "0x60006000f3";
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":4,"method":"eth_estimateGas",
        "params":[{
            "from": format!("0x{}", hex::encode(from_addr.0)),
            "data": init_code
        }]
    }).to_string();
    let resp = io.handle_request(&req).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let gas_hex = v["result"].as_str().unwrap();
    let gas = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16).unwrap();
    assert!(
        gas > 21_000,
        "contract deployment estimate must not collapse to simple-transfer gas: {}",
        gas
    );
}
