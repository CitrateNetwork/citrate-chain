// citrate/core/api/src/eth_rpc.rs

use crate::eth_tx_decoder;
use crate::filter::{FilterRegistry, FilterType};
use crate::methods::{mempool::PendingQuery, ChainApi, MempoolApi, StateApi};
// PIL-49: route block_on through a shared multi-threaded Tokio runtime so
// futures awaiting tokio::sync::* / tokio::time::* / reqwest can wake.
// `futures::executor::block_on` lacks a Tokio reactor, so any such future
// deadlocks — under chatbot load this stranded the RPC accept queue and
// rpc.citrate.ai went silent while the node was still producing blocks.
use crate::rpc_runtime::block_on;
use hex;
use jsonrpc_core::{IoHandler, Params, Value};
use citrate_consensus::types::{Hash, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::Address;
use citrate_sequencer::mempool::{Mempool, TxClass};
use citrate_storage::StorageManager;
use citrate_economics::{
    InstitutionalRewardConfig, InstitutionalRewardEstimator, EstimationParams,
    InstitutionalSlashingConfig, InstitutionalOperatorProfile,
};
use primitive_types::U256;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Build EIP-typed fields for a transaction JSON response.
/// Appends `type`, `chainId`, and optionally `accessList`, `maxFeePerGas`,
/// `maxPriorityFeePerGas` to the given serde_json::Map.
#[allow(clippy::type_complexity)]
fn append_eip_fields(
    map: &mut serde_json::Map<String, Value>,
    eth_tx_type: u8,
    chain_id: Option<u64>,
    max_fee_per_gas: Option<u64>,
    max_priority_fee_per_gas: Option<u64>,
    access_list: &Option<Vec<(Vec<u8>, Vec<Vec<u8>>)>>,
) {
    map.insert("type".into(), json!(format!("0x{:x}", eth_tx_type)));
    if let Some(cid) = chain_id {
        map.insert("chainId".into(), json!(format!("0x{:x}", cid)));
    }
    if eth_tx_type >= 1 {
        // Serialize access list as array of {address, storageKeys}
        let al_json: Vec<Value> = access_list
            .as_ref()
            .map(|al| {
                al.iter()
                    .map(|(addr, keys)| {
                        json!({
                            "address": format!("0x{}", hex::encode(addr)),
                            "storageKeys": keys.iter().map(|k| format!("0x{}", hex::encode(k))).collect::<Vec<_>>()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        map.insert("accessList".into(), json!(al_json));
    }
    if eth_tx_type == 2 {
        if let Some(mf) = max_fee_per_gas {
            map.insert("maxFeePerGas".into(), json!(format!("0x{:x}", mf)));
        }
        if let Some(mp) = max_priority_fee_per_gas {
            map.insert("maxPriorityFeePerGas".into(), json!(format!("0x{:x}", mp)));
        }
    }
}

/// Convert a 32-byte pubkey hex (64 chars) to a 20-byte EVM address (40 chars).
/// If the last 12 bytes are zeros (EVM-style embedded address), returns first 20 bytes.
/// Otherwise returns first 20 bytes as well (truncated pubkey-derived address).
fn pubkey_hex_to_evm_address(hex_str: &str) -> String {
    if hex_str.len() == 64 && hex_str[40..].chars().all(|c| c == '0') {
        // EVM address embedded in first 20 bytes
        format!("0x{}", &hex_str[..40])
    } else if hex_str.len() >= 40 {
        format!("0x{}", &hex_str[..40])
    } else {
        format!("0x{}", hex_str)
    }
}

/// Same as pubkey_hex_to_evm_address but returns None when input is None (for `to` field).
fn pubkey_hex_opt_to_evm_address(hex_opt: Option<&String>) -> Option<String> {
    hex_opt.map(|s| pubkey_hex_to_evm_address(s))
}

fn eth_block_json(block: &crate::types::response::BlockResponse, transactions: Vec<Value>) -> Value {
    // PIL-50: GHOSTDAG topology fields. The consensus header already
    // carries blue_score / blue_work / selected_parent_hash /
    // merge_parent_hashes, but the public RPC was stripping them down to
    // pure Ethereum-shape fields, which blocked the explorer + indexer
    // from rendering the DAG. Add them as additional camelCase fields
    // (Ethereum-spec callers ignore unknown fields, so this is
    // backwards-compatible). `selectedParentHash` is the same value as
    // `parentHash` — duplicated under both names so DAG-aware callers
    // don't have to special-case the Citrate spelling.
    let merge_parents_json: Vec<Value> = block
        .merge_parent_hashes
        .iter()
        .map(|h| Value::String(format!("0x{}", hex::encode(h.as_bytes()))))
        .collect();
    json!({
        "number": format!("0x{:x}", block.height),
        "hash": format!("0x{}", hex::encode(block.hash.as_bytes())),
        "parentHash": format!("0x{}", hex::encode(block.parent_hash.as_bytes())),
        "timestamp": format!("0x{:x}", block.timestamp),
        "gasLimit": format!("0x{:x}", block.gas_limit),
        "gasUsed": format!("0x{:x}", block.gas_used),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "transactions": transactions,
        "miner": pubkey_hex_to_evm_address(&block.proposer_pubkey),
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "transactionsRoot": format!("0x{}", hex::encode(block.tx_root.as_bytes())),
        "stateRoot": format!("0x{}", hex::encode(block.state_root.as_bytes())),
        "receiptsRoot": format!("0x{}", hex::encode(block.receipt_root.as_bytes())),
        "size": format!("0x{:x}", 1000),
        "extraData": "0x",
        "baseFeePerGas": format!("0x{:x}", block.base_fee_per_gas),
        "uncles": [],
        // PIL-50: GHOSTDAG fields (see explorer handoff RPC_DAG_FIELDS_HANDOFF.md).
        "blueScore": format!("0x{:x}", block.blue_score),
        "blueWork": format!("0x{:x}", block.blue_work),
        "selectedParentHash": format!("0x{}", hex::encode(block.parent_hash.as_bytes())),
        "mergeParentHashes": merge_parents_json
    })
}

/// Add Ethereum-compatible RPC methods to the IoHandler
pub fn register_eth_methods(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
    chain_id: u64,
    filter_registry: Arc<FilterRegistry>,
    pause_flag: Option<Arc<AtomicBool>>,
) {
    // eth_blockNumber - Returns the latest block number
    let storage_bn = storage.clone();
    io_handler.add_sync_method("eth_blockNumber", move |_params: Params| {
        let api = ChainApi::new(storage_bn.clone());
        match block_on(api.get_height()) {
            Ok(height) => {
                // Return as hex string as per Ethereum JSON-RPC spec
                Ok(Value::String(format!("0x{:x}", height)))
            }
            Err(_) => Ok(Value::String("0x0".to_string())),
        }
    });

    // eth_getBlockByNumber - Returns block by number
    let storage_gbn = storage.clone();
    io_handler.add_sync_method("eth_getBlockByNumber", move |params: Params| {
        let api = ChainApi::new(storage_gbn.clone());
        
        // Parse params: [blockNumber, includeTransactions]
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };
        
        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing block number"));
        }
        
        // Parse includeTransactions flag (default false)
        let include_transactions = params.get(1)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        // Parse block number from hex string or "latest"
        let is_latest = params[0].as_str() == Some("latest");
        let block_number = match params[0].as_str() {
            Some("latest") | Some("pending") => {
                match block_on(api.get_height()) {
                    Ok(h) => h,
                    Err(_) => return Ok(Value::Null),
                }
            },
            Some("earliest") => 0,
            Some(hex_str) if hex_str.starts_with("0x") => {
                match u64::from_str_radix(&hex_str[2..], 16) {
                    Ok(n) => n,
                    Err(_) => return Err(jsonrpc_core::Error::invalid_params("Invalid block number")),
                }
            },
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid block number format")),
        };

        // Get block from storage.
        // For "latest", if the block at the reported height is missing (race
        // between height bookkeeping and block storage), fall back to height-1.
        let mut try_height = block_number;
        let block_result = loop {
            match block_on(api.get_block(crate::types::request::BlockId::Number(try_height))) {
                Ok(block) => break Ok(block),
                Err(_) if is_latest && try_height > 0 => {
                    try_height -= 1;
                    continue;
                }
                Err(e) => break Err(e),
            }
        };
        match block_result {
            Ok(block) => {
                // Build transactions array based on includeTransactions flag
                let transactions = if include_transactions {
                    // Return full transaction objects
                    block.transactions.iter().enumerate().map(|(index, tx)| {
                        json!({
                            "hash": format!("0x{}", hex::encode(tx.hash.as_bytes())),
                            "from": pubkey_hex_to_evm_address(&tx.from),
                            "to": pubkey_hex_opt_to_evm_address(tx.to.as_ref()),
                            "value": format!("0x{:x}", tx.value),
                            "gas": format!("0x{:x}", tx.gas_limit),
                            "gasPrice": format!("0x{:x}", tx.gas_price),
                            "nonce": format!("0x{:x}", tx.nonce),
                            "input": format!("0x{}", hex::encode(&tx.data)),
                            "blockHash": format!("0x{}", hex::encode(block.hash.as_bytes())),
                            "blockNumber": format!("0x{:x}", block.height),
                            "transactionIndex": format!("0x{:x}", index)
                        })
                    }).collect::<Vec<_>>()
                } else {
                    // Return just transaction hashes
                    block.transactions.iter()
                        .map(|tx| Value::String(format!("0x{}", hex::encode(tx.hash.as_bytes()))))
                        .collect::<Vec<_>>()
                };
                
                Ok(eth_block_json(&block, transactions))
            },
            Err(_) => Ok(Value::Null),
        }
    });

    // eth_getBlockByHash - Returns block by hash
    let storage_gbh = storage.clone();
    io_handler.add_sync_method("eth_getBlockByHash", move |params: Params| {
        let api = ChainApi::new(storage_gbh.clone());
        
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };
        
        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing block hash"));
        }
        
        // Parse includeTransactions flag (default false)
        let include_transactions = params.get(1)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        // Parse block hash
        let hash_str = match params[0].as_str() {
            Some(h) if h.starts_with("0x") => &h[2..],
            Some(h) => h,
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid hash format")),
        };
        
        let hash_bytes = match hex::decode(hash_str) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid hash length")),
        };
        
        match block_on(api.get_block(crate::types::request::BlockId::Hash(Hash::new(hash_bytes)))) {
            Ok(block) => {
                // Build transactions array based on includeTransactions flag
                let transactions = if include_transactions {
                    // Return full transaction objects
                    block.transactions.iter().enumerate().map(|(index, tx)| {
                        json!({
                            "hash": format!("0x{}", hex::encode(tx.hash.as_bytes())),
                            "from": pubkey_hex_to_evm_address(&tx.from),
                            "to": pubkey_hex_opt_to_evm_address(tx.to.as_ref()),
                            "value": format!("0x{:x}", tx.value),
                            "gas": format!("0x{:x}", tx.gas_limit),
                            "gasPrice": format!("0x{:x}", tx.gas_price),
                            "nonce": format!("0x{:x}", tx.nonce),
                            "input": format!("0x{}", hex::encode(&tx.data)),
                            "blockHash": format!("0x{}", hex::encode(block.hash.as_bytes())),
                            "blockNumber": format!("0x{:x}", block.height),
                            "transactionIndex": format!("0x{:x}", index)
                        })
                    }).collect::<Vec<_>>()
                } else {
                    // Return just transaction hashes
                    block.transactions.iter()
                        .map(|tx| Value::String(format!("0x{}", hex::encode(tx.hash.as_bytes()))))
                        .collect::<Vec<_>>()
                };
                
                Ok(eth_block_json(&block, transactions))
            },
            Err(_) => Ok(Value::Null),
        }
    });

    // eth_getTransactionByHash - Returns transaction by hash
    let storage_tx = storage.clone();
    let mempool_tx_lookup = mempool.clone();
    io_handler.add_sync_method("eth_getTransactionByHash", move |params: Params| {
        let api = ChainApi::new(storage_tx.clone());
        
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };
        
        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing transaction hash"));
        }
        
        let hash_str = match params[0].as_str() {
            Some(h) if h.starts_with("0x") => &h[2..],
            Some(h) => h,
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid hash format")),
        };
        
        let hash_bytes = match hex::decode(hash_str) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid hash length")),
        };
        
        let h = Hash::new(hash_bytes);
        match block_on(api.get_transaction(h)) {
            Ok(tx) => {
                let from_hex = pubkey_hex_to_evm_address(&tx.from);
                let to_hex_opt = pubkey_hex_opt_to_evm_address(tx.to.as_ref());
                let mut obj = serde_json::Map::new();
                obj.insert("hash".into(), json!(format!("0x{}", hex::encode(tx.hash.as_bytes()))));
                obj.insert("nonce".into(), json!(format!("0x{:x}", tx.nonce)));
                obj.insert("blockHash".into(), json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
                obj.insert("blockNumber".into(), json!("0x0"));
                obj.insert("transactionIndex".into(), json!("0x0"));
                obj.insert("from".into(), json!(from_hex));
                obj.insert("to".into(), json!(to_hex_opt));
                obj.insert("value".into(), json!(format!("0x{:x}", tx.value)));
                obj.insert("gasPrice".into(), json!(format!("0x{:x}", tx.gas_price)));
                obj.insert("gas".into(), json!(format!("0x{:x}", tx.gas_limit)));
                obj.insert("input".into(), json!(format!("0x{}", hex::encode(&tx.data))));
                obj.insert("v".into(), json!("0x1b"));
                obj.insert("r".into(), json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
                obj.insert("s".into(), json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
                append_eip_fields(
                    &mut obj,
                    tx.eth_tx_type,
                    tx.chain_id,
                    tx.max_fee_per_gas,
                    tx.max_priority_fee_per_gas,
                    &tx.access_list,
                );
                Ok(Value::Object(obj))
            },
            Err(_) => {
                // Fallback: check mempool for pending transaction
                if let Some(tx) = block_on(mempool_tx_lookup.get_transaction(&h)) {
                    let from_addr = citrate_execution::address_utils::normalize_address(&tx.from);
                    let to_addr_opt = tx.to.as_ref().map(citrate_execution::address_utils::normalize_address);
                    let mut obj = serde_json::Map::new();
                    obj.insert("hash".into(), json!(format!("0x{}", hex::encode(tx.hash.as_bytes()))));
                    obj.insert("nonce".into(), json!(format!("0x{:x}", tx.nonce)));
                    obj.insert("blockHash".into(), Value::Null);
                    obj.insert("blockNumber".into(), Value::Null);
                    obj.insert("transactionIndex".into(), Value::Null);
                    obj.insert("from".into(), json!(format!("0x{}", hex::encode(from_addr.0))));
                    obj.insert("to".into(), json!(to_addr_opt.map(|a| format!("0x{}", hex::encode(a.0)))));
                    obj.insert("value".into(), json!(format!("0x{:x}", tx.value)));
                    obj.insert("gasPrice".into(), json!(format!("0x{:x}", tx.gas_price)));
                    obj.insert("gas".into(), json!(format!("0x{:x}", tx.gas_limit)));
                    obj.insert("input".into(), json!(format!("0x{}", hex::encode(&tx.data))));
                    obj.insert("v".into(), json!("0x1b"));
                    obj.insert("r".into(), json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
                    obj.insert("s".into(), json!("0x0000000000000000000000000000000000000000000000000000000000000000"));
                    append_eip_fields(
                        &mut obj,
                        tx.eth_tx_type,
                        tx.chain_id,
                        tx.max_fee_per_gas,
                        tx.max_priority_fee_per_gas,
                        &tx.access_list,
                    );
                    Ok(Value::Object(obj))
                } else {
                    Ok(Value::Null)
                }
            },
        }
    });

    // eth_getTransactionReceipt - Returns transaction receipt
    let storage_rcpt = storage.clone();
    io_handler.add_sync_method("eth_getTransactionReceipt", move |params: Params| {
        let api = ChainApi::new(storage_rcpt.clone());
        
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };
        
        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing transaction hash"));
        }
        
        let hash_str = match params[0].as_str() {
            Some(h) if h.starts_with("0x") => &h[2..],
            Some(h) => h,
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid hash format")),
        };
        
        let hash_bytes = match hex::decode(hash_str) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid hash length")),
        };
        
        match block_on(api.get_receipt(Hash::new(hash_bytes))) {
            Ok(receipt) => {
                // Derive contractAddress if deployment output encodes address
                let contract_address = if receipt.to.is_none() && receipt.output.len() == 20 {
                    Some(format!("0x{}", hex::encode(&receipt.output)))
                } else {
                    None
                };

                Ok(json!({
                    "transactionHash": format!("0x{}", hex::encode(receipt.tx_hash.as_bytes())),
                    "transactionIndex": "0x0",
                    "blockHash": format!("0x{}", hex::encode(receipt.block_hash.as_bytes())),
                    "blockNumber": format!("0x{:x}", receipt.block_number),
                    "from": format!("0x{}", hex::encode(receipt.from.0)),
                    "to": receipt.to.as_ref().map(|t| format!("0x{}", hex::encode(t.0))),
                    "cumulativeGasUsed": format!("0x{:x}", receipt.gas_used),
                    "gasUsed": format!("0x{:x}", receipt.gas_used),
                    "contractAddress": contract_address,
                    "logs": receipt.logs.iter().map(|log| json!({
                        "address": format!("0x{}", hex::encode(log.address.0)),
                        "topics": log.topics.iter()
                            .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
                            .collect::<Vec<_>>(),
                        "data": format!("0x{}", hex::encode(&log.data)),
                        "logIndex": "0x0",
                        "transactionIndex": "0x0",
                        "transactionHash": format!("0x{}", hex::encode(receipt.tx_hash.as_bytes())),
                        "blockHash": format!("0x{}", hex::encode(receipt.block_hash.as_bytes())),
                        "blockNumber": format!("0x{:x}", receipt.block_number),
                        "removed": false
                    })).collect::<Vec<_>>(),
                    "status": if receipt.status { "0x1" } else { "0x0" },
                    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "type": format!("0x{:x}", receipt.eth_tx_type),
                    "effectiveGasPrice": format!("0x{:x}", receipt.effective_gas_price)
                }))
            },
            Err(_) => Ok(Value::Null),
        }
    });

    // eth_chainId - Returns the chain ID
    io_handler.add_sync_method("eth_chainId", move |_params: Params| {
        // Return configured chain ID in hex
        Ok(Value::String(format!("0x{:x}", chain_id)))
    });

    // eth_syncing - Returns sync status
    io_handler.add_sync_method("eth_syncing", move |_params: Params| {
        // Return false when fully synced
        Ok(Value::Bool(false))
    });

    // net_peerCount handled in server.rs with NetworkApi to reflect real peers

    // eth_gasPrice - Returns current gas price
    io_handler.add_sync_method("eth_gasPrice", move |_params: Params| {
        // Return 1 gwei
        Ok(Value::String("0x3b9aca00".to_string()))
    });

    // eth_getBalance - Returns account balance
    let storage_bal = storage.clone();
    let executor_bal = executor.clone();
    io_handler.add_sync_method("eth_getBalance", move |params: Params| {
        let state_api = StateApi::new(storage_bal.clone(), executor_bal.clone());

        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing address"));
        }

        let addr_str = match params[0].as_str() {
            Some(a) if a.starts_with("0x") => &a[2..],
            Some(a) => a,
            None => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address format",
                ))
            }
        };

        let addr_bytes = match hex::decode(addr_str) {
            Ok(b) if b.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address length",
                ))
            }
        };

        match block_on(state_api.get_balance(Address(addr_bytes))) {
            Ok(balance) => Ok(Value::String(format!("0x{:x}", balance))),
            Err(_) => Ok(Value::String("0x0".to_string())),
        }
    });

    // eth_getCode - Returns contract code
    let storage_code = storage.clone();
    let executor_code = executor.clone();
    io_handler.add_sync_method("eth_getCode", move |params: Params| {
        let state_api = StateApi::new(storage_code.clone(), executor_code.clone());

        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing address"));
        }

        let addr_str = match params[0].as_str() {
            Some(a) if a.starts_with("0x") => &a[2..],
            Some(a) => a,
            None => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address format",
                ))
            }
        };

        let addr_bytes = match hex::decode(addr_str) {
            Ok(b) if b.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address length",
                ))
            }
        };

        match block_on(state_api.get_code(Address(addr_bytes))) {
            Ok(code) => Ok(Value::String(format!("0x{}", hex::encode(code)))),
            Err(_) => Ok(Value::String("0x".to_string())),
        }
    });

    // eth_getTransactionCount - Returns account nonce
    let storage_nonce = storage.clone();
    let executor_nonce = executor.clone();
    let mempool_nonce = mempool.clone();
    io_handler.add_sync_method("eth_getTransactionCount", move |params: Params| {
        let state_api = StateApi::new(storage_nonce.clone(), executor_nonce.clone());

        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing address"));
        }

        let addr_str = match params[0].as_str() {
            Some(a) if a.starts_with("0x") => &a[2..],
            Some(a) => a,
            None => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address format",
                ))
            }
        };

        let addr_bytes = match hex::decode(addr_str) {
            Ok(b) if b.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid address length",
                ))
            }
        };

        // Optional second param: block tag ("latest" | "pending" | "earliest")
        let tag = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

        let base_nonce = block_on(state_api.get_nonce(Address(addr_bytes))).unwrap_or_default();

        if tag.eq_ignore_ascii_case("pending") {
            // Include pending mempool transactions from this sender
            let mp = mempool_nonce.clone();
            let total = block_on(mp.stats()).total_transactions;
            let txs = block_on(mp.get_transactions(total));
            let mut max_nonce = None;
            for tx in txs {
                // Derive sender address from tx.from
                let sender_addr = citrate_execution::address_utils::normalize_address(&tx.from);
                if sender_addr.0 == addr_bytes {
                    max_nonce = Some(max_nonce.map_or(tx.nonce, |m: u64| m.max(tx.nonce)));
                }
            }
            let pending_nonce = match max_nonce {
                Some(m) if m + 1 > base_nonce => m + 1,
                _ => base_nonce,
            };
            return Ok(Value::String(format!("0x{:x}", pending_nonce)));
        }

        Ok(Value::String(format!("0x{:x}", base_nonce)))
    });

    // eth_sendTransaction - DISABLED by default (C-02 defense-in-depth).
    // The server.rs handler overrides this with a config-gated version for devnet.
    // This stub ensures that if the override is ever removed, unsigned tx creation
    // is still rejected rather than silently re-enabled.
    io_handler.add_sync_method("eth_sendTransaction", move |_params: Params| {
        Err(jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::MethodNotFound,
            message: "eth_sendTransaction is disabled. Use eth_sendRawTransaction with a signed transaction.".into(),
            data: None,
        })
    });

    // eth_sendRawTransaction - Submit signed transaction
    let mempool_send = mempool.clone();
    let executor_raw_tx = executor.clone();
    let raw_tx_chain_id = chain_id;
    io_handler.add_sync_method("eth_sendRawTransaction", move |params: Params| {
        let mempool = mempool_send.clone();
        let exec = executor_raw_tx.clone();

        tracing::info!("eth_sendRawTransaction called");

        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to parse params: {}", e);
                return Err(jsonrpc_core::Error::invalid_params(e.to_string()));
            }
        };

        if params.is_empty() {
            tracing::error!("Missing transaction data");
            return Err(jsonrpc_core::Error::invalid_params(
                "Missing transaction data",
            ));
        }

        let tx_data = match params[0].as_str() {
            Some(d) if d.starts_with("0x") => &d[2..],
            Some(d) => d,
            None => {
                tracing::error!("Invalid transaction format");
                return Err(jsonrpc_core::Error::invalid_params(
                    "Invalid transaction format",
                ));
            }
        };

        tracing::debug!(
            "Raw tx data (first 100 bytes): {}",
            &tx_data[..tx_data.len().min(200)]
        );

        let tx_bytes = match hex::decode(tx_data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Failed to decode hex: {}", e);
                return Err(jsonrpc_core::Error::invalid_params("Invalid hex data"));
            }
        };

        tracing::debug!("Decoded {} bytes of transaction data", tx_bytes.len());

        // Parse transaction - handles both Ethereum RLP and Citrate bincode formats
        let tx: Transaction = match eth_tx_decoder::decode_eth_transaction(&tx_bytes) {
            Ok(t) => {
                tracing::info!("Successfully decoded transaction");
                t
            }
            Err(e) => {
                tracing::error!("Failed to decode transaction: {}", e);
                return Err(jsonrpc_core::Error::invalid_params(format!(
                    "Failed to parse transaction: {}",
                    e
                )));
            }
        };

        // Validate chain ID if the transaction includes one
        if let Some(tx_chain_id) = tx.chain_id {
            if tx_chain_id != raw_tx_chain_id {
                tracing::error!(
                    "Chain ID mismatch: tx has {}, node expects {}",
                    tx_chain_id, raw_tx_chain_id
                );
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: format!(
                        "Invalid chain ID: transaction has {}, expected {}",
                        tx_chain_id, raw_tx_chain_id
                    ),
                    data: None,
                });
            }
        }

        // Check sender has sufficient balance for value + gas cost
        {
            let sender_addr = citrate_execution::address_utils::normalize_address(&tx.from);
            let sender_balance = exec.get_canonical_account(&sender_addr).balance; // SRP-S4 WP-2.2: non-warming (committed) read — never mutate the shared resident map from RPC
            let tx_cost = U256::from(tx.value)
                .saturating_add(U256::from(tx.gas_limit).saturating_mul(U256::from(tx.gas_price)));
            if sender_balance < tx_cost {
                tracing::error!(
                    "Insufficient balance: sender has {}, tx requires {}",
                    sender_balance, tx_cost
                );
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
                    message: "insufficient funds for gas * price + value".to_string(),
                    data: None,
                });
            }
        }

        // Get transaction hash (now always properly set by decoder)
        let tx_hash = tx.hash;
        tracing::info!("Transaction hash: 0x{}", hex::encode(tx_hash.as_bytes()));

        // Submit to mempool using block_on to execute async function
        match block_on(mempool.add_transaction(tx, TxClass::Standard)) {
            Ok(_) => {
                tracing::info!(
                    "✓ Transaction {} successfully added to mempool",
                    hex::encode(tx_hash.as_bytes())
                );
                Ok(Value::String(format!(
                    "0x{}",
                    hex::encode(tx_hash.as_bytes())
                )))
            }
            Err(e) => {
                tracing::error!("✗ Failed to submit transaction to mempool: {:?}", e);
                Err(jsonrpc_core::Error::invalid_params(format!(
                    "Failed to submit transaction: {:?}",
                    e
                )))
            }
        }
    });

    // eth_call - Execute call without creating transaction
    let executor_call = executor.clone();
    io_handler.add_sync_method("eth_call", move |params: Params| {
        // WP-I.4: eth_call costs 10 budget units
        crate::rate_limit::check_method_budget(10)?;

        use citrate_consensus::types::{PublicKey, Signature};

        let exec = executor_call.clone();

        // Parse params: [callObject, blockTag]
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing call object"));
        }

        // call object
        let obj = match &params[0] {
            Value::Object(map) => map,
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid call object")),
        };

        // to (required)
        let to_str = match obj.get("to").and_then(|v| v.as_str()) {
            Some(s) => s.trim().trim_start_matches("0x"),
            None => return Err(jsonrpc_core::Error::invalid_params("Missing 'to' address")),
        };
        let to_bytes = match hex::decode(to_str) {
            Ok(b) if b.len() == 20 => b,
            _ => return Err(jsonrpc_core::Error::invalid_params("Invalid 'to' address")),
        };
        let mut to_pk_bytes = [0u8; 32];
        to_pk_bytes[..20].copy_from_slice(&to_bytes);
        let to_pk = Some(citrate_consensus::types::PublicKey::new(to_pk_bytes));

        // from (optional)
        let from_pk = if let Some(from_s) = obj.get("from").and_then(|v| v.as_str()) {
            let fs = from_s.trim().trim_start_matches("0x");
            let fbytes = match hex::decode(fs) {
                Ok(b) if b.len() == 20 => b,
                _ => {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "Invalid 'from' address",
                    ))
                }
            };
            let mut pkb = [0u8; 32];
            pkb[..20].copy_from_slice(&fbytes);
            PublicKey::new(pkb)
        } else {
            PublicKey::new([0u8; 32])
        };

        // data (optional but usually required)
        let data = if let Some(d) = obj.get("data").and_then(|v| v.as_str()) {
            let ds = d.trim();
            let ds = ds.strip_prefix("0x").unwrap_or(ds);
            match hex::decode(ds) {
                Ok(b) => b,
                Err(_) => return Err(jsonrpc_core::Error::invalid_params("Invalid data hex")),
            }
        } else {
            Vec::new()
        };

        // value (optional)
        let value_u128: u128 = if let Some(vs) = obj.get("value").and_then(|v| v.as_str()) {
            let s = vs.trim();
            if let Some(hexs) = s.strip_prefix("0x") {
                u128::from_str_radix(hexs, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex value: {}", vs)))?
            } else {
                s.parse::<u128>().map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid value: {}", vs)))?
            }
        } else {
            0u128
        };

        // gas and gasPrice (optional)
        let gas_limit: u64 = if let Some(gs) = obj.get("gas").and_then(|v| v.as_str()) {
            let s = gs.trim();
            if let Some(hexs) = s.strip_prefix("0x") {
                u64::from_str_radix(hexs, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex gas: {}", gs)))?
            } else {
                s.parse::<u64>().map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid gas: {}", gs)))?
            }
        } else {
            1_000_000
        };

        let gas_price: u64 = if let Some(gps) = obj.get("gasPrice").and_then(|v| v.as_str()) {
            let s = gps.trim();
            if let Some(hexs) = s.strip_prefix("0x") {
                u64::from_str_radix(hexs, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex gasPrice: {}", gps)))?
            } else {
                s.parse::<u64>().map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid gasPrice: {}", gps)))?
            }
        } else {
            1
        };

        // Build a lightweight block context
        let blk = citrate_consensus::types::BlockBuilder::new()
            .base_fee_per_gas(1_000_000_000)
            .build_unhashed();

        // For eth_call, use the sender's current nonce so execution doesn't fail
        // on nonce validation (both in executor and REVM).
        let sender_addr = citrate_execution::address_utils::normalize_address(&from_pk);
        let sender_nonce = exec.get_canonical_account(&sender_addr).nonce; // SRP-S4 WP-2.2: non-warming committed read

        // Create a pseudo-transaction
        let mut tx = citrate_consensus::types::Transaction {
            hash: citrate_consensus::types::Hash::default(),
            nonce: sender_nonce,
            from: from_pk,
            to: to_pk,
            value: value_u128,
            gas_limit,
            gas_price,
            data,
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };

        // Determine transaction type from data
        tx.determine_type();

        // WP-Z.4: Set block context with latest VRF output for eth_call simulation.
        // This ensures `block.prevrandao` returns a real value (matching mainnet behavior).
        // The block context persists from the last produced block, so prevrandao
        // reflects the most recent VRF output.

        // Simulate without persisting state — avoids race condition where
        // the block producer could persist the inflated balance to RocksDB.
        let res = block_on(exec.simulate_transaction(&blk, &tx));

        match res {
            Ok(receipt) => {
                // BFR-VM-1 WP-8 — surface in-EVM halts and reverts as
                // JSON-RPC errors instead of returning `0x` with no
                // signal. The CANCUN/MCOPY bug stayed undiagnosed for
                // months because eth_call swallowed REVM's
                // `InvalidOpcode` halt into an empty Ok response. Now
                // any `status: false` receipt with a populated
                // `revert_reason` propagates here as
                // jsonrpc_core::Error code -32000 ("execution
                // reverted") with the reason in the message.
                if !receipt.status {
                    let mut err = jsonrpc_core::Error::new(
                        jsonrpc_core::ErrorCode::ServerError(-32000),
                    );
                    err.message = match receipt.revert_reason.as_deref() {
                        Some(r) => format!("execution reverted: {r}"),
                        None => "execution reverted (no reason)".to_string(),
                    };
                    return Err(err);
                }
                Ok(Value::String(format!("0x{}", hex::encode(receipt.output))))
            }
            Err(e) => Err(jsonrpc_core::Error::invalid_params(format!(
                "eth_call failed: {}",
                e
            ))),
        }
    });

    // eth_estimateGas - Estimate gas for transaction by dry-running execution
    let executor_estimate = executor.clone();
    io_handler.add_sync_method("eth_estimateGas", move |params: Params| {
        // WP-I.4: eth_estimateGas costs 10 budget units
        crate::rate_limit::check_method_budget(10)?;

        use citrate_consensus::types::{PublicKey, Signature};

        let exec = executor_estimate.clone();

        // Parse params: [callObject, blockTag (optional)]
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(_) => {
                // No params - return default gas for simple transfer
                return Ok(Value::String("0x5208".to_string())); // 21000 gas
            }
        };

        if params.is_empty() {
            // No call object - return default gas for simple transfer
            return Ok(Value::String("0x5208".to_string())); // 21000 gas
        }

        // call object
        let obj = match &params[0] {
            Value::Object(map) => map,
            _ => {
                // Invalid params - return default
                return Ok(Value::String("0x5208".to_string()));
            }
        };

        // to (optional for contract deployment)
        let to_pk = if let Some(to_s) = obj.get("to").and_then(|v| v.as_str()) {
            let ts = to_s.trim().trim_start_matches("0x");
            if let Ok(to_bytes) = hex::decode(ts) {
                if to_bytes.len() == 20 {
                    let mut to_pk_bytes = [0u8; 32];
                    to_pk_bytes[..20].copy_from_slice(&to_bytes);
                    Some(PublicKey::new(to_pk_bytes))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // from (optional)
        let from_pk = if let Some(from_s) = obj.get("from").and_then(|v| v.as_str()) {
            let fs = from_s.trim().trim_start_matches("0x");
            if let Ok(fbytes) = hex::decode(fs) {
                if fbytes.len() == 20 {
                    let mut pkb = [0u8; 32];
                    pkb[..20].copy_from_slice(&fbytes);
                    PublicKey::new(pkb)
                } else {
                    PublicKey::new([0u8; 32])
                }
            } else {
                PublicKey::new([0u8; 32])
            }
        } else {
            PublicKey::new([0u8; 32])
        };

        // data (optional)
        let data = if let Some(d) = obj.get("data").and_then(|v| v.as_str()) {
            let ds = d.trim().trim_start_matches("0x");
            hex::decode(ds).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex data: {}", d)))?
        } else {
            Vec::new()
        };

        // value (optional)
        let value_u128: u128 = if let Some(vs) = obj.get("value").and_then(|v| v.as_str()) {
            let s = vs.trim();
            if let Some(hexs) = s.strip_prefix("0x") {
                u128::from_str_radix(hexs, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex value: {}", vs)))?
            } else {
                s.parse::<u128>().map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid value: {}", vs)))?
            }
        } else {
            0
        };

        // Use a high gas limit for estimation (will return actual used)
        let gas_limit: u64 = if let Some(gs) = obj.get("gas").and_then(|v| v.as_str()) {
            let s = gs.trim();
            if let Some(hexs) = s.strip_prefix("0x") {
                u64::from_str_radix(hexs, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex gas: {}", gs)))?
            } else {
                s.parse::<u64>().map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid gas: {}", gs)))?
            }
        } else {
            15_000_000 // Default to block gas limit for estimation
        };

        // Check if this is a simple transfer (no data, has to address)
        if data.is_empty() && to_pk.is_some() {
            // Simple value transfer - return 21000 gas
            return Ok(Value::String("0x5208".to_string()));
        }

        let calldata_floor = 21_000u64.saturating_add(
            data.iter()
                .map(|byte| if *byte == 0 { 4u64 } else { 16u64 })
                .sum::<u64>(),
        );
        let deployment_floor = if to_pk.is_none() && !data.is_empty() {
            let init_code_len = data.len() as u64;
            let init_code_words = init_code_len.saturating_add(31) / 32;
            Some(
                21_000u64
                    .saturating_add(32_000)
                    .saturating_add(init_code_words.saturating_mul(2))
                    // Use init-code length as a conservative proxy for code deposit cost.
                    .saturating_add(init_code_len.saturating_mul(200)),
            )
        } else {
            None
        };

        // Build a lightweight block context for execution
        let blk = citrate_consensus::types::BlockBuilder::new()
            .timestamp(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0))
            .base_fee_per_gas(1_000_000_000)
            .build_unhashed();

        // For gas estimation, use sender's current nonce to pass nonce validation
        let sender_addr = citrate_execution::address_utils::normalize_address(&from_pk);
        let sender_nonce = exec.get_canonical_account(&sender_addr).nonce; // SRP-S4 WP-2.2: non-warming committed read

        // PIL-47b: capture whether this is a contract call before `data`
        // gets moved into the pseudo-transaction. Needed below for the
        // SSTORE-refund-aware buffer logic on the estimate result.
        let data_is_empty = data.is_empty();

        // Create a pseudo-transaction for estimation
        let mut tx = citrate_consensus::types::Transaction {
            hash: citrate_consensus::types::Hash::default(),
            nonce: sender_nonce,
            from: from_pk,
            to: to_pk,
            value: value_u128,
            gas_limit,
            gas_price: 1, // Minimal gas price for estimation
            data,
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };

        // Determine transaction type from data
        tx.determine_type();

        // Simulate without persisting state — avoids race condition where
        // the block producer could persist the inflated balance to RocksDB.
        let res = block_on(exec.simulate_transaction(&blk, &tx));

        match res {
            Ok(receipt) => {
                // PIL-47b: `simulate_transaction` returns the *net*
                // gas_used after EIP-2200 SSTORE refunds. The REAL tx
                // front-loads the gross SSTORE charge (up to ~42k for a
                // cold-slot write) before any refunds apply, so a tx
                // whose gas-limit equals the net estimate hits OOG before
                // reaching the SSTORE — observed in the wild as
                // `updateProviderStatus(true→false)` returning
                // `status=0, gasUsed=700` with a 10%-buffered estimate.
                //
                // For any state-mutating call (`!data.is_empty()` and
                // `to_pk.is_some()`), we need enough headroom upfront for
                // the worst-case un-refunded SSTORE plus the cold-access
                // surcharge. Doubling the simulated net cost is the
                // simplest formula that covers all SSTORE refund cases
                // without a binary-search re-simulation loop; the cost
                // is just a slightly inflated gas-limit on the tx (the
                // EVM still bills only what was actually used).
                //
                // Simple transfers and pure view calls keep the tight
                // +10% margin so block-gas-budgeting stays useful for
                // ordinary value sends.
                let is_state_mutating_call = to_pk.is_some() && !data_is_empty;
                let gas_with_buffer = if is_state_mutating_call {
                    receipt
                        .gas_used
                        .saturating_mul(2)
                        .max(receipt.gas_used.saturating_add(50_000))
                } else {
                    receipt.gas_used.saturating_add(receipt.gas_used / 10)
                };
                let final_gas = gas_with_buffer
                    .max(calldata_floor)
                    .max(deployment_floor.unwrap_or(21_000));
                Ok(Value::String(format!("0x{:x}", final_gas)))
            }
            Err(_) => {
                let fallback_gas = deployment_floor.unwrap_or(calldata_floor.max(21_000));
                Ok(Value::String(format!("0x{:x}", fallback_gas)))
            }
        }
    });

    // eth_feeHistory - Get fee history for EIP-1559
    let storage_fee = storage.clone();
    io_handler.add_sync_method("eth_feeHistory", move |params: Params| {
        // Parse params: [blockCount, newestBlock, rewardPercentiles]
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(_) => {
                // Return default if no params
                return Ok(json!({
                    "oldestBlock": "0x1",
                    "reward": [],
                    "baseFeePerGas": ["0x3b9aca00"],
                    "gasUsedRatio": []
                }));
            }
        };

        // Parse block count (default 1)
        let block_count: u64 = params.first()
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(1)
            .min(1024); // Cap at 1024 blocks

        // Get current height
        let api = ChainApi::new(storage_fee.clone());
        let current_height = block_on(api.get_height()).unwrap_or_default();

        if current_height == 0 {
            return Ok(json!({
                "oldestBlock": "0x0",
                "reward": [],
                "baseFeePerGas": ["0x3b9aca00"],
                "gasUsedRatio": []
            }));
        }

        // Calculate start height
        let start_height = current_height.saturating_sub(block_count - 1);

        // Collect fee data from blocks
        let mut base_fees: Vec<String> = Vec::new();
        let mut gas_used_ratios: Vec<f64> = Vec::new();
        let mut rewards: Vec<Vec<String>> = Vec::new();

        // Parse reward percentiles if provided
        let percentiles: Vec<f64> = params.get(2)
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|p| p.as_f64())
                .collect())
            .unwrap_or_default();

        for height in start_height..=current_height {
            // Get block hash at height
            if let Ok(Some(block_hash)) = storage_fee.blocks.get_block_by_height(height) {
                // Get block data
                if let Ok(Some(block)) = storage_fee.blocks.get_block(&block_hash) {
                    // Use persisted gas_used and gas_limit from block header (EIP-1559 fields)
                    // These are set during block building and represent actual execution results
                    let block_gas_limit = if block.header.gas_limit > 0 {
                        block.header.gas_limit
                    } else {
                        30_000_000 // Default 30M for older blocks without this field
                    };

                    let total_gas_used = if block.header.gas_used > 0 {
                        // Use persisted gas_used from block header (best source)
                        block.header.gas_used
                    } else {
                        // Fallback: calculate from receipts or estimate
                        let mut gas_from_receipts: u64 = 0;
                        let mut has_receipt_data = false;

                        for tx in &block.transactions {
                            if let Ok(Some(receipt)) = storage_fee.transactions.get_receipt(&tx.hash) {
                                gas_from_receipts += receipt.gas_used;
                                has_receipt_data = true;
                            }
                        }

                        if has_receipt_data {
                            gas_from_receipts
                        } else {
                            // Last resort: estimate from transactions
                            block.transactions.iter()
                                .map(|tx| {
                                    if tx.to.is_none() {
                                        tx.gas_limit.min(100_000) // Contract creation
                                    } else if tx.data.is_empty() {
                                        21000 // Simple transfer
                                    } else {
                                        tx.gas_limit.min(50_000) // Contract call
                                    }
                                })
                                .sum()
                        }
                    };

                    let gas_ratio = total_gas_used as f64 / block_gas_limit as f64;
                    gas_used_ratios.push(gas_ratio.min(1.0));

                    // Use persisted base_fee_per_gas from block header (EIP-1559)
                    let base_fee = if block.header.base_fee_per_gas > 0 {
                        // Use the persisted value (best source - set during block building)
                        block.header.base_fee_per_gas
                    } else {
                        // Fallback: calculate from block fullness (older blocks)
                        let target_gas = block_gas_limit / 2;
                        if total_gas_used > target_gas {
                            let delta = total_gas_used - target_gas;
                            1_000_000_000_u64 + (delta as f64 / target_gas as f64 * 125_000_000.0) as u64
                        } else {
                            let delta = target_gas - total_gas_used;
                            1_000_000_000_u64.saturating_sub((delta as f64 / target_gas as f64 * 125_000_000.0) as u64)
                        }.max(1_000_000_000)
                    };
                    base_fees.push(format!("0x{:x}", base_fee));

                    // Calculate reward percentiles from transactions (priority fees)
                    // For legacy transactions, tip = gas_price - base_fee
                    if !percentiles.is_empty() && !block.transactions.is_empty() {
                        let mut tips: Vec<u64> = block.transactions.iter()
                            .map(|tx| tx.gas_price.saturating_sub(base_fee))
                            .collect();
                        tips.sort();

                        let mut block_rewards: Vec<String> = Vec::new();
                        for pct in &percentiles {
                            let idx = ((pct / 100.0) * (tips.len() - 1) as f64).floor() as usize;
                            let tip = tips.get(idx).copied().unwrap_or(0);
                            block_rewards.push(format!("0x{:x}", tip));
                        }
                        rewards.push(block_rewards);
                    } else {
                        rewards.push(vec!["0x0".to_string()]);
                    }
                } else {
                    // Block not found, use defaults
                    base_fees.push("0x3b9aca00".to_string()); // 1 gwei
                    gas_used_ratios.push(0.0);
                    rewards.push(vec!["0x0".to_string()]);
                }
            } else {
                // No block at height, use defaults
                base_fees.push("0x3b9aca00".to_string());
                gas_used_ratios.push(0.0);
                rewards.push(vec!["0x0".to_string()]);
            }
        }

        // Add one more base fee for the next block
        base_fees.push(base_fees.last().cloned().unwrap_or_else(|| "0x3b9aca00".to_string()));

        Ok(json!({
            "oldestBlock": format!("0x{:x}", start_height),
            "reward": rewards,
            "baseFeePerGas": base_fees,
            "gasUsedRatio": gas_used_ratios
        }))
    });

    // eth_maxPriorityFeePerGas - Get max priority fee
    io_handler.add_sync_method("eth_maxPriorityFeePerGas", move |_params: Params| {
        // Return 1 gwei max priority fee
        Ok(Value::String("0x3b9aca00".to_string()))
    });

    // eth_getLogs - Get logs matching filter criteria
    let storage_logs = storage.clone();
    io_handler.add_sync_method("eth_getLogs", move |params: Params| {
        // WP-I.4: eth_getLogs costs 10 budget units
        crate::rate_limit::check_method_budget(10)?;

        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing filter object"));
        }

        let filter = &params[0];

        // Get current height for "latest" resolution
        let current_height = storage_logs.blocks.get_latest_height().unwrap_or(0);

        // Parse fromBlock (default to 0)
        let from_block = match filter.get("fromBlock").and_then(|v| v.as_str()) {
            Some("latest") | Some("pending") => current_height,
            Some("earliest") => 0,
            Some(hex_str) if hex_str.starts_with("0x") => {
                u64::from_str_radix(&hex_str[2..], 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex fromBlock: {}", hex_str)))?
            }
            None => 0,
            Some(other) => return Err(jsonrpc_core::Error::invalid_params(format!("Invalid fromBlock: {}", other))),
        };

        // Parse toBlock (default to latest)
        let to_block = match filter.get("toBlock").and_then(|v| v.as_str()) {
            Some("latest") | Some("pending") => current_height,
            Some("earliest") => 0,
            Some(hex_str) if hex_str.starts_with("0x") => {
                u64::from_str_radix(&hex_str[2..], 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex toBlock: {}", hex_str)))?
            }
            None => current_height,
            Some(other) => return Err(jsonrpc_core::Error::invalid_params(format!("Invalid toBlock: {}", other))),
        };

        // Limit block range to prevent excessive queries
        let max_block_range = 1000u64;
        let effective_to = to_block.min(from_block.saturating_add(max_block_range));

        // Parse address filter (single address or array)
        let address_filter: Vec<Address> = match filter.get("address") {
            Some(Value::String(addr_str)) => {
                let addr_hex = addr_str.trim_start_matches("0x");
                if let Ok(bytes) = hex::decode(addr_hex) {
                    if bytes.len() == 20 {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(&bytes);
                        vec![Address(arr)]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
            Some(Value::Array(addrs)) => {
                addrs
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|addr_str| {
                        let addr_hex = addr_str.trim_start_matches("0x");
                        hex::decode(addr_hex).ok().and_then(|bytes| {
                            if bytes.len() == 20 {
                                let mut arr = [0u8; 20];
                                arr.copy_from_slice(&bytes);
                                Some(Address(arr))
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            }
            _ => vec![],
        };

        // Parse topics filter (array of arrays, each position can be null or array of hashes)
        let topics_filter: Vec<Option<Vec<Hash>>> = match filter.get("topics") {
            Some(Value::Array(topics)) => {
                topics
                    .iter()
                    .map(|topic_entry| {
                        match topic_entry {
                            Value::Null => None, // null means "any"
                            Value::String(hash_str) => {
                                // Single topic hash
                                let hash_hex = hash_str.trim_start_matches("0x");
                                hex::decode(hash_hex).ok().and_then(|bytes| {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        Some(vec![Hash::new(arr)])
                                    } else {
                                        None
                                    }
                                })
                            }
                            Value::Array(hashes) => {
                                // Array of topic hashes (OR logic)
                                let parsed: Vec<Hash> = hashes
                                    .iter()
                                    .filter_map(|v| v.as_str())
                                    .filter_map(|hash_str| {
                                        let hash_hex = hash_str.trim_start_matches("0x");
                                        hex::decode(hash_hex).ok().and_then(|bytes| {
                                            if bytes.len() == 32 {
                                                let mut arr = [0u8; 32];
                                                arr.copy_from_slice(&bytes);
                                                Some(Hash::new(arr))
                                            } else {
                                                None
                                            }
                                        })
                                    })
                                    .collect();
                                if parsed.is_empty() {
                                    None
                                } else {
                                    Some(parsed)
                                }
                            }
                            _ => None,
                        }
                    })
                    .collect()
            }
            _ => vec![],
        };

        // Collect matching logs
        let mut result_logs: Vec<Value> = Vec::new();
        let mut log_index_global = 0usize;

        for height in from_block..=effective_to {
            // Get block hash at this height
            let block_hash = match storage_logs.blocks.get_block_by_height(height) {
                Ok(Some(hash)) => hash,
                _ => continue,
            };

            // Get all transaction hashes in this block
            let tx_hashes = match storage_logs.transactions.get_block_transactions(&block_hash) {
                Ok(hashes) => hashes,
                Err(_) => continue,
            };

            for (tx_index, tx_hash) in tx_hashes.iter().enumerate() {
                // Get receipt for this transaction
                let receipt = match storage_logs.transactions.get_receipt(tx_hash) {
                    Ok(Some(r)) => r,
                    _ => continue,
                };

                // Filter and collect logs from this receipt
                for (log_index_in_tx, log) in receipt.logs.iter().enumerate() {
                    // Check address filter
                    if !address_filter.is_empty() && !address_filter.contains(&log.address) {
                        continue;
                    }

                    // Check topics filter
                    let topics_match = topics_filter.iter().enumerate().all(|(i, topic_filter)| {
                        match topic_filter {
                            None => true, // null means any
                            Some(allowed_topics) => {
                                if i >= log.topics.len() {
                                    false // Log doesn't have this topic position
                                } else {
                                    allowed_topics.contains(&log.topics[i])
                                }
                            }
                        }
                    });

                    if !topics_match {
                        continue;
                    }

                    // Log matches all filters
                    result_logs.push(json!({
                        "address": format!("0x{}", hex::encode(log.address.0)),
                        "topics": log.topics.iter()
                            .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
                            .collect::<Vec<_>>(),
                        "data": format!("0x{}", hex::encode(&log.data)),
                        "blockNumber": format!("0x{:x}", height),
                        "blockHash": format!("0x{}", hex::encode(block_hash.as_bytes())),
                        "transactionHash": format!("0x{}", hex::encode(tx_hash.as_bytes())),
                        "transactionIndex": format!("0x{:x}", tx_index),
                        "logIndex": format!("0x{:x}", log_index_global),
                        "removed": false
                    }));

                    log_index_global += 1;
                    let _ = log_index_in_tx; // Suppress unused warning
                }
            }
        }

        Ok(Value::Array(result_logs))
    });

    // eth_newFilter - Create a new log filter
    let storage_new_filter = storage.clone();
    let filter_registry_new = filter_registry.clone();
    io_handler.add_sync_method("eth_newFilter", move |params: Params| {
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing filter object"));
        }

        let filter = &params[0];
        let current_height = storage_new_filter.blocks.get_latest_height().unwrap_or(0);

        // Parse fromBlock
        let from_block = match filter.get("fromBlock").and_then(|v| v.as_str()) {
            Some("latest") | Some("pending") => Some(current_height),
            Some("earliest") => Some(0),
            Some(hex_str) if hex_str.starts_with("0x") => {
                u64::from_str_radix(&hex_str[2..], 16).ok()
            }
            None => None,
            _ => None,
        };

        // Parse toBlock
        let to_block = match filter.get("toBlock").and_then(|v| v.as_str()) {
            Some("latest") | Some("pending") => Some(current_height),
            Some("earliest") => Some(0),
            Some(hex_str) if hex_str.starts_with("0x") => {
                u64::from_str_radix(&hex_str[2..], 16).ok()
            }
            None => None,
            _ => None,
        };

        // Parse address filter
        let addresses: Vec<Address> = match filter.get("address") {
            Some(Value::String(addr_str)) => {
                let addr_hex = addr_str.trim_start_matches("0x");
                if let Ok(bytes) = hex::decode(addr_hex) {
                    if bytes.len() == 20 {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(&bytes);
                        vec![Address(arr)]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
            Some(Value::Array(addrs)) => {
                addrs
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|addr_str| {
                        let addr_hex = addr_str.trim_start_matches("0x");
                        hex::decode(addr_hex).ok().and_then(|bytes| {
                            if bytes.len() == 20 {
                                let mut arr = [0u8; 20];
                                arr.copy_from_slice(&bytes);
                                Some(Address(arr))
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            }
            _ => vec![],
        };

        // Parse topics filter
        let topics: Vec<Option<Vec<Hash>>> = match filter.get("topics") {
            Some(Value::Array(topics)) => {
                topics
                    .iter()
                    .map(|topic_entry| {
                        match topic_entry {
                            Value::Null => None,
                            Value::String(hash_str) => {
                                let hash_hex = hash_str.trim_start_matches("0x");
                                hex::decode(hash_hex).ok().and_then(|bytes| {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        Some(vec![Hash::new(arr)])
                                    } else {
                                        None
                                    }
                                })
                            }
                            Value::Array(hashes) => {
                                let parsed: Vec<Hash> = hashes
                                    .iter()
                                    .filter_map(|v| v.as_str())
                                    .filter_map(|hash_str| {
                                        let hash_hex = hash_str.trim_start_matches("0x");
                                        hex::decode(hash_hex).ok().and_then(|bytes| {
                                            if bytes.len() == 32 {
                                                let mut arr = [0u8; 32];
                                                arr.copy_from_slice(&bytes);
                                                Some(Hash::new(arr))
                                            } else {
                                                None
                                            }
                                        })
                                    })
                                    .collect();
                                if parsed.is_empty() { None } else { Some(parsed) }
                            }
                            _ => None,
                        }
                    })
                    .collect()
            }
            _ => vec![],
        };

        let filter_id = filter_registry_new.new_log_filter(
            from_block,
            to_block,
            addresses,
            topics,
            current_height,
        );

        Ok(Value::String(format!("0x{:x}", filter_id)))
    });

    // eth_newBlockFilter - Create a new block filter
    let storage_block_filter = storage.clone();
    let filter_registry_block = filter_registry.clone();
    io_handler.add_sync_method("eth_newBlockFilter", move |_params: Params| {
        let current_height = storage_block_filter.blocks.get_latest_height().unwrap_or(0);
        let filter_id = filter_registry_block.new_block_filter(current_height);
        Ok(Value::String(format!("0x{:x}", filter_id)))
    });

    // eth_newPendingTransactionFilter - Create a new pending transaction filter
    let filter_registry_pending = filter_registry.clone();
    io_handler.add_sync_method("eth_newPendingTransactionFilter", move |_params: Params| {
        let filter_id = filter_registry_pending.new_pending_transaction_filter();
        Ok(Value::String(format!("0x{:x}", filter_id)))
    });

    // eth_uninstallFilter - Remove a filter
    let filter_registry_uninstall = filter_registry.clone();
    io_handler.add_sync_method("eth_uninstallFilter", move |params: Params| {
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing filter ID"));
        }

        let filter_id = match params[0].as_str() {
            Some(hex_str) => {
                let hex = hex_str.trim_start_matches("0x");
                u64::from_str_radix(hex, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex filter ID: {}", hex_str)))?
            }
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid filter ID")),
        };

        let removed = filter_registry_uninstall.uninstall_filter(filter_id);
        Ok(Value::Bool(removed))
    });

    // eth_getFilterChanges - Get changes since last poll
    let storage_filter_changes = storage.clone();
    let filter_registry_changes = filter_registry.clone();
    io_handler.add_sync_method("eth_getFilterChanges", move |params: Params| {
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing filter ID"));
        }

        let filter_id = match params[0].as_str() {
            Some(hex_str) => {
                let hex = hex_str.trim_start_matches("0x");
                u64::from_str_radix(hex, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex filter ID: {}", hex_str)))?
            }
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid filter ID")),
        };

        let filter = match filter_registry_changes.get_filter(filter_id) {
            Some(f) => f,
            None => {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidRequest,
                    message: "Filter not found".to_string(),
                    data: None,
                })
            }
        };

        let current_height = storage_filter_changes.blocks.get_latest_height().unwrap_or(0);
        let last_poll_block = filter.last_poll_block;

        match filter.filter_type {
            FilterType::Block => {
                // Return new block hashes since last poll
                let mut block_hashes = Vec::new();
                for height in (last_poll_block + 1)..=current_height {
                    if let Ok(Some(hash)) = storage_filter_changes.blocks.get_block_by_height(height) {
                        block_hashes.push(Value::String(format!("0x{}", hex::encode(hash.as_bytes()))));
                    }
                }
                filter_registry_changes.update_last_poll_block(filter_id, current_height);
                Ok(Value::Array(block_hashes))
            }
            FilterType::PendingTransaction => {
                // For pending transactions, we'd need to track which ones are new
                // This is a simplified implementation that returns empty array
                Ok(Value::Array(vec![]))
            }
            FilterType::Log { from_block, to_block, ref addresses, ref topics } => {
                // Calculate effective block range
                let effective_from = last_poll_block + 1;
                let effective_to = match to_block {
                    Some(t) => t.min(current_height),
                    None => current_height,
                };

                // Skip if from_block was set and we haven't reached it yet
                if let Some(fb) = from_block {
                    if effective_from < fb {
                        filter_registry_changes.update_last_poll_block(filter_id, current_height);
                        return Ok(Value::Array(vec![]));
                    }
                }

                let mut result_logs: Vec<Value> = Vec::new();

                for height in effective_from..=effective_to {
                    let block_hash = match storage_filter_changes.blocks.get_block_by_height(height) {
                        Ok(Some(hash)) => hash,
                        _ => continue,
                    };

                    let tx_hashes = match storage_filter_changes.transactions.get_block_transactions(&block_hash) {
                        Ok(hashes) => hashes,
                        Err(_) => continue,
                    };

                    for (tx_index, tx_hash) in tx_hashes.iter().enumerate() {
                        let receipt = match storage_filter_changes.transactions.get_receipt(tx_hash) {
                            Ok(Some(r)) => r,
                            _ => continue,
                        };

                        for (log_index, log) in receipt.logs.iter().enumerate() {
                            // Check address filter
                            if !addresses.is_empty() && !addresses.contains(&log.address) {
                                continue;
                            }

                            // Check topics filter
                            let topics_match = topics.iter().enumerate().all(|(i, topic_filter)| {
                                match topic_filter {
                                    None => true,
                                    Some(allowed_topics) => {
                                        if i >= log.topics.len() {
                                            false
                                        } else {
                                            allowed_topics.contains(&log.topics[i])
                                        }
                                    }
                                }
                            });

                            if !topics_match {
                                continue;
                            }

                            result_logs.push(json!({
                                "address": format!("0x{}", hex::encode(log.address.0)),
                                "topics": log.topics.iter()
                                    .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
                                    .collect::<Vec<_>>(),
                                "data": format!("0x{}", hex::encode(&log.data)),
                                "blockNumber": format!("0x{:x}", height),
                                "blockHash": format!("0x{}", hex::encode(block_hash.as_bytes())),
                                "transactionHash": format!("0x{}", hex::encode(tx_hash.as_bytes())),
                                "transactionIndex": format!("0x{:x}", tx_index),
                                "logIndex": format!("0x{:x}", log_index),
                                "removed": false
                            }));
                        }
                    }
                }

                filter_registry_changes.update_last_poll_block(filter_id, current_height);
                Ok(Value::Array(result_logs))
            }
        }
    });

    // eth_getFilterLogs - Get all logs matching filter (for log filters only)
    let storage_filter_logs = storage.clone();
    let filter_registry_logs = filter_registry.clone();
    io_handler.add_sync_method("eth_getFilterLogs", move |params: Params| {
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing filter ID"));
        }

        let filter_id = match params[0].as_str() {
            Some(hex_str) => {
                let hex = hex_str.trim_start_matches("0x");
                u64::from_str_radix(hex, 16).map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid hex filter ID: {}", hex_str)))?
            }
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid filter ID")),
        };

        let filter = match filter_registry_logs.get_filter(filter_id) {
            Some(f) => f,
            None => {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidRequest,
                    message: "Filter not found".to_string(),
                    data: None,
                })
            }
        };

        let current_height = storage_filter_logs.blocks.get_latest_height().unwrap_or(0);

        match filter.filter_type {
            FilterType::Log { from_block, to_block, ref addresses, ref topics } => {
                let effective_from = from_block.unwrap_or(0);
                let effective_to = to_block.unwrap_or(current_height).min(current_height);
                let max_range = 1000u64;
                let effective_to = effective_to.min(effective_from.saturating_add(max_range));

                let mut result_logs: Vec<Value> = Vec::new();

                for height in effective_from..=effective_to {
                    let block_hash = match storage_filter_logs.blocks.get_block_by_height(height) {
                        Ok(Some(hash)) => hash,
                        _ => continue,
                    };

                    let tx_hashes = match storage_filter_logs.transactions.get_block_transactions(&block_hash) {
                        Ok(hashes) => hashes,
                        Err(_) => continue,
                    };

                    for (tx_index, tx_hash) in tx_hashes.iter().enumerate() {
                        let receipt = match storage_filter_logs.transactions.get_receipt(tx_hash) {
                            Ok(Some(r)) => r,
                            _ => continue,
                        };

                        for (log_index, log) in receipt.logs.iter().enumerate() {
                            if !addresses.is_empty() && !addresses.contains(&log.address) {
                                continue;
                            }

                            let topics_match = topics.iter().enumerate().all(|(i, topic_filter)| {
                                match topic_filter {
                                    None => true,
                                    Some(allowed_topics) => {
                                        if i >= log.topics.len() {
                                            false
                                        } else {
                                            allowed_topics.contains(&log.topics[i])
                                        }
                                    }
                                }
                            });

                            if !topics_match {
                                continue;
                            }

                            result_logs.push(json!({
                                "address": format!("0x{}", hex::encode(log.address.0)),
                                "topics": log.topics.iter()
                                    .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
                                    .collect::<Vec<_>>(),
                                "data": format!("0x{}", hex::encode(&log.data)),
                                "blockNumber": format!("0x{:x}", height),
                                "blockHash": format!("0x{}", hex::encode(block_hash.as_bytes())),
                                "transactionHash": format!("0x{}", hex::encode(tx_hash.as_bytes())),
                                "transactionIndex": format!("0x{:x}", tx_index),
                                "logIndex": format!("0x{:x}", log_index),
                                "removed": false
                            }));
                        }
                    }
                }

                Ok(Value::Array(result_logs))
            }
            _ => {
                Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::InvalidRequest,
                    message: "eth_getFilterLogs only works with log filters".to_string(),
                    data: None,
                })
            }
        }
    });

    // citrate_getMempoolSnapshot - Get bounded pending transaction summaries
    //
    // RM-B1 / WP-C1.1 (audit H-API-01): operator-auth gated. Pre-fix
    // any unauthenticated caller could dump the full mempool — sender,
    // target, value, calldata, gas price — enabling generalised front-
    // running and deanonymisation. Post-fix the method requires the
    // same `operator_token` that `setOperator` etc. require, gated by
    // `CITRATE_OPERATOR_TOKEN`. Without that env var set, the endpoint
    // is fail-closed (returns 401-equivalent JSON-RPC error). WP-J1.7
    // additionally routes the response through the bounded/redacted
    // pending-summary path so operator requests cannot produce an
    // unbounded calldata dump.
    let mempool_snapshot = mempool.clone();
    io_handler.add_sync_method("citrate_getMempoolSnapshot", move |params: Params| {
        // Parse params as an object for the operator_token field.
        let params_map = match params {
            Params::Map(map) => map,
            Params::None => serde_json::Map::new(),
            Params::Array(arr) => {
                // Some clients send `params: [{ "operator_token": "..." }]`.
                // Accept the first object element if present.
                if let Some(serde_json::Value::Object(map)) = arr.into_iter().next() {
                    map
                } else {
                    serde_json::Map::new()
                }
            }
        };

        // H-API-01 fix: operator-auth gate.
        crate::server::require_operator_auth(&params_map)?;

        let query = PendingQuery::from_params_map(&params_map)?;
        let api = MempoolApi::new(mempool_snapshot.clone());
        match block_on(api.get_pending(query)) {
            Ok(snapshot) => Ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
            Err(err) => Err(err.into()),
        }
    });

    // citrate_getTransactionStatus - Check if transaction is in mempool or mined
    let mempool_status = mempool.clone();
    let storage_status = storage.clone();
    io_handler.add_sync_method("citrate_getTransactionStatus", move |params: Params| {
        let params: Vec<Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
        };

        if params.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("Missing transaction hash"));
        }

        let tx_hash_str = match params[0].as_str() {
            Some(s) => s,
            None => return Err(jsonrpc_core::Error::invalid_params("Invalid transaction hash")),
        };

        // Parse transaction hash
        let tx_hash_hex = tx_hash_str.trim_start_matches("0x");
        let tx_hash_bytes = match hex::decode(tx_hash_hex) {
            Ok(b) => b,
            Err(_) => return Err(jsonrpc_core::Error::invalid_params("Invalid hex format")),
        };

        if tx_hash_bytes.len() != 32 {
            return Err(jsonrpc_core::Error::invalid_params("Transaction hash must be 32 bytes"));
        }

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&tx_hash_bytes);
        let tx_hash = Hash::new(hash_array);

        let mp = mempool_status.clone();
        let storage = storage_status.clone();

        // Check if transaction is mined
        if let Ok(Some(_receipt)) = storage.transactions.get_receipt(&tx_hash) {
            return Ok(json!({
                "status": "mined",
                "location": "blockchain",
                "hash": tx_hash_str
            }));
        }

        // Check if transaction is in mempool
        if let Some(tx) = block_on(mp.get_transaction(&tx_hash)) {
            let stats = block_on(mp.stats());
            return Ok(json!({
                "status": "pending",
                "location": "mempool",
                "hash": tx_hash_str,
                "nonce": tx.nonce,
                "from": format!("0x{}", hex::encode(citrate_execution::address_utils::normalize_address(&tx.from).0)),
                "gasPrice": format!("0x{:x}", tx.gas_price),
                "mempoolSize": stats.total_transactions
            }));
        }

        // Transaction not found
        Ok(json!({
            "status": "not_found",
            "location": null,
            "hash": tx_hash_str
        }))
    });

    // =========================================================================
    // PIL-12.5: Foundry / forge tooling compatibility.
    //
    // Methods that forge script, cast, hardhat, and common SDK probes
    // expect at connection time. Before this commit:
    //   * `forge script --broadcast` failed in the simulation phase with
    //     `-32601: Method not found` on eth_getStorageAt; that's how
    //     PIL-03 originally landed via `cast send` instead of forge.
    //   * Hardhat / ethers / viem startup probes emitted noisy errors
    //     for eth_accounts / eth_mining / eth_protocolVersion even
    //     though they don't actually need the result.
    //   * `cast block --index N` could not introspect tx-by-index.
    //
    // What we don't add here (intentionally):
    //   * debug_traceTransaction / debug_traceCall — heavy, requires REVM
    //     tracing wiring; tracked as a follow-up sprint.
    //   * trace_call / trace_block — Parity-style; same reasoning.
    //   * anvil_* — testnet RPC is not a dev simulator.
    //   * eth_getProof — state-proof generation needs trie wiring we
    //     don't have yet.
    // =========================================================================

    // eth_getStorageAt(address, slot, blockTag) — read a storage slot.
    //
    // forge script uses this in its simulation phase to compute state
    // diffs before broadcast. Returns a left-padded 32-byte hex value;
    // cast call decodes a `uint256` from it directly.
    //
    // We currently only serve "latest" semantics; historical state
    // requires pruning-point-aware storage that we don't have yet.
    // forge tolerates this because it caches the block height itself
    // and re-reads "latest" each call.
    let storage_gsat = storage.clone();
    let executor_gsat = executor.clone();
    io_handler.add_sync_method("eth_getStorageAt", move |params: Params| {
        let state_api = StateApi::new(storage_gsat.clone(), executor_gsat.clone());

        let parsed: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
        if parsed.len() < 2 {
            return Err(jsonrpc_core::Error::invalid_params(
                "eth_getStorageAt: expected [address, slot, blockTag]",
            ));
        }

        // address (required, 20 bytes)
        let addr_str = parsed[0]
            .as_str()
            .ok_or_else(|| jsonrpc_core::Error::invalid_params("address must be a hex string"))?;
        let addr_hex = addr_str.trim_start_matches("0x");
        let addr_bytes = hex::decode(addr_hex).map_err(|e| {
            jsonrpc_core::Error::invalid_params(format!("bad address hex: {e}"))
        })?;
        if addr_bytes.len() != 20 {
            return Err(jsonrpc_core::Error::invalid_params(
                "address must be 20 bytes",
            ));
        }
        let mut addr_arr = [0u8; 20];
        addr_arr.copy_from_slice(&addr_bytes);
        let address = Address(addr_arr);

        // slot (required, up to 32 bytes — left-pad if shorter). Foundry
        // sends both `"0x0"` and `"0x00000…0001"` interchangeably.
        let slot_str = parsed[1]
            .as_str()
            .ok_or_else(|| jsonrpc_core::Error::invalid_params("slot must be a hex string"))?;
        let slot_hex = slot_str.trim_start_matches("0x");
        let slot_padded_hex = if slot_hex.len() % 2 == 1 {
            format!("0{slot_hex}")
        } else {
            slot_hex.to_string()
        };
        let mut slot_bytes = hex::decode(&slot_padded_hex).map_err(|e| {
            jsonrpc_core::Error::invalid_params(format!("bad slot hex: {e}"))
        })?;
        if slot_bytes.len() > 32 {
            return Err(jsonrpc_core::Error::invalid_params(
                "slot must be ≤ 32 bytes",
            ));
        }
        let mut slot_key = vec![0u8; 32 - slot_bytes.len()];
        slot_key.append(&mut slot_bytes);

        // The 3rd param (blockTag) is parsed for forwards-compat with the
        // standard signature but we always serve latest.

        match block_on(state_api.get_storage(address, slot_key)) {
            Ok(value) => {
                // Always return left-padded 32-byte hex.
                let mut padded = vec![0u8; 32];
                let len = value.len().min(32);
                if len > 0 {
                    let src_start = value.len().saturating_sub(len);
                    padded[32 - len..].copy_from_slice(&value[src_start..]);
                }
                Ok(Value::String(format!("0x{}", hex::encode(padded))))
            }
            Err(_) => Ok(Value::String(format!("0x{}", "0".repeat(64)))),
        }
    });

    // eth_getBlockTransactionCountByNumber(blockTag) — uint count.
    let storage_btcbn = storage.clone();
    io_handler.add_sync_method(
        "eth_getBlockTransactionCountByNumber",
        move |params: Params| {
            let api = ChainApi::new(storage_btcbn.clone());
            let parsed: Vec<Value> = params
                .parse()
                .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
            if parsed.is_empty() {
                return Err(jsonrpc_core::Error::invalid_params("missing block tag"));
            }
            let number = match parsed[0].as_str() {
                Some("latest") | Some("pending") => block_on(api.get_height()).unwrap_or(0),
                Some("earliest") => 0,
                Some(s) if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16)
                    .map_err(|_| jsonrpc_core::Error::invalid_params("bad hex block number"))?,
                _ => return Err(jsonrpc_core::Error::invalid_params("bad block tag")),
            };
            match block_on(api.get_block(crate::types::request::BlockId::Number(number))) {
                Ok(block) => Ok(Value::String(format!("0x{:x}", block.transactions.len()))),
                Err(_) => Ok(Value::Null),
            }
        },
    );

    // eth_getBlockTransactionCountByHash(blockHash) — uint count.
    let storage_btcbh = storage.clone();
    io_handler.add_sync_method(
        "eth_getBlockTransactionCountByHash",
        move |params: Params| {
            let api = ChainApi::new(storage_btcbh.clone());
            let parsed: Vec<Value> = params
                .parse()
                .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
            if parsed.is_empty() {
                return Err(jsonrpc_core::Error::invalid_params("missing block hash"));
            }
            let hex_str = parsed[0]
                .as_str()
                .map(|s| s.trim_start_matches("0x"))
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("hash must be a string"))?;
            let bytes = hex::decode(hex_str)
                .map_err(|e| jsonrpc_core::Error::invalid_params(format!("bad hash hex: {e}")))?;
            if bytes.len() != 32 {
                return Err(jsonrpc_core::Error::invalid_params("hash must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let hash = Hash::new(arr);
            match block_on(api.get_block(crate::types::request::BlockId::Hash(hash))) {
                Ok(block) => Ok(Value::String(format!("0x{:x}", block.transactions.len()))),
                Err(_) => Ok(Value::Null),
            }
        },
    );

    // eth_getTransactionByBlockNumberAndIndex(blockTag, index) — full tx
    // object at position `index` of the block. Used by `cast block --index`
    // and Foundry's broadcast verification.
    let storage_tbni = storage.clone();
    io_handler.add_sync_method(
        "eth_getTransactionByBlockNumberAndIndex",
        move |params: Params| {
            let api = ChainApi::new(storage_tbni.clone());
            let parsed: Vec<Value> = params
                .parse()
                .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
            if parsed.len() < 2 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "expected [blockTag, index]",
                ));
            }
            let number = match parsed[0].as_str() {
                Some("latest") | Some("pending") => block_on(api.get_height()).unwrap_or(0),
                Some("earliest") => 0,
                Some(s) if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16)
                    .map_err(|_| jsonrpc_core::Error::invalid_params("bad hex block number"))?,
                _ => return Err(jsonrpc_core::Error::invalid_params("bad block tag")),
            };
            let idx_str = parsed[1]
                .as_str()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("index must be hex string"))?;
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16)
                .map_err(|_| jsonrpc_core::Error::invalid_params("bad hex index"))?;
            let block = match block_on(api.get_block(crate::types::request::BlockId::Number(number)))
            {
                Ok(b) => b,
                Err(_) => return Ok(Value::Null),
            };
            if let Some(tx) = block.transactions.get(idx) {
                Ok(json!({
                    "hash": format!("0x{}", hex::encode(tx.hash.as_bytes())),
                    "from": pubkey_hex_to_evm_address(&tx.from),
                    "to": pubkey_hex_opt_to_evm_address(tx.to.as_ref()),
                    "value": format!("0x{:x}", tx.value),
                    "gas": format!("0x{:x}", tx.gas_limit),
                    "gasPrice": format!("0x{:x}", tx.gas_price),
                    "nonce": format!("0x{:x}", tx.nonce),
                    "input": format!("0x{}", hex::encode(&tx.data)),
                    "blockHash": format!("0x{}", hex::encode(block.hash.as_bytes())),
                    "blockNumber": format!("0x{:x}", block.height),
                    "transactionIndex": format!("0x{:x}", idx),
                }))
            } else {
                Ok(Value::Null)
            }
        },
    );

    // eth_getTransactionByBlockHashAndIndex(blockHash, index) — same
    // shape, address by block hash.
    let storage_tbhi = storage.clone();
    io_handler.add_sync_method(
        "eth_getTransactionByBlockHashAndIndex",
        move |params: Params| {
            let api = ChainApi::new(storage_tbhi.clone());
            let parsed: Vec<Value> = params
                .parse()
                .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
            if parsed.len() < 2 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "expected [blockHash, index]",
                ));
            }
            let hex_str = parsed[0]
                .as_str()
                .map(|s| s.trim_start_matches("0x"))
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("hash must be a string"))?;
            let bytes = hex::decode(hex_str)
                .map_err(|e| jsonrpc_core::Error::invalid_params(format!("bad hash hex: {e}")))?;
            if bytes.len() != 32 {
                return Err(jsonrpc_core::Error::invalid_params("hash must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let hash = Hash::new(arr);
            let idx_str = parsed[1]
                .as_str()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("index must be hex string"))?;
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16)
                .map_err(|_| jsonrpc_core::Error::invalid_params("bad hex index"))?;
            let block = match block_on(api.get_block(crate::types::request::BlockId::Hash(hash))) {
                Ok(b) => b,
                Err(_) => return Ok(Value::Null),
            };
            if let Some(tx) = block.transactions.get(idx) {
                Ok(json!({
                    "hash": format!("0x{}", hex::encode(tx.hash.as_bytes())),
                    "from": pubkey_hex_to_evm_address(&tx.from),
                    "to": pubkey_hex_opt_to_evm_address(tx.to.as_ref()),
                    "value": format!("0x{:x}", tx.value),
                    "gas": format!("0x{:x}", tx.gas_limit),
                    "gasPrice": format!("0x{:x}", tx.gas_price),
                    "nonce": format!("0x{:x}", tx.nonce),
                    "input": format!("0x{}", hex::encode(&tx.data)),
                    "blockHash": format!("0x{}", hex::encode(block.hash.as_bytes())),
                    "blockNumber": format!("0x{:x}", block.height),
                    "transactionIndex": format!("0x{:x}", idx),
                }))
            } else {
                Ok(Value::Null)
            }
        },
    );

    // eth_accounts — read-only RPC always returns []. Wallets that
    // expect "the node has unlocked accounts" should look elsewhere
    // (and shouldn't — partners sign client-side and submit raw).
    io_handler.add_sync_method("eth_accounts", |_params: Params| {
        Ok(Value::Array(vec![]))
    });

    // eth_mining — block production is internal; RPC doesn't expose it.
    // Returning false stops tools from probing eth_hashrate / pendingWork.
    io_handler.add_sync_method("eth_mining", |_params: Params| {
        Ok(Value::Bool(false))
    });

    // eth_hashrate — we're not PoW; canonical zero.
    io_handler.add_sync_method("eth_hashrate", |_params: Params| {
        Ok(Value::String("0x0".to_string()))
    });

    // eth_protocolVersion — Ethereum wire-protocol version. 0x41 = 65,
    // the modern post-merge eth/68 number. Cosmetic; some old clients
    // refuse to connect if this is missing.
    io_handler.add_sync_method("eth_protocolVersion", |_params: Params| {
        Ok(Value::String("0x41".to_string()))
    });

    // eth_coinbase — current block producer's address. Read from the
    // executor's block context (set by the producer on each block).
    let executor_cb = executor.clone();
    io_handler.add_sync_method("eth_coinbase", move |_params: Params| {
        let cb = executor_cb.get_block_context().coinbase;
        Ok(Value::String(format!("0x{}", hex::encode(cb))))
    });

    // web3_sha3(data) — keccak256(data). Pure utility; some scripts
    // use it instead of computing locally.
    io_handler.add_sync_method("web3_sha3", |params: Params| {
        use sha3::{Digest, Keccak256};
        let parsed: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| jsonrpc_core::Error::invalid_params(e.to_string()))?;
        if parsed.is_empty() {
            return Err(jsonrpc_core::Error::invalid_params("missing data"));
        }
        let hex_str = parsed[0]
            .as_str()
            .map(|s| s.trim_start_matches("0x"))
            .ok_or_else(|| jsonrpc_core::Error::invalid_params("data must be hex string"))?;
        let bytes = hex::decode(hex_str)
            .map_err(|e| jsonrpc_core::Error::invalid_params(format!("bad hex: {e}")))?;
        let hash = Keccak256::digest(&bytes);
        Ok(Value::String(format!("0x{}", hex::encode(hash))))
    });

    // citrate_getDagStats - Get DAG statistics including tips, height, and GhostDAG parameters
    let storage_dag = storage.clone();
    io_handler.add_sync_method("citrate_getDagStats", move |_params: Params| {
        let api = ChainApi::new(storage_dag.clone());

        // Get current tips
        let tips = block_on(api.get_tips()).unwrap_or_default();

        // Get current height
        let height = block_on(api.get_height()).unwrap_or_default();

        // Get blue score from the highest tip block
        let mut blue_score = 0u64;
        if let Some(tip_hash) = tips.first() {
            if let Ok(block) = block_on(api.get_block(crate::types::request::BlockId::Hash(*tip_hash))) {
                blue_score = block.blue_score;
            }
        }

        // Use default GhostDAG params (network-wide constants)
        let ghostdag_params = citrate_consensus::types::GhostDagParams::default();

        // Convert tips to hex strings
        let tips_hex: Vec<String> = tips.iter()
            .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
            .collect();

        // For total/blue/red counts, we use height as approximation
        // In a DAG, most blocks are blue (honest), so we estimate ~95% blue
        let total_blocks = height;
        let blue_blocks = (height as f64 * 0.95) as u64;
        let red_blocks = total_blocks.saturating_sub(blue_blocks);

        Ok(json!({
            "totalBlocks": total_blocks,
            "blueBlocks": blue_blocks,
            "redBlocks": red_blocks,
            "tipsCount": tips.len(),
            "maxBlueScore": blue_score,
            "currentTips": tips_hex,
            "height": height,
            "ghostdagParams": {
                "k": ghostdag_params.k,
                "maxParents": ghostdag_params.max_parents,
                "maxBlueScoreDiff": ghostdag_params.max_blue_score_diff,
                "pruningWindow": ghostdag_params.pruning_window,
                "finalityDepth": ghostdag_params.finality_depth
            }
        }))
    });

    // citrate_emergencyPause - Pause block production
    // SECREM-01 API-1: these methods authenticate INSIDE the handler via
    // the env-token path (`require_operator_auth`, CITRATE_OPERATOR_TOKEN).
    // The previous gate read a `thread_local!` flag set by the rate-limit
    // middleware — on a multi-threaded tokio runtime the handler can run
    // on a different worker than `on_request`, so the flag reflected
    // whichever request last touched that thread: a concurrent
    // unauthenticated `citrate_emergencyPause` could observe a stale
    // `true` and HALT BLOCK PRODUCTION. Request-scoped authz must never
    // ride a thread-local across an async boundary.
    if let Some(ref flag) = pause_flag {
        fn emergency_params_map(
            params: Params,
        ) -> serde_json::Map<String, serde_json::Value> {
            match params {
                Params::Map(map) => map,
                Params::None => serde_json::Map::new(),
                Params::Array(arr) => {
                    if let Some(serde_json::Value::Object(map)) = arr.into_iter().next() {
                        map
                    } else {
                        serde_json::Map::new()
                    }
                }
            }
        }

        let pause_flag_pause = flag.clone();
        io_handler.add_sync_method("citrate_emergencyPause", move |params: Params| {
            crate::server::require_operator_auth(&emergency_params_map(params))?;
            pause_flag_pause.store(true, Ordering::Relaxed);
            tracing::warn!("EMERGENCY: Block production PAUSED via RPC");
            Ok(json!({"status": "paused", "message": "Block production paused"}))
        });

        let pause_flag_resume = flag.clone();
        io_handler.add_sync_method("citrate_emergencyResume", move |params: Params| {
            crate::server::require_operator_auth(&emergency_params_map(params))?;
            pause_flag_resume.store(false, Ordering::Relaxed);
            tracing::info!("Block production RESUMED via RPC");
            Ok(json!({"status": "resumed", "message": "Block production resumed"}))
        });

        let pause_flag_status = flag.clone();
        io_handler.add_sync_method("citrate_emergencyStatus", move |params: Params| {
            crate::server::require_operator_auth(&emergency_params_map(params))?;
            let paused = pause_flag_status.load(Ordering::Relaxed);
            Ok(json!({"paused": paused}))
        });

        // ---------------------------------------------------------------
        // Institutional economics RPC methods (Sprint T)
        // ---------------------------------------------------------------

        // citrate_estimateInstitutionalRewards — project monthly rewards
        io_handler.add_sync_method("citrate_estimateInstitutionalRewards", move |params: Params| {
            let params: Vec<Value> = params.parse().unwrap_or_default();

            let expected_uptime = params.first()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.95);
            let models_to_host = params.get(1)
                .and_then(|v| v.as_u64())
                .unwrap_or(2) as u32;
            let adapters_per_month = params.get(2)
                .and_then(|v| v.as_u64())
                .unwrap_or(3) as u32;
            let datasets_per_month = params.get(3)
                .and_then(|v| v.as_u64())
                .unwrap_or(5) as u32;
            let projection_months = params.get(4)
                .and_then(|v| v.as_u64())
                .unwrap_or(12) as u32;

            let config = InstitutionalRewardConfig::default();
            let estimator = InstitutionalRewardEstimator::new(config);
            let est_params = EstimationParams {
                expected_uptime,
                models_to_host,
                adapters_per_month,
                datasets_per_month,
                projection_months,
            };

            let result = estimator.estimate(&est_params);

            let monthly: Vec<Value> = result.monthly_projections.iter().map(|m| {
                json!({
                    "month": m.month,
                    "blockValidationSalt": m.block_validation_salt,
                    "modelHostingSalt": m.model_hosting_salt,
                    "adapterCreationSalt": m.adapter_creation_salt,
                    "dataProvisionSalt": m.data_provision_salt,
                    "totalSalt": m.total_salt,
                    "cumulativeSalt": m.cumulative_salt,
                })
            }).collect();

            Ok(json!({
                "monthlyProjections": monthly,
                "totalProjectedSalt": result.total_projected_salt,
                "averageMonthlySalt": result.average_monthly_salt,
                "minMonthlySalt": result.min_monthly_salt,
                "maxMonthlySalt": result.max_monthly_salt,
            }))
        });

        // citrate_getInstitutionalConfig — return current reward + slashing config
        io_handler.add_sync_method("citrate_getInstitutionalConfig", move |_params: Params| {
            let reward_config = InstitutionalRewardConfig::default();
            let slashing_config = InstitutionalSlashingConfig::default();

            Ok(json!({
                "rewards": {
                    "blockValidationMonthlySalt": reward_config.block_validation_monthly_salt,
                    "uptimeBonusMultiplier": reward_config.uptime_bonus_multiplier,
                    "modelHostingPerModelSalt": reward_config.model_hosting_per_model_salt,
                    "adapterCreationSalt": reward_config.adapter_creation_salt,
                    "dataProvisionPerDatasetSalt": reward_config.data_provision_per_dataset_salt,
                    "minUptimeThreshold": reward_config.min_uptime_threshold,
                    "maxRewardedModels": reward_config.max_rewarded_models,
                    "maxRewardedAdaptersPerEpoch": reward_config.max_rewarded_adapters_per_epoch,
                    "maxRewardedDatasetsPerEpoch": reward_config.max_rewarded_datasets_per_epoch,
                },
                "slashing": {
                    "equivocationPenaltyPct": slashing_config.equivocation_penalty_pct,
                    "invalidStatePenaltyPct": slashing_config.invalid_state_penalty_pct,
                    "censorshipPenaltyPct": slashing_config.censorship_penalty_pct,
                    "firstOffenseGraceEpochs": slashing_config.first_offense_grace_epochs,
                    "cooldownEpochs": slashing_config.cooldown_epochs,
                    "maxCumulativeSlashPct": slashing_config.max_cumulative_slash_pct,
                    "penalizeDowntime": slashing_config.penalize_downtime,
                }
            }))
        });

        // citrate_registerSchoolNode — register a new institutional operator
        io_handler.add_sync_method("citrate_registerSchoolNode", move |params: Params| {
            let params: Vec<Value> = match params.parse() {
                Ok(p) => p,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            let institution_name = params.first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing institution_name"))?
                .to_string();

            let contact_email = params.get(1)
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing contact_email"))?
                .to_string();

            let operator_address_hex = params.get(2)
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing operator_address"))?;

            let addr_hex = operator_address_hex.strip_prefix("0x").unwrap_or(operator_address_hex);
            let addr_bytes = hex::decode(addr_hex)
                .map_err(|e| jsonrpc_core::Error::invalid_params(format!("Invalid address hex: {}", e)))?;

            if addr_bytes.len() < 20 {
                return Err(jsonrpc_core::Error::invalid_params("Address must be at least 20 bytes"));
            }

            let mut addr_arr = [0u8; 20];
            addr_arr.copy_from_slice(&addr_bytes[..20]);
            let address = Address(addr_arr);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let profile = InstitutionalOperatorProfile::new(
                address,
                institution_name.clone(),
                contact_email.clone(),
                now,
            );

            Ok(json!({
                "status": "registered",
                "institutionName": profile.institution_name,
                "contactEmail": profile.contact_email,
                "operatorAddress": format!("0x{}", hex::encode(addr_arr)),
                "registeredAt": profile.registered_at,
                "isActive": profile.is_active,
                "currentEpoch": profile.current_epoch,
            }))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------------------------------------------------------------
    // pubkey_hex_to_evm_address tests
    // ---------------------------------------------------------------

    /// 1. 64-char hex with trailing 24 zeros (embedded EVM address) → first 40 chars
    #[test]
    fn test_evm_address_embedded() {
        // 20 bytes of real address + 12 bytes of zeros = 40 hex chars + 24 '0' chars
        let input = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000";
        let result = pubkey_hex_to_evm_address(input);
        assert_eq!(result, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    }

    /// 2. 64-char hex without trailing zeros (full pubkey) → first 40 chars
    #[test]
    fn test_evm_address_full_pubkey() {
        let input = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let result = pubkey_hex_to_evm_address(input);
        assert_eq!(result, "0xabcdef1234567890abcdef1234567890abcdef12");
    }

    /// 3. Less than 40 chars → returned as-is with "0x" prefix
    #[test]
    fn test_evm_address_short_input() {
        let input = "deadbeef";
        let result = pubkey_hex_to_evm_address(input);
        assert_eq!(result, "0xdeadbeef");
    }

    /// 4. Exactly 40 chars → "0x" + all 40 chars
    #[test]
    fn test_evm_address_exact_40() {
        let input = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let result = pubkey_hex_to_evm_address(input);
        assert_eq!(result, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    }

    /// 5. 64 zeros → still returns first 40 chars (all zeros, not empty)
    #[test]
    fn test_evm_address_all_zeros() {
        let input = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = pubkey_hex_to_evm_address(input);
        // The first 20 bytes are all zeros, and last 12 bytes are zeros too,
        // so the trailing-zeros branch triggers → first 40 chars.
        assert_eq!(result, "0x0000000000000000000000000000000000000000");
    }

    /// 6. Result always starts with "0x"
    #[test]
    fn test_evm_address_prefix_format() {
        let inputs = vec![
            "ab",
            "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000",
        ];
        for input in inputs {
            let result = pubkey_hex_to_evm_address(input);
            assert!(
                result.starts_with("0x"),
                "Expected '0x' prefix for input '{}', got '{}'",
                input,
                result
            );
        }
    }

    // ---------------------------------------------------------------
    // pubkey_hex_opt_to_evm_address tests
    // ---------------------------------------------------------------

    /// 7. Some(hex) → Some(address)
    #[test]
    fn test_opt_some() {
        let hex = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000".to_string();
        let result = pubkey_hex_opt_to_evm_address(Some(&hex));
        assert_eq!(
            result,
            Some("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string())
        );
    }

    /// 8. None → None
    #[test]
    fn test_opt_none() {
        let result = pubkey_hex_opt_to_evm_address(None);
        assert_eq!(result, None);
    }

    // ---------------------------------------------------------------
    // append_eip_fields tests
    // ---------------------------------------------------------------

    /// Helper: create an empty serde_json::Map
    fn empty_map() -> serde_json::Map<String, Value> {
        serde_json::Map::new()
    }

    /// 9. Type 0: only "type" field added, no accessList or maxFee fields
    #[test]
    fn test_eip_type0() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 0, None, None, None, &None);
        assert_eq!(map.get("type"), Some(&json!("0x0")));
        assert!(map.get("accessList").is_none(), "type 0 should not have accessList");
        assert!(map.get("maxFeePerGas").is_none(), "type 0 should not have maxFeePerGas");
        assert!(
            map.get("maxPriorityFeePerGas").is_none(),
            "type 0 should not have maxPriorityFeePerGas"
        );
    }

    /// 10. Type 1: "type" + "accessList" added, no maxFee fields
    #[test]
    fn test_eip_type1() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 1, None, Some(100), Some(10), &None);
        assert_eq!(map.get("type"), Some(&json!("0x1")));
        // accessList should be present (empty array since access_list is None)
        assert!(map.get("accessList").is_some(), "type 1 should have accessList");
        // maxFeePerGas should NOT be present for type 1 even if values were passed
        assert!(
            map.get("maxFeePerGas").is_none(),
            "type 1 should not have maxFeePerGas"
        );
        assert!(
            map.get("maxPriorityFeePerGas").is_none(),
            "type 1 should not have maxPriorityFeePerGas"
        );
    }

    /// 11. Type 2: "type" + "accessList" + "maxFeePerGas" + "maxPriorityFeePerGas"
    #[test]
    fn test_eip_type2() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 2, None, Some(1000), Some(50), &None);
        assert_eq!(map.get("type"), Some(&json!("0x2")));
        assert!(map.get("accessList").is_some(), "type 2 should have accessList");
        assert_eq!(map.get("maxFeePerGas"), Some(&json!("0x3e8")));
        assert_eq!(map.get("maxPriorityFeePerGas"), Some(&json!("0x32")));
    }

    /// 12. chain_id Some(40204) → "chainId": "0x9d0c"
    #[test]
    fn test_eip_chain_id() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 0, Some(40204), None, None, &None);
        assert_eq!(map.get("chainId"), Some(&json!("0x9d0c")));
    }

    /// 13. chain_id None → no "chainId" key in map
    #[test]
    fn test_eip_no_chain_id() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 0, None, None, None, &None);
        assert!(map.get("chainId").is_none(), "chainId should not be present when None");
    }

    /// 14. access list with entries → proper JSON array of {address, storageKeys}
    #[test]
    fn test_eip_access_list_serialization() {
        let mut map = empty_map();
        let addr = vec![0xde, 0xad, 0xbe, 0xef];
        let key1 = vec![0x01, 0x02, 0x03];
        let key2 = vec![0x04, 0x05, 0x06];
        let access_list = Some(vec![(addr.clone(), vec![key1.clone(), key2.clone()])]);
        append_eip_fields(&mut map, 1, None, None, None, &access_list);

        let al = map.get("accessList").expect("accessList should be present");
        let arr = al.as_array().expect("accessList should be an array");
        assert_eq!(arr.len(), 1);

        let entry = &arr[0];
        assert_eq!(entry["address"], json!(format!("0x{}", hex::encode(&addr))));

        let storage_keys = entry["storageKeys"].as_array().expect("storageKeys should be array");
        assert_eq!(storage_keys.len(), 2);
        assert_eq!(storage_keys[0], json!(format!("0x{}", hex::encode(&key1))));
        assert_eq!(storage_keys[1], json!(format!("0x{}", hex::encode(&key2))));
    }

    /// 15. None access list → empty array for type >= 1
    #[test]
    fn test_eip_empty_access_list() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 1, None, None, None, &None);
        let al = map.get("accessList").expect("accessList should be present");
        let arr = al.as_array().expect("accessList should be an array");
        assert!(arr.is_empty(), "accessList should be empty when input is None");
    }

    /// 16. Type hex format: type 2 → "0x2", type 1 → "0x1"
    #[test]
    fn test_eip_type_hex_format() {
        let mut map1 = empty_map();
        append_eip_fields(&mut map1, 1, None, None, None, &None);
        assert_eq!(map1.get("type"), Some(&json!("0x1")));

        let mut map2 = empty_map();
        append_eip_fields(&mut map2, 2, None, None, None, &None);
        assert_eq!(map2.get("type"), Some(&json!("0x2")));

        let mut map0 = empty_map();
        append_eip_fields(&mut map0, 0, None, None, None, &None);
        assert_eq!(map0.get("type"), Some(&json!("0x0")));
    }

    /// 17. Type 1 should NOT have maxFeePerGas even if values are provided
    #[test]
    fn test_eip_max_fee_only_for_type2() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 1, None, Some(999), Some(111), &None);
        assert!(
            map.get("maxFeePerGas").is_none(),
            "type 1 should never insert maxFeePerGas"
        );
        assert!(
            map.get("maxPriorityFeePerGas").is_none(),
            "type 1 should never insert maxPriorityFeePerGas"
        );
    }

    /// 18. Type 2 with None fees → fee fields not inserted
    #[test]
    fn test_eip_type2_missing_fees() {
        let mut map = empty_map();
        append_eip_fields(&mut map, 2, None, None, None, &None);
        assert!(
            map.get("maxFeePerGas").is_none(),
            "maxFeePerGas should not be inserted when None"
        );
        assert!(
            map.get("maxPriorityFeePerGas").is_none(),
            "maxPriorityFeePerGas should not be inserted when None"
        );
        // accessList should still be present for type 2
        assert!(map.get("accessList").is_some());
    }

    // ---------------------------------------------------------------
    // hex format / roundtrip tests
    // ---------------------------------------------------------------

    /// 19. hex::encode + decode identity roundtrip
    #[test]
    fn test_hex_roundtrip() {
        let original: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let encoded = hex::encode(&original);
        let decoded = hex::decode(&encoded).expect("hex::decode should succeed");
        assert_eq!(original, decoded);
    }

    /// 20. Output address always has "0x" prefix followed by even-length hex
    #[test]
    fn test_address_length_consistency() {
        let test_cases = vec![
            // (input, expected_total_len including "0x")
            // Short input: "0x" + 8 chars = 10
            ("deadbeef", 10),
            // 40-char input: "0x" + 40 = 42
            ("f39fd6e51aad88f6f4ce6ab8827279cfffb92266", 42),
            // 64-char embedded: "0x" + 40 = 42
            (
                "f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000",
                42,
            ),
            // 64-char full pubkey: "0x" + 40 = 42
            (
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                42,
            ),
        ];
        for (input, expected_len) in test_cases {
            let result = pubkey_hex_to_evm_address(input);
            assert!(result.starts_with("0x"), "must start with 0x");
            assert_eq!(
                result.len(),
                expected_len,
                "For input '{}', expected len {} but got {} ('{}')",
                input,
                expected_len,
                result.len(),
                result
            );
            // The hex portion (after "0x") should have even length
            let hex_part = &result[2..];
            assert_eq!(
                hex_part.len() % 2,
                0,
                "Hex portion should have even length for input '{}'",
                input
            );
        }
    }
}
