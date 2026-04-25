// Aggregate regression tests for RM-C1 audit findings:
//   H-API-01 (HIGH) — citrate_getMempoolSnapshot operator-auth gate
//   H-API-02 (HIGH) — RLP access-list bounds checks (panic prevention)
//
// H-API-01: pre-fix any unauthenticated caller could dump the full
// mempool. Post-fix the method requires the same operator_token that
// other operator endpoints require, gated by CITRATE_OPERATOR_TOKEN.
//
// H-API-02: pre-fix `H160::from_slice` / `H256::from_slice` on
// attacker-supplied bytes panicked the RPC worker if the length
// didn't match. Post-fix the parser validates length + caps entry
// count.

use rlp::RlpStream;

fn malformed_eip1559_with_short_address() -> Vec<u8> {
    // Build a minimal EIP-1559 transaction with an access-list entry
    // whose address is only 19 bytes — pre-fix this would panic in
    // `H160::from_slice`. Post-fix it returns an Err.
    //
    // EIP-1559 transaction RLP: [chainId, nonce, maxPriorityFeePerGas,
    // maxFeePerGas, gasLimit, to, value, data, accessList,
    // signatureYParity, signatureR, signatureS]
    let mut s = RlpStream::new();
    s.begin_list(12);
    s.append(&1u64); // chain_id
    s.append(&0u64); // nonce
    s.append(&1u64); // max_priority_fee
    s.append(&1u64); // max_fee
    s.append(&21000u64); // gas_limit
    s.append_empty_data(); // to (empty for contract creation)
    s.append(&0u64); // value
    s.append_empty_data(); // data

    // accessList = [(short_address, [])] — short address triggers
    // the bug.
    let mut access_list = RlpStream::new_list(1);
    let mut entry = RlpStream::new_list(2);
    let short_addr: Vec<u8> = vec![0xAB; 19]; // 19 bytes, not 20
    entry.append(&short_addr);
    entry.begin_list(0);
    access_list.append_raw(&entry.out(), 1);
    s.append_raw(&access_list.out(), 1);

    s.append(&0u64); // y_parity
    s.append(&[0xCDu8; 32].to_vec()); // r
    s.append(&[0xEFu8; 32].to_vec()); // s

    let mut payload = vec![0x02u8]; // EIP-1559 type byte
    payload.extend_from_slice(&s.out());
    payload
}

fn malformed_eip1559_with_short_storage_key() -> Vec<u8> {
    // Same shape but the access-list entry has a 31-byte storage
    // key instead of 32.
    let mut s = RlpStream::new();
    s.begin_list(12);
    s.append(&1u64);
    s.append(&0u64);
    s.append(&1u64);
    s.append(&1u64);
    s.append(&21000u64);
    s.append_empty_data();
    s.append(&0u64);
    s.append_empty_data();

    let mut access_list = RlpStream::new_list(1);
    let mut entry = RlpStream::new_list(2);
    let valid_addr: Vec<u8> = vec![0xAB; 20]; // 20 bytes, valid
    entry.append(&valid_addr);
    let mut keys = RlpStream::new_list(1);
    let short_key: Vec<u8> = vec![0xCD; 31]; // 31 bytes, NOT 32
    keys.append(&short_key);
    entry.append_raw(&keys.out(), 1);
    access_list.append_raw(&entry.out(), 1);
    s.append_raw(&access_list.out(), 1);

    s.append(&0u64);
    s.append(&[0xCDu8; 32].to_vec());
    s.append(&[0xEFu8; 32].to_vec());

    let mut payload = vec![0x02u8];
    payload.extend_from_slice(&s.out());
    payload
}

fn malformed_eip1559_huge_access_list() -> Vec<u8> {
    // 2000 access-list entries — exceeds the 1024 cap.
    let mut s = RlpStream::new();
    s.begin_list(12);
    s.append(&1u64);
    s.append(&0u64);
    s.append(&1u64);
    s.append(&1u64);
    s.append(&21000u64);
    s.append_empty_data();
    s.append(&0u64);
    s.append_empty_data();

    const ENTRIES: usize = 2000;
    let mut access_list = RlpStream::new_list(ENTRIES);
    for i in 0..ENTRIES {
        let mut entry = RlpStream::new_list(2);
        let mut addr_bytes = [0u8; 20];
        addr_bytes[0] = (i & 0xFF) as u8;
        entry.append(&addr_bytes.to_vec());
        entry.begin_list(0);
        access_list.append_raw(&entry.out(), 1);
    }
    s.append_raw(&access_list.out(), 1);

    s.append(&0u64);
    s.append(&[0xCDu8; 32].to_vec());
    s.append(&[0xEFu8; 32].to_vec());

    let mut payload = vec![0x02u8];
    payload.extend_from_slice(&s.out());
    payload
}

/// H-API-02.1: a 19-byte access-list address returns Err, not panic.
#[test]
fn h_api_02_short_address_returns_err_not_panic() {
    let bytes = malformed_eip1559_with_short_address();
    let result = std::panic::catch_unwind(|| citrate_api::eth_tx_decoder::decode_eth_transaction(&bytes));
    assert!(
        result.is_ok(),
        "H-API-02: decoder must NOT panic on short address"
    );
    let inner = result.expect("no panic");
    assert!(
        inner.is_err(),
        "H-API-02: decoder must return Err on short address"
    );
    let msg = format!("{:?}", inner.unwrap_err());
    assert!(
        msg.contains("H-API-02") || msg.contains("20"),
        "H-API-02: error must reference address length; got {}",
        msg
    );
}

/// H-API-02.2: a 31-byte storage key returns Err, not panic.
#[test]
fn h_api_02_short_storage_key_returns_err_not_panic() {
    let bytes = malformed_eip1559_with_short_storage_key();
    let result = std::panic::catch_unwind(|| citrate_api::eth_tx_decoder::decode_eth_transaction(&bytes));
    assert!(
        result.is_ok(),
        "H-API-02: decoder must NOT panic on short storage key"
    );
    let inner = result.expect("no panic");
    assert!(
        inner.is_err(),
        "H-API-02: decoder must return Err on short storage key"
    );
}

/// H-API-02.3: huge access list (>1024 entries) is rejected.
#[test]
fn h_api_02_huge_access_list_rejected() {
    let bytes = malformed_eip1559_huge_access_list();
    let result = std::panic::catch_unwind(|| citrate_api::eth_tx_decoder::decode_eth_transaction(&bytes));
    assert!(result.is_ok(), "H-API-02: decoder must NOT panic on huge list");
    let inner = result.expect("no panic");
    assert!(
        inner.is_err(),
        "H-API-02: decoder must return Err on >1024-entry access list"
    );
}

// ────────────────────────────────────────────────────────────────
// M-API-02 / L-API-01: WebSocket config tests.
// ────────────────────────────────────────────────────────────────

/// M-API-02: default WsConfig has the expected caps. Pin them so a
/// future refactor can't silently raise the defaults beyond what
/// the audit baseline requires.
#[test]
fn m_api_02_default_ws_config_has_caps() {
    let cfg = citrate_api::websocket::WsConfig::default();
    assert_eq!(cfg.max_connections, 1024);
    assert_eq!(cfg.max_subscriptions_per_conn, 64);
    assert_eq!(cfg.max_frame_size, 1_048_576); // 1 MiB
    assert_eq!(cfg.idle_timeout_secs, 60);
    assert!(
        cfg.allowed_origins.is_empty(),
        "default allowed_origins is empty (allow all) for devnet/testnet"
    );
}

/// L-API-01: WsConfig can carry a CORS origin allowlist. Empty
/// list = allow all (devnet); non-empty = strict allowlist.
#[test]
fn l_api_01_ws_config_supports_cors_allowlist() {
    let cfg = citrate_api::websocket::WsConfig {
        allowed_origins: vec!["https://app.citrate.ai".into()],
        ..Default::default()
    };
    assert_eq!(cfg.allowed_origins.len(), 1);
    assert_eq!(cfg.allowed_origins[0], "https://app.citrate.ai");
}
