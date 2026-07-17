//! VALIDATOR-S1 (v5) registration ceremony — WS-5 reroll seed tool.
//!
//! For each fleet node this binary:
//!   1. Derives the node's ed25519 **proposer key** from its coinbase, BYTE-FOR-BYTE
//!      with `node/src/main.rs` (`Sha3_256(b"citrate-block-signing-key-v1" ‖ coinbase32)`
//!      → `Ed25519SigningKey::from_bytes`). The registered pubkey is
//!      `verifying_key().to_bytes()`.
//!   2. Reads the staker's on-chain `registrationNonce` (eth_call), builds the
//!      Register EIP-712 digest via `citrate_consensus::crypto::registration_digest`
//!      (the SAME bytes the contract reconstructs), and ed25519-signs it.
//!   3. Signs a legacy EIP-155 `registerValidator(bytes32,bytes)` transaction from
//!      the funded **staker EOA** (msg.sender = staker, msg.value = stake) and
//!      submits it via `eth_sendRawTransaction`, then polls the receipt.
//!
//! SEED-TIMING GUARD: registration MUST land before snapshot S(1)=800 or the node
//! is excluded from the epoch-1 active set and cannot propose at/after the 1000
//! activation height. The tool refuses (unless `--force`) to submit once the chain
//! is within a safety margin of height 800.
//!
//! Keys are never taken on the command line: each staker private key is read from a
//! named environment variable. Public coinbases ARE passed on the CLI.
//!
//! Mock budget: 0. No `.unwrap()`. Real RPC, real signatures, real submission.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use citrate_consensus::crypto::{registration_digest, Ed25519SigningKey};
use citrate_wallet_core::{sign_eip155_legacy_tx, LegacyTxFields};
use clap::Parser;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256, Sha3_256};

/// The exact domain-separation string `node/src/main.rs` hashes before the
/// coinbase to derive the block-signing (proposer) key. MUST match byte-for-byte.
const PROPOSER_KEY_DOMAIN: &[u8] = b"citrate-block-signing-key-v1";

/// Snapshot geometry (mirrors ValidatorRegistry EPOCH=1000, SNAPSHOT_LAG=200):
/// the epoch-1 snapshot is taken at S(1) = 1*1000 - 200 = 800. A registration must
/// be MINED by then to be in the epoch-1 active set.
const FIRST_SNAPSHOT_HEIGHT: u64 = 800;
/// Default block-height safety margin before S(1)=800 at which the tool refuses.
const DEFAULT_SEED_MARGIN_BLOCKS: u64 = 100;

#[derive(Parser, Debug)]
#[command(
    name = "validator-registration-ceremony",
    about = "VALIDATOR-S1 registration ceremony: derive proposer keys from fleet coinbases and register validators on-chain (WS-5)."
)]
struct Cli {
    /// JSON-RPC endpoint of a reroll node (e.g. http://127.0.0.1:8545).
    #[arg(long, env = "CITRATE_RPC_URL")]
    rpc_url: String,

    /// Deployed ValidatorRegistry address (0x-hex, 20 bytes).
    #[arg(long, env = "CITRATE_VALIDATOR_REGISTRY")]
    registry: String,

    /// EIP-155 chain id.
    #[arg(long, default_value_t = 40204)]
    chain_id: u64,

    /// Stake to bond per validator, in whole SALT. Must be >= the registry minStake
    /// (owner-decided 32_000). Sent as msg.value on registerValidator.
    #[arg(long, default_value_t = 32_000)]
    stake_salt: u64,

    /// Gas price in wei for the registration tx.
    #[arg(long, default_value_t = 1_000_000_000)]
    gas_price: u64,

    /// Gas limit for the registration tx.
    #[arg(long, default_value_t = 600_000)]
    gas_limit: u64,

    /// One per fleet node, repeatable. Format: `<coinbase_hex>=<STAKER_KEY_ENV_VAR>`,
    /// where the coinbase is the node's PUBLIC 20-byte address and the env var holds
    /// that validator's staker private key (0x-hex, 32 bytes). Example:
    ///   --node 0x47fb..36090=VALIDATOR_STAKER_1_PRIVATE_KEY
    /// The 4 fleet coinbases (rpc-1 + boot1/2/3) are NOT stored in the repo — the
    /// operator MUST supply them (one distinct coinbase per node, or all nodes derive
    /// the same proposer key and only one validator exists).
    #[arg(long = "node", required = true)]
    nodes: Vec<String>,

    /// Skip the S(1)=800 seed-timing guard (dangerous: a late registration misses the
    /// epoch-1 active set).
    #[arg(long, default_value_t = false)]
    force: bool,

    /// Build + sign + print everything but do NOT broadcast (offline rehearsal).
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// A parsed node spec: public coinbase + the staker key pulled from its env var.
struct NodeSpec {
    coinbase: [u8; 20],
    staker_key: Secp256k1SigningKey,
    staker_key_env: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let registry = parse_addr20(&cli.registry).context("--registry")?;
    let specs = parse_nodes(&cli.nodes)?;

    // Distinctness guard: one-staker-one-pubkey. Duplicate coinbases → duplicate
    // proposer keys → PubkeyTaken revert; duplicate stakers → StakerHasValidator.
    reject_duplicates(&specs)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    // Seed-timing guard (skipped under --dry-run/--force).
    if !cli.dry_run {
        let height = eth_block_number(&client, &cli.rpc_url)
            .await
            .context("eth_blockNumber (seed-timing guard)")?;
        let limit = FIRST_SNAPSHOT_HEIGHT.saturating_sub(DEFAULT_SEED_MARGIN_BLOCKS);
        println!(
            "chain height {} (epoch-1 snapshot S(1)={}, refuse-after {})",
            height, FIRST_SNAPSHOT_HEIGHT, limit
        );
        if height >= limit && !cli.force {
            bail!(
                "chain height {} is within the seed margin of S(1)={} — registrations may miss \
                 the epoch-1 active set. Re-roll and register earlier, or pass --force if you \
                 have verified the tx will mine before height {}.",
                height,
                FIRST_SNAPSHOT_HEIGHT,
                FIRST_SNAPSHOT_HEIGHT
            );
        }
    }

    let stake_wei = salt_to_wei(cli.stake_salt);

    for (i, spec) in specs.iter().enumerate() {
        println!("\n─── node #{} ───────────────────────────────", i + 1);
        register_one(&client, &cli, registry, stake_wei, spec).await?;
    }

    println!("\nAll {} registration(s) processed.", specs.len());
    Ok(())
}

async fn register_one(
    client: &reqwest::Client,
    cli: &Cli,
    registry: [u8; 20],
    stake_wei: u128,
    spec: &NodeSpec,
) -> Result<()> {
    // 1. Proposer key from coinbase (byte-for-byte with node/src/main.rs).
    let proposer = derive_proposer_key(&spec.coinbase);
    let proposer_pubkey: [u8; 32] = proposer.verifying_key().to_bytes();

    // Staker EVM address from its secp256k1 key.
    let staker = evm_address_of_secp256k1(&spec.staker_key);

    println!("coinbase        : 0x{}", hex::encode(spec.coinbase));
    println!("proposer pubkey : 0x{}", hex::encode(proposer_pubkey));
    println!("staker ({:<28}): 0x{}", spec.staker_key_env, hex::encode(staker));

    // 2. On-chain registrationNonce[staker] → the digest's replay nonce.
    let reg_nonce = if cli.dry_run {
        0
    } else {
        eth_registration_nonce(client, &cli.rpc_url, registry, &staker)
            .await
            .context("read registrationNonce[staker]")?
    };

    // Register digest (identical to what the contract reconstructs), then ed25519-sign
    // the 32-byte digest (the contract's `_ed25519Verify` message == abi.encodePacked(digest)).
    let digest = registration_digest(cli.chain_id, &registry, &staker, &proposer_pubkey, reg_nonce);
    let sig: ed25519_dalek::Signature = {
        use ed25519_dalek::Signer;
        proposer.sign(&digest)
    };
    let sig_bytes: [u8; 64] = sig.to_bytes();

    // Fail-fast: verify our own signature the way the 0x0120 precompile will (verify_strict).
    proposer
        .verifying_key()
        .verify_strict(&digest, &sig)
        .map_err(|e| anyhow!("self-verify of registration signature failed: {e}"))?;

    println!("register nonce  : {}", reg_nonce);
    println!("register digest : 0x{}", hex::encode(digest));

    // 3. registerValidator(bytes32,bytes) calldata.
    let calldata = encode_register_validator(&proposer_pubkey, &sig_bytes);

    if cli.dry_run {
        println!("[dry-run] calldata (0x{}...) — not broadcast", hex::encode(&calldata[..8]));
        return Ok(());
    }

    // EVM account nonce for the staker (pending) + a pre-flight balance sanity check.
    let acct_nonce = eth_transaction_count(client, &cli.rpc_url, &staker)
        .await
        .context("eth_getTransactionCount(staker)")?;
    let bal = eth_balance(client, &cli.rpc_url, &staker)
        .await
        .context("eth_getBalance(staker)")?;
    let needed = stake_wei + (cli.gas_price as u128) * (cli.gas_limit as u128);
    if bal < needed {
        bail!(
            "staker 0x{} balance {} wei < required {} wei (stake + max gas). Fund it in genesis.",
            hex::encode(staker),
            bal,
            needed
        );
    }

    let tx = LegacyTxFields {
        nonce: acct_nonce,
        gas_price: cli.gas_price,
        gas_limit: cli.gas_limit,
        to: Some(registry),
        value: stake_wei,
        data: calldata,
    };
    let signed = sign_eip155_legacy_tx(&spec.staker_key, &tx, cli.chain_id)
        .map_err(|e| anyhow!("sign registerValidator tx: {e}"))?;

    let tx_hash = eth_send_raw(client, &cli.rpc_url, &signed.raw)
        .await
        .context("eth_sendRawTransaction")?;
    println!("submitted tx    : {}", tx_hash);

    let ok = poll_receipt(client, &cli.rpc_url, &tx_hash).await?;
    if ok {
        println!("registered ✓ (receipt status 0x1)");
    } else {
        bail!("registration tx {} reverted (receipt status 0x0)", tx_hash);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto: proposer-key derivation + calldata/address encoding.
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the ed25519 proposer signing key from a 20-byte coinbase, reproducing
/// `node/src/main.rs` EXACTLY: the coinbase is zero-padded into a 32-byte buffer,
/// then `Sha3_256(DOMAIN ‖ coinbase32)` seeds `Ed25519SigningKey::from_bytes`.
fn derive_proposer_key(coinbase20: &[u8; 20]) -> Ed25519SigningKey {
    let mut coinbase32 = [0u8; 32];
    coinbase32[..20].copy_from_slice(coinbase20);

    let mut hasher = Sha3_256::new();
    hasher.update(PROPOSER_KEY_DOMAIN);
    hasher.update(coinbase32);
    let seed = hasher.finalize();
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&seed);
    Ed25519SigningKey::from_bytes(&seed_bytes)
}

/// ABI-encode `registerValidator(bytes32 proposerPubkey, bytes ed25519Sig)`.
/// Layout: selector ‖ pubkey(32) ‖ offset=0x40 ‖ len=64 ‖ sig(64). The 64-byte sig
/// is exactly two words, so no tail padding is required.
fn encode_register_validator(proposer_pubkey: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
    let selector = keccak256(b"registerValidator(bytes32,bytes)");
    let mut out = Vec::with_capacity(4 + 32 * 4 + 64);
    out.extend_from_slice(&selector[..4]);
    out.extend_from_slice(proposer_pubkey); // bytes32 (head)
    out.extend_from_slice(&word_u64(0x40)); // offset to the bytes tail
    out.extend_from_slice(&word_u64(64)); // bytes length
    out.extend_from_slice(sig); // 64 bytes == 2 words, already aligned
    out
}

/// EVM address of a secp256k1 key: keccak256(uncompressed_pubkey[1..])[12..32].
fn evm_address_of_secp256k1(key: &Secp256k1SigningKey) -> [u8; 20] {
    let vk = key.verifying_key();
    let point = vk.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn salt_to_wei(salt: u64) -> u128 {
    (salt as u128) * 1_000_000_000_000_000_000u128
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing / validation.
// ─────────────────────────────────────────────────────────────────────────────

fn parse_addr20(s: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x"))
        .with_context(|| format!("invalid hex address: {s}"))?;
    if bytes.len() != 20 {
        bail!("address must be 20 bytes, got {} ({s})", bytes.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_nodes(nodes: &[String]) -> Result<Vec<NodeSpec>> {
    let mut out = Vec::with_capacity(nodes.len());
    for spec in nodes {
        let (coinbase_str, env_name) = spec
            .split_once('=')
            .ok_or_else(|| anyhow!("--node must be <coinbase_hex>=<STAKER_KEY_ENV_VAR>, got: {spec}"))?;
        let coinbase = parse_addr20(coinbase_str).with_context(|| format!("--node coinbase in {spec}"))?;
        let key_hex = std::env::var(env_name)
            .map_err(|_| anyhow!("staker key env var `{env_name}` is not set (referenced by --node {spec})"))?;
        let key_bytes = hex::decode(key_hex.trim().trim_start_matches("0x"))
            .with_context(|| format!("staker key in `{env_name}` is not valid hex"))?;
        if key_bytes.len() != 32 {
            bail!("staker key in `{env_name}` must be 32 bytes, got {}", key_bytes.len());
        }
        let staker_key = Secp256k1SigningKey::from_slice(&key_bytes)
            .map_err(|e| anyhow!("staker key in `{env_name}` is not a valid secp256k1 key: {e}"))?;
        out.push(NodeSpec { coinbase, staker_key, staker_key_env: env_name.to_string() });
    }
    Ok(out)
}

/// Enforce one-staker-one-pubkey off-chain (the contract enforces it too, but a
/// duplicate here would waste gas on a guaranteed revert).
fn reject_duplicates(specs: &[NodeSpec]) -> Result<()> {
    for i in 0..specs.len() {
        for j in (i + 1)..specs.len() {
            if specs[i].coinbase == specs[j].coinbase {
                bail!(
                    "duplicate coinbase 0x{} (nodes #{} and #{}) — each node needs a DISTINCT \
                     coinbase or they derive the same proposer key",
                    hex::encode(specs[i].coinbase),
                    i + 1,
                    j + 1
                );
            }
            let a = evm_address_of_secp256k1(&specs[i].staker_key);
            let b = evm_address_of_secp256k1(&specs[j].staker_key);
            if a == b {
                bail!(
                    "duplicate staker 0x{} (nodes #{} and #{}) — one-staker-one-pubkey requires 4 \
                     distinct funded stakers",
                    hex::encode(a),
                    i + 1,
                    j + 1
                );
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC helpers (reqwest). All fail-closed with context; zero unwrap.
// ─────────────────────────────────────────────────────────────────────────────

async fn rpc(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Result<Value> {
    let resp = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .with_context(|| format!("POST {method} to {url}"))?;
    let body: Value = resp.json().await.with_context(|| format!("decode {method} response"))?;
    if let Some(err) = body.get("error") {
        bail!("{method} RPC error: {err}");
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method}: response missing `result`"))
}

fn hex_to_u64(v: &Value) -> Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected hex-string quantity, got {v}"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("parse quantity {s}"))
}

fn hex_to_u128(v: &Value) -> Result<u128> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected hex-string quantity, got {v}"))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16).with_context(|| format!("parse quantity {s}"))
}

async fn eth_block_number(client: &reqwest::Client, url: &str) -> Result<u64> {
    hex_to_u64(&rpc(client, url, "eth_blockNumber", json!([])).await?)
}

async fn eth_transaction_count(client: &reqwest::Client, url: &str, addr: &[u8; 20]) -> Result<u64> {
    hex_to_u64(&rpc(client, url, "eth_getTransactionCount", json!([addr_hex(addr), "pending"])).await?)
}

async fn eth_balance(client: &reqwest::Client, url: &str, addr: &[u8; 20]) -> Result<u128> {
    hex_to_u128(&rpc(client, url, "eth_getBalance", json!([addr_hex(addr), "latest"])).await?)
}

/// eth_call registrationNonce(address) → uint256 (fits u64 in practice).
async fn eth_registration_nonce(
    client: &reqwest::Client,
    url: &str,
    registry: [u8; 20],
    staker: &[u8; 20],
) -> Result<u64> {
    let selector = keccak256(b"registrationNonce(address)");
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&selector[..4]);
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(staker);
    data.extend_from_slice(&word);
    let ret = rpc(
        client,
        url,
        "eth_call",
        json!([{"to": addr_hex(&registry), "data": format!("0x{}", hex::encode(&data))}, "latest"]),
    )
    .await?;
    let s = ret.as_str().ok_or_else(|| anyhow!("eth_call returned non-string"))?;
    let bytes = hex::decode(s.trim_start_matches("0x")).context("decode registrationNonce return")?;
    if bytes.len() != 32 {
        bail!("registrationNonce return not 32 bytes ({} bytes)", bytes.len());
    }
    // Low 8 bytes of the big-endian uint256 (nonce never realistically exceeds u64).
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(b8))
}

async fn eth_send_raw(client: &reqwest::Client, url: &str, raw: &[u8]) -> Result<String> {
    let ret = rpc(client, url, "eth_sendRawTransaction", json!([format!("0x{}", hex::encode(raw))])).await?;
    ret.as_str().map(|s| s.to_string()).ok_or_else(|| anyhow!("eth_sendRawTransaction returned non-string"))
}

/// Poll up to ~60s for the receipt; Ok(true) if status 0x1, Ok(false) if 0x0.
async fn poll_receipt(client: &reqwest::Client, url: &str, tx_hash: &str) -> Result<bool> {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let ret = rpc(client, url, "eth_getTransactionReceipt", json!([tx_hash])).await?;
        if ret.is_null() {
            continue;
        }
        let status = ret.get("status").and_then(|s| s.as_str()).unwrap_or("0x0");
        return Ok(status == "0x1");
    }
    bail!("no receipt for {tx_hash} after ~60s")
}

fn addr_hex(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — derivation + digest against pinned vectors.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // Fixed vector: the testnet-config.toml fleet coinbase.
    const VEC_COINBASE: &str = "47fb23137e0ee4248eb975848416e6632fa36090";
    // Pinned expected proposer pubkey for VEC_COINBASE (regression teeth: this is
    // the ed25519 verifying key the node registers; a change here means the
    // derivation drifted from node/src/main.rs and every fleet key would move).
    // Reproduce: `validator-registration-ceremony --dry-run --node <coinbase>=<env>`.
    const VEC_PUBKEY: &str = "b898d7550f8bb45b2b6122f56984a5f50c007a46cb219015d13f94539516ee0f";

    fn coinbase20(s: &str) -> [u8; 20] {
        let v = hex::decode(s).expect("valid hex coinbase");
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn derivation_is_deterministic() {
        let cb = coinbase20(VEC_COINBASE);
        let k1 = derive_proposer_key(&cb);
        let k2 = derive_proposer_key(&cb);
        assert_eq!(k1.to_bytes(), k2.to_bytes(), "derivation must be deterministic");
        assert_eq!(k1.verifying_key().to_bytes(), k2.verifying_key().to_bytes());
    }

    #[test]
    fn derivation_matches_inline_main_rs_algorithm() {
        // Independently recompute the main.rs seed and compare — proves this tool
        // reproduces the node's derivation byte-for-byte.
        let cb = coinbase20(VEC_COINBASE);
        let mut coinbase32 = [0u8; 32];
        coinbase32[..20].copy_from_slice(&cb);
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate-block-signing-key-v1");
        hasher.update(coinbase32);
        let seed = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&seed);
        let expected = Ed25519SigningKey::from_bytes(&seed_bytes);
        let got = derive_proposer_key(&cb);
        assert_eq!(expected.to_bytes(), got.to_bytes());
        assert_eq!(
            expected.verifying_key().to_bytes(),
            got.verifying_key().to_bytes()
        );
    }

    #[test]
    fn derivation_pinned_pubkey_vector() {
        if VEC_PUBKEY == "PINNED_BELOW" {
            return; // placeholder run — replaced with the real pin below
        }
        let cb = coinbase20(VEC_COINBASE);
        let pk = derive_proposer_key(&cb).verifying_key().to_bytes();
        assert_eq!(hex::encode(pk), VEC_PUBKEY, "proposer pubkey regression vector drifted");
    }

    #[test]
    fn sign_verify_roundtrip_over_register_digest() {
        // The full cryptographic chain the contract's 0x0120 precompile checks:
        // ed25519 sign the 32-byte register digest, verify_strict must pass.
        use ed25519_dalek::Signer;
        let cb = coinbase20(VEC_COINBASE);
        let key = derive_proposer_key(&cb);
        let pubkey = key.verifying_key().to_bytes();
        let registry = coinbase20("00112233445566778899aabbccddeeff00112233");
        let staker = coinbase20("aabbccddeeff00112233445566778899aabbccdd");
        let digest = registration_digest(40204, &registry, &staker, &pubkey, 0);
        let sig: ed25519_dalek::Signature = key.sign(&digest);
        key.verifying_key()
            .verify_strict(&digest, &sig)
            .expect("register-digest signature must verify_strict");
    }

    #[test]
    fn register_digest_matches_pinned_vector() {
        // Pinned Register-digest vector for fixed inputs (regression teeth against a
        // silent change to the EIP-712 encoding / typehash).
        let cb = coinbase20(VEC_COINBASE);
        let pubkey = derive_proposer_key(&cb).verifying_key().to_bytes();
        let registry = coinbase20("00112233445566778899aabbccddeeff00112233");
        let staker = coinbase20("aabbccddeeff00112233445566778899aabbccdd");
        let digest = registration_digest(40204, &registry, &staker, &pubkey, 0);
        // Hand-recompute keccak256(abi.encode(REGISTER_TYPEHASH, chainId, registry,
        // staker, proposerPubkey, nonce)) to cross-check the consensus helper.
        let mut enc = Vec::new();
        enc.extend_from_slice(&keccak256(
            b"Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)",
        ));
        enc.extend_from_slice(&word_u64(40204));
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&registry);
        enc.extend_from_slice(&w);
        let mut w2 = [0u8; 32];
        w2[12..].copy_from_slice(&staker);
        enc.extend_from_slice(&w2);
        enc.extend_from_slice(&pubkey);
        enc.extend_from_slice(&word_u64(0));
        assert_eq!(keccak256(&enc), digest, "register digest must equal hand-encoded EIP-712 digest");
    }

    #[test]
    fn register_validator_calldata_layout() {
        let pubkey = [0x11u8; 32];
        let sig = [0x22u8; 64];
        let cd = encode_register_validator(&pubkey, &sig);
        // selector(4) + pubkey(32) + offset(32) + len(32) + sig(64) = 164 bytes.
        assert_eq!(cd.len(), 164);
        let selector = keccak256(b"registerValidator(bytes32,bytes)");
        assert_eq!(&cd[..4], &selector[..4]);
        assert_eq!(&cd[4..36], &pubkey);
        // offset word == 0x40
        assert_eq!(cd[4 + 32 + 31], 0x40);
        // length word == 64
        assert_eq!(cd[4 + 64 + 31], 64);
        assert_eq!(&cd[4 + 96..], &sig);
    }

    #[test]
    fn salt_to_wei_is_1e18() {
        assert_eq!(salt_to_wei(1), 1_000_000_000_000_000_000u128);
        assert_eq!(salt_to_wei(32_000), 32_000u128 * 1_000_000_000_000_000_000u128);
    }
}
