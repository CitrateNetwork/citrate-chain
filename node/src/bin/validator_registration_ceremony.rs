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
use citrate_consensus::crypto::registration_digest;
use citrate_wallet_core::{sign_eip155_legacy_tx, LegacyTxFields};
use clap::Parser;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

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

    /// One per fleet node, repeatable. Format:
    ///   `<coinbase_hex>=<STAKER_KEY_ENV_VAR>=<proposer_key_file>`
    /// where the coinbase is the node's PUBLIC 20-byte address, the env var holds that
    /// validator's staker private key (0x-hex, 32 bytes), and the file is that node's
    /// `proposer.key` — the 32-byte ed25519 seed the node minted in its data dir.
    ///   --node 0x47fb..36090=VALIDATOR_STAKER_1_PRIVATE_KEY=/secure/boot1-proposer.key
    ///
    /// WP-11: the third field is REQUIRED and the old two-field form is REJECTED. The
    /// proposer key used to be derived from the public coinbase, which let anyone
    /// reconstruct any validator's signing key and Byzantine-slash it through the
    /// permissionless `submitEquivocation`. It is now a real secret only the node
    /// holds, so the ceremony must be given it rather than recomputing it. Copy the
    /// file off the node over SSH (0600 both ends) or run this tool on the node.
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
    /// WP-11: the node's real ed25519 proposer seed, read from its `proposer.key`.
    proposer_seed: [u8; 32],
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
        let limit = seed_timing_refuse_limit();
        println!(
            "chain height {} (epoch-1 snapshot S(1)={}, refuse-after {})",
            height, FIRST_SNAPSHOT_HEIGHT, limit
        );
        if !seed_timing_permitted(height, cli.force) {
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
    // 1. Proposer key = the node's REAL persisted secret (WP-11), not a derivation.
    let proposer = citrate_consensus::crypto::block_signing_key_from_seed(&spec.proposer_seed);
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

/// WP-11: a node's proposer key is a persisted SECRET, so tests build one from an
/// explicit seed. There is deliberately no `derive_proposer_key(coinbase)` any more —
/// its existence WAS the vulnerability: the coinbase is public, so anyone could
/// reconstruct any validator's signing key and Byzantine-slash it.
#[cfg(test)]
fn proposer_key_from_seed(seed: &[u8; 32]) -> citrate_consensus::crypto::Ed25519SigningKey {
    citrate_consensus::crypto::block_signing_key_from_seed(seed)
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

/// The block height at/after which the seed-timing guard refuses (without
/// `--force`): `S(1) - margin`. A registration mined at or after this height
/// risks missing the epoch-1 active-set snapshot at S(1)=800.
fn seed_timing_refuse_limit() -> u64 {
    FIRST_SNAPSHOT_HEIGHT.saturating_sub(DEFAULT_SEED_MARGIN_BLOCKS)
}

/// Seed-timing guard predicate (factored out of `main` for testing). A
/// registration at `height` is permitted iff it is safely before the
/// refuse-after limit, or `force` overrides the guard. Boundary: with the
/// default margin the limit is 700, so 699 is permitted, 700 is refused, and
/// 700-with-force is permitted.
fn seed_timing_permitted(height: u64, force: bool) -> bool {
    force || height < seed_timing_refuse_limit()
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
        let mut parts = spec.split('=');
        let coinbase_str = parts.next().unwrap_or_default();
        let env_name = parts.next().ok_or_else(|| {
            anyhow!("--node must be <coinbase_hex>=<STAKER_KEY_ENV_VAR>=<proposer_key_file>, got: {spec}")
        })?;
        // WP-11: the proposer key is no longer derivable from the coinbase, so it MUST
        // be supplied. Rejecting the old two-field form loudly is deliberate — silently
        // falling back to a derivation would re-introduce a forgeable consensus key.
        let proposer_key_file = parts.next().ok_or_else(|| {
            anyhow!(
                "--node is missing the proposer key file: expected \
                 <coinbase_hex>=<STAKER_KEY_ENV_VAR>=<proposer_key_file>, got: {spec}. \
                 WP-11 replaced the coinbase-derived proposer key with a real secret; \
                 pass the node's data-dir `proposer.key`."
            )
        })?;
        if parts.next().is_some() {
            bail!("--node has too many '=' separated fields: {spec}");
        }
        let proposer_seed_raw = std::fs::read(proposer_key_file)
            .with_context(|| format!("reading proposer key file {proposer_key_file}"))?;
        if proposer_seed_raw.len() != 32 {
            bail!(
                "proposer key file {proposer_key_file} is {} bytes, expected a 32-byte ed25519 seed",
                proposer_seed_raw.len()
            );
        }
        let mut proposer_seed = [0u8; 32];
        proposer_seed.copy_from_slice(&proposer_seed_raw);
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
        out.push(NodeSpec { coinbase, staker_key, staker_key_env: env_name.to_string(), proposer_seed });
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
    use ed25519_dalek::{Signer, Verifier};
    use proptest::prelude::*;
    use sha3::Sha3_256;

    // Fixed vector: the testnet-config.toml fleet coinbase.
    const VEC_COINBASE: &str = "47fb23137e0ee4248eb975848416e6632fa36090";
    // VEC_PUBKEY was removed 2026-08-03. It pinned
    // b898d755…16ee0f as "the ed25519 verifying key the node registers", which is
    // EXACTLY what sha3_256("citrate-block-signing-key-v1" || coinbase32) produces
    // for VEC_COINBASE — verified by recomputation. That is the PRE-FIX derivation:
    // a signing key that anyone could compute from a public coinbase address.
    //
    // `proposer_key_is_not_derivable_from_the_public_coinbase` below exists because
    // that was a vulnerability, and its own comment says the tests it replaced
    // "asserted the OPPOSITE … which is exactly what pinned the vulnerability in
    // place". This constant was the last surviving piece of that pinning: dead, but
    // sitting there labelled "regression teeth", inviting the next person to wire it
    // back up and re-assert the vulnerable property. Deleted rather than hooked up.

    fn coinbase20(s: &str) -> [u8; 20] {
        let v = hex::decode(s).expect("valid hex coinbase");
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        a
    }

    /// Byte-for-byte reproduction of the derivation that USED to live inline in
    /// `node/src/main.rs` (before the WS-5 refactor extracted it to the shared
    /// `citrate_consensus::crypto::derive_block_signing_key`). It reproduces
    /// main.rs's EXACT `copy_len = min(len, 32)` right-zero-pad and hardcodes the
    /// domain string LITERALLY here so this test file never imports the shared
    /// constant it is trying to police. If the shared derivation (which the node
    /// now calls to sign blocks) ever drifts from this pinned reference, the
    /// derivation-equivalence fuzz below fails — that is the drift tripwire.
    fn main_rs_reference_pubkey(coinbase_bytes: &[u8]) -> [u8; 32] {
        let mut coinbase = [0u8; 32];
        let copy_len = coinbase_bytes.len().min(32);
        coinbase[..copy_len].copy_from_slice(&coinbase_bytes[..copy_len]);
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate-block-signing-key-v1");
        hasher.update(coinbase);
        let seed = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&seed);
        citrate_consensus::crypto::Ed25519SigningKey::from_bytes(&seed_bytes)
            .verifying_key()
            .to_bytes()
    }

    /// A deterministic, valid secp256k1 staker key for tests (nonzero, well below
    /// the curve order). `seed` MUST be nonzero.
    fn test_staker_key(seed: u8) -> Secp256k1SigningKey {
        let mut b = [0u8; 32];
        b[31] = seed;
        Secp256k1SigningKey::from_slice(&b).expect("nonzero 32-byte scalar is a valid secp256k1 key")
    }

    fn node_spec(coinbase: [u8; 20], staker_seed: u8) -> NodeSpec {
        let mut proposer_seed = [0u8; 32];
        proposer_seed[0] = staker_seed;
        proposer_seed[31] = 0xA5;
        NodeSpec {
            coinbase,
            staker_key: test_staker_key(staker_seed),
            staker_key_env: format!("TEST_STAKER_{staker_seed}"),
            proposer_seed,
        }
    }

    /// Independent, hand-rolled ABI encoder for the Register EIP-712 digest —
    /// deliberately NOT calling `registration_digest`, so it is a true oracle.
    fn hand_register_digest(
        chain_id: u64,
        registry: &[u8; 20],
        staker: &[u8; 20],
        pubkey: &[u8; 32],
        nonce: u64,
    ) -> [u8; 32] {
        let mut enc = Vec::new();
        enc.extend_from_slice(&keccak256(
            b"Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)",
        ));
        enc.extend_from_slice(&word_u64(chain_id));
        let mut wr = [0u8; 32];
        wr[12..].copy_from_slice(registry);
        enc.extend_from_slice(&wr);
        let mut ws = [0u8; 32];
        ws[12..].copy_from_slice(staker);
        enc.extend_from_slice(&ws);
        enc.extend_from_slice(pubkey);
        enc.extend_from_slice(&word_u64(nonce));
        keccak256(&enc)
    }

    // ── Example-based regression pins ────────────────────────────────────────

    /// WP-11 SECURITY REGRESSION — the proposer key must NOT be a function of the
    /// coinbase.
    ///
    /// It used to be `Sha3_256(b"citrate-block-signing-key-v1" ‖ coinbase32)`. Every
    /// input was public (the coinbase is recoverable on-chain from
    /// `validatorInfo(pubkey).staker`, which consensus forces to equal it), so anyone
    /// could reconstruct any validator's signing PRIVATE key. `submitEquivocation` is
    /// permissionless, so that meant anyone could forge a double-sign and trigger a
    /// Byzantine slash: 100% of bond + escrow + rewards, a 10% bounty to the attacker,
    /// and a permanent ban of the pubkey and the staker.
    ///
    /// The tests this replaced asserted the OPPOSITE — that the key was a pure
    /// function of the coinbase — which is exactly what pinned the vulnerability in
    /// place.
    #[test]
    fn proposer_key_is_not_derivable_from_the_public_coinbase() {
        use sha3::{Digest as _, Sha3_256};
        let cb = coinbase20(VEC_COINBASE);

        // Recompute exactly what the removed derivation did.
        let mut coinbase32 = [0u8; 32];
        coinbase32[..20].copy_from_slice(&cb);
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate-block-signing-key-v1");
        hasher.update(coinbase32);
        let mut legacy_seed = [0u8; 32];
        legacy_seed.copy_from_slice(&hasher.finalize());
        let forged = citrate_consensus::crypto::Ed25519SigningKey::from_bytes(&legacy_seed)
            .verifying_key()
            .to_bytes();

        let real = citrate_consensus::crypto::generate_block_signing_key()
            .verifying_key()
            .to_bytes();

        assert_ne!(
            real, forged,
            "proposer key is reconstructible from the public coinbase — anyone can forge \
             this validator's block signatures and slash it via submitEquivocation"
        );
    }

    /// Two nodes must get distinct consensus identities. Under the old scheme two
    /// nodes sharing a coinbase collided into ONE key, so only one validator could
    /// ever exist per address.
    #[test]
    fn distinct_nodes_get_distinct_proposer_keys() {
        let a = citrate_consensus::crypto::generate_block_signing_key()
            .verifying_key()
            .to_bytes();
        let b = citrate_consensus::crypto::generate_block_signing_key()
            .verifying_key()
            .to_bytes();
        assert_ne!(a, b, "each node must mint its own independent proposer identity");
    }

    /// A persisted seed must round-trip to the same key, or a node would come back
    /// from a restart with a different identity than the one it registered.
    #[test]
    fn persisted_seed_round_trips_to_the_same_identity() {
        let key = citrate_consensus::crypto::generate_block_signing_key();
        let seed = key.to_bytes();
        let reloaded = proposer_key_from_seed(&seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            reloaded.verifying_key().to_bytes()
        );
    }

    #[test]
    fn sign_verify_roundtrip_over_register_digest() {
        // The full cryptographic chain the contract's 0x0120 precompile checks:
        // ed25519 sign the 32-byte register digest, verify_strict must pass.
        let key = citrate_consensus::crypto::generate_block_signing_key();
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
        // Fully-pinned Register-digest literal for fixed inputs (regression teeth
        // against any silent change to the EIP-712 encoding / typehash). Every
        // input is a literal here (pubkey is NOT derived) so the vector is frozen.
        let registry = coinbase20("00112233445566778899aabbccddeeff00112233");
        let staker = coinbase20("aabbccddeeff00112233445566778899aabbccdd");
        let pubkey = [0xABu8; 32];
        let digest = registration_digest(40204, &registry, &staker, &pubkey, 7);
        assert_eq!(
            hex::encode(digest),
            "f95e614fe16769bd6e1f207674b238a842f3f257f0b8fed00efbf0f5f2b22068",
            "register digest vector drifted",
        );
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

    // ── Guard edges ──────────────────────────────────────────────────────────

    #[test]
    fn seed_timing_guard_boundary() {
        // Default margin 100 → refuse-after limit S(1)-100 = 700.
        assert_eq!(seed_timing_refuse_limit(), 700);
        assert!(seed_timing_permitted(0, false), "genesis-era height permitted");
        assert!(seed_timing_permitted(699, false), "one below limit permitted");
        assert!(!seed_timing_permitted(700, false), "at the limit is refused");
        assert!(!seed_timing_permitted(701, false), "past the limit is refused");
        assert!(!seed_timing_permitted(FIRST_SNAPSHOT_HEIGHT, false), "at S(1) refused");
        // --force overrides at and beyond the boundary.
        assert!(seed_timing_permitted(700, true), "force overrides at the limit");
        assert!(seed_timing_permitted(u64::MAX, true), "force overrides everywhere");
    }

    #[test]
    fn reject_duplicates_accepts_all_distinct() {
        let specs = vec![
            node_spec([1u8; 20], 1),
            node_spec([2u8; 20], 2),
            node_spec([3u8; 20], 3),
        ];
        reject_duplicates(&specs).expect("all-distinct coinbases + stakers accepted");
    }

    #[test]
    fn reject_duplicates_rejects_duplicate_coinbase() {
        // Same coinbase → same proposer pubkey → on-chain PubkeyTaken; caught here.
        let specs = vec![node_spec([7u8; 20], 1), node_spec([7u8; 20], 2)];
        let err = reject_duplicates(&specs).expect_err("duplicate coinbase must be rejected");
        assert!(format!("{err}").contains("duplicate coinbase"));
    }

    #[test]
    fn reject_duplicates_rejects_duplicate_staker() {
        // Distinct coinbases but the SAME staker key → StakerHasValidator on-chain.
        let specs = vec![node_spec([1u8; 20], 9), node_spec([2u8; 20], 9)];
        let err = reject_duplicates(&specs).expect_err("duplicate staker must be rejected");
        assert!(format!("{err}").contains("duplicate staker"));
    }

    #[test]
    fn parse_addr20_rejects_malformed() {
        parse_addr20("0x1234").expect_err("too-short address must error, not panic");
        parse_addr20(&format!("0x{}", "ab".repeat(21))).expect_err("too-long address must error");
        parse_addr20("0xZZ112233445566778899aabbccddeeff00112233")
            .expect_err("non-hex address must error");
        let ok = parse_addr20("0x47fb23137e0ee4248eb975848416e6632fa36090")
            .expect("valid 20-byte address parses");
        assert_eq!(ok, coinbase20(VEC_COINBASE));
    }

    #[test]
    fn parse_nodes_rejects_missing_delimiter() {
        // No '=' → deterministic error, no panic. (NodeSpec isn't Debug, so match
        // rather than expect_err on the Ok payload.)
        match parse_nodes(&["0x47fb23137e0ee4248eb975848416e6632fa36090".to_string()]) {
            Ok(_) => panic!("--node without '=' must error"),
            Err(e) => assert!(format!("{e}").contains("<coinbase_hex>=<STAKER_KEY_ENV_VAR>")),
        }
    }

    // ── Fuzz: derivation equivalence (the load-bearing property) ──────────────
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// WP-11 SECURITY REGRESSION, generalized: for ANY coinbase, a real proposer
        /// key must not equal the key the removed derivation would have produced from
        /// that same public address. The two proptests this replaced asserted exactly
        /// the opposite — that the key WAS a pure function of the coinbase — which is
        /// precisely what let anyone reconstruct a validator's signing key and
        /// Byzantine-slash it through the permissionless `submitEquivocation`.
        #[test]
        fn fuzz_key_is_independent_of_coinbase(coinbase in any::<[u8; 20]>()) {
            let real = citrate_consensus::crypto::generate_block_signing_key()
                .verifying_key()
                .to_bytes();
            prop_assert_ne!(real, main_rs_reference_pubkey(&coinbase));
        }
    }

    // ── Fuzz: Register digest == independent EIP-712 encoding ─────────────────
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn fuzz_registration_digest_matches_hand_encoded(
            chain_id in any::<u64>(),
            registry in any::<[u8; 20]>(),
            staker in any::<[u8; 20]>(),
            pubkey in any::<[u8; 32]>(),
            nonce in any::<u64>(),
        ) {
            let got = registration_digest(chain_id, &registry, &staker, &pubkey, nonce);
            let oracle = hand_register_digest(chain_id, &registry, &staker, &pubkey, nonce);
            prop_assert_eq!(got, oracle);
        }
    }

    // ── Fuzz: sign → verify_strict roundtrip + tamper rejection ───────────────
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn fuzz_sign_verify_strict_roundtrip(
            msg in prop::collection::vec(any::<u8>(), 1..256),
        ) {
            let key = citrate_consensus::crypto::generate_block_signing_key();
            let vk = key.verifying_key();
            let sig: ed25519_dalek::Signature = key.sign(&msg);
            // Honest signature verifies under the strict (non-malleable) check.
            prop_assert!(vk.verify_strict(&msg, &sig).is_ok());
            prop_assert!(vk.verify(&msg, &sig).is_ok());
        }

        #[test]
        fn fuzz_message_bitflip_fails(
            msg in prop::collection::vec(any::<u8>(), 1..256),
            flip_idx in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            let key = citrate_consensus::crypto::generate_block_signing_key();
            let vk = key.verifying_key();
            let sig: ed25519_dalek::Signature = key.sign(&msg);
            let mut tampered = msg.clone();
            let i = flip_idx.index(tampered.len());
            tampered[i] ^= 1u8 << bit;
            // A one-bit change to the message must break verification.
            prop_assert!(vk.verify_strict(&tampered, &sig).is_err());
        }

        #[test]
        fn fuzz_signature_bitflip_fails(
            msg in prop::collection::vec(any::<u8>(), 1..256),
            flip_idx in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            let key = citrate_consensus::crypto::generate_block_signing_key();
            let vk = key.verifying_key();
            let sig: ed25519_dalek::Signature = key.sign(&msg);
            let mut sig_bytes = sig.to_bytes();
            let i = flip_idx.index(sig_bytes.len());
            sig_bytes[i] ^= 1u8 << bit;
            let tampered = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            // A one-bit change to the signature must break verification.
            prop_assert!(vk.verify_strict(&msg, &tampered).is_err());
        }
    }

    // ── Fuzz: registerValidator calldata layout ───────────────────────────────
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn fuzz_calldata_layout(
            pubkey in any::<[u8; 32]>(),
            sig in any::<[u8; 64]>(),
        ) {
            let cd = encode_register_validator(&pubkey, &sig);
            // Independently reconstruct the ABI encoding and compare byte-for-byte.
            let selector = keccak256(b"registerValidator(bytes32,bytes)");
            let mut expected = Vec::with_capacity(164);
            expected.extend_from_slice(&selector[..4]);
            expected.extend_from_slice(&pubkey);      // bytes32 head
            expected.extend_from_slice(&word_u64(0x40)); // offset to tail
            expected.extend_from_slice(&word_u64(64));   // bytes length
            expected.extend_from_slice(&sig);            // 64-byte tail (2 words)
            prop_assert_eq!(cd.len(), 164);
            prop_assert_eq!(cd, expected);
        }
    }
}
