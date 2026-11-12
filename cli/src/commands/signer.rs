//citrate/cli/src/commands/signer.rs
//
// Local transaction signing for the CLI's write commands.
//
// The CLI used to send `eth_sendTransaction` and let the node sign. Public
// nodes refuse that, so every write signs locally and goes out through
// `eth_sendRawTransaction`:
//
//   * key: the CLI keystore (`--account`, password from `--password-file` or a
//     prompt) or the `PRIVATE_KEY` environment variable. Never argv.
//   * nonce, chain id and gas price come from the node; the gas limit comes
//     from `eth_estimateGas` unless `--gas-limit` is given.
//   * the node must be chain 40204 at the genesis in the root address book
//     (`contracts/addresses/40204.json`), unless `--allow-foreign-chain`.
//   * signing is citrate-wallet's `TransactionBuilder::build_and_sign`
//     (native ed25519, chain-bound V2 digest) and its bincode raw encoding.
//     No crypto lives in this file.

use anyhow::{Context, Result};
use citrate_consensus::types::PublicKey;
use citrate_execution::types::Address;
use citrate_wallet::{SignedTransaction, TransactionBuilder};
use clap::Args;
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::utils::keystore;

/// The chain the CLI signs for unless `--allow-foreign-chain`.
pub const EXPECTED_CHAIN_ID: u64 = 40204;

/// The environment variable a raw signing key may come from (32-byte ed25519
/// secret, hex, as `account export` writes it).
pub const PRIVATE_KEY_ENV: &str = "PRIVATE_KEY";

/// The live network's root address book. Its `genesisHash` is the genesis the
/// CLI expects the node to serve.
const ROOT_BOOK: &str = include_str!("../../../contracts/addresses/40204.json");

/// Options shared by every command that signs a transaction.
#[derive(Args, Debug, Clone, Default)]
pub struct SignerArgs {
    /// Keystore account to sign with (its address). Without it the key comes
    /// from the PRIVATE_KEY environment variable, then the config's default_account.
    #[arg(long)]
    pub account: Option<String>,

    /// Read the keystore password from this file (first line). Prompts if omitted.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Gas limit. Estimated with eth_estimateGas when omitted.
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// Sign even if the node is not chain 40204 at the expected genesis
    /// (for a local development chain).
    #[arg(long)]
    pub allow_foreign_chain: bool,
}

/// The genesis hash in the root address book.
pub fn expected_genesis() -> Result<String> {
    anyhow::bail!("not implemented")
}

/// Refuse to sign for a node that is not the expected chain, unless overridden.
pub fn check_chain(
    _node_chain_id: u64,
    _node_genesis: &str,
    _expected_genesis: &str,
    _allow_foreign: bool,
) -> Result<()> {
    Ok(())
}

/// Parse a 32-byte ed25519 secret from hex (with or without 0x).
pub fn parse_secret_hex(_hex_key: &str) -> Result<SigningKey> {
    anyhow::bail!("not implemented")
}

/// The account address of a signing key, as the chain derives it.
pub fn address_of(_key: &SigningKey) -> [u8; 20] {
    [0u8; 20]
}

/// Where the signing key comes from. `account` is `--account`; `env_key` is
/// the PRIVATE_KEY value; `default_account` is the config's.
pub fn resolve_key(
    _account: Option<&str>,
    _env_key: Option<Zeroizing<String>>,
    _default_account: Option<&str>,
    _keystore_dir: &Path,
    _password: &dyn Fn() -> Result<Zeroizing<String>>,
) -> Result<SigningKey> {
    anyhow::bail!("not implemented")
}

/// The values the node supplies for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxParams {
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub chain_id: u64,
}

/// Build and sign a transaction with citrate-wallet's builder.
pub fn build_signed(
    _key: &SigningKey,
    _to: Option<[u8; 20]>,
    _value: u128,
    _data: Vec<u8>,
    _params: &TxParams,
) -> Result<SignedTransaction> {
    anyhow::bail!("not implemented")
}

/// The gas limit to use for an `eth_estimateGas` answer.
pub fn gas_with_headroom(estimate: u64, _has_data: bool) -> u64 {
    estimate
}

/// A signed, submitted transaction and its receipt.
pub struct Sent {
    pub hash: String,
    pub from: [u8; 20],
    pub receipt: Value,
}

/// Sign and submit one transaction, then wait for its receipt.
pub async fn sign_and_send(
    _config: &Config,
    _args: &SignerArgs,
    _to: Option<[u8; 20]>,
    _value: u128,
    _data: Vec<u8>,
) -> Result<Sent> {
    anyhow::bail!("not implemented")
}

#[allow(dead_code)]
fn unused(_: U256, _: PublicKey, _: Address, _: TransactionBuilder) -> Value {
    json!(null)
}

#[allow(dead_code)]
fn unused2(p: &Path, pw: &str) -> Result<SigningKey> {
    keystore::load_key(p, pw).context("x")
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1007_GENESIS: &str =
        "0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631";
    const R1006_GENESIS: &str =
        "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4";
    /// A fixed test key (not a funded account).
    const TEST_SECRET: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[test]
    fn expects_the_r1007_genesis_from_the_root_book() {
        assert_eq!(expected_genesis().ok().as_deref(), Some(R1007_GENESIS));
    }

    #[test]
    fn signs_for_chain_40204_at_the_expected_genesis() {
        assert!(check_chain(40204, R1007_GENESIS, R1007_GENESIS, false).is_ok());
        // Case does not matter.
        let upper = R1007_GENESIS.to_uppercase().replacen("0X", "0x", 1);
        assert!(check_chain(40204, &upper, R1007_GENESIS, false).is_ok());
    }

    #[test]
    fn refuses_another_chain_id_unless_overridden() {
        let err = check_chain(1, R1007_GENESIS, R1007_GENESIS, false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("chain 1"), "{err}");
        assert!(err.contains("--allow-foreign-chain"), "{err}");
        assert!(check_chain(1, R1007_GENESIS, R1007_GENESIS, true).is_ok());
    }

    #[test]
    fn refuses_another_genesis_unless_overridden() {
        let err = check_chain(40204, R1006_GENESIS, R1007_GENESIS, false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains(R1006_GENESIS), "{err}");
        assert!(err.contains(R1007_GENESIS), "{err}");
        assert!(check_chain(40204, R1006_GENESIS, R1007_GENESIS, true).is_ok());
    }

    #[test]
    fn parses_a_hex_secret_and_rejects_bad_ones() {
        let k = parse_secret_hex(TEST_SECRET).ok().map(|k| k.to_bytes());
        assert_eq!(k, Some([0x42; 32]));
        let k0x = parse_secret_hex(&format!("0x{TEST_SECRET}\n"))
            .ok()
            .map(|k| k.to_bytes());
        assert_eq!(k0x, Some([0x42; 32]));
        assert!(parse_secret_hex("0x1234").is_err());
        assert!(parse_secret_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn the_signer_address_is_the_keystore_address() {
        // The CLI keystore names files by this address (account create / import).
        let vk = test_key().verifying_key();
        let expected = Address::from_public_key(&PublicKey::new(*vk.as_bytes())).0;
        assert_eq!(address_of(&test_key()), expected);
        assert_ne!(expected, [0u8; 20]);
    }

    fn no_password() -> Result<Zeroizing<String>> {
        anyhow::bail!("no password expected")
    }

    #[test]
    fn env_key_is_used_when_no_account_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = resolve_key(
            None,
            Some(Zeroizing::new(TEST_SECRET.to_string())),
            None,
            dir.path(),
            &no_password,
        );
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
    }

    #[test]
    fn keystore_account_is_loaded_with_the_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let addr = hex::encode(address_of(&test_key()));
        let path = dir.path().join(format!("{addr}.json"));
        keystore::save_key(&test_key(), "correct horse battery", &path).expect("save");
        let pw = || Ok(Zeroizing::new("correct horse battery".to_string()));
        let key = resolve_key(Some(&format!("0x{addr}")), None, None, dir.path(), &pw);
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
        // The config default is used when nothing else is given.
        let key = resolve_key(None, None, Some(&addr), dir.path(), &pw);
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
    }

    #[test]
    fn an_env_key_for_another_account_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let addr = hex::encode(address_of(&test_key()));
        let path = dir.path().join(format!("{addr}.json"));
        keystore::save_key(&test_key(), "correct horse battery", &path).expect("save");
        let pw = || Ok(Zeroizing::new("correct horse battery".to_string()));
        let other = Zeroizing::new("11".repeat(32));
        let err = resolve_key(Some(&addr), Some(other), None, dir.path(), &pw)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("PRIVATE_KEY"), "{err}");
    }

    #[test]
    fn no_key_source_says_how_to_give_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_key(None, None, None, dir.path(), &no_password)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("--account"), "{err}");
        assert!(err.contains("PRIVATE_KEY"), "{err}");
    }

    fn params() -> TxParams {
        TxParams {
            nonce: 7,
            gas_price: 1_000_000_000,
            gas_limit: 50_000,
            chain_id: 40204,
        }
    }

    #[test]
    fn signed_transfer_authenticates_as_the_keystore_address() {
        let to = [0x11; 20];
        let signed =
            build_signed(&test_key(), Some(to), 1_000, Vec::new(), &params()).expect("sign");
        let tx = &signed.transaction;
        assert!(citrate_consensus::tx_auth::authenticate(tx).is_ok());
        assert_eq!(
            citrate_consensus::native_sig::signed_version(tx),
            Some(citrate_consensus::native_sig::NativeSigVersion::V2)
        );
        assert_eq!(tx.chain_id, Some(40204));
        assert_eq!(
            (tx.nonce, tx.gas_price, tx.gas_limit),
            (7, 1_000_000_000, 50_000)
        );
        assert_eq!(tx.value, 1_000);
        assert_eq!(
            Address::from_public_key(&tx.from).0,
            address_of(&test_key())
        );
        let to_pk = tx.to.map(|pk| Address::from_public_key(&pk).0);
        assert_eq!(to_pk, Some(to));
        // The raw bytes are what eth_sendRawTransaction receives.
        let decoded: citrate_consensus::types::Transaction =
            bincode::deserialize(&signed.raw).expect("decode raw");
        assert_eq!(decoded.signature, tx.signature);
    }

    #[test]
    fn a_deploy_has_no_recipient_and_carries_the_code() {
        let code = vec![0x60, 0x00, 0x60, 0x00];
        let signed = build_signed(&test_key(), None, 0, code.clone(), &params()).expect("sign");
        assert!(signed.transaction.to.is_none());
        assert_eq!(signed.transaction.data, code);
        assert!(citrate_consensus::tx_auth::authenticate(&signed.transaction).is_ok());
    }

    #[test]
    fn calls_get_gas_headroom_and_plain_transfers_do_not() {
        assert_eq!(gas_with_headroom(21_000, false), 21_000);
        assert_eq!(gas_with_headroom(144_294, true), 173_152);
        assert_eq!(gas_with_headroom(u64::MAX, true), u64::MAX);
    }
}
