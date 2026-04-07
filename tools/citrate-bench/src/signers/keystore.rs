//! Foundry-compatible V3 keystore loader.
//!
//! Foundry's `cast wallet import` (and `cast wallet new`) writes V3
//! keystores to `~/.foundry/keystores/<name>`. Each file is a JSON
//! blob with a scrypt-derived KDF, AES-128-CTR ciphertext, and an MAC
//! computed over `keccak256(derived_key[16..32] || ciphertext)`.
//!
//! The `eth-keystore` crate handles the underlying crypto. We wrap it
//! with:
//! - resolution of account name → file path inside a keystore directory
//! - passphrase acquisition (`ETH_PASSWORD` file path, explicit string,
//!   or interactive TTY prompt)
//! - conversion from decrypted bytes into our `Signer` type

use std::path::{Path, PathBuf};

use crate::signers::Signer;
use crate::{Error, Result};

/// How to obtain the keystore passphrase.
pub enum PassphraseSource {
    /// Literal passphrase (used in tests and by the runtime after the
    /// operator's TTY prompt has returned a value).
    Literal(String),
    /// Path to a file whose contents (leading/trailing whitespace
    /// trimmed) are the passphrase. This is the non-interactive path
    /// the ceremony rehearsal uses via `ETH_PASSWORD`.
    File(PathBuf),
    /// Prompt on the controlling TTY once. Fails if stdin is not a TTY.
    Prompt { prompt: String },
}

/// Resolve an account name to a keystore file inside `keystore_dir`.
///
/// Rules:
/// - If `name` contains a path separator or starts with '/', it is
///   treated as a literal path.
/// - Otherwise the file is `keystore_dir.join(name)`.
pub fn resolve_keystore_file(keystore_dir: &Path, name: &str) -> PathBuf {
    if name.contains(std::path::MAIN_SEPARATOR) || name.starts_with('/') {
        PathBuf::from(name)
    } else {
        keystore_dir.join(name)
    }
}

/// Read a passphrase from the given source.
pub fn read_passphrase(source: &PassphraseSource) -> Result<String> {
    match source {
        PassphraseSource::Literal(s) => Ok(s.clone()),
        PassphraseSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| Error::Keystore(format!("read passphrase file: {e}")))?;
            Ok(raw.trim().to_string())
        }
        PassphraseSource::Prompt { prompt } => {
            rpassword::prompt_password(prompt)
                .map_err(|e| Error::Keystore(format!("tty passphrase prompt: {e}")))
        }
    }
}

/// Decrypt a keystore file and wrap the result in a `Signer`.
pub fn load(keystore_file: &Path, passphrase: &str) -> Result<Signer> {
    let key_bytes = eth_keystore::decrypt_key(keystore_file, passphrase)
        .map_err(|e| Error::Keystore(format!("decrypt {}: {e}", keystore_file.display())))?;
    Signer::from_key_bytes(&key_bytes)
}

/// Load all configured accounts from a keystore directory using the
/// same passphrase for every account. The current assumption is that
/// the bench operator uses one passphrase for the bench signer set;
/// this is safe because those signers are burner accounts funded only
/// for a single benchmark window.
pub fn load_many(
    keystore_dir: &Path,
    accounts: &[String],
    source: &PassphraseSource,
) -> Result<Vec<Signer>> {
    if accounts.is_empty() {
        return Err(Error::Keystore("no accounts requested".into()));
    }
    let passphrase = read_passphrase(source)?;
    let mut out = Vec::with_capacity(accounts.len());
    for name in accounts {
        let path = resolve_keystore_file(keystore_dir, name);
        if !path.exists() {
            return Err(Error::Keystore(format!(
                "account '{}' not found at {}",
                name,
                path.display()
            )));
        }
        out.push(load(&path, &passphrase)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_keystore(dir: &Path, name: &str, passphrase: &str) -> [u8; 32] {
        // eth_keystore::new picks a random private key, encrypts it,
        // writes it to `dir/<returned uuid>`, and returns the key and
        // the filename. We immediately rename the file to `name` so the
        // test can look it up by a stable account name.
        let mut rng = OsRng;
        let (key_bytes, uuid_name) = eth_keystore::new(dir, &mut rng, passphrase, Some(name))
            .expect("new keystore");
        // eth_keystore v0.5 honors `Some(name)` and writes to `dir/name`.
        // Defensive: if it used a uuid, rename. (Newer versions may differ.)
        let target = dir.join(name);
        if !target.exists() {
            let source = dir.join(&uuid_name);
            std::fs::rename(&source, &target).expect("rename to account name");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key_bytes);
        k
    }

    #[test]
    fn resolve_relative_name() {
        let dir = Path::new("/tmp/ks");
        assert_eq!(
            resolve_keystore_file(dir, "bench-01"),
            PathBuf::from("/tmp/ks/bench-01")
        );
    }

    #[test]
    fn resolve_absolute_name() {
        let dir = Path::new("/tmp/ks");
        assert_eq!(
            resolve_keystore_file(dir, "/etc/custom/keystore"),
            PathBuf::from("/etc/custom/keystore")
        );
    }

    #[test]
    fn read_literal_passphrase() {
        let pw = read_passphrase(&PassphraseSource::Literal("secret".into())).expect("literal");
        assert_eq!(pw, "secret");
    }

    #[test]
    fn read_file_passphrase_trims_whitespace() {
        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        std::fs::write(tmp.path(), "  hunter2  \n").expect("write");
        let pw = read_passphrase(&PassphraseSource::File(tmp.path().to_path_buf()))
            .expect("file");
        assert_eq!(pw, "hunter2");
    }

    #[test]
    fn round_trip_encrypt_and_decrypt() {
        let dir = tempfile::tempdir().expect("dir");
        let key = make_keystore(dir.path(), "bench-01", "correct horse battery");
        let signer = load(&dir.path().join("bench-01"), "correct horse battery")
            .expect("decrypt");
        // Address derivation should agree with a fresh signer built
        // from the raw key.
        let fresh = Signer::from_key_bytes(&key).expect("fresh");
        assert_eq!(signer.address, fresh.address);
    }

    #[test]
    fn load_many_returns_requested_accounts() {
        let dir = tempfile::tempdir().expect("dir");
        let _k1 = make_keystore(dir.path(), "bench-01", "pw");
        let _k2 = make_keystore(dir.path(), "bench-02", "pw");
        let signers = load_many(
            dir.path(),
            &["bench-01".into(), "bench-02".into()],
            &PassphraseSource::Literal("pw".into()),
        )
        .expect("load_many");
        assert_eq!(signers.len(), 2);
        // Addresses must differ (different random keys)
        assert_ne!(signers[0].address, signers[1].address);
    }

    #[test]
    fn load_many_fails_on_missing_account() {
        let dir = tempfile::tempdir().expect("dir");
        let _k = make_keystore(dir.path(), "bench-01", "pw");
        let err = load_many(
            dir.path(),
            &["bench-01".into(), "bench-ZZ".into()],
            &PassphraseSource::Literal("pw".into()),
        )
        .expect_err("should fail");
        let msg = format!("{err}");
        assert!(msg.contains("bench-ZZ"), "error = {msg}");
    }

    #[test]
    fn load_many_fails_on_wrong_passphrase() {
        let dir = tempfile::tempdir().expect("dir");
        let _k = make_keystore(dir.path(), "bench-01", "right");
        assert!(load_many(
            dir.path(),
            &["bench-01".into()],
            &PassphraseSource::Literal("wrong".into()),
        )
        .is_err());
    }

    #[test]
    fn load_many_empty_accounts_errors() {
        let dir = tempfile::tempdir().expect("dir");
        assert!(load_many(dir.path(), &[], &PassphraseSource::Literal("pw".into())).is_err());
    }
}
