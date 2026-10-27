//! `citrate host-identity`: mint (or read) a producer host's identity ON the host
//! and print only its public parts.
//!
//! A producer has three secrets, all made on its own host and none ever leaving it:
//!
//! | File | Key | Public part printed |
//! |---|---|---|
//! | `<data_dir>/noise.key` | x25519 Noise static key (P2P identity) | `peer_id`, `noise_pubkey` |
//! | `<data_dir>/proposer.key` | ed25519 seed (block signing, registration proof, finality votes) | `proposer_pubkey`, and the P-256 ECVRF key derived from the same seed as `vrf_pubkey` |
//! | `--staker-keystore` | secp256k1 EOA, Web3 Secret Storage v3 (scrypt, aes-128-ctr) | `staker_address` = `coinbase_address` |
//!
//! There is no separate VRF secret: `producer.rs` proves the block VRF with
//! `ecvrf::prove(proposer seed, …)`, so the VRF key is derived from `proposer.key`.
//! There is no separate coinbase key either: consensus requires a block's coinbase to
//! equal its proposer's registered staker (executor check 3c), so the staker EOA is the
//! coinbase.
//!
//! The noise and proposer files are minted by the node's own loaders
//! (`load_or_generate_noise_keypair`, `load_or_generate_proposer_key`: 0600, create-new),
//! so a key minted here is byte-for-byte what the node would have minted on first start.
//! The keystore is written to a private temp file and hard-linked into place, so an
//! existing keystore is never overwritten. Its password is a random 32-byte hex string
//! in `--staker-password-file` (0600), the file Foundry reads with `--password-file`.
//!
//! Without `--mint` nothing is created: a missing file is an error. Secret bytes are
//! never printed, logged or written anywhere but their own 0600 file.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Output schema tag; the bring-up collector refuses anything else.
pub const SCHEMA: &str = "citrate-host-identity/1";

/// scrypt cost for a new keystore: Geth/Web3 "standard" (n = 2^18, r = 8, p = 1).
const SCRYPT_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Everything public about one host. No field is derived from anything but a public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostIdentity {
    pub schema: &'static str,
    pub peer_id: String,
    pub noise_pubkey: String,
    pub proposer_pubkey: String,
    pub vrf_pubkey: String,
    pub staker_address: String,
    pub coinbase_address: String,
}

pub struct IdentityPaths {
    pub data_dir: PathBuf,
    pub staker_keystore: PathBuf,
    pub staker_password_file: PathBuf,
}

pub fn run(paths: &IdentityPaths, mint: bool) -> anyhow::Result<HostIdentity> {
    let noise_path = paths.data_dir.join("noise.key");
    let proposer_path = paths.data_dir.join("proposer.key");
    if !mint {
        for p in [&noise_path, &proposer_path, &paths.staker_keystore] {
            if !p.exists() {
                bail!(
                    "{} does not exist (pass --mint to create the host identity)",
                    p.display()
                );
            }
        }
    }
    if mint && !paths.data_dir.is_dir() {
        bail!("data dir {} does not exist", paths.data_dir.display());
    }
    let noise = crate::load_or_generate_noise_keypair(&noise_path)?;
    let proposer = crate::load_or_generate_proposer_key(&proposer_path)?;
    let seed = Zeroizing::new(proposer.to_bytes());
    let vrf_pubkey = citrate_consensus::ecvrf::derive_public_key(&seed);

    let staker = if paths.staker_keystore.exists() {
        keystore_address(&paths.staker_keystore)?
    } else if mint {
        mint_staker_keystore(
            &paths.staker_keystore,
            &paths.staker_password_file,
            SCRYPT_LOG_N,
        )?
    } else {
        bail!("{} does not exist", paths.staker_keystore.display());
    };
    let staker = format!("0x{}", hex::encode(staker));
    Ok(HostIdentity {
        schema: SCHEMA,
        peer_id: noise.derive_peer_id().to_string(),
        noise_pubkey: noise.public_key_hex(),
        proposer_pubkey: format!("0x{}", hex::encode(proposer.verifying_key().to_bytes())),
        vrf_pubkey: format!("0x{}", hex::encode(vrf_pubkey)),
        coinbase_address: staker.clone(),
        staker_address: staker,
    })
}

/// Write the public identity (mode 0644) atomically.
pub fn write_public(path: &Path, id: &HostIdentity) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".identity.pub.{}.tmp",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    let mut body = serde_json::to_vec_pretty(id)?;
    body.push(b'\n');
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o644);
    }
    let written = o
        .open(&tmp)
        .and_then(|mut f| f.write_all(&body).and_then(|_| f.sync_all()))
        .and_then(|_| {
            // Mode set explicitly: the umask must not hide the public file from readers.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
            }
            std::fs::rename(&tmp, path)
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn owner_only(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has mode {:o}; it must be readable by its owner only",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

/// The address recorded in an existing v3 keystore. Only the public `address` field is
/// read; nothing is decrypted.
pub fn keystore_address(path: &Path) -> anyhow::Result<[u8; 20]> {
    owner_only(path)?;
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)
        .with_context(|| format!("{} is not a JSON keystore", path.display()))?;
    let a = v
        .get("address")
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow!("{} has no address field", path.display()))?;
    let bytes = hex::decode(a.trim_start_matches("0x")).context("keystore address is not hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("keystore address is not 20 bytes"))
}

/// Create a 0600 file that must not exist yet, with `bytes` in it.
fn create_new_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn eth_address(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let h = Keccak256::digest(point.as_bytes().get(1..).unwrap_or_default());
    let mut out = [0u8; 20];
    out.copy_from_slice(h.get(12..32).unwrap_or(&[0u8; 20]));
    out
}

fn mint_staker_keystore(
    keystore: &Path,
    password_file: &Path,
    log_n: u8,
) -> anyhow::Result<[u8; 20]> {
    let dir = keystore
        .parent()
        .filter(|d| d.is_dir())
        .ok_or_else(|| anyhow!("keystore dir for {} does not exist", keystore.display()))?;
    let password = if password_file.exists() {
        owner_only(password_file)?;
        let p = Zeroizing::new(std::fs::read_to_string(password_file)?);
        let line = Zeroizing::new(p.lines().next().unwrap_or("").to_string());
        if line.len() < 16 {
            bail!(
                "{} holds a password shorter than 16 characters",
                password_file.display()
            );
        }
        line
    } else {
        let raw: Zeroizing<[u8; 32]> = Zeroizing::new(rand::random());
        let p = Zeroizing::new(hex::encode(raw.as_slice()));
        create_new_0600(password_file, p.as_bytes())?;
        p
    };
    let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let address = eth_address(&key);
    let secret = Zeroizing::new(key.to_bytes().to_vec());
    let json = encrypt_v3(&secret, password.as_bytes(), &address, log_n)?;

    // Private temp file in the same dir, then a hard link: link(2) fails if the
    // keystore appeared meanwhile, so nothing is ever overwritten.
    let tmp = dir.join(format!(
        ".staker-keystore.{}.tmp",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    create_new_0600(&tmp, json.as_bytes())?;
    let linked = std::fs::hard_link(&tmp, keystore);
    let _ = std::fs::remove_file(&tmp);
    linked
        .with_context(|| format!("{} already exists or cannot be created", keystore.display()))?;
    Ok(address)
}

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

fn derive_key(password: &[u8], salt: &[u8], log_n: u8) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| anyhow!("scrypt params: {e}"))?;
    let mut dk = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &params, dk.as_mut_slice())
        .map_err(|e| anyhow!("scrypt: {e}"))?;
    Ok(dk)
}

fn mac(dk: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(dk.get(16..32).unwrap_or_default());
    h.update(ciphertext);
    h.finalize().into()
}

/// Web3 Secret Storage v3 (the format `cast wallet` and Geth read).
fn encrypt_v3(
    secret: &[u8],
    password: &[u8],
    address: &[u8; 20],
    log_n: u8,
) -> anyhow::Result<String> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let salt: [u8; 32] = rand::random();
    let iv: [u8; 16] = rand::random();
    let dk = derive_key(password, &salt, log_n)?;
    let mut ct = secret.to_vec();
    let enc_key = dk
        .get(0..16)
        .ok_or_else(|| anyhow!("derived key too short"))?;
    let mut cipher = Aes128Ctr::new(enc_key.into(), &iv.into());
    cipher.apply_keystream(&mut ct);
    let id: [u8; 16] = {
        let mut b: [u8; 16] = rand::random();
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        b
    };
    let h = hex::encode(id);
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        h.get(0..8).unwrap_or_default(),
        h.get(8..12).unwrap_or_default(),
        h.get(12..16).unwrap_or_default(),
        h.get(16..20).unwrap_or_default(),
        h.get(20..32).unwrap_or_default()
    );
    let v = serde_json::json!({
        "address": hex::encode(address),
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": { "iv": hex::encode(iv) },
            "ciphertext": hex::encode(&ct),
            "kdf": "scrypt",
            "kdfparams": { "dklen": 32, "n": 1u64 << log_n, "p": SCRYPT_P, "r": SCRYPT_R, "salt": hex::encode(salt) },
            "mac": hex::encode(mac(&dk, &ct)),
        },
        "id": uuid,
        "version": 3,
    });
    Ok(serde_json::to_string(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only decrypt, to prove the keystore holds the key whose address it records.
    fn decrypt_v3(json: &str, password: &[u8]) -> anyhow::Result<Vec<u8>> {
        use ctr::cipher::{KeyIvInit, StreamCipher};
        let v: serde_json::Value = serde_json::from_str(json)?;
        let c = &v["crypto"];
        let n = c["kdfparams"]["n"].as_u64().ok_or_else(|| anyhow!("n"))?;
        let salt = hex::decode(c["kdfparams"]["salt"].as_str().unwrap_or_default())?;
        let iv = hex::decode(c["cipherparams"]["iv"].as_str().unwrap_or_default())?;
        let mut ct = hex::decode(c["ciphertext"].as_str().unwrap_or_default())?;
        let dk = derive_key(password, &salt, n.trailing_zeros() as u8)?;
        if hex::encode(mac(&dk, &ct)) != c["mac"].as_str().unwrap_or_default() {
            bail!("mac mismatch");
        }
        let iv: [u8; 16] = iv.as_slice().try_into()?;
        let mut cipher = Aes128Ctr::new(dk[0..16].into(), &iv.into());
        cipher.apply_keystream(&mut ct);
        Ok(ct)
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
    }

    fn paths(dir: &Path) -> IdentityPaths {
        let data = dir.join("data");
        let etc = dir.join("etc");
        std::fs::create_dir_all(&data).expect("data");
        std::fs::create_dir_all(&etc).expect("etc");
        IdentityPaths {
            data_dir: data,
            staker_keystore: etc.join("staker.keystore.json"),
            staker_password_file: etc.join("staker.password"),
        }
    }

    #[test]
    fn keystore_round_trips_and_records_its_address() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let addr = eth_address(&key);
        let json = encrypt_v3(&key.to_bytes(), b"pw-0123456789abcdef", &addr, 4).expect("encrypt");
        let back = decrypt_v3(&json, b"pw-0123456789abcdef").expect("decrypt");
        assert_eq!(back, key.to_bytes().to_vec());
        let v: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(v["address"], hex::encode(addr));
        assert_eq!(v["version"], 3);
        assert_eq!(v["crypto"]["cipher"], "aes-128-ctr");
        assert!(
            decrypt_v3(&json, b"wrong-password-xxxx").is_err(),
            "a wrong password must fail the MAC"
        );
    }

    #[test]
    fn known_address_vector() {
        // secp256k1 secret 1 -> 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf (well-known).
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = k256::ecdsa::SigningKey::from_bytes((&one).into()).expect("key");
        assert_eq!(
            hex::encode(eth_address(&key)),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    #[cfg(unix)]
    fn mint_creates_owner_only_files_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        let first = run_with_cost(&p, true, 4).expect("mint");
        for f in [
            p.data_dir.join("noise.key"),
            p.data_dir.join("proposer.key"),
            p.staker_keystore.clone(),
            p.staker_password_file.clone(),
        ] {
            assert!(f.exists(), "{} minted", f.display());
            assert_eq!(mode(&f), 0o600, "{} is owner-only", f.display());
        }
        assert_eq!(first.staker_address, first.coinbase_address);
        assert_eq!(first.peer_id, format!("noise_{}", first.noise_pubkey));
        assert_ne!(
            first.vrf_pubkey, first.proposer_pubkey,
            "VRF key is the P-256 key, not the ed25519 one"
        );
        let ks_before = std::fs::read(&p.staker_keystore).expect("ks");
        let second = run_with_cost(&p, true, 4).expect("re-run");
        assert_eq!(first, second, "a second run reports the same identity");
        assert_eq!(
            std::fs::read(&p.staker_keystore).expect("ks"),
            ks_before,
            "keystore untouched"
        );
        let third = run_with_cost(&p, false, 4).expect("read-only run");
        assert_eq!(first, third);
    }

    #[test]
    fn without_mint_nothing_is_created() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        let err = run_with_cost(&p, false, 4).expect_err("missing identity must fail");
        assert!(err.to_string().contains("--mint"), "{err}");
        assert!(!p.data_dir.join("noise.key").exists());
        assert!(!p.data_dir.join("proposer.key").exists());
        assert!(!p.staker_keystore.exists());
        assert!(!p.staker_password_file.exists());
    }

    #[test]
    #[cfg(unix)]
    fn output_carries_no_secret_bytes() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        let id = run_with_cost(&p, true, 4).expect("mint");
        let out = serde_json::to_string(&id).expect("json").to_lowercase();
        let noise = std::fs::read(p.data_dir.join("noise.key")).expect("noise");
        let seed = std::fs::read(p.data_dir.join("proposer.key")).expect("seed");
        let pw = std::fs::read_to_string(&p.staker_password_file).expect("pw");
        let ks = std::fs::read_to_string(&p.staker_keystore).expect("ks");
        let secret = decrypt_v3(&ks, pw.trim().as_bytes()).expect("decrypt");
        // noise.key is private(32) || public(32): only the public half may appear.
        let noise_private = hex::encode(noise.get(0..32).expect("priv"));
        for (what, s) in [
            ("noise private", noise_private),
            ("proposer seed", hex::encode(&seed)),
            ("staker secret", hex::encode(&secret)),
            ("keystore password", pw.trim().to_lowercase()),
        ] {
            assert!(!out.contains(&s), "{what} leaked into the public identity");
        }
        // And the staker address really belongs to the minted secret.
        let key = k256::ecdsa::SigningKey::from_slice(&secret).expect("key");
        assert_eq!(
            format!("0x{}", hex::encode(eth_address(&key))),
            id.staker_address
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_group_readable_keystore_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        run_with_cost(&p, true, 4).expect("mint");
        std::fs::set_permissions(&p.staker_keystore, std::fs::Permissions::from_mode(0o640))
            .expect("chmod");
        let err = run_with_cost(&p, false, 4).expect_err("loose keystore");
        assert!(err.to_string().contains("owner only"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn public_file_is_world_readable_json() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        let id = run_with_cost(&p, true, 4).expect("mint");
        let out = dir.path().join("identity.pub.json");
        write_public(&out, &id).expect("write");
        assert_eq!(mode(&out), 0o644);
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).expect("read")).expect("json");
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["staker_address"], id.staker_address.as_str());
    }

    /// Pins the VRF key's derivation input: it is the P-256 key of the proposer SEED, the
    /// key `producer.rs` proves block VRFs with, so peers verify this host's proofs with
    /// it. Deriving it from anything else (the ed25519 public key, the noise key) makes
    /// every VRF proof this producer signs disagree with its registered key.
    #[test]
    fn vrf_pubkey_is_the_key_block_vrf_proofs_carry() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = paths(dir.path());
        let id = run_with_cost(&p, true, 4).expect("mint");
        let seed: [u8; 32] = std::fs::read(p.data_dir.join("proposer.key"))
            .expect("proposer.key")
            .get(..32)
            .and_then(|b| b.try_into().ok())
            .expect("32-byte seed");
        let (proof, _beta) =
            citrate_consensus::ecvrf::prove(&seed, b"r1006 vrf pin").expect("prove");
        let carried = format!("0x{}", hex::encode(&proof.to_bytes()[..33]));
        assert_eq!(
            id.vrf_pubkey, carried,
            "vrf_pubkey is not the key the producer's VRF proofs carry"
        );
        citrate_consensus::ecvrf::verify(b"r1006 vrf pin", &proof).expect("verifies");
        // Negative control: the same derivation over the ed25519 PUBLIC key differs.
        let pk_hex = id.proposer_pubkey.trim_start_matches("0x");
        let pk: [u8; 32] = hex::decode(pk_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        assert_ne!(
            id.vrf_pubkey,
            format!("0x{}", hex::encode(citrate_consensus::ecvrf::derive_public_key(&pk))),
            "derived from the public key"
        );
    }

    /// `run` with a cheap scrypt cost so tests stay fast; the CLI always uses 2^18.
    fn run_with_cost(p: &IdentityPaths, mint: bool, log_n: u8) -> anyhow::Result<HostIdentity> {
        if mint && !p.staker_keystore.exists() {
            if !p.data_dir.join("noise.key").exists() || !p.data_dir.join("proposer.key").exists() {
                crate::load_or_generate_noise_keypair(&p.data_dir.join("noise.key"))?;
                crate::load_or_generate_proposer_key(&p.data_dir.join("proposer.key"))?;
            }
            mint_staker_keystore(&p.staker_keystore, &p.staker_password_file, log_n)?;
        }
        run(p, mint)
    }
}
