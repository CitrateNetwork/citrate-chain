//! `citrate registration-proof`: the proof of key control a producer gives the r1006
//! genesis build, made ON the producer host.
//!
//! The r1006 genesis registers its producers in the ValidatorRegistry at block 0. The
//! registry's `registerValidator` checks an ed25519 signature by the proposer key over the
//! registration digest (`citrate_consensus::crypto::registration_digest`: chain id,
//! registry, staker, proposer key, nonce 0). This command signs exactly that digest with the
//! host's `proposer.key` and prints only public values (the proposer public key, the staker,
//! the registry, the signature). The key is never printed, logged or passed on a command
//! line. The genesis fill (`scripts/genesis/r1006/fill_producers.py`) verifies each
//! signature and the build replays the registration with it.

use citrate_consensus::crypto::{block_signing_key_from_seed, sign_registration, Ed25519SigningKey};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub const SCHEMA: &str = "citrate-registration-proof/1";

/// Read `proposer.key` (a 32-byte ed25519 seed). Refuses a missing file: this command never
/// mints an identity.
pub fn load_proposer_key(path: &Path) -> anyhow::Result<Ed25519SigningKey> {
    if !path.exists() {
        anyhow::bail!("no proposer key at {path:?}: run the node (or `citrate host-identity`) first");
    }
    let seed = Zeroizing::new(std::fs::read(path).map_err(|e| anyhow::anyhow!("read {path:?}: {e}"))?);
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| anyhow::anyhow!("{path:?} is {} bytes, expected a 32-byte seed", seed.len()))?,
    );
    Ok(block_signing_key_from_seed(&arr))
}

fn addr(raw: &str, what: &str) -> anyhow::Result<[u8; 20]> {
    let b = hex::decode(raw.trim().trim_start_matches("0x")).map_err(|e| anyhow::anyhow!("{what} {raw}: {e}"))?;
    <[u8; 20]>::try_from(b.as_slice()).map_err(|_| anyhow::anyhow!("{what} {raw}: not 20 bytes"))
}

/// The public proof for `key`: the registration digest signed for (chain id, registry,
/// staker, nonce 0).
pub fn proof(chain_id: u64, registry: &str, staker: &str, key: &Ed25519SigningKey) -> anyhow::Result<Value> {
    let reg = addr(registry, "registry")?;
    let st = addr(staker, "staker")?;
    let pk = key.verifying_key().to_bytes();
    let sig = sign_registration(chain_id, &reg, &st, &pk, 0, key);
    Ok(json!({
        "schema": SCHEMA,
        "chain_id": chain_id,
        "registry": format!("0x{}", hex::encode(reg)),
        "staker": format!("0x{}", hex::encode(st)),
        "proposer_pubkey": format!("0x{}", hex::encode(pk)),
        "registration_sig": format!("0x{}", hex::encode(sig.as_bytes())),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn the_proof_verifies_over_the_registration_digest_and_holds_no_secret() {
        let seed = [9u8; 32];
        let key = block_signing_key_from_seed(&seed);
        let reg = "0x1111111111111111111111111111111111111111";
        let st = "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
        let p = proof(40204, reg, st, &key).expect("proof");
        let sig_hex = p["registration_sig"].as_str().expect("sig");
        let sig = Signature::from_slice(&hex::decode(&sig_hex[2..]).expect("hex")).expect("64 bytes");
        let digest = citrate_consensus::crypto::registration_digest(
            40204,
            &[0x11; 20],
            &[0xa0; 20],
            &key.verifying_key().to_bytes(),
            0,
        );
        key.verifying_key().verify(&digest, &sig).expect("the proof verifies");
        // Another registry or chain id does not verify.
        let other = citrate_consensus::crypto::registration_digest(1, &[0x11; 20], &[0xa0; 20], &key.verifying_key().to_bytes(), 0);
        assert!(key.verifying_key().verify(&other, &sig).is_err());
        let text = p.to_string();
        assert!(!text.contains(&hex::encode(seed)), "the seed never appears");
        assert_eq!(p["proposer_pubkey"], format!("0x{}", hex::encode(key.verifying_key().to_bytes())));
    }

    /// The digest the fill (scripts/genesis/r1006/fill_producers.py) verifies against is
    /// the one this signs: a golden vector shared by both (the shell suite pins the same).
    #[test]
    fn the_registration_digest_matches_the_fill_golden_vector() {
        let d = citrate_consensus::crypto::registration_digest(40204, &[0x11; 20], &[0xa0; 20], &[0x01; 32], 0);
        assert_eq!(hex::encode(d), "9884befc29931c0e18cc170372c8131d32ec2a153ead11a49541014804569f23");
    }

    #[test]
    fn a_missing_key_is_refused_never_minted() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("proposer.key");
        assert!(load_proposer_key(&p).is_err());
        assert!(!p.exists(), "nothing was minted");
        std::fs::write(&p, [1u8; 31]).expect("write");
        assert!(load_proposer_key(&p).is_err(), "wrong length refused");
    }
}
