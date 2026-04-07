//! EIP-155 legacy transaction builder and signer.
//!
//! Produces the nine-element signed RLP
//! `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
//! where the signing hash is
//! `keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))`
//! and `v = chain_id * 2 + 35 + recovery_id`.
//!
//! The logic mirrors `tests/load/src/bin/bench_signed.rs` exactly so
//! that cross-checks between the two binaries can catch drift. Test
//! vectors include the canonical EIP-155 example.

use k256::ecdsa::SigningKey;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

use crate::signers::Signer;
use crate::tx::SignedTx;
use crate::{Error, Result};

/// Unsigned legacy transaction parameters.
#[derive(Debug, Clone)]
pub struct LegacyTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTx {
    /// Compute the EIP-155 signing pre-image: the RLP of
    /// `[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut s = RlpStream::new_list(9);
        append_u64(&mut s, self.nonce);
        append_u128(&mut s, self.gas_price);
        append_u64(&mut s, self.gas_limit);
        append_optional_address(&mut s, self.to.as_ref());
        append_u128(&mut s, self.value);
        s.append(&self.data.as_slice());
        append_u64(&mut s, self.chain_id);
        s.append_empty_data();
        s.append_empty_data();
        s.out().to_vec()
    }

    /// Keccak256 of the signing pre-image.
    pub fn signing_hash(&self) -> [u8; 32] {
        let pre = self.signing_preimage();
        let mut out = [0u8; 32];
        out.copy_from_slice(&Keccak256::digest(&pre));
        out
    }

    /// Sign with the given `Signer` and produce the final raw RLP.
    pub fn sign(&self, signer: &Signer) -> Result<SignedTx> {
        let hash = self.signing_hash();
        let key = SigningKey::from_bytes(signer.key_bytes().into())
            .map_err(|e| Error::Signing(format!("invalid secp256k1 key: {e}")))?;

        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| Error::Signing(format!("sign_prehash_recoverable: {e}")))?;

        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];
        let v = self
            .chain_id
            .checked_mul(2)
            .and_then(|n| n.checked_add(35))
            .and_then(|n| n.checked_add(recovery_id.to_byte() as u64))
            .ok_or_else(|| Error::Signing("v overflow".into()))?;

        let mut signed = RlpStream::new_list(9);
        append_u64(&mut signed, self.nonce);
        append_u128(&mut signed, self.gas_price);
        append_u64(&mut signed, self.gas_limit);
        append_optional_address(&mut signed, self.to.as_ref());
        append_u128(&mut signed, self.value);
        signed.append(&self.data.as_slice());
        append_u64(&mut signed, v);
        signed.append(&strip_leading_zeros(r));
        signed.append(&strip_leading_zeros(s));
        let raw = signed.out().to_vec();

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&Keccak256::digest(&raw));

        Ok(SignedTx {
            raw,
            hash: tx_hash,
            nonce: self.nonce,
            sender: signer.address,
        })
    }
}

fn append_u64(s: &mut RlpStream, value: u64) {
    let bytes = value.to_be_bytes();
    let stripped = strip_leading_zeros(&bytes);
    s.append(&stripped);
}

fn append_u128(s: &mut RlpStream, value: u128) {
    let bytes = value.to_be_bytes();
    let stripped = strip_leading_zeros(&bytes);
    s.append(&stripped);
}

fn append_optional_address(s: &mut RlpStream, to: Option<&[u8; 20]>) {
    match to {
        Some(addr) => {
            s.append(&addr.as_slice());
        }
        None => {
            // Contract creation: empty bytes for `to`.
            s.append_empty_data();
        }
    }
}

/// Strip leading zero bytes. `[0, 0, 1]` → `[1]`. All-zero input → `[]`.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-155 canonical test vector.
    ///
    /// From the EIP:
    ///
    /// > Consider a transaction with nonce = 9, gasprice = 20 * 10**9,
    /// > startgas = 21000, to = 0x3535353535353535353535353535353535353535,
    /// > value = 10**18, data = '' (empty).
    /// >
    /// > The "signing data" becomes:
    /// > 0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025
    /// >
    /// > The "signing hash" becomes:
    /// > 0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
    /// >
    /// > If signed by the private key
    /// >   0x4646464646464646464646464646464646464646464646464646464646464646
    /// > using chain_id 1, the resulting transaction is:
    /// > 0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
    const EIP155_PRIVKEY: [u8; 32] = [0x46; 32];
    const EIP155_TO: [u8; 20] = [0x35; 20];
    // Signing preimage: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
    // Ends with 80 (empty data) 01 (chain_id=1) 80 80 (two zeros).
    // This hashes to the canonical EIP-155 signing hash.
    const EIP155_SIGNING_PREIMAGE_HEX: &str = "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
    const EIP155_SIGNING_HASH_HEX: &str = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
    // Signed transaction RLP: final form with [v=37, r, s] replacing [chainId, 0, 0].
    // v = 37 = 0x25 for chain_id=1 + recovery_id=0 (since 1*2+35+0 = 37).
    const EIP155_SIGNED_HEX: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    fn eip155_tx() -> LegacyTx {
        LegacyTx {
            nonce: 9,
            gas_price: 20_000_000_000u128,
            gas_limit: 21_000,
            to: Some(EIP155_TO),
            value: 1_000_000_000_000_000_000u128,
            data: Vec::new(),
            chain_id: 1,
        }
    }

    #[test]
    fn signing_preimage_matches_eip155() {
        let tx = eip155_tx();
        assert_eq!(hex::encode(tx.signing_preimage()), EIP155_SIGNING_PREIMAGE_HEX);
    }

    #[test]
    fn signing_hash_matches_eip155() {
        let tx = eip155_tx();
        assert_eq!(hex::encode(tx.signing_hash()), EIP155_SIGNING_HASH_HEX);
    }

    #[test]
    fn signed_tx_matches_eip155_test_vector() {
        let signer = Signer::from_key_bytes(&EIP155_PRIVKEY).expect("signer");
        let tx = eip155_tx();
        let signed = tx.sign(&signer).expect("sign");
        assert_eq!(hex::encode(&signed.raw), EIP155_SIGNED_HEX);
        assert_eq!(signed.nonce, 9);
    }

    #[test]
    fn contract_creation_encodes_empty_to() {
        let signer = Signer::from_key_bytes(&EIP155_PRIVKEY).expect("signer");
        let tx = LegacyTx {
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 100_000,
            to: None,
            value: 0,
            data: vec![0x60, 0x80, 0x60, 0x40, 0x52],
            chain_id: 40204,
        };
        // Smoke check: signs cleanly and the raw bytes start with a
        // list header.
        let signed = tx.sign(&signer).expect("sign");
        assert!(!signed.raw.is_empty());
        // RLP list header byte: long list if len >= 56, else 0xc0 + len.
        // We don't assert the exact header here — just that it's a list.
        assert!(signed.raw[0] >= 0xc0);
    }

    #[test]
    fn strip_leading_zeros_behaviors() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[1]), &[1]);
        assert_eq!(strip_leading_zeros(&[]), &[] as &[u8]);
    }

    #[test]
    fn different_chain_ids_yield_different_v() {
        let signer = Signer::from_key_bytes(&EIP155_PRIVKEY).expect("signer");
        let mainnet = eip155_tx();
        let mut citrate = mainnet.clone();
        citrate.chain_id = 40204;
        let a = mainnet.sign(&signer).expect("mainnet");
        let b = citrate.sign(&signer).expect("citrate");
        assert_ne!(a.raw, b.raw);
    }
}
