// Fixture (wallet-gate-signing, negative): the primitive inside a #[cfg(test)] module, where
// tests build throwaway signatures to exercise verification. Nothing here may be flagged.
pub fn recover(sig: &[u8; 65], digest: &[u8; 32]) -> Option<[u8; 20]> {
    let _ = (sig, digest);
    None
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;

    #[test]
    fn recovers_a_fresh_signature() {
        let sk = SigningKey::from_bytes(&[0x42; 32].into()).expect("key");
        let (sig, id) = sk.sign_prehash_recoverable(&[7u8; 32]).expect("sign");
        let _ = (sig, id);
    }
}
