// Fixture (wallet-gate-signing, positive): the secp256k1 (C) crate's signing methods.
pub fn relay_sign(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    msg: &Message,
    sk: &SecretKey,
) -> [u8; 65] {
    let (rid, sig) = secp.sign_ecdsa_recoverable(msg, sk).serialize_compact(); // FLAG
    let plain = secp.sign_ecdsa(msg, sk); // FLAG
    let _ = (rid, sig, plain);
    [0u8; 65]
}
