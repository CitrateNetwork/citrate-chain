// Fixture (wallet-gate-signing, positive): production code that calls the raw ECDSA primitive
// instead of the wallet-core signer. Every marked line must be flagged.
fn sign_drip_tx(key: &k256::ecdsa::SigningKey, sighash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let (sig, recid) = key.sign_prehash_recoverable(sighash).expect("sign"); // FLAG
    let _first = (&sig, &recid);
    // served from /fonts/* so a glob in a line comment must not open a block comment
    let url = "http://example.invalid/*"; // nor may one in a string
    let (sig2, _) = key
        .sign_prehash_recoverable(sighash) // FLAG: method on its own line
        .map_err(|e| e.to_string())?;
    let plain: k256::ecdsa::Signature = key.sign_prehash(sighash).expect("sign"); // FLAG
    let d = key.sign_digest_recoverable(digest).expect("sign"); // FLAG
    let t = key.sign_recoverable::<sha3::Keccak256>(msg); // FLAG: turbofish
    let _ = (sig, recid, url, sig2, plain, d, t);
    Ok(Vec::new())
}
