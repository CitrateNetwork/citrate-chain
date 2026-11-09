// Fixture (wallet-gate-signing, negative): production code that signs through the gate.
// Nothing here may be flagged.
use citrate_wallet_core::{sign_eip155_legacy_tx, sign_recoverable, LegacyTxFields};

fn sign_drip_tx(
    key: &k256::ecdsa::SigningKey,
    tx: &LegacyTxFields,
    chain_id: u64,
) -> Result<Vec<u8>, String> {
    let signed = sign_eip155_legacy_tx(key, tx, chain_id).map_err(|e| e.to_string())?;
    let (r, s, v) =
        citrate_wallet_core::sign_recoverable(key, &signed.hash).map_err(|e| e.to_string())?;
    let (r2, s2, v2) = sign_recoverable(key, &signed.hash).map_err(|e| e.to_string())?;
    // key.sign_prehash_recoverable(&h) in a comment is not a call
    /* key.sign_prehash(&h) in a block comment is not a call */
    let note = "key.sign_prehash_recoverable(&h) in a string is not a call";
    // ed25519 proposer proofs are not wallet signatures: generic Signer::sign is out of scope
    let pop = proposer.sign(&digest);
    let _ = (r, s, v, r2, s2, v2, note, pop);
    Ok(signed.raw)
}
