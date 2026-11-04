//! #184: the VRF is bound to the slot (G9), and equivocation evidence is
//! recorded durably for the slashing path (G10, owner question O8). Spec:
//! planset 2026-11-03-r1007-v060, `06_CONSENSUS_SPEC.md` §2 G9, G10.

use citrate_consensus::dag_store::{DagStore, KvStore};
use citrate_consensus::slots::SLOT_DURATION_SECS;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature};
use citrate_consensus::vrf::VrfProposerSelector;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const G_TS: u64 = 1_767_225_600;

fn ts(slot: u64) -> u64 {
    G_TS + slot * SLOT_DURATION_SECS
}

fn id(tag: &[u8]) -> Hash {
    let mut b = [0u8; 32];
    for (d, s) in b.iter_mut().zip(tag.iter()) {
        *d = *s;
    }
    Hash::new(b)
}

fn genesis() -> Block {
    BlockBuilder::new()
        .hash(id(b"G"))
        .timestamp(G_TS)
        .build_unhashed()
}

/// A block of `key` at height 1 on genesis, stamped `timestamp`, whose ECVRF
/// proof is over `vrf_slot` (alpha = pubkey || genesis VRF output || slot) and
/// whose ed25519 signature covers its hash.
fn signed_block(tag: &[u8], key: &SigningKey, timestamp: u64, vrf_slot: u64, g: &Block) -> Block {
    let pk = PublicKey::new(key.verifying_key().to_bytes());
    let proof = VrfProposerSelector::production()
        .generate_vrf_proof(
            &key.to_bytes(),
            &pk,
            &g.header.vrf_reveal.output,
            vrf_slot,
        )
        .expect("ECVRF proof");
    let hash = id(tag);
    BlockBuilder::new()
        .hash(hash)
        .parent(g.hash())
        .height(1)
        .blue_score(1)
        .timestamp(timestamp)
        .proposer(pk)
        .vrf_reveal(proof)
        .signature(Signature::new(key.sign(hash.as_bytes()).to_bytes()))
        .build_unhashed()
}

/// G9: `alpha = pubkey || vrf_output(SP) || slot(B)`. A proof for slot s is
/// not a proof for slot s + 1, and a proof for the block's own slot is valid
/// even though it is not the block's height (the pre-r1007 alpha bound the
/// height).
#[tokio::test]
async fn vrf_proof_binds_slot() {
    let store = DagStore::with_strict_vrf(true);
    let g = genesis();
    store.store_block(g.clone()).await.expect("genesis");
    let key = SigningKey::from_bytes(&[0x42; 32]);

    let s = 7;
    let stale = signed_block(b"stale", &key, ts(s + 1), s, &g);
    let err = store
        .store_block(stale)
        .await
        .expect_err("a proof for slot s must be invalid at slot s + 1");
    assert!(
        err.to_string().contains("VRF"),
        "rejected for the VRF binding, got: {err}"
    );

    let height_bound = signed_block(b"height", &key, ts(s + 1), 1, &g);
    assert!(
        store.store_block(height_bound).await.is_err(),
        "a proof over the height (1) is not a proof over the slot ({})",
        s + 1
    );

    let honest = signed_block(b"honest", &key, ts(s + 1), s + 1, &g);
    store
        .store_block(honest)
        .await
        .expect("a proof for the block's own slot is valid");
}

#[derive(Default)]
struct MemKv {
    #[allow(clippy::type_complexity)]
    data: Mutex<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>,
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf).and_then(|m| m.get(key).cloned()))
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        d.entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        if let Some(m) = d.get_mut(cf) {
            m.remove(key);
        }
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self.kv_get(cf, key)?.is_some())
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }
}

/// O8: equivocation is red AND slashed. Slashing is out of scope here; the
/// evidence it needs is recorded when the second block of a (proposer, slot)
/// is stored, with both signed headers, and survives a restart and the pruning
/// of the blocks themselves. A different proposer in the same slot, or the
/// same proposer in another slot, is not evidence.
#[tokio::test]
async fn equivocation_evidence_recorded() {
    let kv = Arc::new(MemKv::default());
    let x = SigningKey::from_bytes(&[0x58; 32]);
    let y = SigningKey::from_bytes(&[0x59; 32]);
    let g = genesis();
    let a = signed_block(b"A", &x, ts(1), 1, &g);
    let a2 = signed_block(b"A2", &x, ts(1), 1, &g);
    let b = signed_block(b"B", &y, ts(1), 1, &g);
    let later = signed_block(b"L", &x, ts(2), 2, &g);
    {
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), true).expect("store");
        for blk in [&g, &a, &b, &later] {
            store.store_block(blk.clone()).await.expect("store");
        }
        assert!(
            store.equivocation_evidence().await.is_empty(),
            "honest width and a later slot are not equivocation"
        );
        store.store_block(a2.clone()).await.expect("stored, not rejected");
        let ev = store.equivocation_evidence().await;
        assert_eq!(ev.len(), 1, "one equivocation recorded");
        let e = &ev[0];
        assert_eq!(e.proposer, a.header.proposer_pubkey);
        assert_eq!(e.slot, 1);
        assert_eq!(e.hashes(), (a.hash(), a2.hash()));
        let enc = |h| bincode::serialize(h).expect("header encodes");
        assert_eq!(enc(&e.first), enc(&a.header), "first signed header kept");
        assert_eq!(e.first_signature, a.signature);
        assert_eq!(enc(&e.second), enc(&a2.header), "second signed header kept");
        assert_eq!(e.second_signature, a2.signature);
    }
    // Durable: a restarted node still holds it, after pruning the pair away.
    let store = DagStore::persistent_with_strict_vrf(kv.clone(), true).expect("reload");
    let ev = store.equivocation_evidence().await;
    assert_eq!(ev.len(), 1, "evidence survives a restart");
    assert_eq!(ev[0].hashes(), (a.hash(), a2.hash()));
    // C (height 2, on B) becomes the pruning point; everything below goes.
    let mut c = signed_block(b"C", &y, ts(3), 3, &b);
    c.header.height = 2;
    c.header.blue_score = 2;
    store.store_block(c.clone()).await.expect("child");
    store.update_pruning_point(c.hash()).await.expect("pp");
    assert!(store.prune().await.expect("prune") > 0);
    assert!(!store.has_block(&a.hash()).await, "pruned");
    let store = DagStore::persistent_with_strict_vrf(kv, true).expect("reload");
    assert_eq!(
        store.equivocation_evidence().await.len(),
        1,
        "evidence outlives the blocks it names"
    );
}
