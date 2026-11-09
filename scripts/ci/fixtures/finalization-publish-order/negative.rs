// Fixture (finalization-publish-order, negative): the hook only raises the floor; publication
// happens in after_finalize, behind the persistence check. Nothing may be flagged.
pub struct FloorVerifier {
    verified_height: AtomicU64,
    verified_pairs: VerifiedPairs,
}

impl FloorVerifier {
    pub async fn on_finalize(&self, cert: &Checkpoint) -> Option<FloorTick> {
        self.applicator
            .register_certified(cert.height, cert.block_hash);
        // Not published here: the certificate is not persisted yet (record_verified waits).
        self.publish_metrics(false);
        Some(FloorTick::Verified)
    }

    pub async fn after_finalize(&self, cert: &Checkpoint) -> Option<FloorTick> {
        let published = self.record_verified(cert.height, cert.block_hash);
        Some(if published {
            FloorTick::Verified
        } else {
            FloorTick::Pending
        })
    }

    fn record_verified(&self, height: u64, hash: Hash) -> bool {
        if !self.manager.is_certificate_persisted(height, &hash) {
            return false;
        }
        self.verified_height.fetch_max(height, Ordering::SeqCst);
        self.verified_pairs.record(height, hash);
        true
    }

    fn publish_metrics(&self, halted: bool) {
        crate::metrics::record_finality_floor(halted);
    }
}

struct FinalizeHook(Weak<FloorVerifier>);

#[async_trait::async_trait]
impl FinalizationGuard for FinalizeHook {
    async fn before_finalize(&self, certificate: &Checkpoint) {
        if let Some(verifier) = self.0.upgrade() {
            let _ = verifier.on_finalize(certificate).await;
        }
    }

    async fn after_finalize(&self, certificate: &Checkpoint) {
        if let Some(verifier) = self.0.upgrade() {
            let _ = verifier.after_finalize(certificate).await;
        }
    }
}
