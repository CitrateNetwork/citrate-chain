// Fixture (finalization-publish-order, positive): the finalization hook raises the floor and
// publishes the finalized pair to RPC before the certificate is written, and the publishing fn
// never checks persistence. Must be flagged (P2 and P3).
pub struct FloorVerifier {
    verified_height: AtomicU64,
    verified_pairs: VerifiedPairs,
}

impl FloorVerifier {
    pub async fn on_finalize(&self, cert: &Checkpoint) -> Option<FloorTick> {
        self.applicator
            .register_certified(cert.height, cert.block_hash);
        self.record_verified(cert.height, cert.block_hash);
        Some(FloorTick::Verified)
    }

    fn record_verified(&self, height: u64, hash: Hash) {
        self.verified_height.fetch_max(height, Ordering::SeqCst);
        self.verified_pairs.record(height, hash);
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
}
