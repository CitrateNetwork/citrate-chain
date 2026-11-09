// Fixture (finalization-publish-order, positive): a guard whose publication path matches none
// of the P1 anchors. The scan must fail closed (P4) rather than pass it unexamined.
struct TagHook(Arc<Tags>);

#[async_trait::async_trait]
impl FinalizationGuard for TagHook {
    async fn before_finalize(&self, certificate: &Checkpoint) {
        self.0.update(certificate.height, certificate.block_hash);
    }
}
