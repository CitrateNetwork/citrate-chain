// FIXTURE (NEGATIVE — the tripwire MUST NOT flag this).
//
// The post-fix shape: every producer path that stores a locally-produced block
// into the DAG store ALSO registers it into GhostDAG, keeping the in-memory tip
// set that `select_tip` reads consistent with the DAG store.
//
// Two accepted registration forms are exercised:
//   * produce_block      -> ghostdag.add_block (fresh block, full BlueSet compute)
//   * eager_load_from_dag -> ghostdag.register_existing_block (cheap re-index at boot)
//
// This file is scanned by fork_choice_add_block_parity_tripwire.sh --self-test.
// It is NOT compiled into any crate.

struct BlockProducer;

impl BlockProducer {
    async fn produce_block(&self) -> anyhow::Result<Hash> {
        let block = self.build_block().await?;

        // Update DAG store.
        self.dag_store.store_block(block.clone()).await?;

        // FORK-CHOICE PARITY: register our own block into GhostDAG's tip set,
        // exactly as admission does for received blocks.
        if let Err(e) = self.ghostdag.add_block(&block).await {
            warn!("could not register produced block into GhostDAG tips: {e}");
        }
        Ok(block.header.block_hash)
    }

    // A multi-line signature that spans several lines before the body brace —
    // this used to break naive brace-depth segmentation.
    async fn eager_load_from_dag(
        dag_store: Arc<DagStore>,
        ghostdag: Arc<GhostDag>,
    ) -> anyhow::Result<()> {
        for block in dag_store.iter_blocks().await? {
            dag_store.store_block(block.clone()).await?;
            // PIL-13: at boot use register_existing_block, not add_block, to avoid
            // recomputing the full BlueSet for every historical block.
            ghostdag.register_existing_block(&block).await?;
        }
        Ok(())
    }
}
