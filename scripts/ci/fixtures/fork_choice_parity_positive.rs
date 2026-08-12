// FIXTURE (POSITIVE — the tripwire MUST flag this).
//
// Models the chain-40204 reroll wedge (2026-08-12): a producer path that stores
// a locally-produced block into the DAG store but NEVER registers it into
// GhostDAG's in-memory tip set. `select_tip` reads `GhostDag.tips`, so the
// produced blocks never enter fork-choice and the tip stays pinned to genesis
// while the single-producer chain grows — wedging at exactly SUPERSEDE_WALK_CAP+1.
//
// This file is scanned by fork_choice_add_block_parity_tripwire.sh --self-test.
// It is NOT compiled into any crate.

struct BlockProducer;

impl BlockProducer {
    // Regression shape: store_block with no ghostdag.add_block / register_existing_block.
    async fn produce_block(&self) -> anyhow::Result<Hash> {
        let block = self.build_block().await?;

        // Update DAG store — chain grows via dag_store.get_tips()...
        self.dag_store.store_block(block.clone()).await?;

        // ...but GhostDAG's tip set was NEVER told about our own block, so
        // `select_tip` stays pinned to genesis. THIS is the bug the tripwire catches.
        self.broadcast(block.clone()).await?;
        Ok(block.header.block_hash)
    }
}
