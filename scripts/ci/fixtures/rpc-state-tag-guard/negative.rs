// Fixture: every state-read handler checks the tag; other methods need no check.
fn register(io_handler: &mut IoHandler) {
    io_handler.add_sync_method("eth_getBalance", move |params: Params| {
        crate::state_tag::require_executed_head_state(params.get(1), &storage)?;
        Ok(balance())
    });
    io_handler.add_sync_method("eth_call", move |params: Params| {
        state_tag::require_executed_head_state(params.get(1), &storage)?;
        Ok(simulate())
    });
    io_handler.add_sync_method("eth_getBlockByNumber", move |params: Params| Ok(block()));
    // S3-7: a read routed through historical_state::resolve_state_read, which serves a
    // block of the applied chain below the head from the undo records and sends every
    // other tag through require_executed_head_state.
    io_handler.add_sync_method("eth_getStorageAt", move |params: Params| {
        let read = crate::historical_state::resolve_state_read(params.get(2), &storage, tags)?;
        Ok(slot(read))
    });
}
