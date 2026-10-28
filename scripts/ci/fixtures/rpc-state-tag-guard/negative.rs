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
}
