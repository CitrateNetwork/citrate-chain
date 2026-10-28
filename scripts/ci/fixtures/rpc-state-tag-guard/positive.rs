// Fixture: state-read handlers that read the node's state without checking the block tag.
#[rustfmt::skip]
fn register(io_handler: &mut IoHandler) {
    io_handler.add_sync_method("eth_getBalance", move |params: Params| { // FLAG
        let tag = params.get(1).and_then(|v| v.as_str());
        require_serviceable_finality_tag(tag, &finalized, &storage, latest)?;
        Ok(balance())
    });
    io_handler.add_sync_method(
        "eth_call", // FLAG
        move |params: Params| {
            // require_executed_head_state(params.get(1), &storage) in a comment is not a call
            Ok(simulate())
        },
    );
    io_handler.add_method("eth_getStorageAt", move |params: Params| async move { // FLAG
        Ok(slot())
    });
}
