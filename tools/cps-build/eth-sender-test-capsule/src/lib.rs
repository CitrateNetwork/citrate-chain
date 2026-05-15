// CIT-AGENT-9c-write-host — eth-sender test capsule.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_send;
use bindings::exports::citrate::eth_sender_test::action::Guest;

struct Component;

impl Guest for Component {
    fn send(to: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, String> {
        eth_send::send(&to, &data)
    }
}

bindings::export!(Component with_types_in bindings);
