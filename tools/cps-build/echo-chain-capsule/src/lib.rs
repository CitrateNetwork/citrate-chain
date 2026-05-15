// CIT-AGENT-9c-host — echo-chain capsule.
//
// Imports `citrate:chain/eth-call` and re-exports `query` that
// forwards (to, data) to the host. Used in cit-agent-core
// integration tests as the simplest capsule that proves the
// chain-call host plumbing works.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_call;
use bindings::exports::citrate::echo_chain_capsule::query::Guest;

struct Component;

impl Guest for Component {
    fn query(to: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, String> {
        eth_call::call(&to, &data)
    }
}

bindings::export!(Component with_types_in bindings);
