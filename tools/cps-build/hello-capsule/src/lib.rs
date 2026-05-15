// CIT-AGENT-9b — hello-capsule implementation.
//
// Pure compute. No host imports. cargo-component auto-generates
// the `bindings` module from `wit/world.wit` at build time; we
// implement the Guest trait and call `export!` to wire it.

#[allow(warnings)]
mod bindings;

use bindings::exports::citrate::hello_capsule::greeter::Guest;

struct Component;

impl Guest for Component {
    fn greet(name: String) -> String {
        if name.is_empty() {
            "Hello, world".to_string()
        } else {
            format!("Hello, {name}")
        }
    }
}

bindings::export!(Component with_types_in bindings);
