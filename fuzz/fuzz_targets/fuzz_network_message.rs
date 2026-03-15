#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_network::protocol::NetworkMessage;

fuzz_target!(|data: &[u8]| {
    // Fuzz network message deserialization with arbitrary bytes.
    // NetworkMessage is a large enum covering: Hello, HelloAck, Disconnect,
    // Ping, Pong, NewBlock, NewTransaction, GetBlocks, BlockResponse,
    // and many more variants. Bincode must handle all malformed inputs gracefully.
    let _: Result<NetworkMessage, _> = bincode::deserialize(data);

    // JSON path (used in some API/debug contexts)
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<NetworkMessage, _> = serde_json::from_str(s);
    }
});
