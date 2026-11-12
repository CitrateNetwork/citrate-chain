//citrate/cli/src/commands/rpc_hint.rs
//
// Plain-language guidance for the failures a new user hits first against the
// public chain 40204 network: no node on the default endpoint, and a public
// RPC that refuses unsigned transactions.

/// The public JSON-RPC endpoint for chain 40204.
pub const PUBLIC_RPC: &str = "https://rpc.citrate.ai";

/// The message a write command reports for a JSON-RPC error.
///
/// The write commands send `eth_sendTransaction`, which asks the node to sign.
/// Public nodes refuse it, so that error gets the next step appended. Every
/// other message is returned unchanged.
pub fn explain_send_error(message: &str) -> String {
    if message.contains("eth_sendTransaction is disabled") {
        format!(
            "{message}\n\nThis command sends an unsigned transaction for the node to sign \
             (eth_sendTransaction); citrate-cli does not sign transactions itself. Public \
             endpoints such as {PUBLIC_RPC} refuse that. To move SALT, use \
             `citrate-wallet send`, which signs locally. For contract and governance writes, \
             point --rpc at a local development node that has eth_sendTransaction enabled."
        )
    } else {
        message.to_string()
    }
}

/// A hint to print when a command could not reach the RPC endpoint at all
/// (connection refused, DNS failure, timeout while connecting).
pub fn connect_failure_hint(err: &anyhow::Error, endpoint: &str) -> Option<String> {
    let is_connect = err.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|e| e.is_connect())
    });
    if !is_connect {
        return None;
    }
    Some(format!(
        "Could not reach a node at {endpoint}. To use the public network, pass \
         --rpc {PUBLIC_RPC} or set CITRATE_RPC={PUBLIC_RPC}. To use your own node, \
         start it first or set rpc_endpoint in ~/.citrate/config.json."
    ))
}

/// The lines `network status` prints about which chain the endpoint serves.
///
/// * `node_chain_id`: the node's `eth_chainId`, if it answered.
/// * `config_chain_id`: the chain id in the CLI config.
/// * `node_genesis`: the hash of the node's block 0, if it answered.
/// * `book_genesis`: the genesis hash in the vendored federation contract
///   (`cli/federation-contract.json`), which `devx` reads its addresses from.
pub fn chain_lines(
    node_chain_id: Option<u64>,
    config_chain_id: u64,
    node_genesis: Option<&str>,
    book_genesis: Option<&str>,
) -> Vec<String> {
    let mut lines = Vec::new();
    match node_chain_id {
        Some(id) => {
            lines.push(format!("Chain ID: {id}"));
            if id != config_chain_id {
                lines.push(format!(
                    "WARNING: the node serves chain {id}, but the CLI config expects chain \
                     {config_chain_id}."
                ));
            }
        }
        None => lines.push(format!(
            "Chain ID: unknown (the node did not answer eth_chainId; config expects \
             {config_chain_id})"
        )),
    }
    if let Some(genesis) = node_genesis {
        match book_genesis {
            Some(book) if book.eq_ignore_ascii_case(genesis) => {
                lines.push(format!(
                    "Genesis: {genesis} (matches the vendored address book)"
                ));
            }
            Some(book) => {
                lines.push(format!("Genesis: {genesis}"));
                lines.push(format!(
                    "WARNING: the vendored address book is for genesis {book}. The addresses \
                     `devx contract` and `devx predict-address` use may be stale for this chain."
                ));
            }
            None => lines.push(format!("Genesis: {genesis}")),
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1007_GENESIS: &str =
        "0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631";
    const R1006_GENESIS: &str =
        "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4";

    #[test]
    fn a_refused_eth_send_transaction_says_what_to_do() {
        let msg = explain_send_error(
            "eth_sendTransaction is disabled. Use eth_sendRawTransaction with a signed transaction.",
        );
        assert!(msg.starts_with("eth_sendTransaction is disabled"), "{msg}");
        assert!(msg.contains("does not sign transactions"), "{msg}");
        assert!(msg.contains("citrate-wallet send"), "{msg}");
    }

    #[test]
    fn other_rpc_errors_pass_through_unchanged() {
        assert_eq!(explain_send_error("nonce too low"), "nonce too low");
    }

    /// A real connection failure: port 1 on loopback has no listener.
    async fn refused() -> anyhow::Error {
        let err = match reqwest::Client::new()
            .post("http://127.0.0.1:1")
            .body("{}")
            .send()
            .await
        {
            Ok(r) => panic!("unexpected listener on 127.0.0.1:1: {}", r.status()),
            Err(e) => e,
        };
        anyhow::Error::new(err).context("Failed to connect to RPC endpoint")
    }

    #[tokio::test]
    async fn unreachable_default_endpoint_points_at_the_public_rpc() {
        let err = refused().await;
        let hint = connect_failure_hint(&err, "http://localhost:8545").unwrap_or_default();
        assert!(hint.contains("http://localhost:8545"), "{hint}");
        assert!(hint.contains("--rpc https://rpc.citrate.ai"), "{hint}");
        assert!(hint.contains("CITRATE_RPC"), "{hint}");
    }

    #[test]
    fn errors_that_are_not_connection_failures_get_no_hint() {
        let err = anyhow::anyhow!("Transaction not found");
        assert!(connect_failure_hint(&err, "http://localhost:8545").is_none());
    }

    #[test]
    fn status_reports_the_node_chain_id_and_genesis() {
        let lines = chain_lines(Some(40204), 40204, Some(R1007_GENESIS), Some(R1007_GENESIS));
        let text = lines.join("\n");
        assert!(text.contains("Chain ID: 40204"), "{text}");
        assert!(
            text.contains(&format!("Genesis: {R1007_GENESIS}")),
            "{text}"
        );
        assert!(text.contains("matches the vendored address book"), "{text}");
        assert!(!text.contains("WARNING"), "{text}");
    }

    #[test]
    fn status_warns_when_the_node_is_not_the_configured_chain() {
        let text = chain_lines(Some(1), 40204, None, None).join("\n");
        assert!(text.contains("Chain ID: 1"), "{text}");
        assert!(text.contains("WARNING"), "{text}");
        assert!(text.contains("40204"), "{text}");
    }

    #[test]
    fn status_warns_when_the_vendored_book_is_for_another_genesis() {
        let text =
            chain_lines(Some(40204), 40204, Some(R1007_GENESIS), Some(R1006_GENESIS)).join("\n");
        assert!(text.contains("WARNING"), "{text}");
        assert!(text.contains(R1006_GENESIS), "{text}");
        assert!(text.contains("devx"), "{text}");
    }
}
