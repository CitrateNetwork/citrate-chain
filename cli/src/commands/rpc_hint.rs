//citrate/cli/src/commands/rpc_hint.rs
//
// Plain-language guidance for the failures a new user hits first against the
// public chain 40204 network: no node on the default endpoint, and a public
// RPC that refuses unsigned transactions.

/// The public JSON-RPC endpoint for chain 40204.
pub const PUBLIC_RPC: &str = "https://rpc.citrate.ai";

/// The message a write command reports for a JSON-RPC error.
pub fn explain_send_error(message: &str) -> String {
    message.to_string()
}

/// A hint to print when a command could not reach the RPC endpoint at all.
pub fn connect_failure_hint(_err: &anyhow::Error, _endpoint: &str) -> Option<String> {
    None
}

/// The lines `network status` prints about which chain the endpoint serves.
pub fn chain_lines(
    _node_chain_id: Option<u64>,
    config_chain_id: u64,
    _node_genesis: Option<&str>,
    _book_genesis: Option<&str>,
) -> Vec<String> {
    vec![format!("Chain ID: {}", config_chain_id)]
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
