#!/usr/bin/env bash
# Fixture (rpc-historical-state, negative): shell JSON-RPC at "latest", and comments only.
set -euo pipefail
# eth_getCode at an old block would be wrong here; we read latest.
curl -s "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$A\",\"latest\"],\"id\":1}"
cast call "$ADDR" "owner()(address)" --rpc-url "$RPC"
