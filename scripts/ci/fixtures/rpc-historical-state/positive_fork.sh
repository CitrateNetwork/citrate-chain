#!/usr/bin/env bash
# Fixture (rpc-historical-state, positive): forking / calling at a past block over Citrate RPC.
set -euo pipefail
anvil --fork-url "$RPC" --fork-block-number 365784 & # FLAG
cast call "$ADDR" "owner()(address)" --rpc-url "$RPC" --block 365784 # FLAG
curl -s "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$A\",\"$HX\"],\"id\":1}" # FLAG
jr() { curl -s "$RPC" -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}"; }
jr eth_getStorageAt "[\"$C\",\"0x0\",\"$HX\"]" # FLAG
