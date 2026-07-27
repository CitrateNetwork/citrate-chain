#!/usr/bin/env bash
# SRP-S4 Phase-1 (WP-1.2) local reproduction harness — WIP.
# Local §R'-active producer + cold-sync follower, mined deep past the S(E)
# boundary that first desyncs the durable store from the root-folded resident map,
# then `state-digest` diffs the two data dirs to NAME the diverging account/slot.
#
# TWO BLOCKERS TO CLEAR (see planset 2026-07-22-srp-s4-reward-rmw-store-purity.md):
#   1. local `--network testnet` genesis under-funds the deployer for the 32k SALT
#      bond -> deploy a low-minStake registry + recompute its CREATE2 addr + set
#      CITRATE_VALIDATOR_REGISTRY to it before starting the producer.
#   2. the CREATE2 registry deploy currently fails (gasUsed 700) -> debug the forge
#      init-code/broadcast (FOUNDRY_VIA_IR, --skip-simulation).
# Once §R' engages past activation, extend the run deep + add the state-digest diff.
#
# SRP-S4 reproduction harness: local §R'-active producer + cold-sync follower,
# mined deep until the cold-sync state-root diverges, then state-digest both data
# dirs to NAME the diverging account/slot. Pins the live block-5406 wedge locally.
set -uo pipefail
CHAIN=/home/saul/Projects/Citrate-Labs/citrate-chain
BIN=$CHAIN/target/release/citrate
DIG=$CHAIN/target/release/state-digest
SCR=/tmp/claude-1000/-home-saul-Projects-Citrate-Labs/24130b06-755f-4d61-b09c-8ce5c1ea552c/scratchpad
DIR=$SCR/s4; rm -rf "$DIR"; mkdir -p "$DIR"
ENVF=/home/saul/Projects/Citrate-Labs/.env.testnet
DK=$(grep -m1 '^DEPLOYER_PRIVATE_KEY=' "$ENVF" | cut -d= -f2)
DEP=0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732
REG=0x915DdE02831ebacFc57f329f60944492ebb0A095
export CITRATE_STORAGE_KEY=0000000000000000000000000000000000000000000000000000000000000001
export CITRATE_BLOCK_V2=1 CITRATE_VALIDATOR_ACTIVATION_HEIGHT=800 CITRATE_VALIDATOR_REGISTRY=$REG
hi(){ curl -s -m4 -X POST 127.0.0.1:$1 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -oE '0x[0-9a-f]+' | head -1 | (read h; echo $((${h:-0}))); }

echo "== [1] producer: coinbase=staker=deployer, §R' activation=800 =="
setsid nohup "$BIN" --network testnet --mine --coinbase "$DEP" --data-dir "$DIR/p" \
  --rpc-addr 127.0.0.1:18800 --p2p-addr 0.0.0.0:30800 --bootstrap >"$DIR/p.log" 2>&1 & disown
for i in $(seq 1 25); do sleep 3; [ "$(hi 18800)" -ge 4 ] && break; done
echo "   producer up @ height $(hi 18800)"

echo "== [2] deploy ValidatorRegistry via CREATE2 (-> $REG) =="
cd "$CHAIN/contracts"
FOUNDRY_VIA_IR=true DEPLOYER_ADDRESS=$DEP forge script script/DeployValidatorRegistry.s.sol \
  --rpc-url http://127.0.0.1:18800 --private-key "$DK" --broadcast --skip-simulation >"$DIR/deploy.log" 2>&1
code=$(cast code $REG --rpc-url http://127.0.0.1:18800 2>/dev/null | wc -c)
echo "   registry code bytes: $code  (expect >2)"; [ "$code" -gt 2 ] || { echo "DEPLOY FAILED"; tail -8 "$DIR/deploy.log"; exit 1; }

echo "== [3] register the producer's validator (staker=coinbase=deployer, 32k SALT) =="
cd "$CHAIN"
VALIDATOR_STAKER_1=$DK cargo run --release --quiet --bin validator-registration-ceremony -- \
  --rpc-url http://127.0.0.1:18800 --registry $REG \
  --node ${DEP}=VALIDATOR_STAKER_1 --force >"$DIR/register.log" 2>&1
echo "   registration exit=$?"; tail -3 "$DIR/register.log"

echo "== [4] wait for producer to CROSS activation 800 (proves §R' policy materialized) =="
for i in $(seq 1 120); do sleep 5; h=$(hi 18800); [ "$h" -ge 810 ] && break; done
PH=$(hi 18800)
echo "   producer head=$PH"
if [ "$PH" -lt 810 ]; then echo "PRODUCER STALLED before/at activation — §R' policy likely failed to materialize"; grep -iE "R'|reward|policy|reject|halt|snapshot" "$DIR/p.log" | tail -8; exit 1; fi
echo "   >>> §R' ACTIVE and producing past 800. Setup validated."
echo "PHASE1_OK head=$PH"
