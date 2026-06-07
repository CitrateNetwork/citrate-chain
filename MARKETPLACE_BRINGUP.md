# Marketplace bring-up — register models + providers (chain 40204)

The buyer webapp + x402 gateway are wired and live, but the marketplace
gateway (`gateway.citrate.ai`) returns **no models** until models are
registered in `ModelRegistry` **and** at least one provider is registered
against `InferenceRouter`. This runbook gets a model serving end-to-end.

## Addresses (chain 40204, per `contracts/DEPLOYED_ADDRESSES.md`)

| Contract | Address |
|---|---|
| ModelRegistry | `0x077fbc3338a9e6bad90a3a041e6b7425689754ef` |
| InferenceRouter | `0xad7c3135c1b9b3189208fd617b6b058c1c0469f3` |
| ComputePricingOracle | `0xa1eed6ae021504e2a1e310e6c0f7c1a0c5bf4647` |
| WrappedSALT (wSALT) | `0x1f73bb479f397a34b5e3145e51d25bc5007273bf` |

RPC `https://rpc.citrate.ai` · Faucet `https://faucet.citrate.ai` (10 SALT / 24h).

## 0. Fund a registrar EOA

```bash
curl -s -X POST https://faucet.citrate.ai/faucet \
  -H 'content-type: application/json' -d '{"address":"0xYOUR_REGISTRAR"}'
```

You need ≥ 0.1 SALT per model (registration fee) plus the provider stake
(below). Drip a few times if needed.

## 1. Register starter models (ModelRegistry)

`script/RegisterStarterModels.s.sol` is ready — the default gemma model
already has its IPFS CID filled in.

```bash
cd contracts
export REGISTRAR_PRIVATE_KEY=0x...        # funded registrar
forge script script/RegisterStarterModels.s.sol:RegisterStarterModels \
  --rpc-url https://rpc.citrate.ai --broadcast --private-key $REGISTRAR_PRIVATE_KEY
```

- 0.1 SALT fee per model; safe to re-run (duplicates are skipped, not reverted).
- Verify — the gateway reads `ModelRegistry.listModels()`:

```bash
curl -s https://gateway.citrate.ai/v1/models | jq
```

## 2. Stand up a provider that speaks the gateway protocol

The gateway dispatches **`POST {endpoint}/infer`** with
`{ "model", "prompt", "max_tokens" }` and expects
`{ "output", "input_tokens", "output_tokens" }`
(`gateway/src/provider.rs::ProviderProtocolRequest`).

Raw llama.cpp (`/v1/chat/completions`, as on `infer.citrate.ai`) is **not**
this shape — run a thin adapter that exposes `/infer` and forwards to your
model server. The endpoint must be HTTPS and publicly reachable.

## 3. Register the provider (InferenceRouter)

```solidity
function registerProvider(string endpoint, uint256 minPrice, bytes32[] supportedModels) payable
// require(msg.value >= minProviderStake)
```

```bash
# read the current minimum stake
cast call 0xad7c3135c1b9b3189208fd617b6b058c1c0469f3 \
  "minProviderStake()(uint256)" --rpc-url https://rpc.citrate.ai

# the bytes32 model hash(es) come from ModelRegistry (step 1)
cast send 0xad7c3135c1b9b3189208fd617b6b058c1c0469f3 \
  "registerProvider(string,uint256,bytes32[])" \
  "https://your-provider.example/infer" \
  <minPriceWei> \
  "[<modelHash>]" \
  --value <stakeWei> \
  --rpc-url https://rpc.citrate.ai --private-key $PROVIDER_PRIVATE_KEY
```

- `--value` ≥ `minProviderStake`.
- `minPrice` is your per-inference floor (wei).

## 4. Verify end-to-end

```bash
curl -s https://gateway.citrate.ai/v1/models | jq          # model now listed
curl -s -X POST https://gateway.citrate.ai/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gemma-4-E4B-it-Q4_K_M","messages":[{"role":"user","content":"hi"}],"max_tokens":16}'
# → 200 (open-chat) or a 402 x402 challenge (paid path)
```

Once `/v1/models` is non-empty **and** the gateway CORS change is deployed
(`citrate-inference-gateway` — enable CORS PR), the buyer webapp's
auto-resolver picks `gateway.citrate.ai` and the x402 marketplace path lights
up automatically.

## Buyer funding (to actually pay x402)

x402 settles in **wSALT**. A fresh buyer wallet: faucet SALT → wrap to wSALT
(`WrappedSALT.deposit` / send native value to the wSALT contract, 1:1). The
webapp Wallet screen has a **Fund** (faucet) + **Wrap** button that does this.

## Related changes

- `citrate-inference-gateway` — enable CORS + fix the stale pricing-oracle
  address (so browsers can reach the gateway and pricing reads hit the real oracle).
- `citrate-sdk-marketplace` — canonical addresses (pricing oracle + deployed
  marketplace/bulk-gateway) corrected.
