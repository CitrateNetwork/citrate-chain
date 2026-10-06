---
created: 2026-10-01
branch: hup/n5-chain-precompiles
author: Larry Klosowski + Claude Opus 5.5
updated: 2026-10-04
status: accepted (active at genesis of the 2026-10-05 40204 reroll; placeholder gas schedule owner-signed)
---

# ADR-2026-10-01: Precompile integration and the agent precompile fork

## Status

Accepted 2026-10-04 (owner decision). Active at genesis of the 2026-10-05 40204 reroll:
the release pin is `(40204, Some(0))`, so the four precompiles are live from block 1 and
no mid-chain activation is scheduled. The placeholder gas schedule is owner-signed as is.
Implemented on `hup/n5-chain-precompiles`, carried onto `reroll/panic-s1`. Spec:
`docs/precompiles/AGENT_PRECOMPILES.md`.

## Context

The Hermes upskill program (planset decision D-25) asks for three things on chain:
finish the model/LoRA precompile integration, add a LoRA precompile for federated
learning, and add memory and agent precompiles. Three facts shape the design:

1. Model inference (0x0101 / 0x0102) is non-deterministic across hardware, so it is not
   a consensus operation (audit C-01). The node keeps it behind strict mode and the REVM
   bridge does not expose the inference family to contract code.
2. A CALL or STATICCALL to an address with no code succeeds with empty returndata. A
   contract that checks only the success flag cannot tell "no precompile here" from
   "the precompile answered".
3. Contract-visible precompile changes are consensus changes. They must not alter the
   result of any block below an agreed height.

## Decisions

### D1. Encoding: an in-contract adapter, not an ABI mode in the node

Contracts encode each precompile's native byte layout through one library,
`contracts/src/lib/CitratePrecompiles.sol`. The node does not learn to decode Solidity
ABI selectors.

Rejected: a "precompile ABI mode" in the node. It would add a second input format to
each precompile (two decoders to keep in consensus), and for the inference family it
would expose a non-deterministic operation to contract code.

### D2. Fail closed

Every library helper requires a successful call with output of the expected shape and
otherwise reverts (`PrecompileUnavailable`, `PrecompileBadOutput`). Model and LoRA
contracts route inference through it, and make no precompile call for operations that
are records (registration, training and merge requests, which run off chain and are
recorded by the operator, as `completeTraining` / `completeMerge` already did). On 40204
today, contract inference therefore reverts, together with any payment in the same call.

### D3. New precompiles are pure and live in already-reserved slots

`0x0112 LORA_APPLY`, `0x0113 LORA_MERGE`, `0x0121 MEMORY_ANCHOR_VERIFY`,
`0x0122 AGENT_OPS`. Pure byte functions only: Q16.16 integer arithmetic and SHA-256 /
keccak / secp256k1 recovery. Using reserved slots means `is_precompile` and the reserved
list do not change, and below the fork the addresses keep today's behaviour exactly.

- LoRA works per tile (at most 256 x 256 outputs) so a single disputed tile of a large
  adapter or aggregate can be recomputed on chain. It does not try to move whole model
  adapters through calldata.
- MEMORY_ANCHOR_VERIFY is byte-identical to the runtime's nightly anchor proof
  (`citrate-agent-anchor`), pinned by shared vectors.
- AGENT_OPS starts with DeviceLink / DeviceRevocation verification (the D-31 device
  identity), byte-identical to citrate-cluster, pinned by the shared golden messages. It
  is op-coded so later operations do not need new addresses; each new op is a new fork.

Considered and not built: an agent-ops "budget check" (already expressed in Solidity by
`BudgetedAutonomy` + `CapabilityGrant`; a precompile would add a second meter) and a
record-hash op (a domain-prefixed SHA-256 is cheap in Solidity via 0x02).

### D4. A separate activation height, pinned per release network

`core/execution/src/agent_fork.rs` holds one store and one resolver. On a release
network the release pin is the only source: a per-node env or config height refuses to
start, including while nothing is pinned. 40204 ships pinned at genesis (`Some(0)`,
accepted 2026-10-04). Dev chains may set it by config or env. The PBA hardening height
is independent (the reroll also pins it at genesis).

The REVM bridge registers the four precompiles only at and after the height (call and
create paths). The TLA+ model `specs/tla/consensus/AgentPrecompileFork.tla` checks that
started nodes agree on the precompile set at every height, and that the set below the
fork is the legacy set; a mutation that lets a node self-schedule on a release network
breaks agreement.

## Consequences

- Inference from contracts stays unavailable on 40204 until a deterministic or attested
  path exists (CM-08). The contracts will work unchanged if a later fork serves 0x0101 to
  contract code with the native layout.
- Gas values are conservative placeholders (RM-M2 matmul rate for LoRA; SHA-256 and
  ecrecover rates for the others), owner-signed as the genesis schedule. Changing them
  later is a new fork.
- The height is an owner decision (the pin: genesis of the reroll) and an operator action
  (build every node of the new genesis from the release commit). No agent sets the
  height, deploys, signs or sends.
- The model and LoRA contracts change bytecode; they are part of the post-reroll
  redeploy set (federation F-4) and are not deployed on 40204 today.
- Rule 6: this changes `citrate-execution` (a core crate); the daily benchmark must be
  run after merge. It was not run on this branch.
