# Adversarial Testing Harness

This document describes the adversarial test suite for Citrate's ZK proof pipeline, agent trust system, spec registry, and inference routing contracts.

## Overview

The adversarial test harness exercises attack vectors that a malicious actor might attempt against Citrate's core security mechanisms. Unlike normal unit tests that verify happy paths, these tests deliberately submit malformed, replayed, cross-circuit, and otherwise adversarial inputs to verify that the system rejects them.

## Test Files

| File | Language | Target |
|------|----------|--------|
| `core/execution/tests/zkp_adversarial.rs` | Rust | ZK proof pipeline (Groth16 + MiMC) |
| `contracts/test/Adversarial.t.sol` | Solidity | Agent trust, spec registry, inference router |

## How to Run

### Rust ZK Adversarial Tests

```bash
cd citrate_v0.01.1

# Run all adversarial ZK tests
cargo test -p citrate-execution --test zkp_adversarial

# Run a specific test
cargo test -p citrate-execution --test zkp_adversarial test_random_bytes_never_verify

# Run with output
cargo test -p citrate-execution --test zkp_adversarial -- --nocapture
```

Note: These tests involve Groth16 key generation (`initialize()`) which takes several seconds per backend instance. Tests that share a backend pattern are grouped to minimize setup overhead.

### Solidity Adversarial Tests

```bash
cd citrate_v0.01.1/contracts

# Run all adversarial contract tests
forge test --match-contract AdversarialTest

# Run a specific test
forge test --match-test test_dispute_bombing

# Verbose output with traces
forge test --match-contract AdversarialTest -vvv
```

## Security Properties Verified

### Part 1: ZK Proof Pipeline (`zkp_adversarial.rs`)

#### 1. Proof Forgery Resistance

| Test | Property |
|------|----------|
| `test_random_bytes_never_verify` | Random byte sequences at various sizes never produce a valid Groth16 proof |
| `test_zero_proof_rejected` | All-zero byte arrays are rejected by the deserializer or verifier |
| `test_proof_from_wrong_circuit_rejected` | A proof generated for ModelExecution cannot verify against DataIntegrity, GradientSubmission, or StateTransition verifying keys (and vice versa) |
| `test_replayed_proof_with_different_inputs_fails` | Capturing a valid proof and presenting it with different public inputs is detected and rejected |
| `test_proof_with_swapped_public_inputs_fails` | Reordering public inputs [a,b,c] to [b,a,c] causes verification failure |

#### 2. Public Input Manipulation

| Test | Property |
|------|----------|
| `test_public_input_overflow_rejected` | `u128::MAX` as a public input does not produce a valid proof |
| `test_negative_field_element_handling` | Values near the u128 ceiling are handled without panic or false acceptance |
| `test_duplicate_public_inputs_handled` | Setting all public inputs to the same value does not circumvent verification |

#### 3. Circuit Constraint Enforcement

| Test | Property |
|------|----------|
| `test_state_transition_same_root_rejected` | `old_root == new_root` violates the `enforce_not_equal` constraint; proof generation fails |
| `test_gradient_zero_samples_rejected` | `num_samples == 0` violates the non-zero constraint; proof generation fails |
| `test_gradient_zero_hash_rejected` | All-zero gradient hash violates the non-zero constraint; proof generation fails |
| `test_data_integrity_wrong_merkle_root_rejected` | A Merkle root that does not match `hash_pair` computation is rejected at the byte-equality enforcement |
| `test_state_transition_zero_tx_hash_rejected` | All-zero transaction hash violates the non-zero constraint |

#### 4. Key Management

| Test | Property |
|------|----------|
| `test_proof_from_different_setup_rejected` | A proof from one trusted setup (backend A) is rejected by a different trusted setup (backend B), because the verifying keys differ |
| `test_verify_after_double_initialize` | Calling `initialize()` twice does not corrupt the backend; proofs generated after re-init still verify |

#### 5. MiMC Hash Security

| Test | Property |
|------|----------|
| `test_mimc_preimage_resistance` | A brute-force search over 10,000+ inputs fails to find a preimage for a target hash |
| `test_mimc_second_preimage_resistance` | Given input A and H(A), a search over 10,000+ different inputs fails to find B where H(B) == H(A) |
| `test_mimc_length_extension_resistance` | Inputs of length 1 through 50 all produce distinct hashes (Miyaguchi-Preneel sponge prevents length extension) |
| `test_mimc_key_influence` | Different encryption keys produce different outputs, proving the key is mixed into every round |
| `test_fr_to_bytes_edge_cases` | Fr field element roundtrip through `fr_to_bytes_le` is lossless for edge values (0, 1, u64::MAX, u128::MAX, p-1) |

#### 6. Proof Integrity

| Test | Property |
|------|----------|
| `test_single_bit_flip_detected` | Flipping any single bit in the proof bytes causes verification to fail |
| `test_truncated_proof_rejected` | Truncated proof bytes (at various lengths) are rejected |
| `test_extended_proof_rejected` | Proof bytes with appended garbage are rejected |
| `test_empty_public_inputs_with_valid_proof_bytes_fails` | Valid proof bytes paired with empty public inputs fail verification |
| `test_extra_public_inputs_rejected` | Adding extra public inputs beyond what the circuit expects fails verification |

### Part 2: Agent and Contract Attacks (`Adversarial.t.sol`)

#### 1. Trust Score Manipulation

| Test | Property |
|------|----------|
| `test_dispute_bombing` | Rapidly disputing all of an agent's decisions correctly drives the trust score deeply negative |
| `test_trust_score_cannot_go_negative_underflow` | Negative trust scores are handled correctly as `int256`; no underflow or wrap-around |
| `test_sybil_agent_ids` | Multiple agent IDs from the same address get independent trust scores (documents sybil isolation limitation) |
| `test_double_dispute_reverts` | Cannot dispute the same decision twice |
| `test_dispute_resolved_decision_reverts` | Cannot dispute a decision that has already been resolved |
| `test_dispute_nonexistent_reverts` | Cannot dispute a nonexistent decision ID |

#### 2. Spec Registry Attacks

| Test | Property |
|------|----------|
| `test_unauthorized_spec_update` | Non-governor cannot update specs |
| `test_unauthorized_spec_register` | Non-governor cannot register new specs |
| `test_unauthorized_spec_deactivate_reactivate` | Non-governor cannot toggle spec activation |
| `test_spec_deactivate_reactivate_spam` | 50 rapid toggles leave the spec in a consistent active state |
| `test_empty_cid_rejected` | Registering a spec with empty CID reverts |
| `test_empty_domain_rejected` | Registering a spec with empty domain reverts |
| `test_update_empty_cid_rejected` | Updating to an empty CID reverts |
| `test_update_nonexistent_domain_rejected` | Updating a nonexistent domain reverts |
| `test_duplicate_domain_rejected` | Registering the same domain twice reverts |
| `test_transfer_governor_to_zero_rejected` | Transferring governance to address(0) reverts |

#### 3. Inference Routing Attacks

| Test | Property |
|------|----------|
| `test_underpay_inference` | `msg.value < maxPrice` reverts with "Insufficient payment" |
| `test_zero_payment_inference` | Zero-value payment reverts |
| `test_provider_timeout_handling` | A request stuck in Processing cannot be cancelled by the requester |
| `test_double_submit_result` | Completing the same request twice reverts with "Invalid status" |
| `test_unassigned_provider_cannot_complete` | Only the assigned provider can submit results |
| `test_provider_insufficient_stake` | Providers must meet minimum stake |
| `test_provider_empty_endpoint` | Empty endpoint string rejected |
| `test_provider_no_models` | Must support at least one model |
| `test_no_provider_available` | Requesting inference with no registered providers reverts |
| `test_withdraw_stake_while_active_reverts` | Active providers cannot withdraw stake |
| `test_double_registration_reverts` | Same address cannot register as provider twice |
| `test_unauthorized_set_platform_fee` | Non-admin cannot change platform fee |
| `test_platform_fee_too_high` | Fee above 10% (1000 basis points) rejected |
| `test_withdraw_no_earnings` | Cannot withdraw zero earnings |

## How to Add New Adversarial Tests

### Adding Rust ZK Tests

1. Open `core/execution/tests/zkp_adversarial.rs`
2. Add your test function with the `#[test]` attribute
3. Use the existing helper functions (`initialized_backend()`, `generate_valid_proof()`, etc.)
4. Follow the pattern: set up the attack scenario, then assert the system rejects it
5. Use `match result { Ok(valid) => assert!(!valid, ...), Err(_) => {} }` for verification results where both error and `false` are acceptable outcomes

Example:
```rust
#[test]
fn test_my_new_attack() {
    let backend = initialized_backend();
    let malicious_proof = /* construct attack */;
    let result = backend.verify_proof(ProofType::ModelExecution, &malicious_proof);
    match result {
        Ok(valid) => assert!(!valid, "Attack must be rejected"),
        Err(_) => {} // Error is also acceptable
    }
}
```

### Adding Solidity Tests

1. Open `contracts/test/Adversarial.t.sol`
2. Add your test function (must start with `test_`)
3. Use `vm.prank(attacker)` to simulate attacker transactions
4. Use `vm.expectRevert("error message")` for expected failures
5. Use the helper functions `_registerProvider()` and `_registerProviderFor()` for setup

Example:
```solidity
function test_my_new_attack() public {
    vm.prank(attacker);
    vm.expectRevert("Expected error");
    targetContract.vulnerableFunction();
}
```

## Design Philosophy

These tests follow the "assume breach" model:

1. **Forgery**: Can an attacker create a proof that passes verification without knowing the witness?
2. **Replay**: Can an attacker reuse a valid proof in a different context?
3. **Manipulation**: Can an attacker alter public inputs or proof bytes to change the verified statement?
4. **Privilege Escalation**: Can a non-authorized party modify system state?
5. **Economic Attacks**: Can an attacker extract value through underpayment, double-claims, or timeout exploitation?
6. **Sybil Attacks**: Can an attacker bypass trust penalties through multiple identities?

Each test targets exactly one attack vector and includes a descriptive assertion message explaining what security property would be violated if the test fails.
