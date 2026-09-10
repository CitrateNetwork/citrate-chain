---
created: 2026-09-06T00:00:00Z
branch: prep/rm-q-chain-nonconsensus
author: Codex
status: red-green witness
finding: CRY-C1
---

# CRY-C1 ECIES key-wrap witness

The red witness was run at the pre-fix pin `f88a52c` with:

```text
cargo test --locked -p citrate-execution --test cry_c1_tripwire
```

Result: **RED** — `cry_c1_address_only_key_wrap_is_rejected` failed because the
old implementation accepted address-only input and returned an XOR-wrapped key.

After the fix, the same tripwire plus the private-key mismatch check ran on
`prep/rm-q-chain-nonconsensus`:

```text
running 2 tests
test cry_c1_address_only_key_wrap_is_rejected ... ok
test cry_c1_ecies_wrap_requires_the_recipient_private_key ... ok
test result: ok. 2 passed; 0 failed
```

The fixed path uses secp256k1 ECIES with HKDF-SHA256 and AES-256-GCM. Legacy
version-0 key wraps are rejected; pre-reroll ciphertext is not migrated because
the old key material was already exposed and must be re-encrypted/re-uploaded.
