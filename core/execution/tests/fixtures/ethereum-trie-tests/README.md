---
created: 2026-11-07
branch: r1007/s3-state-root
author: Claude Opus 5.5 (lane CHAIN-STATEROOT) for Larry Klosowski
status: active
---

# Ethereum trie test vectors (unmodified)

The five JSON files here are copied byte for byte from
[ethereum/tests](https://github.com/ethereum/tests), directory `TrieTests/`, at commit
`c67e485ff8b5be9abc8ad15345ec21aa22e290d9`. They are the conformance oracle for the
standard MPT state root (ADR-2026-11-03 CV-14 (a)); the test that reads them is
`core/execution/tests/mpt_conformance.rs`.

Licence: MIT, Copyright 2014-2025 Ethereum Foundation (the `LICENSE` file beside them,
copied from the same commit).

| File | sha256 |
|---|---|
| `trieanyorder.json` | `92404d5c2076524e62f02e9657a684aa0561067d49f3b489b78b5033c6fc3e2d` |
| `trietest.json` | `0ce5e1151210958edf47911b332fe188696d741f9f44b1a471ee62bc666c1f0f` |
| `trieanyorder_secureTrie.json` | `acba24dcef034b8ddd78d4ba8e716468854bac1a5ac886cc806c93f1c93f1ed4` |
| `trietest_secureTrie.json` | `98b76fd92fed69cb449d7a555cdb3eb397e7179614857de1289de2f63ac8e77a` |
| `hex_encoded_securetrie_test.json` | `487f9e1e404e46dc0a54d526b14927d3a5ba90f7f52625e7d49cd170974ce9ff` |

Format: `in` is a map (any insert order gives `root`) or a list of `[key, value]`
operations applied in order, where a `null` value deletes the key. A string starting
with `0x` is hex, any other string is its UTF-8 bytes. The `_secureTrie` and
`hex_encoded_securetrie` files key the trie by keccak256(key).

`trietestnextprev.json` (iterator next/prev) is not used: it tests a trie API, not
root values.
