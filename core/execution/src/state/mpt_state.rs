// citrate/core/execution/src/state/mpt_state.rs
//
// What the state tries hold under the MPT state root (`crate::mpt_state_root`).
// These are consensus rules; the spec text (06 section "state root") restates
// them.
//
// ACCOUNT TRIE (secure): key keccak256(address, 20 bytes); value
//
//   RLP[nonce, balance, storage_root, code_hash]                (no model permissions)
//   RLP[nonce, balance, storage_root, code_hash, [m1, ..., mk]] (k >= 1 model ids, in
//                                                                the account's order)
//
//   * nonce and balance are RLP integers (big-endian, no leading zeros, zero is
//     the empty string);
//   * storage_root is the account's storage trie root, `EMPTY_ROOT` when it holds
//     no slot;
//   * code_hash is the account's code hash, `KECCAK_EMPTY` for an account with no
//     code (an all-zero code hash is how the executor spells "no code");
//   * the 4-item form is exactly Ethereum's, so a standard `eth_getProof`
//     verifier checks an ordinary account. The 5th item is the Citrate model
//     permissions, each a 32-byte string.
//   * An EMPTY account (nonce 0, balance 0, no code, no storage, no model
//     permissions) is absent from the trie (EIP-161), so an empty account
//     resident on one node and not on another never moves the root.
//
// STORAGE TRIE (secure, one per account): key keccak256(slot key, any length);
// value
//
//   * a 32-byte value v (every EVM slot): RLP(v as an integer), and a zero value
//     is absent, exactly as in Ethereum;
//   * any other length (non-EVM precompile slots): RLP[ v ], a one-item list, so
//     it can never collide with an EVM value (an RLP string).

use crate::state::mpt::{keccak, rlp_append_bytes, rlp_list, trim_be, EMPTY_ROOT, KECCAK_EMPTY};
use crate::types::AccountState;
use citrate_consensus::types::Hash;

/// The storage-trie leaf for a slot value, or `None` if the slot is absent from
/// the trie (an EVM zero).
pub fn encode_storage_value(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() == 32 {
        let v = trim_be(value);
        if v.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(33);
        rlp_append_bytes(&mut out, v);
        Some(out)
    } else {
        let mut payload = Vec::with_capacity(value.len().saturating_add(9));
        rlp_append_bytes(&mut payload, value);
        Some(rlp_list(&payload))
    }
}

/// The trie key of a slot.
pub fn storage_trie_key(slot_key: &[u8]) -> [u8; 32] {
    keccak(slot_key)
}

/// The trie key of an account.
pub fn account_trie_key(address: &[u8; 20]) -> [u8; 32] {
    keccak(address)
}

/// The code hash as committed: `KECCAK_EMPTY` for "no code".
pub fn committed_code_hash(code_hash: &Hash) -> [u8; 32] {
    if *code_hash == Hash::default() {
        KECCAK_EMPTY
    } else {
        *code_hash.as_bytes()
    }
}

/// Whether the account is absent from the account trie. `storage_root` is the
/// root of its storage trie.
pub fn account_is_empty(account: &AccountState, storage_root: &[u8; 32]) -> bool {
    account.nonce == 0
        && account.balance.is_zero()
        && committed_code_hash(&account.code_hash) == KECCAK_EMPTY
        && *storage_root == EMPTY_ROOT
        && account.model_permissions.is_empty()
}

/// The account-trie leaf of `account` with storage root `storage_root`, or
/// `None` if the account is empty (absent from the trie).
pub fn encode_account(account: &AccountState, storage_root: &[u8; 32]) -> Option<Vec<u8>> {
    if account_is_empty(account, storage_root) {
        return None;
    }
    let mut payload = Vec::with_capacity(80);
    rlp_append_bytes(&mut payload, trim_be(&account.nonce.to_be_bytes()));
    let mut balance = [0u8; 32];
    account.balance.to_big_endian(&mut balance);
    rlp_append_bytes(&mut payload, trim_be(&balance));
    rlp_append_bytes(&mut payload, storage_root);
    rlp_append_bytes(&mut payload, &committed_code_hash(&account.code_hash));
    if !account.model_permissions.is_empty() {
        let mut ids = Vec::with_capacity(account.model_permissions.len().saturating_mul(33));
        for m in &account.model_permissions {
            rlp_append_bytes(&mut ids, m.0.as_bytes());
        }
        payload.extend_from_slice(&rlp_list(&ids));
    }
    Some(rlp_list(&payload))
}

/// The storage root an account-trie leaf commits to (its third item).
pub fn account_leaf_storage_root(leaf: &[u8]) -> Option<[u8; 32]> {
    let r = rlp::Rlp::new(leaf);
    let n = r.item_count().ok()?;
    if n != 4 && n != 5 {
        return None;
    }
    let item = r.at(2).ok()?;
    let data = item.data().ok()?;
    <[u8; 32]>::try_from(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    #[test]
    fn evm_values_are_trimmed_integers_and_zero_is_absent() {
        assert_eq!(encode_storage_value(&[0u8; 32]), None);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(encode_storage_value(&one), Some(vec![0x01]));
        let mut big = [0u8; 32];
        big[30] = 0x01;
        big[31] = 0x00;
        assert_eq!(encode_storage_value(&big), Some(vec![0x82, 0x01, 0x00]));
        // A non-EVM value is a one-item list, never an RLP string.
        assert_eq!(encode_storage_value(&[0x01]), Some(vec![0xc1, 0x01]));
        assert_eq!(encode_storage_value(&[]), Some(vec![0xc1, 0x80]));
    }

    /// The account in `hex_encoded_securetrie_test.json` (ethereum/tests): nonce 1,
    /// balance 0x05f446a7, no storage, no code.
    #[test]
    fn an_ordinary_account_is_the_ethereum_4_item_encoding() {
        let a = AccountState {
            nonce: 1,
            balance: U256::from(0x05f4_46a7u64),
            ..Default::default()
        };
        let want = "f848018405f446a7a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(
            encode_account(&a, &EMPTY_ROOT).map(hex::encode).as_deref(),
            Some(want)
        );
        assert_eq!(
            account_leaf_storage_root(&hex::decode(want).unwrap_or_default()),
            Some(EMPTY_ROOT)
        );
        assert_eq!(encode_account(&AccountState::default(), &EMPTY_ROOT), None);
    }
}
