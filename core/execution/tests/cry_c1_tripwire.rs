use citrate_execution::crypto::encryption::{
    EncryptionConfig, ModelEncryption, RecipientPublicKeys,
};
use citrate_execution::crypto::ecdh::ECIES;
use primitive_types::{H160, H256};
use std::collections::HashMap;

#[test]
fn cry_c1_address_only_key_wrap_is_rejected() {
    let encryption = ModelEncryption::new(EncryptionConfig::default());
    let result = encryption.encrypt_model(
        H256::zero(),
        b"tripwire",
        H160::from_low_u64_be(1),
        vec![],
    );
    assert!(result.is_err());
}

#[test]
fn cry_c1_ecies_wrap_requires_the_recipient_private_key() {
    let encryption = ModelEncryption::new(EncryptionConfig::default());
    let owner = H160::from_low_u64_be(1);
    let owner_private = [7u8; 32];
    let owner_public = ECIES::from_private_key(owner_private).unwrap().public_key();
    let public_keys: RecipientPublicKeys = HashMap::from([(owner, owner_public)]);
    let encrypted = encryption
        .encrypt_model_with_keys(
            H256::zero(),
            b"tripwire",
            owner,
            vec![],
            &public_keys,
        )
        .unwrap();

    assert_eq!(
        encryption.decrypt_model(&encrypted, &owner_private, owner).unwrap(),
        b"tripwire"
    );
    assert!(encryption
        .decrypt_model(&encrypted, &[8u8; 32], owner)
        .is_err());
}
