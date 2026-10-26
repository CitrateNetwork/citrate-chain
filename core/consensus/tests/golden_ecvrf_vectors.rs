// citrate/core/consensus/tests/golden_ecvrf_vectors.rs
//
// Golden vectors for ECVRF-P256-SHA256-TAI (`citrate_consensus::ecvrf`).
//
// The ECVRF output picks block proposers, so every byte here is consensus: a
// node whose `prove`/`verify` disagrees with these values forks off. The hex
// below was captured on the p256 0.13 line (2026-10-25) and is the reference
// for any curve-crate upgrade. The tests only use this crate's public API (no
// p256 types), so the same file compiles on both sides of an upgrade.
//
// Regenerating these values is a consensus change and needs a fork, never a
// dependency bump.

use citrate_consensus::ecvrf::{self, EcvrfError, EcvrfProof};

/// P-256 group order n, big-endian.
const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn secrets() -> [[u8; 32]; 3] {
    [
        [0u8; 32],
        [0xffu8; 32],
        core::array::from_fn(|i| (i + 1) as u8),
    ]
}

fn alphas() -> [Vec<u8>; 3] {
    [
        Vec::new(),
        b"citrate-epoch-40204-round-1".to_vec(),
        vec![0xa5u8; 200],
    ]
}

/// Compressed P-256 public key for each secret.
const PUBKEYS: [&str; 3] = [
    "038100cb111884a7ad5663d08440315ad76dbf87159564dbe704d4c65260365b45",
    "02f9f8f7da2cbfa31d3accc91d831c6c1ac5ddf662e4c370d90955cce1a82d2b7a",
    "02b40e04caf3f58db71aac62ef8877c4af4216f54461e29e30daf9e11074544e99",
];

/// `(proof bytes, beta)` for `prove(secrets()[i], alphas()[j])`, row i, column j.
/// Proof layout: pk(33) || Gamma(33) || c(16) || s(32) = 114 bytes.
const VECTORS: [[(&str, &str); 3]; 3] = [
    [
        (
            "038100cb111884a7ad5663d08440315ad76dbf87159564dbe704d4c65260365b45036858ce9a4a390928925a7b07d08cc16bfe9a3ea64aecf7d740ad792555c2b0ff86a1624e22476402c5eb675134d52d82cf6dec404eae2e85b3477522231935afa5128b281f2203018a5aa25719e0555e",
            "2f6408c36e450afb267a479aa966651ab1417afffd240843c4c5c630493947c1",
        ),
        (
            "038100cb111884a7ad5663d08440315ad76dbf87159564dbe704d4c65260365b4502bf69d297493189461600fd9d36d4532e8c1cb3ccff8316aafe1e8651df061bdfdf56df78c6141c24b5ceb6b380cf699a7bdd43cfe767f25df88fecd56942035b2f5d0c93fdc5e639c54f20db1ead59ff",
            "5d64c042729e7dc48f96e5802cf0eca7ef755265a0e3a22ed0f0c3e27369ea86",
        ),
        (
            "038100cb111884a7ad5663d08440315ad76dbf87159564dbe704d4c65260365b4502f132b1b8427e252d37761b3cfe1b8103387636f3b5d59dc0f2294ab50d3a7cdfccf73b07ab162d35f9ddd1f6c8c7f0b6c7ce25688741774bfb4aebd01c7497ff9ac5472f7166c429d963fded46ff2dce",
            "61ee338b53a2c5eb17da2d24b798912bda227a85bbc811e908a4563d48527cef",
        ),
    ],
    [
        (
            "02f9f8f7da2cbfa31d3accc91d831c6c1ac5ddf662e4c370d90955cce1a82d2b7a0243f9c6bbfde185cdc295be6e1f259d748a065fa54148800207b4745e12e37b70578302f2d0e4baad071e47670fb469f5b158f2e5762bccd8dd8edddb72c646b6dffbf72a33106c6eb2affefb560e568c",
            "2695ce4d680c8b248ac84d1d1c8192fcb6a8957680b1e98cd129ef7917d9a070",
        ),
        (
            "02f9f8f7da2cbfa31d3accc91d831c6c1ac5ddf662e4c370d90955cce1a82d2b7a0202e5b46623540be9ce9eb89d89239e2efd07b8d4ca6e9d642181f07dbead6e38ccdd0661ac4596796b3325f968c6f6a9e5e23f560736990b3c176e8cdac882eb242a5e8e05f0cf5c50ae2f10ef5c48cc",
            "205c371ba8c77d6a61e2ae9ae2bed806e15cff089d5dd19cd0ffb8e18c605526",
        ),
        (
            "02f9f8f7da2cbfa31d3accc91d831c6c1ac5ddf662e4c370d90955cce1a82d2b7a031627cadf928e7de16bf5b1594fc72e0d6343875d81094ab1f58817a79a7e64809cf9176c6a8877fd8e7aa7a7ab22ff833283810ab6210bcfc3cf89b185f78c1e1c3b135d9c061f6cb2eeeb9f5e16eeeb",
            "cc2cfb943bee2ad325d0bcd0159607527254d1ebe277a4d0b8778cf1383c5949",
        ),
    ],
    [
        (
            "02b40e04caf3f58db71aac62ef8877c4af4216f54461e29e30daf9e11074544e9903e0b05b83c843b4ccaac6583bd43826c4e20193c840999133e8992b6eababaa2c1fd2de2390b05079bddd56be71ccab1f098e9dbf51eb892a93293a1d11a0f95beb198b2690d7e7300dbe4160b2875e26",
            "7d6abc25985ab252e597f0a87058d45b6325fb7e47acaa8d8f5f81c6b0689c49",
        ),
        (
            "02b40e04caf3f58db71aac62ef8877c4af4216f54461e29e30daf9e11074544e9902e2abaf975d26b73200492721234edcbd4c90e7680d29ac130ce91626bf8a607eab008befe24ac10f44eaec24a179a1895e550c2925356f15b9dd3349a6361f4aac822993a3928ceb9314aa478b600ce8",
            "0e251997afe0b5e19f9b350d6220ad6c56d5cd9585e995473f8d134af7801e53",
        ),
        (
            "02b40e04caf3f58db71aac62ef8877c4af4216f54461e29e30daf9e11074544e9902d95bc4d400638fd5c1d4a67ae2146df9cba0ec7357accbe2110323d58f4630629e650b65639f641f74f30a53ddadc93d029356e178073d542ca243afadb0f53ec1e4722ab128f3a5d5caafa75f043659",
            "e7abd38dd3722d79a02ef058981bf2a673480aaa7921a8cc5dcf361d3af75cb1",
        ),
    ],
];

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in vector")
}

#[test]
fn golden_ecvrf_public_keys_are_byte_identical() {
    for (i, secret) in secrets().iter().enumerate() {
        assert_eq!(
            hex::encode(ecvrf::derive_public_key(secret)),
            PUBKEYS[i],
            "derive_public_key changed for secret #{i}"
        );
    }
}

#[test]
fn golden_ecvrf_proofs_and_outputs_are_byte_identical() {
    for (i, secret) in secrets().iter().enumerate() {
        for (j, alpha) in alphas().iter().enumerate() {
            let (proof, beta) = ecvrf::prove(secret, alpha).expect("prove");
            let (want_proof, want_beta) = VECTORS[i][j];
            assert_eq!(
                hex::encode(proof.to_bytes()),
                want_proof,
                "proof bytes changed for secret #{i}, alpha #{j}"
            );
            assert_eq!(
                hex::encode(beta),
                want_beta,
                "VRF output changed for secret #{i}, alpha #{j}"
            );
        }
    }
}

#[test]
fn golden_ecvrf_pinned_proofs_verify_to_pinned_outputs() {
    for (i, row) in VECTORS.iter().enumerate() {
        for (j, (proof_hex, beta_hex)) in row.iter().enumerate() {
            let proof = EcvrfProof::from_bytes(&unhex(proof_hex)).expect("pinned proof decodes");
            assert_eq!(
                hex::encode(proof.to_bytes()),
                *proof_hex,
                "decode/encode is not the identity for #{i}{j}"
            );
            let beta = ecvrf::verify(&alphas()[j], &proof).expect("pinned proof verifies");
            assert_eq!(
                hex::encode(beta),
                *beta_hex,
                "verify output changed for #{i}{j}"
            );
            assert_eq!(
                hex::encode(ecvrf::proof_to_hash(&proof.gamma)),
                *beta_hex,
                "proof_to_hash changed for #{i}{j}"
            );
        }
    }
}

#[test]
fn golden_ecvrf_pinned_proof_rejects_the_wrong_alpha() {
    let proof = EcvrfProof::from_bytes(&unhex(VECTORS[2][1].0)).expect("decodes");
    assert!(ecvrf::verify(b"citrate-epoch-40204-round-2", &proof).is_err());
}

#[test]
fn golden_ecvrf_every_single_bit_flip_in_c_or_s_fails_closed() {
    let good = unhex(VECTORS[1][2].0);
    // c is bytes 66..82, s is bytes 82..114.
    for byte in 66..114 {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[byte] ^= 1 << bit;
            match EcvrfProof::from_bytes(&bad) {
                Ok(proof) => assert!(
                    ecvrf::verify(&alphas()[2], &proof).is_err(),
                    "flipped bit {bit} of byte {byte} still verifies"
                ),
                Err(EcvrfError::InvalidScalar) => {}
                Err(e) => panic!("unexpected error for byte {byte} bit {bit}: {e}"),
            }
        }
    }
}

#[test]
fn golden_ecvrf_non_canonical_s_is_rejected_at_decode() {
    // s = n and s = 2^256 - 1 are not canonical scalars: decode must refuse
    // them rather than reduce them (a reducing decoder would accept a second
    // encoding of the same proof).
    let good = unhex(VECTORS[0][0].0);
    for s in [P256_ORDER.to_string(), "ff".repeat(32)] {
        let mut bad = good.clone();
        bad[82..].copy_from_slice(&unhex(&s));
        assert!(
            matches!(EcvrfProof::from_bytes(&bad), Err(EcvrfError::InvalidScalar)),
            "s = {s} must be rejected"
        );
    }
}

#[test]
fn golden_ecvrf_invalid_gamma_encodings_are_rejected_at_decode() {
    let good = unhex(VECTORS[0][1].0);
    let with_gamma = |tag: u8, x: &str| {
        let mut b = good.clone();
        b[33] = tag;
        b[34..66].copy_from_slice(&unhex(x));
        b
    };
    let cases = [
        // x = p (the field modulus) is a non-canonical field element.
        (
            "x = p",
            with_gamma(
                0x02,
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            ),
        ),
        // x = 2^256 - 1 is above p.
        ("x = 2^256-1", with_gamma(0x03, &"ff".repeat(32))),
        // 0x04 (uncompressed) needs 65 bytes, not 33.
        ("tag 0x04", with_gamma(0x04, &hex::encode(&good[34..66]))),
        ("tag 0x06", with_gamma(0x06, &hex::encode(&good[34..66]))),
        // The identity encoding (single 0x00) cannot appear in a 33-byte slot.
        ("tag 0x00", with_gamma(0x00, &hex::encode(&good[34..66]))),
    ];
    for (name, bytes) in cases {
        assert!(
            matches!(
                EcvrfProof::from_bytes(&bytes),
                Err(EcvrfError::InvalidPoint)
            ),
            "{name} gamma must be rejected"
        );
    }
}

/// SEC1 also defines a 0x05 "compact" tag (x only; y is the smaller root). Both
/// the 0.13 and 0.14 curve lines decode it, so `from_bytes` accepts it today.
/// This pins that behaviour so a curve upgrade cannot change it silently: the
/// decoded proof re-encodes with the 0x02/0x03 tag, and it verifies only when
/// the compact y is Gamma's y.
#[test]
fn golden_ecvrf_compact_tag_gamma_decode_is_pinned() {
    // VECTORS[0][0] has Gamma tag 0x03 and its y is the compact root.
    let canonical = unhex(VECTORS[0][0].0);
    assert_eq!(canonical[33], 0x03);
    let mut compact = canonical.clone();
    compact[33] = 0x05;
    let proof = EcvrfProof::from_bytes(&compact).expect("0x05 decodes on this curve line");
    assert_eq!(
        proof.to_bytes(),
        canonical,
        "re-encodes to the canonical proof"
    );
    assert_eq!(
        hex::encode(ecvrf::verify(&alphas()[0], &proof).expect("verifies")),
        VECTORS[0][0].1
    );

    // VECTORS[0][1] has Gamma tag 0x02, and the compact root is the other y.
    let canonical = unhex(VECTORS[0][1].0);
    assert_eq!(canonical[33], 0x02);
    let mut compact = canonical.clone();
    compact[33] = 0x05;
    let proof = EcvrfProof::from_bytes(&compact).expect("0x05 decodes on this curve line");
    assert_eq!(
        hex::encode(&proof.to_bytes()[33..66]),
        "03bf69d297493189461600fd9d36d4532e8c1cb3ccff8316aafe1e8651df061bdf",
        "compact decode picks the other root"
    );
    assert!(ecvrf::verify(&alphas()[1], &proof).is_err());
}
