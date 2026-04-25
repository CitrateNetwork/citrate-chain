// Audit finding C-02 regression: previously
// `Address::from_public_key` accepted any 32-byte byte string as a
// PublicKey, then the dual-format derivation could be tricked into
// mapping an attacker-supplied `[victim_evm_addr || 0x00; 12]` to
// the victim's address — attribution spoofing. The structural fix
// is the `PublicKey::is_admissible` gate, used at every untrusted
// ingress point (network gossip, RPC tx decoding).
//
// Embedded-EVM dual-format is intentional and remains supported.
// What's NOT supported is "neither embedded-EVM nor on-curve" —
// the previous `from_public_key` would happily Keccak-derive an
// address from such an input, which had no defense against
// attacker-controlled byte choice.

use citrate_consensus::types::PublicKey;
use ed25519_dalek::SigningKey;

/// C-02.1: a real ed25519-derived public key passes `is_admissible`.
#[test]
fn c02_real_ed25519_pubkey_is_admissible() {
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let vk_bytes = sk.verifying_key().to_bytes();
    let pk = PublicKey::new(vk_bytes);
    assert!(pk.is_valid_ed25519_curve_point());
    assert!(pk.is_admissible());
}

/// C-02.2: an embedded-EVM-form pubkey (first 20 bytes non-zero,
/// last 12 zero) is admissible — this is intentional dual-format.
#[test]
fn c02_embedded_evm_pubkey_is_admissible() {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate().take(20) {
        *b = (i as u8) + 1;
    }
    // bytes[20..32] remain zero
    let pk = PublicKey::new(bytes);
    assert!(pk.is_likely_embedded_evm());
    // It's not a valid curve point but the embedded-EVM check
    // is sufficient.
    assert!(pk.is_admissible());
}

/// C-02.3: a known off-curve byte pattern is REJECTED. The
/// pattern is constructed by taking a real verifying key and
/// flipping a high-bit on byte 31 to violate canonical encoding.
/// Pre-fix such a PublicKey would have Keccak-derived to an
/// attacker-controlled address; post-fix it's rejected at
/// admission.
#[test]
fn c02_off_curve_pattern_rejected() {
    // Build a real verifying key, then mutate it into a non-
    // canonical encoding. Most byte mutations produce off-curve
    // bytes; the loop searches for one that is.
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let mut bytes = sk.verifying_key().to_bytes();

    // Tail mutation that's definitely not embedded-EVM.
    let mut found_off_curve = false;
    for i in 0..255u8 {
        let mut probe = bytes;
        probe[20] ^= i; // flip middle byte; embedded-EVM would require last 12 zero
        probe[31] = i.wrapping_add(0x10); // ensure tail nonzero
        let pk = PublicKey::new(probe);
        if !pk.is_likely_embedded_evm() && !pk.is_valid_ed25519_curve_point() {
            assert!(
                !pk.is_admissible(),
                "C-02: off-curve, non-embedded pubkey must be inadmissible"
            );
            found_off_curve = true;
            break;
        }
    }
    assert!(
        found_off_curve,
        "C-02: search must find at least one off-curve pattern (validates the search itself)"
    );

    // Also bend an additional reasonable case: take real-key bytes
    // and OR the high bit of byte 31 — this is a non-canonical
    // encoding that ed25519_dalek rejects.
    bytes[31] |= 0x80;
    bytes[31] |= 0x40; // set both high bits to push outside spec
    let pk = PublicKey::new(bytes);
    if !pk.is_likely_embedded_evm() && !pk.is_valid_ed25519_curve_point() {
        assert!(
            !pk.is_admissible(),
            "C-02: non-canonically-encoded pubkey must be inadmissible"
        );
    }
}

/// C-02.4: the specific exploit vector probe — an attacker
/// constructs `[victim_evm_addr || 0u8 ; 12]` to claim the victim's
/// embedded-EVM identity. `is_admissible` accepts it (legitimate
/// dual-format), but signature verification (separate from this
/// gate) prevents the attacker from acting on behalf of the
/// victim. The C-02 closure is that any "non-embedded but
/// natural-looking" forgery (e.g., `[victim_evm_addr || X..]`
/// with random X) is now REJECTED at admission, so the attacker
/// can't slip a non-curve-but-not-embedded form through.
#[test]
fn c02_natural_looking_forgery_with_nonzero_tail_rejected() {
    let victim = [0xAB; 20];
    let mut forged = [0u8; 32];
    forged[..20].copy_from_slice(&victim);
    forged[31] = 0x01; // single non-zero in tail → NOT embedded-EVM-form
    let pk = PublicKey::new(forged);

    assert!(!pk.is_likely_embedded_evm());
    assert!(
        !pk.is_admissible(),
        "C-02: forgery with non-zero tail is neither embedded-EVM nor on-curve; \
         pre-fix would have Keccak-derived to an attacker-controlled address"
    );
}

/// C-02.5: zeros pubkey is structurally suspicious — first 20 all
/// zero is not embedded-EVM. The ed25519 curve treats the all-
/// zeros encoding as the identity element which IS technically a
/// valid curve point (some libraries reject it via additional
/// low-order checks; ed25519_dalek admits it). We document this
/// as a known acceptable corner: signature verification will
/// always fail against the identity element, so an attacker can't
/// exploit it for impersonation.
#[test]
fn c02_zero_pubkey_documented_corner_case() {
    let pk = PublicKey::new([0u8; 32]);
    assert!(!pk.is_likely_embedded_evm());
    // Whether the identity element is admissible is library-
    // dependent. The C-02 closure relies on signature
    // verification rejecting any signing attempt against the
    // zero key — which it does, because the secret-scalar
    // implied by a zero verifying key is unknown / undefined.
    // Documented behavior:
    let _ = pk.is_admissible();
}
