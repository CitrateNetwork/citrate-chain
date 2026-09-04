// citrate/core/network/src/noise.rs
//
// Noise_XX_25519_ChaChaPoly_SHA256 handshake for authenticated peer transport.
// After the 3-message handshake, all subsequent traffic is encrypted with
// ChaCha20-Poly1305 using session keys derived from X25519 ECDH.

use crate::NetworkError;
use parking_lot::Mutex;
use snow::{Builder, TransportState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;
use zeroize::Zeroizing;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_NOISE_MSG_LEN: usize = 65535;

/// Static keypair for Noise protocol identity.
///
/// CRY-M1: the static `private` key is held in `Zeroizing` so its bytes are
/// wiped when the keypair is dropped, and `Clone` is intentionally NOT derived
/// so the long-lived secret cannot be silently copied. The transport shares a
/// single instance via `Arc<NoiseKeypair>`. There is no `Debug` derive, so the
/// key can never be formatted into a log line.
pub struct NoiseKeypair {
    private: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

impl NoiseKeypair {
    /// Generate a new random X25519 keypair.
    pub fn generate() -> Self {
        let builder = Builder::new(
            NOISE_PATTERN
                .parse()
                .unwrap_or_else(|e| panic!("valid noise pattern: {e}")),
        );
        let kp = builder
            .generate_keypair()
            .unwrap_or_else(|e| panic!("keypair generation: {e}"));
        Self {
            private: Zeroizing::new(kp.private.clone()),
            public: kp.public.clone(),
        }
    }

    /// Hex-encoded public key (for logging / peer ID derivation).
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public)
    }

    /// Derive a canonical PeerId from this keypair's public key.
    ///
    /// WP-H.1: The PeerId is cryptographically bound to the Noise static key.
    /// Format: `noise_{hex(public_key)}` — deterministic and verifiable.
    pub fn derive_peer_id(&self) -> crate::peer::PeerId {
        crate::peer::PeerId::new(format!("noise_{}", self.public_key_hex()))
    }

    /// Serialize keypair to bytes (private || public, 64 bytes total).
    /// Used to persist Noise identity across node restarts.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.private);
        out.extend_from_slice(&self.public);
        out
    }

    /// Deserialize keypair from bytes (private || public, 64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::NetworkError> {
        if bytes.len() != 64 {
            return Err(crate::NetworkError::TransportError(format!(
                "invalid noise key length: expected 64, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            private: Zeroizing::new(bytes[..32].to_vec()),
            public: bytes[32..].to_vec(),
        })
    }
}

/// Encrypted session established after the Noise handshake.
///
/// Both `encrypt` and `decrypt` are safe to call from different tokio tasks —
/// the internal `Mutex` serializes access. Since encrypt/decrypt are fast
/// (~microseconds), contention is negligible.
pub struct NoiseSession {
    transport: Arc<Mutex<TransportState>>,
    remote_static: Vec<u8>,
}

impl NoiseSession {
    /// Encrypt plaintext into ciphertext (16-byte AEAD tag appended).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let mut buf = vec![0u8; plaintext.len() + 64];
        let mut ts = self.transport.lock();
        let len = ts
            .write_message(plaintext, &mut buf)
            .map_err(|e| NetworkError::TransportError(format!("noise encrypt: {}", e)))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt ciphertext into plaintext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let mut ts = self.transport.lock();
        let len = ts
            .read_message(ciphertext, &mut buf)
            .map_err(|e| NetworkError::TransportError(format!("noise decrypt: {}", e)))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Remote peer's static X25519 public key.
    pub fn remote_public_key(&self) -> &[u8] {
        &self.remote_static
    }

    /// Derive the expected PeerId from the remote peer's Noise static key.
    ///
    /// WP-H.1: Used after Noise handshake to verify the claimed peer_id in
    /// Hello/HelloAck messages. If the claimed id doesn't match, the peer is
    /// impersonating another identity and the connection must be rejected.
    pub fn expected_remote_peer_id(&self) -> crate::peer::PeerId {
        crate::peer::PeerId::new(format!("noise_{}", hex::encode(&self.remote_static)))
    }
}

/// Perform Noise_XX handshake as **initiator** (outbound connection).
///
/// Message flow:
///   → e          (initiator sends ephemeral key)
///   ← e, ee, s, es  (responder replies with ephemeral + static)
///   → s, se      (initiator reveals static key)
pub async fn handshake_initiator<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    keypair: &NoiseKeypair,
) -> Result<NoiseSession, NetworkError> {
    let mut hs = Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| NetworkError::TransportError(format!("noise pattern: {}", e)))?,
    )
    .local_private_key(&keypair.private)
    .build_initiator()
    .map_err(|e| NetworkError::TransportError(format!("noise init: {}", e)))?;

    let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];

    // → e
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg1: {}", e)))?;
    send_frame(stream, &buf[..len]).await?;

    // ← e, ee, s, es
    let msg2 = recv_frame(stream).await?;
    hs.read_message(&msg2, &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg2: {}", e)))?;

    // → s, se
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg3: {}", e)))?;
    send_frame(stream, &buf[..len]).await?;

    let remote_static = hs
        .get_remote_static()
        .ok_or_else(|| NetworkError::TransportError("no remote static key".into()))?
        .to_vec();

    let transport = hs
        .into_transport_mode()
        .map_err(|e| NetworkError::TransportError(format!("noise transport: {}", e)))?;

    debug!(
        "Noise initiator handshake complete (remote={})",
        hex::encode(&remote_static[..8])
    );

    Ok(NoiseSession {
        transport: Arc::new(Mutex::new(transport)),
        remote_static,
    })
}

/// Perform Noise_XX handshake as **responder** (inbound connection).
pub async fn handshake_responder<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    keypair: &NoiseKeypair,
) -> Result<NoiseSession, NetworkError> {
    let mut hs = Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| NetworkError::TransportError(format!("noise pattern: {}", e)))?,
    )
    .local_private_key(&keypair.private)
    .build_responder()
    .map_err(|e| NetworkError::TransportError(format!("noise init: {}", e)))?;

    let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];

    // ← e
    let msg1 = recv_frame(stream).await?;
    hs.read_message(&msg1, &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg1: {}", e)))?;

    // → e, ee, s, es
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg2: {}", e)))?;
    send_frame(stream, &buf[..len]).await?;

    // ← s, se
    let msg3 = recv_frame(stream).await?;
    hs.read_message(&msg3, &mut buf)
        .map_err(|e| NetworkError::TransportError(format!("noise msg3: {}", e)))?;

    let remote_static = hs
        .get_remote_static()
        .ok_or_else(|| NetworkError::TransportError("no remote static key".into()))?
        .to_vec();

    let transport = hs
        .into_transport_mode()
        .map_err(|e| NetworkError::TransportError(format!("noise transport: {}", e)))?;

    debug!(
        "Noise responder handshake complete (remote={})",
        hex::encode(&remote_static[..8])
    );

    Ok(NoiseSession {
        transport: Arc::new(Mutex::new(transport)),
        remote_static,
    })
}

// ---------------------------------------------------------------------------
// Simple 4-byte length-prefixed framing for the 3 handshake messages.
// After handshake, the regular LengthDelimitedCodec takes over.
// ---------------------------------------------------------------------------

async fn send_frame<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> Result<(), NetworkError> {
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| NetworkError::TransportError(format!("noise frame write len: {}", e)))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| NetworkError::TransportError(format!("noise frame write data: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| NetworkError::TransportError(format!("noise flush: {}", e)))?;
    Ok(())
}

async fn recv_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>, NetworkError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetworkError::TransportError(format!("noise frame read len: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_NOISE_MSG_LEN {
        return Err(NetworkError::TransportError(format!(
            "noise frame too large: {} > {}",
            len, MAX_NOISE_MSG_LEN
        )));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| NetworkError::TransportError(format!("noise frame read data: {}", e)))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = NoiseKeypair::generate();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
        assert_ne!(kp.private.as_slice(), kp.public.as_slice());
    }

    #[test]
    fn test_different_keypairs() {
        let kp1 = NoiseKeypair::generate();
        let kp2 = NoiseKeypair::generate();
        assert_ne!(kp1.public, kp2.public);
    }

    #[test]
    fn test_keypair_persistence_roundtrip() {
        let kp = NoiseKeypair::generate();
        let bytes = kp.to_bytes();
        assert_eq!(bytes.len(), 64);
        let restored = NoiseKeypair::from_bytes(&bytes).expect("roundtrip from_bytes");
        assert_eq!(kp.private.as_slice(), restored.private.as_slice());
        assert_eq!(kp.public, restored.public);
        assert_eq!(kp.derive_peer_id(), restored.derive_peer_id());
    }

    /// CRY-M1 tripwire: the Noise static private key must be held in
    /// `Zeroizing` so it is wiped on drop. The type annotation below only
    /// compiles while `private` is `Zeroizing<Vec<u8>>` — reverting it to a
    /// plain `Vec<u8>` breaks the build.
    #[test]
    fn test_cry_m1_private_key_is_zeroizing() {
        let kp = NoiseKeypair::generate();
        let _assert_type: &zeroize::Zeroizing<Vec<u8>> = &kp.private;
        assert_eq!(
            kp.private.len(),
            32,
            "X25519 static private key is 32 bytes"
        );
    }

    #[test]
    fn test_keypair_from_bytes_invalid_length() {
        let result = NoiseKeypair::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
    }

    // Noise protocol tests use tokio::io::duplex() for in-memory transport.
    // This avoids loopback TCP socket permission issues in sandboxed CI
    // while still proving full handshake + encrypt/decrypt correctness.

    /// Helper: perform a full Noise_XX handshake over an in-memory duplex channel.
    async fn duplex_handshake() -> (NoiseSession, NoiseSession, NoiseKeypair, NoiseKeypair) {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

        // NoiseKeypair is intentionally not Clone (CRY-M1); reconstruct an
        // independent copy for the spawned responder task via its byte form.
        let server_kp_clone = NoiseKeypair::from_bytes(&server_kp.to_bytes())
            .expect("roundtrip server keypair bytes");
        let server = tokio::spawn(async move {
            handshake_responder(&mut server_stream, &server_kp_clone)
                .await
                .expect("responder handshake")
        });

        let client_session = handshake_initiator(&mut client_stream, &client_kp)
            .await
            .expect("initiator handshake");
        let server_session = server.await.expect("server task");

        (client_session, server_session, client_kp, server_kp)
    }

    #[tokio::test]
    async fn test_noise_handshake() {
        let (client_session, server_session, client_kp, server_kp) = duplex_handshake().await;

        // Verify remote keys match
        assert_eq!(client_session.remote_public_key(), &server_kp.public);
        assert_eq!(server_session.remote_public_key(), &client_kp.public);
    }

    #[tokio::test]
    async fn test_noise_encrypt_decrypt() {
        let (client_session, server_session, _client_kp, _server_kp) = duplex_handshake().await;

        // Client encrypts, server decrypts
        let plaintext = b"hello from client";
        let ciphertext = client_session.encrypt(plaintext).expect("encrypt");
        assert_ne!(&ciphertext, plaintext);
        let decrypted = server_session.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(&decrypted, plaintext);

        // Server encrypts, client decrypts
        let plaintext2 = b"hello from server";
        let ciphertext2 = server_session.encrypt(plaintext2).expect("encrypt2");
        let decrypted2 = client_session.decrypt(&ciphertext2).expect("decrypt2");
        assert_eq!(&decrypted2, plaintext2);
    }

    #[tokio::test]
    async fn test_noise_tampered_message_rejected() {
        let (client_session, server_session, _client_kp, _server_kp) = duplex_handshake().await;

        // Encrypt then tamper with ciphertext
        let ciphertext = client_session.encrypt(b"genuine message").expect("encrypt");
        let mut tampered = ciphertext.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 0xff;
        }
        assert!(server_session.decrypt(&tampered).is_err());
    }
}
