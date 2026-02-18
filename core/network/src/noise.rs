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
use tokio::net::TcpStream;
use tracing::{debug, info};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_NOISE_MSG_LEN: usize = 65535;

/// Static keypair for Noise protocol identity.
#[derive(Clone)]
pub struct NoiseKeypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl NoiseKeypair {
    /// Generate a new random X25519 keypair.
    pub fn generate() -> Self {
        let builder = Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"));
        let kp = builder.generate_keypair().expect("keypair generation");
        Self {
            private: kp.private.clone(),
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
pub async fn handshake_initiator(
    stream: &mut TcpStream,
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
pub async fn handshake_responder(
    stream: &mut TcpStream,
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

async fn send_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), NetworkError> {
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

async fn recv_frame(stream: &mut TcpStream) -> Result<Vec<u8>, NetworkError> {
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
    use tokio::net::TcpListener;

    #[test]
    fn test_keypair_generation() {
        let kp = NoiseKeypair::generate();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
        assert_ne!(kp.private, kp.public);
    }

    #[test]
    fn test_different_keypairs() {
        let kp1 = NoiseKeypair::generate();
        let kp2 = NoiseKeypair::generate();
        assert_ne!(kp1.public, kp2.public);
    }

    #[tokio::test]
    async fn test_noise_handshake() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_kp_clone = server_kp.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake_responder(&mut stream, &server_kp_clone).await.unwrap()
        });

        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        let client_session = handshake_initiator(&mut client_stream, &client_kp)
            .await
            .unwrap();

        let server_session = server.await.unwrap();

        // Verify remote keys match
        assert_eq!(client_session.remote_public_key(), &server_kp.public);
        assert_eq!(server_session.remote_public_key(), &client_kp.public);
    }

    #[tokio::test]
    async fn test_noise_encrypt_decrypt() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_kp_clone = server_kp.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake_responder(&mut stream, &server_kp_clone).await.unwrap()
        });

        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        let client_session = handshake_initiator(&mut client_stream, &client_kp)
            .await
            .unwrap();
        let server_session = server.await.unwrap();

        // Client encrypts, server decrypts
        let plaintext = b"hello from client";
        let ciphertext = client_session.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);
        let decrypted = server_session.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Server encrypts, client decrypts
        let plaintext2 = b"hello from server";
        let ciphertext2 = server_session.encrypt(plaintext2).unwrap();
        let decrypted2 = client_session.decrypt(&ciphertext2).unwrap();
        assert_eq!(&decrypted2, plaintext2);
    }

    #[tokio::test]
    async fn test_noise_tampered_message_rejected() {
        let server_kp = NoiseKeypair::generate();
        let client_kp = NoiseKeypair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_kp_clone = server_kp.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake_responder(&mut stream, &server_kp_clone).await.unwrap()
        });

        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        let client_session = handshake_initiator(&mut client_stream, &client_kp)
            .await
            .unwrap();
        let server_session = server.await.unwrap();

        // Encrypt then tamper with ciphertext
        let ciphertext = client_session.encrypt(b"genuine message").unwrap();
        let mut tampered = ciphertext.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 0xff;
        }
        assert!(server_session.decrypt(&tampered).is_err());
    }
}
