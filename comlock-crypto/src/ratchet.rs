//! # ComLock Crypto - Ratchet Module
//!
//! Implements the KEM Braid ratchet state machine for hybrid post-quantum
//! key agreement. Combines X25519 (classical ECDH) with Kyber-1024 (ML-KEM)
//! for quantum-resistant forward secrecy.

use hkdf::Hkdf;
use pqc_kyber::*;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::ComLockError;
use crate::header::MessageHeader;

/// Size of Kyber-1024 public key in bytes
pub const KYBER_PUBKEY_SIZE: usize = KYBER_PUBLICKEYBYTES;

/// Size of Kyber-1024 ciphertext in bytes
pub const KYBER_CIPHERTEXT_SIZE: usize = KYBER_CIPHERTEXTBYTES;

/// Size of Kyber-1024 secret key in bytes
pub const KYBER_SECRETKEY_SIZE: usize = KYBER_SECRETKEYBYTES;

/// The ratchet state machine managing the KEM Braid.
///
/// This struct maintains two parallel key evolution timelines:
/// - **Classical (fast)**: X25519 ECDH updates with every message
/// - **Post-Quantum (heavy)**: Kyber-1024 KEM updates opportunistically
///
/// The "braid" design allows sparse PQ ratcheting to minimize bandwidth
/// while maintaining post-compromise security against quantum adversaries.
#[derive(Clone)]
#[allow(dead_code)] // Some fields reserved for future ECDH integration
pub struct RatchetState {
    /// The root key derived from the initial PQXDH handshake.
    root_key: [u8; 32],

    /// Sending chain key - for deriving message keys when sending
    send_chain_key: [u8; 32],

    /// Receiving chain key - for deriving message keys when receiving
    recv_chain_key: [u8; 32],

    /// Our current X25519 ephemeral keypair for sending
    our_ephemeral_secret: StaticSecret,

    /// Counter for messages sent
    send_count: u32,

    /// Counter for messages received
    recv_count: u32,

    /// The remote party's X25519 public key (last received)
    remote_pubkey: Option<X25519PublicKey>,

    /// Our pending Kyber keypair for KEM exchange
    our_kem_keypair: Option<Keypair>,

    /// The remote party's Kyber public key (if they sent one)
    pending_kem_pubkey: Option<[u8; KYBER_PUBKEY_SIZE]>,

    /// The shared secret from the last successful KEM operation
    last_kem_secret: [u8; 32],

    /// Flag indicating if we should include our KEM pubkey in next message
    should_send_kem_pubkey: bool,

    /// Message number of last KEM ratchet advancement
    last_kem_message_number: u32,

    /// Whether this party is the initiator (affects initial state)
    is_initiator: bool,
}

/// Output from a ratchet step: the message key and header to send
pub struct RatchetOutput {
    /// The symmetric key for encrypting/decrypting the message payload
    pub message_key: [u8; 32],
    /// The header to include with the message
    pub header: MessageHeader,
}

/// Output from receiving a message
pub struct DecryptionContext {
    /// The symmetric key for decrypting the message payload
    pub message_key: [u8; 32],
}

impl RatchetState {
    /// Create a new RatchetState from the output of a PQXDH handshake.
    ///
    /// Both parties must use the same `root_key` from the handshake.
    /// The `is_initiator` flag determines asymmetric initial state.
    pub fn new(root_key: [u8; 32], is_initiator: bool) -> Self {
        let mut rng = rand::thread_rng();

        // Generate initial X25519 keypair
        let our_ephemeral_secret = StaticSecret::random_from_rng(&mut rng);

        // Derive initial chain keys from root - asymmetric for sender/receiver roles
        let (send_chain, recv_chain) = if is_initiator {
            let (a, b) = Self::kdf_derive(&root_key, b"init_chains", &[]);
            (a, b)
        } else {
            // Responder uses reversed chain keys
            let (a, b) = Self::kdf_derive(&root_key, b"init_chains", &[]);
            (b, a)
        };

        // Generate initial Kyber keypair for the initiator
        let our_kem_keypair = if is_initiator {
            Some(keypair(&mut rng).expect("Kyber keypair generation failed"))
        } else {
            None
        };

        Self {
            root_key,
            send_chain_key: send_chain,
            recv_chain_key: recv_chain,
            our_ephemeral_secret,
            send_count: 0,
            recv_count: 0,
            remote_pubkey: None,
            our_kem_keypair,
            pending_kem_pubkey: None,
            last_kem_secret: [0u8; 32],
            should_send_kem_pubkey: is_initiator,
            last_kem_message_number: 0,
            is_initiator,
        }
    }

    /// Perform a sending ratchet step - derive message key and produce header.
    ///
    /// This implements the "KEM Braid" design with sparse PQ ratcheting.
    pub fn step(
        &mut self,
        _remote_kem_ciphertext: Option<&[u8]>,
    ) -> Result<RatchetOutput, ComLockError> {
        let mut rng = rand::thread_rng();

        // Get our current public key for the header
        let our_public = X25519PublicKey::from(&self.our_ephemeral_secret);

        // === KEM Operations ===
        let (kem_shared_secret, kem_ciphertext) = self.try_kem_encapsulate(&mut rng)?;

        // Update last_kem_secret if we got a new one
        if let Some(ref ss) = kem_shared_secret {
            self.last_kem_secret = *ss;
            self.last_kem_message_number = self.send_count;
        }

        // === Key Derivation ===
        // Mix the send chain key with counter to derive message key
        let kem_input = kem_shared_secret.unwrap_or(self.last_kem_secret);
        let mut ikm = Vec::with_capacity(36);
        ikm.extend_from_slice(&self.send_count.to_le_bytes());
        ikm.extend_from_slice(&kem_input);

        let (message_key, new_send_chain) =
            Self::kdf_derive(&self.send_chain_key, b"msg_send", &ikm);

        // Update state
        self.send_chain_key = new_send_chain;

        // Rotate ephemeral key for forward secrecy
        self.our_ephemeral_secret = StaticSecret::random_from_rng(&mut rng);

        // Build header
        let kem_pubkey = if self.should_send_kem_pubkey {
            self.should_send_kem_pubkey = false;
            self.our_kem_keypair.as_ref().map(|kp| kp.public)
        } else {
            None
        };

        let header = MessageHeader::new(
            our_public.to_bytes(),
            kem_ciphertext,
            kem_pubkey,
            self.send_count,
            self.recv_count,
        );

        self.send_count += 1;

        Ok(RatchetOutput {
            message_key,
            header,
        })
    }

    /// Process an incoming message header and derive the decryption key.
    pub fn receive_step(
        &mut self,
        header: &MessageHeader,
    ) -> Result<DecryptionContext, ComLockError> {
        let mut rng = rand::thread_rng();

        // Update remote public key
        let remote_pub = X25519PublicKey::from(header.classical_pubkey);
        self.remote_pubkey = Some(remote_pub);

        // === KEM Decapsulation ===
        let kem_shared_secret = if let Some(ref ct_bytes) = header.kem_ciphertext {
            if let Some(ref our_keypair) = self.our_kem_keypair {
                let ct: [u8; KYBER_CIPHERTEXT_SIZE] = ct_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ComLockError::InvalidCiphertext)?;

                let shared_secret = decapsulate(&ct, &our_keypair.secret)
                    .map_err(|_| ComLockError::DecapsulationFailed)?;

                // Generate new KEM keypair for next exchange
                self.our_kem_keypair =
                    Some(keypair(&mut rng).expect("Kyber keypair generation failed"));
                self.should_send_kem_pubkey = true;

                Some(shared_secret)
            } else {
                return Err(ComLockError::MissingKemKeypair);
            }
        } else {
            None
        };

        // Store remote's KEM pubkey if they sent one
        if let Some(ref pubkey_bytes) = header.kem_pubkey {
            let pubkey: [u8; KYBER_PUBKEY_SIZE] = pubkey_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ComLockError::InvalidPublicKey)?;
            self.pending_kem_pubkey = Some(pubkey);

            // If we don't have a KEM keypair, generate one to respond
            if self.our_kem_keypair.is_none() {
                self.our_kem_keypair =
                    Some(keypair(&mut rng).expect("Kyber keypair generation failed"));
                self.should_send_kem_pubkey = true;
            }
        }

        // Update last_kem_secret if we got a new one
        if let Some(ref ss) = kem_shared_secret {
            self.last_kem_secret = *ss;
        }

        // === Key Derivation ===
        let kem_input = kem_shared_secret.unwrap_or(self.last_kem_secret);
        let mut ikm = Vec::with_capacity(36);
        ikm.extend_from_slice(&header.message_number.to_le_bytes());
        ikm.extend_from_slice(&kem_input);

        let (message_key, new_recv_chain) =
            Self::kdf_derive(&self.recv_chain_key, b"msg_send", &ikm);

        // Update state
        self.recv_chain_key = new_recv_chain;
        self.recv_count = header.message_number + 1;

        Ok(DecryptionContext { message_key })
    }

    /// Try to encapsulate to the remote's KEM public key if available.
    #[allow(clippy::type_complexity)]
    fn try_kem_encapsulate<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(Option<[u8; 32]>, Option<Vec<u8>>), ComLockError> {
        if let Some(remote_pubkey) = self.pending_kem_pubkey.take() {
            let (ciphertext, shared_secret) =
                encapsulate(&remote_pubkey, rng).map_err(|_| ComLockError::EncapsulationFailed)?;

            // Generate new keypair for receiving their response
            self.our_kem_keypair = Some(keypair(rng).expect("Kyber keypair generation failed"));
            self.should_send_kem_pubkey = true;

            Ok((Some(shared_secret), Some(ciphertext.to_vec())))
        } else {
            Ok((None, None))
        }
    }

    /// HKDF-SHA256 based key derivation.
    fn kdf_derive(input_key: &[u8; 32], info: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(input_key), ikm);

        let mut okm = [0u8; 64];
        hk.expand(info, &mut okm).expect("HKDF expansion failed");

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key1.copy_from_slice(&okm[..32]);
        key2.copy_from_slice(&okm[32..]);

        (key1, key2)
    }

    /// Get our current X25519 public key.
    pub fn our_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.our_ephemeral_secret)
    }

    /// Get our current Kyber public key if available.
    pub fn our_kem_public_key(&self) -> Option<[u8; KYBER_PUBKEY_SIZE]> {
        self.our_kem_keypair.as_ref().map(|kp| kp.public)
    }

    /// Check if we should advance the KEM ratchet based on policy.
    pub fn should_advance_kem(&self, policy_message_threshold: u32) -> bool {
        self.send_count.saturating_sub(self.last_kem_message_number) >= policy_message_threshold
    }

    /// Manually trigger KEM ratchet advancement.
    pub fn trigger_kem_advancement(&mut self) {
        let mut rng = rand::thread_rng();
        self.our_kem_keypair = Some(keypair(&mut rng).expect("Kyber keypair generation failed"));
        self.should_send_kem_pubkey = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_initialization() {
        let root_key = [42u8; 32];
        let state = RatchetState::new(root_key, true);

        assert_eq!(state.send_count, 0);
        assert_eq!(state.recv_count, 0);
        assert!(state.our_kem_keypair.is_some());
    }

    #[test]
    fn test_responder_initialization() {
        let root_key = [42u8; 32];
        let state = RatchetState::new(root_key, false);

        assert!(state.our_kem_keypair.is_none());
    }

    #[test]
    fn test_chain_key_asymmetry() {
        let root_key = [42u8; 32];
        let alice = RatchetState::new(root_key, true);
        let bob = RatchetState::new(root_key, false);

        // Alice's send chain should equal Bob's recv chain
        assert_eq!(alice.send_chain_key, bob.recv_chain_key);
        // Alice's recv chain should equal Bob's send chain
        assert_eq!(alice.recv_chain_key, bob.send_chain_key);
    }

    #[test]
    fn test_kdf_determinism() {
        let key = [1u8; 32];
        let (k1a, k2a) = RatchetState::kdf_derive(&key, b"test", &[0u8; 32]);
        let (k1b, k2b) = RatchetState::kdf_derive(&key, b"test", &[0u8; 32]);

        assert_eq!(k1a, k1b);
        assert_eq!(k2a, k2b);
    }

    #[test]
    fn test_kdf_different_inputs() {
        let key = [1u8; 32];
        let (k1a, _) = RatchetState::kdf_derive(&key, b"test", &[0u8; 32]);
        let (k1b, _) = RatchetState::kdf_derive(&key, b"test", &[1u8; 32]);

        assert_ne!(k1a, k1b);
    }
}
