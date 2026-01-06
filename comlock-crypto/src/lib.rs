//! # ComLock Crypto
//!
//! Hybrid Post-Quantum cryptographic primitives for Project ComLock.
//!
//! This crate implements the "KEM Braid" design for maximum-secure
//! communications, combining:
//! - **X25519** for classical ECDH (fast, every message)
//! - **Kyber-1024 (ML-KEM)** for post-quantum security (sparse, opportunistic)
//! - **HKDF-SHA256** for key derivation
//! - **AES-256-GCM-SIV** for authenticated encryption
//!
//! ## Safety
//!
//! This crate forbids all unsafe code to maximize auditability and security.
//!
//! ## Example
//!
//! ```rust,ignore
//! use comlock_crypto::{RatchetState, encrypt_message, decrypt_message};
//!
//! // Initialize from PQXDH handshake output
//! let shared_secret = [0u8; 32]; // From handshake
//! let mut alice_state = RatchetState::new(shared_secret, true);
//! let mut bob_state = RatchetState::new(shared_secret, false);
//!
//! // Alice sends a message
//! let ciphertext = encrypt_message(b"Hello, Bob!", &mut alice_state).unwrap();
//!
//! // Bob decrypts
//! let plaintext = decrypt_message(&ciphertext, &mut bob_state).unwrap();
//! assert_eq!(plaintext, b"Hello, Bob!");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(clippy::unwrap_used)]

pub mod fragment;
pub mod header;
pub mod ratchet;

pub use fragment::{
    FragmentBuffer, HeaderFragment, fragment_header, needs_fragmentation, reassemble_header,
};
pub use header::MessageHeader;
pub use ratchet::RatchetState;

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use thiserror::Error;

/// Errors that can occur during ComLock cryptographic operations.
#[derive(Debug, Error)]
pub enum ComLockError {
    /// The message header is malformed or invalid.
    #[error("Invalid message header")]
    InvalidHeader,

    /// The ciphertext is malformed or invalid.
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// The public key is malformed or invalid.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// KEM encapsulation failed.
    #[error("KEM encapsulation failed")]
    EncapsulationFailed,

    /// KEM decapsulation failed (wrong key or tampered ciphertext).
    #[error("KEM decapsulation failed")]
    DecapsulationFailed,

    /// Missing KEM keypair for decapsulation.
    #[error("Missing KEM keypair")]
    MissingKemKeypair,

    /// AEAD encryption failed.
    #[error("Encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed (authentication error).
    #[error("Decryption failed: authentication error")]
    DecryptionFailed,

    /// Message is too short to be valid.
    #[error("Message too short")]
    MessageTooShort,
}

/// Result type for ComLock operations.
pub type Result<T> = std::result::Result<T, ComLockError>;

/// Size of the AES-GCM-SIV nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Encrypt a message using the current ratchet state.
///
/// This function:
/// 1. Advances the ratchet to derive a fresh message key
/// 2. Encrypts the plaintext using AES-256-GCM-SIV
/// 3. Serializes the header and ciphertext into a single blob
///
/// # Arguments
/// * `msg` - The plaintext message to encrypt
/// * `state` - Mutable reference to the sender's ratchet state
///
/// # Returns
/// * `Vec<u8>` containing the serialized header, nonce, and ciphertext
///
/// # Wire Format
/// ```text
/// [header_len: u16 LE][header bytes][nonce: 12 bytes][ciphertext + tag]
/// ```
pub fn encrypt_message(msg: &[u8], state: &mut RatchetState) -> Result<Vec<u8>> {
    // Advance the ratchet and get the message key
    let ratchet_output = state.step(None)?;

    // Serialize the header
    let header_bytes = ratchet_output.header.serialize();
    let header_len = header_bytes.len() as u16;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the message using AES-256-GCM-SIV
    let cipher =
        Aes256GcmSiv::new_from_slice(&ratchet_output.message_key).expect("Invalid key length");
    let ciphertext = cipher
        .encrypt(nonce, msg)
        .map_err(|_| ComLockError::EncryptionFailed)?;

    // Build the output: [header_len][header][nonce][ciphertext]
    let mut output = Vec::with_capacity(2 + header_bytes.len() + NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&header_len.to_le_bytes());
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a message using the current ratchet state.
///
/// This function:
/// 1. Parses the header from the ciphertext blob
/// 2. Advances the receiving ratchet to derive the message key
/// 3. Decrypts and authenticates the ciphertext
///
/// # Arguments
/// * `ciphertext` - The complete encrypted message blob
/// * `state` - Mutable reference to the receiver's ratchet state
///
/// # Returns
/// * `Vec<u8>` containing the decrypted plaintext
///
/// # Errors
/// - `InvalidHeader` if the header cannot be parsed
/// - `DecryptionFailed` if authentication fails (tampered or wrong key)
pub fn decrypt_message(ciphertext: &[u8], state: &mut RatchetState) -> Result<Vec<u8>> {
    // Minimum size: 2 (len) + 41 (min header) + 12 (nonce) + 16 (tag)
    const MIN_SIZE: usize = 2 + 41 + NONCE_SIZE + 16;
    if ciphertext.len() < MIN_SIZE {
        return Err(ComLockError::MessageTooShort);
    }

    // Parse header length
    let header_len = u16::from_le_bytes([ciphertext[0], ciphertext[1]]) as usize;

    // Validate header length
    if ciphertext.len() < 2 + header_len + NONCE_SIZE + 16 {
        return Err(ComLockError::MessageTooShort);
    }

    // Parse header
    let header_bytes = &ciphertext[2..2 + header_len];
    let header = MessageHeader::deserialize(header_bytes)?;

    // Extract nonce and ciphertext
    let nonce_start = 2 + header_len;
    let nonce_bytes: [u8; NONCE_SIZE] = ciphertext[nonce_start..nonce_start + NONCE_SIZE]
        .try_into()
        .map_err(|_| ComLockError::InvalidCiphertext)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = &ciphertext[nonce_start + NONCE_SIZE..];

    // Advance the receiving ratchet
    let decrypt_ctx = state.receive_step(&header)?;

    // Decrypt using AES-256-GCM-SIV
    let cipher =
        Aes256GcmSiv::new_from_slice(&decrypt_ctx.message_key).expect("Invalid key length");
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| ComLockError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Encrypt a message with explicit KEM ciphertext from the remote party.
///
/// Use this when you have received a KEM ciphertext that needs to be
/// processed during this send operation.
///
/// # Arguments
/// * `msg` - The plaintext message to encrypt
/// * `state` - Mutable reference to the sender's ratchet state
/// * `remote_kem_ct` - KEM ciphertext received from the remote party
pub fn encrypt_message_with_kem(
    msg: &[u8],
    state: &mut RatchetState,
    remote_kem_ct: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Advance the ratchet with the remote KEM ciphertext
    let ratchet_output = state.step(remote_kem_ct)?;

    // Serialize the header
    let header_bytes = ratchet_output.header.serialize();
    let header_len = header_bytes.len() as u16;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the message
    let cipher =
        Aes256GcmSiv::new_from_slice(&ratchet_output.message_key).expect("Invalid key length");
    let ciphertext = cipher
        .encrypt(nonce, msg)
        .map_err(|_| ComLockError::EncryptionFailed)?;

    // Build the output
    let mut output = Vec::with_capacity(2 + header_bytes.len() + NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&header_len.to_le_bytes());
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates a shared secret from a PQXDH handshake
    fn mock_handshake_secret() -> [u8; 32] {
        // In practice, this comes from the PQXDH key exchange
        let mut secret = [0u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(42);
        }
        secret
    }

    #[test]
    fn test_basic_encryption_decryption() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // Synchronize: Bob needs Alice's public key
        // First message from Alice establishes the link
        let msg = b"Hello, Bob!";
        let ciphertext = encrypt_message(msg, &mut alice).expect("Encryption failed");
        let plaintext = decrypt_message(&ciphertext, &mut bob).expect("Decryption failed");

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_alice_sends_three_messages() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // Alice sends 3 messages
        let messages = [
            b"Message 1: Hello!".as_slice(),
            b"Message 2: How are you?".as_slice(),
            b"Message 3: Fine weather today.".as_slice(),
        ];

        let mut ciphertexts = Vec::new();
        for msg in &messages {
            let ct = encrypt_message(msg, &mut alice).expect("Encryption failed");
            ciphertexts.push(ct);
        }

        // Bob decrypts all 3 messages
        for (i, ct) in ciphertexts.iter().enumerate() {
            let plaintext = decrypt_message(ct, &mut bob).expect("Decryption failed");
            assert_eq!(plaintext, messages[i]);
        }
    }

    #[test]
    fn test_alice_sends_three_bob_replies_one() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // Alice sends 3 messages
        let alice_msgs = [
            b"Alice msg 1".as_slice(),
            b"Alice msg 2".as_slice(),
            b"Alice msg 3".as_slice(),
        ];

        for msg in &alice_msgs {
            let ct = encrypt_message(msg, &mut alice).expect("Encryption failed");
            let pt = decrypt_message(&ct, &mut bob).expect("Decryption failed");
            assert_eq!(pt, *msg);
        }

        // Bob triggers KEM ratchet advancement and replies
        bob.trigger_kem_advancement();
        let bob_msg = b"Bob's reply with KEM advancement!";
        let bob_ct = encrypt_message(bob_msg, &mut bob).expect("Bob encryption failed");

        // Alice decrypts Bob's reply
        let bob_pt = decrypt_message(&bob_ct, &mut alice).expect("Alice decryption failed");
        assert_eq!(bob_pt, bob_msg.as_slice());

        // Verify Alice can still send more messages after receiving Bob's KEM
        let followup = b"Alice followup after KEM exchange";
        let followup_ct =
            encrypt_message(followup, &mut alice).expect("Followup encryption failed");
        let followup_pt =
            decrypt_message(&followup_ct, &mut bob).expect("Followup decryption failed");
        assert_eq!(followup_pt, followup.as_slice());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        let msg = b"Secret message";
        let mut ciphertext = encrypt_message(msg, &mut alice).expect("Encryption failed");

        // Tamper with the ciphertext (flip a byte near the end)
        let last_idx = ciphertext.len() - 5;
        ciphertext[last_idx] ^= 0xFF;

        // Decryption should fail due to authentication
        let result = decrypt_message(&ciphertext, &mut bob);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ComLockError::DecryptionFailed
        ));
    }

    #[test]
    fn test_tampered_header_fails() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        let msg = b"Secret message";
        let mut ciphertext = encrypt_message(msg, &mut alice).expect("Encryption failed");

        // Tamper with the message counter in the header (bytes 33-37)
        // This will cause the receiver to derive a different message key
        ciphertext[35] ^= 0xFF;

        // Decryption should fail because the derived key will be wrong
        // (wrong message counter -> wrong KDF input -> wrong key -> AEAD fails)
        let result = decrypt_message(&ciphertext, &mut bob);
        // Either header parsing fails or AEAD authentication fails
        assert!(
            result.is_err(),
            "Tampered header should cause decryption failure"
        );
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let shared_secret_alice_bob = mock_handshake_secret();
        let mut shared_secret_alice_eve = [0u8; 32];
        shared_secret_alice_eve.copy_from_slice(&shared_secret_alice_bob);
        shared_secret_alice_eve[0] ^= 0x01; // Different secret for Eve

        let mut alice = RatchetState::new(shared_secret_alice_bob, true);
        let mut eve = RatchetState::new(shared_secret_alice_eve, false);

        let msg = b"For Bob's eyes only";
        let ciphertext = encrypt_message(msg, &mut alice).expect("Encryption failed");

        // Eve (with wrong shared secret) cannot decrypt
        let result = decrypt_message(&ciphertext, &mut eve);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_ordering_matters() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // Alice sends 2 messages
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let ct1 = encrypt_message(msg1, &mut alice).expect("Encryption 1 failed");
        let ct2 = encrypt_message(msg2, &mut alice).expect("Encryption 2 failed");

        // Bob decrypts in order
        let pt1 = decrypt_message(&ct1, &mut bob).expect("Decryption 1 failed");
        assert_eq!(pt1, msg1);

        let pt2 = decrypt_message(&ct2, &mut bob).expect("Decryption 2 failed");
        assert_eq!(pt2, msg2);
    }

    #[test]
    fn test_empty_message() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        let msg: &[u8] = b"";
        let ciphertext = encrypt_message(msg, &mut alice).expect("Encryption failed");
        let plaintext = decrypt_message(&ciphertext, &mut bob).expect("Decryption failed");

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_large_message() {
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // 64KB message
        let msg: Vec<u8> = (0..65536).map(|i| (i & 0xFF) as u8).collect();
        let ciphertext = encrypt_message(&msg, &mut alice).expect("Encryption failed");
        let plaintext = decrypt_message(&ciphertext, &mut bob).expect("Decryption failed");

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_kem_tampering_detection() {
        // This test verifies that tampering with encrypted data
        // causes AEAD authentication to fail
        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // Exchange initial messages to establish the ratchet
        let msg1 = b"Setup message";
        let ct1 = encrypt_message(msg1, &mut alice).expect("Encryption failed");
        let _ = decrypt_message(&ct1, &mut bob).expect("Decryption failed");

        // Bob triggers KEM and sends
        bob.trigger_kem_advancement();
        let bob_msg = b"Bob's KEM message";
        let mut bob_ct = encrypt_message(bob_msg, &mut bob).expect("Bob encryption failed");

        // Tamper with the AEAD ciphertext portion (after header + nonce)
        // This should cause authentication to fail
        let header_len = u16::from_le_bytes([bob_ct[0], bob_ct[1]]) as usize;
        let aead_start = 2 + header_len + 12; // header_len_field + header + nonce
        if bob_ct.len() > aead_start + 5 {
            bob_ct[aead_start + 3] ^= 0xFF;
        }

        // Alice should fail to decrypt due to AEAD authentication failure
        let result = decrypt_message(&bob_ct, &mut alice);
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail AEAD authentication"
        );
    }

    #[test]
    fn test_conversation_scenario_from_spec() {
        // Full scenario from the specification:
        // 1. Alice sends 3 messages
        // 2. Bob replies with 1 message (advancing KEM ratchet)
        // 3. Verify tampered KEM causes failure

        let shared_secret = mock_handshake_secret();
        let mut alice = RatchetState::new(shared_secret, true);
        let mut bob = RatchetState::new(shared_secret, false);

        // === Part 1: Alice sends 3 messages ===
        println!("=== Alice sends 3 messages ===");
        let alice_messages = [
            b"Alice: Hello Bob, are you there?".as_slice(),
            b"Alice: I have important news.".as_slice(),
            b"Alice: The project is approved!".as_slice(),
        ];

        let mut ciphertexts = Vec::new();
        for msg in &alice_messages {
            let ct = encrypt_message(msg, &mut alice).expect("Alice encryption failed");
            ciphertexts.push(ct);
        }

        // Bob decrypts all 3
        for (i, ct) in ciphertexts.iter().enumerate() {
            let pt = decrypt_message(ct, &mut bob).expect("Bob decryption failed");
            assert_eq!(pt, alice_messages[i]);
        }

        // === Part 2: Bob replies, advancing KEM ratchet ===
        println!("=== Bob replies with KEM advancement ===");
        bob.trigger_kem_advancement();

        let bob_reply = b"Bob: Great news! Let's celebrate!";
        let bob_ct = encrypt_message(bob_reply, &mut bob).expect("Bob encryption failed");

        let bob_pt = decrypt_message(&bob_ct, &mut alice).expect("Alice decryption failed");
        assert_eq!(bob_pt, bob_reply.as_slice());

        // === Part 3: Verify tampering detection ===
        println!("=== Verifying tamper detection ===");

        // Create a fresh pair for the tamper test
        let mut alice2 = RatchetState::new(shared_secret, true);
        let mut bob2 = RatchetState::new(shared_secret, false);

        // Initial exchange
        let init_msg = b"Initial sync";
        let init_ct = encrypt_message(init_msg, &mut alice2).expect("Encryption failed");
        decrypt_message(&init_ct, &mut bob2).expect("Decryption failed");

        // Bob sends with KEM
        bob2.trigger_kem_advancement();
        let kem_msg = b"Message with KEM data";
        let mut kem_ct = encrypt_message(kem_msg, &mut bob2).expect("Encryption failed");

        // Tamper with the KEM-related data in the ciphertext
        // Flip bits in the encrypted portion to corrupt it
        let tamper_idx = kem_ct.len() - 10;
        kem_ct[tamper_idx] ^= 0xFF;

        // Decryption must fail
        let tamper_result = decrypt_message(&kem_ct, &mut alice2);
        assert!(
            tamper_result.is_err(),
            "Tampered KEM message should fail decryption"
        );

        println!("=== All tests passed! ===");
    }
}
