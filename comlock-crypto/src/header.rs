//! # ComLock Crypto - Message Header Module
//!
//! Defines the `MessageHeader` structure for efficient serialization
//! of cryptographic metadata in ComLock messages.

use serde::{Deserialize, Serialize};

use crate::ratchet::{KYBER_CIPHERTEXT_SIZE, KYBER_PUBKEY_SIZE};
use crate::ComLockError;

/// Message header containing cryptographic metadata.
///
/// This header accompanies every encrypted message and contains:
/// - Classical X25519 ephemeral public key (always present, 32 bytes)
/// - Optional Kyber-1024 ciphertext (when KEM ratchet advances, ~1568 bytes)
/// - Optional Kyber-1024 public key (to enable the remote to encapsulate)
/// - Message counters for ordering and replay detection
///
/// The header is designed for efficient serialization with optional
/// fields to minimize bandwidth when KEM operations are not performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageHeader {
    /// X25519 ephemeral public key (32 bytes, always present)
    pub classical_pubkey: [u8; 32],

    /// Kyber-1024 ciphertext (optional, ~1568 bytes when present)
    /// Present when the sender encapsulates to the receiver's KEM pubkey
    #[serde(with = "optional_bytes")]
    pub kem_ciphertext: Option<Vec<u8>>,

    /// Kyber-1024 public key (optional, ~1568 bytes when present)
    /// Sent to enable the receiver to encapsulate back to us
    #[serde(with = "optional_bytes")]
    pub kem_pubkey: Option<Vec<u8>>,

    /// Message number in the current sending chain (for ordering)
    pub message_number: u32,

    /// Length of the previous receiving chain (for skipped message handling)
    pub previous_chain_length: u32,
}

/// Custom serialization for optional byte vectors to handle compact encoding
mod optional_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)
    }
}

impl MessageHeader {
    /// Create a new message header.
    ///
    /// # Arguments
    /// * `classical_pubkey` - The 32-byte X25519 ephemeral public key
    /// * `kem_ciphertext` - Optional Kyber ciphertext (when encapsulating)
    /// * `kem_pubkey` - Optional Kyber public key (to receive encapsulation)
    /// * `message_number` - Current message number in sending chain
    /// * `previous_chain_length` - Length of previous receiving chain
    pub fn new(
        classical_pubkey: [u8; 32],
        kem_ciphertext: Option<Vec<u8>>,
        kem_pubkey: Option<[u8; KYBER_PUBKEY_SIZE]>,
        message_number: u32,
        previous_chain_length: u32,
    ) -> Self {
        Self {
            classical_pubkey,
            kem_ciphertext,
            kem_pubkey: kem_pubkey.map(|pk| pk.to_vec()),
            message_number,
            previous_chain_length,
        }
    }

    /// Serialize the header to a compact binary format.
    ///
    /// Format:
    /// - Bytes 0-31: Classical public key (fixed)
    /// - Byte 32: Flags (bit 0: has_kem_ct, bit 1: has_kem_pk)
    /// - Bytes 33-36: Message number (u32 LE)
    /// - Bytes 37-40: Previous chain length (u32 LE)
    /// - If has_kem_ct: Next KYBER_CIPHERTEXT_SIZE bytes
    /// - If has_kem_pk: Next KYBER_PUBKEY_SIZE bytes
    pub fn serialize(&self) -> Vec<u8> {
        let has_kem_ct = self.kem_ciphertext.is_some();
        let has_kem_pk = self.kem_pubkey.is_some();

        // Calculate total size
        let mut size = 32 + 1 + 4 + 4; // pubkey + flags + msg_num + prev_chain
        if has_kem_ct {
            size += KYBER_CIPHERTEXT_SIZE;
        }
        if has_kem_pk {
            size += KYBER_PUBKEY_SIZE;
        }

        let mut buffer = Vec::with_capacity(size);

        // Classical public key (32 bytes)
        buffer.extend_from_slice(&self.classical_pubkey);

        // Flags byte
        let flags: u8 = (has_kem_ct as u8) | ((has_kem_pk as u8) << 1);
        buffer.push(flags);

        // Message counters
        buffer.extend_from_slice(&self.message_number.to_le_bytes());
        buffer.extend_from_slice(&self.previous_chain_length.to_le_bytes());

        // Optional KEM ciphertext
        if let Some(ref ct) = self.kem_ciphertext {
            buffer.extend_from_slice(ct);
        }

        // Optional KEM public key
        if let Some(ref pk) = self.kem_pubkey {
            buffer.extend_from_slice(pk);
        }

        buffer
    }

    /// Deserialize a header from binary format.
    ///
    /// # Errors
    /// Returns `ComLockError::InvalidHeader` if the buffer is malformed.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ComLockError> {
        const MIN_SIZE: usize = 32 + 1 + 4 + 4; // 41 bytes minimum

        if bytes.len() < MIN_SIZE {
            return Err(ComLockError::InvalidHeader);
        }

        // Parse classical public key
        let classical_pubkey: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| ComLockError::InvalidHeader)?;

        // Parse flags
        let flags = bytes[32];
        let has_kem_ct = (flags & 0x01) != 0;
        let has_kem_pk = (flags & 0x02) != 0;

        // Parse message counters
        let message_number = u32::from_le_bytes(
            bytes[33..37]
                .try_into()
                .map_err(|_| ComLockError::InvalidHeader)?,
        );
        let previous_chain_length = u32::from_le_bytes(
            bytes[37..41]
                .try_into()
                .map_err(|_| ComLockError::InvalidHeader)?,
        );

        // Calculate expected size and validate
        let mut expected_size = MIN_SIZE;
        if has_kem_ct {
            expected_size += KYBER_CIPHERTEXT_SIZE;
        }
        if has_kem_pk {
            expected_size += KYBER_PUBKEY_SIZE;
        }

        if bytes.len() < expected_size {
            return Err(ComLockError::InvalidHeader);
        }

        // Parse optional KEM ciphertext
        let mut offset = MIN_SIZE;
        let kem_ciphertext = if has_kem_ct {
            let ct = bytes[offset..offset + KYBER_CIPHERTEXT_SIZE].to_vec();
            offset += KYBER_CIPHERTEXT_SIZE;
            Some(ct)
        } else {
            None
        };

        // Parse optional KEM public key
        let kem_pubkey = if has_kem_pk {
            let pk = bytes[offset..offset + KYBER_PUBKEY_SIZE].to_vec();
            Some(pk)
        } else {
            None
        };

        Ok(Self {
            classical_pubkey,
            kem_ciphertext,
            kem_pubkey,
            message_number,
            previous_chain_length,
        })
    }

    /// Returns the total serialized size of this header.
    pub fn serialized_size(&self) -> usize {
        let mut size = 32 + 1 + 4 + 4; // Fixed overhead
        if self.kem_ciphertext.is_some() {
            size += KYBER_CIPHERTEXT_SIZE;
        }
        if self.kem_pubkey.is_some() {
            size += KYBER_PUBKEY_SIZE;
        }
        size
    }

    /// Check if this header includes KEM advancement (ciphertext or pubkey).
    pub fn has_kem_data(&self) -> bool {
        self.kem_ciphertext.is_some() || self.kem_pubkey.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_minimal_roundtrip() {
        let header = MessageHeader::new([42u8; 32], None, None, 5, 3);

        let serialized = header.serialize();
        let deserialized = MessageHeader::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
        assert_eq!(serialized.len(), 41); // Minimal size
    }

    #[test]
    fn test_header_with_kem_ciphertext() {
        let kem_ct = vec![0xABu8; KYBER_CIPHERTEXT_SIZE];
        let header = MessageHeader::new([1u8; 32], Some(kem_ct), None, 10, 7);

        let serialized = header.serialize();
        let deserialized = MessageHeader::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
        assert_eq!(serialized.len(), 41 + KYBER_CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_header_with_kem_pubkey() {
        let kem_pk: [u8; KYBER_PUBKEY_SIZE] = [0xCDu8; KYBER_PUBKEY_SIZE];
        let header = MessageHeader::new([2u8; 32], None, Some(kem_pk), 15, 12);

        let serialized = header.serialize();
        let deserialized = MessageHeader::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
        assert_eq!(serialized.len(), 41 + KYBER_PUBKEY_SIZE);
    }

    #[test]
    fn test_header_full_roundtrip() {
        let kem_ct = vec![0xEFu8; KYBER_CIPHERTEXT_SIZE];
        let kem_pk: [u8; KYBER_PUBKEY_SIZE] = [0x12u8; KYBER_PUBKEY_SIZE];
        let header = MessageHeader::new([3u8; 32], Some(kem_ct), Some(kem_pk), 100, 99);

        let serialized = header.serialize();
        let deserialized = MessageHeader::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
        assert_eq!(
            serialized.len(),
            41 + KYBER_CIPHERTEXT_SIZE + KYBER_PUBKEY_SIZE
        );
    }

    #[test]
    fn test_header_too_short() {
        let short_buffer = [0u8; 10];
        assert!(MessageHeader::deserialize(&short_buffer).is_err());
    }

    #[test]
    fn test_header_claims_kem_but_truncated() {
        // Create a buffer that claims to have KEM ciphertext but is too short
        let mut buffer = vec![0u8; 41];
        buffer[32] = 0x01; // Flag: has_kem_ct = true

        assert!(MessageHeader::deserialize(&buffer).is_err());
    }

    #[test]
    fn test_serialized_size() {
        let header_minimal = MessageHeader::new([0u8; 32], None, None, 0, 0);
        assert_eq!(header_minimal.serialized_size(), 41);

        let header_with_ct = MessageHeader::new(
            [0u8; 32],
            Some(vec![0u8; KYBER_CIPHERTEXT_SIZE]),
            None,
            0,
            0,
        );
        assert_eq!(header_with_ct.serialized_size(), 41 + KYBER_CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_has_kem_data() {
        let header_none = MessageHeader::new([0u8; 32], None, None, 0, 0);
        assert!(!header_none.has_kem_data());

        let header_ct = MessageHeader::new(
            [0u8; 32],
            Some(vec![0u8; KYBER_CIPHERTEXT_SIZE]),
            None,
            0,
            0,
        );
        assert!(header_ct.has_kem_data());

        let header_pk = MessageHeader::new([0u8; 32], None, Some([0u8; KYBER_PUBKEY_SIZE]), 0, 0);
        assert!(header_pk.has_kem_data());
    }
}
