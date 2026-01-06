//! # Header Fragmentation
//!
//! Implements fragmentation and reassembly of large message headers
//! to prevent packet size correlation attacks when using post-quantum
//! KEM keys (Kyber-1024 keys/ciphertexts are ~1568 bytes).
//!
//! ## Design
//!
//! When a message header contains KEM data that would make it exceed
//! the maximum Sphinx payload size, we split it into multiple fragments
//! that can be sent via different mix routes and reassembled by the
//! recipient.

use crate::ComLockError;
use crate::header::MessageHeader;

/// Maximum header size that fits in a single Sphinx packet.
pub const MAX_SINGLE_HEADER_SIZE: usize = 2048;

/// Size of fragment metadata overhead.
const FRAGMENT_OVERHEAD: usize = 12; // fragment_id(1) + total(1) + seq(4) + len(2) + reserved(4)

/// A fragmented piece of a message header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFragment {
    /// Unique identifier for this fragmented header (random).
    pub fragment_id: [u8; 8],
    /// This fragment's index (0-indexed).
    pub index: u8,
    /// Total number of fragments.
    pub total: u8,
    /// The fragment data.
    pub data: Vec<u8>,
}

impl HeaderFragment {
    /// Serialize the fragment to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAGMENT_OVERHEAD + self.data.len());
        bytes.extend_from_slice(&self.fragment_id);
        bytes.push(self.index);
        bytes.push(self.total);
        let len = self.data.len() as u16;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize a fragment from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ComLockError> {
        if bytes.len() < FRAGMENT_OVERHEAD {
            return Err(ComLockError::InvalidHeader);
        }

        let fragment_id: [u8; 8] = bytes[0..8]
            .try_into()
            .map_err(|_| ComLockError::InvalidHeader)?;
        let index = bytes[8];
        let total = bytes[9];
        let len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;

        if bytes.len() < FRAGMENT_OVERHEAD + len {
            return Err(ComLockError::InvalidHeader);
        }

        let data = bytes[FRAGMENT_OVERHEAD..FRAGMENT_OVERHEAD + len].to_vec();

        Ok(Self {
            fragment_id,
            index,
            total,
            data,
        })
    }
}

/// Fragment a message header into smaller pieces.
///
/// Returns `None` if the header fits in a single packet (no fragmentation needed).
/// Returns `Some(fragments)` if the header was split.
pub fn fragment_header(
    header: &MessageHeader,
    max_fragment_size: usize,
) -> Option<Vec<HeaderFragment>> {
    let header_bytes = header.serialize();

    if header_bytes.len() <= MAX_SINGLE_HEADER_SIZE {
        return None; // No fragmentation needed
    }

    let data_per_fragment = max_fragment_size.saturating_sub(FRAGMENT_OVERHEAD);
    if data_per_fragment == 0 {
        return None; // Invalid configuration
    }

    let total_fragments = (header_bytes.len() + data_per_fragment - 1) / data_per_fragment;
    if total_fragments > 255 {
        return None; // Too many fragments
    }

    // Generate a random fragment ID
    let mut fragment_id = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut fragment_id);

    let mut fragments = Vec::with_capacity(total_fragments);

    for (i, chunk) in header_bytes.chunks(data_per_fragment).enumerate() {
        fragments.push(HeaderFragment {
            fragment_id,
            index: i as u8,
            total: total_fragments as u8,
            data: chunk.to_vec(),
        });
    }

    Some(fragments)
}

/// Reassemble header fragments into a complete MessageHeader.
///
/// Fragments must all have the same `fragment_id` and all indices
/// from 0 to total-1 must be present.
pub fn reassemble_header(fragments: &[HeaderFragment]) -> Result<MessageHeader, ComLockError> {
    if fragments.is_empty() {
        return Err(ComLockError::InvalidHeader);
    }

    // Verify all fragments have the same ID
    let expected_id = fragments[0].fragment_id;
    let expected_total = fragments[0].total;

    if fragments.len() != expected_total as usize {
        return Err(ComLockError::InvalidHeader);
    }

    for frag in fragments {
        if frag.fragment_id != expected_id || frag.total != expected_total {
            return Err(ComLockError::InvalidHeader);
        }
    }

    // Sort by index
    let mut sorted: Vec<_> = fragments.to_vec();
    sorted.sort_by_key(|f| f.index);

    // Verify we have all indices
    for (i, frag) in sorted.iter().enumerate() {
        if frag.index != i as u8 {
            return Err(ComLockError::InvalidHeader);
        }
    }

    // Concatenate data
    let total_size: usize = sorted.iter().map(|f| f.data.len()).sum();
    let mut reassembled = Vec::with_capacity(total_size);
    for frag in sorted {
        reassembled.extend_from_slice(&frag.data);
    }

    // Deserialize the header
    MessageHeader::deserialize(&reassembled)
}

/// Check if a header needs fragmentation.
pub fn needs_fragmentation(header: &MessageHeader) -> bool {
    let size = header.serialize().len();
    size > MAX_SINGLE_HEADER_SIZE
}

/// Fragment buffer for accumulating incoming fragments.
#[derive(Debug, Default)]
pub struct FragmentBuffer {
    /// Pending fragments grouped by fragment_id.
    pending: std::collections::HashMap<[u8; 8], Vec<HeaderFragment>>,
}

impl FragmentBuffer {
    /// Create a new fragment buffer.
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
        }
    }

    /// Add a fragment to the buffer.
    ///
    /// Returns `Some(header)` if all fragments are now received and
    /// the header was successfully reassembled.
    pub fn add_fragment(&mut self, fragment: HeaderFragment) -> Option<MessageHeader> {
        let frag_id = fragment.fragment_id;
        let expected_total = fragment.total;

        let entry = self.pending.entry(frag_id).or_default();

        // Check if we already have this index
        if entry.iter().any(|f| f.index == fragment.index) {
            return None; // Duplicate
        }

        entry.push(fragment);
        let is_complete = entry.len() == expected_total as usize;

        // Check if complete - need to drop the entry borrow first
        if is_complete {
            let frags = self.pending.remove(&frag_id)?;
            reassemble_header(&frags).ok()
        } else {
            None
        }
    }

    /// Clear old pending fragments.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Number of incomplete fragment groups.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_large_header() -> MessageHeader {
        // Create a header with KEM data to trigger fragmentation
        MessageHeader {
            classical_pubkey: [0x42; 32],
            kem_ciphertext: Some(vec![0xAB; 1568]), // Kyber-1024 ciphertext
            kem_pubkey: Some(vec![0xCD; 1568]),     // Kyber-1024 public key
            message_number: 42,
            previous_chain_length: 10,
        }
    }

    fn create_small_header() -> MessageHeader {
        MessageHeader {
            classical_pubkey: [0x42; 32],
            kem_ciphertext: None,
            kem_pubkey: None,
            message_number: 1,
            previous_chain_length: 0,
        }
    }

    #[test]
    fn test_small_header_no_fragmentation() {
        let header = create_small_header();
        let result = fragment_header(&header, 512);
        assert!(result.is_none());
        assert!(!needs_fragmentation(&header));
    }

    #[test]
    fn test_large_header_fragments() {
        let header = create_large_header();
        assert!(needs_fragmentation(&header));

        let fragments = fragment_header(&header, 512).unwrap();
        assert!(fragments.len() > 1);

        // Verify all fragments have same ID and correct total
        let id = fragments[0].fragment_id;
        let total = fragments[0].total;
        for (i, frag) in fragments.iter().enumerate() {
            assert_eq!(frag.fragment_id, id);
            assert_eq!(frag.total, total);
            assert_eq!(frag.index, i as u8);
        }
    }

    #[test]
    fn test_fragment_serialization() {
        let frag = HeaderFragment {
            fragment_id: [1, 2, 3, 4, 5, 6, 7, 8],
            index: 0,
            total: 3,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = frag.serialize();
        let parsed = HeaderFragment::deserialize(&bytes).unwrap();

        assert_eq!(parsed.fragment_id, frag.fragment_id);
        assert_eq!(parsed.index, frag.index);
        assert_eq!(parsed.total, frag.total);
        assert_eq!(parsed.data, frag.data);
    }

    #[test]
    fn test_reassembly() {
        let header = create_large_header();
        let fragments = fragment_header(&header, 512).unwrap();

        // Reassemble in order
        let reassembled = reassemble_header(&fragments).unwrap();
        assert_eq!(reassembled.classical_pubkey, header.classical_pubkey);
        assert_eq!(reassembled.message_number, header.message_number);
        assert_eq!(reassembled.kem_ciphertext, header.kem_ciphertext);
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let header = create_large_header();
        let mut fragments = fragment_header(&header, 512).unwrap();

        // Shuffle fragments
        fragments.reverse();

        let reassembled = reassemble_header(&fragments).unwrap();
        assert_eq!(reassembled.message_number, header.message_number);
    }

    #[test]
    fn test_fragment_buffer() {
        let header = create_large_header();
        let fragments = fragment_header(&header, 512).unwrap();

        let mut buffer = FragmentBuffer::new();

        // Add all but the last fragment
        for frag in fragments.iter().take(fragments.len() - 1) {
            let result = buffer.add_fragment(frag.clone());
            assert!(result.is_none());
        }

        assert_eq!(buffer.pending_count(), 1);

        // Add the last fragment
        let result = buffer.add_fragment(fragments.last().unwrap().clone());
        assert!(result.is_some());

        let reassembled = result.unwrap();
        assert_eq!(reassembled.message_number, header.message_number);

        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_missing_fragment_fails() {
        let header = create_large_header();
        let mut fragments = fragment_header(&header, 512).unwrap();

        // Remove one fragment
        fragments.remove(1);

        let result = reassemble_header(&fragments);
        assert!(result.is_err());
    }
}
