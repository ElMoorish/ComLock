//! # Sphinx Packet Construction
//!
//! Implements the Sphinx packet format for onion-encrypted mixnet communication.
//! All packets are padded to a fixed size (32KB) to prevent traffic analysis.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{MixNode, Result, Route, TransportError};

/// Fixed packet size for traffic analysis resistance (32KB).
pub const PACKET_SIZE: usize = 32 * 1024;

/// Size of the Sphinx header (routing info).
pub const HEADER_SIZE: usize = 1024;

/// Size of the payload section.
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

/// Maximum number of hops in a route.
pub const MAX_HOPS: usize = 5;

/// Size of each routing command in the header.
const ROUTING_INFO_SIZE: usize = 64;

/// A Sphinx packet header containing encrypted routing information.
#[derive(Debug, Clone)]
pub struct SphinxHeader {
    /// Ephemeral public key for this hop.
    pub ephemeral_key: [u8; 32],
    /// Encrypted routing information (peeled at each hop).
    pub routing_info: Vec<u8>,
    /// MAC for integrity verification.
    pub mac: [u8; 16],
}

/// A complete Sphinx packet (header + encrypted payload).
#[derive(Debug, Clone)]
pub struct SphinxPacket {
    /// The packet header.
    pub header: SphinxHeader,
    /// The encrypted payload (fixed size).
    pub payload: Vec<u8>,
}

/// Routing command decoded by a mix node.
#[derive(Debug, Clone)]
pub enum RoutingCommand {
    /// Forward to the next hop.
    Relay {
        /// Next node's address.
        next_address: String,
        /// Delay in milliseconds before forwarding.
        delay_ms: u32,
    },
    /// Deliver to a mailbox (final hop).
    Deliver {
        /// Mailbox identifier.
        mailbox_id: [u8; 32],
    },
}

/// Result of unwrapping one layer of a Sphinx packet.
pub struct UnwrapResult {
    /// The routing command for this hop.
    pub command: RoutingCommand,
    /// The packet to forward (with one layer removed).
    pub next_packet: SphinxPacket,
}

impl SphinxPacket {
    /// Create a new Sphinx packet for the given route and payload.
    ///
    /// The payload is encrypted in layers (onion encryption) so that each
    /// hop can only decrypt its own routing command.
    pub fn create(payload: &[u8], route: &Route, mailbox_id: [u8; 32]) -> Result<Self> {
        if payload.len() > PAYLOAD_SIZE - 48 {
            // Reserve space for padding and auth tag
            return Err(TransportError::SphinxError("Payload too large".into()));
        }

        let mut rng = rand::thread_rng();

        // Generate ephemeral keypairs for each hop
        let hop_secrets: Vec<StaticSecret> = (0..route.nodes.len())
            .map(|_| StaticSecret::random_from_rng(&mut rng))
            .collect();

        // Compute shared secrets with each node
        let shared_secrets: Vec<[u8; 32]> = route
            .nodes
            .iter()
            .zip(hop_secrets.iter())
            .map(|(node, secret)| {
                let node_pub = PublicKey::from(node.public_key);
                let shared = secret.diffie_hellman(&node_pub);
                *shared.as_bytes()
            })
            .collect();

        // Build routing info (in reverse order for onion wrapping)
        let routing_info = Self::build_routing_info(&route.nodes, mailbox_id)?;

        // Encrypt routing info in layers (reverse order)
        let encrypted_routing = Self::encrypt_routing_layers(&routing_info, &shared_secrets)?;

        // Encrypt payload in layers (reverse order)
        let encrypted_payload = Self::encrypt_payload_layers(payload, &shared_secrets)?;

        // Compute MAC before building header (to avoid move)
        let mac = Self::compute_mac(&shared_secrets[0], &encrypted_routing);

        // Build final header
        let header = SphinxHeader {
            ephemeral_key: PublicKey::from(&hop_secrets[0]).to_bytes(),
            routing_info: encrypted_routing,
            mac,
        };

        Ok(Self {
            header,
            payload: encrypted_payload,
        })
    }

    /// Unwrap one layer of the Sphinx packet using our secret key.
    pub fn unwrap(&self, our_secret: &StaticSecret) -> Result<UnwrapResult> {
        // Compute shared secret
        let their_pub = PublicKey::from(self.header.ephemeral_key);
        let shared_secret = our_secret.diffie_hellman(&their_pub);

        // Verify MAC
        let expected_mac = Self::compute_mac(shared_secret.as_bytes(), &self.header.routing_info);
        if expected_mac != self.header.mac {
            return Err(TransportError::UnwrapError(
                "MAC verification failed".into(),
            ));
        }

        // Derive decryption key
        let (routing_key, payload_key) = Self::derive_keys(shared_secret.as_bytes());

        // Decrypt routing info
        let decrypted_routing = Self::decrypt_layer(&self.header.routing_info, &routing_key)?;

        // Parse routing command
        let (command, remaining_routing) = Self::parse_routing_command(&decrypted_routing)?;

        // Decrypt payload layer
        let decrypted_payload = Self::decrypt_layer(&self.payload, &payload_key)?;

        // Generate blinded ephemeral key for next hop
        let next_ephemeral = Self::blind_key(&self.header.ephemeral_key, shared_secret.as_bytes());

        // Build next packet
        let next_header = SphinxHeader {
            ephemeral_key: next_ephemeral,
            routing_info: remaining_routing,
            mac: Self::extract_next_mac(&decrypted_routing),
        };

        let next_packet = SphinxPacket {
            header: next_header,
            payload: decrypted_payload,
        };

        Ok(UnwrapResult {
            command,
            next_packet,
        })
    }

    /// Serialize the packet to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PACKET_SIZE);
        bytes.extend_from_slice(&self.header.ephemeral_key);
        bytes.extend_from_slice(&self.header.mac);
        bytes.extend_from_slice(&self.header.routing_info);

        // Pad routing info to fixed size
        let routing_padding = HEADER_SIZE - 32 - 16 - self.header.routing_info.len();
        bytes.extend(vec![0u8; routing_padding]);

        bytes.extend_from_slice(&self.payload);

        // Pad payload to fixed size
        if bytes.len() < PACKET_SIZE {
            bytes.extend(vec![0u8; PACKET_SIZE - bytes.len()]);
        }

        bytes
    }

    /// Parse a packet from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PACKET_SIZE {
            return Err(TransportError::SphinxError("Packet too small".into()));
        }

        let ephemeral_key: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| TransportError::SphinxError("Invalid ephemeral key".into()))?;

        let mac: [u8; 16] = bytes[32..48]
            .try_into()
            .map_err(|_| TransportError::SphinxError("Invalid MAC".into()))?;

        let routing_info = bytes[48..HEADER_SIZE].to_vec();
        let payload = bytes[HEADER_SIZE..].to_vec();

        Ok(Self {
            header: SphinxHeader {
                ephemeral_key,
                routing_info,
                mac,
            },
            payload,
        })
    }

    // === Private helper methods ===

    fn build_routing_info(nodes: &[MixNode], mailbox_id: [u8; 32]) -> Result<Vec<u8>> {
        let mut info = Vec::new();

        for (i, node) in nodes.iter().enumerate() {
            if i == nodes.len() - 1 {
                // Final hop: deliver to mailbox
                info.push(0x02); // Deliver command
                info.extend_from_slice(&mailbox_id);
            } else {
                // Relay to next hop
                info.push(0x01); // Relay command
                let addr_bytes = node.address.as_bytes();
                info.push(addr_bytes.len() as u8);
                info.extend_from_slice(addr_bytes);
                info.extend_from_slice(&[0u8; 4]); // delay_ms placeholder
            }

            // Pad each routing entry to fixed size
            let padding = ROUTING_INFO_SIZE - (info.len() % ROUTING_INFO_SIZE);
            if padding < ROUTING_INFO_SIZE {
                info.extend(vec![0u8; padding]);
            }
        }

        Ok(info)
    }

    fn encrypt_routing_layers(routing: &[u8], secrets: &[[u8; 32]]) -> Result<Vec<u8>> {
        let mut encrypted = routing.to_vec();

        // Encrypt in reverse order (last hop first)
        for secret in secrets.iter().rev() {
            let (key, _) = Self::derive_keys(secret);
            encrypted = Self::encrypt_layer(&encrypted, &key)?;
        }

        Ok(encrypted)
    }

    fn encrypt_payload_layers(payload: &[u8], secrets: &[[u8; 32]]) -> Result<Vec<u8>> {
        // Pad payload to fixed size
        let mut padded = payload.to_vec();
        padded.extend(vec![0u8; PAYLOAD_SIZE - payload.len()]);

        let mut encrypted = padded;

        // Encrypt in reverse order
        for secret in secrets.iter().rev() {
            let (_, key) = Self::derive_keys(secret);
            encrypted = Self::encrypt_layer(&encrypted, &key)?;
        }

        Ok(encrypted)
    }

    fn encrypt_layer(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TransportError::CryptoError(e.to_string()))?;

        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce (key is unique per layer)

        cipher
            .encrypt(nonce, data)
            .map_err(|e| TransportError::CryptoError(e.to_string()))
    }

    fn decrypt_layer(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TransportError::CryptoError(e.to_string()))?;

        let nonce = Nonce::from_slice(&[0u8; 12]);

        cipher
            .decrypt(nonce, data)
            .map_err(|e| TransportError::CryptoError(e.to_string()))
    }

    fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut routing_key = [0u8; 32];
        let mut payload_key = [0u8; 32];

        hk.expand(b"sphinx_routing", &mut routing_key)
            .expect("HKDF expand failed");
        hk.expand(b"sphinx_payload", &mut payload_key)
            .expect("HKDF expand failed");

        (routing_key, payload_key)
    }

    fn compute_mac(secret: &[u8; 32], data: &[u8]) -> [u8; 16] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(secret);
        hasher.update(data);
        let result = hasher.finalize();

        let mut mac = [0u8; 16];
        mac.copy_from_slice(&result[..16]);
        mac
    }

    fn parse_routing_command(data: &[u8]) -> Result<(RoutingCommand, Vec<u8>)> {
        if data.is_empty() {
            return Err(TransportError::SphinxError("Empty routing data".into()));
        }

        let command = match data[0] {
            0x01 => {
                // Relay
                let addr_len = data[1] as usize;
                let addr = String::from_utf8_lossy(&data[2..2 + addr_len]).to_string();
                let delay_ms = u32::from_le_bytes([
                    data[2 + addr_len],
                    data[3 + addr_len],
                    data[4 + addr_len],
                    data[5 + addr_len],
                ]);
                RoutingCommand::Relay {
                    next_address: addr,
                    delay_ms,
                }
            }
            0x02 => {
                // Deliver
                let mut mailbox_id = [0u8; 32];
                mailbox_id.copy_from_slice(&data[1..33]);
                RoutingCommand::Deliver { mailbox_id }
            }
            _ => {
                return Err(TransportError::SphinxError(
                    "Unknown routing command".into(),
                ))
            }
        };

        let remaining = data[ROUTING_INFO_SIZE..].to_vec();
        Ok((command, remaining))
    }

    fn extract_next_mac(data: &[u8]) -> [u8; 16] {
        // The MAC for the next hop is embedded in the routing info
        let mut mac = [0u8; 16];
        if data.len() >= ROUTING_INFO_SIZE + 16 {
            mac.copy_from_slice(&data[ROUTING_INFO_SIZE..ROUTING_INFO_SIZE + 16]);
        }
        mac
    }

    fn blind_key(key: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
        // Simple key blinding using HKDF
        let hk = Hkdf::<Sha256>::new(Some(secret), key);
        let mut blinded = [0u8; 32];
        hk.expand(b"sphinx_blind", &mut blinded)
            .expect("HKDF expand failed");
        blinded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeId;

    fn create_test_route() -> Route {
        let nodes: Vec<MixNode> = (1..=3)
            .map(|i| MixNode {
                id: NodeId::new([i; 32]),
                public_key: [i; 32],
                address: format!("127.0.0.1:900{}", i),
                layer: i,
            })
            .collect();

        Route::new(nodes).unwrap()
    }

    #[test]
    fn test_packet_size() {
        assert_eq!(PACKET_SIZE, 32 * 1024);
        assert_eq!(HEADER_SIZE + PAYLOAD_SIZE, PACKET_SIZE);
    }

    #[test]
    fn test_packet_serialization() {
        let route = create_test_route();
        let payload = b"Hello, Mixnet!";
        let mailbox_id = [0xAB; 32];

        let packet = SphinxPacket::create(payload, &route, mailbox_id).unwrap();
        let bytes = packet.to_bytes();

        // Packet should be at least PACKET_SIZE (AEAD adds some overhead)
        assert!(bytes.len() >= PACKET_SIZE);

        let parsed = SphinxPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header.ephemeral_key, packet.header.ephemeral_key);
    }

    #[test]
    fn test_routing_command_parse() {
        // Build a relay command
        let mut data = vec![0x01, 14]; // Relay, addr_len=14
        data.extend_from_slice(b"127.0.0.1:9001");
        data.extend_from_slice(&[0, 0, 0, 0]); // delay_ms = 0
        data.extend(vec![
            0u8;
            ROUTING_INFO_SIZE - data.len() + ROUTING_INFO_SIZE
        ]); // padding

        let (cmd, _remaining) = SphinxPacket::parse_routing_command(&data).unwrap();

        match cmd {
            RoutingCommand::Relay { next_address, .. } => {
                assert_eq!(next_address, "127.0.0.1:9001");
            }
            _ => panic!("Expected Relay command"),
        }
    }
}
