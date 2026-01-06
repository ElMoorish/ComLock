//! # ComLock Transport
//!
//! Mixnet transport layer implementing Sphinx packet format and Loopix-style
//! anonymous communication for Project ComLock.
//!
//! ## Features
//!
//! - **Sphinx Packets**: Onion-encrypted 32KB packets for traffic analysis resistance
//! - **Loopix Client**: Stratified mixnet routing (L1 Gateway → L2 Mix → L3 Exit)
//! - **Cover Traffic**: Poisson-distributed dummy packets for unlinkability
//! - **SURB Support**: Single Use Reply Blocks for anonymous responses
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
//! │  Client │───▶│ Gateway │───▶│  Mix    │───▶│ Mailbox │
//! │  (L0)   │    │  (L1)   │    │  (L2)   │    │  (L3)   │
//! └─────────┘    └─────────┘    └─────────┘    └─────────┘
//!      │                                             │
//!      └─────────────── SURB Response ◀──────────────┘
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod cover;
pub mod mixnet;
pub mod sphinx;

pub use cover::{AnonymityBudget, CoverTrafficGenerator};
pub use mixnet::{Mailbox, MixClient, MixClientConfig};
pub use sphinx::{SphinxHeader, SphinxPacket, PACKET_SIZE};

use thiserror::Error;

/// Errors that can occur in the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to construct Sphinx packet.
    #[error("Sphinx packet construction failed: {0}")]
    SphinxError(String),

    /// Failed to unwrap a Sphinx layer.
    #[error("Sphinx unwrap failed: {0}")]
    UnwrapError(String),

    /// Network connection error.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid route configuration.
    #[error("Invalid route: {0}")]
    InvalidRoute(String),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Timeout waiting for response.
    #[error("Operation timed out")]
    Timeout,

    /// Mailbox polling failed.
    #[error("Mailbox error: {0}")]
    MailboxError(String),
}

/// Result type for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Node identifier in the mixnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Create a new node ID from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the node ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A node in the mixnet with its public key and address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MixNode {
    /// Unique identifier (derived from public key).
    pub id: NodeId,
    /// X25519 public key for Sphinx encryption.
    pub public_key: [u8; 32],
    /// Network address (e.g., "192.168.1.1:9000").
    pub address: String,
    /// Layer in the stratified topology (1=Gateway, 2=Mix, 3=Exit).
    pub layer: u8,
}

/// A route through the mixnet.
#[derive(Debug, Clone)]
pub struct Route {
    /// Ordered list of nodes from entry to exit.
    pub nodes: Vec<MixNode>,
}

impl Route {
    /// Create a new route from a list of nodes.
    pub fn new(nodes: Vec<MixNode>) -> Result<Self> {
        if nodes.is_empty() {
            return Err(TransportError::InvalidRoute("Route cannot be empty".into()));
        }
        if nodes.len() < 3 {
            return Err(TransportError::InvalidRoute(
                "Route must have at least 3 hops (L1→L2→L3)".into(),
            ));
        }
        Ok(Self { nodes })
    }

    /// Get the entry (gateway) node.
    pub fn entry(&self) -> &MixNode {
        &self.nodes[0]
    }

    /// Get the exit (mailbox) node.
    pub fn exit(&self) -> &MixNode {
        self.nodes.last().expect("Route is never empty")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id() {
        let id = NodeId::new([42u8; 32]);
        assert_eq!(id.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn test_route_validation() {
        let node = MixNode {
            id: NodeId::new([1u8; 32]),
            public_key: [2u8; 32],
            address: "127.0.0.1:9000".into(),
            layer: 1,
        };

        // Empty route should fail
        assert!(Route::new(vec![]).is_err());

        // Single node should fail
        assert!(Route::new(vec![node.clone()]).is_err());

        // 3 nodes should succeed
        let route = Route::new(vec![node.clone(), node.clone(), node.clone()]);
        assert!(route.is_ok());
    }
}
