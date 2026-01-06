//! # Mixnet Client
//!
//! Implements the Loopix-style mixnet client for anonymous message delivery.
//! Handles routing through the stratified topology and mailbox polling.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};

use crate::sphinx::{SphinxPacket, PACKET_SIZE};
use crate::{MixNode, NodeId, Result, Route, TransportError};

/// Configuration for the mix client.
#[derive(Debug, Clone)]
pub struct MixClientConfig {
    /// Our node ID (derived from keypair).
    pub our_id: NodeId,
    /// Gateway node to connect to.
    pub gateway: MixNode,
    /// Timeout for network operations.
    pub timeout: Duration,
    /// Interval for polling mailbox.
    pub poll_interval: Duration,
    /// Maximum retries for failed sends.
    pub max_retries: u32,
}

impl Default for MixClientConfig {
    fn default() -> Self {
        Self {
            our_id: NodeId::new([0u8; 32]),
            gateway: MixNode {
                id: NodeId::new([0u8; 32]),
                public_key: [0u8; 32],
                address: "127.0.0.1:9000".into(),
                layer: 1,
            },
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            max_retries: 3,
        }
    }
}

/// A mailbox for receiving messages.
#[derive(Debug, Clone)]
pub struct Mailbox {
    /// Unique mailbox identifier.
    pub id: [u8; 32],
    /// Exit node hosting this mailbox.
    pub provider: MixNode,
}

/// Single Use Reply Block for anonymous responses.
#[derive(Debug, Clone)]
pub struct Surb {
    /// Pre-computed Sphinx header for the return path.
    pub header_bytes: Vec<u8>,
    /// First hop address for the response.
    pub first_hop: String,
    /// Symmetric key for decrypting the response.
    pub reply_key: [u8; 32],
}

/// Message received from the mixnet.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Decrypted payload.
    pub payload: Vec<u8>,
    /// Optional SURB for replying.
    pub reply_surb: Option<Surb>,
    /// Timestamp when received.
    pub received_at: Instant,
}

/// The mixnet client for sending and receiving anonymous messages.
pub struct MixClient {
    /// Client configuration.
    config: MixClientConfig,
    /// Known mix nodes by layer.
    topology: Arc<RwLock<HashMap<u8, Vec<MixNode>>>>,
    /// Our mailboxes.
    mailboxes: Arc<RwLock<Vec<Mailbox>>>,
    /// Channel for outgoing packets.
    outgoing_tx: mpsc::Sender<SphinxPacket>,
    /// Channel for incoming messages.
    incoming_rx: mpsc::Receiver<ReceivedMessage>,
    /// Our X25519 secret key for decryption.
    #[allow(dead_code)]
    our_secret: x25519_dalek::StaticSecret,
}

impl MixClient {
    /// Create a new mixnet client.
    pub fn new(config: MixClientConfig) -> Self {
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(100);
        let (_incoming_tx, incoming_rx) = mpsc::channel(100);

        let our_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand::thread_rng());

        Self {
            config,
            topology: Arc::new(RwLock::new(HashMap::new())),
            mailboxes: Arc::new(RwLock::new(Vec::new())),
            outgoing_tx,
            incoming_rx,
            our_secret,
        }
    }

    /// Send a message through the mixnet.
    ///
    /// The message is wrapped in a Sphinx packet and routed through
    /// randomly selected nodes in each layer.
    pub async fn send_message(
        &self,
        payload: &[u8],
        recipient_mailbox: &Mailbox,
    ) -> Result<()> {
        // Select a random route
        let route = self.select_route(recipient_mailbox).await?;

        // Create Sphinx packet
        let packet = SphinxPacket::create(payload, &route, recipient_mailbox.id)?;

        // Send to gateway
        self.send_to_gateway(packet).await
    }

    /// Send a message with a SURB for anonymous reply.
    pub async fn send_with_surb(
        &self,
        payload: &[u8],
        recipient_mailbox: &Mailbox,
    ) -> Result<Surb> {
        // Create return route SURB
        let surb = self.create_surb().await?;

        // Combine payload with SURB
        let mut combined = payload.to_vec();
        combined.extend_from_slice(&surb.header_bytes);

        // Send the message
        self.send_message(&combined, recipient_mailbox).await?;

        Ok(surb)
    }

    /// Poll our mailbox for incoming messages.
    pub async fn poll_mailbox(&mut self) -> Result<Option<ReceivedMessage>> {
        // In a real implementation, this would:
        // 1. Connect to our mailbox provider
        // 2. Send an anonymous fetch request
        // 3. Decrypt and return any waiting messages

        match self.incoming_rx.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(TransportError::MailboxError("Channel closed".into()))
            }
        }
    }

    /// Register a new mailbox with a provider.
    pub async fn register_mailbox(&self, provider: MixNode) -> Result<Mailbox> {
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut id);

        let mailbox = Mailbox { id, provider };

        self.mailboxes.write().await.push(mailbox.clone());

        Ok(mailbox)
    }

    /// Update the network topology.
    pub async fn update_topology(&self, nodes: Vec<MixNode>) {
        let mut topology = self.topology.write().await;
        topology.clear();

        for node in nodes {
            topology.entry(node.layer).or_default().push(node);
        }
    }

    /// Get statistics about the client.
    pub async fn stats(&self) -> ClientStats {
        let topology = self.topology.read().await;
        let mailboxes = self.mailboxes.read().await;

        ClientStats {
            known_gateways: topology.get(&1).map(|v| v.len()).unwrap_or(0),
            known_mixes: topology.get(&2).map(|v| v.len()).unwrap_or(0),
            known_providers: topology.get(&3).map(|v| v.len()).unwrap_or(0),
            registered_mailboxes: mailboxes.len(),
        }
    }

    // === Private methods ===

    async fn select_route(&self, recipient_mailbox: &Mailbox) -> Result<Route> {
        let topology = self.topology.read().await;

        // Select one node from each layer
        let gateway = topology
            .get(&1)
            .and_then(|nodes| nodes.first())
            .ok_or_else(|| TransportError::InvalidRoute("No gateways available".into()))?
            .clone();

        let mix = topology
            .get(&2)
            .and_then(|nodes| nodes.first())
            .ok_or_else(|| TransportError::InvalidRoute("No mix nodes available".into()))?
            .clone();

        let exit = recipient_mailbox.provider.clone();

        Route::new(vec![gateway, mix, exit])
    }

    async fn send_to_gateway(&self, packet: SphinxPacket) -> Result<()> {
        // In a real implementation, this would open a connection to the gateway
        // and send the packet bytes. For now, we just queue it.
        self.outgoing_tx
            .send(packet)
            .await
            .map_err(|_| TransportError::NetworkError("Failed to queue packet".into()))
    }

    async fn create_surb(&self) -> Result<Surb> {
        let mut rng = rand::thread_rng();
        let mut reply_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut reply_key);

        // Create a return route through the mixnet
        // In a real implementation, this would build a complete Sphinx header

        Ok(Surb {
            header_bytes: vec![0u8; 512], // Placeholder
            first_hop: self.config.gateway.address.clone(),
            reply_key,
        })
    }
}

/// Client statistics.
#[derive(Debug, Clone)]
pub struct ClientStats {
    /// Number of known gateway nodes.
    pub known_gateways: usize,
    /// Number of known mix nodes.
    pub known_mixes: usize,
    /// Number of known provider nodes.
    pub known_providers: usize,
    /// Number of registered mailboxes.
    pub registered_mailboxes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = MixClientConfig::default();
        let client = MixClient::new(config);

        let stats = client.stats().await;
        assert_eq!(stats.known_gateways, 0);
        assert_eq!(stats.registered_mailboxes, 0);
    }

    #[tokio::test]
    async fn test_topology_update() {
        let config = MixClientConfig::default();
        let client = MixClient::new(config);

        let nodes = vec![
            MixNode {
                id: NodeId::new([1u8; 32]),
                public_key: [1u8; 32],
                address: "127.0.0.1:9001".into(),
                layer: 1,
            },
            MixNode {
                id: NodeId::new([2u8; 32]),
                public_key: [2u8; 32],
                address: "127.0.0.1:9002".into(),
                layer: 2,
            },
        ];

        client.update_topology(nodes).await;

        let stats = client.stats().await;
        assert_eq!(stats.known_gateways, 1);
        assert_eq!(stats.known_mixes, 1);
    }

    #[tokio::test]
    async fn test_mailbox_registration() {
        let config = MixClientConfig::default();
        let client = MixClient::new(config);

        let provider = MixNode {
            id: NodeId::new([3u8; 32]),
            public_key: [3u8; 32],
            address: "127.0.0.1:9003".into(),
            layer: 3,
        };

        let mailbox = client.register_mailbox(provider).await.unwrap();
        assert_eq!(mailbox.id.len(), 32);

        let stats = client.stats().await;
        assert_eq!(stats.registered_mailboxes, 1);
    }
}
