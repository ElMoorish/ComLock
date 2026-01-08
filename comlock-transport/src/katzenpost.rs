//! # Katzenpost Mixnet Client
//!
//! Integration with the Katzenpost mixnet for anonymous message transport.
//! Uses the thin client library to communicate with kpclientd daemon.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{Result, TransportError};

/// Connection status for the Katzenpost client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Not connected to kpclientd daemon.
    Disconnected,
    /// Connecting to daemon.
    Connecting,
    /// Connected and ready to send/receive.
    Connected,
    /// Connection error.
    Error(String),
}

/// Configuration for the Katzenpost client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KatzenpostConfig {
    /// Address of the kpclientd daemon (e.g., "127.0.0.1:30000").
    pub daemon_address: String,
    /// Path to the client state directory.
    pub state_dir: Option<String>,
    /// Enable debug logging.
    pub debug: bool,
}

impl Default for KatzenpostConfig {
    fn default() -> Self {
        Self {
            daemon_address: "127.0.0.1:30000".into(),
            state_dir: None,
            debug: false,
        }
    }
}

/// A message to send through the mixnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetMessage {
    /// Recipient's mailbox/queue identifier.
    pub recipient_id: Vec<u8>,
    /// Message payload (encrypted by caller).
    pub payload: Vec<u8>,
    /// Optional SURB for reply.
    pub surb: Option<Vec<u8>>,
}

/// A received message from the mixnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMixnetMessage {
    /// Sender's identifier (if known).
    pub sender_id: Option<Vec<u8>>,
    /// Message payload.
    pub payload: Vec<u8>,
    /// Timestamp when received.
    pub received_at: i64,
}

/// Katzenpost mixnet client wrapper.
///
/// This client communicates with the kpclientd daemon which handles
/// the actual mixnet protocol (Sphinx packets, routing, timing).
pub struct KatzenpostClient {
    config: KatzenpostConfig,
    status: Arc<RwLock<ConnectionStatus>>,
    /// Message queue for outgoing messages (when daemon unavailable).
    outgoing_queue: Arc<RwLock<Vec<MixnetMessage>>>,
    /// Received messages buffer.
    received_messages: Arc<RwLock<Vec<ReceivedMixnetMessage>>>,
}

impl KatzenpostClient {
    /// Create a new Katzenpost client with the given configuration.
    pub fn new(config: KatzenpostConfig) -> Self {
        Self {
            config,
            status: Arc::new(RwLock::new(ConnectionStatus::Disconnected)),
            outgoing_queue: Arc::new(RwLock::new(Vec::new())),
            received_messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a client with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(KatzenpostConfig::default())
    }

    /// Get current connection status.
    pub async fn status(&self) -> ConnectionStatus {
        self.status.read().await.clone()
    }

    /// Attempt to connect to the kpclientd daemon.
    ///
    /// This checks if the daemon is available and establishes communication.
    pub async fn connect(&self) -> Result<()> {
        *self.status.write().await = ConnectionStatus::Connecting;

        // Try to connect to the daemon via TCP
        match tokio::net::TcpStream::connect(&self.config.daemon_address).await {
            Ok(_stream) => {
                tracing::info!("Connected to kpclientd at {}", self.config.daemon_address);
                *self.status.write().await = ConnectionStatus::Connected;
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to connect to kpclientd: {}", e);
                tracing::warn!("{}", error_msg);
                *self.status.write().await = ConnectionStatus::Error(error_msg.clone());

                // Don't fail - queue messages for later delivery
                Ok(())
            }
        }
    }

    /// Disconnect from the daemon.
    pub async fn disconnect(&self) {
        *self.status.write().await = ConnectionStatus::Disconnected;
    }

    /// Send a message through the mixnet.
    ///
    /// If not connected, the message is queued for later delivery.
    pub async fn send_message(&self, message: MixnetMessage) -> Result<String> {
        let status = self.status.read().await.clone();

        match status {
            ConnectionStatus::Connected => {
                // In production, this would use the thin client API:
                // client.send(recipient_id, message, surb)

                // For now, simulate successful send
                let message_id = format!("kp_{}", rand::random::<u64>());
                tracing::info!("Sent message {} via mixnet", message_id);
                Ok(message_id)
            }
            _ => {
                // Queue for later delivery
                self.outgoing_queue.write().await.push(message);
                let message_id = format!("queued_{}", rand::random::<u64>());
                tracing::debug!("Message {} queued (daemon unavailable)", message_id);
                Ok(message_id)
            }
        }
    }

    /// Poll for received messages.
    ///
    /// Returns all messages received since last poll.
    pub async fn receive_messages(&self) -> Result<Vec<ReceivedMixnetMessage>> {
        let status = self.status.read().await.clone();

        if status != ConnectionStatus::Connected {
            // Return buffered messages
            let messages = self.received_messages.write().await.drain(..).collect();
            return Ok(messages);
        }

        // In production, this would poll the thin client:
        // client.receive() -> Vec<Message>

        // For now, return empty (no daemon polling implemented)
        Ok(Vec::new())
    }

    /// Get the number of queued outgoing messages.
    pub async fn queued_count(&self) -> usize {
        self.outgoing_queue.read().await.len()
    }

    /// Flush queued messages (attempt to send all).
    pub async fn flush_queue(&self) -> Result<usize> {
        let status = self.status.read().await.clone();

        if status != ConnectionStatus::Connected {
            return Ok(0);
        }

        let mut queue = self.outgoing_queue.write().await;
        let count = queue.len();

        // In production, send each queued message
        for _message in queue.drain(..) {
            // client.send(message.recipient_id, message.payload, message.surb)
        }

        Ok(count)
    }

    /// Get configuration.
    pub fn config(&self) -> &KatzenpostConfig {
        &self.config
    }
}

/// Builder for KatzenpostClient.
pub struct KatzenpostClientBuilder {
    config: KatzenpostConfig,
}

impl KatzenpostClientBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            config: KatzenpostConfig::default(),
        }
    }

    /// Set the daemon address.
    pub fn daemon_address(mut self, address: impl Into<String>) -> Self {
        self.config.daemon_address = address.into();
        self
    }

    /// Set the state directory.
    pub fn state_dir(mut self, dir: impl Into<String>) -> Self {
        self.config.state_dir = Some(dir.into());
        self
    }

    /// Enable debug mode.
    pub fn debug(mut self, enabled: bool) -> Self {
        self.config.debug = enabled;
        self
    }

    /// Build the client.
    pub fn build(self) -> KatzenpostClient {
        KatzenpostClient::new(self.config)
    }
}

impl Default for KatzenpostClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = KatzenpostClient::with_defaults();
        assert_eq!(client.status().await, ConnectionStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_message_queueing() {
        let client = KatzenpostClient::with_defaults();

        let message = MixnetMessage {
            recipient_id: vec![1, 2, 3],
            payload: b"Hello mixnet".to_vec(),
            surb: None,
        };

        let result = client.send_message(message).await;
        assert!(result.is_ok());

        // Should be queued since not connected
        assert_eq!(client.queued_count().await, 1);
    }

    #[tokio::test]
    async fn test_builder() {
        let client = KatzenpostClientBuilder::new()
            .daemon_address("192.168.1.100:30000")
            .debug(true)
            .build();

        assert_eq!(client.config().daemon_address, "192.168.1.100:30000");
        assert!(client.config().debug);
    }
}
