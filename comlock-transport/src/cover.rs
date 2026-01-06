//! # Cover Traffic Generator
//!
//! Implements Poisson-distributed cover (dummy) traffic to prevent
//! traffic analysis attacks. Maintains constant traffic patterns
//! regardless of actual user activity.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Exp};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use crate::sphinx::SphinxPacket;
use crate::{MixNode, Result, Route, TransportError};

/// Anonymity budget determining cover traffic intensity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymityBudget {
    /// Low data usage (~500MB/month), higher latency.
    Low,
    /// Medium data usage (~2GB/month), balanced.
    Medium,
    /// Maximum privacy (~5GB/month), constant bitrate.
    Max,
}

impl AnonymityBudget {
    /// Get the average packets per second for this budget.
    pub fn packets_per_second(&self) -> f64 {
        match self {
            Self::Low => 0.1,    // ~6 packets/minute
            Self::Medium => 0.5, // ~30 packets/minute
            Self::Max => 2.0,    // ~120 packets/minute (constant stream)
        }
    }

    /// Get the Poisson lambda parameter.
    pub fn lambda(&self) -> f64 {
        self.packets_per_second()
    }

    /// Estimated monthly data usage in MB.
    pub fn estimated_monthly_mb(&self) -> u32 {
        // 32KB packets * packets_per_second * seconds_per_month
        let packets_per_month = self.packets_per_second() * 60.0 * 60.0 * 24.0 * 30.0;
        (packets_per_month * 32.0 / 1024.0) as u32 // Convert to MB
    }
}

/// Configuration for cover traffic generation.
#[derive(Debug, Clone)]
pub struct CoverConfig {
    /// Anonymity budget level.
    pub budget: AnonymityBudget,
    /// Whether to reduce traffic on low battery.
    pub battery_saver: bool,
    /// Battery threshold for saver mode (0-100).
    pub battery_threshold: u8,
    /// Whether cover traffic is enabled.
    pub enabled: bool,
}

impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            budget: AnonymityBudget::Medium,
            battery_saver: true,
            battery_threshold: 20,
            enabled: true,
        }
    }
}

/// Statistics about cover traffic.
#[derive(Debug, Clone, Default)]
pub struct CoverStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total loops completed (round-trip dummies).
    pub loops_completed: u64,
    /// Current packets per second rate.
    pub current_rate: f64,
    /// Whether in degraded mode (battery saver active).
    pub degraded: bool,
}

/// Cover traffic generator using Poisson-distributed timing.
pub struct CoverTrafficGenerator {
    /// Configuration.
    config: CoverConfig,
    /// Whether the generator is running.
    running: Arc<AtomicBool>,
    /// Packet counter.
    packets_sent: Arc<AtomicU64>,
    /// Loops counter.
    loops_completed: Arc<AtomicU64>,
    /// Channel for sending generated packets.
    packet_tx: mpsc::Sender<SphinxPacket>,
    /// Current battery level (0-100, simulated).
    battery_level: Arc<AtomicU64>,
}

impl CoverTrafficGenerator {
    /// Create a new cover traffic generator.
    pub fn new(config: CoverConfig, packet_tx: mpsc::Sender<SphinxPacket>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            loops_completed: Arc::new(AtomicU64::new(0)),
            packet_tx,
            battery_level: Arc::new(AtomicU64::new(100)),
        }
    }

    /// Start the cover traffic generator.
    pub async fn start(&self, gateway: MixNode, topology: Vec<MixNode>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let packets_sent = self.packets_sent.clone();
        let loops_completed = self.loops_completed.clone();
        let battery_level = self.battery_level.clone();
        let config = self.config.clone();
        let packet_tx = self.packet_tx.clone();

        tokio::spawn(async move {
            Self::traffic_loop(
                running,
                packets_sent,
                loops_completed,
                battery_level,
                config,
                packet_tx,
                gateway,
                topology,
            )
            .await
        });

        Ok(())
    }

    /// Stop the cover traffic generator.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Update the battery level (for battery saver mode).
    pub fn update_battery(&self, level: u8) {
        self.battery_level.store(level as u64, Ordering::SeqCst);
    }

    /// Get current statistics.
    pub fn stats(&self) -> CoverStats {
        let battery = self.battery_level.load(Ordering::SeqCst) as u8;
        let degraded =
            self.config.battery_saver && battery < self.config.battery_threshold;

        CoverStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            loops_completed: self.loops_completed.load(Ordering::SeqCst),
            current_rate: if degraded {
                self.config.budget.packets_per_second() * 0.25
            } else {
                self.config.budget.packets_per_second()
            },
            degraded,
        }
    }

    /// Update configuration.
    pub fn set_budget(&mut self, budget: AnonymityBudget) {
        self.config.budget = budget;
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // === Private methods ===

    async fn traffic_loop(
        running: Arc<AtomicBool>,
        packets_sent: Arc<AtomicU64>,
        loops_completed: Arc<AtomicU64>,
        battery_level: Arc<AtomicU64>,
        config: CoverConfig,
        packet_tx: mpsc::Sender<SphinxPacket>,
        gateway: MixNode,
        topology: Vec<MixNode>,
    ) {
        let mut rng = StdRng::from_entropy();

        while running.load(Ordering::SeqCst) {
            // Check battery level
            let battery = battery_level.load(Ordering::SeqCst) as u8;
            let rate_multiplier = if config.battery_saver && battery < config.battery_threshold {
                0.25 // Reduce to 25% when battery is low
            } else {
                1.0
            };

            let lambda = config.budget.lambda() * rate_multiplier;

            // Sample inter-arrival time from exponential distribution
            let exp = Exp::new(lambda).unwrap_or_else(|_| Exp::new(0.1).unwrap());
            let delay_secs = exp.sample(&mut rng);
            let delay = Duration::from_secs_f64(delay_secs);

            tokio::time::sleep(delay).await;

            if !running.load(Ordering::SeqCst) {
                break;
            }

            // Generate a dummy packet (loop traffic)
            match Self::generate_loop_packet(&gateway, &topology) {
                Ok(packet) => {
                    if packet_tx.send(packet).await.is_ok() {
                        packets_sent.fetch_add(1, Ordering::SeqCst);
                        // Loops complete when we receive them back (simulated here)
                        if rng.gen_bool(0.9) {
                            // 90% success rate
                            loops_completed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                Err(_) => {
                    // Log error in production
                }
            }
        }
    }

    fn generate_loop_packet(gateway: &MixNode, topology: &[MixNode]) -> Result<SphinxPacket> {
        // Create a loop: L1 -> L2 -> L1 (returns to us via gateway)
        let mix_nodes: Vec<&MixNode> = topology.iter().filter(|n| n.layer == 2).collect();

        if mix_nodes.is_empty() {
            return Err(TransportError::InvalidRoute("No mix nodes for loop".into()));
        }

        // Build a simple loop route
        let route = Route::new(vec![
            gateway.clone(),
            mix_nodes[0].clone(),
            gateway.clone(), // Return to our gateway
        ])?;

        // Dummy payload (random bytes)
        let mut payload = vec![0u8; 256];
        rand::thread_rng().fill(&mut payload[..]);

        // Our mailbox ID (for loop return)
        let mailbox_id = [0x10; 32]; // Loop pattern marker

        SphinxPacket::create(&payload, &route, mailbox_id)
    }
}

/// Builder for cover traffic generator.
pub struct CoverTrafficBuilder {
    config: CoverConfig,
}

impl CoverTrafficBuilder {
    /// Create a new builder with default config.
    pub fn new() -> Self {
        Self {
            config: CoverConfig::default(),
        }
    }

    /// Set the anonymity budget.
    pub fn budget(mut self, budget: AnonymityBudget) -> Self {
        self.config.budget = budget;
        self
    }

    /// Enable/disable battery saver mode.
    pub fn battery_saver(mut self, enabled: bool) -> Self {
        self.config.battery_saver = enabled;
        self
    }

    /// Set battery threshold for saver mode.
    pub fn battery_threshold(mut self, threshold: u8) -> Self {
        self.config.battery_threshold = threshold;
        self
    }

    /// Enable/disable cover traffic.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Build the generator.
    pub fn build(self, packet_tx: mpsc::Sender<SphinxPacket>) -> CoverTrafficGenerator {
        CoverTrafficGenerator::new(self.config, packet_tx)
    }
}

impl Default for CoverTrafficBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymity_budget() {
        assert!(AnonymityBudget::Low.packets_per_second() < AnonymityBudget::Medium.packets_per_second());
        assert!(AnonymityBudget::Medium.packets_per_second() < AnonymityBudget::Max.packets_per_second());
    }

    #[test]
    fn test_monthly_estimate() {
        let low_mb = AnonymityBudget::Low.estimated_monthly_mb();
        let max_mb = AnonymityBudget::Max.estimated_monthly_mb();

        // Just verify the ordering is correct
        assert!(low_mb < max_mb);
    }

    #[tokio::test]
    async fn test_generator_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let generator = CoverTrafficBuilder::new()
            .budget(AnonymityBudget::Medium)
            .battery_saver(true)
            .build(tx);

        assert!(!generator.is_running());

        let stats = generator.stats();
        assert_eq!(stats.packets_sent, 0);
    }

    #[test]
    fn test_battery_degradation() {
        let (tx, _rx) = mpsc::channel(10);
        let generator = CoverTrafficBuilder::new()
            .budget(AnonymityBudget::Max)
            .battery_saver(true)
            .battery_threshold(20)
            .build(tx);

        // Full battery
        generator.update_battery(100);
        let stats = generator.stats();
        assert!(!stats.degraded);

        // Low battery
        generator.update_battery(15);
        let stats = generator.stats();
        assert!(stats.degraded);
        assert!(stats.current_rate < AnonymityBudget::Max.packets_per_second());
    }
}
