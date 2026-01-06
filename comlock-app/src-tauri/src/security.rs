//! Security Module for ComLock
//!
//! Implements panic-layer security features including:
//! - Duress PIN (triggers silent wipe and decoy mode)
//! - Dead Man's Switch (auto-wipe after inactivity)
//! - Secure deletion with memory zeroization

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// SECURITY CONFIGURATION
// ============================================================================

/// Security configuration stored encrypted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// SHA-256 hash of the normal unlock PIN
    #[serde(with = "option_hex_32")]
    pub pin_hash: Option<[u8; 32]>,
    /// SHA-256 hash of the duress PIN (triggers wipe)
    #[serde(with = "option_hex_32")]
    pub duress_pin_hash: Option<[u8; 32]>,
    /// Days until auto-wipe (0 = disabled)
    pub dead_man_days: u32,
    /// Last time the app was accessed (Unix timestamp)
    pub last_accessed: i64,
    /// Whether panic gesture (3-finger long press) is enabled
    pub panic_gesture_enabled: bool,
    /// Number of failed PIN attempts
    pub failed_attempts: u32,
    /// Max failed attempts before wipe (0 = unlimited)
    pub max_failed_attempts: u32,
    /// Whether security is enabled at all
    pub security_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pin_hash: None,
            duress_pin_hash: None,
            dead_man_days: 0,
            last_accessed: current_timestamp(),
            panic_gesture_enabled: true,
            failed_attempts: 0,
            max_failed_attempts: 10,
            security_enabled: false,
        }
    }
}

impl SecurityConfig {
    /// Check if dead man's switch has triggered
    pub fn is_dead_man_triggered(&self) -> bool {
        if self.dead_man_days == 0 {
            return false;
        }

        let now = current_timestamp();
        let days_since_access = (now - self.last_accessed) / 86400;
        days_since_access >= self.dead_man_days as i64
    }

    /// Update last accessed timestamp
    pub fn update_access(&mut self) {
        self.last_accessed = current_timestamp();
        self.failed_attempts = 0;
    }

    /// Record a failed PIN attempt
    pub fn record_failed_attempt(&mut self) -> bool {
        self.failed_attempts += 1;
        if self.max_failed_attempts > 0 && self.failed_attempts >= self.max_failed_attempts {
            return true; // Should trigger wipe
        }
        false
    }
}

// ============================================================================
// PIN VERIFICATION
// ============================================================================

/// Result of PIN verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinResult {
    /// Correct normal PIN - proceed to app
    Normal,
    /// Duress PIN entered - trigger silent wipe
    Duress,
    /// Wrong PIN - increment failure counter
    Invalid,
    /// No PIN is set - proceed to app
    NoPinSet,
    /// Too many failed attempts - trigger wipe
    MaxAttemptsExceeded,
}

/// Sensitive PIN holder that zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pin(String);

impl Pin {
    pub fn new(pin: String) -> Self {
        Self(pin)
    }

    /// Hash the PIN using SHA-256 with salt
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"COMLOCK_PIN_SALT_V1");
        hasher.update(self.0.as_bytes());
        hasher.finalize().into()
    }

    /// Constant-time comparison of PIN hash
    pub fn verify(&self, expected_hash: &[u8; 32]) -> bool {
        let hash = self.hash();
        constant_time_eq(&hash, expected_hash)
    }
}

/// Verify a PIN against the security config
pub fn verify_pin(pin: &str, config: &SecurityConfig) -> PinResult {
    // If security is not enabled, allow access
    if !config.security_enabled {
        return PinResult::NoPinSet;
    }

    // Check if max attempts exceeded
    if config.max_failed_attempts > 0 && config.failed_attempts >= config.max_failed_attempts {
        return PinResult::MaxAttemptsExceeded;
    }

    let pin = Pin::new(pin.to_string());

    // Check duress PIN first (if set)
    if let Some(duress_hash) = &config.duress_pin_hash {
        if pin.verify(duress_hash) {
            return PinResult::Duress;
        }
    }

    // Check normal PIN
    if let Some(pin_hash) = &config.pin_hash {
        if pin.verify(pin_hash) {
            return PinResult::Normal;
        }
    } else {
        // No PIN set but security enabled means we just need any PIN
        return PinResult::NoPinSet;
    }

    PinResult::Invalid
}

/// Set the normal unlock PIN
pub fn set_pin(pin: &str) -> [u8; 32] {
    let pin = Pin::new(pin.to_string());
    pin.hash()
}

/// Set the duress PIN (must be different from normal PIN)
pub fn set_duress_pin(pin: &str, normal_pin_hash: &[u8; 32]) -> Option<[u8; 32]> {
    let pin = Pin::new(pin.to_string());
    let hash = pin.hash();

    // Ensure duress PIN is different from normal PIN
    if constant_time_eq(&hash, normal_pin_hash) {
        return None;
    }

    Some(hash)
}

// ============================================================================
// WIPE FUNCTIONALITY
// ============================================================================

/// Wipe state tracking
#[derive(Debug, Clone, Default)]
pub struct WipeState {
    /// Whether a wipe has been triggered
    pub wiped: bool,
    /// Reason for wipe
    pub reason: WipeReason,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WipeReason {
    #[default]
    NotWiped,
    DuressPin,
    DeadManSwitch,
    MaxAttempts,
    PanicGesture,
    ManualWipe,
}

impl WipeState {
    /// Trigger a wipe with the given reason
    pub fn trigger(&mut self, reason: WipeReason) {
        self.wiped = true;
        self.reason = reason;
    }

    /// Check if app should show decoy
    pub fn should_show_decoy(&self) -> bool {
        self.wiped
    }
}

/// Secure deletion helper - overwrites memory with zeros
pub fn secure_zeroize<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

// ============================================================================
// DEAD MAN'S SWITCH
// ============================================================================

/// Calculate days until dead man's switch triggers
pub fn days_until_wipe(config: &SecurityConfig) -> Option<i64> {
    if config.dead_man_days == 0 {
        return None;
    }

    let now = current_timestamp();
    let days_since = (now - config.last_accessed) / 86400;
    let days_left = config.dead_man_days as i64 - days_since;

    Some(days_left.max(0))
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Constant-time byte comparison
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Generate a random salt
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

// Custom serde for Option<[u8; 32]>
mod option_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid length"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_hashing_deterministic() {
        let pin1 = Pin::new("1234".to_string());
        let pin2 = Pin::new("1234".to_string());

        assert_eq!(pin1.hash(), pin2.hash());
    }

    #[test]
    fn test_pin_hashing_different_pins() {
        let pin1 = Pin::new("1234".to_string());
        let pin2 = Pin::new("5678".to_string());

        assert_ne!(pin1.hash(), pin2.hash());
    }

    #[test]
    fn test_pin_verification() {
        let pin = Pin::new("1234".to_string());
        let hash = pin.hash();

        let pin_verify = Pin::new("1234".to_string());
        assert!(pin_verify.verify(&hash));

        let wrong_pin = Pin::new("wrong".to_string());
        assert!(!wrong_pin.verify(&hash));
    }

    #[test]
    fn test_verify_pin_normal() {
        let mut config = SecurityConfig::default();
        config.security_enabled = true;
        config.pin_hash = Some(set_pin("1234"));

        assert_eq!(verify_pin("1234", &config), PinResult::Normal);
        assert_eq!(verify_pin("wrong", &config), PinResult::Invalid);
    }

    #[test]
    fn test_verify_pin_duress() {
        let mut config = SecurityConfig::default();
        config.security_enabled = true;
        config.pin_hash = Some(set_pin("1234"));
        config.duress_pin_hash = set_duress_pin("9999", &config.pin_hash.unwrap());

        assert_eq!(verify_pin("1234", &config), PinResult::Normal);
        assert_eq!(verify_pin("9999", &config), PinResult::Duress);
        assert_eq!(verify_pin("wrong", &config), PinResult::Invalid);
    }

    #[test]
    fn test_duress_pin_must_be_different() {
        let normal_hash = set_pin("1234");

        // Same PIN should fail
        assert!(set_duress_pin("1234", &normal_hash).is_none());

        // Different PIN should succeed
        assert!(set_duress_pin("5678", &normal_hash).is_some());
    }

    #[test]
    fn test_dead_man_switch_disabled() {
        let config = SecurityConfig {
            dead_man_days: 0,
            last_accessed: current_timestamp() - 100 * 86400, // 100 days ago
            ..Default::default()
        };

        assert!(!config.is_dead_man_triggered());
    }

    #[test]
    fn test_dead_man_switch_not_triggered() {
        let config = SecurityConfig {
            dead_man_days: 7,
            last_accessed: current_timestamp() - 3 * 86400, // 3 days ago
            ..Default::default()
        };

        assert!(!config.is_dead_man_triggered());
    }

    #[test]
    fn test_dead_man_switch_triggered() {
        let config = SecurityConfig {
            dead_man_days: 7,
            last_accessed: current_timestamp() - 10 * 86400, // 10 days ago
            ..Default::default()
        };

        assert!(config.is_dead_man_triggered());
    }

    #[test]
    fn test_failed_attempts() {
        let mut config = SecurityConfig {
            max_failed_attempts: 3,
            ..Default::default()
        };

        assert!(!config.record_failed_attempt()); // 1
        assert!(!config.record_failed_attempt()); // 2
        assert!(config.record_failed_attempt()); // 3 - should trigger wipe
    }

    #[test]
    fn test_days_until_wipe() {
        let config = SecurityConfig {
            dead_man_days: 7,
            last_accessed: current_timestamp() - 3 * 86400,
            ..Default::default()
        };

        let days = days_until_wipe(&config);
        assert_eq!(days, Some(4));
    }

    #[test]
    fn test_wipe_state() {
        let mut state = WipeState::default();

        assert!(!state.should_show_decoy());

        state.trigger(WipeReason::DuressPin);

        assert!(state.should_show_decoy());
        assert_eq!(state.reason, WipeReason::DuressPin);
    }
}
