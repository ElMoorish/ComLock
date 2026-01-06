//! Secure Storage for ComLock
//!
//! Encrypted local storage for security configuration.
//! Uses AES-256-GCM for encryption with PIN-derived key.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::security::SecurityConfig;

// ============================================================================
// SECURE STORAGE
// ============================================================================

/// Encrypted storage for security configuration
pub struct SecureStorage {
    /// Path to the config file
    config_path: PathBuf,
}

impl SecureStorage {
    /// Create a new secure storage instance
    pub fn new(app_data_dir: PathBuf) -> Self {
        let config_path = app_data_dir.join("security.enc");
        Self { config_path }
    }

    /// Derive encryption key from PIN
    fn derive_key(pin: &str) -> [u8; 32] {
        // Use PBKDF2 or Argon2 in production
        // For now, use salted SHA-256
        let mut hasher = Sha256::new();
        hasher.update(b"COMLOCK_STORAGE_KEY_V1");
        hasher.update(pin.as_bytes());
        hasher.update(b"COMLOCK_STORAGE_KEY_V1");
        hasher.finalize().into()
    }

    /// Save security config encrypted with PIN
    pub fn save_config(&self, config: &SecurityConfig, pin: &str) -> Result<(), StorageError> {
        // Serialize config to JSON
        let json = serde_json::to_string(config).map_err(|_| StorageError::SerializationFailed)?;

        // Derive encryption key
        let key = Self::derive_key(pin);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|_| StorageError::EncryptionFailed)?;

        // Write: nonce (12 bytes) + ciphertext
        let mut file = File::create(&self.config_path).map_err(|_| StorageError::IoError)?;
        file.write_all(&nonce_bytes)
            .map_err(|_| StorageError::IoError)?;
        file.write_all(&ciphertext)
            .map_err(|_| StorageError::IoError)?;

        Ok(())
    }

    /// Load and decrypt security config
    pub fn load_config(&self, pin: &str) -> Result<SecurityConfig, StorageError> {
        // Read file
        let mut file = File::open(&self.config_path).map_err(|_| StorageError::NotFound)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|_| StorageError::IoError)?;

        if data.len() < 12 {
            return Err(StorageError::CorruptedData);
        }

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        // Derive key and decrypt
        let key = Self::derive_key(pin);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)?;

        // Deserialize
        let json = String::from_utf8(plaintext).map_err(|_| StorageError::CorruptedData)?;
        serde_json::from_str(&json).map_err(|_| StorageError::CorruptedData)
    }

    /// Check if config file exists
    pub fn config_exists(&self) -> bool {
        self.config_path.exists()
    }

    /// Securely delete the config file
    pub fn secure_delete(&self) -> Result<(), StorageError> {
        if !self.config_path.exists() {
            return Ok(());
        }

        // Overwrite with random data
        if let Ok(metadata) = fs::metadata(&self.config_path) {
            let size = metadata.len() as usize;
            let mut random_data = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut random_data);

            if let Ok(mut file) = File::create(&self.config_path) {
                let _ = file.write_all(&random_data);
                let _ = file.sync_all();
            }

            // Overwrite with zeros
            let zeros = vec![0u8; size];
            if let Ok(mut file) = File::create(&self.config_path) {
                let _ = file.write_all(&zeros);
                let _ = file.sync_all();
            }
        }

        // Delete the file
        fs::remove_file(&self.config_path).map_err(|_| StorageError::IoError)?;

        Ok(())
    }

    /// Delete all app data securely
    pub fn wipe_all_data(&self) -> Result<(), StorageError> {
        // Delete config
        self.secure_delete()?;

        // In production, also delete:
        // - Contact database
        // - Message cache
        // - Key material
        // - Any other sensitive files

        Ok(())
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum StorageError {
    NotFound,
    IoError,
    SerializationFailed,
    EncryptionFailed,
    DecryptionFailed,
    CorruptedData,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "Config file not found"),
            StorageError::IoError => write!(f, "IO error"),
            StorageError::SerializationFailed => write!(f, "Serialization failed"),
            StorageError::EncryptionFailed => write!(f, "Encryption failed"),
            StorageError::DecryptionFailed => write!(f, "Decryption failed (wrong PIN?)"),
            StorageError::CorruptedData => write!(f, "Data corrupted"),
        }
    }
}

impl std::error::Error for StorageError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_storage() -> SecureStorage {
        let temp_dir = env::temp_dir().join(format!("comlock_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();
        SecureStorage::new(temp_dir)
    }

    #[test]
    fn test_save_and_load_config() {
        let storage = temp_storage();

        let config = SecurityConfig {
            security_enabled: true,
            dead_man_days: 7,
            ..Default::default()
        };

        storage.save_config(&config, "mypin").unwrap();

        let loaded = storage.load_config("mypin").unwrap();
        assert!(loaded.security_enabled);
        assert_eq!(loaded.dead_man_days, 7);

        // Cleanup
        let _ = storage.secure_delete();
    }

    #[test]
    fn test_wrong_pin_fails() {
        let storage = temp_storage();

        let config = SecurityConfig::default();
        storage.save_config(&config, "correctpin").unwrap();

        let result = storage.load_config("wrongpin");
        assert!(result.is_err());

        // Cleanup
        let _ = storage.secure_delete();
    }

    #[test]
    fn test_config_exists() {
        let storage = temp_storage();

        assert!(!storage.config_exists());

        let config = SecurityConfig::default();
        storage.save_config(&config, "pin").unwrap();

        assert!(storage.config_exists());

        // Cleanup
        let _ = storage.secure_delete();
    }

    #[test]
    fn test_secure_delete() {
        let storage = temp_storage();

        let config = SecurityConfig::default();
        storage.save_config(&config, "pin").unwrap();

        assert!(storage.config_exists());

        storage.secure_delete().unwrap();

        assert!(!storage.config_exists());
    }
}
