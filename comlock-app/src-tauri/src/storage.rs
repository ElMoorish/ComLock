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

    /// Derive encryption key from PIN using Argon2id
    fn derive_key(pin: &str) -> [u8; 32] {
        use argon2::Argon2;

        // Fixed salt for deterministic key derivation
        // Note: In production, consider using random salts stored with ciphertext
        let salt = b"comlock_storage_salt_v2!";

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(pin.as_bytes(), salt, &mut key)
            .expect("Argon2 hashing failed");
        key
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
        // Get app data directory from config path
        let app_dir = self.config_path.parent();

        // Delete config file securely
        if self.config_path.exists() {
            self.secure_delete()?;
        }

        // Delete other sensitive files in app directory
        if let Some(dir) = app_dir {
            // Securely delete contacts database
            let contacts_file = dir.join("contacts.db");
            if contacts_file.exists() {
                Self::secure_delete_file(&contacts_file)?;
            }

            // Securely delete message cache
            let messages_file = dir.join("messages.cache");
            if messages_file.exists() {
                Self::secure_delete_file(&messages_file)?;
            }

            // Securely delete key material
            let keys_file = dir.join("keys.enc");
            if keys_file.exists() {
                Self::secure_delete_file(&keys_file)?;
            }

            // Delete identity file
            let identity_file = dir.join("identity.enc");
            if identity_file.exists() {
                Self::secure_delete_file(&identity_file)?;
            }

            // Delete mailbox credentials
            let mailbox_file = dir.join("mailbox.enc");
            if mailbox_file.exists() {
                Self::secure_delete_file(&mailbox_file)?;
            }
        }

        Ok(())
    }

    /// Securely delete a specific file by overwriting with zeros
    fn secure_delete_file(path: &std::path::Path) -> Result<(), StorageError> {
        use std::fs::{File, OpenOptions};
        use std::io::Write;

        if let Ok(metadata) = std::fs::metadata(path) {
            let size = metadata.len() as usize;
            // Overwrite with zeros
            if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; size];
                let _ = file.write_all(&zeros);
                let _ = file.sync_all();
            }
        }

        // Delete the file
        std::fs::remove_file(path).map_err(|_| StorageError::IoError)?;
        Ok(())
    }

    // ========================================================================
    // ENCRYPTED CONTACT PERSISTENCE (Optional)
    // ========================================================================

    /// Save contacts encrypted with PIN (optional persistence)
    pub fn save_contacts(
        &self,
        contacts: &[crate::contacts::Contact],
        pin: &str,
    ) -> Result<(), StorageError> {
        let contacts_path = self
            .config_path
            .parent()
            .map(|p| p.join("contacts.enc"))
            .ok_or(StorageError::IoError)?;

        let json =
            serde_json::to_string(contacts).map_err(|_| StorageError::SerializationFailed)?;

        let key = Self::derive_key(pin);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|_| StorageError::EncryptionFailed)?;

        let mut file = File::create(&contacts_path).map_err(|_| StorageError::IoError)?;
        file.write_all(&nonce_bytes)
            .map_err(|_| StorageError::IoError)?;
        file.write_all(&ciphertext)
            .map_err(|_| StorageError::IoError)?;

        Ok(())
    }

    /// Load and decrypt contacts
    pub fn load_contacts(&self, pin: &str) -> Result<Vec<crate::contacts::Contact>, StorageError> {
        let contacts_path = self
            .config_path
            .parent()
            .map(|p| p.join("contacts.enc"))
            .ok_or(StorageError::IoError)?;

        if !contacts_path.exists() {
            return Ok(Vec::new()); // No saved contacts
        }

        let mut data = Vec::new();
        File::open(&contacts_path)
            .map_err(|_| StorageError::NotFound)?
            .read_to_end(&mut data)
            .map_err(|_| StorageError::IoError)?;

        if data.len() < 12 {
            return Err(StorageError::CorruptedData);
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Self::derive_key(pin);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::DecryptionFailed)?;
        let json = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)?;

        let contacts: Vec<crate::contacts::Contact> =
            serde_json::from_slice(&json).map_err(|_| StorageError::CorruptedData)?;

        Ok(contacts)
    }

    /// Delete contacts file securely
    pub fn delete_contacts(&self) -> Result<(), StorageError> {
        let contacts_path = self
            .config_path
            .parent()
            .map(|p| p.join("contacts.enc"))
            .ok_or(StorageError::IoError)?;

        if contacts_path.exists() {
            Self::secure_delete_file(&contacts_path)?;
        }
        Ok(())
    }

    // ========================================================================
    // SECURE IDENTITY STORAGE
    // ========================================================================

    /// Save identity encrypted with PIN
    pub fn save_identity(&self, identity: &crate::Identity, pin: &str) -> Result<(), StorageError> {
        let identity_path = self
            .config_path
            .parent()
            .map(|p| p.join("identity.enc"))
            .ok_or(StorageError::IoError)?;

        let json =
            serde_json::to_string(identity).map_err(|_| StorageError::SerializationFailed)?;

        let key = Self::derive_key(pin);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|_| StorageError::EncryptionFailed)?;

        let mut file = File::create(&identity_path).map_err(|_| StorageError::IoError)?;
        file.write_all(&nonce_bytes)
            .map_err(|_| StorageError::IoError)?;
        file.write_all(&ciphertext)
            .map_err(|_| StorageError::IoError)?;

        Ok(())
    }

    /// Load and decrypt identity
    pub fn load_identity(&self, pin: &str) -> Result<Option<crate::Identity>, StorageError> {
        let identity_path = self
            .config_path
            .parent()
            .map(|p| p.join("identity.enc"))
            .ok_or(StorageError::IoError)?;

        if !identity_path.exists() {
            return Ok(None); // No saved identity
        }

        let mut data = Vec::new();
        File::open(&identity_path)
            .map_err(|_| StorageError::NotFound)?
            .read_to_end(&mut data)
            .map_err(|_| StorageError::IoError)?;

        if data.len() < 12 {
            return Err(StorageError::CorruptedData);
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Self::derive_key(pin);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::DecryptionFailed)?;
        let json = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)?;

        let identity: crate::Identity =
            serde_json::from_slice(&json).map_err(|_| StorageError::CorruptedData)?;

        Ok(Some(identity))
    }

    /// Check if identity file exists
    pub fn has_saved_identity(&self) -> bool {
        self.config_path
            .parent()
            .map(|p| p.join("identity.enc").exists())
            .unwrap_or(false)
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
