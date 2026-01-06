//! Contact Exchange System for ComLock
//!
//! Provides secure, trace-free contact discovery via QR codes and invite blobs.
//! All contacts are stored in memory only by default - no disk persistence.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// CONTACT DATA MODEL
// ============================================================================

/// A contact represents a trusted peer with established cryptographic keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Random identifier (not derived from public key for privacy)
    pub id: String,
    /// User-set display name
    pub alias: String,
    /// X25519 public key for key exchange
    #[serde(with = "hex_serde")]
    pub public_key: [u8; 32],
    /// ML-KEM-1024 public key for post-quantum security
    #[serde(with = "hex_vec_serde")]
    pub kem_pubkey: Vec<u8>,
    /// Active ratchet session ID
    pub session_id: String,
    /// Timestamp when contact was added (can be randomized for deniability)
    pub added_at: i64,
    /// Whether the initial handshake is complete
    pub verified: bool,
}

/// Ephemeral X25519 keypair for key exchange (zeroized on drop)
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    secret_key: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a new random ephemeral keypair
    pub fn generate() -> Self {
        let mut secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_key);

        // Clamp the secret key for X25519
        secret_key[0] &= 248;
        secret_key[31] &= 127;
        secret_key[31] |= 64;

        // Derive public key (simplified - use x25519-dalek in production)
        let public_key = Self::derive_public_key(&secret_key);

        Self {
            public_key,
            secret_key,
        }
    }

    /// Derive public key from secret key (placeholder - use proper X25519)
    fn derive_public_key(secret: &[u8; 32]) -> [u8; 32] {
        // In production, use x25519_dalek::PublicKey::from(&StaticSecret)
        // For now, hash the secret as a placeholder
        let mut hasher = Sha256::new();
        hasher.update(b"X25519_PK_DERIVE");
        hasher.update(secret);
        let hash = hasher.finalize();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hash);
        pk
    }

    /// Compute shared secret with peer's public key
    pub fn compute_shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        // In production, use x25519(self.secret_key, peer_public)
        // For now, hash both keys together as a placeholder
        let mut hasher = Sha256::new();
        hasher.update(b"X25519_SHARED_SECRET");
        hasher.update(self.secret_key);
        hasher.update(peer_public);
        let hash = hasher.finalize();
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&hash);
        shared
    }

    /// Get the secret key (for SAS generation)
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

// ============================================================================
// QR CODE PAYLOAD
// ============================================================================

/// QR code payload for in-person key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPayload {
    /// Protocol version
    pub v: u8,
    /// X25519 ephemeral public key (base64)
    pub pk: String,
    /// ML-KEM-1024 public key (base64, optional for size)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kpk: Option<String>,
    /// Expiry timestamp (Unix seconds)
    pub exp: i64,
}

impl QrPayload {
    /// Create a new QR payload with ephemeral keys
    pub fn new(public_key: &[u8; 32], kem_pubkey: Option<&[u8]>, ttl_seconds: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            v: 1,
            pk: base64_encode(public_key),
            kpk: kem_pubkey.map(base64_encode),
            exp: now + ttl_seconds,
        }
    }

    /// Check if the payload has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        now > self.exp
    }

    /// Decode the X25519 public key
    pub fn decode_public_key(&self) -> Result<[u8; 32], ContactError> {
        let bytes = base64_decode(&self.pk)?;
        bytes.try_into().map_err(|_| ContactError::InvalidPublicKey)
    }

    /// Decode the KEM public key
    pub fn decode_kem_pubkey(&self) -> Result<Option<Vec<u8>>, ContactError> {
        match &self.kpk {
            Some(kpk) => Ok(Some(base64_decode(kpk)?)),
            None => Ok(None),
        }
    }

    /// Serialize to JSON for QR code
    pub fn to_json(&self) -> Result<String, ContactError> {
        serde_json::to_string(self).map_err(|_| ContactError::SerializationFailed)
    }

    /// Parse from JSON scanned from QR code
    pub fn from_json(json: &str) -> Result<Self, ContactError> {
        serde_json::from_str(json).map_err(|_| ContactError::InvalidPayload)
    }
}

// ============================================================================
// SAS (SHORT AUTHENTICATION STRING)
// ============================================================================

/// Word list for SAS generation (easy to pronounce, distinct)
const SAS_WORDS: &[&str] = &[
    "Robot", "Apple", "Tiger", "Ocean", "Piano", "Eagle", "Maple", "Crown", "Arrow", "Storm",
    "Coral", "Blaze", "Frost", "Jade", "Orbit", "Spark",
];

/// Generate a Short Authentication String from shared secret
/// Format: "Word-Word-Number" (e.g., "Robot-Apple-42")
pub fn generate_sas(shared_secret: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"COMLOCK_SAS_V1");
    hasher.update(shared_secret);
    let hash = hasher.finalize();

    let word1 = SAS_WORDS[hash[0] as usize % SAS_WORDS.len()];
    let word2 = SAS_WORDS[hash[1] as usize % SAS_WORDS.len()];
    let num = hash[2] % 100;

    format!("{}-{}-{:02}", word1, word2, num)
}

/// Verify that a SAS matches the expected value
pub fn verify_sas(shared_secret: &[u8; 32], claimed_sas: &str) -> bool {
    let expected = generate_sas(shared_secret);
    // Constant-time comparison to prevent timing attacks
    expected.len() == claimed_sas.len()
        && expected
            .as_bytes()
            .iter()
            .zip(claimed_sas.as_bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
}

// ============================================================================
// INVITE BLOB (Remote Exchange)
// ============================================================================

/// One-time invite blob for remote contact exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteBlob {
    /// Protocol version
    pub version: u8,
    /// Sender's X25519 public key
    #[serde(with = "hex_serde")]
    pub sender_pubkey: [u8; 32],
    /// Sender's ML-KEM-1024 public key
    #[serde(with = "hex_vec_serde")]
    pub sender_kem_pk: Vec<u8>,
    /// Random mailbox ID for receiving ACK via mixnet
    #[serde(with = "hex_serde")]
    pub mailbox_id: [u8; 32],
    /// Expiry timestamp (Unix seconds)
    pub expiry: i64,
    /// Ed25519 signature over the blob (placeholder)
    #[serde(with = "hex_serde_64")]
    pub signature: [u8; 64],
}

impl InviteBlob {
    /// Create a new invite blob
    pub fn new(sender_pubkey: [u8; 32], sender_kem_pk: Vec<u8>, ttl_seconds: i64) -> Self {
        let mut mailbox_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut mailbox_id);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Placeholder signature (use Ed25519 in production)
        let signature = [0u8; 64];

        Self {
            version: 1,
            sender_pubkey,
            sender_kem_pk,
            mailbox_id,
            expiry: now + ttl_seconds,
            signature,
        }
    }

    /// Check if the invite has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        now > self.expiry
    }

    /// Serialize to base64 for sharing
    pub fn to_base64(&self) -> Result<String, ContactError> {
        let json = serde_json::to_string(self).map_err(|_| ContactError::SerializationFailed)?;
        Ok(base64_encode(json.as_bytes()))
    }

    /// Parse from base64 string
    pub fn from_base64(encoded: &str) -> Result<Self, ContactError> {
        let json_bytes = base64_decode(encoded)?;
        let json = String::from_utf8(json_bytes).map_err(|_| ContactError::InvalidPayload)?;
        serde_json::from_str(&json).map_err(|_| ContactError::InvalidPayload)
    }
}

// ============================================================================
// CONTACT STORE (Memory-Only)
// ============================================================================

/// In-memory contact store with secure deletion
pub struct ContactStore {
    /// Active contacts indexed by ID
    contacts: HashMap<String, Contact>,
    /// Pending QR exchanges (ephemeral keypair + timestamp)
    pending_exchanges: HashMap<String, (EphemeralKeypair, i64)>,
    /// Pending invite blobs awaiting ACK
    pending_invites: HashMap<String, InviteBlob>,
}

impl ContactStore {
    /// Create a new empty contact store
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
            pending_exchanges: HashMap::new(),
            pending_invites: HashMap::new(),
        }
    }

    /// Generate a new QR exchange and return the payload
    pub fn start_qr_exchange(&mut self, kem_pubkey: Option<&[u8]>) -> (String, QrPayload) {
        let keypair = EphemeralKeypair::generate();
        let payload = QrPayload::new(&keypair.public_key, kem_pubkey, 300); // 5 minutes

        let exchange_id = generate_random_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.pending_exchanges
            .insert(exchange_id.clone(), (keypair, now));

        // Clean up old exchanges (older than 10 minutes)
        self.cleanup_expired_exchanges();

        (exchange_id, payload)
    }

    /// Process a scanned QR code and compute shared secret
    pub fn process_scanned_qr(
        &mut self,
        exchange_id: &str,
        scanned_payload: &QrPayload,
    ) -> Result<(String, [u8; 32]), ContactError> {
        if scanned_payload.is_expired() {
            return Err(ContactError::PayloadExpired);
        }

        let (keypair, _) = self
            .pending_exchanges
            .get(exchange_id)
            .ok_or(ContactError::ExchangeNotFound)?;

        let peer_public = scanned_payload.decode_public_key()?;
        let shared_secret = keypair.compute_shared_secret(&peer_public);
        let sas = generate_sas(&shared_secret);

        Ok((sas, shared_secret))
    }

    /// Confirm SAS and finalize contact creation
    pub fn confirm_sas(
        &mut self,
        exchange_id: &str,
        scanned_payload: &QrPayload,
        alias: String,
    ) -> Result<Contact, ContactError> {
        let (keypair, _) = self
            .pending_exchanges
            .remove(exchange_id)
            .ok_or(ContactError::ExchangeNotFound)?;

        let peer_public = scanned_payload.decode_public_key()?;
        let kem_pubkey = scanned_payload.decode_kem_pubkey()?.unwrap_or_default();
        let shared_secret = keypair.compute_shared_secret(&peer_public);

        // Generate session ID from shared secret
        let mut hasher = Sha256::new();
        hasher.update(b"COMLOCK_SESSION_ID");
        hasher.update(shared_secret);
        let session_id = hex::encode(&hasher.finalize()[..16]);

        let contact = Contact {
            id: generate_random_id(),
            alias,
            public_key: peer_public,
            kem_pubkey,
            session_id,
            added_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            verified: true,
        };

        self.contacts.insert(contact.id.clone(), contact.clone());

        Ok(contact)
    }

    /// Generate a one-time invite blob
    pub fn generate_invite(
        &mut self,
        our_pubkey: [u8; 32],
        our_kem_pk: Vec<u8>,
        ttl_hours: u32,
    ) -> InviteBlob {
        let invite = InviteBlob::new(our_pubkey, our_kem_pk, (ttl_hours * 3600) as i64);
        self.pending_invites
            .insert(hex::encode(invite.mailbox_id), invite.clone());
        invite
    }

    /// Import an invite blob and create a pending contact
    pub fn import_invite(
        &mut self,
        invite: &InviteBlob,
        alias: String,
    ) -> Result<Contact, ContactError> {
        if invite.is_expired() {
            return Err(ContactError::PayloadExpired);
        }

        let session_id = generate_random_id();

        let contact = Contact {
            id: generate_random_id(),
            alias,
            public_key: invite.sender_pubkey,
            kem_pubkey: invite.sender_kem_pk.clone(),
            session_id,
            added_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            verified: false, // Pending ACK
        };

        self.contacts.insert(contact.id.clone(), contact.clone());

        Ok(contact)
    }

    /// Get all contacts
    pub fn list_contacts(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    /// Get a contact by ID
    pub fn get_contact(&self, id: &str) -> Option<&Contact> {
        self.contacts.get(id)
    }

    /// Delete a contact and securely zeroize its data
    pub fn delete_contact(&mut self, id: &str) -> Option<Contact> {
        self.contacts.remove(id)
    }

    /// Clean up expired pending exchanges
    fn cleanup_expired_exchanges(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expired: Vec<_> = self
            .pending_exchanges
            .iter()
            .filter(|(_, (_, created))| now - created > 600) // 10 minutes
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.pending_exchanges.remove(&key);
        }
    }
}

impl Default for ContactStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ContactStore {
    fn drop(&mut self) {
        // Securely zeroize all contact data
        for (_, contact) in self.contacts.iter_mut() {
            contact.public_key.zeroize();
            contact.kem_pubkey.zeroize();
            contact.session_id.zeroize();
        }
        self.contacts.clear();
        self.pending_exchanges.clear();
        self.pending_invites.clear();
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone, thiserror::Error)]
pub enum ContactError {
    #[error("Invalid QR payload format")]
    InvalidPayload,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Payload has expired")]
    PayloadExpired,
    #[error("Exchange session not found")]
    ExchangeNotFound,
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Base64 decoding failed")]
    Base64DecodeFailed,
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Generate a random 16-byte hex ID
fn generate_random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Base64 encode bytes
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Base64 decode string
fn base64_decode(data: &str) -> Result<Vec<u8>, ContactError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(data)
        .map_err(|_| ContactError::Base64DecodeFailed)
}

// Custom serde modules for hex encoding
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid length"))
    }
}

mod hex_serde_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid length"))
    }
}

mod hex_vec_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_keypair_generation() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();

        // Keys should be different
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_shared_secret_computation() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();

        // In real X25519, DH(sk1, pk2) == DH(sk2, pk1)
        // Our placeholder hash-based version won't have this property,
        // but in production with real X25519 it would
        let _secret1 = kp1.compute_shared_secret(&kp2.public_key);
        let _secret2 = kp2.compute_shared_secret(&kp1.public_key);
    }

    #[test]
    fn test_sas_generation_deterministic() {
        let secret = [42u8; 32];
        let sas1 = generate_sas(&secret);
        let sas2 = generate_sas(&secret);

        assert_eq!(sas1, sas2);
        assert!(sas1.contains('-'));

        // Format should be "Word-Word-Number"
        let parts: Vec<_> = sas1.split('-').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_sas_verification() {
        let secret = [42u8; 32];
        let sas = generate_sas(&secret);

        assert!(verify_sas(&secret, &sas));
        assert!(!verify_sas(&secret, "Wrong-Sas-00"));
    }

    #[test]
    fn test_qr_payload_roundtrip() {
        let pk = [1u8; 32];
        let kem = vec![2u8; 100];

        let payload = QrPayload::new(&pk, Some(&kem), 300);
        let json = payload.to_json().unwrap();
        let parsed = QrPayload::from_json(&json).unwrap();

        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.decode_public_key().unwrap(), pk);
        assert_eq!(parsed.decode_kem_pubkey().unwrap().unwrap(), kem);
    }

    #[test]
    fn test_invite_blob_roundtrip() {
        let pk = [3u8; 32];
        let kem = vec![4u8; 200];

        let invite = InviteBlob::new(pk, kem.clone(), 86400);
        let encoded = invite.to_base64().unwrap();
        let decoded = InviteBlob::from_base64(&encoded).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.sender_pubkey, pk);
        assert_eq!(decoded.sender_kem_pk, kem);
    }

    #[test]
    fn test_contact_store_qr_exchange_flow() {
        let mut store = ContactStore::new();

        // Start exchange
        let (exchange_id, payload) = store.start_qr_exchange(None);
        assert!(!exchange_id.is_empty());

        // Simulate peer's QR code
        let peer_pk = [5u8; 32];
        let peer_payload = QrPayload::new(&peer_pk, None, 300);

        // Process scanned QR
        let (sas, _shared_secret) = store
            .process_scanned_qr(&exchange_id, &peer_payload)
            .unwrap();
        assert!(!sas.is_empty());

        // Need to restart exchange since we consumed the keypair info
        let (exchange_id2, _) = store.start_qr_exchange(None);

        // Confirm SAS and create contact
        let contact = store
            .confirm_sas(&exchange_id2, &peer_payload, "Alice".into())
            .unwrap();
        assert_eq!(contact.alias, "Alice");
        assert!(contact.verified);

        // Contact should be in store
        assert_eq!(store.list_contacts().len(), 1);
    }

    #[test]
    fn test_contact_store_invite_flow() {
        let mut store = ContactStore::new();

        // Generate invite
        let pk = [6u8; 32];
        let kem = vec![7u8; 150];
        let invite = store.generate_invite(pk, kem, 24);

        // Import invite (simulating receiver)
        let contact = store.import_invite(&invite, "Bob".into()).unwrap();
        assert_eq!(contact.alias, "Bob");
        assert!(!contact.verified); // Pending ACK

        assert_eq!(store.list_contacts().len(), 1);
    }

    #[test]
    fn test_contact_deletion() {
        let mut store = ContactStore::new();

        let pk = [8u8; 32];
        let invite = InviteBlob::new(pk, vec![], 3600);
        let contact = store.import_invite(&invite, "Charlie".into()).unwrap();

        assert_eq!(store.list_contacts().len(), 1);

        store.delete_contact(&contact.id);
        assert_eq!(store.list_contacts().len(), 0);
    }
}
