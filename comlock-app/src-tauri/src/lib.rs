//! ComLock Tauri Application - Rust Backend
//!
//! This module provides the mobile entry point and Tauri commands
//! for cryptographic operations using the comlock-crypto crate.

pub mod contacts;
pub mod decoy;
pub mod security;
pub mod storage;

use std::collections::HashMap;
use std::sync::Mutex;

use comlock_crypto::{decrypt_message, encrypt_message, RatchetState};
// Transport layer types - imported for future async integration
// use comlock_transport::{MixClient, MixClientConfig, Mailbox, MixNode, NodeId};
use contacts::{Contact, ContactStore, InviteBlob, QrPayload};
use decoy::{DecoyContact, DecoyMessage, DecoyVault};
use security::{verify_pin, PinResult, SecurityConfig, WipeReason, WipeState};
use serde::{Deserialize, Serialize};
use tauri::State;

/// Application state holding active ratchet sessions.
pub struct AppState {
    /// Map of session ID to ratchet state.
    sessions: Mutex<HashMap<String, RatchetState>>,
    /// The user's identity (mnemonic-derived root key).
    identity: Mutex<Option<Identity>>,
    /// In-memory contact store (no disk persistence).
    contacts: Mutex<ContactStore>,
    /// Security configuration.
    security_config: Mutex<SecurityConfig>,
    /// Current wipe state (for decoy mode).
    wipe_state: Mutex<WipeState>,
    /// Decoy vault for duress mode.
    decoy_vault: Mutex<DecoyVault>,
    // Transport layer will be added when async integration is complete:
    // mix_client: Mutex<MixClient>,
    // mailbox: Mutex<Option<Mailbox>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            identity: Mutex::new(None),
            contacts: Mutex::new(ContactStore::new()),
            security_config: Mutex::new(SecurityConfig::default()),
            wipe_state: Mutex::new(WipeState::default()),
            decoy_vault: Mutex::new(DecoyVault::load_default()),
        }
    }
}

/// User identity bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// 24-word mnemonic (BIP-39).
    pub mnemonic: Vec<String>,
    /// Root key derived from mnemonic.
    pub root_key: [u8; 32],
    /// User's public identifier (hash of root key).
    pub public_id: String,
    /// ML-KEM-1024 decapsulation key (private, 3168 bytes).
    #[serde(default)]
    pub kem_decap_key: Vec<u8>,
    /// ML-KEM-1024 encapsulation key (public, 1568 bytes).
    #[serde(default)]
    pub kem_encap_key: Vec<u8>,
}

/// Result of creating a new identity.
#[derive(Debug, Serialize)]
pub struct CreateIdentityResult {
    pub mnemonic: Vec<String>,
    pub public_id: String,
}

/// Message encryption result.
#[derive(Debug, Serialize)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub ciphertext_hex: String,
}

/// Message decryption result.
#[derive(Debug, Serialize)]
pub struct DecryptResult {
    pub plaintext: String,
}

// ============================================================================
// IDENTITY COMMANDS
// ============================================================================

/// Create a new identity with a random mnemonic.
#[tauri::command]
fn create_identity(state: State<AppState>) -> Result<CreateIdentityResult, String> {
    use bip39::Mnemonic;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    // Generate 32 bytes of entropy for 24-word mnemonic
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);

    // Create mnemonic from entropy using BIP-39
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;

    let words: Vec<String> = mnemonic.word_iter().map(|s| s.to_string()).collect();

    // Derive root key from mnemonic seed (using BIP-39 seed derivation)
    let seed = mnemonic.to_seed(""); // Empty passphrase for simplicity
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&seed[..32]);

    // Create public ID (hash of root key)
    let mut hasher = Sha256::new();
    hasher.update(root_key);
    let hash = hasher.finalize();
    let public_id = hex::encode(&hash[..8]);

    // Generate ML-KEM-1024 keypair for post-quantum key encapsulation
    use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem1024::generate(&mut rng);

    // Serialize keypair for storage using as_bytes()
    let kem_decap_key = dk.as_bytes().to_vec();
    let kem_encap_key = ek.as_bytes().to_vec();

    let identity = Identity {
        mnemonic: words.clone(),
        root_key,
        public_id: public_id.clone(),
        kem_decap_key,
        kem_encap_key,
    };

    // Store identity
    let mut id_lock = state.identity.lock().map_err(|e| e.to_string())?;
    *id_lock = Some(identity);

    Ok(CreateIdentityResult {
        mnemonic: words,
        public_id,
    })
}

/// Recover identity from mnemonic.
#[tauri::command]
fn recover_identity(mnemonic: Vec<String>, state: State<AppState>) -> Result<String, String> {
    use bip39::Mnemonic;
    use sha2::{Digest, Sha256};

    if mnemonic.len() != 24 {
        return Err("Mnemonic must be 24 words".into());
    }

    // Join words and parse as BIP-39 mnemonic
    let phrase = mnemonic.join(" ");
    let bip39_mnemonic =
        Mnemonic::parse(&phrase).map_err(|e| format!("Invalid mnemonic: {}", e))?;

    // Derive root key from mnemonic seed
    let seed = bip39_mnemonic.to_seed("");
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&seed[..32]);

    // Create public ID
    let mut hasher = Sha256::new();
    hasher.update(root_key);
    let hash = hasher.finalize();
    let public_id = hex::encode(&hash[..8]);

    // Generate ML-KEM-1024 keypair for post-quantum key encapsulation
    use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem1024::generate(&mut rng);

    // Serialize keypair for storage using as_bytes()
    let kem_decap_key = dk.as_bytes().to_vec();
    let kem_encap_key = ek.as_bytes().to_vec();

    let identity = Identity {
        mnemonic,
        root_key,
        public_id: public_id.clone(),
        kem_decap_key,
        kem_encap_key,
    };

    let mut id_lock = state.identity.lock().map_err(|e| e.to_string())?;
    *id_lock = Some(identity);

    Ok(public_id)
}

// ============================================================================
// SESSION COMMANDS
// ============================================================================

/// Initialize a new ratchet session with a contact.
#[tauri::command]
fn init_session(
    session_id: String,
    shared_secret_hex: String,
    is_initiator: bool,
    state: State<AppState>,
) -> Result<(), String> {
    let shared_secret: [u8; 32] = hex::decode(&shared_secret_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "Shared secret must be 32 bytes")?;

    let ratchet = RatchetState::new(shared_secret, is_initiator);

    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    sessions.insert(session_id, ratchet);

    Ok(())
}

/// Trigger KEM ratchet advancement for a session.
#[tauri::command]
fn trigger_kem(session_id: String, state: State<AppState>) -> Result<(), String> {
    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let ratchet = sessions.get_mut(&session_id).ok_or("Session not found")?;

    ratchet.trigger_kem_advancement();
    Ok(())
}

// ============================================================================
// CRYPTO COMMANDS
// ============================================================================

/// Encrypt a message for a session.
#[tauri::command]
fn encrypt(
    session_id: String,
    plaintext: String,
    state: State<AppState>,
) -> Result<EncryptResult, String> {
    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let ratchet = sessions.get_mut(&session_id).ok_or("Session not found")?;

    let ciphertext = encrypt_message(plaintext.as_bytes(), ratchet).map_err(|e| e.to_string())?;

    Ok(EncryptResult {
        ciphertext_hex: hex::encode(&ciphertext),
        ciphertext,
    })
}

/// Decrypt a message for a session.
#[tauri::command]
fn decrypt(
    session_id: String,
    ciphertext_hex: String,
    state: State<AppState>,
) -> Result<DecryptResult, String> {
    let ciphertext = hex::decode(&ciphertext_hex).map_err(|e| e.to_string())?;

    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let ratchet = sessions.get_mut(&session_id).ok_or("Session not found")?;

    let plaintext_bytes = decrypt_message(&ciphertext, ratchet).map_err(|e| e.to_string())?;

    let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| e.to_string())?;

    Ok(DecryptResult { plaintext })
}

// ============================================================================
// TRANSPORT LAYER COMMANDS
// ============================================================================

/// Result of sending a message via mixnet.
#[derive(Debug, Serialize)]
pub struct SendMessageResult {
    pub message_id: String,
    pub status: String,
}

/// Result of polling the mailbox.
#[derive(Debug, Serialize)]
pub struct ReceivedMessage {
    pub message_id: String,
    pub sender_id: String,
    pub ciphertext_hex: String,
    pub received_at: i64,
}

/// Send an encrypted message through the mixnet.
/// Note: Currently queues the message for delivery. Actual mixnet
/// delivery will be implemented when the transport layer is fully connected.
#[tauri::command]
fn send_via_mixnet(
    session_id: String,
    recipient_mailbox_id: String,
    plaintext: String,
    state: State<AppState>,
) -> Result<SendMessageResult, String> {
    // Encrypt the message first
    let ciphertext = {
        let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let ratchet = sessions.get_mut(&session_id).ok_or("Session not found")?;
        encrypt_message(plaintext.as_bytes(), ratchet).map_err(|e| e.to_string())?
    };

    // Generate message ID
    let message_id = format!(
        "msg_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    // Log for now - actual mixnet delivery will be implemented
    // when the network layer is ready
    println!(
        "[MIXNET] Queued message {} for {}: {} bytes",
        message_id,
        recipient_mailbox_id,
        ciphertext.len()
    );

    Ok(SendMessageResult {
        message_id,
        status: "queued".to_string(),
    })
}

/// Poll the mailbox for incoming messages.
/// Note: Currently returns empty. Will be connected to actual
/// mailbox polling when the transport layer is fully operational.
#[tauri::command]
fn poll_messages(_state: State<AppState>) -> Result<Vec<ReceivedMessage>, String> {
    // Currently no real mailbox polling - return empty
    // This will be connected to the async transport layer
    Ok(vec![])
}

/// Get transport layer status.
#[tauri::command]
fn get_transport_status(_state: State<AppState>) -> Result<TransportStatus, String> {
    Ok(TransportStatus {
        connected: false,
        gateway_address: None,
        mailbox_id: None,
        messages_queued: 0,
        messages_received: 0,
    })
}

/// Transport layer status.
#[derive(Debug, Serialize)]
pub struct TransportStatus {
    pub connected: bool,
    pub gateway_address: Option<String>,
    pub mailbox_id: Option<String>,
    pub messages_queued: u32,
    pub messages_received: u32,
}

// ============================================================================
// CONTACT EXCHANGE COMMANDS
// ============================================================================

/// Result of starting a QR exchange
#[derive(Debug, Serialize)]
pub struct QrExchangeResult {
    pub exchange_id: String,
    pub qr_payload: String,
}

/// Result of processing a scanned QR code
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub sas: String,
}

/// Result of confirming SAS and creating contact
#[derive(Debug, Serialize)]
pub struct ConfirmSasResult {
    pub contact: Contact,
    pub session_id: String,
    pub session_initialized: bool,
}

/// Generate a QR payload for in-person key exchange.
#[tauri::command]
fn generate_qr_payload(state: State<AppState>) -> Result<QrExchangeResult, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;

    // Get KEM pubkey from identity if available
    let identity = state.identity.lock().map_err(|e| e.to_string())?;
    let kem_pubkey: Option<Vec<u8>> = identity.as_ref().map(|id| {
        // Use the real ML-KEM-1024 encapsulation key from identity
        id.kem_encap_key.clone()
    });

    let (exchange_id, payload) = contacts.start_qr_exchange(kem_pubkey.as_deref());
    let qr_json = payload.to_json().map_err(|e| e.to_string())?;

    Ok(QrExchangeResult {
        exchange_id,
        qr_payload: qr_json,
    })
}

/// Process a scanned QR code and return the SAS for verification.
#[tauri::command]
fn process_scanned_qr(
    exchange_id: String,
    qr_json: String,
    state: State<AppState>,
) -> Result<ScanResult, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    let payload = QrPayload::from_json(&qr_json).map_err(|e| e.to_string())?;

    let (sas, _shared_secret) = contacts
        .process_scanned_qr(&exchange_id, &payload)
        .map_err(|e| e.to_string())?;

    Ok(ScanResult { sas })
}

/// Confirm SAS match and finalize contact creation.
/// Also initializes the ratchet session automatically.
#[tauri::command]
fn confirm_sas(
    exchange_id: String,
    qr_json: String,
    alias: String,
    state: State<AppState>,
) -> Result<ConfirmSasResult, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    let payload = QrPayload::from_json(&qr_json).map_err(|e| e.to_string())?;

    // Get the shared secret before consuming the exchange
    let peer_public = payload.decode_public_key().map_err(|e| e.to_string())?;
    let shared_secret = {
        let (keypair, _) = contacts
            .get_pending_exchange(&exchange_id)
            .ok_or("Exchange not found")?;
        keypair.compute_shared_secret(&peer_public)
    };

    // Create the contact
    let contact = contacts
        .confirm_sas(&exchange_id, &payload, alias)
        .map_err(|e| e.to_string())?;

    // Auto-initialize the ratchet session with the shared secret
    let session_id = contact.session_id.clone();
    let ratchet = RatchetState::new(shared_secret, true); // We're the scanner, so we're initiator

    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    sessions.insert(session_id.clone(), ratchet);

    Ok(ConfirmSasResult {
        contact,
        session_id,
        session_initialized: true,
    })
}

/// Generate a one-time invite blob for remote contact exchange.
#[tauri::command]
fn generate_invite(ttl_hours: Option<u32>, state: State<AppState>) -> Result<String, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    let identity = state.identity.lock().map_err(|e| e.to_string())?;

    let identity = identity.as_ref().ok_or("No identity created yet")?;

    // Derive X25519 public key from root key (placeholder)
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(b"COMLOCK_X25519_PK");
    hasher.update(identity.root_key);
    let hash = hasher.finalize();
    let mut our_pubkey = [0u8; 32];
    our_pubkey.copy_from_slice(&hash);

    // Use real ML-KEM-1024 encapsulation key from identity
    let our_kem_pk = identity.kem_encap_key.clone();

    let invite = contacts.generate_invite(our_pubkey, our_kem_pk, ttl_hours.unwrap_or(24));
    invite.to_base64().map_err(|e| e.to_string())
}

/// Import an invite blob and create a pending contact.
#[tauri::command]
fn import_invite(
    invite_b64: String,
    alias: String,
    state: State<AppState>,
) -> Result<Contact, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    let invite = InviteBlob::from_base64(&invite_b64).map_err(|e| e.to_string())?;

    contacts
        .import_invite(&invite, alias)
        .map_err(|e| e.to_string())
}

/// List all contacts in memory.
#[tauri::command]
fn list_contacts(state: State<AppState>) -> Result<Vec<Contact>, String> {
    let contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    Ok(contacts.list_contacts())
}

/// Delete a contact and securely zeroize its data.
#[tauri::command]
fn delete_contact(contact_id: String, state: State<AppState>) -> Result<bool, String> {
    let mut contacts = state.contacts.lock().map_err(|e| e.to_string())?;
    Ok(contacts.delete_contact(&contact_id).is_some())
}

// ============================================================================
// SECURITY COMMANDS
// ============================================================================

/// Security status result
#[derive(Debug, Serialize)]
pub struct SecurityStatus {
    pub security_enabled: bool,
    pub has_pin: bool,
    pub has_duress_pin: bool,
    pub dead_man_days: u32,
    pub days_until_wipe: Option<i64>,
    pub panic_gesture_enabled: bool,
    pub failed_attempts: u32,
    pub is_decoy_mode: bool,
}

/// Unlock result
#[derive(Debug, Serialize)]
pub struct UnlockResult {
    pub success: bool,
    pub is_decoy: bool,
    pub reason: String,
}

/// Get current security status (safe info only).
#[tauri::command]
fn get_security_status(state: State<AppState>) -> Result<SecurityStatus, String> {
    let config = state.security_config.lock().map_err(|e| e.to_string())?;
    let wipe_state = state.wipe_state.lock().map_err(|e| e.to_string())?;

    Ok(SecurityStatus {
        security_enabled: config.security_enabled,
        has_pin: config.pin_hash.is_some(),
        has_duress_pin: config.duress_pin_hash.is_some(),
        dead_man_days: config.dead_man_days,
        days_until_wipe: security::days_until_wipe(&config),
        panic_gesture_enabled: config.panic_gesture_enabled,
        failed_attempts: config.failed_attempts,
        is_decoy_mode: wipe_state.should_show_decoy(),
    })
}

/// Set up the normal unlock PIN.
#[tauri::command]
fn setup_pin(pin: String, state: State<AppState>) -> Result<(), String> {
    let mut config = state.security_config.lock().map_err(|e| e.to_string())?;

    if pin.len() < 4 {
        return Err("PIN must be at least 4 characters".into());
    }

    config.pin_hash = Some(security::set_pin(&pin));
    config.security_enabled = true;
    config.update_access();

    Ok(())
}

/// Set up the duress PIN (different from normal PIN).
#[tauri::command]
fn setup_duress_pin(duress_pin: String, state: State<AppState>) -> Result<(), String> {
    let mut config = state.security_config.lock().map_err(|e| e.to_string())?;

    let normal_hash = config.pin_hash.ok_or("Set normal PIN first")?;

    if duress_pin.len() < 4 {
        return Err("Duress PIN must be at least 4 characters".into());
    }

    let duress_hash = security::set_duress_pin(&duress_pin, &normal_hash)
        .ok_or("Duress PIN must be different from normal PIN")?;

    config.duress_pin_hash = Some(duress_hash);

    Ok(())
}

/// Verify PIN and handle unlock/duress/wipe scenarios.
#[tauri::command]
fn verify_unlock(pin: String, state: State<AppState>) -> Result<UnlockResult, String> {
    let mut config = state.security_config.lock().map_err(|e| e.to_string())?;
    let mut wipe_state = state.wipe_state.lock().map_err(|e| e.to_string())?;

    // Check dead man's switch first
    if config.is_dead_man_triggered() {
        wipe_state.trigger(WipeReason::DeadManSwitch);
        return Ok(UnlockResult {
            success: true,
            is_decoy: true,
            reason: "dead_man_switch".into(),
        });
    }

    let result = verify_pin(&pin, &config);

    match result {
        PinResult::Normal => {
            config.update_access();
            Ok(UnlockResult {
                success: true,
                is_decoy: false,
                reason: "authenticated".into(),
            })
        }
        PinResult::Duress => {
            wipe_state.trigger(WipeReason::DuressPin);
            Ok(UnlockResult {
                success: true,
                is_decoy: true,
                reason: "duress_pin".into(),
            })
        }
        PinResult::Invalid => {
            let should_wipe = config.record_failed_attempt();
            if should_wipe {
                wipe_state.trigger(WipeReason::MaxAttempts);
                return Ok(UnlockResult {
                    success: true,
                    is_decoy: true,
                    reason: "max_attempts".into(),
                });
            }
            Err(format!(
                "Invalid PIN. {} attempts remaining",
                config.max_failed_attempts - config.failed_attempts
            ))
        }
        PinResult::NoPinSet => {
            config.update_access();
            Ok(UnlockResult {
                success: true,
                is_decoy: false,
                reason: "no_pin_required".into(),
            })
        }
        PinResult::MaxAttemptsExceeded => {
            wipe_state.trigger(WipeReason::MaxAttempts);
            Ok(UnlockResult {
                success: true,
                is_decoy: true,
                reason: "max_attempts".into(),
            })
        }
    }
}

/// Configure dead man's switch.
#[tauri::command]
fn configure_dead_man(days: u32, state: State<AppState>) -> Result<(), String> {
    let mut config = state.security_config.lock().map_err(|e| e.to_string())?;
    config.dead_man_days = days;
    config.update_access();
    Ok(())
}

/// Toggle panic gesture.
#[tauri::command]
fn toggle_panic_gesture(enabled: bool, state: State<AppState>) -> Result<(), String> {
    let mut config = state.security_config.lock().map_err(|e| e.to_string())?;
    config.panic_gesture_enabled = enabled;
    Ok(())
}

/// Trigger panic gesture wipe.
#[tauri::command]
fn trigger_panic(state: State<AppState>) -> Result<(), String> {
    let config = state.security_config.lock().map_err(|e| e.to_string())?;

    if !config.panic_gesture_enabled {
        return Err("Panic gesture is disabled".into());
    }

    let mut wipe_state = state.wipe_state.lock().map_err(|e| e.to_string())?;
    wipe_state.trigger(WipeReason::PanicGesture);

    Ok(())
}

/// Get decoy contacts (for decoy mode).
#[tauri::command]
fn get_decoy_contacts(state: State<AppState>) -> Result<Vec<DecoyContact>, String> {
    let vault = state.decoy_vault.lock().map_err(|e| e.to_string())?;
    Ok(vault.get_contacts())
}

/// Get decoy messages for a contact (for decoy mode).
#[tauri::command]
fn get_decoy_messages(
    contact_id: String,
    state: State<AppState>,
) -> Result<Vec<DecoyMessage>, String> {
    let vault = state.decoy_vault.lock().map_err(|e| e.to_string())?;
    Ok(vault.get_messages(&contact_id))
}

/// Check if in decoy mode.
#[tauri::command]
fn is_decoy_mode(state: State<AppState>) -> Result<bool, String> {
    let wipe_state = state.wipe_state.lock().map_err(|e| e.to_string())?;
    Ok(wipe_state.should_show_decoy())
}

// ============================================================================
// ENTRY POINT
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // Identity
            create_identity,
            recover_identity,
            // Sessions
            init_session,
            trigger_kem,
            // Crypto
            encrypt,
            decrypt,
            // Transport Layer
            send_via_mixnet,
            poll_messages,
            get_transport_status,
            // Contact Exchange
            generate_qr_payload,
            process_scanned_qr,
            confirm_sas,
            generate_invite,
            import_invite,
            list_contacts,
            delete_contact,
            // Security
            get_security_status,
            setup_pin,
            setup_duress_pin,
            verify_unlock,
            configure_dead_man,
            toggle_panic_gesture,
            trigger_panic,
            get_decoy_contacts,
            get_decoy_messages,
            is_decoy_mode,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ============================================================================
// WORD LIST (Simplified - use full BIP-39 in production)
// ============================================================================

const WORD_LIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acquire", "across",
    "act", "action", "actor", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient",
    "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "answer", "antenna",
    "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange",
    "arrest", "arrive", "arrow", "art", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
    "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "bacon", "badge", "bag", "balance", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle",
    "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
    "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
    "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
    "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket",
    "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker",
    "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
    "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy",
];
