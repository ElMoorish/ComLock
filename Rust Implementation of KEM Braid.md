The "KEM Braid" (or Sparse Post-Quantum Ratchet) is the most complex component of Project ComLock. It solves a physics problem: Bandwidth vs. Security.

Classical Signal: Sends a 32-byte Curve25519 key with every message. Cheap and fast.

Naive Post-Quantum: Sending a Kyber-1024 public key (~1568 bytes) with every message would increase bandwidth consumption by ~50x, draining battery and killing latency on mobile networks.

The Solution: We decouple the Classical Ratchet (fast, runs every message) from the Post-Quantum Ratchet (heavy, runs intermittently).

1. The State Machine Architecture
In Rust, we define a RatchetState that manages two parallel timelines. We use the pqc_kyber crate (FIPS 203 compliant) and x25519-dalek for the classical layer.

Rust

use pqc_kyber::{kyber1024, Keypair, Ciphertext};
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct RatchetState {
    // The "Root of Trust" derived from the initial PQXDH handshake
    root_key: [u8; 32], 
    
    // Classical: Updates every message (Speed)
    chain_key_classical: [u8; 32],
    ephemeral_key_pair: StaticSecret,
    
    // Post-Quantum: Updates opportunistically (Security)
    // We store the "Next" encapsulation key to create the braid
    pending_kem_pubkey: Option<kyber1024::PublicKey>,
    last_kem_secret: [u8; 32], // The entropy from the last successful decap
}
2. The "Braid" Logic (Step Function)
The core innovation is the step function. It attempts to perform a KEM encapsulation only if the "Braid" is open (i.e., we have a fresh public key from the recipient). If not, it falls back to classical security temporarily, but "heals" the stream as soon as a KEM exchange completes.

Rust

impl RatchetState {
    pub fn step(&mut self, remote_classical_pub: PublicKey, remote_kem_pub: Option<Vec<u8>>) -> ([u8; 32], MessageHeader) {
        // 1. Always perform Classical ECDH (Cheap)
        let dh_out = self.ephemeral_key_pair.diffie_hellman(&remote_classical_pub);

        // 2. Opportunistic KEM Encapsulation (Heavy)
        let (kem_out, kem_ciphertext) = if let Some(pub_bytes) = remote_kem_pub {
            // We have a fresh PQ key from the recipient. Encapsulate!
            let (ct, ss) = kyber1024::encapsulate(&pub_bytes, &mut rand::thread_rng()).unwrap();
            (Some(ss), Some(ct))
        } else {
            // No fresh PQ key. Rely on the previous shared secret (Forward Secrecy holds, PCS is paused)
            (None, None)
        };

        // 3. The "Unified" Derivation
        // We mix: Old Root + ECDH + New KEM (if any) + Old KEM (if none)
        let input_key_material = [
            dh_out.as_bytes(),
            kem_out.as_deref().unwrap_or(&self.last_kem_secret)
        ].concat();

        let (new_root, new_chain) = self.kdf_ratchet(&input_key_material);
        
        self.root_key = new_root;
        
        // Update state
        if let Some(ss) = kem_out {
            self.last_kem_secret = ss.into();
        }

        (new_chain, MessageHeader::new(self.ephemeral_key_pair.public, kem_ciphertext))
    }
}
3. The "Split-Header" Optimization
A 1568-byte Kyber key is too large for a single Loopix/Sphinx packet header (which is strictly size-limited to ensure indistinguishability).

Strategy: We implement "Header Fragmentation." The Kyber ciphertext is split into 3 chunks.

Implementation: The MessageHeader struct includes a fragment_id and total_fragments. The receiver's ratchet pauses (buffers messages) until all 3 fragments of the KEM key arrive, then reassembles the ciphertext, decapsulates, and derives the key. This prevents the "metadata leak" of sending one giant packet.