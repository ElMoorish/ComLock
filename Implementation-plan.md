Phase 1: The Cryptographic Core (Rust)
Objective: Build a no_std compatible Rust crate comlock-crypto.

Tasks:

Import pq-crypto crates for ML-KEM-1024 (FIPS 203 standard) and X25519.

Implement the KEM Braid logic:

Create a state machine that tracks RootKey, ChainKey, and NextKEMKey.

Implement the "Split-Header" mechanism where the large Kyber ciphertext is split across multiple Sphinx packets if necessary (though 32KB packets usually suffice).

Deliverable: A text-based REPL chat demonstrating PQ-forward secrecy.

Phase 2: The Transport Layer (Loopix/Sphinx)
Objective: Implement the mixnet client and node logic.

Tasks:

Implement Sphinx packet construction in Rust (onion encryption).

Develop the Loopix Client:

Implement the Poisson scheduler for cover traffic.

Optimization: Use "Predictive Cover" – if the user is typing, reduce dummy traffic to save bandwidth for the real message.

Deliverable: A Dockerized testnet with 3 mix nodes and 2 clients exchanging indistinguishable packets.

Phase 3: ZK-Identity & Anti-Spam
Objective: Integrate RLN for Sybil resistance.

Tasks:

Deploy a Waku RLN Relay node.

Implement rln-v2 circuits (Groth16 or PLONK) in the client.

Create the Membership Contract: A lightweight smart contract (on a L2 like Arbitrum or a sovereign chain) that maintains the Merkle Root of valid users.

Deliverable: A client that gets auto-banned by the network if it attempts to spam >1 message/second.

Phase 4: High-Assurance Mobile (iOS/Android)
Objective: Secure Enclave integration and UI.

Tasks:

Android: Use JNA/JNI to call the Rust binary. Store the RootKey in the Titan M2 chip using Android Keystore System.

iOS: Use UniFFI to generate Swift bindings. Store RootKey in the Secure Enclave.

Duress: Implement the "Wipe" logic.

Logic: if hash(input) == duress_hash { fs::remove_file("db.sqlite"); secure_enclave::delete_key(); load_dummy_db(); }

Reproducible Build: Configure flake.nix to cross-compile the Rust core for aarch64-linux-android and aarch64-apple-ios with pinned dependencies.

Phase 5: Red Teaming & Audit
Tasks:

Formal Verification: Use Verus or Kani to verify memory safety of the packet parser.

Traffic Analysis: Simulate a GNA observing the testnet. Verify that statistical tests (entropy checks) cannot distinguish real packets from cover packets.