<p align="center">
  <img src="https://img.shields.io/badge/Post--Quantum-Ready-blueviolet?style=for-the-badge" alt="Post-Quantum Ready"/>
  <img src="https://img.shields.io/badge/Mixnet-Anonymous-success?style=for-the-badge" alt="Mixnet Anonymous"/>
  <img src="https://img.shields.io/badge/E2E-Encrypted-blue?style=for-the-badge" alt="E2E Encrypted"/>
</p>

<h1 align="center">🔐 ComLock</h1>

<p align="center">
  <strong>Quantum-Resistant Encrypted Messaging</strong><br>
  <em>Privacy that survives tomorrow's threats</em>
</p>

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🔒 **ML-KEM-1024** | NIST-approved post-quantum key encapsulation |
| 🧅 **Mixnet Transport** | Katzenpost-based anonymous routing |
| 🔑 **Double Ratchet** | Forward secrecy with X3DH key exchange |
| 📱 **Cross-Platform** | Desktop + Android (Tauri + React) |
| 🗝️ **BIP-39 Recovery** | 24-word mnemonic seed backup |
| 🔥 **Secure Wipe** | Zero-overwrite sensitive data deletion |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      ComLock App                         │
├──────────────────────────────────────────────────────────┤
│  React UI  │  Tauri Commands  │  Rust Backend            │
├──────────────────────────────────────────────────────────┤
│            comlock-crypto (Double Ratchet + Kyber)       │
├──────────────────────────────────────────────────────────┤
│            comlock-transport (Sphinx + Katzenpost)       │
└──────────────────────────────────────────────────────────┘
```

---

## � Cryptography Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X25519 + ML-KEM-1024 | Hybrid post-quantum |
| Signatures | Ed25519 | Authentication |
| Encryption | AES-256-GCM | Message encryption |
| Key Derivation | Argon2id | PIN-to-key derivation |
| Recovery | BIP-39 | Mnemonic seed phrases |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/ElMoorish/ComLock.git
cd ComLock

# Install dependencies
cd comlock-app
npm install

# Run desktop app
npm run tauri dev

# Build Android
npm run tauri android build
```

---

## 📦 Project Structure

```
ComLock/
├── comlock-app/          # Tauri + React application
│   ├── src/              # React frontend
│   └── src-tauri/        # Rust backend
├── comlock-crypto/       # Post-quantum cryptography
└── comlock-transport/    # Mixnet transport layer
```

---

## 🛡️ Security Model

- **Zero Trust**: All messages encrypted end-to-end
- **Forward Secrecy**: Compromised keys don't reveal past messages
- **Post-Quantum**: Resistant to quantum computer attacks
- **Anonymity**: Mixnet hides metadata and traffic patterns
- **Deniability**: No long-term identity proofs stored

---

## 📋 Roadmap

- [x] Core cryptography (ML-KEM-1024, Double Ratchet)
- [x] Katzenpost mixnet client
- [x] Encrypted local storage
- [x] Android APK builds
- [ ] iOS support
- [ ] Production mixnet deployment
- [ ] Group messaging

---

## ⚠️ Disclaimer

This software is experimental. Use at your own risk. Not audited for production use.

---

## � Support Development

If you find ComLock useful, consider supporting development:

<table>
<tr>
<td align="center">
<img src="https://img.shields.io/badge/Bitcoin-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Bitcoin"/>
<br><code>17ospCx6MbNQfqETd1UjAQQSus8ENHXgnh</code>
</td>
<td align="center">
<img src="https://img.shields.io/badge/BNB-F0B90B?style=for-the-badge&logo=binance&logoColor=white" alt="BNB"/>
<br><code>0x92526bbd4a02baeaedda62208e4c485d852ef66d</code>
</td>
</tr>
</table>

---

<p align="center">
  <sub>Built with 🔐 for privacy • MIT License</sub>
</p>
