# ComLock

**ComLock** is a high-assurance, post-quantum secure communication platform designed for extreme threat models. It combines the "Terminal Chic" aesthetic of a hacker dashboard with NSA-grade cryptographic engineering.

## 🛡️ Core Features

-   **Post-Quantum Cryptography**: Uses **Kyber-1024 (ML-KEM)** for key encapsulation and **X25519** for ongoing ratchet secrecy.
-   **Panic Layer**: "Duress Mode" and "Dead Man's Switch" provide plausible deniability and automated data wiping.
-   **Offline-First**: Maximum security through local key management and QR-based offline handshakes.
-   **Terminal Chic UI**: A retro-futuristic, high-contrast interface designed for clarity and speed.

## 🚀 Getting Started

### Prerequisites

-   **Node.js**: v18+
-   **Rust**: Stable toolchain (1.75+)
-   **Tauri CLI**: `cargo install tauri-cli`

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/elmoorish/comlock.git
    cd comlock/comlock-app
    ```

2.  Install dependencies:
    ```bash
    npm install
    # Backend dependencies are handled by Cargo automatically
    ```

3.  Run in Development Mode:
    ```bash
    npm run tauri dev
    ```

## 🏗️ Build & Release

We use GitHub Actions for automated cross-platform builds.

### Triggering a Release
Push a tag starting with `v` (e.g., `v1.0.0`) to the `main` branch.
```bash
git tag v1.0.0
git push origin v1.0.0
```

### GitHub Secrets Required
For the CI/CD pipeline to work, configure the following repository secrets:

**Android**:
-   `ANDROID_KEYSTORE`: Base64 encoded keystore file.
-   `ANDROID_KEYSTORE_PASSWORD`: Keystore password.
-   `ANDROID_KEY_ALIAS`: Key alias.
-   `ANDROID_KEY_PASSWORD`: Key password.

**iOS**:
-   `APPLE_CERTIFICATE`: Base64 p12 certificate.
-   `APPLE_CERTIFICATE_PASSWORD`: Certificate password.
-   `APPLE_MOBILE_PROVISIONING_PROFILE`: Base64 provisioning profile.

## 🔐 Security

ComLock is built with a "paranoia-first" mindset.

-   **Audit Status**: Phase 5 Audit Passed (Jan 2026).
-   **Memory Safety**: All keys are zeroized on drop.
-   **Storage**: AES-256-GCM encrypted local storage PIN-protected.

##  Donation 

BTC: 17ospCx6MbNQfqETd1UjAQQSus8ENHXgnh

BNB: 0x92526bbd4a02baeaedda62208e4c485d852ef66d
---

*(c) 2026 ComLock Project*
