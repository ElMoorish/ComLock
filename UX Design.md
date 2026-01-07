1. Design Philosophy: "Patience is Privacy"
Standard messengers optimize for instant gratification. ComLock optimizes for certainty and safety. The UX must manage user expectations regarding latency (Mixnet delays) without causing frustration.

Core Visuals:

Theme: "Terminal Chic" – High contrast, dark mode default (OLED black).

Typography: Monospaced headers (JetBrains Mono) for technical trust; Sans-serif body (Inter) for readability.

Feedback: Haptic feedback for cryptographic confirmations.

2. Onboarding Flow (The "Zero-Knowledge" Entry)
Screen 1: The Airlock

Visual: A minimal, pulsating shield icon.

Action: "Create Identity" or "Recover".

No fields for Phone/Email.

Screen 2: The Key Ceremony

Animation: Visual representation of entropy generation (user taps/swipes screen to add randomness).

Display: "Generating Quantum-Safe Keys..." -> "Registering in Anonymity Set..." (Waiting for RLN tree inclusion).

Output: Display the 24-word mnemonic.

Constraint: Screenshotting is blocked. User must write it down.

Screen 3: The Cover Story (Duress Setup)

Prompt: "Set a Master PIN for your real data."

Prompt: "Set a Duress PIN. If forced to unlock your phone, enter this PIN to destroy keys and show a fake profile."

3. Main Chat Interface
The "Mixing" Indicator (Critical UX):

Problem: Messages in a Mixnet take 2-10 seconds to arrive. Users might think the app is broken.

Solution:

Status: Sending: One gray check.

Status: Mixing: A small, animated "noise" waveform icon next to the message. This indicates the message is currently bouncing through the mix nodes.

Status: Delivered: Two gray checks.

Status: Decrypted: Two solid checks (Green/Blue).

The "Traffic Light" (Network Health):

Top Bar Element: A subtle colored dot.

Green: Connected, cover traffic active, anonymity set high.

Yellow: Low cover traffic (Battery saver), metadata leakage possible.

Red: Disconnected or Blocked (Recommend switching Transport).

4. Contact Discovery (The "Handshake")
Flow: In-Person (QR Code)

Users scan each other's QR codes.

SAS Verification: Both screens display a Short Authentication String (e.g., "Robot - Apple - 42"). Users verbally confirm they match. This authenticates the Kyber public keys.

Flow: Remote (The "Invite Link")

User A generates a "One-Time Blob" (Base64 string).

User A sends Blob to User B via an out-of-band channel (Signal, email).

User B pastes Blob -> ComLock performs a "0-RTT" blind handshake to establish the channel.

5. Settings & The "Panic" Button
Privacy Settings:

"Anonymity Budget": A slider controlling bandwidth usage.

Left: "Low Data (500MB/mo)" -> Higher latency, less cover traffic.

Right: "Max Privacy (5GB/mo)" -> Constant bitrate cover traffic, indistinguishable from streaming.

The Panic Gesture:

A specific multi-finger gesture (e.g., 3-finger long press) or shaking the device vigorously (configurable) triggers an immediate "Lock & Wipe" countdown.

