# Project: Privacy-First E2EE post quantum Chat App (Kotlin/Swift/GCP)

Please read technical plan at https://docs.google.com/document/d/1ed1ZChYBov-3MVqU6XsdMiyLYhVLLbpnXMvtpuUOu9s/edit?usp=sharing

## 1. Project Overview
A "Zero-Knowledge" end-to-end encrypted chat application.
- **Privacy Goal:** No phone numbers, no emails. Identity via Mnemonic Seed Phrases.
- **Protocol:** Signal Protocol (X3DH + Double Ratchet).
- **Infrastructure:** Google Cloud Platform (Cloud Run/GKE, Cloud SQL, Firestore).

---

## 2. Technical Stack
### Mobile Clients (Native)
* **Android:** Kotlin + `libsignal-protocol-android`.
* **iOS:** Swift + `LibSignalProtocolSwift`.
* **Identity:** Client-side UUID generation + BIP39 Mnemonic Seed for recovery.

### Backend (GCP)
* **Compute:** Cloud Run (Serverless) or GKE.
* **Relational (Key Directory):** Cloud SQL (MySQL). Stores Public Key Bundles.
* **NoSQL (Message Relay):** Cloud Firestore. Stores encrypted blobs; uses real-time listeners for message delivery.

---

## 3. MySQL Database Schema (Key Directory)
Used for managing cryptographic handshakes and user metadata.

```sql
CREATE TABLE users (
    user_uuid CHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    identity_key_public BLOB NOT NULL,
    registration_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE signed_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

CREATE TABLE one_time_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    is_consumed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

The cloud run endpoint url is https://quantchat-server-1078066473760.us-central1.run.app# KyberChat iOS — Claude Code Guide
### Pair-Programming Battle Map 🥄

> *"Clarity of purpose leads to honesty in action!"* — The Tick

This document is the authoritative guide for **Claude and all developers** working on `kyberchat-ios`. It covers the app's design philosophy, the full backend API surface, the current iOS project state, and concrete engineering task lists for each screen. Read it before writing a single line of code.

**iOS Project:** `/Users/tom/work/kyberchat-ios`
**Server Project:** `/Users/tom/work/kyberchat-server/cloudrun`
**Server Base URL:** `https://quantchat-server-1078066473760.us-central1.run.app`

---

## Project Overview
A zero-knowledge, end-to-end encrypted chat application. This repo is the **iOS client**.

- **Privacy model:** No phone numbers, no emails. Identity via BIP39 Mnemonic Seed Phrases.
- **Encryption protocol:** Signal Protocol (X3DH key agreement + Double Ratchet messaging), hybridized with post-quantum cryptography.
- **Backend:** GCP (Cloud Run/GKE, Cloud SQL/MySQL for key directory, Firestore for message relay).
- **Threat model:** Protection against harvest-now-decrypt-later attacks by nation-state / quantum-capable adversaries.

---

## Post-Quantum Cryptography (PQC) Strategy

The goal is a **hybrid classical + post-quantum** design. Classical algorithms (X25519, AES-256-GCM) remain in place for present-day security; ML-KEM (CRYSTALS-Kyber, NIST FIPS 203) is layered on top to defeat future quantum decryption.

### Key Exchange
- Combine **X25519** (classical ECDH) with **ML-KEM-768** (post-quantum KEM) in every X3DH handshake.
- Derive the final shared secret by feeding all DH outputs AND the KEM shared secret into a single HKDF:
  ```
  SK = HKDF-SHA256(DH1 || DH2 || DH3 || DH4 || KEM_SS, info="kyberchat-x3dh")
  ```
  Where `KEM_SS` is the 32-byte ML-KEM-768 shared secret from encapsulation against the recipient's `kem_public_key`. Compromise of either layer alone does not break the session.
- **Library:** `swift-crypto 3.3+` (`import Crypto`). `MLKem768.PrivateKey(seed:)` — seed is 64 bytes derived from master seed via HKDF. Public key is 1184 bytes (`rawRepresentation`). Encapsulation: `kemPub.encapsulate() -> (ciphertext: Data, sharedSecret: Data)`. Decapsulation: `kemPriv.decapsulate(ciphertext:) -> Data`.

### Storage (iOS)
1. **Master Seed** — generated once on first launch from a CSPRNG; 256 bits of entropy.
2. **DB Key** — derived from the master seed via HKDF-SHA3-256 to produce a 256-bit SQLCipher key.
3. **Seed at rest** — stored as a Keychain "Generic Password" item, protected by biometric authentication (Face ID / Touch ID). Access control: `kSecAccessControlBiometryCurrentSet`.
4. **ML-KEM seed** — stored in Keychain under `"kemPrivateKeySeed"` (64 bytes). The `MLKem768.PrivateKey` is re-instantiated on demand from this seed via `MLKem768.PrivateKey(seed:)` — the raw private key bytes never leave the seed. PQC math runs in app memory using `swift-crypto 3.3+`; the Secure Enclave is not involved (it supports only P-256 natively).

### Storage (Android)
- Master seed stored in the Android Keystore, unlocked by BiometricPrompt.
- ML-KEM private keys kept as encrypted files in the app's private storage, key-wrapped with the Keystore-backed AES-256-GCM key.

### Server / Key Directory
- The key directory stores an **ML-KEM-768 public key** alongside each user's classical Signal key bundle.
- The API schema is extended: `kem_public_key BLOB NOT NULL` on the `users` table (see MySQL Schema below).
- One-time pre-keys also carry a paired KEM encapsulation key so each message can perform a fresh KEM encapsulation.
- The server never sees any private keys or plaintext — the PQC layer does not change the zero-knowledge property.

---

## Technical Stack

### This Repo (iOS Client)
- **Language:** Swift
- **UI:** SwiftUI
- **Persistence:** SwiftData (local store)
- **Crypto:** Custom Swift Signal Protocol implementation (X3DH + Double Ratchet) + **`swift-crypto 3.3+`** (Apple) for ML-KEM-768 via the `Crypto` module. Add via SPM: `https://github.com/apple/swift-crypto` (tag ≥ 3.3.0), product `.product(name: "Crypto", package: "swift-crypto")`.
- **Identity:** Client-side UUID generation + BIP39 mnemonic for account recovery

### Android Client (separate repo)
- **Language:** Kotlin
- **Crypto:** `libsignal-protocol-android` + `liboqs-android` (or equivalent JNI wrapper for ML-KEM)

### Backend (GCP)
- **Compute:** Cloud Run (serverless) or GKE
- **Key Directory:** Cloud SQL (MySQL) — stores public key bundles including ML-KEM public keys
- **Message Relay:** Cloud Firestore — stores encrypted blobs, real-time listeners for delivery

---

## Architecture

### Identity & Onboarding
Users have no PII account. On first launch:
1. Generate a UUID locally.
2. Generate a BIP39 mnemonic — this IS the identity recovery mechanism.
3. Derive Signal Protocol key material from the mnemonic seed.
4. Register the public key bundle (Identity Key, Signed Pre-Key, One-Time Pre-Keys) with the backend key directory.

### Sending a Message (X3DH + Double Ratchet)
1. Fetch recipient's key bundle from Cloud SQL via the backend API.
2. Perform X3DH to establish a shared secret.
3. Initialize a Double Ratchet session.
4. Encrypt the message payload; upload the ciphertext blob to Firestore.
5. Recipient's device listens via Firestore real-time listener, downloads and decrypts.

### Zero-Knowledge Principle
- The server never sees plaintext. It only stores encrypted blobs and public keys.
- User lookup is by username or UUID — no phone/email stored anywhere.

---

## MySQL Schema (Key Directory — Backend)

```sql
CREATE TABLE users (
    user_uuid CHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    identity_key_public BLOB NOT NULL,       -- X25519 identity key
    kem_public_key BLOB NOT NULL,            -- ML-KEM-768 public key
    registration_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE signed_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

CREATE TABLE one_time_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    is_consumed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);
```

---

## Project Structure

```
kyberchat/
├── kyberchat.xcodeproj/
└── kyberchat/
    ├── kyberchatApp.swift      # App entry point, SwiftData ModelContainer setup
    ├── ContentView.swift       # Root view (placeholder — replace with real UI)
    ├── Item.swift              # SwiftData model (placeholder)
    └── Assets.xcassets/
```

---

## Development Conventions

- **SwiftUI only** — no UIKit unless strictly required by a third-party library.
- **SwiftData** for local persistence (sessions, cached messages, key material).
- All crypto operations must happen off the main thread (use `async/await` with actors or background tasks).
- Never log plaintext message content or key material — not even in DEBUG builds.
- Prefer `async/await` over completion handlers for all async work.
- Keep crypto and networking logic out of View files — use ViewModels or service objects.

## Build & Run

Open `kyberchat/kyberchat.xcodeproj` in Xcode. No package manager CLI setup required; Swift Package Manager handles dependencies via Xcode.

```bash
# Build from CLI (optional)
xcodebuild -project kyberchat/kyberchat.xcodeproj \
           -scheme kyberchat \
           -destination 'platform=iOS Simulator,name=iPhone 16' \
           build

# Run tests
xcodebuild test \
           -project kyberchat/kyberchat.xcodeproj \
           -scheme kyberchat \
           -destination 'platform=iOS Simulator,name=iPhone 16'
```

---

## Current iOS File Inventory

| File | Status | Notes |
|---|---|---|
| `KeychainHelper.swift` | ✅ Done | Keychain wrapper + `KeychainAccount` enum (authToken, masterSeed, identityPrivateKey, signingPrivateKey, signedPreKeyPrivate, signedPreKeyId, kemPrivateKeySeed) |
| `SessionManager.swift` | ✅ Done | `@Observable` auth state, PASETO token in Keychain, auto-login, 401 logout |
| `MnemonicService.swift` | ✅ Done | BIP39 (CSPRNG → mnemonic), PBKDF2-HMAC-SHA512 seed, HKDF-SHA256 key derivation, `kemPublicKeyHex(from:)` |
| `BIP39Wordlist.swift` | ✅ Done | Full 2048-word BIP39 English wordlist |
| `APIService.swift` | ✅ Done | Full API client, PASETO Bearer tokens, all endpoints, 401 → SessionManager.logout() |
| `LoginView.swift` | ✅ Done | SessionManager injection, proper auth flow, keyboard handling |
| `CreateAccountView.swift` | ✅ Done | BIP39 flow, MnemonicRevealView, deterministic keys, ML-KEM registration, pre-key upload |
| `ContentView.swift` | ✅ Done | SessionManager, auto-login on appear, routes to HomeView or LoginView |
| `PasswordFieldView.swift` | ✅ Good | Reusable as-is |
| `HomeView.swift` | ❌ Placeholder | Replace with `FriendsListView` |
| `FriendsListView.swift` | ❌ Not started | Screen 4 — see tasks below |
| `ChatView.swift` | ❌ Not started | Screen 5 — see tasks below |
| `ChangePasswordView.swift` | ❌ Not started | Screen 3 — see tasks below |
| `Item.swift` | ❌ Unused | Delete — replace with real SwiftData models |

---

## Backend API Reference

### Token System: PASETO v4.local (NOT JWT)

> **Critical:** The server uses **PASETO v4.local** (XChaCha20-Poly1305 + BLAKE2b symmetric AEAD), not JWT. Tokens are **opaque strings** — do not attempt to decode or inspect them client-side. They are used identically to JWTs: `Authorization: Bearer <token>`. Token expiry is **7 days**. On `401`, clear the stored token and route to the login screen.

All authenticated endpoints require: `Authorization: Bearer <paseto_token>`

---

### Authentication & Account Management

#### `POST /create_user` — Register a new account
**Auth:** None

**Request:**
```json
{
  "user_uuid": "string (UUID v4 — deterministically derived from BIP39 mnemonic seed)",
  "username": "string (max 50 chars, unique)",
  "password": "string",
  "identity_key_public": "string (hex-encoded X25519 public key, 32 bytes → 64 hex chars)",
  "registration_id": "integer (1–65535)",
  "kem_public_key": "string (optional — hex-encoded ML-KEM-768 public key, 1184 bytes → 2368 hex chars)"
}
```

**Response 201:**
```json
{
  "message": "User created successfully",
  "user_uuid": "string",
  "token": "string (PASETO v4.local)"
}
```

**Errors:** `400` missing field / invalid hex · `409` username or UUID taken · `500`

**Notes for iOS:**
- ✅ `create_user` returns a PASETO token directly — use it immediately for `POST /keys/upload`. No extra login round-trip needed.
- Keys must be **derived from the BIP39 mnemonic seed**, not randomly generated. See Identity & Onboarding section.

---

#### `POST /validate_login` — Authenticate and receive PASETO token
**Auth:** None

**Request:**
```json
{ "username": "string", "password": "string" }
```

**Response 200:**
```json
{
  "message": "User found",
  "token": "string (PASETO v4.local)",
  "user": {
    "user_uuid": "string",
    "username": "string",
    "registration_id": "integer",
    "created_at": "string (ISO-8601)"
  }
}
```

**Errors:** `400` missing fields · `401` invalid credentials (generic — server does not distinguish bad username vs bad password) · `500`

**Notes for iOS:**
- Store `token` in Keychain: service `"kyberchat"`, account `"authToken"`.
- Store `user_uuid` and `username` in `UserDefaults` (non-sensitive).
- Error display: always say "Invalid username or password." — never be more specific.

---

#### `POST /update_auth` — Heartbeat / online presence ping
**Auth:** Bearer token required ✅

**Request:** Empty body `{}`

**Response 200:** `{ "message": "Auth updated successfully" }`

**Errors:** `401` invalid/expired token · `404` user not found

**Notes for iOS:** Call every 90s while `scenePhase == .active`. Updates `last_seen` in MySQL + Redis heartbeat (120s TTL). `user_uuid` is derived server-side from the Bearer token — do not send it in the body.

---

#### `POST /change_password` — Update the user's password
**Auth:** Bearer token required ✅ (defense-in-depth: also verifies `old_password`)

**Request:**
```json
{
  "old_password": "string",
  "new_password": "string"
}
```

**Response 200:** `{ "message": "Password changed successfully" }`

**Errors:** `401` old password wrong or bad token · `404` user not found · `500`

**Notes for iOS:** Existing PASETO token remains valid after change — no re-login needed. Do NOT send `user_uuid` in body; it is derived from the Bearer token server-side.

---

#### `POST /delete_user` — Soft-delete the account
**Auth:** Bearer token required ✅ (defense-in-depth: also verifies `password`)

**Request:**
```json
{ "password": "string" }
```

**Response 200:** `{ "message": "User deleted successfully" }`

**Errors:** `401` wrong password or bad token · `404` not found · `500`

**Notes for iOS:** After success, call `SessionManager.shared.logout()` and `KeychainHelper.deleteAll()`. Do NOT send `user_uuid` in body.

---

#### `POST /register_device` — Register FCM push token
**Auth:** Bearer token required
**Request:** `{ "push_token": "string (FCM token)" }`
**Response 201:** new device · **200:** token updated
**Notes for iOS:** Call after login AND after FCM SDK delivers a new/refreshed token. Required for all push notifications (friend requests, messages).

---

#### `POST /unregister_device` — Remove FCM push token
**Auth:** Bearer token required
**Request:** `{ "push_token": "string" }`
**Response 200:** `{ "message": "Device unregistered" }`
**Notes for iOS:** Call on logout before clearing the session token.

---

### Friends & Connections
All require `Authorization: Bearer <paseto_token>`.

#### `POST /get_friends` — Fetch accepted friends list
**Response 200:**
```json
{
  "friends": [
    {
      "user_uuid": "string",
      "username": "string",
      "identity_key_public": "string (hex X25519)",
      "registration_id": "integer",
      "is_online": true
    }
  ]
}
```
Refresh on: app foreground · FCM `FRIEND_REQUEST_ACCEPTED` push · pull-to-refresh.

---

#### `POST /friends/request` — Send friend request
**Rate limit:** 5/hour · **Request:** `{ "username": "string" }`
**Response 201:** `{ "status": "pending" }` · **200 (existing):** `{ "status": "pending"|"accepted" }`
**Errors:** `400` self/missing · `404` not found · `429` rate limit

---

#### `POST /friends/accept` — Accept pending request
**Request:** `{ "requester_uuid": "string" }`
**Response 200:** `{ "status": "accepted" }` · **Errors:** `400` missing · `404` no pending request

---

#### `POST /friends/remove` — Remove an accepted friend
**Auth:** Bearer token required
**Request:** `{ "friend_uuid": "string" }`
**Response 200:** `{ "message": "Friend removed" }`
**Errors:** `400` missing/self · `404` friendship not found · `401`
**Notes for iOS:** Remove locally from `FriendsStore.friends` optimistically. If `404`, sync list silently.

---

#### `POST /friends/accept_preview` — Accept private-account connection
**Request:** `{ "requester_uuid": "string" }`
**Response 200:** `{ "status": "accepted" }`
Used when the logged-in user has a **private account** and receives an FCM `CONNECTION_REQUEST` notification containing `requester_uuid` in the data payload.

---

### User Search
#### `POST /search_user` — Find a user by username
**Auth:** Required · **Rate limit:** 5/hour · **Request:** `{ "username": "string" }`

**Response (public user):** `{ "user_uuid": "string", "username": "string", "private": 0 }`
**Response (private user):** `{ "private": 1, "status": "notified" }` — UUID hidden, FCM sent to them
**Response (existing relationship):** `{ "status": "pending"|"accepted" }`
**Errors:** `400` self-search · `404` not found · `429` rate limit

---

### Message Relay
All require `Authorization: Bearer <paseto_token>`.

> **Zero-knowledge relay:** The iOS client encrypts with Double Ratchet. The server receives only padded ciphertext, stores it in Firestore, and delivers it. The server never sees plaintext.

#### `POST /messages/send` — Send an encrypted message
**Request:**
```json
{
  "recipient_uuid": "string",
  "ciphertext": "string (base64-encoded, exactly 1024 bytes when decoded)"
}
```
**Response 201:** `{ "message_id": "string (UUID)" }`
**Errors:** `400` invalid JSON / wrong payload size / invalid base64 · `404` recipient not found · `401`

**Notes for iOS:**
- Pad the Signal Protocol wire frame to exactly **1024 bytes** before base64-encoding. This defeats traffic analysis — every message looks identical on the wire.
- Server writes to Firestore and sends FCM `NEW_MESSAGE` to recipient.
- ⚠️ **Bug:** `notifications.py::notify_new_message()` has a `NameError` that will crash the server on every send. **This endpoint is broken until the server bug is fixed.** See Open Question Q6.

---

#### `GET /messages` — Fetch all pending messages
**Response 200:**
```json
{
  "messages": [
    {
      "message_id": "string",
      "sender_uuid": "string",
      "ciphertext": "string (base64)",
      "created_at": "string (ISO-8601)"
    }
  ]
}
```
**Notes for iOS:** Fetch on app launch, app foreground, and FCM `NEW_MESSAGE`. Messages are oldest-first. After decrypting successfully, call `POST /messages/ack` to delete from server.

> **Architecture decision (Q7):** For real-time chat, iOS writes encrypted messages **directly to Firestore** via the Firebase iOS SDK. `POST /messages/send` is the fallback for non-real-time scenarios. See Chat Screen architecture below.

---

#### `DELETE /messages/<message_id>` — Delete a single message
**Auth:** Bearer token required
**Response 200:** `{ "message": "Message deleted" }` · **403** not recipient · **404** not found

---

#### `POST /messages/ack` — Batch delete after successful decryption
**Auth:** Bearer token required
**Request:** `{ "message_ids": ["uuid1", "uuid2"] }`
**Response 200:** `{ "deleted": 5, "not_found": 0, "forbidden": 0 }`
**Notes for iOS:** Call after successfully decrypting all messages in a batch. Max 500 IDs per call.

---

### End-to-End Encryption (Signal Protocol)
All require `Authorization: Bearer <paseto_token>`.

#### `POST /keys/upload` — Upload pre-key bundle
**Request:**
```json
{
  "signed_pre_key": {
    "key_id": 123,
    "public_key": "hex (X25519)",
    "signature": "hex (Ed25519 signature over public_key)"
  },
  "one_time_pre_keys": [
    { "key_id": 1, "public_key": "hex (X25519)" }
  ],
  "identity_key_ed25519_public": "hex (optional — enables SPK signature verification)"
}
```
**Response 201:** `{ "message": "Pre-keys uploaded", "otpk_count": 10 }`
**Errors:** `400` missing SPK / bad signature · `404` user not found · `409` duplicate key_id

Call immediately after `create_user` using the token from the 201 response. Generate 1 SPK + 10–20 OTPKs. Store ALL private keys in Keychain.

---

#### `GET /keys/bundle/<target_uuid>` — Fetch recipient's key bundle for X3DH
**Response 200:**
```json
{
  "user_uuid": "string",
  "identity_key_public": "hex (X25519, 32 bytes)",
  "registration_id": "integer",
  "signed_pre_key": { "key_id": 123, "public_key": "hex", "signature": "hex" },
  "one_time_pre_key": { "key_id": 7, "public_key": "hex" },
  "otpk_remaining": 14,
  "kem_public_key": "hex (ML-KEM-768 public key, 1184 bytes) or null for pre-PQC accounts"
}
```
`one_time_pre_key` may be `null`. **Always verify the SPK signature** before proceeding — an unverified key is a MITM attack vector. If `otpk_remaining < 5`, replenish in background. If `kem_public_key` is non-null, perform hybrid X3DH with KEM encapsulation.

---

#### `POST /keys/replenish` — Replenish OTPK pool
**Request:** `{ "one_time_pre_keys": [{ "key_id": 20, "public_key": "hex" }] }`
**Response 201:** `{ "message": "OTPKs replenished", "count": 10 }`

---

## Cryptographic Wire Format

Signal Protocol message envelope written to **Firestore** directly by the iOS client (and also served via `GET /messages` for non-real-time delivery). All envelopes are padded to exactly **1024 bytes** before base64-encoding.

```json
{
  "version": 1,
  "sender_uuid": "string",
  "x3dh_header": {
    "ik_public": "hex (sender's X25519 identity key)",
    "ek_public": "hex (sender's X25519 ephemeral key)",
    "spk_id": 123,
    "otpk_id": 7,
    "kem_ciphertext": "hex (ML-KEM-768 encapsulated key, 1088 bytes) — omit for pre-PQC recipients"
  },
  "ratchet_header": {
    "dh_public": "hex (sender's current X25519 ratchet key)",
    "pn": 0,
    "n": 0
  },
  "ciphertext": "hex (Double Ratchet output, AES-256-GCM)",
  "nonce": "hex (12 bytes, AES-256-GCM)",
  "tag": "hex (16 bytes, GCM auth tag)"
}
```

`x3dh_header` is present **only on the first message** of a new session. All subsequent messages omit it.

### Hybrid X3DH Key Agreement (with ML-KEM)

When `kem_public_key` is non-null in the recipient's bundle:
1. Compute classical DH outputs `DH1…DH4` as per standard X3DH (X25519)
2. Encapsulate against `kem_public_key`: `(kem_ciphertext, KEM_SS) = MLKem768PublicKey.encapsulate()`
3. Combine: `SK = HKDF-SHA256(DH1 || DH2 || DH3 || DH4 || KEM_SS, info="kyberchat-x3dh")`
4. Include `kem_ciphertext` in `x3dh_header`

Receiver decapsulates with `MLKem768.PrivateKey(seed: kemSeed).decapsulate(kem_ciphertext)` to recover `KEM_SS`, then derives `SK` identically.

### Message Relay Architecture (Q7 Decision)
- **Real-time chat:** iOS writes encrypted envelopes **directly to Firestore** using the Firebase iOS SDK. Recipient subscribes via `addSnapshotListener`. Low-latency.
- **Fallback / server-side:** `POST /messages/send` + `GET /messages` via Cloud Run for non-Firestore-connected clients or server-triggered scenarios.
- FCM `NEW_MESSAGE` is sent by the server after `POST /messages/send`. For direct Firestore writes, the sender should trigger FCM via a Cloud Function or include it in a batch write.

---

## Screen Implementation Tasks

> *"It's time to be a hero!"*

---

### Screen 1 — Login Screen
**File:** `LoginView.swift` (exists — needs hardening)

- [ ] **1.1 — Keychain token persistence**
  Store PASETO token in Keychain: service `"kyberchat"`, account `"authToken"`. Store `user_uuid` + `username` in `UserDefaults`. Create `KeychainHelper` and `SessionManager` (see Shared Infrastructure).

- [ ] **1.2 — Auto-login on launch**
  In `ContentView.onAppear`, check Keychain for token. If present, navigate directly to `FriendsListView`. Implement via `SessionManager` observable.

- [ ] **1.3 — Centralized 401 handling**
  `SessionManager` clears Keychain + UserDefaults on any `401` and emits navigation event to route back to `LoginView` with message "Session expired. Please log in again."

- [ ] **1.4 — Loading UX**
  `ProgressView` in button while in-flight. Disable all inputs during request.

- [ ] **1.5 — Keyboard handling**
  Username → password on Return. Password Return triggers login. Dismiss keyboard on background tap.

- [ ] **1.6 — Forgot password placeholder**
  Muted link: alert "Contact support to reset your password." (No server endpoint exists yet.)

---

### Screen 2 — Create Account Screen
**File:** `CreateAccountView.swift` (exists — fundamentally wrong key generation, must rework)

> ⚠️ **Critical:** The current code uses `UUID().uuidString` and `Curve25519.KeyAgreement.PrivateKey()` — both randomly generated and NOT recoverable. Per the project spec, keys must be **derived from a BIP39 mnemonic**. This entire flow needs to be redesigned. See Open Question Q8.

- [ ] **2.1 — BIP39 mnemonic generation**
  On Create Account tap: generate a 256-bit CSPRNG seed, derive a 24-word BIP39 mnemonic. Show it to the user on a dedicated "Backup Your Mnemonic" screen. User must confirm they've saved it before proceeding.

- [ ] **2.2 — Deterministic key derivation from mnemonic**
  From the mnemonic seed, derive via HKDF-SHA3-256:
  - `user_uuid` (deterministic from seed so account is recoverable)
  - X25519 identity key pair
  - Ed25519 signing key pair
  - ML-KEM-768 key pair (future — see PQC section)
  - `registration_id`

- [ ] **2.3 — Store master seed in Keychain with biometric protection**
  Store raw seed bytes in Keychain with `kSecAccessControlBiometryCurrentSet`. Never store derived private keys in UserDefaults.

- [ ] **2.4 — Use token from `create_user` 201 response**
  `create_user` now returns a PASETO token. Store it immediately. Call `POST /keys/upload` with this token — no extra login round-trip needed.

- [ ] **2.5 — Upload pre-key bundle**
  Add `APIService.uploadKeyBundle(signedPreKey:oneTimePreKeys:token:)`. After `createUser()` succeeds, generate SPK + 10 OTPKs and upload. On success, transition to `FriendsListView`.

- [ ] **2.6 — Confirm password + strength indicator**
  Second `PasswordFieldView` for confirm. Inline "Passwords do not match" error. Visual strength bar from shared `PasswordValidator`.

- [ ] **2.7 — Username availability check (UX enhancement)**
  Debounced `.onChange` (~500ms): call `POST /search_user`. Green checkmark / red X.

---

### Screen 3 — Change Password Screen
**File:** `ChangePasswordView.swift` (does not exist — create it)

- [ ] **3.1 — Create `ChangePasswordView.swift`**
  Three `PasswordFieldView` instances: Current · New · Confirm New. Save disabled until all non-empty and new passwords match.

- [ ] **3.2 — Add `changePassword()` to `APIService`**
  `changePassword(userUUID: String, oldPassword: String, newPassword: String) async throws`
  `401` → "Current password is incorrect." `404` → clear session.

- [ ] **3.3 — Shared `PasswordValidator`**
  Extract validation from `CreateAccountView` into `struct PasswordValidator` with `validate(_ pw: String) -> [PasswordRule]`. 5 rules: length > 6, uppercase, lowercase, digit, special char.

- [ ] **3.4 — Navigation entry point**
  Gear icon in `FriendsListView` toolbar → `SettingsView` → Change Password row.

- [ ] **3.5 — Success feedback**
  Brief confirmation then `dismiss()`. Clear all three fields.

---

### Screen 4 — Friends List Screen
**File:** `FriendsListView.swift` (does not exist — create it; replace `HomeView`)

- [ ] **4.1 — Create `FriendsListView.swift`**
  `List` with: username (bold), online dot (green/grey), `>` chevron. Pull-to-refresh (`.refreshable`).

- [ ] **4.2 — Add `getFriends()` to `APIService`**
  Returns `[Friend]`. `Friend` model: `user_uuid`, `username`, `identity_key_public`, `registration_id`, `is_online`.

- [ ] **4.3 — `FriendsStore` observable**
  `@Observable class FriendsStore`: `friends: [Friend]`, `isLoading: Bool`, `errorMessage: String?`. `loadFriends()` async. Inject via environment.

- [ ] **4.4 — Search / Add Friend flow**
  Toolbar search icon → `SearchUserView` sheet. Calls `POST /search_user`. Status-aware results:
  - Public, not yet friends → "Send Friend Request" → `POST /friends/request`
  - Private → "Request Sent" (read-only)
  - Existing friend → "Already Friends" badge
  - Pending → "Request Pending" badge
  - `429` → "Too many requests. Try again later."

- [ ] **4.5 — Pending requests UI**
  "Requests" section or badge count. Accept button → `POST /friends/accept` → refresh list.

- [ ] **4.6 — FCM-triggered refresh**
  On FCM push types `FRIEND_REQUEST`, `FRIEND_REQUEST_ACCEPTED`, `NEW_MESSAGE` → `loadFriends()`.

- [ ] **4.7 — Heartbeat timer**
  `Timer.publish(every: 90, on: .main, in: .common)` while `scenePhase == .active`. Calls `POST /update_auth`.

- [ ] **4.8 — Empty state**
  "No friends yet. Tap 🔍 to find someone to connect with."

---

### Screen 5 — Chat With Friend Screen
**File:** `ChatView.swift` (does not exist — create it)

> All blocking issues (Q1–Q7) resolved. Implement Signal Protocol correctly or not at all. Half-baked E2EE is worse than no E2EE.

**Message Flow (direct Firestore):**
```
Sender → Hybrid X3DH / Double Ratchet encrypt → pad to 1024 bytes → base64 → Firestore write
→ Cloud Function triggers FCM NEW_MESSAGE to recipient
Recipient → FCM wakes app → Firestore snapshot listener → decode + unpad + decrypt → display → POST /messages/ack
```

- [ ] **5.1 — Hybrid X3DH session init (sender)**
  1. `GET /keys/bundle/<friend_uuid>` → `KeyBundle`
  2. Verify SPK signature — abort if invalid
  3. Classical X3DH: compute `DH1…DH4` using X25519
  4. If `bundle.kem_public_key != nil`: encapsulate → `(kem_ciphertext, KEM_SS) = MLKem768PublicKey.encapsulate()`
  5. `SK = HKDF-SHA256(DH1 || DH2 || DH3 || DH4 || KEM_SS, info="kyberchat-x3dh")`
  6. Include `kem_ciphertext` in `x3dh_header`
  7. Persist `RatchetSession` to SwiftData

- [ ] **5.2 — Hybrid X3DH session init (receiver)**
  On first message with `x3dh_header`:
  1. Look up private keys from Keychain by `key_id`
  2. Compute `DH1…DH4` (X25519)
  3. If `x3dh_header.kem_ciphertext` present: `KEM_SS = MLKem768.PrivateKey(seed: kemSeed).decapsulate(kem_ciphertext)`
  4. Derive `SK` via same HKDF formula
  5. Delete consumed OTPK private key from Keychain

- [ ] **5.3 — Double Ratchet in Swift**
  Implement to match `e2e.py` exactly:
  - DH ratchet: X25519 + HKDF-SHA256 → new root key + chain key
  - Chain key step: HMAC-SHA256 (0x01 for msg key, 0x02 for next chain key)
  - Encryption: AES-256-GCM, 12-byte nonce, 16-byte tag
  - Out-of-order tolerance: cache up to 1000 skipped message keys
  - Wire format: matches `encrypt_message()` / `decrypt_message()` in `e2e.py`

- [ ] **5.4 — 1024-byte padding**
  `MessagePadder.pad(_ data: Data, to: 1024) -> Data` and `.unpad()`. Applied after Signal encrypt (send) and before Signal decrypt (receive).

- [ ] **5.5 — Message fetch and decrypt loop**
  `GET /messages` → for each message: look up session for `sender_uuid`, decrypt, update+persist session, display. Handle first-message `x3dh_header` vs ongoing session.

- [ ] **5.6 — Chat UI**
  Bubble layout: own messages right (blue), received left (grey). `ScrollViewReader` auto-scroll. Compose bar with TextField + send. Optimistic local insert on send.

- [ ] **5.7 — Ratchet session persistence**
  Serialize `RatchetSession` to JSON after every encrypt/decrypt. Store in SwiftData. Match field names with server's `serialise()` for interoperability.

- [ ] **5.8 — OTPK replenishment**
  If `otpk_remaining < 5` after bundle fetch: generate 10 OTPKs, call `POST /keys/replenish` in background `Task`.

- [ ] **5.9 — FCM `NEW_MESSAGE` handler**
  Trigger `GET /messages` and decrypt loop.

---

## Shared Infrastructure Tasks

Build these early — they are used across all screens.

| Component | Description |
|---|---|
| `KeychainHelper` | Read/write/delete wrapper around `Security` framework. Service `"kyberchat"`. |
| `SessionManager` | `@Observable` auth state: `token`, `userUUID`, `username`. Owns Keychain I/O. Emits 401 event for navigation. |
| `APIService` hardening | Centralize 401 handling. 15s timeout. PASETO tokens are opaque — no decode. |
| `PasswordValidator` | `struct` with `validate(_ pw: String) -> [PasswordRule]`. 5 rules. |
| `HeartbeatService` | Starts/stops timer based on `scenePhase`. Calls `POST /update_auth`. |
| `MnemonicService` | BIP39 generation, seed derivation, key derivation. Core of account identity. |
| `MessagePadder` | `pad(_ data: Data, to: Int) -> Data` and `unpad()`. Used in chat send/receive. |
| Firebase setup | `FirebaseApp.configure()` in `kyberchatApp.swift`. Register for remote notifications. Handle FCM token — see Open Question Q1. |

---

## Open Questions & Design Issues

> *"This is not a plot hole; this is a vacuum of logic that we must fill!"*

All nine questions have been resolved. Decisions documented below for reference.

---

### ✅ Q1 — Device token registration — RESOLVED
**Decision:** `POST /register_device` and `POST /unregister_device` endpoints added to server (`devices.py`). Call `register_device` after every login and after Firebase delivers a new/refreshed FCM token. Call `unregister_device` before logout.

---

### ✅ Q2 — Message deletion — RESOLVED
**Decision:** `DELETE /messages/<id>` and `POST /messages/ack` added to server (`messages.py`). Call `POST /messages/ack` with all successfully decrypted message IDs after each fetch batch. Max 500 IDs per batch.

---

### ✅ Q3 — `/friends/remove` endpoint — RESOLVED
**Decision:** `POST /friends/remove` added to server (`friends.py`). Deletes friendship in both directions.

---

### ✅ Q4 — `POST /update_auth` auth — RESOLVED
**Decision:** Bearer token auth added. `user_uuid` no longer sent in body — derived from token server-side.

---

### ✅ Q5 — `change_password` / `delete_user` auth — RESOLVED
**Decision:** Bearer token auth added to both endpoints as defense-in-depth. Password still required. `user_uuid` no longer sent in body.

---

### ✅ Q6 — `notify_new_message()` crash bug — FIXED
**Decision:** `notifications.py` fixed. Removed undefined variable references (`requester_uuid`, `target_is_online`). Now sends only a silent FCM data message: `{ type: "NEW_MESSAGE" }`. `POST /messages/send` is unblocked.

---

### ✅ Q7 — Message relay architecture — RESOLVED
**Decision:** iOS clients write encrypted envelopes **directly to Firestore** for real-time delivery. Server `POST /messages/send` / `GET /messages` remain as fallback. Firebase iOS SDK is responsible for real-time `addSnapshotListener`. A Cloud Function should trigger FCM for direct Firestore writes (sender-side).

---

### ✅ Q8 — BIP39 mnemonic key derivation — RESOLVED
**Decision:** All identity material is deterministically derived from the BIP39 mnemonic seed:
- `user_uuid` derived via `HKDF(seed, info="kyberchat-uuid")` — fully recoverable
- Identity key, signing key, registration ID, KEM seed — all HKDF-derived
- User is shown the 24-word phrase on registration and warned: **"If you lose these words, you lose your account."**
- `MnemonicService.swift` + `BIP39Wordlist.swift` + `KeychainHelper.swift` implement the full stack. No external BIP39 library needed.

---

### ✅ Q9 — ML-KEM-768 integration — IN PROGRESS (v1)
**Decision:** ML-KEM-768 is a v1 feature. Using **`swift-crypto 3.3+`** (Apple's library, `import Crypto`). Add via SPM: `https://github.com/apple/swift-crypto` (tag ≥ 3.3.0).

**Completed work:**
- Server: `kem_public_key BLOB NULL` column added to `users` table (migration `001_add_kem_public_key.sql`)
- Server: `POST /create_user` accepts optional `kem_public_key` (1184 bytes hex)
- Server: `GET /keys/bundle/<uuid>` returns `kem_public_key`
- iOS: `MnemonicService.kemPublicKeyHex(from:)` generates ML-KEM public key from 64-byte seed
- iOS: `KeychainAccount.kemPrivateKeySeed` stores the seed
- iOS: `CreateAccountView` generates and registers `kem_public_key` on account creation
- iOS: `APIService.KeyBundle` now includes `kem_public_key: String?`

**Remaining work:**
- Add `swift-crypto 3.3+` SPM dependency in Xcode (required before building)
- Implement hybrid X3DH in `ChatView` (encapsulation on send, decapsulation on receive)
- Add `kem_ciphertext` to `x3dh_header` in wire format

---

## Engineering Standards

> *"A hero must wield their power wisely!"*

- **Never** store cryptographic private keys outside Keychain. Not UserDefaults, not SwiftData, not logs.
- **Never** log tokens, passwords, private keys, or plaintext messages — not even in DEBUG.
- **Always** verify SPK signatures before trusting a key bundle.
- **Always** handle `401` centrally in `SessionManager` — never scatter session cleanup across views.
- PASETO tokens are **opaque** — do not decode or inspect client-side.
- Use `async/await` throughout. No completion handler callbacks.
- Use `@Observable` (iOS 17+) consistently. Do not mix with `ObservableObject`.
- One `APIService.shared` actor instance.
- All user-facing error messages must be human-readable. No raw HTTP codes or stack traces.
- Test the unhappy paths: `401`, `404`, `429`, network timeout, malformed response.
- Crypto operations off the main thread — use actors or background `Task`.

---

*"The true measure of a hero is not how they celebrate victory, but how they handle defeat."*
*SPOON!* 🥄
