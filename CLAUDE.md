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

The cloud run endpoint url is https://quantchat-server-1078066473760.us-central1.run.app