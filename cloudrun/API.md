# KyberChat Server API Reference

**Base URL:** `https://quantchat-server-1078066473760.us-central1.run.app`

All request and response bodies are JSON. All binary values (keys, signatures) are **lowercase hex strings**.

---

## Authentication

Most endpoints require a **PASETO v4.local** Bearer token obtained from `/validate_login`.

```
Authorization: Bearer <token>
```

Tokens use **PASETO v4.local** (XChaCha20-Poly1305 + BLAKE2b symmetric AEAD). The payload is encrypted — clients treat the token as an opaque string and must not attempt to decode it. Tokens expire after **7 days**. A new token is issued on each successful login.

> **Migration note:** PASETO tokens are not compatible with the previous JWT tokens. Existing sessions are invalidated on server deploy; users must log in again.

---

## User Management

### `POST /create_user`

Register a new user account. Call this once after generating the user's identity key pair on-device.

**Request body:**
```json
{
  "user_uuid":           "string (UUID v4, client-generated)",
  "username":            "string (unique, max 50 chars)",
  "password":            "string",
  "identity_key_public": "string (hex — X25519 public key)",
  "registration_id":     "integer (Signal device registration ID)"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `201` | `{"message": "User created successfully", "user_uuid": "<uuid>"}` |
| `400` | `{"error": "Missing field: <field>"}` or `{"error": "identity_key_public must be a valid hex string"}` |
| `409` | `{"error": "Username or UUID already exists"}` |

---

### `POST /validate_login`

Authenticate a user and receive a JWT token. Returns a generic error for both wrong username and wrong password to prevent username enumeration.

**Request body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `200` | `{"message": "User found", "user": { "user_uuid": "...", "username": "...", "registration_id": 123, "created_at": "ISO8601" }, "token": "<paseto>"}` |
| `400` | `{"error": "Missing username or password"}` |
| `401` | `{"error": "Invalid username or password"}` |

---

### `POST /update_auth`

Update the authenticated user's `last_seen` timestamp. Call this periodically (e.g. on app foreground) to maintain online status. Does **not** require a Bearer token — passes `user_uuid` in the body.

**Request body:**
```json
{
  "user_uuid": "string"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `200` | `{"message": "Auth updated successfully"}` |
| `400` | `{"error": "Missing user_uuid"}` |
| `404` | `{"error": "User not found"}` |

---

### `POST /delete_user`

Soft-delete the user's account. Requires password confirmation.

**Request body:**
```json
{
  "user_uuid": "string",
  "password":  "string"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `200` | `{"message": "User deleted successfully"}` |
| `400` | `{"error": "Missing user_uuid or password"}` |
| `401` | `{"error": "Invalid password"}` |
| `404` | `{"error": "User not found"}` |

---

### `POST /change_password`

Change the user's password. Requires the current password.

**Request body:**
```json
{
  "user_uuid":    "string",
  "old_password": "string",
  "new_password": "string"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `200` | `{"message": "Password changed successfully"}` |
| `400` | `{"error": "Missing field: <field>"}` |
| `401` | `{"error": "Invalid password"}` |
| `404` | `{"error": "User not found"}` |

---

## Friends

All friends endpoints require `Authorization: Bearer <token>`.

### `POST /get_friends`

Fetch the authenticated user's accepted friends list. Each entry includes the public key material needed to initiate an X3DH session.

**Request body:** _(empty — identity comes from the JWT)_

**Response `200`:**
```json
{
  "friends": [
    {
      "user_uuid":           "string",
      "username":            "string",
      "identity_key_public": "string (hex — X25519)",
      "registration_id":     123,
      "is_online":           true
    }
  ]
}
```

`is_online` is `true` if the friend's `last_seen` is within the last 2 minutes.

---

### `POST /friends/request`

Send a friend request to another user by username. Rate-limited to **5 requests per hour** per user.

**Request body:**
```json
{
  "username": "string (target user's username)"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `201` | `{"status": "pending"}` — request created |
| `200` | `{"status": "<existing_status>"}` — relationship already exists (`pending` or `accepted`) |
| `400` | `{"error": "Missing username"}` or `{"error": "Cannot send a friend request to yourself"}` |
| `404` | `{"error": "User not found"}` |
| `429` | `{"error": "Rate limit exceeded. Try again later."}` |

The target user receives an FCM push notification with `data.type = "FRIEND_REQUEST"`.

---

### `POST /friends/accept`

Accept a pending friend request directed at the authenticated user.

**Request body:**
```json
{
  "requester_uuid": "string (UUID of the user who sent the request)"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `200` | `{"status": "accepted"}` |
| `400` | `{"error": "Missing requester_uuid"}` |
| `404` | `{"error": "No pending request found"}` |

The original requester receives a silent FCM data message with `data.type = "FRIEND_REQUEST_ACCEPTED"` so their friends list can refresh.

---

## E2E Key Management

All key endpoints require `Authorization: Bearer <token>`.

These endpoints implement the server-side key directory for the **Signal Protocol (X3DH + Double Ratchet)**. Keys are exchanged via this API; all encryption and decryption happens on-device.

### `POST /keys/upload`

Upload a Signed Pre-Key (SPK) and a batch of One-Time Pre-Keys (OTPKs) after registration, or when rotating keys. The identity key is never changed here — it is fixed at registration.

Optionally provide `identity_key_ed25519_public` for the server to verify the SPK signature.

**Request body:**
```json
{
  "signed_pre_key": {
    "key_id":    123,
    "public_key": "string (hex — X25519)",
    "signature":  "string (hex — Ed25519 signature over SPK public key bytes)"
  },
  "one_time_pre_keys": [
    {"key_id": 1, "public_key": "string (hex — X25519)"},
    {"key_id": 2, "public_key": "string (hex — X25519)"}
  ],
  "identity_key_ed25519_public": "string (hex — optional, for SPK sig verification)"
}
```

**Responses:**
| Status | Body |
|--------|------|
| `201` | `{"message": "Pre-keys uploaded", "otpk_count": 10}` |
| `400` | `{"error": "Missing signed_pre_key"}` or `{"error": "SPK signature verification failed"}` |
| `404` | `{"error": "User not found"}` |
| `409` | `{"error": "Duplicate key_id"}` |

---

### `GET /keys/bundle/<target_uuid>`

Fetch a recipient's public key bundle to initiate an X3DH session. Atomically consumes one OTPK from the recipient's pool.

**Path parameter:** `target_uuid` — the recipient's UUID.

**Response `200`:**
```json
{
  "user_uuid":             "string",
  "identity_key_public":   "string (hex — X25519)",
  "registration_id":       123,
  "signed_pre_key": {
    "key_id":    456,
    "public_key": "string (hex — X25519)",
    "signature":  "string (hex — Ed25519)"
  },
  "one_time_pre_key": {
    "key_id":    7,
    "public_key": "string (hex — X25519)"
  },
  "otpk_remaining": 14
}
```

- `one_time_pre_key` is `null` if the recipient's OTPK pool is exhausted. X3DH is still possible without it, but forward secrecy for that session is reduced.
- `otpk_remaining` is a hint — if it falls below **5**, the recipient's client should call `/keys/replenish`.

**Responses:**
| Status | Body |
|--------|------|
| `200` | Bundle object (see above) |
| `404` | `{"error": "User not found"}` or `{"error": "No signed pre-key on file"}` |

---

### `POST /keys/replenish`

Top up the authenticated user's OTPK pool. Call this when `otpk_remaining` from a `/keys/bundle` response (for your own UUID) drops below 5, or proactively on app launch.

**Request body:**
```json
{
  "one_time_pre_keys": [
    {"key_id": 20, "public_key": "string (hex — X25519)"},
    {"key_id": 21, "public_key": "string (hex — X25519)"}
  ]
}
```

**Responses:**
| Status | Body |
|--------|------|
| `201` | `{"message": "OTPKs replenished", "count": 10}` |
| `400` | `{"error": "No keys provided"}` |

---

## Push Notifications (FCM)

The server sends FCM data messages to trigger client-side refreshes. No sensitive content is included in push payloads — no sender identity, username, or message content is ever present in a notification.

| `data.type` | Trigger | Client action |
|-------------|---------|---------------|
| `FRIEND_REQUEST` | Someone sent you a friend request | Fetch pending requests and update UI |
| `FRIEND_REQUEST_ACCEPTED` | Your friend request was accepted | Call `/get_friends` to refresh the list |
| `NEW_MESSAGE` | A new encrypted message is waiting | Call `GET /messages` to fetch and decrypt |

All `NEW_MESSAGE` and `FRIEND_REQUEST_ACCEPTED` notifications are **silent high-priority** data messages (`content-available: true` on iOS, `priority: high` on Android) — they wake the app without displaying a banner. `FRIEND_REQUEST` shows a standard push notification with the generic title *"New Invitation"* for offline users only.

---

## Messages

All message endpoints require `Authorization: Bearer <token>`.

The server relays **opaque encrypted blobs only** — it never sees plaintext. All encryption and decryption happens on-device using the Signal Protocol (X3DH + Double Ratchet). Messages are stored in **Firestore**.

### `POST /messages/send`

Store a 1024-byte E2EE ciphertext in Firestore and notify the recipient via FCM.

The fixed 1024-byte payload size is intentional — uniform-length ciphertexts prevent traffic-analysis attacks that would otherwise leak information about message length.

**Headers:** `Authorization: Bearer <token>`

**Request body:**
```json
{
  "recipient_uuid": "string (UUID of the recipient)",
  "ciphertext":     "string (base64 — exactly 1024 bytes when decoded)"
}
```

The `ciphertext` field must be a **base64-encoded 1024-byte blob**. This is the complete on-device encrypted payload (see [Message Wire Format](#message-wire-format) for the structure packed inside those 1024 bytes).

**Responses:**
| Status | Body |
|--------|------|
| `201` | `{"message_id": "<uuid>"}` |
| `400` | `{"error": "Missing field: <field>"}` or `{"error": "ciphertext must be valid base64"}` or `{"error": "ciphertext must be exactly 1024 bytes, got <n>"}` |
| `400` | `{"error": "Cannot send a message to yourself"}` |
| `404` | `{"error": "Recipient not found"}` |

The recipient receives a silent FCM data message with `data.type = "NEW_MESSAGE"`.

---

### `GET /messages`

Fetch all messages stored on the server that are addressed to the authenticated user, ordered oldest-first. Clients should delete messages locally after successful decryption.

**Headers:** `Authorization: Bearer <token>`

**Response `200`:**
```json
{
  "messages": [
    {
      "message_id":  "string (UUID)",
      "sender_uuid": "string (UUID)",
      "ciphertext":  "string (base64 — 1024 bytes when decoded)",
      "created_at":  "string (ISO-8601 UTC)"
    }
  ]
}
```

**Error responses:**
| Status | Body |
|--------|------|
| `401` | `{"error": "Missing or invalid Authorization header"}` / `{"error": "Token expired"}` / `{"error": "Invalid token"}` |
| `500` | `{"error": "Internal server error"}` |

---

## Message Wire Format

Messages are encrypted on-device and stored as documents in **Firestore**. The server never sees plaintext. The full wire frame written to Firestore is:

```json
{
  "version":     1,
  "sender_uuid": "string",
  "x3dh_header": {
    "ik_public": "string (hex)",
    "ek_public": "string (hex)",
    "spk_id":    123,
    "otpk_id":   7
  },
  "ratchet_header": {
    "dh_public": "string (hex)",
    "pn":        0,
    "n":         0
  },
  "ciphertext": "string (hex — AES-256-GCM ciphertext)",
  "nonce":      "string (hex — 12-byte GCM nonce)",
  "tag":        "string (hex — 16-byte GCM auth tag)"
}
```

- `x3dh_header` is present **only on the first message** of a new session. Omit it for all subsequent messages.
- `ratchet_header` is present on **every message**.
- The recipient's client must call `GET /keys/bundle/<sender_uuid>` before or during X3DH to obtain the sender's public keys for session bootstrapping.
