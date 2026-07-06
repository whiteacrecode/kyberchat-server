CREATE DATABASE IF NOT EXISTS e2e_chat_service;
USE e2e_chat_service;

-- 1. Users Table
-- Stores basic identity. No PII (Email/Phone) as per requirements.
CREATE OR REPLACE TABLE users (
    user_uuid CHAR(36) PRIMARY KEY, -- Generated deterministically on client from BIP39 mnemonic seed
    username VARCHAR(50) UNIQUE NOT NULL, -- Human readable ID
    identity_key_public BLOB NOT NULL, -- Long-term X25519 Identity Public Key (IK), 32 bytes
    registration_id INT NOT NULL, -- Signal-specific ID for the device
    -- Argon2id hash (time_cost=3, memory_cost=65536, parallelism=4).
    -- One-way: irrecoverable by users or service operators.
    password_hash VARCHAR(255) NOT NULL,
    -- ML-KEM-768 post-quantum public key (1184 bytes). NULL for pre-PQC accounts.
    -- Populated on registration by clients with swift-crypto 3.3+ installed.
    kem_public_key BLOB NULL,
    private INT NOT NULL DEFAULT 0,  -- 0 = public (discoverable), 1 = private
    deleted INT NOT NULL DEFAULT 0,  -- 0 = active, 1 = soft-deleted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 2. Signed Pre-Keys Table
-- Medium-term keys signed by the Identity Key. Rotated periodically.
CREATE OR REPLACE TABLE signed_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL, -- Client-side identifier for the key
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL, -- Signature of the public key using IK
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (user_uuid)
);

-- 3. One-Time Pre-Keys Table
-- A pool of keys consumed when someone starts a chat with this user.
-- This is critical for "Asynchronous" key exchange.
CREATE OR REPLACE TABLE one_time_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    is_consumed BOOLEAN DEFAULT FALSE, -- Set to TRUE once a peer uses it
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (user_uuid, is_consumed)
);

-- 4. Devices/Sessions Table
-- Tracks FCM push tokens per user. Supports multiple devices (multi-device).
-- Notifications are always sent to the token with the most recent updated_at.
CREATE OR REPLACE TABLE user_devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    push_token VARCHAR(255) NOT NULL,           -- FCM registration token
    platform ENUM('ios', 'android') NULL,       -- NULL until client sends platform field
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL               -- Last token refresh / heartbeat
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Prevent duplicate (user, token) rows that can accumulate from repeated registrations
    UNIQUE KEY unique_user_token (user_uuid, push_token),
    INDEX (user_uuid)
);

-- 5. Friends Table
-- Tracks friendship relationships between users.
-- A row exists for each directional request: requester -> addressee.
-- status='accepted' means mutual friendship (both sides use this single row).
CREATE OR REPLACE TABLE friends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requester_uuid CHAR(36) NOT NULL,   -- user who sent the friend request
    addressee_uuid CHAR(36) NOT NULL,   -- user who received the friend request
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (addressee_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    UNIQUE KEY unique_friendship (requester_uuid, addressee_uuid),
    INDEX (requester_uuid, status),
    INDEX (addressee_uuid, status)
);

-- 6. Recovery Blobs Table
-- Client-side encrypted keychain backups. The server stores opaque ciphertext
-- and the KDF parameters needed for the client to derive its wrap key from a
-- password — it never sees plaintext key material and cannot decrypt the blob.
--
-- Blob plaintext (JSON, only the client sees this):
--   { v, u, ms, ik, sk, kem, spk?: {id, priv}, otpks: [{id, priv}, ...] }
--
-- The wrap key is AES-256, derived via PBKDF2-HMAC-SHA256(password, kdf_salt,
-- kdf_iters). Ciphertext is AES-256-GCM (auth tag appended).
--
-- Compromise of this row alone does not yield key material — an attacker must
-- still mount an offline PBKDF2 brute-force against the user's password.
CREATE OR REPLACE TABLE recovery_blobs (
    user_uuid     CHAR(36)      NOT NULL PRIMARY KEY,
    blob_version  INT           NOT NULL DEFAULT 1, -- plaintext schema version (client-controlled)
    ciphertext    LONGBLOB      NOT NULL,           -- AES-256-GCM ciphertext + 16-byte tag appended
    nonce         VARBINARY(12) NOT NULL,           -- AES-GCM nonce, fresh per upload
    kdf_algo      VARCHAR(64)   NOT NULL DEFAULT 'pbkdf2-sha256',
    kdf_iters     INT           NOT NULL,           -- server enforces minimum (100000)
    kdf_salt      VARBINARY(32) NOT NULL,           -- 16 bytes today; column allows future KDFs
    created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP     NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

-- 7. Messages Table
-- Stores encrypted message payloads. The server operates as an opaque relay.
CREATE OR REPLACE TABLE messages (
    message_id     CHAR(36)     PRIMARY KEY,
    sender_uuid    CHAR(36)     NOT NULL,
    recipient_uuid CHAR(36)     NOT NULL,
    ciphertext     TEXT         NOT NULL, -- base64-encoded, exactly 1024 bytes decoded
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_uuid)    REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (recipient_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (recipient_uuid, created_at)
);

-- 8. User Profiles Table
-- Stores optional profile display data for each user.
-- All columns nullable — a user may have an account without filling in profile.
CREATE OR REPLACE TABLE user_profiles (
    user_uuid  CHAR(36)     NOT NULL PRIMARY KEY,
    first_name VARCHAR(64)  NULL DEFAULT NULL,
    last_name  VARCHAR(64)  NULL DEFAULT NULL,
    -- email is stored here for display purposes only; it is not used for login.
    -- Users may leave it blank.
    email      VARCHAR(254) NULL DEFAULT NULL,
    phone      VARCHAR(30)  NULL DEFAULT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP    NOT NULL
                   DEFAULT CURRENT_TIMESTAMP
                   ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX idx_user_profiles_email (email),
    INDEX idx_user_profiles_phone (phone)
);

-- 9. Media Uploads Table
-- Tracks GCS ciphertext blobs issued for encrypted audio/video attachments
-- (Phase 1 of the A/V messaging feature).
CREATE OR REPLACE TABLE media_uploads (
    -- Unique identifier for this blob; doubles as the GCS object name suffix.
    blob_id            CHAR(36)                  NOT NULL,

    -- The user who requested the upload URL (and whose token must be used to
    -- issue download URLs, or to delete the blob).
    owner_uuid         CHAR(36)                  NOT NULL,

    -- Broad media category — drives size caps and client-side rendering hints.
    media_type         ENUM('audio', 'video')    NOT NULL,

    -- MIME type declared by the client (e.g. 'audio/m4a', 'video/mp4').
    -- Stored for client rendering hints; not enforced server-side.
    mime_type          VARCHAR(128)              NOT NULL DEFAULT 'application/octet-stream',

    -- Byte count declared by the client at upload-url request time.
    -- The server enforces a cap on this value; the actual GCS object size may
    -- differ (the client controls the PUT).  A future sweeper can compare
    -- declared vs. actual sizes via GCS object metadata.
    declared_byte_size INT UNSIGNED              NOT NULL,

    -- Full GCS object path, e.g. "media/<uuid>".  Stored so the signed-URL
    -- issuer and sweeper do not need to reconstruct it from blob_id.
    gcs_object         VARCHAR(512)              NOT NULL,

    -- When the blob should be considered stale.  The sweeper uses this to find
    -- objects that can be deleted from GCS and marked deleted here.
    expires_at         TIMESTAMP                 NOT NULL,

    -- Soft-delete flag.  Set to 1 by DELETE /media/<blob_id> or the sweeper.
    -- Rows are never hard-deleted so that the sweeper can audit its own work.
    deleted            TINYINT(1)                NOT NULL DEFAULT 0,

    created_at         TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (blob_id),
    FOREIGN KEY (owner_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,

    -- Fast lookup of all blobs owned by a user (for quota / list endpoints).
    INDEX idx_owner (owner_uuid),

    -- Sweeper query: find expired, non-deleted blobs.
    INDEX idx_expires (expires_at, deleted)
);

-- 10. Kybergroups Table
-- One row per group chat. `owner_uuid` is the creator; ownership does not
-- currently transfer. See GROUP_PLAN.md for the full group-chat design.
-- Named `kybergroups`, not `groups` — GROUPS is a reserved word in MySQL 8.
CREATE OR REPLACE TABLE kybergroups (
    group_uuid          CHAR(36)     PRIMARY KEY, -- client-generated UUID v4
    group_name          VARCHAR(100) NOT NULL,
    owner_uuid          CHAR(36)     NOT NULL,
    description         VARCHAR(500) NULL,
    searchable          TINYINT(1)   NOT NULL DEFAULT 0,
    message_ttl_seconds INT          NULL,
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted             INT          NOT NULL DEFAULT 0, -- 0 = active, 1 = soft-deleted
    FOREIGN KEY (owner_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Narrows the scan for POST /groups/search before the LIKE match on
    -- group_name/description (neither of which can use a plain B-tree index
    -- for a leading-wildcard LIKE).
    INDEX idx_kybergroups_searchable (searchable)
);

-- 11. Group Members Table
-- Membership roster, metadata only — no sender keys or message content.
-- Mirrored into Firestore (groups/{groupId}.members) via the Firebase Admin
-- SDK on every mutation, since Firestore security rules cannot query MySQL.
CREATE OR REPLACE TABLE group_members (
    group_uuid  CHAR(36)               NOT NULL,
    user_uuid   CHAR(36)               NOT NULL,
    role        ENUM('owner','member') NOT NULL DEFAULT 'member',
    joined_at   TIMESTAMP              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_uuid, user_uuid),
    FOREIGN KEY (group_uuid) REFERENCES kybergroups(group_uuid) ON DELETE CASCADE,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Fast lookup of "which groups is user X in" for /get_groups.
    INDEX idx_user (user_uuid)
);

-- 12. Group Invites Table
-- Pending group invites. A row here means invitee_uuid has been invited to
-- group_uuid and has not yet responded. Both accept and decline delete the
-- row outright (mirrors friends.decline_friend_request) — there is no
-- retained "declined" state, so the same user can be re-invited later.
CREATE OR REPLACE TABLE group_invites (
    group_uuid   CHAR(36)  NOT NULL,
    invitee_uuid CHAR(36)  NOT NULL,
    inviter_uuid CHAR(36)  NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_uuid, invitee_uuid),
    FOREIGN KEY (group_uuid) REFERENCES kybergroups(group_uuid) ON DELETE CASCADE,
    FOREIGN KEY (invitee_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (inviter_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Fast lookup of "which invites are waiting for me" for /groups/invites/pending.
    INDEX idx_invitee (invitee_uuid)
);

