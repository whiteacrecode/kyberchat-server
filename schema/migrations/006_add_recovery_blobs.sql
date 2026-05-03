-- Migration 002: Add recovery_blobs table for client-side encrypted key backup.
-- Run once on Cloud SQL before deploying the updated server.
--
-- Stores opaque ciphertext + KDF parameters only. The server never sees plaintext
-- key material and cannot decrypt the blob. The client wraps the keychain dump
-- with AES-256-GCM under a key derived from the user's password via PBKDF2.
--
-- Threat model:
--   * Server compromise reveals only ciphertext + per-blob KDF params + per-user
--     salt. An attacker still needs the user's password to mount an offline
--     attack, and PBKDF2 cost (>=100k iters enforced server-side, 600k default
--     on iOS) is intended to make that prohibitively expensive.
--   * The fk_recovery_user FK ensures the row is purged when the user is hard-
--     deleted (soft-delete leaves the blob in place — the client may want to
--     restore the account).
--
-- Idempotent? No — fails on rerun because of the table create. Wrap in a
-- transaction or check INFORMATION_SCHEMA before running if you need that.

CREATE TABLE recovery_blobs (
    user_uuid     CHAR(36)    NOT NULL PRIMARY KEY,
    blob_version  INT         NOT NULL DEFAULT 1
        COMMENT 'Plaintext schema version (client-controlled). Bump when blob shape changes.',
    ciphertext    LONGBLOB    NOT NULL
        COMMENT 'AES-256-GCM ciphertext (includes the 16-byte auth tag appended).',
    nonce         VARBINARY(12) NOT NULL
        COMMENT '12-byte AES-GCM nonce. Fresh per upload.',
    kdf_algo      VARCHAR(64) NOT NULL DEFAULT 'pbkdf2-sha256'
        COMMENT 'KDF identifier. Allowlisted server-side; today only pbkdf2-sha256.',
    kdf_iters     INT         NOT NULL
        COMMENT 'PBKDF2 iteration count. Server enforces a minimum (currently 100000).',
    kdf_salt      VARBINARY(32) NOT NULL
        COMMENT 'Per-blob random salt. 16 bytes today; column allows up to 32 for future KDFs.',
    created_at    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_recovery_user
        FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
)
COMMENT 'Client-encrypted keychain backups. Server is opaque storage only.';
