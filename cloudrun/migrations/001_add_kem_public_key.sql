-- Migration 001: Add ML-KEM-768 post-quantum public key to users table
-- Run once on Cloud SQL before deploying the updated server.
--
-- kem_public_key is NULL for existing users (classical-only).
-- New registrations will supply a 1184-byte ML-KEM-768 public key.
-- Once all clients are updated, enforce NOT NULL via migration 002.

ALTER TABLE users
    ADD COLUMN kem_public_key BLOB NULL
    COMMENT 'ML-KEM-768 public key (1184 bytes). NULL for pre-PQC accounts.';

-- Index is not needed — this column is fetched by primary key (user_uuid) only.
