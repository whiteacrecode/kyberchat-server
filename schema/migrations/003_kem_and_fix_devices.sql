-- Migration 003: ML-KEM-768 public key + user_devices schema fixes
-- Run this against an existing database to bring it up to date with schema.sql.
-- Prerequisites: migrations 001 (add_friends) and 002 (add_private) must have run.
--
-- Changes:
--   1. users.kem_public_key   — ML-KEM-768 post-quantum public key (1184 bytes).
--                               NULL for legacy accounts registered before this migration.
--                               New iOS clients always populate it on /create_user.
--   2. user_devices.platform  — Make nullable (was NOT NULL without a DEFAULT, causing
--                               INSERT failures in devices.py which omits the column).
--   3. user_devices.updated_at — Add a proper update-tracking column. The old code
--                               incorrectly mutated `created_at` for token refresh;
--                               devices.py should now update this column instead.
--   4. user_devices UNIQUE KEY — Prevent duplicate (user_uuid, push_token) rows from
--                               race conditions. Matches the check-then-insert pattern
--                               in POST /register_device.

USE e2e_chat_service;

-- 1. ML-KEM-768 public key on users
--    Mirrors cloudrun/migrations/001_add_kem_public_key.sql, which was applied
--    to the Cloud SQL instance directly. This migration brings schema/schema.sql
--    into sync so both migration paths are consistent.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS kem_public_key BLOB NULL
    COMMENT 'ML-KEM-768 public key (1184 bytes). NULL for pre-PQC accounts registered before this migration.';

-- 2. Make user_devices.platform nullable so existing INSERT queries work.
--    The column is preserved for future multi-platform device management;
--    devices.py can set it once the client sends a platform field.
ALTER TABLE user_devices
    MODIFY COLUMN platform ENUM('ios', 'android') NULL DEFAULT NULL
    COMMENT 'Device platform. NULL if not supplied (e.g. current iOS client). Populate once platform detection is added to /register_device.';

-- 3. Add updated_at for proper token-refresh tracking.
--    The previous workaround mutated created_at (semantically wrong).
--    After this migration, devices.py should UPDATE updated_at on token refresh.
ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
    COMMENT 'Last time this device was seen (token refresh). Use for ORDER BY to pick the most-recently-active token.';

-- Backfill updated_at from created_at for existing rows
UPDATE user_devices SET updated_at = created_at WHERE updated_at = '0000-00-00 00:00:00' OR updated_at IS NULL;

-- 4. Unique constraint to prevent duplicate device rows.
--    Matches the SELECT-then-INSERT upsert pattern in POST /register_device.
--    On conflict the UPDATE path runs instead of a duplicate INSERT.
ALTER TABLE user_devices
    ADD CONSTRAINT IF NOT EXISTS unique_user_token UNIQUE KEY (user_uuid, push_token);
