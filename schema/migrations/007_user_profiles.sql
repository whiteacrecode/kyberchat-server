-- Migration 007: user_profiles table
--
-- Stores optional profile display data for each user.
-- All columns nullable — a user may have an account without filling in profile.
-- The avatar image is NOT stored here; it lives in Firestore at
-- profiles/{user_uuid} as a base64-encoded 100×100 JPEG blob so the iOS/
-- Android clients can read it directly without a server round-trip.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 007_user_profiles.sql

USE e2e_chat_service;

CREATE TABLE IF NOT EXISTS user_profiles (
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
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);
