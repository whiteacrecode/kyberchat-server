-- Migration 014: Add per-friend location sharing preference table
--
-- Adds the `location_share_prefs` table: a persistent, per-(user, friend)
-- toggle recording whether a user is willing to share their live location
-- with a specific friend.
--
-- This is distinct from `location_shares` (migration 012):
--   * location_shares       — ephemeral, time-boxed ACTIVE sessions (expire).
--   * location_share_prefs  — a durable preference the user sets once and that
--                             persists until they flip it back off.
--
-- Like every other location table this holds ZERO coordinates. It is pure
-- access-control metadata; the zero-knowledge model is preserved.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 014_add_location_share_prefs.sql

USE e2e_chat_service;

-- 14. Location Sharing Preferences Table
CREATE TABLE IF NOT EXISTS location_share_prefs (
    grantor_uuid  CHAR(36)   NOT NULL,   -- user who owns the preference
    friend_uuid   CHAR(36)   NOT NULL,   -- friend they choose to share with
    share_enabled TINYINT(1) NOT NULL DEFAULT 0, -- 1 = willing to share, 0 = not
    created_at    TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (grantor_uuid, friend_uuid),
    FOREIGN KEY (grantor_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (friend_uuid)  REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- "who is willing to share with me" lookups (reverse direction)
    INDEX idx_lsp_friend (friend_uuid, share_enabled)
);
