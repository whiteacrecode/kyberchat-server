-- Migration 012: Add location sharing authorization table
--
-- Adds the `location_shares` table to manage who has active permissions
-- to request or listen to a user's E2EE location stream.
-- This table matches the zero-knowledge model: no coordinates or physical
-- data live in MySQL; it acts purely as the metadata access control layer.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 012_add_location_sharing.sql

USE e2e_chat_service;

-- 13. Location Shares Table
CREATE TABLE IF NOT EXISTS location_shares (
    share_uuid   CHAR(36)     PRIMARY KEY, -- Client-generated UUID v4
    grantor_uuid CHAR(36)     NOT NULL,    -- User sharing location
    grantee_uuid CHAR(36)     NULL,        -- Target friend allowed to view
    group_uuid   CHAR(36)     NULL,        -- Target group allowed to view
    is_active    TINYINT(1)   NOT NULL DEFAULT 1, -- 1 = active, 0 = stopped/expired
    expires_at   TIMESTAMP    NOT NULL,    -- Expiration timestamp (automated TTL)
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (grantor_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (grantee_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (group_uuid)   REFERENCES kybergroups(group_uuid) ON DELETE CASCADE,
    CONSTRAINT chk_recipient CHECK (grantee_uuid IS NOT NULL OR group_uuid IS NOT NULL)
);

-- Indexing for high-performance lookups of active shares
CREATE INDEX idx_location_grantor_active ON location_shares (grantor_uuid, is_active);
CREATE INDEX idx_location_grantee_active ON location_shares (grantee_uuid, is_active);
CREATE INDEX idx_location_group_active   ON location_shares (group_uuid, is_active);
