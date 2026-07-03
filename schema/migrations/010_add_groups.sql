-- Migration 010: kybergroups + group_members tables
--
-- Table is named `kybergroups`, not `groups` — `GROUPS` is a reserved word
-- in MySQL 8 (and would require backticks/quoting everywhere it's used).
--
-- Adds group-chat membership tracking (Phase 0 of the group-chat feature —
-- see GROUP_PLAN.md). The server only ever authenticates who is allowed to
-- write/read a group's Firestore collection and lists membership for the
-- client to fan out pairwise sender-key distribution over the existing
-- hybrid X3DH + Double Ratchet channels. No group message content, sender
-- keys, or key material live in MySQL — this is metadata only, mirroring
-- the zero-knowledge relay model used for 1:1 chat.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 010_add_groups.sql

USE e2e_chat_service;

-- 10. Kybergroups Table
-- One row per group. `owner_uuid` is the creator; ownership does not
-- currently transfer (out of scope for v1 — see GROUP_PLAN.md Phase 7).
CREATE TABLE IF NOT EXISTS kybergroups (
    group_uuid   CHAR(36)     PRIMARY KEY, -- client-generated UUID v4
    group_name   VARCHAR(100) NOT NULL,
    owner_uuid   CHAR(36)     NOT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted      INT          NOT NULL DEFAULT 0, -- 0 = active, 1 = soft-deleted
    FOREIGN KEY (owner_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

-- 11. Group Members Table
-- Membership roster. Mirrored into Firestore (groups/{groupId}.members)
-- by the server via the Firebase Admin SDK on every mutation, since
-- Firestore security rules cannot query MySQL directly.
CREATE TABLE IF NOT EXISTS group_members (
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
