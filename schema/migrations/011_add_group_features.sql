-- Migration 011: group metadata (description, searchable, message TTL) + invites
--
-- Adds the columns needed to make groups more usable:
--   - description        free-text blurb shown alongside the group name
--   - searchable         opt-in flag; only searchable=1 groups are returned
--                         by POST /groups/search
--   - message_ttl_seconds disappearing-messages setting for the group. NULL
--                         means messages never auto-expire. Enforcement of
--                         the TTL against Firestore message docs is a
--                         separate concern (client / Cloud Function) — this
--                         column only stores the group's configured value.
--
-- Also adds group_invites, a pending-invite table mirroring the `friends`
-- request/accept pattern so joining a group requires the invitee's consent
-- instead of an owner unilaterally adding them (see POST /groups/members/add
-- for the existing owner-adds-directly flow, which is left in place).
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 011_add_group_features.sql

USE e2e_chat_service;

ALTER TABLE kybergroups
    ADD COLUMN description         VARCHAR(500) NULL,
    ADD COLUMN searchable          TINYINT(1)   NOT NULL DEFAULT 0,
    ADD COLUMN message_ttl_seconds INT          NULL;

-- Narrows the scan for POST /groups/search before the LIKE match on
-- group_name/description (neither of which can use a plain B-tree index
-- for a leading-wildcard LIKE).
CREATE INDEX idx_kybergroups_searchable ON kybergroups (searchable);

-- Pending group invites. A row here means invitee_uuid has been invited to
-- group_uuid and has not yet responded. Both accept and decline delete the
-- row outright (mirrors friends.decline_friend_request) — there is no
-- retained "declined" state, so the same user can be re-invited later.
CREATE TABLE IF NOT EXISTS group_invites (
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
