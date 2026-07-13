-- 015_lowercase_uuids.sql
--
-- One-time canonicalisation of every *user* UUID to lowercase.
--
-- Why: Foundation's `UUID.uuidString` (the current iOS derivation path) is
-- always UPPERCASE, while older client paths produced lowercase. Every
-- downstream comparison is exact and case-sensitive:
--   • chatId = [myUUID, peerUUID].sorted().joined("_")  (client)
--   • firestore.rules  request.auth.uid == <chatId component>
--   • Firebase custom-token uid  ==  MySQL user_uuid  ==  PASETO `sub`
-- A single mismatched case anywhere yields silent Firestore PERMISSION_DENIED.
-- We standardise on lowercase server-side; the app-layer shim in
-- auth.canonical_uuid() lowercases at every boundary so already-issued
-- (uppercase-`sub`) 7-day tokens keep resolving to these migrated rows.
--
-- Scope: only *user identity* UUIDs are lowercased. Entity ids that never
-- cross the identity/rules boundary and are already generated lowercase
-- (kybergroups.group_uuid, location_shares.share_uuid, messages.message_id,
-- media blob ids) are intentionally left untouched — rewriting them would
-- risk desyncing a client that cached the original case.
--
-- Safety:
--   • LOWER() is idempotent — re-running this migration is a no-op.
--   • FOREIGN_KEY_CHECKS is disabled for the session so a PK can be lowered
--     alongside its (also-lowered) child FK rows; the end state is FK-consistent.
--   • Wrapped in a single transaction so a failure rolls back cleanly.
--
-- Pre-flight check for pathological data (a UNIQUE key collision only if two
-- rows differ *solely* by case — not expected, since each account is
-- internally case-consistent). Run this first and expect zero rows:
--
--     SELECT LOWER(user_uuid) u, COUNT(*) c FROM users GROUP BY u HAVING c > 1;
--
-- Deploy AFTER the auth.canonical_uuid() shim is live (see auth.py / firebase.py).

SET FOREIGN_KEY_CHECKS = 0;

START TRANSACTION;

-- Core identity + Signal key material
UPDATE users              SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE signed_pre_keys    SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE one_time_pre_keys  SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE user_devices       SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE user_voip_devices  SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE recovery_blobs     SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE user_profiles      SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);

-- Friendships (both directions)
UPDATE friends            SET requester_uuid = LOWER(requester_uuid) WHERE requester_uuid <> LOWER(requester_uuid);
UPDATE friends            SET addressee_uuid = LOWER(addressee_uuid) WHERE addressee_uuid <> LOWER(addressee_uuid);

-- REST-fallback message relay
UPDATE messages           SET sender_uuid    = LOWER(sender_uuid)    WHERE sender_uuid    <> LOWER(sender_uuid);
UPDATE messages           SET recipient_uuid = LOWER(recipient_uuid) WHERE recipient_uuid <> LOWER(recipient_uuid);

-- Media ownership
UPDATE media_uploads      SET owner_uuid     = LOWER(owner_uuid)     WHERE owner_uuid     <> LOWER(owner_uuid);

-- Groups
UPDATE kybergroups        SET owner_uuid     = LOWER(owner_uuid)     WHERE owner_uuid     <> LOWER(owner_uuid);
UPDATE group_members      SET user_uuid      = LOWER(user_uuid)      WHERE user_uuid      <> LOWER(user_uuid);
UPDATE group_invites      SET invitee_uuid   = LOWER(invitee_uuid)   WHERE invitee_uuid   <> LOWER(invitee_uuid);
UPDATE group_invites      SET inviter_uuid   = LOWER(inviter_uuid)   WHERE inviter_uuid   <> LOWER(inviter_uuid);

-- Location sharing
UPDATE location_shares      SET grantor_uuid = LOWER(grantor_uuid)   WHERE grantor_uuid   <> LOWER(grantor_uuid);
UPDATE location_shares      SET grantee_uuid = LOWER(grantee_uuid)   WHERE grantee_uuid IS NOT NULL AND grantee_uuid <> LOWER(grantee_uuid);
UPDATE location_share_prefs SET grantor_uuid = LOWER(grantor_uuid)   WHERE grantor_uuid   <> LOWER(grantor_uuid);
UPDATE location_share_prefs SET friend_uuid  = LOWER(friend_uuid)    WHERE friend_uuid    <> LOWER(friend_uuid);

COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
