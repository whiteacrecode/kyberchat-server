-- Migration 009: indexes on user_profiles(phone) and user_profiles(email)
--
-- Supports exact-match lookups added by POST /users/search (search.py).
-- Values are normalized (lowercased email, digits-only phone) at write time
-- by profile.py's normalize_email()/normalize_phone() going forward; rows
-- written before this migration remain unnormalized until the owning user
-- next saves their profile.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 009_add_profile_search_indexes.sql

USE e2e_chat_service;

CREATE INDEX idx_user_profiles_email ON user_profiles (email);
CREATE INDEX idx_user_profiles_phone ON user_profiles (phone);
