-- Migration 004: Add messages table for server-side message relay
-- The REST API (POST /messages/send, GET /messages) stores encrypted blobs here.
-- Firestore is used by iOS clients for direct real-time writes; this table is
-- the server-side fallback path.

USE e2e_chat_service;

CREATE TABLE IF NOT EXISTS messages (
    message_id  CHAR(36)     PRIMARY KEY,
    sender_uuid    CHAR(36)     NOT NULL,
    recipient_uuid CHAR(36)     NOT NULL,
    ciphertext     TEXT         NOT NULL,  -- base64-encoded, exactly 1024 bytes decoded
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_uuid)    REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (recipient_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (recipient_uuid, created_at)
);
