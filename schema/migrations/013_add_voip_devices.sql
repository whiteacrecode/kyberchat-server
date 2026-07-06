-- Migration 013: Add user VoIP devices table for PushKit/APNs calling
--
-- Adds the `user_voip_devices` table to manage registered APNs/PushKit VoIP
-- tokens per user. This is distinct from standard FCM push tokens as iOS
-- requires direct PushKit/VoIP tokens to wake CallKit.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 013_add_voip_devices.sql

USE e2e_chat_service;

-- 14. User VoIP Devices Table
CREATE TABLE IF NOT EXISTS user_voip_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    voip_token VARCHAR(255) NOT NULL,           -- Hex or Base64 Apple PushKit token
    platform VARCHAR(50) NOT NULL DEFAULT 'ios', -- Platform identifier ('ios' / 'android')
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL               -- Last token refresh / heartbeat
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Prevent duplicate (user, token) rows
    UNIQUE KEY unique_user_voip_token (user_uuid, voip_token),
    INDEX idx_voip_user (user_uuid)
);
