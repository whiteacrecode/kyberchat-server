CREATE DATABASE IF NOT EXISTS e2e_chat_service;
USE e2e_chat_service;

-- 1. Users Table
-- Stores basic identity. No PII (Email/Phone) as per requirements.
CREATE TABLE users (
    user_uuid CHAR(36) PRIMARY KEY, -- Generated deterministically on client from BIP39 mnemonic seed
    username VARCHAR(50) UNIQUE NOT NULL, -- Human readable ID
    identity_key_public BLOB NOT NULL, -- Long-term X25519 Identity Public Key (IK), 32 bytes
    registration_id INT NOT NULL, -- Signal-specific ID for the device
    -- Argon2id hash (time_cost=3, memory_cost=65536, parallelism=4).
    -- One-way: irrecoverable by users or service operators.
    password_hash VARCHAR(255) NOT NULL,
    -- ML-KEM-768 post-quantum public key (1184 bytes). NULL for pre-PQC accounts.
    -- Populated on registration by clients with swift-crypto 3.3+ installed.
    kem_public_key BLOB NULL,
    private INT NOT NULL DEFAULT 0,  -- 0 = public (discoverable), 1 = private
    deleted INT NOT NULL DEFAULT 0,  -- 0 = active, 1 = soft-deleted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 2. Signed Pre-Keys Table
-- Medium-term keys signed by the Identity Key. Rotated periodically.
CREATE TABLE signed_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL, -- Client-side identifier for the key
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL, -- Signature of the public key using IK
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (user_uuid)
);

-- 3. One-Time Pre-Keys Table
-- A pool of keys consumed when someone starts a chat with this user.
-- This is critical for "Asynchronous" key exchange.
CREATE TABLE one_time_pre_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    key_id INT NOT NULL,
    public_key BLOB NOT NULL,
    is_consumed BOOLEAN DEFAULT FALSE, -- Set to TRUE once a peer uses it
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    INDEX (user_uuid, is_consumed)
);

-- 4. Devices/Sessions Table
-- Tracks FCM push tokens per user. Supports multiple devices (multi-device).
-- Notifications are always sent to the token with the most recent updated_at.
CREATE TABLE user_devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid CHAR(36) NOT NULL,
    push_token VARCHAR(255) NOT NULL,           -- FCM registration token
    platform ENUM('ios', 'android') NULL,       -- NULL until client sends platform field
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL               -- Last token refresh / heartbeat
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    -- Prevent duplicate (user, token) rows that can accumulate from repeated registrations
    UNIQUE KEY unique_user_token (user_uuid, push_token),
    INDEX (user_uuid)
);

-- 5. Friends Table
-- Tracks friendship relationships between users.
-- A row exists for each directional request: requester -> addressee.
-- status='accepted' means mutual friendship (both sides use this single row).
CREATE TABLE friends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requester_uuid CHAR(36) NOT NULL,   -- user who sent the friend request
    addressee_uuid CHAR(36) NOT NULL,   -- user who received the friend request
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (addressee_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    UNIQUE KEY unique_friendship (requester_uuid, addressee_uuid),
    INDEX (requester_uuid, status),
    INDEX (addressee_uuid, status)
);

