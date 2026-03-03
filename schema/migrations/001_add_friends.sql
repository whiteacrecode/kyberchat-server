-- Migration 001: Add friends table
-- Run this against an existing database to bring it up to date with schema.sql.

USE e2e_chat_service;

CREATE TABLE IF NOT EXISTS friends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requester_uuid CHAR(36) NOT NULL,
    addressee_uuid CHAR(36) NOT NULL,
    status ENUM('pending', 'accepted', 'blocked') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    FOREIGN KEY (addressee_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,
    UNIQUE KEY unique_friendship (requester_uuid, addressee_uuid),
    INDEX (requester_uuid, status),
    INDEX (addressee_uuid, status)
);
