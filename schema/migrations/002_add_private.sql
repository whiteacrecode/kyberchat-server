-- Migration 002: Add private column to users table
-- Run this against an existing database to bring it up to date with schema.sql.

USE e2e_chat_service;

ALTER TABLE users
    ADD COLUMN private INT NOT NULL DEFAULT 0
    COMMENT '0=public (discoverable), 1=private (connection requests require target approval)';
