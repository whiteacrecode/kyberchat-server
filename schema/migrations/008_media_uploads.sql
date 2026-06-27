-- Migration 008: media_uploads table
--
-- Tracks GCS ciphertext blobs issued for encrypted audio/video attachments
-- (Phase 1 of the A/V messaging feature).
--
-- The server is an opaque signed-URL broker: it never sees plaintext or media
-- keys.  This table stores only the metadata needed to:
--   (a) issue and authorise signed GET URLs to authenticated callers,
--   (b) enforce per-blob TTL / expiry,
--   (c) allow an orphaned-blob sweeper to find and delete expired GCS objects.
--
-- Apply with:
--   mysql -h <host> -u <user> -p e2e_chat_service < 008_media_uploads.sql
--
-- Required env vars on Cloud Run:
--   GCS_MEDIA_BUCKET           — GCS bucket holding ciphertext blobs
--   MEDIA_UPLOAD_URL_TTL_MIN   — signed PUT URL lifetime in minutes (default 15)
--   MEDIA_DOWNLOAD_URL_TTL_MIN — signed GET URL lifetime in minutes (default 60)
--   MEDIA_BLOB_TTL_DAYS        — days until a blob is considered expired (default 30)
--   MEDIA_MAX_AUDIO_BYTES      — max declared audio size (default 26214400 = 25 MiB)
--   MEDIA_MAX_VIDEO_BYTES      — max declared video size (default 209715200 = 200 MiB)
--   MEDIA_RATE_LIMIT_MAX       — max upload-url requests per user per window (default 50)
--   MEDIA_RATE_LIMIT_WINDOW    — rate-limit window in seconds (default 3600)

USE e2e_chat_service;

CREATE TABLE IF NOT EXISTS media_uploads (
    -- Unique identifier for this blob; doubles as the GCS object name suffix.
    blob_id            CHAR(36)                  NOT NULL,

    -- The user who requested the upload URL (and whose token must be used to
    -- issue download URLs, or to delete the blob).
    owner_uuid         CHAR(36)                  NOT NULL,

    -- Broad media category — drives size caps and client-side rendering hints.
    media_type         ENUM('audio', 'video')    NOT NULL,

    -- MIME type declared by the client (e.g. 'audio/m4a', 'video/mp4').
    -- Stored for client rendering hints; not enforced server-side.
    mime_type          VARCHAR(128)              NOT NULL DEFAULT 'application/octet-stream',

    -- Byte count declared by the client at upload-url request time.
    -- The server enforces a cap on this value; the actual GCS object size may
    -- differ (the client controls the PUT).  A future sweeper can compare
    -- declared vs. actual sizes via GCS object metadata.
    declared_byte_size INT UNSIGNED              NOT NULL,

    -- Full GCS object path, e.g. "media/<uuid>".  Stored so the signed-URL
    -- issuer and sweeper do not need to reconstruct it from blob_id.
    gcs_object         VARCHAR(512)              NOT NULL,

    -- When the blob should be considered stale.  The sweeper uses this to find
    -- objects that can be deleted from GCS and marked deleted here.
    expires_at         TIMESTAMP                 NOT NULL,

    -- Soft-delete flag.  Set to 1 by DELETE /media/<blob_id> or the sweeper.
    -- Rows are never hard-deleted so that the sweeper can audit its own work.
    deleted            TINYINT(1)                NOT NULL DEFAULT 0,

    created_at         TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (blob_id),
    FOREIGN KEY (owner_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE,

    -- Fast lookup of all blobs owned by a user (for quota / list endpoints).
    INDEX idx_owner (owner_uuid),

    -- Sweeper query: find expired, non-deleted blobs.
    INDEX idx_expires (expires_at, deleted)
);
