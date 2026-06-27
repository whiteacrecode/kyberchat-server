"""
media.py — GCS signed-URL endpoints for encrypted audio/video attachments.

Design
------
The server is a *signed-URL broker* only.  It never sees plaintext or media
keys.  The client:

  1.  Calls POST /media/upload-url to get a short-lived GCS PUT URL + blobId.
  2.  Uploads the AES-256-GCM ciphertext blob directly to GCS.
  3.  Wraps (blobId, mediaKey, IV, ciphertextSHA256) in a MediaEnvelope and
      delivers it through the existing Double Ratchet channel — the server
      never sees the key.
  4.  Recipient calls GET /media/<blobId>/download-url, downloads the blob,
      verifies the SHA-256 digest, then decrypts locally.

Security properties
-------------------
* Signed URLs are capability-bearing and expire in minutes.
* Access to a download URL requires: (a) a valid PASETO token AND (b) knowing
  the blobId.  The blobId travels inside the E2EE envelope, so only the
  intended recipient can obtain it.
* The GCS bucket must have allUsers access disabled; all reads/writes go
  through signed URLs.

Lifecycle
---------
* Every blob has an expires_at timestamp (BLOB_TTL_DAYS from creation).
* A separate sweeper job (Cloud Scheduler → Cloud Run) should periodically
  DELETE expired / orphaned blobs from GCS using the query:
      SELECT blob_id, gcs_object FROM media_uploads
      WHERE expires_at < NOW() AND deleted = 0
  then UPDATE media_uploads SET deleted = 1.

Environment variables
---------------------
GCS_MEDIA_BUCKET           — required; GCS bucket name
MEDIA_UPLOAD_URL_TTL_MIN   — signed PUT URL lifetime in minutes (default 15)
MEDIA_DOWNLOAD_URL_TTL_MIN — signed GET URL lifetime in minutes (default 60)
MEDIA_BLOB_TTL_DAYS        — days until a blob is considered expired (default 30)
MEDIA_MAX_AUDIO_BYTES      — max declared audio ciphertext size (default 25 MiB)
MEDIA_MAX_VIDEO_BYTES      — max declared video ciphertext size (default 200 MiB)
MEDIA_RATE_LIMIT_MAX       — max upload-url requests per user per window (default 50)
MEDIA_RATE_LIMIT_WINDOW    — rate-limit window in seconds (default 3600)
"""

import logging
import os
import uuid as uuid_module
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from sqlalchemy import text

from auth import verify_token
from cache import check_rate_limit_for
from db import engine

media_bp = Blueprint('media', __name__)
logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
GCS_BUCKET           = os.environ.get('GCS_MEDIA_BUCKET', '')
UPLOAD_URL_TTL_MIN   = int(os.environ.get('MEDIA_UPLOAD_URL_TTL_MIN',   '15'))
DOWNLOAD_URL_TTL_MIN = int(os.environ.get('MEDIA_DOWNLOAD_URL_TTL_MIN', '60'))
BLOB_TTL_DAYS        = int(os.environ.get('MEDIA_BLOB_TTL_DAYS',        '30'))
MAX_AUDIO_BYTES      = int(os.environ.get('MEDIA_MAX_AUDIO_BYTES',      str(25  * 1024 * 1024)))  # 25 MiB
MAX_VIDEO_BYTES      = int(os.environ.get('MEDIA_MAX_VIDEO_BYTES',      str(200 * 1024 * 1024)))  # 200 MiB
RATE_LIMIT_MAX       = int(os.environ.get('MEDIA_RATE_LIMIT_MAX',       '50'))
RATE_LIMIT_WINDOW    = int(os.environ.get('MEDIA_RATE_LIMIT_WINDOW',    '3600'))

ALLOWED_MEDIA_TYPES  = {'audio', 'video'}

# ── GCS client (lazy-init, picks up ADC on Cloud Run automatically) ────────────
_gcs_client = None


def _get_gcs():
    global _gcs_client
    if _gcs_client is None:
        from google.cloud import storage
        _gcs_client = storage.Client()
    return _gcs_client


# ── Endpoints ──────────────────────────────────────────────────────────────────

@media_bp.route('/media/upload-url', methods=['POST'])
def request_upload_url():
    """
    Issue a short-lived GCS signed PUT URL so the client can upload a
    ciphertext blob directly to GCS without routing bytes through Cloud Run.

    Authentication: Bearer PASETO token.

    Request body:
      {
        "media_type": "audio" | "video",
        "byte_size":  <int>,          -- declared ciphertext byte count (enforced as cap)
        "mime_type":  "<string>"      -- e.g. "audio/m4a", "video/mp4" (stored, not enforced)
      }

    Returns 200:
      {
        "blob_id":    "<uuid>",
        "upload_url": "<signed GCS PUT URL (valid UPLOAD_URL_TTL_MIN minutes)>",
        "expires_at": "<ISO-8601 — when the blob itself expires>"
      }

    Errors:
      400 — missing/invalid fields or size exceeds cap
      401 — bad/missing token
      429 — rate limit exceeded
      503 — GCS_MEDIA_BUCKET not configured
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not GCS_BUCKET:
            logger.error("GCS_MEDIA_BUCKET env var not set")
            return jsonify({'error': 'Media storage not configured'}), 503

        if not check_rate_limit_for('media_upload', user_uuid, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW):
            return jsonify({'error': 'Too many upload requests. Try again later.'}), 429

        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Invalid JSON'}), 400

        # ── Validate media_type ───────────────────────────────────────────────
        media_type = data.get('media_type', '')
        if media_type not in ALLOWED_MEDIA_TYPES:
            return jsonify({'error': f'media_type must be one of: {sorted(ALLOWED_MEDIA_TYPES)}'}), 400

        # ── Validate byte_size ────────────────────────────────────────────────
        byte_size = data.get('byte_size')
        if not isinstance(byte_size, int) or byte_size <= 0:
            return jsonify({'error': 'byte_size must be a positive integer'}), 400

        max_bytes = MAX_AUDIO_BYTES if media_type == 'audio' else MAX_VIDEO_BYTES
        if byte_size > max_bytes:
            return jsonify({
                'error': f'{media_type} blobs must be <= {max_bytes // (1024 * 1024)} MiB'
            }), 400

        # ── mime_type (informational — stored but not enforced in the signed URL) ─
        mime_type = str(data.get('mime_type', 'application/octet-stream'))[:128]

        # ── Generate blobId and signed PUT URL ────────────────────────────────
        blob_id = str(uuid_module.uuid4())
        gcs_object = f'media/{blob_id}'

        bucket = _get_gcs().bucket(GCS_BUCKET)
        gcs_blob = bucket.blob(gcs_object)

        signed_put_url = gcs_blob.generate_signed_url(
            version='v4',
            expiration=timedelta(minutes=UPLOAD_URL_TTL_MIN),
            method='PUT',
            content_type='application/octet-stream',
        )

        # ── Persist the upload record before returning the URL ────────────────
        blob_expires_at = datetime.now(timezone.utc) + timedelta(days=BLOB_TTL_DAYS)

        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO media_uploads
                    (blob_id, owner_uuid, media_type, mime_type,
                     declared_byte_size, gcs_object, expires_at)
                VALUES
                    (:blob_id, :owner, :media_type, :mime_type,
                     :byte_size, :gcs_object, :expires_at)
            """), {
                'blob_id':    blob_id,
                'owner':      user_uuid,
                'media_type': media_type,
                'mime_type':  mime_type,
                'byte_size':  byte_size,
                'gcs_object': gcs_object,
                'expires_at': blob_expires_at,
            })

        logger.info(
            'upload-url issued: user=%s blob=%s type=%s declared_bytes=%d',
            user_uuid, blob_id, media_type, byte_size,
        )
        return jsonify({
            'blob_id':    blob_id,
            'upload_url': signed_put_url,
            'expires_at': blob_expires_at.isoformat(),
        }), 200

    except Exception as e:
        logger.error('Error in request_upload_url: %s', e)
        return jsonify({'error': 'Internal server error'}), 500


@media_bp.route('/media/<blob_id>/download-url', methods=['GET'])
def request_download_url(blob_id: str):
    """
    Issue a short-lived GCS signed GET URL so the client can download and
    decrypt a ciphertext blob.

    Any authenticated user who knows the blobId may obtain a download URL.
    BlobIds travel inside E2EE MediaEnvelopes — only the intended recipient
    should ever know the blobId.

    Authentication: Bearer PASETO token.

    Returns 200:
      {
        "download_url": "<signed GCS GET URL (valid DOWNLOAD_URL_TTL_MIN minutes)>",
        "expires_at":   "<ISO-8601 — when the URL itself expires>"
      }

    Errors:
      401 — bad/missing token
      404 — blob not found, expired, or deleted
      503 — GCS_MEDIA_BUCKET not configured
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not GCS_BUCKET:
            logger.error("GCS_MEDIA_BUCKET env var not set")
            return jsonify({'error': 'Media storage not configured'}), 503

        # ── Look up the blob record ───────────────────────────────────────────
        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT gcs_object, expires_at, deleted
                FROM media_uploads
                WHERE blob_id = :id
            """), {'id': blob_id}).fetchone()

        if not row:
            return jsonify({'error': 'Blob not found'}), 404

        gcs_object, expires_at, deleted = row

        if deleted:
            return jsonify({'error': 'Blob not found'}), 404

        # Normalise DB timestamp to UTC-aware for comparison
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                return jsonify({'error': 'Blob has expired'}), 404

        # ── Generate signed GET URL ───────────────────────────────────────────
        url_ttl = timedelta(minutes=DOWNLOAD_URL_TTL_MIN)
        url_expires_at = datetime.now(timezone.utc) + url_ttl

        bucket = _get_gcs().bucket(GCS_BUCKET)
        gcs_blob = bucket.blob(gcs_object)
        signed_get_url = gcs_blob.generate_signed_url(
            version='v4',
            expiration=url_ttl,
            method='GET',
        )

        logger.info('download-url issued: user=%s blob=%s', user_uuid, blob_id)
        return jsonify({
            'download_url': signed_get_url,
            'expires_at':   url_expires_at.isoformat(),
        }), 200

    except Exception as e:
        logger.error('Error in request_download_url blob=%s: %s', blob_id, e)
        return jsonify({'error': 'Internal server error'}), 500


@media_bp.route('/media/<blob_id>', methods=['DELETE'])
def delete_media_blob(blob_id: str):
    """
    Delete a media blob from GCS and mark the DB record as deleted.
    Only the owner (the user who uploaded it) may delete a blob.

    Authentication: Bearer PASETO token.

    Returns:
      200 { "message": "Blob deleted" }
      403 — not the owner
      404 — blob not found or already deleted
      401 — bad/missing token
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT owner_uuid, gcs_object, deleted
                FROM media_uploads
                WHERE blob_id = :id
            """), {'id': blob_id}).fetchone()

        if not row or row[2]:
            return jsonify({'error': 'Blob not found'}), 404

        owner_uuid, gcs_object, _ = row

        if owner_uuid != user_uuid:
            return jsonify({'error': 'Forbidden'}), 403

        # Delete from GCS — non-fatal if the object is already gone
        if GCS_BUCKET:
            try:
                _get_gcs().bucket(GCS_BUCKET).blob(gcs_object).delete()
            except Exception as gcs_err:
                # Log but continue: mark the DB row deleted so the sweeper
                # won't issue new URLs for an object that may be gone.
                logger.warning('GCS delete failed for blob %s: %s', blob_id, gcs_err)

        with engine.begin() as conn:
            conn.execute(text("""
                UPDATE media_uploads SET deleted = 1 WHERE blob_id = :id
            """), {'id': blob_id})

        logger.info('Blob deleted: %s by owner %s', blob_id, user_uuid)
        return jsonify({'message': 'Blob deleted'}), 200

    except Exception as e:
        logger.error('Error deleting blob %s: %s', blob_id, e)
        return jsonify({'error': 'Internal server error'}), 500
