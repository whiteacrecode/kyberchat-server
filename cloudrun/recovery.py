"""
recovery.py — encrypted-recovery-blob endpoints.

The server is *opaque storage* for client-encrypted keychain backups.

Threat model
------------
The blob is wrapped with AES-256-GCM under a key the client derives from the
user's password via PBKDF2-HMAC-SHA256.  The server stores:

  * ciphertext + 16-byte GCM auth tag (one column)
  * 12-byte AES-GCM nonce
  * KDF identifier (allowlisted; today only "pbkdf2-sha256")
  * KDF iteration count (server enforces a minimum — see `MIN_KDF_ITERS`)
  * 16-byte per-blob random salt

The server **cannot** decrypt the blob.  Even with full database compromise an
attacker still needs the user's password to mount an offline PBKDF2 attack.

Endpoints
---------
* POST  /recovery/upload    — upsert the user's encrypted blob (idempotent).
* GET   /recovery/download  — fetch it back; 404 when absent.
* DELETE /recovery          — wipe it.

All three require a valid PASETO Bearer token; the row is keyed on the token's
`sub` claim, so a client can never read or overwrite another user's blob.

Server-side validation
----------------------
We bound the obvious foot-guns:

  * `MAX_CIPHERTEXT_BYTES` — refuses payloads larger than 256 KiB so a
    misbehaving client can't fill Cloud SQL storage.
  * `MIN_KDF_ITERS` — refuses suspiciously cheap KDF parameters.  A malicious
    client could still derive its own key with whatever cost it wants, but
    forcing a minimum on the *stored* parameters means the blob can't be
    replayed against a future weakened recovery flow.
  * Hex parsing is strict and length-checked — junk input is a 400, never a
    500, and never silently truncated/padded.
"""

import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text

from db import engine
from auth import verify_token

recovery_bp = Blueprint('recovery', __name__)
logger = logging.getLogger(__name__)

# ── Hard limits ────────────────────────────────────────────────────────────────
# 256 KiB ceiling on the AES-GCM ciphertext+tag (well over what an Everything-
# in-Keychain dump needs: ~2.4 KiB ML-KEM + ~32 bytes per OTPK private key * a
# few hundred OTPKs ≈ 8 KiB.  256 KiB leaves a generous future-proofing margin
# without exposing us to "stuff a movie in here" abuse.)
MAX_CIPHERTEXT_BYTES = 256 * 1024

NONCE_BYTES        = 12          # AES-GCM standard nonce length
SALT_BYTES         = 16          # 128 bits of salt is plenty for PBKDF2

# Floors a malicious or buggy client below which we reject the upload.  iOS
# defaults to 600_000; this is a hard "no" at anything below ~OWASP-2023
# guidance.
MIN_KDF_ITERS      = 100_000
MAX_KDF_ITERS      = 10_000_000  # safety ceiling vs. DoS-by-server-replay

# Allowlist of recognised KDF identifiers.  Add new entries here as we adopt
# them — DO NOT silently accept unknown algos: the server can't migrate blobs
# (it never sees plaintext) so the algo string must round-trip exactly.
ALLOWED_KDF_ALGOS  = {'pbkdf2-sha256'}


def _hex_to_bytes(value, *, name: str, expected_len: int | None = None,
                  max_len: int | None = None) -> bytes:
    """Parse a hex string -> bytes with strict length validation.

    Raises ValueError with a user-facing message on any failure; callers
    should translate to a 400 response.
    """
    if not isinstance(value, str):
        raise ValueError(f'{name} must be a hex string')
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f'{name} must be a valid hex string')
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f'{name} must be exactly {expected_len} bytes ({expected_len * 2} hex chars)')
    if max_len is not None and len(raw) > max_len:
        raise ValueError(f'{name} must be at most {max_len} bytes')
    return raw


@recovery_bp.route('/recovery/upload', methods=['POST'])
def upload_recovery_blob():
    """
    Upserts the encrypted recovery blob for the authenticated user.

    Authentication: Bearer PASETO token.

    Request body (all hex-encoded except the kdf object):
      {
        "version":    1,
        "ciphertext": "<hex — AES-256-GCM ciphertext+tag>",
        "nonce":      "<24 hex chars — 12-byte AES-GCM nonce>",
        "kdf": {
          "algo":  "pbkdf2-sha256",
          "iters": 600000,
          "salt":  "<32 hex chars — 16-byte salt>"
        }
      }

    Returns:
      200 { "message": "Recovery blob updated" }   — pre-existing row replaced
      201 { "message": "Recovery blob stored" }    — first upload
      400 validation error
      401 bad/missing token
      413 ciphertext too large
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Invalid JSON'}), 400

        # ── version (defaults to 1, must be a positive int) ───────────────
        version = data.get('version', 1)
        if not isinstance(version, int) or version < 1 or version > 1_000_000:
            return jsonify({'error': 'version must be a positive integer'}), 400

        # ── ciphertext + nonce ────────────────────────────────────────────
        try:
            ciphertext = _hex_to_bytes(
                data.get('ciphertext'),
                name='ciphertext',
                max_len=MAX_CIPHERTEXT_BYTES,
            )
        except ValueError as e:
            # Distinguish "too large" from "malformed" so the client can
            # produce a useful error message.
            msg = str(e)
            if 'at most' in msg:
                return jsonify({'error': msg}), 413
            return jsonify({'error': msg}), 400

        if not ciphertext:
            return jsonify({'error': 'ciphertext must not be empty'}), 400

        try:
            nonce = _hex_to_bytes(data.get('nonce'), name='nonce',
                                  expected_len=NONCE_BYTES)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # ── KDF parameters ────────────────────────────────────────────────
        kdf = data.get('kdf')
        if not isinstance(kdf, dict):
            return jsonify({'error': 'kdf object is required'}), 400

        algo = kdf.get('algo')
        if algo not in ALLOWED_KDF_ALGOS:
            return jsonify({'error': f'kdf.algo must be one of: {sorted(ALLOWED_KDF_ALGOS)}'}), 400

        iters = kdf.get('iters')
        if not isinstance(iters, int):
            return jsonify({'error': 'kdf.iters must be an integer'}), 400
        if iters < MIN_KDF_ITERS:
            return jsonify({'error': f'kdf.iters must be >= {MIN_KDF_ITERS}'}), 400
        if iters > MAX_KDF_ITERS:
            return jsonify({'error': f'kdf.iters must be <= {MAX_KDF_ITERS}'}), 400

        try:
            salt = _hex_to_bytes(kdf.get('salt'), name='kdf.salt',
                                 expected_len=SALT_BYTES)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # ── Upsert ────────────────────────────────────────────────────────
        # We use INSERT ... ON DUPLICATE KEY UPDATE because the user_uuid is the
        # primary key — a single user has at most one recovery blob.  This is
        # idempotent: re-running the same body produces the same row state.
        with engine.begin() as conn:
            # Verify the user exists and isn't soft-deleted; without this, a
            # leaked PASETO token after account deletion could keep stuffing
            # blobs into the table.
            row = conn.execute(
                text('SELECT 1 FROM users WHERE user_uuid = :u AND deleted = 0'),
                {'u': user_uuid},
            ).fetchone()
            if not row:
                return jsonify({'error': 'User not found'}), 404

            existing = conn.execute(
                text('SELECT 1 FROM recovery_blobs WHERE user_uuid = :u'),
                {'u': user_uuid},
            ).fetchone()

            conn.execute(text("""
                INSERT INTO recovery_blobs
                    (user_uuid, blob_version, ciphertext, nonce,
                     kdf_algo, kdf_iters, kdf_salt)
                VALUES
                    (:user_uuid, :version, :ciphertext, :nonce,
                     :algo, :iters, :salt)
                ON DUPLICATE KEY UPDATE
                    blob_version = VALUES(blob_version),
                    ciphertext   = VALUES(ciphertext),
                    nonce        = VALUES(nonce),
                    kdf_algo     = VALUES(kdf_algo),
                    kdf_iters    = VALUES(kdf_iters),
                    kdf_salt     = VALUES(kdf_salt)
            """), {
                'user_uuid':  user_uuid,
                'version':    version,
                'ciphertext': ciphertext,
                'nonce':      nonce,
                'algo':       algo,
                'iters':      iters,
                'salt':       salt,
            })

        if existing:
            logger.info(f'Recovery blob updated for {user_uuid} ({len(ciphertext)} bytes)')
            return jsonify({'message': 'Recovery blob updated'}), 200
        logger.info(f'Recovery blob stored for {user_uuid} ({len(ciphertext)} bytes)')
        return jsonify({'message': 'Recovery blob stored'}), 201

    except Exception as e:
        logger.error(f'Error uploading recovery blob: {e}')
        return jsonify({'error': 'Internal server error'}), 500


@recovery_bp.route('/recovery/download', methods=['GET'])
def download_recovery_blob():
    """
    Returns the authenticated user's encrypted recovery blob.

    Authentication: Bearer PASETO token.

    Returns:
      200 {
        "version":    <int>,
        "ciphertext": "<hex>",
        "nonce":      "<hex>",
        "kdf": { "algo": "...", "iters": <int>, "salt": "<hex>" },
        "updated_at": "<ISO 8601>"
      }
      404 — no blob stored for this user
      401 — bad/missing token
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT blob_version, ciphertext, nonce,
                       kdf_algo, kdf_iters, kdf_salt, updated_at
                FROM recovery_blobs
                WHERE user_uuid = :u
            """), {'u': user_uuid}).fetchone()

        if not row:
            return jsonify({'error': 'No recovery blob found'}), 404

        version, ciphertext, nonce, kdf_algo, kdf_iters, kdf_salt, updated_at = row

        return jsonify({
            'version':    version,
            'ciphertext': ciphertext.hex() if isinstance(ciphertext, (bytes, bytearray)) else bytes(ciphertext).hex(),
            'nonce':      nonce.hex()      if isinstance(nonce,      (bytes, bytearray)) else bytes(nonce).hex(),
            'kdf': {
                'algo':  kdf_algo,
                'iters': kdf_iters,
                'salt':  kdf_salt.hex() if isinstance(kdf_salt, (bytes, bytearray)) else bytes(kdf_salt).hex(),
            },
            'updated_at': updated_at.isoformat() if updated_at else None,
        }), 200

    except Exception as e:
        logger.error(f'Error downloading recovery blob: {e}')
        return jsonify({'error': 'Internal server error'}), 500


@recovery_bp.route('/recovery', methods=['DELETE'])
def delete_recovery_blob():
    """
    Wipes the authenticated user's encrypted recovery blob.

    Idempotent — returns 200 even when no blob exists, so callers can use
    this as a "best effort cleanup" without checking ahead of time.

    Authentication: Bearer PASETO token.
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.begin() as conn:
            result = conn.execute(
                text('DELETE FROM recovery_blobs WHERE user_uuid = :u'),
                {'u': user_uuid},
            )

        deleted = result.rowcount or 0
        logger.info(f'Recovery blob deleted for {user_uuid} (rows: {deleted})')
        return jsonify({'message': 'Recovery blob deleted', 'deleted': deleted}), 200

    except Exception as e:
        logger.error(f'Error deleting recovery blob: {e}')
        return jsonify({'error': 'Internal server error'}), 500
