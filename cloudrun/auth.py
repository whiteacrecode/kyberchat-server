import os
import json
import logging
from datetime import datetime, timezone, timedelta

import pyseto
from pyseto import Key

# PASETO v4.local uses XChaCha20-Poly1305 + BLAKE2b (symmetric AEAD).
# The key must be exactly 32 bytes, supplied as a 64-char hex string via env.
_RAW_SECRET = os.environ.get('PASETO_SECRET', '')
_KEY: Key | None = None

TOKEN_EXPIRY_DAYS = 7  # Mobile clients stay logged in for a week

logger = logging.getLogger(__name__)


def _get_key() -> Key:
    """Returns the cached v4.local symmetric key, initialising it on first call."""
    global _KEY
    if _KEY is not None:
        return _KEY

    if not _RAW_SECRET:
        raise RuntimeError("PASETO_SECRET environment variable is not set")

    # Accept a 64-char hex string (preferred) or a raw 32-byte ASCII secret.
    if len(_RAW_SECRET) == 64:
        try:
            key_bytes = bytes.fromhex(_RAW_SECRET)
        except ValueError:
            raise RuntimeError("PASETO_SECRET must be a 64-char hex string (32 bytes)")
    else:
        key_bytes = _RAW_SECRET.encode()

    if len(key_bytes) != 32:
        raise RuntimeError("PASETO_SECRET must be exactly 32 bytes (64 hex chars)")

    _KEY = Key.new(version=4, purpose="local", key=key_bytes)
    return _KEY


def issue_token(user_uuid: str) -> str:
    """Issues a signed-and-encrypted PASETO v4.local token for the given user.
    Called once at login."""
    exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRY_DAYS)
    payload = {
        'sub': user_uuid,
        'exp': exp.isoformat(),
    }
    token = pyseto.encode(_get_key(), json.dumps(payload).encode())
    # pyseto returns a bytes-like Token; decode to a plain string for the JSON response.
    return token.decode() if isinstance(token, (bytes, bytearray)) else str(token)


def verify_token(request) -> tuple:
    """
    Extracts and verifies the Bearer PASETO token from the Authorization header.

    Returns (user_uuid, None) on success.
    Returns (None, (response, status_code)) on failure — callers should
    immediately return the error tuple.

    Usage:
        user_uuid, err = verify_token(request)
        if err:
            return err
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, ({'error': 'Missing or invalid Authorization header'}, 401)

    token_str = auth_header[7:]
    try:
        decoded = pyseto.decode(_get_key(), token_str)
        payload = json.loads(decoded.payload)

        exp_str = payload.get('exp')
        if not exp_str:
            return None, ({'error': 'Invalid token: missing expiry'}, 401)

        if datetime.now(timezone.utc) > datetime.fromisoformat(exp_str):
            logger.warning("PASETO verification failed: token expired")
            return None, ({'error': 'Token expired'}, 401)

        return payload['sub'], None

    except (pyseto.PasetoException, ValueError, KeyError) as e:
        logger.warning(f"PASETO verification failed: {e}")
        return None, ({'error': 'Invalid token'}, 401)
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {e}")
        return None, ({'error': 'Invalid token'}, 401)
