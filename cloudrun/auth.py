import os
import logging
from datetime import datetime, timezone, timedelta

import jwt

JWT_SECRET = os.environ.get('JWT_SECRET')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_DAYS = 7  # Mobile clients stay logged in for a week

logger = logging.getLogger(__name__)


def issue_token(user_uuid: str) -> str:
    """Issues a signed JWT for the given user. Called once at login."""
    payload = {
        'sub': user_uuid,
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRY_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(request) -> tuple:
    """
    Extracts and verifies the Bearer JWT from the Authorization header.

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

    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['sub'], None
    except jwt.ExpiredSignatureError:
        logger.warning("JWT verification failed: token expired")
        return None, ({'error': 'Token expired'}, 401)
    except jwt.InvalidTokenError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None, ({'error': 'Invalid token'}, 401)
