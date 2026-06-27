import os
import logging

import redis

REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Heartbeat TTL — a user is "online" as long as the client
# keeps calling /update_auth within this window.
HEARTBEAT_TTL = 120  # seconds (2 minutes)

# Friend request rate limit: 5 per hour per user
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 3600  # seconds

logger = logging.getLogger(__name__)

_client = None


def _get_redis():
    global _client
    if _client is None:
        _client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=1)
    return _client


def set_heartbeat(user_uuid: str) -> None:
    """Mark a user as online. Called by /update_auth on every client heartbeat."""
    try:
        _get_redis().setex(f'heartbeat:{user_uuid}', HEARTBEAT_TTL, '1')
    except Exception as e:
        # Redis failure must never break the auth heartbeat flow
        logger.warning(f"Redis set_heartbeat failed: {e}")


def is_online(user_uuid: str) -> bool:
    """True if the user has a live heartbeat key in Redis."""
    try:
        return _get_redis().exists(f'heartbeat:{user_uuid}') == 1
    except Exception as e:
        logger.warning(f"Redis is_online failed: {e}")
        return False  # default to offline — safer for notification routing


def check_rate_limit(user_uuid: str) -> bool:
    """
    Returns True if the user is within their friend-request limit, False if exceeded.
    Fails open: if Redis is unreachable the request is allowed through.
    """
    return check_rate_limit_for('friend_request', user_uuid, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)


def check_rate_limit_for(key_prefix: str, user_uuid: str,
                          max_count: int, window: int) -> bool:
    """
    Generic sliding-window rate limiter backed by Redis INCR + EXPIRE.

    key_prefix  — namespaces the Redis key, e.g. 'friend_request' or 'media_upload'
    max_count   — maximum allowed calls within the window
    window      — window length in seconds

    Returns True if the request is within the limit.
    Fails open: if Redis is unreachable the request is allowed through.
    """
    try:
        client = _get_redis()
        key = f'rate:{key_prefix}:{user_uuid}'
        count = client.incr(key)
        if count == 1:
            client.expire(key, window)
        return count <= max_count
    except Exception as e:
        logger.warning(f"Redis rate limit check failed (failing open) [{key_prefix}]: {e}")
        return True
