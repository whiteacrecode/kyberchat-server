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
    Returns True if the user is within their limit, False if exceeded.
    Fails open: if Redis is unreachable the request is allowed through.
    """
    try:
        client = _get_redis()
        key = f'rate:friend_request:{user_uuid}'
        count = client.incr(key)
        if count == 1:
            client.expire(key, RATE_LIMIT_WINDOW)
        return count <= RATE_LIMIT_MAX
    except Exception as e:
        logger.warning(f"Redis rate limit check failed (failing open): {e}")
        return True
