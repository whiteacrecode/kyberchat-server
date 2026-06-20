import logging

from sqlalchemy import text

from firebase import send_fcm_notification

logger = logging.getLogger(__name__)


def notify_user(recipient_uuid: str, event_type: str, extra: dict | None = None) -> None:
    """
    Look up all registered push tokens for recipient_uuid and send a silent
    FCM data message to each device.

    extra: optional flat dict of additional string values merged into the payload,
    e.g. {"requester_uuid": "..."} for CONNECTION_REQUEST events.
    """
    from db import engine
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT push_token FROM user_devices
                WHERE user_uuid = :u
                ORDER BY updated_at DESC
            """), {'u': recipient_uuid}).fetchall()
    except Exception as exc:
        logger.warning("notify_user: token lookup failed for %s: %s", recipient_uuid, exc)
        return

    payload: dict = {"type": event_type}
    if extra:
        payload.update({k: str(v) for k, v in extra.items()})

    for row in rows:
        token = row[0]
        if token:
            send_fcm_notification(token, payload)


# ---------------------------------------------------------------------------
# Legacy single-token helpers — kept for callers that already hold a token.
# Prefer notify_user() for new code.
# ---------------------------------------------------------------------------

def notify_friend_request(push_token: str | None, target_is_online: bool) -> None:
    if push_token:
        send_fcm_notification(push_token, {"type": "FRIEND_REQUEST"})


def notify_new_message(push_token: str | None) -> None:
    if push_token:
        send_fcm_notification(push_token, {"type": "NEW_MESSAGE"})


def notify_connection_request(push_token: str | None, requester_uuid: str, target_is_online: bool) -> None:
    if push_token:
        send_fcm_notification(push_token, {"type": "CONNECTION_REQUEST", "requester_uuid": requester_uuid})


def notify_request_accepted(push_token: str | None) -> None:
    if push_token:
        send_fcm_notification(push_token, {"type": "FRIEND_REQUEST_ACCEPTED"})
