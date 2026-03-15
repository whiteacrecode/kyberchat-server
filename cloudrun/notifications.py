import logging

import firebase_admin
from firebase_admin import messaging

logger = logging.getLogger(__name__)

# On Cloud Run the service account's Application Default Credentials are used
# automatically — no explicit key file needed.
_fcm_ready = False
try:
    firebase_admin.initialize_app()
    _fcm_ready = True
except Exception as e:
    logger.warning(f"Firebase Admin SDK init failed — push notifications disabled: {e}")


def _send(message: messaging.Message) -> None:
    if not _fcm_ready:
        return
    try:
        messaging.send(message)
    except Exception as e:
        # FCM failure must never fail the HTTP request
        logger.warning(f"FCM send failed: {e}")


def notify_friend_request(push_token: str | None, target_is_online: bool) -> None:
    """
    Notifies the addressee of a new friend request.

    Online  → silent high-priority data message (wakes the app, shows no banner).
              The client fetches pending requests and renders its own UI.
    Offline → standard push notification with a generic title.
              No sender username or identity is included (metadata minimisation).
    """
    if not push_token:
        return

    if target_is_online:
        msg = messaging.Message(
            data={'type': 'FRIEND_REQUEST'},
            token=push_token,
            android=messaging.AndroidConfig(priority='high'),
            apns=messaging.APNSConfig(
                headers={'apns-priority': '10'},
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(content_available=True)
                )
            )
        )
    else:
        msg = messaging.Message(
            notification=messaging.Notification(
                title='New Invitation',
                body='Someone wants to connect with you.'
            ),
            data={'type': 'FRIEND_REQUEST'},
            token=push_token,
        )

    _send(msg)

    
def notify_new_message(push_token: str | None) -> None:
    """
    Notifies the recipient of a new incoming message.
    Always a silent high-priority data message — the app fetches and decrypts
    the payload itself. No sender identity or content is included in the push
    payload (metadata minimisation).
    """
    if not push_token:
        return

    _send(messaging.Message(
        data={'type': 'NEW_MESSAGE'},
        token=push_token,
        android=messaging.AndroidConfig(priority='high'),
        apns=messaging.APNSConfig(
            headers={'apns-priority': '10'},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(content_available=True)
            )
        )
    ))


def notify_connection_request(push_token: str | None, requester_uuid: str, target_is_online: bool) -> None:
    """
    Notifies a private-account user that someone wants to connect with them.
    Includes the requester_uuid so the recipient can Accept or Decline via
    POST /friends/accept_preview.

    Online  → silent high-priority data message.
    Offline → standard push notification with a generic title.
    """
    if not push_token:
        return

    if target_is_online:
        msg = messaging.Message(
            data={'type': 'CONNECTION_REQUEST', 'requester_uuid': requester_uuid},
            token=push_token,
            android=messaging.AndroidConfig(priority='high'),
            apns=messaging.APNSConfig(
                headers={'apns-priority': '10'},
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(content_available=True)
                )
            )
        )
    else:
        msg = messaging.Message(
            notification=messaging.Notification(
                title='New Connection Request',
                body='Someone wants to connect with you.'
            ),
            data={'type': 'CONNECTION_REQUEST', 'requester_uuid': requester_uuid},
            token=push_token,
        )

    _send(msg)


def notify_request_accepted(push_token: str | None) -> None:
    """
    Notifies the original requester that their invitation was accepted.
    Always a silent data message — the app refreshes its friends list on receipt.
    """
    if not push_token:
        return

    _send(messaging.Message(
        data={'type': 'FRIEND_REQUEST_ACCEPTED'},
        token=push_token,
        android=messaging.AndroidConfig(priority='high'),
        apns=messaging.APNSConfig(
            headers={'apns-priority': '10'},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(content_available=True)
            )
        )
    ))
