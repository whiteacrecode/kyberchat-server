# cloudrun/firebase.py
#
# Firebase Admin SDK initialisation + two public helpers:
#   create_custom_token(user_uuid)          — for POST /firebase_token
#   send_fcm_notification(token, payload)   — for push notifications
#
# Auth strategy: Application Default Credentials (ADC).
# On Cloud Run the runtime SA is used automatically — no key file needed
# as long as the SA has roles/firebase.sdkAdminServiceAgent and
# roles/cloudmessaging.admin (see gcloud commands at bottom of file).
#
# Local dev: set GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
# or run `gcloud auth application-default login`.
#
# Android + iOS both use the same FCM token type; send_fcm_notification
# is platform-agnostic.  The APNs-specific headers are set for iOS so
# silent pushes (content-available:1) work correctly; Android ignores them.

import os
import logging

import firebase_admin
from firebase_admin import auth as firebase_auth, credentials, firestore, messaging
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

_app: firebase_admin.App | None = None

# Blueprint — registered in main.py as:  app.register_blueprint(firebase_bp)
firebase_bp = Blueprint("firebase", __name__)


# ---------------------------------------------------------------------------
# Internal: lazy initialisation
# ---------------------------------------------------------------------------

def _get_app() -> firebase_admin.App:
    """
    Initialise the Firebase Admin SDK exactly once per process.
    If another module (e.g. notifications.py) already initialised the default
    app, we reuse it instead of raising ValueError.
    Uses Application Default Credentials unless GOOGLE_APPLICATION_CREDENTIALS
    points at a service-account JSON file.
    """
    global _app
    if _app is not None:
        return _app

    # Reuse an already-initialised default app (e.g. initialised by notifications.py)
    try:
        _app = firebase_admin.get_app()
        return _app
    except ValueError:
        pass  # not yet initialised — fall through

    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if cred_path and os.path.isfile(cred_path):
        cred = credentials.Certificate(cred_path)
        _app = firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialised with service-account key.")
    else:
        # On Cloud Run with ADC the SDK picks up the runtime SA automatically.
        _app = firebase_admin.initialize_app()
        logger.info("Firebase Admin SDK initialised with Application Default Credentials.")

    return _app


# ---------------------------------------------------------------------------
# POST /firebase_token
# ---------------------------------------------------------------------------

def _require_paseto_auth(f):
    """
    Decorator that verifies the PASETO Bearer token and injects user_uuid as
    the first positional argument to the wrapped function.
    Uses the same verify_token() helper used elsewhere in the server.
    """
    from auth import verify_token as _verify
    import functools

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user_uuid, err = _verify(request)
        if err:
            body, status = err
            return jsonify(body), status
        return f(user_uuid, *args, **kwargs)

    return wrapper


@firebase_bp.route("/firebase_token", methods=["POST"])
@_require_paseto_auth
def firebase_token_endpoint(user_uuid: str):
    """
    Exchange a valid PASETO session token for a Firebase custom token.

    The iOS/Android client calls this once per session (or after logout).
    The returned firebase_token is passed to:
      iOS:     Auth.auth().signIn(withCustomToken: token)
      Android: Firebase.auth.signInWithCustomToken(token).await()

    The resulting Firebase ID token satisfies Firestore security rules:
      request.auth.uid == user_uuid

    Returns:
      200  {"firebase_token": "<signed-jwt>"}
      503  {"error": "Firebase auth unavailable."}   (Admin SDK not initialised)
    """
    try:
        token = create_custom_token(user_uuid)
        return jsonify({"firebase_token": token}), 200
    except Exception as exc:
        logger.error("firebase_token error for %s: %s", user_uuid, exc)
        return jsonify({"error": "Firebase authentication service unavailable."}), 503


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_custom_token(user_uuid: str) -> str:
    """
    Issue a Firebase custom token for *user_uuid*.

    The client exchanges this for a Firebase ID token via:
      iOS:     Auth.auth().signIn(withCustomToken: token)
      Android: Firebase.auth.signInWithCustomToken(token).await()

    The resulting ID token satisfies Firestore security rules:
      request.auth.uid == user_uuid

    Raises firebase_admin.exceptions.FirebaseError on failure.
    """
    _get_app()
    token = firebase_auth.create_custom_token(user_uuid)
    # SDK may return bytes on some versions
    if isinstance(token, bytes):
        return token.decode("utf-8")
    return token


def send_fcm_notification(push_token: str, data_payload: dict) -> bool:
    """
    Send a silent, data-only FCM push to *push_token*.

    *data_payload* must be a flat {str: str} dict, e.g.::
        {"type": "NEW_MESSAGE"}
        {"type": "FRIEND_REQUEST"}
        {"type": "FRIEND_REQUEST_ACCEPTED"}

    Both iOS and Android receive the same payload.

      iOS path:   AppDelegate.application(_:didReceiveRemoteNotification:...)
                  → posts NotificationCenter(.kycRefreshFriends)
      Android:    KyberChatFCMService.onMessageReceived()
                  → sends LocalBroadcast("kycRefreshFriends")

    Returns True on success, False (logged) on any error.
    Callers should not crash on False — FCM delivery is best-effort.
    Stale tokens (404/UNREGISTERED) should be removed from the DB.
    """
    _get_app()

    # Ensure all values are strings (FCM data payload requirement)
    str_payload = {k: str(v) for k, v in data_payload.items()}

    message = messaging.Message(
        data=str_payload,
        token=push_token,
        # iOS: content-available triggers background fetch even with no alert
        apns=messaging.APNSConfig(
            headers={
                "apns-push-type": "background",
                "apns-priority": "5",        # low priority for silent push
            },
            payload=messaging.APNSPayload(
                aps=messaging.Aps(content_available=True)
            ),
        ),
        # Android: HIGH priority wakes the app from Doze mode
        android=messaging.AndroidConfig(priority="high"),
    )

    try:
        messaging.send(message)
        return True
    except messaging.UnregisteredError:
        logger.warning("FCM token unregistered (stale): ...%s", push_token[-8:])
        return False
    except Exception as exc:
        logger.error("FCM send failed for token ...%s: %s", push_token[-8:], exc)
        return False


# ---------------------------------------------------------------------------
# Group membership mirror (Phase 1 of the group-chat feature — GROUP_PLAN.md)
# ---------------------------------------------------------------------------
#
# MySQL (`kybergroups` / `group_members`) is the source of truth for who is
# in a group. Firestore security rules can't query MySQL, so on every
# membership mutation the server (trusted, via Admin SDK — bypasses rules)
# mirrors the current roster into a Firestore doc that the rules *can* read
# with get(). This mirror is metadata only (a list of UUIDs) — no sender
# keys, no message content.

def sync_group_membership(group_uuid: str, member_uuids: list[str]) -> None:
    """
    Overwrite groups/{group_uuid} in Firestore with the current member list.
    Called after create/add/remove/leave so the mirror always reflects the
    latest MySQL state. Safe to call with the full roster every time —
    last-write-wins is fine since MySQL is the source of truth.
    """
    _get_app()
    client = firestore.client()
    client.collection("groups").document(group_uuid).set({"members": member_uuids})


def delete_group_membership_mirror(group_uuid: str) -> None:
    """
    Remove groups/{group_uuid} from Firestore. Once gone, the group_conversations
    security rule's get() lookup fails closed (Firestore rules deny on
    exceptions), so nobody can read/write that group's messages any more.
    """
    _get_app()
    client = firestore.client()
    client.collection("groups").document(group_uuid).delete()


# ---------------------------------------------------------------------------
# Group icon (Phase B of the group-chat completion plan — GROUP_COMPLETION_PLAN.md)
# ---------------------------------------------------------------------------
#
# Piggybacks on the same groups/{group_uuid} membership-mirror doc rather
# than a new collection: it's already read-restricted to members via
# firestore.rules (`request.auth.uid in resource.data.members`), and writes
# already go exclusively through the Admin SDK (`allow write: if false`), so
# there's no new security-rule surface to add. This is stricter than the
# equivalent user-avatar storage (profiles/{userUUID}, globally readable) —
# a group's icon is only visible to its members.

def set_group_icon(group_uuid: str, icon_jpeg_b64: str | None) -> None:
    """
    Sets (or clears, when *icon_jpeg_b64* is None) the group's icon.
    Uses merge=True so the `members` field written by sync_group_membership()
    is left untouched. Called by POST /groups/icon (owner-only, see groups.py).
    """
    _get_app()
    client = firestore.client()
    client.collection("groups").document(group_uuid).set(
        {"icon_jpeg_b64": icon_jpeg_b64}, merge=True
    )


# ---------------------------------------------------------------------------
# Cloud Run SA setup (run once; idempotent)
# ---------------------------------------------------------------------------
#
# gcloud projects add-iam-policy-binding quantchat-server \
#   --member="serviceAccount:<SA_EMAIL>" \
#   --role="roles/firebase.sdkAdminServiceAgent"
#
# gcloud projects add-iam-policy-binding quantchat-server \
#   --member="serviceAccount:<SA_EMAIL>" \
#   --role="roles/cloudmessaging.admin"
#
# Find the SA email:
# gcloud run services describe quantchat-server --region=us-central1 \
#   --format='value(spec.template.spec.serviceAccountName)'
# ---------------------------------------------------------------------------
