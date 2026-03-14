"""
firebase.py — Firebase custom token exchange (Option A)

Bridges KyberChat's PASETO session layer with Firebase Auth so that the iOS
client can write directly to Firestore with proper security rule enforcement.

Flow:
  1. iOS calls POST /firebase_token with its PASETO Bearer token.
  2. Server verifies the PASETO token and extracts user_uuid.
  3. Server calls firebase_admin.auth.create_custom_token(user_uuid).
     — Signed with the Cloud Run service account's private key via ADC.
     — Expires after 1 hour (Firebase-mandated maximum).
  4. iOS receives the custom token and calls Auth.auth().signIn(withCustomToken:).
     — This gives Firebase a UID equal to the user's KyberChat user_uuid.
     — The resulting Firebase session credential persists until it expires.
  5. iOS uses that credential for all Firestore reads/writes.
     — Firestore security rules check request.auth.uid against document fields.

Firebase custom token expiry:
  Custom tokens themselves expire after 1 hour, but the Firebase ID token obtained
  from signIn(withCustomToken:) auto-refreshes (valid for ~1 hour, silently renewed
  by the Firebase SDK). In practice the iOS client should only need to call this
  endpoint on first login and after a complete sign-out. The SDK handles the rest.

Required IAM permission on the Cloud Run service account:
  roles/iam.serviceAccountTokenCreator
  (or the finer-grained: iam.serviceAccounts.signBlob on the service account itself)

  Without this, create_custom_token raises:
    google.auth.exceptions.TransportError: ... compute-metadata ... signBlob
  Grant it in the GCP console or via:
    gcloud projects add-iam-policy-binding <PROJECT_ID> \\
      --member="serviceAccount:<SA_EMAIL>" \\
      --role="roles/iam.serviceAccountTokenCreator"
"""

import time
import logging

import firebase_admin
from firebase_admin import auth as firebase_auth
from flask import Blueprint, request, jsonify

from auth import verify_token

firebase_bp = Blueprint('firebase', __name__)
logger = logging.getLogger(__name__)

# Additional claims embedded in the Firebase custom token.
# Available in Firestore security rules as request.auth.token.*
# so rules can distinguish real KyberChat sessions from other Firebase tenants.
_CUSTOM_CLAIMS: dict = {
    'kyc': True,  # "KyberChat" flag — rules: request.auth.token.kyc == true
}

# Firebase custom tokens are valid for 1 hour (Firebase-enforced maximum).
_TOKEN_TTL_SECONDS = 3600


@firebase_bp.route('/firebase_token', methods=['POST'])
def get_firebase_token():
    """
    Exchanges a valid KyberChat PASETO session token for a Firebase custom token.

    The iOS client uses the Firebase custom token to call
    Auth.auth().signIn(withCustomToken:), which sets request.auth.uid in
    Firestore security rules to the caller's KyberChat user_uuid.

    Authentication: Bearer PASETO token (standard KyberChat session).

    Request body: empty {} or omit body entirely.

    Response 200:
      {
        "firebase_token": "<signed JWT string>",
        "uid":            "<user_uuid>",
        "expires_in":     3600
      }

    Response 401: PASETO token missing, invalid, or expired.
    Response 503: Firebase Admin SDK unavailable (misconfigured service account).
    Response 500: Unexpected server error.

    iOS client notes:
      • Cache the result — only re-call when Firebase throws an auth error or on
        cold launch after a full sign-out.
      • The Firebase SDK auto-refreshes ID tokens obtained from signIn(withCustomToken:),
        so 1-hour re-exchanges are NOT required in normal operation.
      • Call sequence on login:
          1. POST /validate_login  → store PASETO token
          2. POST /firebase_token  → call Auth.auth().signIn(withCustomToken:)
          3. POST /register_device → register FCM token
    """
    try:
        # ── 1. Verify the KyberChat PASETO session ────────────────────────
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        # ── 2. Guard: Firebase Admin SDK must be initialised ──────────────
        # notifications.py calls firebase_admin.initialize_app() at import time.
        # If that failed (e.g. missing ADC on localhost), _apps will be empty.
        if not firebase_admin._apps:
            logger.error("Firebase Admin SDK is not initialised — cannot issue custom token")
            return jsonify({'error': 'Firebase authentication service is not available'}), 503

        # ── 3. Issue a Firebase custom token for this user_uuid ───────────
        # The token's `uid` will equal user_uuid, which Firestore rules see
        # as request.auth.uid. Additional claims are available as
        # request.auth.token.<key> in security rules.
        try:
            raw = firebase_auth.create_custom_token(user_uuid, _CUSTOM_CLAIMS)
            # firebase_admin ≥ 5.x returns bytes; older versions return str.
            firebase_token = raw.decode('utf-8') if isinstance(raw, (bytes, bytearray)) else raw
        except firebase_auth.UnexpectedResponseError as e:
            # Likely a missing signBlob IAM permission on the service account.
            logger.error(
                f"Firebase custom token creation failed (check IAM: "
                f"roles/iam.serviceAccountTokenCreator): {e}"
            )
            return jsonify({
                'error': 'Firebase authentication service is not available',
                'hint':  'Ensure the Cloud Run service account has roles/iam.serviceAccountTokenCreator'
            }), 503
        except Exception as e:
            logger.error(f"Firebase custom token creation failed: {e}")
            return jsonify({'error': 'Firebase authentication service is not available'}), 503

        # ── 4. Return token + metadata ────────────────────────────────────
        logger.info(f"Firebase custom token issued for user: {user_uuid}")
        return jsonify({
            'firebase_token': firebase_token,
            'uid':            user_uuid,
            # Millisecond epoch of when the custom token itself expires.
            # The Firebase ID token the SDK derives from it auto-refreshes;
            # this value is informational for client-side observability only.
            'expires_in':     _TOKEN_TTL_SECONDS,
            'issued_at':      int(time.time()),
        }), 200

    except Exception as e:
        logger.error(f"Unexpected error in /firebase_token: {e}")
        return jsonify({'error': 'Internal server error'}), 500
