# Server Changes Needed — Steps 5.1-5.9

> **Note:** The files `firebase.py`, `notifications.py`, `main.py`, etc. in
> `kyberchat-server/cloudrun/` are currently open in an editor and cannot be
> read from the VM. This document describes the exact changes required.
> Close your editor or check these against your current file contents.

---

## 1. `cloudrun/firebase.py` — Firebase Admin SDK + `/firebase_token` endpoint

The iOS client calls `POST /firebase_token` (see `APIService.swift:getFirebaseToken`).
This endpoint must exist and must call `firebase_admin.auth.create_custom_token(user_uuid)`.

### Required in `requirements.txt`:
```
firebase-admin>=6.0.0
```

### What `firebase.py` must contain:

```python
# cloudrun/firebase.py
import os
import firebase_admin
from firebase_admin import auth as firebase_auth, credentials

_app = None

def _get_app():
    """Lazy-initialise the Firebase Admin SDK (safe for Cloud Run cold starts)."""
    global _app
    if _app is not None:
        return _app

    # Cloud Run: set GOOGLE_APPLICATION_CREDENTIALS to the path of a service
    # account JSON file, OR use Workload Identity (recommended — no file needed).
    # If neither is set, Application Default Credentials are used, which works
    # automatically on Cloud Run with the correct IAM binding (see section 3).
    cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if cred_path:
        cred = credentials.Certificate(cred_path)
        _app = firebase_admin.initialize_app(cred)
    else:
        # Application Default Credentials (Cloud Run default)
        _app = firebase_admin.initialize_app()
    return _app


def create_custom_token(user_uuid: str) -> str:
    """
    Issue a Firebase custom token for `user_uuid`.
    The client exchanges this for a Firebase ID token via
    Auth.auth().signIn(withCustomToken:) (iOS) or
    FirebaseAuth.getInstance().signInWithCustomToken(token) (Android).
    """
    _get_app()
    token_bytes = firebase_auth.create_custom_token(user_uuid)
    # create_custom_token returns bytes on some SDK versions
    if isinstance(token_bytes, bytes):
        return token_bytes.decode("utf-8")
    return token_bytes


def send_fcm_notification(push_token: str, data_payload: dict) -> bool:
    """
    Send a silent data-only FCM push to a device token.
    Returns True on success, False on failure.

    iOS:   push_token is the FCM registration token from AppDelegate
    Android: push_token is the FCM registration token from onNewToken()

    Both platforms use the same token type and the same send call.
    """
    from firebase_admin import messaging
    _get_app()
    message = messaging.Message(
        data=data_payload,          # silent data payload (no notification key)
        token=push_token,
        apns=messaging.APNSConfig(  # iOS: content-available triggers background fetch
            headers={"apns-push-type": "background", "apns-priority": "5"},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(content_available=True)
            ),
        ),
        android=messaging.AndroidConfig(  # Android: high priority for background wake
            priority="high",
        ),
    )
    try:
        messaging.send(message)
        return True
    except Exception as e:
        print(f"[FCM] send failed for token ...{push_token[-8:]}: {e}")
        return False
```

### Flask route to add in `main.py` (or wherever routes live):

```python
from firebase import create_custom_token

@app.route("/firebase_token", methods=["POST"])
@require_paseto_auth          # your existing auth decorator
def firebase_token(user_uuid: str):
    """
    Exchange a valid PASETO session token for a Firebase custom token.
    The client uses this to sign into Firebase Auth and get Firestore write access.
    """
    try:
        token = create_custom_token(user_uuid)
        return jsonify({"firebase_token": token}), 200
    except Exception as e:
        app.logger.error(f"firebase_token error for {user_uuid}: {e}")
        return jsonify({"error": "Firebase authentication service unavailable."}), 503
```

---

## 2. `cloudrun/notifications.py` — FCM push on key events

After each of these server events, call `send_fcm_notification` for each
push token registered to the *recipient*:

| Event | `data` payload `type` value |
|-------|---------------------------|
| Friend request sent | `"FRIEND_REQUEST"` |
| Friend request accepted | `"FRIEND_REQUEST_ACCEPTED"` |
| Message stored (REST fallback only) | `"NEW_MESSAGE"` |

> **Note on NEW_MESSAGE:** When using Firestore as the primary transport
> (step 5.5), the Firestore real-time listener handles delivery without
> a push. The FCM push is only needed as a wake-up signal when the app
> is backgrounded. It does NOT carry the message content.

```python
# In notifications.py (or wherever device tokens are queried)

from firebase import send_fcm_notification

def notify_user(recipient_uuid: str, event_type: str, db_conn):
    """
    Look up all push tokens for recipient_uuid and send a silent FCM push.
    Tokens that return a 404 (unregistered) should be deleted from the DB.
    """
    tokens = get_push_tokens_for_user(recipient_uuid, db_conn)  # your existing query
    for token in tokens:
        success = send_fcm_notification(token, {"type": event_type})
        if not success:
            # Optionally delete stale tokens here
            pass
```

---

## 3. Cloud / IAM Setup (required before deploying)

### Option A — Workload Identity (recommended, no credentials file)

```bash
PROJECT_ID="quantchat-server"
REGION="us-central1"
SERVICE_ACCOUNT="quantchat-server-sa"   # adjust to your Cloud Run SA name

# Grant the Cloud Run service account the Firebase Admin SDK role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/firebase.sdkAdminServiceAgent"

# Also grant FCM send permission
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/cloudmessaging.admin"
```

### Option B — Service account key file (simpler but less secure)

```bash
PROJECT_ID="quantchat-server"

# Create a dedicated service account for Firebase Admin
gcloud iam service-accounts create firebase-admin-sa \
  --display-name="KyberChat Firebase Admin" \
  --project=${PROJECT_ID}

# Grant Firebase Admin role
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:firebase-admin-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/firebase.sdkAdminServiceAgent"

# Download the key
gcloud iam service-accounts keys create firebase-admin-key.json \
  --iam-account="firebase-admin-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project=${PROJECT_ID}

# Store in Secret Manager (don't embed in Docker image)
gcloud secrets create firebase-admin-key \
  --data-file=firebase-admin-key.json \
  --project=${PROJECT_ID}

# Mount secret in Cloud Run
gcloud run services update quantchat-server \
  --region=${REGION} \
  --set-secrets="GOOGLE_APPLICATION_CREDENTIALS=firebase-admin-key:latest:/secrets/firebase-admin-key.json" \
  --project=${PROJECT_ID}
```

---

## 4. Firestore Security Rules Deployment

The rules file is at `firestore.rules` in the kyberchat-ios repo root.

### Via Firebase CLI (recommended):
```bash
# Install CLI if needed
npm install -g firebase-tools

# Login
firebase login

# Deploy rules only (no code deploy)
firebase deploy --only firestore:rules --project quantchat-server
```

### Via gcloud (alternative):
```bash
# Firestore rules must go through the Firebase CLI or REST API.
# gcloud does not have a direct "deploy firestore rules" command.
# Use the Firebase CLI above, or use the REST API:

curl -X PATCH \
  "https://firebaserules.googleapis.com/v1/projects/quantchat-server/releases/cloud.firestore" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{
  "name": "projects/quantchat-server/releases/cloud.firestore",
  "rulesetName": "projects/quantchat-server/rulesets/LATEST_RULESET_ID"
}
EOF

# To create a new ruleset first:
# firebase deploy --only firestore:rules --project quantchat-server
```

---

## 5. Enable Required Firebase/GCP APIs

```bash
PROJECT_ID="quantchat-server"

gcloud services enable \
  firestore.googleapis.com \
  firebase.googleapis.com \
  fcm.googleapis.com \
  firebaseauth.googleapis.com \
  identitytoolkit.googleapis.com \
  --project=${PROJECT_ID}
```

---

## 6. Firestore Database Creation (if not already done)

```bash
PROJECT_ID="quantchat-server"
REGION="us-central1"

# Create Firestore database in Native mode (required for real-time listeners)
gcloud firestore databases create \
  --location=${REGION} \
  --project=${PROJECT_ID}
# If it already exists this will return an error — that's fine.
```

---

## 7. Firebase Storage (for encrypted image attachments — step 5.10)

iOS sends images E2EE using a per-attachment AES-256-GCM content key carried
inside the Double-Ratchet-encrypted body. The ciphertext blob is uploaded to
Firebase Storage under `attachments/{chatId}/{uuid}.bin`. The receiver
downloads, decrypts, renders locally, and deletes the blob — Storage is an
ephemeral relay, matching the Firestore design.

### 7a. Enable Firebase Storage
```bash
PROJECT_ID="quantchat-server"

# Storage is enabled through Firebase, not raw GCS. If you haven't yet,
# visit the Firebase console → Build → Storage → Get Started, pick the
# multi-region bucket (us-central1), then confirm it shows up in gsutil:
gsutil ls -p ${PROJECT_ID}
# Expected bucket name: ${PROJECT_ID}.appspot.com
```

### 7b. Deploy Storage security rules
```bash
# Rules live at kyberchat-ios/storage.rules
firebase deploy --only storage --project ${PROJECT_ID}
```

The rules (see `storage.rules` in the iOS repo root) restrict the
`attachments/{chatId}/{objectId}` path to participants of the chat, cap
uploads at 8 MiB, and pin `contentType == 'application/octet-stream'`.
All other Storage paths are denied.

### 7c. iOS SPM dependency
Xcode target must include `FirebaseStorage` from the `firebase-ios-sdk`
package. Already wired in `kyberchat.xcodeproj/project.pbxproj` — no server
action needed, listed here for completeness.

### 7d. Info.plist additions (iOS target)

Two privacy strings are required for image send/save flows:

| Key | Purpose | Required? |
|-----|---------|-----------|
| `NSPhotoLibraryAddUsageDescription` | Needed when the user taps **Save** in the full-screen image viewer (`UIImageWriteToSavedPhotosAlbum`). | **Yes** |
| `NSPhotoLibraryUsageDescription` | PhotosPicker uses a privacy-preserving out-of-process picker that does **not** require this on iOS 14+. Safe to omit. Include only as defence in case we later swap to PHPickerViewController in-process or UIImagePickerController. | Optional |

Suggested strings:
- Add: `"Save received images from KyberChat to your photo library."`
- Read: `"Let KyberChat attach images you choose to encrypted messages."`
