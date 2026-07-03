# AGENTS.md — Operational Manual for Autonomous Agents

## 1. Project Identity & Context
- **Project:** KyberChat Server / Backend API
- **Core Purpose:** Zero-knowledge, post-quantum hybridized (ML-KEM-768) public key directory and encrypted message relay server for secure end-to-end (X3DH + Double Ratchet) communication.
- **Tech Stack:** Python 3.11 (Flask), SQLAlchemy 2.0, PyMySQL, Redis, PySETO (PASETO v4.local), cryptography (>= 43.0), Firebase Admin SDK (Cloud Firestore & FCM).
- **Critical Invariants:**
  1. **Zero-Knowledge Principle:** The server MUST NOT store, log, or process unencrypted messages or private keys.
  2. **Uniform Payload Size:** Every message ciphertext must be padded to exactly 1024 bytes (before base64-encoding) to prevent traffic analysis.
  3. **Opaque Tokens:** Authentication tokens must use PASETO v4.local (XChaCha20-Poly1305 + BLAKE2b AEAD) with a 7-day expiration.
  4. **Parameterized SQL:** Parameterize all database operations using SQLAlchemy text/bindings to prevent SQL Injection.

## 2. Toolchain Registry
| Intent | Command | Notes / Flag Requirements |
| :--- | :--- | :--- |
| **Install** | `pip install -r cloudrun/requirements.txt` | Standard Python dependency resolution. |
| **Run Dev** | `gunicorn --bind :$PORT --workers 1 --threads 8 main:app` | Start the local HTTP gateway (bind to port). |
| **Verify API**| `python3 test/create_user.py --user <user> --pass <pass>` | Validate register endpoint. |
| **Test Auth** | `python3 test/validate_login_api.py --user <user> --pass <pass>` | Validate login and PASETO token response. |
| **Format** | `black cloudrun/` | Standard style formatter to clean up layout. |
| **Lint** | `ruff check cloudrun/` | Validate static code rules and code health. |

## 3. Coding Conventions (Show, Don't Tell)
Do not explain rules in text. Follow this exact pattern for parameters, DB queries, and error wrapping:

### Safe Endpoint Routing, Database Bindings, and Error Envelope
```python
# WRONG: Swallowing exceptions, direct raw SQL concatenation, or unvalidated json keys
def do_bad():
    db.execute(f"UPDATE users SET name='{request.json['name']}' WHERE uuid='{request.json['uuid']}'")

# CORRECT: Sealed, type-safe route parsing with structured logging & parameterized SQLAlchemy text binds
from flask import Blueprint, request, jsonify
from sqlalchemy import text
from db import engine
import logging

logger = logging.getLogger(__name__)
friends_bp = Blueprint('friends', __name__)

@friends_bp.route('/friends/remove', methods=['POST'])
def remove_friend():
    """Removes a friendship safely in both directions using parameterized bindings."""
    try:
        data = request.get_json() or {}
        friend_uuid = data.get("friend_uuid")
        if not friend_uuid:
            return jsonify({"error": "Missing friend_uuid"}), 400

        # Authenticate token (derived from request context)
        user_uuid = getattr(request, "user_uuid", None)
        if not user_uuid:
            return jsonify({"error": "Unauthorized"}), 401

        with engine.connect() as conn:
            # Atomic double-directional removal
            query = text("""
                DELETE FROM friendships 
                WHERE (user_uuid = :user_uuid AND friend_uuid = :friend_uuid)
                   OR (user_uuid = :friend_uuid AND friend_uuid = :user_uuid)
            """)
            result = conn.execute(query, {"user_uuid": user_uuid, "friend_uuid": friend_uuid})
            conn.commit()

            if result.rowcount == 0:
                return jsonify({"error": "Friendship not found"}), 404

        logger.info(f"Friendship severed between {user_uuid} and {friend_uuid}")
        return jsonify({"message": "Friend removed successfully"}), 200

    except Exception as e:
        logger.error(f"Failed to remove friend: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
```
