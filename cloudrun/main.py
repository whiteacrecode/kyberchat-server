import os
import logging
from flask import Flask, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from db import engine, ph
from auth import issue_token, verify_token
from cache import set_heartbeat
from friends import friends_bp
from e2e import e2e_bp
from search import search_bp
from messages import messages_bp
from devices import devices_bp
from firebase import firebase_bp

# Initialize Flask app
app = Flask(__name__)
app.register_blueprint(friends_bp)
app.register_blueprint(e2e_bp)
app.register_blueprint(search_bp)
app.register_blueprint(messages_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(firebase_bp)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/create_user', methods=['POST'])
def create_user():
    """
    Creates a new user in the database.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        required_fields = ['user_uuid', 'username', 'identity_key_public', 'registration_id', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        user_uuid = data['user_uuid']
        username = data['username']
        password = data['password']

        try:
            identity_key_public = bytes.fromhex(data['identity_key_public'])
        except ValueError:
            return jsonify({'error': 'identity_key_public must be a valid hex string'}), 400

        # ML-KEM-768 public key (1184 bytes) — optional during rollout, required once all clients updated
        kem_public_key: bytes | None = None
        if 'kem_public_key' in data:
            try:
                kem_public_key = bytes.fromhex(data['kem_public_key'])
                if len(kem_public_key) != 1184:
                    return jsonify({'error': 'kem_public_key must be 1184 bytes (ML-KEM-768)'}), 400
            except ValueError:
                return jsonify({'error': 'kem_public_key must be a valid hex string'}), 400

        registration_id = data['registration_id']
        password_hash = ph.hash(password)

        with engine.connect() as connection:
            query = text("""
                INSERT INTO users (user_uuid, username, identity_key_public, registration_id, password_hash, kem_public_key)
                VALUES (:user_uuid, :username, :identity_key_public, :registration_id, :password_hash, :kem_public_key)
            """)
            connection.execute(query, {
                'user_uuid': user_uuid,
                'username': username,
                'identity_key_public': identity_key_public,
                'registration_id': registration_id,
                'password_hash': password_hash,
                'kem_public_key': kem_public_key,
            })
            connection.commit()

        token = issue_token(user_uuid)
        logger.info(f"User created: {username} ({user_uuid})")
        return jsonify({'message': 'User created successfully', 'user_uuid': user_uuid, 'token': token}), 201

    except IntegrityError as e:
        logger.warning(f"IntegrityError: {e}")
        return jsonify({'error': 'Username or UUID already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/validate_login', methods=['POST'])
def validate_login():
    """
    Validates a user login by verifying username and password.
    Returns a generic error for both bad username and bad password to
    prevent username enumeration.
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing username or password'}), 400

        username = data['username']
        password = data['password']

        with engine.connect() as connection:
            query = text("""
                SELECT user_uuid, username, registration_id, created_at, password_hash
                FROM users
                WHERE username = :username AND deleted = 0
            """)
            result = connection.execute(query, {'username': username}).fetchone()

        if not result:
            logger.warning(f"Login failed: User not found {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        try:
            ph.verify(result[4], password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            logger.warning(f"Login failed: Bad password for {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        # Transparently rehash if the stored hash was produced with outdated parameters
        if ph.check_needs_rehash(result[4]):
            new_hash = ph.hash(password)
            with engine.connect() as connection:
                connection.execute(
                    text("UPDATE users SET password_hash = :h WHERE user_uuid = :u"),
                    {'h': new_hash, 'u': result[0]}
                )
                connection.commit()

        user_data = {
            'user_uuid': result[0],
            'username': result[1],
            'registration_id': result[2],
            'created_at': result[3].isoformat() if result[3] else None
        }
        token = issue_token(result[0])
        logger.info(f"Login validated for: {username}")
        return jsonify({'message': 'User found', 'user': user_data, 'token': token}), 200

    except Exception as e:
        logger.error(f"Error validating login: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/update_auth', methods=['POST'])
def update_auth():
    """
    Updates last_seen for the authenticated user and refreshes their Redis heartbeat.
    Authentication: Bearer PASETO token (user_uuid is derived from token, not body).
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as connection:
            query = text("""
                UPDATE users
                SET last_seen = CURRENT_TIMESTAMP
                WHERE user_uuid = :user_uuid AND deleted = 0
            """)
            result = connection.execute(query, {'user_uuid': user_uuid})
            connection.commit()

            if result.rowcount == 0:
                return jsonify({'error': 'User not found'}), 404

        # Also refresh the Redis heartbeat so online-status checks are real-time
        set_heartbeat(user_uuid)

        logger.info(f"Auth updated (last_seen) for: {user_uuid}")
        return jsonify({'message': 'Auth updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating auth: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/delete_user', methods=['POST'])
def delete_user():
    """
    Soft-deletes a user by setting deleted = 1.
    Authentication: Bearer PASETO token (defense-in-depth: also requires password).
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({'error': 'Missing password'}), 400

        password = data['password']

        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT password_hash FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': user_uuid}
            ).fetchone()

        if not result:
            return jsonify({'error': 'User not found'}), 404

        try:
            ph.verify(result[0], password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return jsonify({'error': 'Invalid password'}), 401

        with engine.connect() as connection:
            connection.execute(
                text("UPDATE users SET deleted = 1 WHERE user_uuid = :u"),
                {'u': user_uuid}
            )
            connection.commit()

        logger.info(f"User soft-deleted: {user_uuid}")
        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/change_password', methods=['POST'])
def change_password():
    """
    Changes a user's password.
    Authentication: Bearer PASETO token (defense-in-depth: also requires old_password).
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        required_fields = ['old_password', 'new_password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        old_password = data['old_password']
        new_password = data['new_password']

        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT password_hash FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': user_uuid}
            ).fetchone()

        if not result:
            return jsonify({'error': 'User not found'}), 404

        try:
            ph.verify(result[0], old_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return jsonify({'error': 'Invalid password'}), 401

        new_hash = ph.hash(new_password)
        with engine.connect() as connection:
            connection.execute(
                text("UPDATE users SET password_hash = :h WHERE user_uuid = :u"),
                {'h': new_hash, 'u': user_uuid}
            )
            connection.commit()

        logger.info(f"Password changed for: {user_uuid}")
        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/keys/reset_identity', methods=['POST'])
def reset_identity():
    """
    Replaces the user's identity key and KEM public key, and purges all
    existing pre-keys (SPK + OTPKs).  The client must immediately follow
    this call with POST /keys/upload to install a fresh pre-key bundle.

    Intended for "Start Fresh" recovery when the user has lost their mnemonic
    and needs to re-establish a cryptographic identity under the same account.

    NOTE: All existing E2EE sessions with this user become invalid after this
    call.  Recipients who cached the old public key will get decryption errors
    until they fetch the updated bundle.  Delete all messages before calling
    this endpoint (DELETE /messages/all).

    Authentication: Bearer PASETO token.

    Request body:
      {
        "identity_key_public":  "<64 hex chars — 32-byte X25519 public key>",
        "kem_public_key":       "<2368 hex chars — 1184-byte ML-KEM-768 public key>"  (optional)
      }

    Returns:
      200 { "message": "Identity key updated" }
      400 validation error
      401 bad token
      404 user not found
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json() or {}

        # ── Validate identity_key_public ───────────────────────────────────────
        ik_hex = data.get('identity_key_public', '')
        if not ik_hex:
            return jsonify({'error': 'identity_key_public is required'}), 400
        try:
            ik_bytes = bytes.fromhex(ik_hex)
        except ValueError:
            return jsonify({'error': 'identity_key_public must be valid hex'}), 400
        if len(ik_bytes) != 32:
            return jsonify({'error': 'identity_key_public must be 32 bytes (64 hex chars)'}), 400

        # ── Validate kem_public_key (optional) ────────────────────────────────
        kem_bytes = None
        kem_hex = data.get('kem_public_key', '')
        if kem_hex:
            try:
                kem_bytes = bytes.fromhex(kem_hex)
            except ValueError:
                return jsonify({'error': 'kem_public_key must be valid hex'}), 400
            if len(kem_bytes) != 1184:
                return jsonify({'error': 'kem_public_key must be 1184 bytes (2368 hex chars)'}), 400

        # ── Update DB ──────────────────────────────────────────────────────────
        with engine.begin() as conn:
            # Verify user exists
            row = conn.execute(
                text("SELECT user_uuid FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': user_uuid}
            ).fetchone()
            if not row:
                return jsonify({'error': 'User not found'}), 404

            # Update identity key (and KEM key if supplied)
            if kem_bytes:
                conn.execute(text("""
                    UPDATE users
                    SET identity_key_public = :ik, kem_public_key = :kem
                    WHERE user_uuid = :u
                """), {'ik': ik_bytes, 'kem': kem_bytes, 'u': user_uuid})
            else:
                conn.execute(text("""
                    UPDATE users SET identity_key_public = :ik WHERE user_uuid = :u
                """), {'ik': ik_bytes, 'u': user_uuid})

            # Purge all pre-keys — they were signed with the old signing key
            conn.execute(
                text("DELETE FROM signed_pre_keys WHERE user_uuid = :u"),
                {'u': user_uuid}
            )
            conn.execute(
                text("DELETE FROM one_time_pre_keys WHERE user_uuid = :u"),
                {'u': user_uuid}
            )

        logger.info(f"reset_identity: updated identity key for {user_uuid}")
        return jsonify({'message': 'Identity key updated'}), 200

    except Exception as e:
        logger.error(f"Error in reset_identity for {user_uuid if 'user_uuid' in dir() else '?'}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == "__main__":
    # Cloud Run provides the PORT environment variable
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
