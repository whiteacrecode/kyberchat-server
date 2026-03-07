import os
import logging
from flask import Flask, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from db import engine, ph
from auth import issue_token
from cache import set_heartbeat
from friends import friends_bp
from e2e import e2e_bp

# Initialize Flask app
app = Flask(__name__)
app.register_blueprint(friends_bp)
app.register_blueprint(e2e_bp)

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
            # Assuming the client sends a hex string
            identity_key_public = bytes.fromhex(data['identity_key_public'])
        except ValueError:
            return jsonify({'error': 'identity_key_public must be a valid hex string'}), 400

        registration_id = data['registration_id']
        password_hash = ph.hash(password)

        with engine.connect() as connection:
            query = text("""
                INSERT INTO users (user_uuid, username, identity_key_public, registration_id, password_hash)
                VALUES (:user_uuid, :username, :identity_key_public, :registration_id, :password_hash)
            """)
            connection.execute(query, {
                'user_uuid': user_uuid,
                'username': username,
                'identity_key_public': identity_key_public,
                'registration_id': registration_id,
                'password_hash': password_hash
            })
            connection.commit()

        logger.info(f"User created: {username} ({user_uuid})")
        return jsonify({'message': 'User created successfully', 'user_uuid': user_uuid}), 201

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
    Updates last_seen for a user.
    """
    try:
        data = request.get_json()
        if not data or 'user_uuid' not in data:
            return jsonify({'error': 'Missing user_uuid'}), 400

        user_uuid = data['user_uuid']

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
    Requires the user's password to confirm the action.
    """
    try:
        data = request.get_json()
        if not data or 'user_uuid' not in data or 'password' not in data:
            return jsonify({'error': 'Missing user_uuid or password'}), 400

        user_uuid = data['user_uuid']
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
    Changes a user's password. Requires the current password to be correct
    before the new password is accepted.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        required_fields = ['user_uuid', 'old_password', 'new_password']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        user_uuid = data['user_uuid']
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


if __name__ == "__main__":
    # Cloud Run provides the PORT environment variable
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
