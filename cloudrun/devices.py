import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from db import engine
from auth import verify_token

devices_bp = Blueprint('devices', __name__)
logger = logging.getLogger(__name__)


@devices_bp.route('/register_device', methods=['POST'])
def register_device():
    """
    Registers or updates the FCM push token for the authenticated user's device.

    Called once on first launch, and again whenever the FCM SDK issues a new token
    (e.g. after an app reinstall, token rotation, or OS upgrade).

    Authentication: Bearer PASETO token.

    Request body:
      { "push_token": "<FCM registration token string>" }

    Returns:
      201 { "message": "Device registered" }  — new row inserted
      200 { "message": "Device updated" }     — existing token updated in-place
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'push_token' not in data:
            return jsonify({'error': 'Missing push_token'}), 400

        push_token = data['push_token'].strip()
        if not push_token:
            return jsonify({'error': 'push_token must not be empty'}), 400

        with engine.begin() as conn:
            # Check if this exact token is already registered for this user
            existing = conn.execute(text("""
                SELECT id FROM user_devices
                WHERE user_uuid = :u AND push_token = :t
            """), {'u': user_uuid, 't': push_token}).fetchone()

            if existing:
                # Refresh updated_at so this token sorts to the top as 'most recently active'
                conn.execute(text("""
                    UPDATE user_devices
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id
                """), {'id': existing[0]})
                logger.info(f"Device token refreshed for user: {user_uuid}")
                return jsonify({'message': 'Device updated'}), 200

            # Insert the new token.
            # We intentionally allow multiple rows per user (multi-device support).
            # Notifications are always sent to the most-recently-registered token
            # (ORDER BY created_at DESC LIMIT 1 in query sites).
            conn.execute(text("""
                INSERT INTO user_devices (user_uuid, push_token)
                VALUES (:u, :t)
            """), {'u': user_uuid, 't': push_token})

        logger.info(f"Device registered for user: {user_uuid}")
        return jsonify({'message': 'Device registered'}), 201

    except Exception as e:
        logger.error(f"Error registering device: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@devices_bp.route('/unregister_device', methods=['POST'])
def unregister_device():
    """
    Removes the given FCM token from the authenticated user's registered devices.

    Call this on logout to stop push notifications for this device.

    Authentication: Bearer PASETO token.

    Request body:
      { "push_token": "<FCM registration token string>" }

    Returns:
      200 { "message": "Device unregistered" }
      404 { "error": "Token not found" }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'push_token' not in data:
            return jsonify({'error': 'Missing push_token'}), 400

        push_token = data['push_token'].strip()

        with engine.begin() as conn:
            result = conn.execute(text("""
                DELETE FROM user_devices
                WHERE user_uuid = :u AND push_token = :t
            """), {'u': user_uuid, 't': push_token})

        if result.rowcount == 0:
            return jsonify({'error': 'Token not found'}), 404

        logger.info(f"Device unregistered for user: {user_uuid}")
        return jsonify({'message': 'Device unregistered'}), 200

    except Exception as e:
        logger.error(f"Error unregistering device: {e}")
        return jsonify({'error': 'Internal server error'}), 500
