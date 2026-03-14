import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text

from db import engine
from auth import verify_token
from cache import is_online, check_rate_limit
from notifications import notify_connection_request

search_bp = Blueprint('search', __name__)
logger = logging.getLogger(__name__)


@search_bp.route('/search_user', methods=['POST'])
def search_user():
    """
    Searches for a user by username and returns enough info to initiate a
    friend request. Behaviour depends on the target's privacy setting:

    private = 0 (public):
      Returns { user_uuid, username, private: 0 }.
      The caller should then POST /friends/request to send a formal request.

    private = 1 (private):
      Does NOT return the target's UUID.
      Sends a silent FCM notification to the target containing the requester's
      UUID so they can Accept or Decline via POST /friends/accept_preview.
      Returns { private: 1, status: "notified" }.

    If a relationship already exists in either direction the current status is
    returned immediately and no notification is sent.

    Authentication: Bearer JWT.
    Rate limit:     5 calls per hour per user (Redis-backed, fails open).

    Request body: { "username": "target_username" }
    Headers:      Authorization: Bearer <token>
    """
    try:
        requester_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit(requester_uuid):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({'error': 'Missing username'}), 400

        target_username = data['username']

        with engine.connect() as conn:
            # 1. Resolve username → UUID + privacy flag
            target = conn.execute(
                text("""
                    SELECT user_uuid, username, private
                    FROM users
                    WHERE username = :username AND deleted = 0
                """),
                {'username': target_username}
            ).fetchone()

            if not target:
                return jsonify({'error': 'User not found'}), 404

            target_uuid, target_username_db, target_private = target

            if target_uuid == requester_uuid:
                return jsonify({'error': 'Cannot search for yourself'}), 400

            # 2. Check for any existing relationship (both directions)
            existing = conn.execute(text("""
                SELECT status FROM friends
                WHERE (requester_uuid = :a AND addressee_uuid = :b)
                   OR (requester_uuid = :b AND addressee_uuid = :a)
            """), {'a': requester_uuid, 'b': target_uuid}).fetchone()

            if existing:
                return jsonify({'status': existing[0]}), 200

            # 3. Fetch push token if we'll need to notify
            device = None
            if target_private:
                device = conn.execute(text("""
                    SELECT push_token FROM user_devices
                    WHERE user_uuid = :u
                    ORDER BY created_at DESC LIMIT 1
                """), {'u': target_uuid}).fetchone()

        # 4a. Public account — return info for the caller to use /friends/request
        if not target_private:
            logger.info(f"Search: {requester_uuid} found public user {target_uuid}")
            return jsonify({
                'user_uuid': target_uuid,
                'username': target_username_db,
                'private': 0
            }), 200

        # 4b. Private account — notify target, do not reveal UUID to requester
        push_token = device[0] if device else None
        notify_connection_request(push_token, requester_uuid, is_online(target_uuid))

        logger.info(f"Search: {requester_uuid} notified private user {target_uuid}")
        return jsonify({'private': 1, 'status': 'notified'}), 200

    except Exception as e:
        logger.error(f"Error in search_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500
