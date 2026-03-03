import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from db import engine
from auth import verify_token
from cache import is_online, check_rate_limit
from notifications import notify_friend_request, notify_request_accepted

friends_bp = Blueprint('friends', __name__)
logger = logging.getLogger(__name__)


@friends_bp.route('/get_friends', methods=['POST'])
def get_friends():
    """
    Returns the accepted friends list for the authenticated user.

    Authentication: Bearer JWT (issued by /validate_login).
    The token encodes the user_uuid — no password is sent after login.

    Each friend entry includes what the client needs to initiate an X3DH session:
      - user_uuid
      - username
      - identity_key_public  (hex — long-term Identity Key)
      - registration_id      (Signal device registration ID)
      - is_online            (True if last_seen within the last 2 minutes)

    Headers:
      Authorization: Bearer <token>
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as connection:
            rows = connection.execute(text("""
                SELECT
                    u.user_uuid,
                    u.username,
                    u.identity_key_public,
                    u.registration_id,
                    (u.last_seen >= NOW() - INTERVAL 2 MINUTE) AS is_online
                FROM friends f
                JOIN users u ON (
                    (f.requester_uuid = :u AND f.addressee_uuid = u.user_uuid)
                    OR
                    (f.addressee_uuid = :u AND f.requester_uuid = u.user_uuid)
                )
                WHERE f.status = 'accepted'
                  AND u.deleted = 0
                ORDER BY u.username ASC
            """), {'u': user_uuid}).fetchall()

        friends = [
            {
                'user_uuid': row[0],
                'username': row[1],
                'identity_key_public': row[2].hex() if row[2] else None,
                'registration_id': row[3],
                'is_online': bool(row[4])
            }
            for row in rows
        ]

        logger.info(f"Returned {len(friends)} friends for user: {user_uuid}")
        return jsonify({'friends': friends}), 200

    except Exception as e:
        logger.error(f"Error fetching friends: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@friends_bp.route('/friends/request', methods=['POST'])
def send_friend_request():
    """
    Sends a friend request from the authenticated user to a target by username.

    Authentication: Bearer JWT.
    Rate limit: 5 requests per hour per user (Redis-backed, fails open).

    Steps:
      1. Resolve target username → UUID.
      2. Check for any existing relationship in either direction (atomic).
      3. Insert pending row. The DB UNIQUE key on (requester, addressee) is the
         last-resort guard against race conditions.
      4. Poke the addressee: silent FCM data message if online, push if offline.
         The notification payload contains no sender identity (metadata minimisation).

    Request body: { "username": "target_username" }
    Headers:      Authorization: Bearer <token>

    Returns:
      201 { "status": "pending" }         — request created
      200 { "status": "<existing_status>" } — relationship already exists
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

        with engine.begin() as conn:  # auto-commit on success, rollback on exception
            # 1. Resolve username → UUID
            target = conn.execute(
                text("SELECT user_uuid FROM users WHERE username = :username AND deleted = 0"),
                {'username': target_username}
            ).fetchone()

            if not target:
                return jsonify({'error': 'User not found'}), 404

            addressee_uuid = target[0]

            if addressee_uuid == requester_uuid:
                return jsonify({'error': 'Cannot send a friend request to yourself'}), 400

            # 2. Check for any existing relationship (both directions)
            existing = conn.execute(text("""
                SELECT status FROM friends
                WHERE (requester_uuid = :a AND addressee_uuid = :b)
                   OR (requester_uuid = :b AND addressee_uuid = :a)
            """), {'a': requester_uuid, 'b': addressee_uuid}).fetchone()

            if existing:
                return jsonify({'status': existing[0]}), 200

            # 3. Insert the pending request
            conn.execute(text("""
                INSERT INTO friends (requester_uuid, addressee_uuid, status)
                VALUES (:requester, :addressee, 'pending')
            """), {'requester': requester_uuid, 'addressee': addressee_uuid})

            # Fetch the addressee's most recent push token while still in transaction
            device = conn.execute(text("""
                SELECT push_token FROM user_devices
                WHERE user_uuid = :u
                ORDER BY created_at DESC LIMIT 1
            """), {'u': addressee_uuid}).fetchone()

        # 4. Poke the addressee outside the DB transaction
        push_token = device[0] if device else None
        notify_friend_request(push_token, is_online(addressee_uuid))

        logger.info(f"Friend request sent: {requester_uuid} → {addressee_uuid}")
        return jsonify({'status': 'pending'}), 201

    except IntegrityError:
        # Race condition: another request slipped in between our check and insert.
        # The relationship exists; just return the current status.
        logger.warning(f"IntegrityError on friend request — concurrent insert detected")
        return jsonify({'status': 'pending'}), 200
    except Exception as e:
        logger.error(f"Error sending friend request: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@friends_bp.route('/friends/accept', methods=['POST'])
def accept_friend_request():
    """
    Accepts a pending friend request directed at the authenticated user.

    Authentication: Bearer JWT (the accepter must be the addressee).

    Steps:
      1. Update the pending row → accepted.
      2. Send a silent FCM data message to the requester so their
         friends list refreshes immediately.

    Request body: { "requester_uuid": "..." }
    Headers:      Authorization: Bearer <token>
    """
    try:
        accepter_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'requester_uuid' not in data:
            return jsonify({'error': 'Missing requester_uuid'}), 400

        requester_uuid = data['requester_uuid']

        with engine.begin() as conn:
            result = conn.execute(text("""
                UPDATE friends
                SET status = 'accepted'
                WHERE requester_uuid = :requester
                  AND addressee_uuid = :accepter
                  AND status = 'pending'
            """), {'requester': requester_uuid, 'accepter': accepter_uuid})

            if result.rowcount == 0:
                return jsonify({'error': 'No pending request found'}), 404

            # Fetch the requester's push token to notify them of acceptance
            device = conn.execute(text("""
                SELECT push_token FROM user_devices
                WHERE user_uuid = :u
                ORDER BY created_at DESC LIMIT 1
            """), {'u': requester_uuid}).fetchone()

        push_token = device[0] if device else None
        notify_request_accepted(push_token)

        logger.info(f"Friend request accepted: {requester_uuid} → {accepter_uuid}")
        return jsonify({'status': 'accepted'}), 200

    except Exception as e:
        logger.error(f"Error accepting friend request: {e}")
        return jsonify({'error': 'Internal server error'}), 500
