import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text

from db import engine
from auth import verify_token

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
      - is_online            (True if last_seen within the last 5 minutes)

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
                    (u.last_seen >= NOW() - INTERVAL 5 MINUTE) AS is_online
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
