import base64
import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text

from db import engine
from auth import verify_token, canonical_uuid
from cache import check_rate_limit, check_rate_limit_for
from notifications import notify_user
from profile import normalize_email, normalize_phone

search_bp = Blueprint('search', __name__)
logger = logging.getLogger(__name__)

USERS_SEARCH_PAGE_SIZE = 20
USERS_SEARCH_RATE_LIMIT_MAX = 10
USERS_SEARCH_RATE_LIMIT_WINDOW = 3600  # seconds


def _decode_page_token(token: str | None) -> int:
    """Opaque pagination cursor: base64 of a plain integer offset."""
    if not token:
        return 0
    try:
        return max(0, int(base64.urlsafe_b64decode(token.encode()).decode()))
    except Exception:
        return 0


def _encode_page_token(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


@search_bp.route('/user/lookup', methods=['POST'])
def lookup_user():
    """
    Resolves a username to a UUID. Requires auth but has no rate limit.
    Intended for internal flows (e.g. accepting a known friend request)
    rather than user discovery.

    Request body: { "username": "target_username" }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "user_uuid": "...", "username": "..." }
      404 { "error": "User not found" }
    """
    try:
        _, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({'error': 'Missing username'}), 400

        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT user_uuid, username FROM users WHERE username = :u AND deleted = 0"),
                {'u': data['username']}
            ).fetchone()

        if not row:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'user_uuid': canonical_uuid(row[0]), 'username': row[1]}), 200

    except Exception as e:
        logger.error(f"Error in lookup_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500


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
            target_uuid = canonical_uuid(target_uuid)

            if target_uuid == requester_uuid:
                return jsonify({'error': 'Cannot search for yourself'}), 400

            # 2. Check for any existing relationship (both directions)
            existing = conn.execute(text("""
                SELECT status FROM friends
                WHERE (requester_uuid = :a AND addressee_uuid = :b)
                   OR (requester_uuid = :b AND addressee_uuid = :a)
            """), {'a': requester_uuid, 'b': target_uuid}).fetchone()

            if existing:
                return jsonify({'status': existing[0], 'user_uuid': target_uuid}), 200

        # 4a. Public account — return info for the caller to use /friends/request
        if not target_private:
            logger.info(f"Search: {requester_uuid} found public user {target_uuid}")
            return jsonify({
                'user_uuid': target_uuid,
                'username': target_username_db,
                'private': 0
            }), 200

        # 4b. Private account — notify target, do not reveal UUID to requester
        notify_user(target_uuid, 'CONNECTION_REQUEST', extra={'requester_uuid': requester_uuid})

        logger.info(f"Search: {requester_uuid} notified private user {target_uuid}")
        return jsonify({'private': 1, 'status': 'notified'}), 200

    except Exception as e:
        logger.error(f"Error in search_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@search_bp.route('/users/search', methods=['POST'])
def search_users():
    """
    Searches for users by exact username, phone, and/or email match, with
    pagination. Unlike /search_user, this is a pure read — no notification
    is sent as a side effect of searching. Sending a friend request for any
    result (public or private) is done separately via the existing
    POST /friends/request, which already resolves by username regardless
    of the target's privacy flag.

    Privacy: phone/email matches are restricted to public accounts
    (users.private = 0) — a private account is reachable ONLY by exact
    username, and even then the response omits user_uuid entirely so the
    client has no way to fetch an avatar or otherwise treat it like a
    public result.

    Authentication: Bearer PASETO token.
    Rate limit: 10 calls per hour per user (separate bucket from
    /friends/request's 5/hr — this is a distinct action).

    Request body:
      {
        "username":   "optional — exact match, any privacy setting",
        "phone":      "optional — exact match, public accounts only",
        "email":      "optional — exact match, public accounts only",
        "page_token": "optional — opaque cursor from a previous response"
      }
    At least one of username/phone/email is required.

    Response 200:
      {
        "results": [
          { "user_uuid": "...", "username": "...", "private": 0,
            "status": "none"|"pending"|"accepted", "matched_fields": ["phone"] },
          { "username": "...", "private": 1, "status": "none"|"pending"|"accepted" }
        ],
        "next_page_token": "..." | null
      }
    """
    try:
        requester_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('user_search', requester_uuid,
                                     USERS_SEARCH_RATE_LIMIT_MAX, USERS_SEARCH_RATE_LIMIT_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json() or {}
        username = (data.get('username') or '').strip() or None
        phone = (data.get('phone') or '').strip() or None
        email = (data.get('email') or '').strip() or None

        if not username and not phone and not email:
            return jsonify({'error': 'Provide at least one of username, phone, or email'}), 400

        if phone:
            phone = normalize_phone(phone)
        if email:
            email = normalize_email(email)

        offset = _decode_page_token(data.get('page_token'))

        conditions = []
        params = {'requester': requester_uuid}
        if username:
            conditions.append("u.username = :username")
            params['username'] = username
        if phone:
            conditions.append("(u.private = 0 AND p.phone = :phone)")
            params['phone'] = phone
        if email:
            conditions.append("(u.private = 0 AND p.email = :email)")
            params['email'] = email

        where_clause = " OR ".join(conditions)

        with engine.connect() as conn:
            rows = conn.execute(text(f"""
                SELECT u.user_uuid, u.username, u.private, p.phone, p.email
                FROM users u
                LEFT JOIN user_profiles p ON p.user_uuid = u.user_uuid
                WHERE u.deleted = 0
                  AND u.user_uuid != :requester
                  AND ({where_clause})
                ORDER BY u.username ASC
                LIMIT :limit OFFSET :offset
            """), {**params, 'limit': USERS_SEARCH_PAGE_SIZE + 1, 'offset': offset}).fetchall()

            has_more = len(rows) > USERS_SEARCH_PAGE_SIZE
            rows = rows[:USERS_SEARCH_PAGE_SIZE]

            results = []
            for target_uuid, target_username, target_private, target_phone, target_email in rows:
                existing = conn.execute(text("""
                    SELECT status FROM friends
                    WHERE (requester_uuid = :a AND addressee_uuid = :b)
                       OR (requester_uuid = :b AND addressee_uuid = :a)
                """), {'a': requester_uuid, 'b': target_uuid}).fetchone()
                status = existing[0] if existing else 'none'

                if target_private:
                    results.append({
                        'username': target_username,
                        'private': 1,
                        'status': status,
                    })
                else:
                    matched_fields = []
                    if username and target_username == username:
                        matched_fields.append('username')
                    if phone and target_phone == phone:
                        matched_fields.append('phone')
                    if email and target_email == email:
                        matched_fields.append('email')
                    results.append({
                        'user_uuid': canonical_uuid(target_uuid),
                        'username': target_username,
                        'private': 0,
                        'status': status,
                        'matched_fields': matched_fields,
                    })

        next_page_token = _encode_page_token(offset + USERS_SEARCH_PAGE_SIZE) if has_more else None

        logger.info(f"users/search: {requester_uuid} found {len(results)} match(es)")
        return jsonify({'results': results, 'next_page_token': next_page_token}), 200

    except Exception as e:
        logger.error(f"Error in search_users: {e}")
        return jsonify({'error': 'Internal server error'}), 500
