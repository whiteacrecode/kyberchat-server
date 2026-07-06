import base64
import logging
import uuid as uuidlib
from flask import Blueprint, request, jsonify
from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError

from db import engine
from auth import verify_token
from cache import check_rate_limit_for
from notifications import notify_user
from firebase import sync_group_membership, delete_group_membership_mirror, set_group_icon
from search import _decode_page_token, _encode_page_token

groups_bp = Blueprint('groups', __name__)
logger = logging.getLogger(__name__)

# Sender-key fanout cost is O(members) per key distribution, so we cap group
# size well below Signal's ~1000-member limit. Revisit if usage demands more.
MAX_GROUP_MEMBERS = 50

MAX_GROUP_NAME_LEN = 100
MAX_DESCRIPTION_LEN = 500

# Sanity cap on the decoded icon JPEG. The client resizes/compresses to
# ~200x200 before upload (see GroupIconService.uploadIcon on iOS) — this is
# just a server-side guard against a misbehaving/hostile client, not the
# primary size control.
MAX_ICON_DECODED_BYTES = 60_000

_CREATE_RATE_MAX, _CREATE_RATE_WINDOW = 10, 3600          # 10 groups/hour
_ADD_MEMBER_RATE_MAX, _ADD_MEMBER_RATE_WINDOW = 30, 3600  # 30 adds/hour
_INVITE_RATE_MAX, _INVITE_RATE_WINDOW = 30, 3600          # 30 invites/hour
_SEARCH_RATE_MAX, _SEARCH_RATE_WINDOW = 20, 3600          # 20 searches/hour
_JOIN_RATE_MAX, _JOIN_RATE_WINDOW = 20, 3600              # 20 self-joins/hour

GROUPS_SEARCH_PAGE_SIZE = 20


def _fetch_member_uuids(conn, group_uuid: str) -> list:
    rows = conn.execute(
        text("SELECT user_uuid FROM group_members WHERE group_uuid = :g"),
        {'g': group_uuid}
    ).fetchall()
    return [row[0] for row in rows]


def _fetch_role(conn, group_uuid: str, user_uuid: str):
    row = conn.execute(text("""
        SELECT role FROM group_members
        WHERE group_uuid = :g AND user_uuid = :u
    """), {'g': group_uuid, 'u': user_uuid}).fetchone()
    return row[0] if row else None


def _fetch_member_count(conn, group_uuid: str) -> int:
    row = conn.execute(
        text("SELECT COUNT(*) FROM group_members WHERE group_uuid = :g"),
        {'g': group_uuid}
    ).fetchone()
    return row[0] if row else 0


@groups_bp.route('/groups/create', methods=['POST'])
def create_group():
    """
    Creates a new group with the authenticated user as owner.

    Authentication: Bearer PASETO token.
    Rate limit: 10 groups per hour per user.

    Request body:
      {
        "group_name": "string",
        "member_uuids": ["uuid1", "uuid2", ...],
        "description": "optional string, <= 500 chars",
        "searchable": "optional bool, default false",
        "message_ttl_seconds": "optional int >= 0, or null for no expiry"
      }
      (member_uuids should NOT include the caller — they're added as owner
      automatically. Duplicates and the caller's own uuid, if present, are
      silently ignored.)

    Steps:
      1. Validate group_name, description, message_ttl_seconds, and member
         count (<= MAX_GROUP_MEMBERS).
      2. Verify every member_uuid resolves to an active user.
      3. Insert kybergroups row + group_members rows (owner + members).
      4. Mirror the roster into Firestore (groups/{group_uuid}.members) so
         Firestore security rules can authorize group_conversations access.
      5. Notify each invited member (GROUP_INVITE) so their client can pull
         the new group and start distributing/receiving sender keys.

    Returns:
      201 { "group_uuid": "...", "group_name": "...", "description": "...",
            "searchable": false, "message_ttl_seconds": null,
            "member_uuids": [...] }
      400 missing/invalid fields, too many members, or unknown member_uuid
    """
    try:
        owner_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('group_create', owner_uuid, _CREATE_RATE_MAX, _CREATE_RATE_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json()
        if not data or not data.get('group_name'):
            return jsonify({'error': 'Missing group_name'}), 400

        group_name = data['group_name'].strip()
        if not group_name:
            return jsonify({'error': 'group_name cannot be blank'}), 400
        if len(group_name) > MAX_GROUP_NAME_LEN:
            return jsonify({'error': f'group_name must be <= {MAX_GROUP_NAME_LEN} characters'}), 400

        description = data.get('description')
        if description is not None:
            description = description.strip() or None
        if description and len(description) > MAX_DESCRIPTION_LEN:
            return jsonify({'error': f'description must be <= {MAX_DESCRIPTION_LEN} characters'}), 400

        searchable = bool(data.get('searchable', False))

        message_ttl_seconds = data.get('message_ttl_seconds')
        if message_ttl_seconds is not None:
            if not isinstance(message_ttl_seconds, int) or isinstance(message_ttl_seconds, bool) or message_ttl_seconds < 0:
                return jsonify({'error': 'message_ttl_seconds must be a non-negative integer or null'}), 400

        member_uuids = list({
            u for u in (data.get('member_uuids') or [])
            if u and u != owner_uuid
        })

        if len(member_uuids) + 1 > MAX_GROUP_MEMBERS:
            return jsonify({'error': f'Groups are limited to {MAX_GROUP_MEMBERS} members'}), 400

        group_uuid = str(uuidlib.uuid4())

        with engine.begin() as conn:
            if member_uuids:
                found = conn.execute(
                    text("""
                        SELECT user_uuid FROM users
                        WHERE user_uuid IN :uuids AND deleted = 0
                    """).bindparams(bindparam('uuids', expanding=True)),
                    {'uuids': member_uuids}
                ).fetchall()
                found_uuids = {row[0] for row in found}
                missing = set(member_uuids) - found_uuids
                if missing:
                    return jsonify({'error': f'Unknown member_uuid(s): {sorted(missing)}'}), 400

            conn.execute(text("""
                INSERT INTO kybergroups (group_uuid, group_name, owner_uuid, description, searchable, message_ttl_seconds)
                VALUES (:g, :name, :owner, :description, :searchable, :ttl)
            """), {
                'g': group_uuid, 'name': group_name, 'owner': owner_uuid,
                'description': description, 'searchable': searchable, 'ttl': message_ttl_seconds
            })

            conn.execute(text("""
                INSERT INTO group_members (group_uuid, user_uuid, role)
                VALUES (:g, :u, 'owner')
            """), {'g': group_uuid, 'u': owner_uuid})

            for member_uuid in member_uuids:
                conn.execute(text("""
                    INSERT INTO group_members (group_uuid, user_uuid, role)
                    VALUES (:g, :u, 'member')
                """), {'g': group_uuid, 'u': member_uuid})

        all_members = [owner_uuid] + member_uuids
        sync_group_membership(group_uuid, all_members)

        for member_uuid in member_uuids:
            notify_user(member_uuid, 'GROUP_INVITE', {'group_uuid': group_uuid})

        logger.info(f"Group created: {group_uuid} by {owner_uuid} with {len(member_uuids)} members")
        return jsonify({
            'group_uuid': group_uuid,
            'group_name': group_name,
            'description': description,
            'searchable': searchable,
            'message_ttl_seconds': message_ttl_seconds,
            'member_uuids': all_members
        }), 201

    except Exception as e:
        logger.error(f"Error creating group: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/members/add', methods=['POST'])
def add_group_member():
    """
    Adds a member to an existing group. Owner-only in v1.

    Request body: { "group_uuid": "...", "member_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Steps:
      1. Verify caller is the group owner.
      2. Verify target user exists and isn't already a member.
      3. Insert group_members row, re-sync the Firestore mirror.
      4. Notify the new member (GROUP_INVITE) and every existing member
         (GROUP_MEMBER_ADDED) so they redistribute their sender key to the
         newcomer over the existing pairwise Double Ratchet channel.

    Returns:
      201 { "message": "Member added" }
      400 missing fields / already a member
      403 caller is not the owner
      404 group or user not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('group_add_member', caller_uuid, _ADD_MEMBER_RATE_MAX, _ADD_MEMBER_RATE_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json()
        if not data or 'group_uuid' not in data or 'member_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid or member_uuid'}), 400

        group_uuid = data['group_uuid']
        member_uuid = data['member_uuid']

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can add members'}), 403

            target = conn.execute(
                text("SELECT user_uuid FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': member_uuid}
            ).fetchone()
            if not target:
                return jsonify({'error': 'User not found'}), 404

            existing_members = _fetch_member_uuids(conn, group_uuid)
            if member_uuid in existing_members:
                return jsonify({'error': 'User is already a member'}), 400

            if len(existing_members) + 1 > MAX_GROUP_MEMBERS:
                return jsonify({'error': f'Groups are limited to {MAX_GROUP_MEMBERS} members'}), 400

            conn.execute(text("""
                INSERT INTO group_members (group_uuid, user_uuid, role)
                VALUES (:g, :u, 'member')
            """), {'g': group_uuid, 'u': member_uuid})

            updated_members = existing_members + [member_uuid]

        sync_group_membership(group_uuid, updated_members)

        notify_user(member_uuid, 'GROUP_INVITE', {'group_uuid': group_uuid})
        for existing_uuid in existing_members:
            if existing_uuid != caller_uuid:
                notify_user(existing_uuid, 'GROUP_MEMBER_ADDED',
                            {'group_uuid': group_uuid, 'member_uuid': member_uuid})

        logger.info(f"Group member added: {member_uuid} -> {group_uuid} by {caller_uuid}")
        return jsonify({'message': 'Member added'}), 201

    except IntegrityError:
        return jsonify({'error': 'User is already a member'}), 400
    except Exception as e:
        logger.error(f"Error adding group member: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/members/remove', methods=['POST'])
def remove_group_member():
    """
    Removes a member from a group. Allowed if the caller is the group owner
    (removing anyone else) OR the caller is removing themselves (self-leave).
    The owner can never be removed this way — use DELETE /groups/<group_uuid>
    to disband the group instead.

    Request body: { "group_uuid": "...", "member_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Member removed" }
      400 target is the owner
      403 caller is neither the owner nor the target themselves
      404 group or membership not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data or 'member_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid or member_uuid'}), 400

        group_uuid = data['group_uuid']
        member_uuid = data['member_uuid']

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            is_owner = group[0] == caller_uuid
            is_self = caller_uuid == member_uuid

            if not is_owner and not is_self:
                return jsonify({'error': 'Only the group owner can remove other members'}), 403

            if member_uuid == group[0]:
                return jsonify({'error': 'Cannot remove the owner — delete the group instead'}), 400

            result = conn.execute(text("""
                DELETE FROM group_members
                WHERE group_uuid = :g AND user_uuid = :u AND role = 'member'
            """), {'g': group_uuid, 'u': member_uuid})

            if result.rowcount == 0:
                return jsonify({'error': 'Membership not found'}), 404

            remaining_members = _fetch_member_uuids(conn, group_uuid)

        sync_group_membership(group_uuid, remaining_members)

        # Phase 7 (GROUP_PLAN.md): this push is what drives sender-key
        # rotation on the client. Each remaining member's device (see
        # AppDelegate.handleKyberChatPush → GroupsStore.
        # rotateSenderKeyAfterRemoval) generates a brand new chain key on
        # receipt and redistributes it over the existing pairwise ratchet
        # channels, so the removed member's retained chain key only ever
        # unlocks messages up to this point — nothing sent afterward.
        # Best-effort like the rest of this handshake: a client that's
        # offline when this push arrives rotates lazily next time it opens
        # the Groups tab and its GroupsStore reloads.
        for remaining_uuid in remaining_members:
            notify_user(remaining_uuid, 'GROUP_MEMBER_REMOVED',
                        {'group_uuid': group_uuid, 'member_uuid': member_uuid})
        notify_user(member_uuid, 'GROUP_MEMBER_REMOVED',
                    {'group_uuid': group_uuid, 'member_uuid': member_uuid})

        logger.info(f"Group member removed: {member_uuid} from {group_uuid} by {caller_uuid}")
        return jsonify({'message': 'Member removed'}), 200

    except Exception as e:
        logger.error(f"Error removing group member: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/leave', methods=['POST'])
def leave_group():
    """
    Removes the authenticated user from a group they belong to.
    The owner cannot leave — they must delete the group instead (no
    ownership-transfer flow exists in v1).

    Request body: { "group_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Left group" }
      400 caller is the owner
      404 not a member of this group
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']

        with engine.begin() as conn:
            role = _fetch_role(conn, group_uuid, user_uuid)
            if role is None:
                return jsonify({'error': 'Not a member of this group'}), 404

            if role == 'owner':
                return jsonify({'error': 'Owner cannot leave — delete the group instead'}), 400

            conn.execute(text("""
                DELETE FROM group_members WHERE group_uuid = :g AND user_uuid = :u
            """), {'g': group_uuid, 'u': user_uuid})

            remaining_members = _fetch_member_uuids(conn, group_uuid)

        sync_group_membership(group_uuid, remaining_members)

        for remaining_uuid in remaining_members:
            notify_user(remaining_uuid, 'GROUP_MEMBER_REMOVED',
                        {'group_uuid': group_uuid, 'member_uuid': user_uuid})

        logger.info(f"User left group: {user_uuid} left {group_uuid}")
        return jsonify({'message': 'Left group'}), 200

    except Exception as e:
        logger.error(f"Error leaving group: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/get_groups', methods=['POST'])
def get_groups():
    """
    Returns all groups the authenticated user belongs to, with the full
    member roster (uuid, username, role) for each — mirrors the shape of
    POST /get_friends.

    Headers: Authorization: Bearer <token>

    Returns:
      200 {
        "groups": [
          {
            "group_uuid": "...", "group_name": "...", "owner_uuid": "...",
            "description": "...", "searchable": false, "message_ttl_seconds": null,
            "created_at": "ISO-8601",
            "members": [{"user_uuid": "...", "username": "...", "role": "owner"}, ...]
          }, ...
        ]
      }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as conn:
            group_rows = conn.execute(text("""
                SELECT g.group_uuid, g.group_name, g.owner_uuid, g.created_at,
                       g.description, g.searchable, g.message_ttl_seconds
                FROM kybergroups g
                JOIN group_members gm ON gm.group_uuid = g.group_uuid
                WHERE gm.user_uuid = :u AND g.deleted = 0
                ORDER BY g.created_at DESC
            """), {'u': user_uuid}).fetchall()

            groups = []
            for row in group_rows:
                group_uuid = row[0]
                member_rows = conn.execute(text("""
                    SELECT u.user_uuid, u.username, gm.role
                    FROM group_members gm
                    JOIN users u ON u.user_uuid = gm.user_uuid
                    WHERE gm.group_uuid = :g AND u.deleted = 0
                    ORDER BY gm.role DESC, u.username ASC
                """), {'g': group_uuid}).fetchall()

                groups.append({
                    'group_uuid': group_uuid,
                    'group_name': row[1],
                    'owner_uuid': row[2],
                    'created_at': row[3].isoformat() if row[3] else None,
                    'description': row[4],
                    'searchable': bool(row[5]),
                    'message_ttl_seconds': row[6],
                    'members': [
                        {'user_uuid': m[0], 'username': m[1], 'role': m[2]}
                        for m in member_rows
                    ]
                })

        return jsonify({'groups': groups}), 200

    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/edit', methods=['POST'])
def edit_group():
    """
    Edits a group's metadata. Owner-only. All fields are optional — only the
    ones present in the request body are updated.

    Request body:
      {
        "group_uuid": "...",
        "group_name": "optional, <= 100 chars, non-blank if provided",
        "description": "optional, <= 500 chars, null/empty clears it",
        "searchable": "optional bool",
        "message_ttl_seconds": "optional int >= 0, or null to disable expiry"
      }
    Headers: Authorization: Bearer <token>

    Returns:
      200 { "group_uuid": "...", "group_name": "...", "description": "...",
            "searchable": false, "message_ttl_seconds": null }
      400 no group_uuid / no fields to update / invalid field value
      403 caller is not the owner
      404 group not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']

        updates = {}

        if 'group_name' in data:
            group_name = (data['group_name'] or '').strip()
            if not group_name:
                return jsonify({'error': 'group_name cannot be blank'}), 400
            if len(group_name) > MAX_GROUP_NAME_LEN:
                return jsonify({'error': f'group_name must be <= {MAX_GROUP_NAME_LEN} characters'}), 400
            updates['group_name'] = group_name

        if 'description' in data:
            description = data['description']
            if description is not None:
                description = description.strip() or None
            if description and len(description) > MAX_DESCRIPTION_LEN:
                return jsonify({'error': f'description must be <= {MAX_DESCRIPTION_LEN} characters'}), 400
            updates['description'] = description

        if 'searchable' in data:
            updates['searchable'] = bool(data['searchable'])

        if 'message_ttl_seconds' in data:
            ttl = data['message_ttl_seconds']
            if ttl is not None:
                if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
                    return jsonify({'error': 'message_ttl_seconds must be a non-negative integer or null'}), 400
            updates['message_ttl_seconds'] = ttl

        if not updates:
            return jsonify({'error': 'No fields to update'}), 400

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can edit the group'}), 403

            set_clause = ', '.join(f"{col} = :{col}" for col in updates)
            conn.execute(
                text(f"UPDATE kybergroups SET {set_clause} WHERE group_uuid = :g"),
                {**updates, 'g': group_uuid}
            )

            row = conn.execute(text("""
                SELECT group_name, description, searchable, message_ttl_seconds
                FROM kybergroups WHERE group_uuid = :g
            """), {'g': group_uuid}).fetchone()

            members = _fetch_member_uuids(conn, group_uuid)

        for member_uuid in members:
            if member_uuid != caller_uuid:
                notify_user(member_uuid, 'GROUP_UPDATED', {'group_uuid': group_uuid})

        logger.info(f"Group edited: {group_uuid} by {caller_uuid} ({sorted(updates.keys())})")
        return jsonify({
            'group_uuid': group_uuid,
            'group_name': row[0],
            'description': row[1],
            'searchable': bool(row[2]),
            'message_ttl_seconds': row[3]
        }), 200

    except Exception as e:
        logger.error(f"Error editing group: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/icon', methods=['POST'])
def set_group_icon_endpoint():
    """
    Sets or clears a group's icon. Owner-only.

    Request body: { "group_uuid": "...", "icon_jpeg_b64": "<base64>" | null }
    Headers:      Authorization: Bearer <token>

    The server only sanity-checks decodability and size — resizing/compression
    to ~200x200 happens client-side (see GroupIconService.uploadIcon on iOS).
    Stored in the group's existing Firestore membership-mirror doc
    (groups/{group_uuid}.icon_jpeg_b64), which is already read-restricted to
    members by firestore.rules — no new collection or rule needed.

    Returns:
      200 { "message": "Group icon updated" }
      400 missing group_uuid / icon_jpeg_b64 not valid base64 / too large
      403 caller is not the owner
      404 group not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']
        # Absent or null both mean "clear the icon".
        icon_jpeg_b64 = data.get('icon_jpeg_b64')

        if icon_jpeg_b64 is not None:
            if not isinstance(icon_jpeg_b64, str) or not icon_jpeg_b64.strip():
                return jsonify({'error': 'icon_jpeg_b64 must be a non-empty base64 string or null'}), 400
            try:
                decoded = base64.b64decode(icon_jpeg_b64, validate=True)
            except Exception:
                return jsonify({'error': 'icon_jpeg_b64 is not valid base64'}), 400
            if len(decoded) > MAX_ICON_DECODED_BYTES:
                return jsonify({'error': f'Icon must be <= {MAX_ICON_DECODED_BYTES} bytes after decoding'}), 400

        with engine.connect() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can change the group icon'}), 403

            members = _fetch_member_uuids(conn, group_uuid)

        set_group_icon(group_uuid, icon_jpeg_b64)

        for member_uuid in members:
            if member_uuid != caller_uuid:
                notify_user(member_uuid, 'GROUP_ICON_UPDATED', {'group_uuid': group_uuid})

        action = 'cleared' if icon_jpeg_b64 is None else 'updated'
        logger.info(f"Group icon {action}: {group_uuid} by {caller_uuid}")
        return jsonify({'message': 'Group icon updated'}), 200

    except Exception as e:
        logger.error(f"Error setting group icon: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/invite', methods=['POST'])
def invite_to_group():
    """
    Sends a pending invite for a user to join a group. Owner-only. Unlike
    POST /groups/members/add (which adds a member immediately), this
    requires the invitee to accept via POST /groups/invite/accept before
    they become a member.

    Rate limit: 30 invites per hour per user.

    Request body: { "group_uuid": "...", "username": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      201 { "status": "pending" }        — invite created
      200 { "status": "pending" }        — invite already existed
      400 missing fields / inviting self / already a member
      403 caller is not the owner
      404 group or user not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('group_invite', caller_uuid, _INVITE_RATE_MAX, _INVITE_RATE_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json()
        if not data or 'group_uuid' not in data or not data.get('username'):
            return jsonify({'error': 'Missing group_uuid or username'}), 400

        group_uuid = data['group_uuid']
        username = data['username']

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid, group_name FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can invite members'}), 403

            target = conn.execute(
                text("SELECT user_uuid FROM users WHERE username = :u AND deleted = 0"),
                {'u': username}
            ).fetchone()
            if not target:
                return jsonify({'error': 'User not found'}), 404

            invitee_uuid = target[0]

            if invitee_uuid == caller_uuid:
                return jsonify({'error': 'Cannot invite yourself'}), 400

            existing_members = _fetch_member_uuids(conn, group_uuid)
            if invitee_uuid in existing_members:
                return jsonify({'error': 'User is already a member'}), 400

            if len(existing_members) + 1 > MAX_GROUP_MEMBERS:
                return jsonify({'error': f'Groups are limited to {MAX_GROUP_MEMBERS} members'}), 400

            existing_invite = conn.execute(text("""
                SELECT 1 FROM group_invites WHERE group_uuid = :g AND invitee_uuid = :u
            """), {'g': group_uuid, 'u': invitee_uuid}).fetchone()
            if existing_invite:
                return jsonify({'status': 'pending'}), 200

            conn.execute(text("""
                INSERT INTO group_invites (group_uuid, invitee_uuid, inviter_uuid)
                VALUES (:g, :invitee, :inviter)
            """), {'g': group_uuid, 'invitee': invitee_uuid, 'inviter': caller_uuid})

        notify_user(invitee_uuid, 'GROUP_INVITE_RECEIVED',
                    {'group_uuid': group_uuid, 'group_name': group[1]})

        logger.info(f"Group invite sent: {invitee_uuid} invited to {group_uuid} by {caller_uuid}")
        return jsonify({'status': 'pending'}), 201

    except IntegrityError:
        return jsonify({'status': 'pending'}), 200
    except Exception as e:
        logger.error(f"Error inviting to group: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/invites/pending', methods=['POST'])
def get_pending_group_invites():
    """
    Returns pending group invites addressed to the authenticated user.

    Headers: Authorization: Bearer <token>

    Returns:
      200 {
        "invites": [
          { "group_uuid": "...", "group_name": "...", "description": "...",
            "inviter_uuid": "...", "inviter_username": "...",
            "created_at": "ISO-8601" }, ...
        ]
      }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT gi.group_uuid, g.group_name, g.description,
                       gi.inviter_uuid, u.username, gi.created_at
                FROM group_invites gi
                JOIN kybergroups g ON g.group_uuid = gi.group_uuid
                JOIN users u ON u.user_uuid = gi.inviter_uuid
                WHERE gi.invitee_uuid = :u AND g.deleted = 0
                ORDER BY gi.created_at DESC
            """), {'u': user_uuid}).fetchall()

        invites = [
            {
                'group_uuid': row[0],
                'group_name': row[1],
                'description': row[2],
                'inviter_uuid': row[3],
                'inviter_username': row[4],
                'created_at': row[5].isoformat() if row[5] else None
            }
            for row in rows
        ]

        return jsonify({'invites': invites}), 200

    except Exception as e:
        logger.error(f"Error fetching pending group invites: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/invite/accept', methods=['POST'])
def accept_group_invite():
    """
    Accepts a pending invite, joining the authenticated user to the group.

    Request body: { "group_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Joined group", "group_uuid": "..." }
      400 group is full
      404 no pending invite found
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']

        with engine.begin() as conn:
            invite = conn.execute(text("""
                SELECT inviter_uuid FROM group_invites
                WHERE group_uuid = :g AND invitee_uuid = :u
            """), {'g': group_uuid, 'u': user_uuid}).fetchone()
            if not invite:
                return jsonify({'error': 'No pending invite found'}), 404

            inviter_uuid = invite[0]

            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                conn.execute(text("""
                    DELETE FROM group_invites WHERE group_uuid = :g AND invitee_uuid = :u
                """), {'g': group_uuid, 'u': user_uuid})
                return jsonify({'error': 'Group not found'}), 404

            existing_members = _fetch_member_uuids(conn, group_uuid)
            if len(existing_members) + 1 > MAX_GROUP_MEMBERS:
                return jsonify({'error': f'Groups are limited to {MAX_GROUP_MEMBERS} members'}), 400

            conn.execute(text("""
                DELETE FROM group_invites WHERE group_uuid = :g AND invitee_uuid = :u
            """), {'g': group_uuid, 'u': user_uuid})

            conn.execute(text("""
                INSERT INTO group_members (group_uuid, user_uuid, role)
                VALUES (:g, :u, 'member')
            """), {'g': group_uuid, 'u': user_uuid})

            updated_members = existing_members + [user_uuid]

        sync_group_membership(group_uuid, updated_members)

        notify_user(inviter_uuid, 'GROUP_INVITE_ACCEPTED',
                    {'group_uuid': group_uuid, 'member_uuid': user_uuid})
        for existing_uuid in existing_members:
            if existing_uuid != inviter_uuid:
                notify_user(existing_uuid, 'GROUP_MEMBER_ADDED',
                            {'group_uuid': group_uuid, 'member_uuid': user_uuid})

        logger.info(f"Group invite accepted: {user_uuid} joined {group_uuid}")
        return jsonify({'message': 'Joined group', 'group_uuid': group_uuid}), 200

    except IntegrityError:
        return jsonify({'error': 'Already a member'}), 400
    except Exception as e:
        logger.error(f"Error accepting group invite: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/invite/decline', methods=['POST'])
def decline_group_invite():
    """
    Declines a pending group invite addressed to the authenticated user.
    Deletes the row outright — the inviter is free to invite again later.

    Request body: { "group_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Invite declined" }
      404 no pending invite found
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']

        with engine.begin() as conn:
            result = conn.execute(text("""
                DELETE FROM group_invites WHERE group_uuid = :g AND invitee_uuid = :u
            """), {'g': group_uuid, 'u': user_uuid})

            if result.rowcount == 0:
                return jsonify({'error': 'No pending invite found'}), 404

        logger.info(f"Group invite declined: {user_uuid} declined {group_uuid}")
        return jsonify({'message': 'Invite declined'}), 200

    except Exception as e:
        logger.error(f"Error declining group invite: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/members/role', methods=['POST'])
def set_group_member_role():
    """
    Changes a member's role. Owner-only. Setting role="owner" transfers
    ownership: the caller (current owner) becomes a regular member and the
    target becomes the sole owner (both kybergroups.owner_uuid and the
    group_members role are updated atomically). There is always exactly one
    owner, so role="member" is only meaningful as a no-op confirmation for
    a user who is already a plain member — the owner cannot demote
    themselves without transferring ownership first.

    Request body: { "group_uuid": "...", "member_uuid": "...", "role": "owner"|"member" }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "...", "owner_uuid": "..." }
      400 invalid role / target is caller trying to no-op-demote themselves
      403 caller is not the owner
      404 group or membership not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'group_uuid' not in data or 'member_uuid' not in data or 'role' not in data:
            return jsonify({'error': 'Missing group_uuid, member_uuid, or role'}), 400

        group_uuid = data['group_uuid']
        member_uuid = data['member_uuid']
        role = data['role']

        if role not in ('owner', 'member'):
            return jsonify({'error': "role must be 'owner' or 'member'"}), 400

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can change member roles'}), 403

            target_role = _fetch_role(conn, group_uuid, member_uuid)
            if target_role is None:
                return jsonify({'error': 'User is not a member of this group'}), 404

            if role == 'owner':
                if member_uuid == caller_uuid:
                    return jsonify({'error': 'Caller is already the owner'}), 400

                conn.execute(
                    text("UPDATE kybergroups SET owner_uuid = :m WHERE group_uuid = :g"),
                    {'m': member_uuid, 'g': group_uuid}
                )
                conn.execute(text("""
                    UPDATE group_members SET role = 'member'
                    WHERE group_uuid = :g AND user_uuid = :u
                """), {'g': group_uuid, 'u': caller_uuid})
                conn.execute(text("""
                    UPDATE group_members SET role = 'owner'
                    WHERE group_uuid = :g AND user_uuid = :u
                """), {'g': group_uuid, 'u': member_uuid})

                members = _fetch_member_uuids(conn, group_uuid)

                for member in members:
                    if member not in (caller_uuid, member_uuid):
                        notify_user(member, 'GROUP_OWNER_CHANGED',
                                    {'group_uuid': group_uuid, 'owner_uuid': member_uuid})
                notify_user(member_uuid, 'GROUP_OWNER_CHANGED',
                            {'group_uuid': group_uuid, 'owner_uuid': member_uuid})
                notify_user(caller_uuid, 'GROUP_OWNER_CHANGED',
                            {'group_uuid': group_uuid, 'owner_uuid': member_uuid})

                logger.info(f"Group ownership transferred: {group_uuid} {caller_uuid} -> {member_uuid}")
                return jsonify({'message': 'Ownership transferred', 'owner_uuid': member_uuid}), 200

            # role == 'member'
            if member_uuid == caller_uuid:
                return jsonify({'error': 'Owner cannot demote themselves — transfer ownership instead'}), 400

            # Only one owner ever exists (the caller), so any other member is
            # already role='member' — this is a confirming no-op.
            return jsonify({'message': 'User is already a member', 'owner_uuid': group[0]}), 200

    except Exception as e:
        logger.error(f"Error changing group member role: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/search', methods=['POST'])
def search_groups():
    """
    Searches for groups by name or description, restricted to groups that
    have opted in via searchable=1. Non-searchable groups never appear here
    regardless of match.

    Rate limit: 20 searches per hour per user.

    Request body:
      { "query": "string, <= 100 chars", "page_token": "optional — opaque cursor" }

    Response 200:
      {
        "groups": [
          { "group_uuid": "...", "group_name": "...", "description": "...",
            "owner_uuid": "...", "member_count": 5, "is_member": false }, ...
        ],
        "next_page_token": "..." | null
      }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('group_search', user_uuid, _SEARCH_RATE_MAX, _SEARCH_RATE_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json() or {}
        query = (data.get('query') or '').strip()
        if not query:
            return jsonify({'error': 'Missing query'}), 400
        if len(query) > 100:
            return jsonify({'error': 'query must be <= 100 characters'}), 400

        # Escape LIKE metacharacters so a query containing % or _ matches
        # literally rather than as a wildcard.
        escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        like_term = f"%{escaped}%"

        offset = _decode_page_token(data.get('page_token'))

        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT group_uuid, group_name, description, owner_uuid
                FROM kybergroups
                WHERE deleted = 0 AND searchable = 1
                  AND (group_name LIKE :like OR description LIKE :like)
                ORDER BY group_name ASC
                LIMIT :limit OFFSET :offset
            """), {'like': like_term, 'limit': GROUPS_SEARCH_PAGE_SIZE + 1, 'offset': offset}).fetchall()

            has_more = len(rows) > GROUPS_SEARCH_PAGE_SIZE
            rows = rows[:GROUPS_SEARCH_PAGE_SIZE]

            results = []
            for group_uuid, group_name, description, owner_uuid in rows:
                member_count = _fetch_member_count(conn, group_uuid)
                is_member = _fetch_role(conn, group_uuid, user_uuid) is not None
                results.append({
                    'group_uuid': group_uuid,
                    'group_name': group_name,
                    'description': description,
                    'owner_uuid': owner_uuid,
                    'member_count': member_count,
                    'is_member': is_member
                })

        next_page_token = _encode_page_token(offset + GROUPS_SEARCH_PAGE_SIZE) if has_more else None

        logger.info(f"groups/search: {user_uuid} found {len(results)} match(es)")
        return jsonify({'groups': results, 'next_page_token': next_page_token}), 200

    except Exception as e:
        logger.error(f"Error searching groups: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/join', methods=['POST'])
def join_group():
    """
    Self-service join for a discoverable group. This is the counterpart to
    /groups/search: any group the owner opts into search (searchable=1) is
    also open to be joined directly, with no owner-approval step. This is the
    deliberate v1 semantic — "discoverable" means "open-join". If a future
    version needs an approval gate, this insert is what a join-request table
    would come to guard.

    Contrast with the other join paths:
      • /groups/members/add   — owner adds an existing friend directly
      • /groups/invite/accept — invitee accepts an owner-initiated invite
      • /groups/join          — requester joins an opted-in public group (here)

    Rate limit: 20 joins per hour per user.

    Request body: { "group_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Joined group", "group_uuid": "..." }
      400 group is full / already a member
      403 group is not open to join (searchable=0)
      404 group not found
      429 rate limit exceeded
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        if not check_rate_limit_for('group_join', user_uuid, _JOIN_RATE_MAX, _JOIN_RATE_WINDOW):
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

        data = request.get_json()
        if not data or 'group_uuid' not in data:
            return jsonify({'error': 'Missing group_uuid'}), 400

        group_uuid = data['group_uuid']

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT searchable FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            # Only discoverable groups are self-joinable. A non-searchable
            # group is joinable only by owner-add or accepted invite.
            if not group[0]:
                return jsonify({'error': 'This group is not open to join'}), 403

            existing_members = _fetch_member_uuids(conn, group_uuid)
            if user_uuid in existing_members:
                return jsonify({'error': 'Already a member'}), 400
            if len(existing_members) + 1 > MAX_GROUP_MEMBERS:
                return jsonify({'error': f'Groups are limited to {MAX_GROUP_MEMBERS} members'}), 400

            conn.execute(text("""
                INSERT INTO group_members (group_uuid, user_uuid, role)
                VALUES (:g, :u, 'member')
            """), {'g': group_uuid, 'u': user_uuid})

            updated_members = existing_members + [user_uuid]

        sync_group_membership(group_uuid, updated_members)

        # Existing members redistribute their sender key on GROUP_MEMBER_ADDED
        # (Phase 7); the joiner gets GROUP_JOINED, which falls under the generic
        # GROUP_ prefix refresh in AppDelegate.
        for existing_uuid in existing_members:
            notify_user(existing_uuid, 'GROUP_MEMBER_ADDED',
                        {'group_uuid': group_uuid, 'member_uuid': user_uuid})
        notify_user(user_uuid, 'GROUP_JOINED', {'group_uuid': group_uuid})

        logger.info(f"Group joined (self-service): {user_uuid} joined {group_uuid}")
        return jsonify({'message': 'Joined group', 'group_uuid': group_uuid}), 200

    except IntegrityError:
        return jsonify({'error': 'Already a member'}), 400
    except Exception as e:
        logger.error(f"Error joining group: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@groups_bp.route('/groups/<group_uuid>', methods=['DELETE'])
def delete_group(group_uuid):
    """
    Disbands a group. Owner-only. Soft-deletes the kybergroups row (mirrors
    the users.deleted / media_uploads.deleted pattern elsewhere) — group_members
    rows are left intact for audit but /get_groups filters on deleted=0.
    Removes the Firestore membership mirror so group_conversations access
    fails closed immediately.

    Headers: Authorization: Bearer <token>

    Returns:
      200 { "message": "Group deleted" }
      403 caller is not the owner
      404 group not found
    """
    try:
        caller_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.begin() as conn:
            group = conn.execute(
                text("SELECT owner_uuid FROM kybergroups WHERE group_uuid = :g AND deleted = 0"),
                {'g': group_uuid}
            ).fetchone()
            if not group:
                return jsonify({'error': 'Group not found'}), 404

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can delete the group'}), 403

            members = _fetch_member_uuids(conn, group_uuid)

            conn.execute(
                text("UPDATE kybergroups SET deleted = 1 WHERE group_uuid = :g"),
                {'g': group_uuid}
            )

        delete_group_membership_mirror(group_uuid)

        for member_uuid in members:
            if member_uuid != caller_uuid:
                notify_user(member_uuid, 'GROUP_DELETED', {'group_uuid': group_uuid})

        logger.info(f"Group deleted: {group_uuid} by {caller_uuid}")
        return jsonify({'message': 'Group deleted'}), 200

    except Exception as e:
        logger.error(f"Error deleting group: {e}")
        return jsonify({'error': 'Internal server error'}), 500
