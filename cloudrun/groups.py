import logging
import uuid as uuidlib
from flask import Blueprint, request, jsonify
from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError

from db import engine
from auth import verify_token
from cache import check_rate_limit_for
from notifications import notify_user
from firebase import sync_group_membership, delete_group_membership_mirror

groups_bp = Blueprint('groups', __name__)
logger = logging.getLogger(__name__)

# Sender-key fanout cost is O(members) per key distribution, so we cap group
# size well below Signal's ~1000-member limit. Revisit if usage demands more.
MAX_GROUP_MEMBERS = 50

_CREATE_RATE_MAX, _CREATE_RATE_WINDOW = 10, 3600      # 10 groups/hour
_ADD_MEMBER_RATE_MAX, _ADD_MEMBER_RATE_WINDOW = 30, 3600  # 30 adds/hour


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


@groups_bp.route('/groups/create', methods=['POST'])
def create_group():
    """
    Creates a new group with the authenticated user as owner.

    Authentication: Bearer PASETO token.
    Rate limit: 10 groups per hour per user.

    Request body:
      { "group_name": "string", "member_uuids": ["uuid1", "uuid2", ...] }
      (member_uuids should NOT include the caller — they're added as owner
      automatically. Duplicates and the caller's own uuid, if present, are
      silently ignored.)

    Steps:
      1. Validate group_name and member count (<= MAX_GROUP_MEMBERS).
      2. Verify every member_uuid resolves to an active user.
      3. Insert kybergroups row + group_members rows (owner + members).
      4. Mirror the roster into Firestore (groups/{group_uuid}.members) so
         Firestore security rules can authorize group_conversations access.
      5. Notify each invited member (GROUP_INVITE) so their client can pull
         the new group and start distributing/receiving sender keys.

    Returns:
      201 { "group_uuid": "...", "group_name": "...", "member_uuids": [...] }
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
                INSERT INTO kybergroups (group_uuid, group_name, owner_uuid)
                VALUES (:g, :name, :owner)
            """), {'g': group_uuid, 'name': group_name, 'owner': owner_uuid})

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
    Removes a member from a group. Owner-only; cannot remove the owner
    (use DELETE /groups/<group_uuid> to disband the group instead).

    Request body: { "group_uuid": "...", "member_uuid": "..." }
    Headers:      Authorization: Bearer <token>

    Returns:
      200 { "message": "Member removed" }
      400 target is the owner
      403 caller is not the owner
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

            if group[0] != caller_uuid:
                return jsonify({'error': 'Only the group owner can remove members'}), 403

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
                SELECT g.group_uuid, g.group_name, g.owner_uuid, g.created_at
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
                    'members': [
                        {'user_uuid': m[0], 'username': m[1], 'role': m[2]}
                        for m in member_rows
                    ]
                })

        return jsonify({'groups': groups}), 200

    except Exception as e:
        logger.error(f"Error fetching groups: {e}")
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
