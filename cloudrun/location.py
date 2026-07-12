# cloudrun/location.py
#
# Real-time E2EE location sharing authorization and session management.
#
# Routes (all require PASETO Bearer auth):
#   POST /location/share  — starts sharing location with a friend or a group
#   POST /location/stop   — stops sharing location (updates MySQL and Firestore)
#   GET  /location/active  — fetches active location shares for the user
#
# This blueprint maintains the zero-knowledge principle: coordinates are
# never sent to this server or stored in MySQL. It only controls permission
# metadata.

import logging
import uuid as uuid_module
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from sqlalchemy import text

from auth import verify_token, canonical_uuid
from db import engine
from firebase import sync_location_share, delete_location_share_mirror

location_bp = Blueprint('location', __name__)
logger = logging.getLogger(__name__)


def user_shares_location_with(conn, grantor_uuid: str, grantee_uuid: str) -> bool:
    """
    Returns True if `grantor_uuid` has an enabled per-friend location-sharing
    preference toward `grantee_uuid`.

    This is the single source of truth for "does user A share location with
    user B?" — a durable preference, independent of whether an ephemeral
    location_shares session is currently active. Callers pass an open
    SQLAlchemy connection so the check can compose inside a larger transaction.
    """
    row = conn.execute(text("""
        SELECT share_enabled FROM location_share_prefs
        WHERE grantor_uuid = :grantor AND friend_uuid = :grantee
    """), {'grantor': grantor_uuid, 'grantee': grantee_uuid}).fetchone()
    return bool(row and row[0])


@location_bp.route('/location/share', methods=['POST'])
def start_location_share():
    """
    Registers a new active location share in MySQL and mirrors it to Firestore
    so security rules can authenticate high-frequency streaming coordinate updates.

    Request:
      {
        "grantee_uuid": "<uuid>", -- optional
        "group_uuid": "<uuid>",   -- optional
        "duration_hours": 2       -- integer, optional (1-24, default 1)
      }
    Exactly one of grantee_uuid or group_uuid must be non-null.
    """
    try:
        grantor_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        grantee_uuid = canonical_uuid(data.get('grantee_uuid'))
        group_uuid = data.get('group_uuid')
        duration_hours = data.get('duration_hours', 1)

        # Validate exactly one target is provided
        if not grantee_uuid and not group_uuid:
            return jsonify({'error': 'Either grantee_uuid or group_uuid must be provided'}), 400
        if grantee_uuid and group_uuid:
            return jsonify({'error': 'Cannot provide both grantee_uuid and group_uuid'}), 400

        # Validate duration_hours
        try:
            duration_hours = int(duration_hours)
            if duration_hours < 1 or duration_hours > 24:
                raise ValueError()
        except ValueError:
            return jsonify({'error': 'duration_hours must be an integer between 1 and 24'}), 400

        share_uuid = str(uuid_module.uuid4())
        # Use offset-naive datetime.utcnow() which SQLAlchemy maps perfectly to TIMESTAMP
        expires_at = datetime.utcnow() + timedelta(hours=duration_hours)

        with engine.begin() as conn:
            if grantee_uuid:
                # 1. Validate grantee user exists and is active
                user_check = conn.execute(text("""
                    SELECT user_uuid FROM users WHERE user_uuid = :uuid AND deleted = 0
                """), {'uuid': grantee_uuid}).fetchone()
                if not user_check:
                    return jsonify({'error': 'Target user not found or deleted'}), 404

                if grantee_uuid == grantor_uuid:
                    return jsonify({'error': 'Cannot share location with yourself'}), 400

                # 2. Validate active, accepted friendship
                friend_check = conn.execute(text("""
                    SELECT 1 FROM friends
                    WHERE ((requester_uuid = :grantor AND addressee_uuid = :grantee)
                       OR (requester_uuid = :grantee AND addressee_uuid = :grantor))
                      AND status = 'accepted'
                """), {'grantor': grantor_uuid, 'grantee': grantee_uuid}).fetchone()
                if not friend_check:
                    return jsonify({'error': 'You must be accepted friends to share location'}), 403
            else:
                # 3. Validate group exists and is active
                group_check = conn.execute(text("""
                    SELECT group_uuid FROM kybergroups WHERE group_uuid = :group AND deleted = 0
                """), {'group': group_uuid}).fetchone()
                if not group_check:
                    return jsonify({'error': 'Group not found or deleted'}), 404

                # 4. Validate grantor is a member of the group
                member_check = conn.execute(text("""
                    SELECT 1 FROM group_members
                    WHERE group_uuid = :group AND user_uuid = :grantor
                """), {'group': group_uuid, 'grantor': grantor_uuid}).fetchone()
                if not member_check:
                    return jsonify({'error': 'You are not a member of this group'}), 403

            # 5. Insert active location share
            conn.execute(text("""
                INSERT INTO location_shares (share_uuid, grantor_uuid, grantee_uuid, group_uuid, is_active, expires_at)
                VALUES (:share_uuid, :grantor, :grantee, :group, 1, :expires)
            """), {
                'share_uuid': share_uuid,
                'grantor': grantor_uuid,
                'grantee': grantee_uuid,
                'group': group_uuid,
                'expires': expires_at
            })

        # Synchronize metadata to Firestore so security rules can check in real-time
        sync_location_share(share_uuid, grantor_uuid, grantee_uuid, group_uuid, expires_at)

        logger.info(f"Location share started: {share_uuid} by {grantor_uuid}")
        return jsonify({
            'share_uuid': share_uuid,
            'expires_at': expires_at.isoformat() + 'Z'
        }), 201

    except Exception as e:
        logger.error(f"Error starting location share: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@location_bp.route('/location/stop', methods=['POST'])
def stop_location_share():
    """
    Stops an active location share, marking it inactive in MySQL and deleting
    its mirror document in Firestore, instantly revoking read/write access.

    Request:
      {
        "share_uuid": "<uuid>"
      }
    """
    try:
        grantor_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'share_uuid' not in data:
            return jsonify({'error': 'Missing share_uuid'}), 400

        share_uuid = data['share_uuid']

        with engine.begin() as conn:
            # Look up active share
            share = conn.execute(text("""
                SELECT grantor_uuid, is_active FROM location_shares WHERE share_uuid = :share_uuid
            """), {'share_uuid': share_uuid}).fetchone()

            if not share:
                return jsonify({'error': 'Location share not found'}), 404

            # Verify that this row contains grantor_uuid
            if share[0] != grantor_uuid:
                return jsonify({'error': 'You are not authorized to stop this location share'}), 403

            if share[1] == 0:
                # Already stopped locally, but ensure Firestore mirror is cleaned up anyway
                delete_location_share_mirror(share_uuid)
                return jsonify({'message': 'Location share is already stopped'}), 200

            # Deactivate in MySQL
            conn.execute(text("""
                UPDATE location_shares
                SET is_active = 0
                WHERE share_uuid = :share_uuid
            """), {'share_uuid': share_uuid})

        # Remove Firestore mirror document to block listener rules
        delete_location_share_mirror(share_uuid)

        logger.info(f"Location share stopped: {share_uuid} by {grantor_uuid}")
        return jsonify({'message': 'Location sharing stopped successfully'}), 200

    except Exception as e:
        logger.error(f"Error stopping location share: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@location_bp.route('/location/active', methods=['GET'])
def get_active_location_shares():
    """
    Retrieves all active, unexpired location shares where the user is either:
      1. The grantor (Alice sharing with Bob)
      2. The grantee (Bob receiving Alice's share)
      3. A member of a group that Alice is sharing with
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT s.share_uuid, s.grantor_uuid, u_grantor.username AS grantor_username,
                       s.grantee_uuid, u_grantee.username AS grantee_username,
                       s.group_uuid, g.group_name, s.expires_at, s.created_at
                FROM location_shares s
                JOIN users u_grantor ON s.grantor_uuid = u_grantor.user_uuid
                LEFT JOIN users u_grantee ON s.grantee_uuid = u_grantee.user_uuid
                LEFT JOIN kybergroups g ON s.group_uuid = g.group_uuid
                WHERE s.is_active = 1
                  AND s.expires_at > NOW()
                  AND (
                      s.grantor_uuid = :user_uuid
                      OR s.grantee_uuid = :user_uuid
                      OR s.group_uuid IN (
                          SELECT group_uuid FROM group_members WHERE user_uuid = :user_uuid
                      )
                  )
                ORDER BY s.created_at DESC
            """), {'user_uuid': user_uuid}).fetchall()

        shares = []
        for row in rows:
            shares.append({
                'share_uuid': row[0],
                'grantor_uuid': row[1],
                'grantor_username': row[2],
                'grantee_uuid': row[3],
                'grantee_username': row[4],
                'group_uuid': row[5],
                'group_name': row[6],
                'expires_at': row[7].isoformat() + 'Z' if row[7] else None,
                'created_at': row[8].isoformat() + 'Z' if row[8] else None
            })

        return jsonify({'shares': shares}), 200

    except Exception as e:
        logger.error(f"Error fetching active location shares: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@location_bp.route('/location/preference', methods=['POST'])
def set_location_share_preference():
    """
    Sets (or clears) the authenticated user's durable preference to share their
    live location with a specific friend. This is a persistent per-friend toggle,
    distinct from the ephemeral, time-boxed sessions in POST /location/share.

    The friend must be an accepted friend of the caller.

    Request:
      {
        "friend_uuid": "<uuid>",
        "share_enabled": true | false
      }

    Returns:
      200 { "friend_uuid": "<uuid>", "share_enabled": true|false }
      400 missing/invalid field · 403 not accepted friends · 404 friend not found
    """
    try:
        grantor_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'friend_uuid' not in data:
            return jsonify({'error': 'Missing friend_uuid'}), 400
        if 'share_enabled' not in data:
            return jsonify({'error': 'Missing share_enabled'}), 400

        friend_uuid = data['friend_uuid']
        share_enabled = data['share_enabled']

        if not isinstance(share_enabled, bool):
            return jsonify({'error': 'share_enabled must be a boolean'}), 400

        if friend_uuid == grantor_uuid:
            return jsonify({'error': 'Cannot set a location preference for yourself'}), 400

        with engine.begin() as conn:
            # 1. Validate the friend exists and is active
            user_check = conn.execute(text("""
                SELECT user_uuid FROM users WHERE user_uuid = :uuid AND deleted = 0
            """), {'uuid': friend_uuid}).fetchone()
            if not user_check:
                return jsonify({'error': 'Friend not found or deleted'}), 404

            # 2. Validate an accepted friendship exists (either direction)
            friend_check = conn.execute(text("""
                SELECT 1 FROM friends
                WHERE ((requester_uuid = :grantor AND addressee_uuid = :friend)
                   OR (requester_uuid = :friend AND addressee_uuid = :grantor))
                  AND status = 'accepted'
            """), {'grantor': grantor_uuid, 'friend': friend_uuid}).fetchone()
            if not friend_check:
                return jsonify({'error': 'You must be accepted friends to share location'}), 403

            # 3. Upsert the preference
            conn.execute(text("""
                INSERT INTO location_share_prefs (grantor_uuid, friend_uuid, share_enabled)
                VALUES (:grantor, :friend, :enabled)
                ON DUPLICATE KEY UPDATE share_enabled = :enabled
            """), {'grantor': grantor_uuid, 'friend': friend_uuid, 'enabled': 1 if share_enabled else 0})

        logger.info(f"Location share preference set: {grantor_uuid} -> {friend_uuid} = {share_enabled}")
        return jsonify({'friend_uuid': friend_uuid, 'share_enabled': share_enabled}), 200

    except Exception as e:
        logger.error(f"Error setting location share preference: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@location_bp.route('/location/preference/status', methods=['POST'])
def get_location_share_preference():
    """
    Reports whether the authenticated user shares their location with a friend,
    and whether that friend shares theirs back — the two independent per-friend
    preferences that back the conversation-menu toggle.

    Request:
      { "friend_uuid": "<uuid>" }

    Returns:
      200 {
            "friend_uuid": "<uuid>",
            "i_share_with_them": true|false,   -- caller's own toggle
            "they_share_with_me": true|false   -- friend's toggle toward caller
          }
      400 missing friend_uuid
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'friend_uuid' not in data:
            return jsonify({'error': 'Missing friend_uuid'}), 400

        friend_uuid = data['friend_uuid']

        with engine.connect() as conn:
            i_share = user_shares_location_with(conn, user_uuid, friend_uuid)
            they_share = user_shares_location_with(conn, friend_uuid, user_uuid)

        return jsonify({
            'friend_uuid': friend_uuid,
            'i_share_with_them': i_share,
            'they_share_with_me': they_share
        }), 200

    except Exception as e:
        logger.error(f"Error fetching location share preference: {e}")
        return jsonify({'error': 'Internal server error'}), 500
