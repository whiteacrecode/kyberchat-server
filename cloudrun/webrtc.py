# cloudrun/webrtc.py
#
# WebRTC Signaling, TURN REST API Credentials, and Apple PushKit/VoIP Push Gateway.
#
# This blueprint enables secure real-time call initialization:
#   1. POST /webrtc/register_voip_token   — Register a PushKit/VoIP token for the device
#   2. POST /webrtc/unregister_voip_token — Unregister a VoIP token on logout
#   3. GET  /webrtc/turn-credentials       — Generate ephemeral, time-limited TURN/STUN credentials
#   4. POST /webrtc/call                   — Initiate a high-priority VoIP push to the callee
#
# To keep the system zero-knowledge and secure:
#   • No SDP offers/answers are sent to the server; they are exchanged through Firestore.
#   • The TURN REST API credentials are generated on the fly using HMAC-SHA1.

import os
import time
import hmac
import hashlib
import base64
import logging
from flask import Blueprint, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from auth import verify_token
from db import engine
from firebase import _get_app

logger = logging.getLogger(__name__)
webrtc_bp = Blueprint('webrtc', __name__)

# Default bundle ID of the iOS application (used for Apple VoIP push apns-topic)
IOS_BUNDLE_ID = os.environ.get("IOS_BUNDLE_ID", "org.tomw.kyberchat")

# Shared secret key used for TURN REST API credential generation.
# Default is "the_gluten_of_evil" per the VIDEO_PLAN.md specification.
TURN_SHARED_SECRET = os.environ.get("TURN_SHARED_SECRET", "the_gluten_of_evil")

# Hostname of our deployed TURN server.
TURN_SERVER_HOST = os.environ.get("TURN_SERVER_HOST", "turn.kyberchat.com:3478")


# ---------------------------------------------------------------------------
# POST /webrtc/register_voip_token
# ---------------------------------------------------------------------------

@webrtc_bp.route('/webrtc/register_voip_token', methods=['POST'])
def register_voip_token():
    """
    Registers or updates the Apple PushKit/VoIP push token for the authenticated user's device.
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'voip_token' not in data:
            return jsonify({'error': 'Missing voip_token'}), 400

        voip_token = data['voip_token'].strip()
        if not voip_token:
            return jsonify({'error': 'voip_token must not be empty'}), 400

        platform = data.get('platform', 'ios').strip()

        with engine.begin() as conn:
            # Check if this exact token is already registered for this user
            existing = conn.execute(text("""
                SELECT id FROM user_voip_devices
                WHERE user_uuid = :u AND voip_token = :t
            """), {'u': user_uuid, 't': voip_token}).fetchone()

            if existing:
                conn.execute(text("""
                    UPDATE user_voip_devices
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id
                """), {'id': existing[0]})
                logger.info(f"VoIP device token refreshed for user: {user_uuid}")
                return jsonify({'message': 'VoIP device updated'}), 200

            # Insert the new VoIP token
            conn.execute(text("""
                INSERT INTO user_voip_devices (user_uuid, voip_token, platform)
                VALUES (:u, :t, :p)
            """), {'u': user_uuid, 't': voip_token, 'p': platform})

        logger.info(f"VoIP device registered for user: {user_uuid}")
        return jsonify({'message': 'VoIP device registered'}), 201

    except Exception as e:
        logger.error(f"Error registering VoIP device: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------------------------------------------------------------
# POST /webrtc/unregister_voip_token
# ---------------------------------------------------------------------------

@webrtc_bp.route('/webrtc/unregister_voip_token', methods=['POST'])
def unregister_voip_token():
    """
    Removes the given VoIP token from the authenticated user's registered devices.
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'voip_token' not in data:
            return jsonify({'error': 'Missing voip_token'}), 400

        voip_token = data['voip_token'].strip()

        with engine.begin() as conn:
            result = conn.execute(text("""
                DELETE FROM user_voip_devices
                WHERE user_uuid = :u AND voip_token = :t
            """), {'u': user_uuid, 't': voip_token})

        if result.rowcount == 0:
            return jsonify({'error': 'VoIP token not found'}), 404

        logger.info(f"VoIP device unregistered for user: {user_uuid}")
        return jsonify({'message': 'VoIP device unregistered'}), 200

    except Exception as e:
        logger.error(f"Error unregistering VoIP device: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------------------------------------------------------------
# GET /webrtc/turn-credentials
# ---------------------------------------------------------------------------

@webrtc_bp.route('/webrtc/turn-credentials', methods=['GET'])
def get_turn_credentials():
    """
    Generates time-limited, standard TURN REST API authentication credentials.
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        # Credentials valid for 24 hours (86400 seconds)
        ttl = 86400
        expiry = int(time.time()) + ttl
        username = f"{expiry}:{user_uuid}"
        
        # Calculate HMAC-SHA1 signature using the shared secret
        key = TURN_SHARED_SECRET.encode('utf-8')
        message = username.encode('utf-8')
        signature = hmac.new(key, message, hashlib.sha1).digest()
        credential = base64.b64encode(signature).decode('utf-8')

        # Build list of ICE servers
        ice_servers = [
            {
                "urls": "stun:stun.l.google.com:19302"
            },
            {
                "urls": f"turn:{TURN_SERVER_HOST}?transport=udp",
                "username": username,
                "credential": credential
            },
            {
                "urls": f"turn:{TURN_SERVER_HOST}?transport=tcp",
                "username": username,
                "credential": credential
            }
        ]

        return jsonify({"ice_servers": ice_servers}), 200

    except Exception as e:
        logger.error(f"Error generating TURN credentials: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------------------------------------------------------------
# POST /webrtc/call
# ---------------------------------------------------------------------------

@webrtc_bp.route('/webrtc/call', methods=['POST'])
def initiate_call():
    """
    Initiates a high-priority APNs VoIP push to the callee's devices to trigger CallKit.
    """
    try:
        sender_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'recipient_uuid' not in data or 'call_uuid' not in data:
            return jsonify({'error': 'Missing recipient_uuid or call_uuid'}), 400

        recipient_uuid = data['recipient_uuid'].strip()
        call_uuid = data['call_uuid'].strip()

        # Query database for sender username and recipient's active VoIP tokens
        with engine.connect() as conn:
            sender_username = conn.execute(text("""
                SELECT username FROM users WHERE user_uuid = :u
            """), {'u': sender_uuid}).scalar()

            if not sender_username:
                return jsonify({'error': 'Sender user not found'}), 404

            rows = conn.execute(text("""
                SELECT voip_token, platform FROM user_voip_devices
                WHERE user_uuid = :u
            """), {'u': recipient_uuid}).fetchall()

        if not rows:
            logger.info(f"No VoIP tokens registered for recipient {recipient_uuid}")
            return jsonify({'message': 'No registered VoIP devices found'}), 200

        # Lazy init firebase app so we have the messaging module
        _get_app()
        from firebase_admin import messaging

        success_count = 0
        failure_count = 0

        # Custom calling payload
        payload_data = {
            'type': 'incoming_call',
            'call_uuid': call_uuid,
            'sender_uuid': sender_uuid,
            'sender_username': sender_username
        }

        for row in rows:
            voip_token, platform = row[0], row[1]
            
            # Formulate the high-priority APNs VoIP message configuration
            message = messaging.Message(
                token=voip_token,
                apns=messaging.APNSConfig(
                    headers={
                        'apns-topic': f'{IOS_BUNDLE_ID}.voip',
                        'apns-push-type': 'voip',
                        'apns-priority': '10',  # Immediate high-priority delivery
                    },
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(content_available=True),
                        custom_data=payload_data
                    ),
                ),
                android=messaging.AndroidConfig(
                    priority="high"
                )
            )

            try:
                messaging.send(message)
                success_count += 1
            except messaging.UnregisteredError:
                # Token has expired; remove it silently from DB
                with engine.begin() as conn:
                    conn.execute(text("""
                        DELETE FROM user_voip_devices WHERE voip_token = :t
                    """), {'t': voip_token})
                logger.warning(f"Pruned unregistered VoIP token: {voip_token[-8:]}")
            except Exception as e:
                logger.error(f"Failed to dispatch APNs VoIP push to {voip_token[-8:]}: {e}")
                failure_count += 1

        logger.info(f"VoIP calling notifications for call {call_uuid}: {success_count} success, {failure_count} failed.")
        return jsonify({
            'message': 'VoIP call notifications processed',
            'sent_count': success_count,
            'failed_count': failure_count
        }), 200

    except Exception as e:
        logger.error(f"Error initiating VoIP call: {e}")
        return jsonify({'error': 'Internal server error'}), 500
