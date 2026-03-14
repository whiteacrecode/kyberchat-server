import base64
import logging
import uuid as uuid_module
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify
from firebase_admin import firestore
from sqlalchemy import text

from auth import verify_token
from db import engine
from notifications import notify_new_message

messages_bp = Blueprint('messages', __name__)
logger = logging.getLogger(__name__)

CIPHERTEXT_SIZE = 1024  # bytes — fixed-size E2EE payload


@messages_bp.route('/messages/send', methods=['POST'])
def send_message():
    """
    Stores a 1024-byte E2EE ciphertext in Firestore and notifies the recipient
    via FCM.

    The server never sees plaintext — it relays opaque encrypted blobs only.
    Fixed-size payloads prevent traffic-analysis leaks about message length.

    Authentication: Bearer JWT.

    Request body:
      {
        "recipient_uuid": "<uuid>",
        "ciphertext": "<base64-encoded 1024-byte blob>"
      }

    Returns:
      201 { "message_id": "<uuid>" }
    """
    try:
        sender_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        for field in ('recipient_uuid', 'ciphertext'):
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        recipient_uuid = data['recipient_uuid']

        if recipient_uuid == sender_uuid:
            return jsonify({'error': 'Cannot send a message to yourself'}), 400

        try:
            raw = base64.b64decode(data['ciphertext'])
        except Exception:
            return jsonify({'error': 'ciphertext must be valid base64'}), 400

        if len(raw) != CIPHERTEXT_SIZE:
            return jsonify({
                'error': f'ciphertext must be exactly {CIPHERTEXT_SIZE} bytes, got {len(raw)}'
            }), 400

        # Verify recipient exists and fetch their push token in one query
        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT u.user_uuid, d.push_token
                FROM users u
                LEFT JOIN user_devices d ON d.user_uuid = u.user_uuid
                WHERE u.user_uuid = :uuid AND u.deleted = 0
                ORDER BY d.created_at DESC
                LIMIT 1
            """), {'uuid': recipient_uuid}).fetchone()

        if not row:
            return jsonify({'error': 'Recipient not found'}), 404

        push_token = row[1]

        # Persist the encrypted blob in Firestore
        message_id = str(uuid_module.uuid4())
        db = firestore.client()
        db.collection('messages').document(message_id).set({
            'message_id': message_id,
            'sender_uuid': sender_uuid,
            'recipient_uuid': recipient_uuid,
            'ciphertext': data['ciphertext'],  # store as base64 string
            'created_at': datetime.now(timezone.utc),
            'delivered': False,
        })

        # Notify the recipient — silent data message to avoid metadata leaks
        notify_new_message(push_token)

        logger.info(f"Message stored: {sender_uuid} → {recipient_uuid} ({message_id})")
        return jsonify({'message_id': message_id}), 201

    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@messages_bp.route('/messages', methods=['GET'])
def get_messages():
    """
    Returns all messages addressed to the authenticated user, ordered by
    creation time (oldest first).

    Clients should delete messages locally after decryption; this endpoint
    returns everything still on the server.

    Authentication: Bearer JWT.

    Returns:
      200 {
        "messages": [
          {
            "message_id": "<uuid>",
            "sender_uuid": "<uuid>",
            "ciphertext": "<base64>",
            "created_at": "<ISO-8601>"
          },
          ...
        ]
      }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        db = firestore.client()
        docs = (
            db.collection('messages')
            .where('recipient_uuid', '==', user_uuid)
            .order_by('created_at')
            .stream()
        )

        messages = []
        for doc in docs:
            d = doc.to_dict()
            created_at = d.get('created_at')
            messages.append({
                'message_id': d.get('message_id'),
                'sender_uuid': d.get('sender_uuid'),
                'ciphertext': d.get('ciphertext'),
                'created_at': created_at.isoformat() if created_at else None,
            })

        logger.info(f"Returned {len(messages)} messages for user: {user_uuid}")
        return jsonify({'messages': messages}), 200

    except Exception as e:
        logger.error(f"Error fetching messages: {e}")
        return jsonify({'error': 'Internal server error'}), 500
