import base64
import logging
import uuid as uuid_module

from flask import Blueprint, request, jsonify
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
    Stores a 1024-byte E2EE ciphertext in MySQL and notifies the recipient
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

        with engine.begin() as conn:
            # Verify recipient exists and fetch their push token
            row = conn.execute(text("""
                SELECT u.user_uuid, d.push_token
                FROM users u
                LEFT JOIN user_devices d ON d.user_uuid = u.user_uuid
                WHERE u.user_uuid = :uuid AND u.deleted = 0
                ORDER BY d.updated_at DESC
                LIMIT 1
            """), {'uuid': recipient_uuid}).fetchone()

            if not row:
                return jsonify({'error': 'Recipient not found'}), 404

            push_token = row[1]

            message_id = str(uuid_module.uuid4())
            conn.execute(text("""
                INSERT INTO messages (message_id, sender_uuid, recipient_uuid, ciphertext)
                VALUES (:message_id, :sender, :recipient, :ciphertext)
            """), {
                'message_id': message_id,
                'sender': sender_uuid,
                'recipient': recipient_uuid,
                'ciphertext': data['ciphertext'],
            })

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

        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT message_id, sender_uuid, ciphertext, created_at
                FROM messages
                WHERE recipient_uuid = :uuid
                ORDER BY created_at ASC
            """), {'uuid': user_uuid}).fetchall()

        messages = [
            {
                'message_id': row[0],
                'sender_uuid': row[1],
                'ciphertext': row[2],
                'created_at': row[3].isoformat() if row[3] else None,
            }
            for row in rows
        ]

        logger.info(f"Returned {len(messages)} messages for user: {user_uuid}")
        return jsonify({'messages': messages}), 200

    except Exception as e:
        logger.error(f"Error fetching messages: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@messages_bp.route('/messages/<message_id>', methods=['DELETE'])
def delete_message(message_id: str):
    """
    Deletes a single message after the client has decrypted it.
    Only the intended recipient may delete a message.

    Authentication: Bearer PASETO token.

    Returns:
      200 { "message": "Message deleted" }
      403 { "error": "Forbidden" }
      404 { "error": "Message not found" }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.begin() as conn:
            row = conn.execute(text("""
                SELECT recipient_uuid FROM messages WHERE message_id = :id
            """), {'id': message_id}).fetchone()

            if not row:
                return jsonify({'error': 'Message not found'}), 404

            if row[0] != user_uuid:
                return jsonify({'error': 'Forbidden'}), 403

            conn.execute(text("DELETE FROM messages WHERE message_id = :id"), {'id': message_id})

        logger.info(f"Message deleted: {message_id} by recipient {user_uuid}")
        return jsonify({'message': 'Message deleted'}), 200

    except Exception as e:
        logger.error(f"Error deleting message {message_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@messages_bp.route('/messages/ack', methods=['POST'])
def ack_messages():
    """
    Batch-deletes messages after the client confirms decryption.

    Authentication: Bearer PASETO token.

    Request body:
      { "message_ids": ["<uuid>", "<uuid>", ...] }

    Returns:
      200 { "deleted": 3, "not_found": 0, "forbidden": 0 }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data or 'message_ids' not in data:
            return jsonify({'error': 'Missing message_ids'}), 400

        message_ids = data['message_ids']
        if not isinstance(message_ids, list) or not message_ids:
            return jsonify({'error': 'message_ids must be a non-empty list'}), 400

        if len(message_ids) > 500:
            return jsonify({'error': 'Maximum 500 message_ids per request'}), 400

        deleted = not_found = forbidden = 0

        with engine.begin() as conn:
            for mid in message_ids:
                row = conn.execute(text("""
                    SELECT recipient_uuid FROM messages WHERE message_id = :id
                """), {'id': str(mid)}).fetchone()

                if not row:
                    not_found += 1
                    continue

                if row[0] != user_uuid:
                    forbidden += 1
                    continue

                conn.execute(text("DELETE FROM messages WHERE message_id = :id"), {'id': str(mid)})
                deleted += 1

        logger.info(f"Batch ack for {user_uuid}: deleted={deleted}, not_found={not_found}, forbidden={forbidden}")
        return jsonify({'deleted': deleted, 'not_found': not_found, 'forbidden': forbidden}), 200

    except Exception as e:
        logger.error(f"Error in ack_messages: {e}")
        return jsonify({'error': 'Internal server error'}), 500
