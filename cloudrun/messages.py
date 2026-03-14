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
                ORDER BY d.updated_at DESC
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


@messages_bp.route('/messages/<message_id>', methods=['DELETE'])
def delete_message(message_id: str):
    """
    Deletes a single message from Firestore after the client has decrypted it.

    Only the intended recipient may delete a message — the server verifies
    ownership before deletion. This enforces forward-privacy: once decrypted
    and acknowledged, the ciphertext is gone from the server.

    Authentication: Bearer PASETO token.

    URL parameter: message_id (UUID)

    Returns:
      200 { "message": "Message deleted" }
      403 { "error": "Forbidden" }         — message belongs to someone else
      404 { "error": "Message not found" } — already deleted or bad ID
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        db = firestore.client()
        doc_ref = db.collection('messages').document(message_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({'error': 'Message not found'}), 404

        data = doc.to_dict()

        # Only the recipient may delete — prevent senders from erasing evidence
        if data.get('recipient_uuid') != user_uuid:
            return jsonify({'error': 'Forbidden'}), 403

        doc_ref.delete()

        logger.info(f"Message deleted: {message_id} by recipient {user_uuid}")
        return jsonify({'message': 'Message deleted'}), 200

    except Exception as e:
        logger.error(f"Error deleting message {message_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@messages_bp.route('/messages/ack', methods=['POST'])
def ack_messages():
    """
    Batch-deletes multiple messages after the client confirms decryption.

    More efficient than calling DELETE /messages/<id> in a loop after
    receiving a batch from GET /messages.

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

        db = firestore.client()
        deleted = not_found = forbidden = 0

        # Firestore batch delete — max 500 ops per batch
        batch = db.batch()
        batch_count = 0

        for mid in message_ids:
            doc_ref = db.collection('messages').document(str(mid))
            doc = doc_ref.get()

            if not doc.exists:
                not_found += 1
                continue

            if doc.to_dict().get('recipient_uuid') != user_uuid:
                forbidden += 1
                continue

            batch.delete(doc_ref)
            deleted += 1
            batch_count += 1

            if batch_count == 500:
                batch.commit()
                batch = db.batch()
                batch_count = 0

        if batch_count > 0:
            batch.commit()

        logger.info(f"Batch ack for {user_uuid}: deleted={deleted}, not_found={not_found}, forbidden={forbidden}")
        return jsonify({'deleted': deleted, 'not_found': not_found, 'forbidden': forbidden}), 200

    except Exception as e:
        logger.error(f"Error in ack_messages: {e}")
        return jsonify({'error': 'Internal server error'}), 500
