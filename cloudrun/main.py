import os
import logging
import urllib.parse
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration from environment variables
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME')
DB_HOST = os.environ.get('DB_HOST') # e.g., /cloudsql/project:region:instance for Unix socket or IP for TCP

# Construct the database URL
# Assuming Cloud SQL with PyMySQL
# For TCP: mysql+pymysql://user:pass@host/dbname
# For Unix Socket: mysql+pymysql://user:pass@/dbname?unix_socket=/cloudsql/INSTANCE_CONNECTION_NAME

if DB_USER:
    db_user_escaped = urllib.parse.quote_plus(DB_USER)
else:
    db_user_escaped = DB_USER

if DB_PASS:
    db_pass_escaped = urllib.parse.quote_plus(DB_PASS)
else:
    db_pass_escaped = DB_PASS

if DB_HOST and DB_HOST.startswith('/'):
    db_url = f"mysql+pymysql://{db_user_escaped}:{db_pass_escaped}@/{DB_NAME}?unix_socket={DB_HOST}"
else:
    db_url = f"mysql+pymysql://{db_user_escaped}:{db_pass_escaped}@{DB_HOST}/{DB_NAME}"

# Create SQLAlchemy engine
engine = create_engine(db_url, pool_size=5, max_overflow=2, pool_timeout=30, pool_recycle=1800)

@app.route('/create_user', methods=['POST'])
def create_user():
    """
    Creates a new user in the database.
    Expected JSON payload:
    {
        "user_uuid": "UUID string",
        "username": "string",
        "identity_key_public": "hex or base64 string (stored as BLOB)",
        "registration_id": 12345
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        required_fields = ['user_uuid', 'username', 'identity_key_public', 'registration_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        user_uuid = data['user_uuid']
        username = data['username']
        # Convert identity_key_public to bytes if it's sent as hex/base64, or store as is if client handles encoding
        # Assuming client sends hex string for simplicity in this example, or raw bytes if content-type is appropriate.
        # For this example, we'll assume the client sends a hex string and we convert to bytes for BLOB storage.
        # If the client sends base64, change accordingly.
        # Here we assume the input is a string representation that the DB can handle or we encode it.
        # Let's assume it's sent as a hex string.
        try:
             # Basic hex validation/conversion if needed. 
             # For now, we'll store it directly if the DB driver handles it, or encode to bytes.
             # SQLAlchemy/PyMySQL usually handles bytes for BLOBs.
             identity_key_public = bytes.fromhex(data['identity_key_public'])
        except ValueError:
             return jsonify({'error': 'identity_key_public must be a valid hex string'}), 400

        registration_id = data['registration_id']

        with engine.connect() as connection:
            query = text("""
                INSERT INTO users (user_uuid, username, identity_key_public, registration_id)
                VALUES (:user_uuid, :username, :identity_key_public, :registration_id)
            """)
            connection.execute(query, {
                'user_uuid': user_uuid,
                'username': username,
                'identity_key_public': identity_key_public,
                'registration_id': registration_id
            })
            connection.commit()

        logger.info(f"User created: {username} ({user_uuid})")
        return jsonify({'message': 'User created successfully', 'user_uuid': user_uuid}), 201

    except IntegrityError as e:
        logger.warning(f"IntegrityError: {e}")
        return jsonify({'error': 'Username or UUID already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/validate_login', methods=['POST'])
def validate_login():
    """
    Validates a user login by checking if the username exists.
    Expected JSON payload:
    {
        "username": "string"
    }
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({'error': 'Missing username'}), 400

        username = data['username']

        with engine.connect() as connection:
            query = text("""
                SELECT user_uuid, username, registration_id, created_at 
                FROM users 
                WHERE username = :username
            """)
            result = connection.execute(query, {'username': username}).fetchone()

        if result:
            # Found user
            user_data = {
                'user_uuid': result[0],
                'username': result[1],
                'registration_id': result[2],
                'created_at': result[3].isoformat() if result[3] else None
            }
            logger.info(f"Login validated for: {username}")
            return jsonify({'message': 'User found', 'user': user_data}), 200
        else:
            logger.warning(f"Login failed: User not found {username}")
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        logger.error(f"Error validating login: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/update_auth', methods=['POST'])
def update_auth():
    """
    Updates authentication details (e.g., last_seen) for a user.
    Expected JSON payload:
    {
        "user_uuid": "UUID string"
    }
    """
    try:
        data = request.get_json()
        if not data or 'user_uuid' not in data:
            return jsonify({'error': 'Missing user_uuid'}), 400

        user_uuid = data['user_uuid']

        with engine.connect() as connection:
            # Check if user exists first (optional, but good for explicit errors)
            # Or just update and check rowcount
            query = text("""
                UPDATE users 
                SET last_seen = CURRENT_TIMESTAMP 
                WHERE user_uuid = :user_uuid
            """)
            result = connection.execute(query, {'user_uuid': user_uuid})
            connection.commit()

            if result.rowcount == 0:
                return jsonify({'error': 'User not found'}), 404

        logger.info(f"Auth updated (last_seen) for: {user_uuid}")
        return jsonify({'message': 'Auth updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating auth: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == "__main__":
    # Local development server
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
