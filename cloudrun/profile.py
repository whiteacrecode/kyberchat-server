# cloudrun/profile.py
#
# User profile management endpoints.
#
# Routes (all require PASETO Bearer auth):
#   GET  /profile           — fetch the authenticated user's own profile
#   POST /profile/update    — update firstname, lastname, email, phone, private
#
# Profile text fields are stored in the `user_profiles` table (see
# schema/migrations/005_user_profiles.sql).  The avatar image is stored
# client-side in Firestore (profiles/{userUUID}) — this module only handles
# the text fields plus the `private` discoverability flag, which lives on
# `users.private` (a different table) rather than `user_profiles`.
#
# All fields are optional on update; only supplied fields are modified.
# Validation:
#   first_name / last_name : max 64 chars, stripped
#   email                  : max 254 chars, stripped, basic @ check
#   phone                  : max 30 chars, digits / spaces / +()-. only
#   private                : truthy/falsy (bool, "0"/"1", "true"/"false")

import logging
import re

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from auth import verify_token
from db import engine

logger = logging.getLogger(__name__)

profile_bp = Blueprint("profile", __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EMAIL_RE   = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_PHONE_RE   = re.compile(r'^[\d\s\+\(\)\-\.]{0,30}$')
_NAME_MAX   = 64
_EMAIL_MAX  = 254
_PHONE_MAX  = 30


def normalize_email(email: str) -> str:
    """Canonical form for email comparisons: trimmed, lowercased."""
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    """
    Canonical form for phone comparisons: digits only, plus a leading '+'
    if the original number had one (distinguishes +1... from a bare
    national number that happens to share the same digits).
    """
    stripped = phone.strip()
    plus = '+' if stripped.startswith('+') else ''
    digits = re.sub(r'\D', '', stripped)
    return plus + digits


def _validate_profile_fields(data: dict) -> tuple[dict, str | None]:
    """
    Validate and sanitise whitelisted profile fields from *data*.

    Returns (cleaned_dict, error_message_or_None).
    Only keys present in *data* are included in the returned dict.
    """
    cleaned: dict = {}

    for field in ('first_name', 'last_name'):
        if field in data:
            val = str(data[field]).strip()
            if len(val) > _NAME_MAX:
                return {}, f"{field} must be at most {_NAME_MAX} characters"
            cleaned[field] = val

    if 'email' in data:
        val = str(data['email']).strip()
        if val and not _EMAIL_RE.match(val):
            return {}, "email must be a valid email address"
        if len(val) > _EMAIL_MAX:
            return {}, f"email must be at most {_EMAIL_MAX} characters"
        cleaned['email'] = normalize_email(val) if val else val

    if 'phone' in data:
        val = str(data['phone']).strip()
        if val and not _PHONE_RE.match(val):
            return {}, "phone contains invalid characters"
        if len(val) > _PHONE_MAX:
            return {}, f"phone must be at most {_PHONE_MAX} characters"
        cleaned['phone'] = normalize_phone(val) if val else val

    return cleaned, None


def _parse_private(value) -> int:
    """Coerce a bool/int/str truthy representation of `private` to 0 or 1."""
    if isinstance(value, bool):
        return 1 if value else 0
    return 1 if str(value).strip().lower() in ('1', 'true', 'yes') else 0


# ---------------------------------------------------------------------------
# GET /profile
# ---------------------------------------------------------------------------

@profile_bp.route("/profile", methods=["GET"])
def get_profile():
    """
    Fetch the authenticated user's profile.

    Returns the profile row if it exists; otherwise returns all-empty strings
    so the client always gets a consistent shape.

    Response 200:
        {
            "user_uuid":   "<uuid>",
            "username":    "<username>",
            "private":     0 | 1,
            "first_name":  "...",
            "last_name":   "...",
            "email":       "...",
            "phone":       "..."
        }
    """
    user_uuid, err = verify_token(request)
    if err:
        return jsonify(err[0]), err[1]

    try:
        with engine.connect() as conn:
            # Fetch username + privacy flag from users table
            user_row = conn.execute(
                text("SELECT username, private FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': user_uuid}
            ).fetchone()

            if not user_row:
                return jsonify({'error': 'User not found'}), 404

            # Fetch profile (may not exist yet — LEFT JOIN style)
            profile_row = conn.execute(
                text("""
                    SELECT first_name, last_name, email, phone
                    FROM user_profiles
                    WHERE user_uuid = :u
                """),
                {'u': user_uuid}
            ).fetchone()

        if profile_row:
            first_name, last_name, email, phone = profile_row
        else:
            first_name = last_name = email = phone = ''

        return jsonify({
            'user_uuid':  user_uuid,
            'username':   user_row[0],
            'private':    int(user_row[1]),
            'first_name': first_name or '',
            'last_name':  last_name  or '',
            'email':      email      or '',
            'phone':      phone      or '',
        }), 200

    except Exception as exc:
        logger.error("get_profile error for %s: %s", user_uuid, exc)
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------------------------------------------------------------
# POST /profile/update
# ---------------------------------------------------------------------------

@profile_bp.route("/profile/update", methods=["POST"])
def update_profile():
    """
    Update the authenticated user's profile.

    All body fields are optional; omitted fields are left unchanged.

    Request body (JSON):
        {
            "first_name": "...",   // optional, max 64 chars
            "last_name":  "...",   // optional, max 64 chars
            "email":      "...",   // optional, max 254 chars, must be valid email or empty
            "phone":      "...",   // optional, max 30 chars, digits/spaces/+()-. only
            "private":    0|1|true|false|"0"|"1"   // optional — updates users.private
        }

    Response 200:
        { "message": "Profile updated" }
    Response 400:
        { "error": "<validation message>" }
    """
    user_uuid, err = verify_token(request)
    if err:
        return jsonify(err[0]), err[1]

    try:
        data = request.get_json() or {}

        cleaned, validation_err = _validate_profile_fields(data)
        if validation_err:
            return jsonify({'error': validation_err}), 400

        update_private = 'private' in data
        private_value  = _parse_private(data['private']) if update_private else None

        if not cleaned and not update_private:
            # Nothing to update — treat as a no-op success
            return jsonify({'message': 'Profile updated'}), 200

        # Upsert: create a row if none exists, otherwise update only the
        # supplied columns.  MySQL's INSERT ... ON DUPLICATE KEY UPDATE is
        # idiomatic here. Only built when there are user_profiles columns to
        # write — `private` lives on `users`, not `user_profiles`.
        if cleaned:
            update_clause = ', '.join(f"{col} = VALUES({col})" for col in cleaned)
            sql = text(f"""
                INSERT INTO user_profiles (user_uuid, {', '.join(cleaned)})
                VALUES (:u, {', '.join(':' + c for c in cleaned)})
                ON DUPLICATE KEY UPDATE {update_clause}
            """)
            params = {**cleaned, 'u': user_uuid}

        with engine.begin() as conn:
            # Verify user exists
            row = conn.execute(
                text("SELECT user_uuid FROM users WHERE user_uuid = :u AND deleted = 0"),
                {'u': user_uuid}
            ).fetchone()
            if not row:
                return jsonify({'error': 'User not found'}), 404

            if cleaned:
                conn.execute(sql, params)

            if update_private:
                conn.execute(
                    text("UPDATE users SET private = :p WHERE user_uuid = :u"),
                    {'p': private_value, 'u': user_uuid}
                )

        logger.info(
            "update_profile: updated %s fields (private=%s) for %s",
            list(cleaned), private_value if update_private else 'unchanged', user_uuid
        )
        return jsonify({'message': 'Profile updated'}), 200

    except Exception as exc:
        logger.error("update_profile error for %s: %s", user_uuid, exc)
        return jsonify({'error': 'Internal server error'}), 500
