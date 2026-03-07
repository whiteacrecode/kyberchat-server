"""
user_utils.py — KyberChat server utility helpers
=================================================
Covers:
  - create_user()      POST /create_user
  - add_friend()       POST /friends/request  (requires a valid JWT)
  - login()            POST /validate_login   (helper; returns JWT for auth'd calls)

All crypto material (identity key, registration ID) is generated locally so the
caller doesn't need to care about Signal protocol internals.

Usage (CLI quick-start):
  # create two users and wire up a friend request + acceptance
  python user_utils.py

Usage (library):
  from user_utils import create_user, login, add_friend, accept_friend

Environment:
  BASE_URL — defaults to the Cloud Run service URL below.
"""

import os
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Optional

import requests

BASE_URL: str = os.environ.get(
    "BASE_URL",
    "https://quantchat-server-1078066473760.us-central1.run.app",
).rstrip("/")


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class UserCredentials:
    """Everything the server returned (or we generated) for a freshly created user."""
    user_uuid: str
    username: str
    password: str
    identity_key_public_hex: str
    registration_id: int
    token: Optional[str] = field(default=None)   # populated after login()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _post(path: str, payload: dict, token: Optional[str] = None) -> requests.Response:
    """Thin wrapper around requests.post with optional Bearer auth."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{BASE_URL}{path}"
    resp = requests.post(url, json=payload, headers=headers, timeout=15)
    return resp


def _raise_for_status(resp: requests.Response, context: str) -> None:
    if not resp.ok:
        raise RuntimeError(
            f"[{context}] HTTP {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_user(
    username: str,
    password: str,
    *,
    user_uuid: Optional[str] = None,
    identity_key_public_hex: Optional[str] = None,
    registration_id: Optional[int] = None,
) -> UserCredentials:
    """
    Creates a new KyberChat user.

    The Signal-protocol fields (identity_key_public, registration_id) are
    generated randomly when not supplied — fine for testing / scripting.

    Parameters
    ----------
    username             : Unique display name.
    password             : Plain-text password (hashed server-side with Argon2).
    user_uuid            : RFC-4122 UUID string; auto-generated when omitted.
    identity_key_public_hex : 32-byte Curve25519 public key as hex; random when omitted.
    registration_id      : 1–16 383 Signal registration ID; random when omitted.

    Returns
    -------
    UserCredentials (token is None until login() is called).
    """
    user_uuid = user_uuid or str(uuid.uuid4())
    identity_key_public_hex = identity_key_public_hex or secrets.token_hex(32)
    registration_id = registration_id or (secrets.randbits(14) or 1)  # 1–16383

    payload = {
        "user_uuid": user_uuid,
        "username": username,
        "password": password,
        "identity_key_public": identity_key_public_hex,
        "registration_id": registration_id,
    }

    resp = _post("/create_user", payload)
    _raise_for_status(resp, "create_user")

    return UserCredentials(
        user_uuid=user_uuid,
        username=username,
        password=password,
        identity_key_public_hex=identity_key_public_hex,
        registration_id=registration_id,
    )


def login(creds: UserCredentials) -> UserCredentials:
    """
    Authenticates with the server and stores the returned JWT in *creds*.

    Mutates the supplied UserCredentials in-place and also returns it so the
    call can be chained:  creds = login(create_user(...))
    """
    resp = _post("/validate_login", {"username": creds.username, "password": creds.password})
    _raise_for_status(resp, "login")

    body = resp.json()
    creds.token = body["token"]
    # Sync UUID back in case the caller passed a pre-existing username
    creds.user_uuid = body["user"]["user_uuid"]
    return creds


def add_friend(requester: UserCredentials, target_username: str) -> dict:
    """
    Sends a friend request from *requester* to *target_username*.

    Requires requester.token to be set (call login() first).

    Returns the raw JSON response body.
      {"status": "pending"}  → new request created (201)
      {"status": <existing>} → relationship already existed (200)
    """
    if not requester.token:
        raise ValueError("requester has no JWT — call login() first")

    resp = _post("/friends/request", {"username": target_username}, token=requester.token)
    _raise_for_status(resp, "add_friend")
    return resp.json()


def accept_friend(accepter: UserCredentials, requester_uuid: str) -> dict:
    """
    Accepts a pending friend request on behalf of *accepter*.

    Requires accepter.token to be set (call login() first).

    Parameters
    ----------
    accepter       : The user accepting the request.
    requester_uuid : UUID of the user who originally sent the request.

    Returns the raw JSON response body: {"status": "accepted"}
    """
    if not accepter.token:
        raise ValueError("accepter has no JWT — call login() first")

    resp = _post(
        "/friends/accept",
        {"requester_uuid": requester_uuid},
        token=accepter.token,
    )
    _raise_for_status(resp, "accept_friend")
    return resp.json()


def get_friends(user: UserCredentials) -> list[dict]:
    """
    Returns the accepted friends list for *user*.

    Requires user.token to be set (call login() first).
    """
    if not user.token:
        raise ValueError("user has no JWT — call login() first")

    resp = _post("/get_friends", {}, token=user.token)
    _raise_for_status(resp, "get_friends")
    return resp.json().get("friends", [])


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    suffix = secrets.token_hex(4)
    alice_username = f"alice_{suffix}"
    bob_username = f"bob_{suffix}"

    print(f"[+] Creating user: {alice_username}")
    alice = create_user(alice_username, "hunter2_alice")
    print(f"    uuid={alice.user_uuid}")

    print(f"[+] Creating user: {bob_username}")
    bob = create_user(bob_username, "hunter2_bob")
    print(f"    uuid={bob.user_uuid}")

    print("[+] Logging in as Alice …")
    login(alice)
    print(f"    token (truncated)={alice.token[:24]}…")

    print("[+] Logging in as Bob …")
    login(bob)

    print(f"[+] Alice sends friend request → {bob_username}")
    result = add_friend(alice, bob_username)
    print(f"    response={json.dumps(result)}")

    print(f"[+] Bob accepts Alice's friend request")
    result = accept_friend(bob, alice.user_uuid)
    print(f"    response={json.dumps(result)}")

    print("[+] Alice's friends list:")
    friends = get_friends(alice)
    for f in friends:
        print(f"    {f['username']} ({f['user_uuid']})  online={f['is_online']}")

    print("\nSPOON! Justice has been served!")
