#!/usr/bin/env python3
"""
Fetch all pending messages for a user via GET /messages.

NOTE: This script attempts to decode ciphertext as plain UTF-8 (test mode).
      Production clients decrypt with Signal Protocol before displaying.
"""

import argparse
import base64
import json
import sys
import urllib.request
import urllib.error

BASE_URL = "https://quantchat-server-1078066473760.us-central1.run.app"


def login(username, password):
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/validate_login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))


def decode_payload(ciphertext_b64):
    """Base64-decode and strip null-byte padding. Returns readable text or raw hex."""
    try:
        raw = base64.b64decode(ciphertext_b64)
        text = raw.rstrip(b"\x00").decode("utf-8")
        return text
    except Exception:
        return f"<binary {len(base64.b64decode(ciphertext_b64))} bytes>"


def main():
    parser = argparse.ArgumentParser(description="Fetch all messages for a user")
    parser.add_argument("--user", required=True, help="Your username")
    parser.add_argument("--pass", dest="password", required=True, help="Your password")
    args = parser.parse_args()

    print(f"Logging in as {args.user}...")
    try:
        login_resp = login(args.user, args.password)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"Login failed {e.code}: {e.reason}", file=sys.stderr)
        try:
            print(json.dumps(json.loads(body), indent=2), file=sys.stderr)
        except json.JSONDecodeError:
            print(body, file=sys.stderr)
        sys.exit(1)

    token = login_resp["token"]
    print(f"Logged in. user_uuid: {login_resp['user']['user_uuid']}\n")

    req = urllib.request.Request(
        f"{BASE_URL}/messages",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req) as response:
            body = json.loads(response.read().decode("utf-8"))
            messages = body.get("messages", [])
            print(f"Status: {response.status} — {len(messages)} message(s)\n")

            if not messages:
                print("No pending messages.")
                return

            for i, msg in enumerate(messages, 1):
                print(f"--- Message {i} ---")
                print(f"  message_id:  {msg['message_id']}")
                print(f"  sender_uuid: {msg['sender_uuid']}")
                print(f"  created_at:  {msg['created_at']}")
                print(f"  content:     {decode_payload(msg['ciphertext'])}")
                print()

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"Error {e.code}: {e.reason}", file=sys.stderr)
        try:
            print(json.dumps(json.loads(body), indent=2), file=sys.stderr)
        except json.JSONDecodeError:
            print(body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
