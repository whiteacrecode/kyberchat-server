#!/usr/bin/env python3
"""
Send a test message via POST /messages/send.

NOTE: This script sends unencrypted plaintext padded to 1024 bytes.
      It is for development/testing only — production clients use
      Signal Protocol (X3DH + Double Ratchet) before sending.
"""

import argparse
import base64
import json
import sys
import urllib.request
import urllib.error

BASE_URL = "https://quantchat-server-1078066473760.us-central1.run.app"
PAYLOAD_SIZE = 1024  # bytes — server enforces this exactly


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


def pad_message(message, size):
    """UTF-8 encode and pad with null bytes to exactly `size` bytes."""
    encoded = message.encode("utf-8")
    if len(encoded) > size:
        raise ValueError(f"Message too long: {len(encoded)} bytes (max {size})")
    return encoded + b"\x00" * (size - len(encoded))


def main():
    parser = argparse.ArgumentParser(description="Send a test message to a user")
    parser.add_argument("--user", required=True, help="Your username")
    parser.add_argument("--pass", dest="password", required=True, help="Your password")
    parser.add_argument("--uuid", required=True, help="Recipient user UUID")
    parser.add_argument("--message", required=True, help="Message text to send")
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
    print(f"Logged in. Sending to recipient: {args.uuid}")

    try:
        padded = pad_message(args.message, PAYLOAD_SIZE)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    ciphertext_b64 = base64.b64encode(padded).decode("utf-8")

    print(f"\nSending message ({len(args.message.encode())} bytes, padded to {PAYLOAD_SIZE})...")
    payload = json.dumps({
        "recipient_uuid": args.uuid,
        "ciphertext": ciphertext_b64,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/messages/send",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            print(f"Status: {response.status}")
            try:
                print(json.dumps(json.loads(body), indent=2))
            except json.JSONDecodeError:
                print(body)
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
