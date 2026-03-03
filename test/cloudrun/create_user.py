#!/usr/bin/env python3
"""Test script for the /create_user endpoint."""

import argparse
import json
import sys
import urllib.request
import urllib.error
import os
import random
import uuid

BASE_URL = "https://quantchat-server-1078066473760.us-central1.run.app"


def main():
    parser = argparse.ArgumentParser(description="Test the /create_user endpoint")
    parser.add_argument("--user", required=True, help="Username to register")
    parser.add_argument("--pass", dest="password", required=True, help="Password for the account")
    args = parser.parse_args()

    url = f"{BASE_URL}/create_user"
    user_uuid = str(uuid.uuid4())
    identity_key_public = os.urandom(32).hex()   # 32-byte X25519 public key placeholder
    registration_id = random.randint(1, 16380)   # Signal Protocol valid range

    print(f"Generated UUID:            {user_uuid}")
    print(f"Generated registration_id: {registration_id}")
    print(f"Generated identity_key:    {identity_key_public}")

    payload = json.dumps({
        "user_uuid": user_uuid,
        "username": args.user,
        "password": args.password,
        "identity_key_public": identity_key_public,
        "registration_id": registration_id,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
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
