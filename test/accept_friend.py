#!/usr/bin/env python3
"""Accept a pending friend request via POST /friends/accept."""

import argparse
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


def lookup_user(token, username):
    payload = json.dumps({"username": username}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/user/lookup",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Accept a pending friend request")
    parser.add_argument("--user", required=True, help="Your username (the one accepting)")
    parser.add_argument("--pass", dest="password", required=True, help="Your password")
    parser.add_argument("--friend", required=True, help="Username of the user who sent the request")
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
    print(f"Logged in. user_uuid: {login_resp['user']['user_uuid']}")

    print(f"Looking up UUID for '{args.friend}'...")
    try:
        lookup_resp = lookup_user(token, args.friend)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"User lookup failed {e.code}: {e.reason}", file=sys.stderr)
        try:
            print(json.dumps(json.loads(body), indent=2), file=sys.stderr)
        except json.JSONDecodeError:
            print(body, file=sys.stderr)
        sys.exit(1)

    requester_uuid = lookup_resp.get("user_uuid")
    if not requester_uuid:
        print(f"Error: could not resolve UUID for '{args.friend}'", file=sys.stderr)
        sys.exit(1)

    print(f"Resolved UUID: {requester_uuid}")

    print(f"\nAccepting friend request from {args.friend} ({requester_uuid})...")
    payload = json.dumps({"requester_uuid": requester_uuid}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/friends/accept",
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
