#!/usr/bin/env python3
"""Login and print user details including UUID via POST /validate_login."""

import argparse
import json
import sys
import urllib.request
import urllib.error

BASE_URL = "https://quantchat-server-1078066473760.us-central1.run.app"


def main():
    parser = argparse.ArgumentParser(description="Login and retrieve user UUID")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--pass", dest="password", required=True, help="Password")
    args = parser.parse_args()

    payload = json.dumps({"username": args.user, "password": args.password}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/validate_login",
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
