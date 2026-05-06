#!/usr/bin/env python3
"""Test the validate_login endpoint at https://api.kyberchat.com"""

import argparse
import json
import sys
import urllib.request
import urllib.error

BASE_URL = "https://api.kyberchat.com"

def test_validate_login(username, password):
    print(f"Testing validate_login for user: {username} at {BASE_URL}")
    
    payload = json.dumps({
        "username": username,
        "password": password
    }).encode("utf-8")
    
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
            data = json.loads(body)
            print(json.dumps(data, indent=2))
            
            if "token" in data:
                print("\nLogin successful! Token received.")
            else:
                print("\nLogin might have failed or response format changed.")
                
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
    parser = argparse.ArgumentParser(description="Test validate_login at api.kyberchat.com")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--pass", dest="password", required=True, help="Password")
    args = parser.parse_args()

    test_validate_login(args.user, args.password)
