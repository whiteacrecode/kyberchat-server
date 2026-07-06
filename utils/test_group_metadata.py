#!/usr/bin/env python3
"""
🥄 Group Metadata Integration Test Script: test_group_metadata.py

This script implements Step A.1 of our Battle Map:
1. Registers two unique temporary users (User A - Owner, User B - Member).
2. Creates a group with User A as the owner and User B as a member.
3. Asserts `/get_groups` initially returns correct default metadata.
4. Asserts `/groups/edit` under User A (owner) successfully edits group metadata.
5. Asserts `/groups/edit` rejects empty/blank group names (400 Bad Request).
6. Asserts `/groups/edit` rejects oversized descriptions > 500 characters (400 Bad Request).
7. Asserts `/groups/edit` under User B (non-owner/member) rejects changes (403 Forbidden).
8. Performs cleanup by deleting the created group.

Usage:
  python3 test_group_metadata.py [--url <server_base_url>]
"""

import argparse
import json
import os
import random
import sys
import urllib.request
import urllib.error
import uuid

DEFAULT_BASE_URL = "https://quantchat-server-1078066473760.us-central1.run.app"


def make_request(url, payload=None, token=None, method="POST"):
    """Helper to perform standard library HTTP requests."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data_bytes = None
    if payload is not None:
        data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
            body = response.read().decode("utf-8")
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                parsed_body = body
            return status, parsed_body
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8")
        try:
            parsed_body = json.loads(body)
        except json.JSONDecodeError:
            parsed_body = body
        return status, parsed_body
    except urllib.error.URLError as e:
        print(f"\n❌ Connection Error targeting: {url}", file=sys.stderr)
        print(f"Reason: {e.reason}", file=sys.stderr)
        sys.exit(1)


def register_user(base_url, username, password):
    """Registers a new user and returns their user_uuid and PASETO token."""
    user_uuid = str(uuid.uuid4())
    identity_key_public = os.urandom(32).hex()
    registration_id = random.randint(1, 16380)

    payload = {
        "user_uuid": user_uuid,
        "username": username,
        "password": password,
        "identity_key_public": identity_key_public,
        "registration_id": registration_id
    }

    status, response = make_request(f"{base_url}/create_user", payload=payload)
    if status != 201:
        print(f"❌ Failed to register user {username}: Status {status}, Response {response}", file=sys.stderr)
        sys.exit(1)

    token = response["token"]
    return user_uuid, token


def main():
    parser = argparse.ArgumentParser(description="Test E2EE Group Metadata and Edit Operations")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="Server base URL")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print("======================================================================")
    print("🥄 STARTING HEROIC GROUP METADATA AND EDIT INTEGRATION TEST!")
    print(f"🎯 Target URL: {base_url}")
    print("======================================================================")

    # 1. Register Temporary Users
    suffix = random.randint(100000, 999999)
    owner_username = f"meta_owner_{suffix}"
    member_username = f"meta_member_{suffix}"
    password = "SuperStrongPassword123!"

    print(f"\n👥 Registering temporary test users...")
    print(f"👉 Owner:  {owner_username}")
    owner_uuid, owner_token = register_user(base_url, owner_username, password)
    print(f"   Success! UUID: {owner_uuid}")

    print(f"👉 Member: {member_username}")
    member_uuid, member_token = register_user(base_url, member_username, password)
    print(f"   Success! UUID: {member_uuid}")

    group_uuid = None

    try:
        # 2. Create a Group
        print(f"\n🏗️ Creating test group under owner '{owner_username}'...")
        group_payload = {
            "group_name": "Metadata Test Group",
            "member_uuids": [member_uuid],
            "description": "Initial test group description",
            "searchable": False,
            "message_ttl_seconds": None
        }

        status, response = make_request(
            f"{base_url}/groups/create",
            payload=group_payload,
            token=owner_token
        )

        if status != 201:
            raise AssertionError(f"Failed to create group. Status: {status}, Response: {response}")

        group_uuid = response["group_uuid"]
        print(f"✅ Group created successfully! UUID: {group_uuid}")

        # 3. Assert /get_groups returns correct initial metadata
        print(f"\n🔍 Verifying initial group metadata via /get_groups...")
        status, response = make_request(f"{base_url}/get_groups", payload={}, token=owner_token)
        if status != 200:
            raise AssertionError(f"Failed to get groups. Status: {status}")

        groups = response.get("groups", [])
        test_group = next((g for g in groups if g["group_uuid"] == group_uuid), None)

        if not test_group:
            raise AssertionError("Created group not returned in /get_groups.")

        print("👉 Initial Metadata assertions:")
        print(f"   - Name:                 '{test_group['group_name']}'")
        print(f"   - Description:          '{test_group['description']}'")
        print(f"   - Searchable:           {test_group['searchable']}")
        print(f"   - Message TTL Seconds:  {test_group['message_ttl_seconds']}")

        assert test_group["group_name"] == "Metadata Test Group", "Initial group name mismatch"
        assert test_group["description"] == "Initial test group description", "Initial description mismatch"
        assert test_group["searchable"] is False, "Initial searchable status mismatch"
        assert test_group["message_ttl_seconds"] is None, "Initial message_ttl_seconds mismatch"
        print("⚡ Initial metadata is correct and fully formatted!")

        # 4. Assert /groups/edit under Owner successfully edits metadata
        print(f"\n📝 Attempting valid edits to group metadata as the owner...")
        edit_payload = {
            "group_uuid": group_uuid,
            "group_name": "Spoon Supreme Club",
            "description": "Justice is like a muscle... and we are very in shape!",
            "searchable": True,
            "message_ttl_seconds": 86400
        }

        status, response = make_request(
            f"{base_url}/groups/edit",
            payload=edit_payload,
            token=owner_token
        )

        if status != 200:
            raise AssertionError(f"Failed to edit group metadata as owner. Status: {status}, Response: {response}")

        print("👉 Edited Response assertions:")
        print(f"   - Name:                 '{response['group_name']}'")
        print(f"   - Description:          '{response['description']}'")
        print(f"   - Searchable:           {response['searchable']}")
        print(f"   - Message TTL Seconds:  {response['message_ttl_seconds']}")

        assert response["group_name"] == "Spoon Supreme Club", "Updated group name mismatch"
        assert response["description"] == "Justice is like a muscle... and we are very in shape!", "Updated description mismatch"
        assert response["searchable"] is True, "Updated searchable mismatch"
        assert response["message_ttl_seconds"] == 86400, "Updated message_ttl_seconds mismatch"
        print("⚡ Owner group edit successfully completed!")

        # Double check /get_groups returns the modified values
        print(f"\n🔍 Verifying updated group metadata via /get_groups...")
        status, response = make_request(f"{base_url}/get_groups", payload={}, token=owner_token)
        test_group = next((g for g in response.get("groups", []) if g["group_uuid"] == group_uuid), None)

        assert test_group["group_name"] == "Spoon Supreme Club", "Roster name sync failed"
        assert test_group["description"] == "Justice is like a muscle... and we are very in shape!", "Roster description sync failed"
        assert test_group["searchable"] is True, "Roster searchable status sync failed"
        assert test_group["message_ttl_seconds"] == 86400, "Roster message_ttl_seconds sync failed"
        print("⚡ Updated metadata is verified in the roster!")

        # 5. Assert /groups/edit rejects empty/blank group names
        print(f"\n⚠️ Testing validation: Rejects blank group names...")
        invalid_payload_name = {
            "group_uuid": group_uuid,
            "group_name": "   "
        }
        status, response = make_request(
            f"{base_url}/groups/edit",
            payload=invalid_payload_name,
            token=owner_token
        )
        print(f"👉 Status returned: {status} (Expected: 400), Response: {response}")
        assert status == 400, "Server failed to reject blank group name."
        print("⚡ Correctly rejected blank group name!")

        # 6. Assert /groups/edit rejects oversized descriptions
        print(f"\n⚠️ Testing validation: Rejects descriptions > 500 characters...")
        oversized_desc = "X" * 501
        invalid_payload_desc = {
            "group_uuid": group_uuid,
            "description": oversized_desc
        }
        status, response = make_request(
            f"{base_url}/groups/edit",
            payload=invalid_payload_desc,
            token=owner_token
        )
        print(f"👉 Status returned: {status} (Expected: 400), Response: {response}")
        assert status == 400, "Server failed to reject oversized description."
        print("⚡ Correctly rejected oversized description!")

        # 7. Assert /groups/edit under non-owner (Member B) rejects changes (403)
        print(f"\n🛡️ Testing authorization: Rejects edits made by a regular member...")
        unauthorized_payload = {
            "group_uuid": group_uuid,
            "group_name": "Villainous Takeover Attempt"
        }
        status, response = make_request(
            f"{base_url}/groups/edit",
            payload=unauthorized_payload,
            token=member_token
        )
        print(f"👉 Status returned: {status} (Expected: 403), Response: {response}")
        assert status == 403, "Server failed to reject group edit by a non-owner member."
        print("⚡ Correctly rejected edit from non-owner!")

    except Exception as e:
        print(f"\n❌ TEST FAILURE: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        # 8. Cleanup
        if group_uuid:
            print(f"\n🧹 Cleaning up test group {group_uuid}...")
            status, response = make_request(
                f"{base_url}/groups/{group_uuid}",
                token=owner_token,
                method="DELETE"
            )
            if status == 200:
                print("⚡ Test group deleted successfully!")
            else:
                print(f"⚠️ Failed to delete group in cleanup: {response}", file=sys.stderr)

    print("\n======================================================================")
    print("🎉 SPOON! ALL METADATA AND EDITING SERVER TESTS PASSED WITH FLYING COLORS!")
    print("======================================================================")


if __name__ == "__main__":
    main()
