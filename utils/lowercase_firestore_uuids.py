#!/usr/bin/env python3
"""
One-off Firestore canonicalisation to accompany schema migration
015_lowercase_uuids.sql.

Firestore holds two pieces of state keyed by a *user* UUID whose case must
match the (now lowercase) Firebase custom-token uid:

  1. groups/{group_uuid}.members  — array of member UUIDs. firestore.rules
     gate group read/write on `request.auth.uid in resource.data.members`.
     Any member still stored uppercase would lose access once their uid is
     lowercase. ACCESS-CRITICAL — this script fixes it.

  2. profiles/{userId}            — avatar doc id == owner uid. A stale
     uppercase doc is merely cosmetic (the avatar self-heals on the next
     upload), but we relocate it too so friends see it immediately.

Message docs under conversations/{chatId}/messages are ephemeral (deleted by
the recipient after decrypt) and short-lived, so they are intentionally NOT
rewritten — in-flight messages drain within seconds.

Idempotent: rewriting already-lowercase data is a no-op.

Usage:
    # Uses Application Default Credentials (same as the Cloud Run SA).
    python3 lowercase_firestore_uuids.py            # dry run (default)
    python3 lowercase_firestore_uuids.py --apply    # perform writes
"""
import argparse
import sys

import firebase_admin
from firebase_admin import firestore


def _canon(u: str) -> str:
    return u.strip().lower() if isinstance(u, str) else u


def fix_group_members(db, apply: bool) -> None:
    changed = 0
    for doc in db.collection("groups").stream():
        data = doc.to_dict() or {}
        members = data.get("members")
        if not isinstance(members, list):
            continue
        canon = [_canon(m) for m in members]
        if canon != members:
            changed += 1
            print(f"  groups/{doc.id}: {members} -> {canon}")
            if apply:
                # merge=True to preserve icon_jpeg_b64 written by set_group_icon.
                doc.reference.set({"members": canon}, merge=True)
    print(f"groups: {changed} membership doc(s) {'updated' if apply else 'would change'}")


def fix_profiles(db, apply: bool) -> None:
    changed = 0
    for doc in db.collection("profiles").stream():
        canon_id = _canon(doc.id)
        if canon_id != doc.id:
            changed += 1
            print(f"  profiles/{doc.id} -> profiles/{canon_id}")
            if apply:
                data = doc.to_dict() or {}
                # Move the doc to the lowercase id, then delete the old one.
                db.collection("profiles").document(canon_id).set(data, merge=True)
                doc.reference.delete()
    print(f"profiles: {changed} doc(s) {'relocated' if apply else 'would relocate'}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="Perform writes (default is a dry run).")
    args = parser.parse_args()

    if not firebase_admin._apps:
        firebase_admin.initialize_app()
    db = firestore.client()

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"=== Firestore UUID lowercase canonicalisation ({mode}) ===")
    fix_group_members(db, args.apply)
    fix_profiles(db, args.apply)
    if not args.apply:
        print("\nDry run only. Re-run with --apply to perform the writes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
