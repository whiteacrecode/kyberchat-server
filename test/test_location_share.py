# test/test_location_share.py
#
# Integration tests for the location-sharing blueprint (cloudrun/location.py):
#   POST /location/share
#   POST /location/stop
#   GET  /location/active
#
# Uses unittest and mock to test endpoints in isolation, mirroring
# test_webrtc.py's style: patch location.verify_token / location.engine /
# location.sync_location_share / location.delete_location_share_mirror so no
# real database, PASETO, or Firestore round-trip happens.
#
# Coverage, per geo_implementation_steps.md Step 5.1:
#   - Sharing (POST /location/share) returns valid data for both friend and
#     group targets, and rejects malformed/unauthorized requests.
#   - Stopping (POST /location/stop) deactivates a share, is idempotent, and
#     rejects non-grantors.
#   - Fetching active shares (GET /location/active) returns valid data.
#   - Non-participants / unauthenticated callers get clean 401/403/404
#     responses rather than 500s or leaked data.

import os
import sys
import unittest
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Ensure cloudrun directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../cloudrun')))

import main


UNAUTHORIZED_ERR = ({'error': 'Missing or invalid token'}, 401)


class LocationShareTestCase(unittest.TestCase):

    def setUp(self):
        self.app = main.app.test_client()
        self.app.testing = True

    # ------------------------------------------------------------------
    # POST /location/share
    # ------------------------------------------------------------------

    @patch('location.sync_location_share')
    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_with_friend_success(self, mock_verify_token, mock_engine, mock_sync):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.side_effect = [
            MagicMock(fetchone=lambda: ('bob-uuid',)),  # grantee exists
            MagicMock(fetchone=lambda: (1,)),            # accepted friendship
            MagicMock(),                                  # INSERT
        ]

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid', 'duration_hours': 2}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('share_uuid', data)
        self.assertIn('expires_at', data)
        mock_sync.assert_called_once()
        # Server never learns coordinates — just confirm the mirror call
        # only carries metadata (grantor/grantee/expiry), not location data.
        sync_args = mock_sync.call_args.args
        self.assertEqual(sync_args[1], 'alice-uuid')
        self.assertEqual(sync_args[2], 'bob-uuid')

    @patch('location.sync_location_share')
    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_with_group_success(self, mock_verify_token, mock_engine, mock_sync):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.side_effect = [
            MagicMock(fetchone=lambda: ('group-uuid',)),  # group exists
            MagicMock(fetchone=lambda: (1,)),               # alice is a member
            MagicMock(),                                     # INSERT
        ]

        response = self.app.post(
            '/location/share',
            data=json.dumps({'group_uuid': 'group-uuid', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('share_uuid', data)
        mock_sync.assert_called_once()

    @patch('location.verify_token')
    def test_start_share_unauthenticated(self, mock_verify_token):
        mock_verify_token.return_value = (None, UNAUTHORIZED_ERR)

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_missing_target(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        response = self.app.post(
            '/location/share',
            data=json.dumps({'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('grantee_uuid or group_uuid', data['error'])

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_both_targets(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid', 'group_uuid': 'group-uuid'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_invalid_duration_out_of_range(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid', 'duration_hours': 999}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('duration_hours', data['error'])

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_invalid_duration_non_numeric(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid', 'duration_hours': 'lots'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_grantee_not_found(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = None  # user_check fails

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'ghost-uuid', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_cannot_share_with_self(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = ('alice-uuid',)  # user_check succeeds

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'alice-uuid', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('yourself', data['error'])

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_not_friends(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.side_effect = [
            MagicMock(fetchone=lambda: ('bob-uuid',)),  # grantee exists
            MagicMock(fetchone=lambda: None),            # not an accepted friendship
        ]

        response = self.app.post(
            '/location/share',
            data=json.dumps({'grantee_uuid': 'bob-uuid', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_group_not_found(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = None  # group_check fails

        response = self.app.post(
            '/location/share',
            data=json.dumps({'group_uuid': 'ghost-group', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_start_share_not_group_member(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.side_effect = [
            MagicMock(fetchone=lambda: ('group-uuid',)),  # group exists
            MagicMock(fetchone=lambda: None),               # alice isn't a member
        ]

        response = self.app.post(
            '/location/share',
            data=json.dumps({'group_uuid': 'group-uuid', 'duration_hours': 1}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------
    # POST /location/stop
    # ------------------------------------------------------------------

    @patch('location.delete_location_share_mirror')
    @patch('location.engine')
    @patch('location.verify_token')
    def test_stop_share_success(self, mock_verify_token, mock_engine, mock_delete_mirror):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.side_effect = [
            MagicMock(fetchone=lambda: ('alice-uuid', 1)),  # grantor_uuid, is_active
            MagicMock(),                                      # UPDATE
        ]

        response = self.app.post(
            '/location/stop',
            data=json.dumps({'share_uuid': 'share-1'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        mock_delete_mirror.assert_called_once_with('share-1')

    @patch('location.verify_token')
    def test_stop_share_unauthenticated(self, mock_verify_token):
        mock_verify_token.return_value = (None, UNAUTHORIZED_ERR)

        response = self.app.post(
            '/location/stop',
            data=json.dumps({'share_uuid': 'share-1'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_stop_share_missing_share_uuid(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        response = self.app.post(
            '/location/stop',
            data=json.dumps({}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_stop_share_not_found(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = None

        response = self.app.post(
            '/location/stop',
            data=json.dumps({'share_uuid': 'ghost-share'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_stop_share_not_authorized(self, mock_verify_token, mock_engine):
        # Bob (an uninvolved, authenticated user) tries to stop Alice's share.
        mock_verify_token.return_value = ('bob-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = ('alice-uuid', 1)

        response = self.app.post(
            '/location/stop',
            data=json.dumps({'share_uuid': 'share-1'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

    @patch('location.delete_location_share_mirror')
    @patch('location.engine')
    @patch('location.verify_token')
    def test_stop_share_already_stopped_is_idempotent(self, mock_verify_token, mock_engine, mock_delete_mirror):
        mock_verify_token.return_value = ('alice-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchone.return_value = ('alice-uuid', 0)  # already inactive

        response = self.app.post(
            '/location/stop',
            data=json.dumps({'share_uuid': 'share-1'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        # Firestore mirror is still cleaned up even though MySQL had nothing to update.
        mock_delete_mirror.assert_called_once_with('share-1')
        # Only the SELECT ran — no redundant UPDATE for an already-stopped share.
        self.assertEqual(mock_conn.execute.call_count, 1)

    # ------------------------------------------------------------------
    # GET /location/active
    # ------------------------------------------------------------------

    @patch('location.engine')
    @patch('location.verify_token')
    def test_get_active_shares_success(self, mock_verify_token, mock_engine):
        mock_verify_token.return_value = ('alice-uuid', None)

        now = datetime(2026, 7, 6, 18, 30, 0, tzinfo=timezone.utc)
        rows = [
            # Friend-target share
            ('share-1', 'alice-uuid', 'alice', 'bob-uuid', 'bob', None, None, now, now),
            # Group-target share
            ('share-2', 'alice-uuid', 'alice', None, None, 'group-uuid', 'Weekend Trip', now, now),
        ]

        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchall.return_value = rows

        response = self.app.get('/location/active')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data['shares']), 2)

        friend_share = data['shares'][0]
        self.assertEqual(friend_share['share_uuid'], 'share-1')
        self.assertEqual(friend_share['grantee_uuid'], 'bob-uuid')
        self.assertIsNone(friend_share['group_uuid'])
        self.assertTrue(friend_share['expires_at'].endswith('Z'))

        group_share = data['shares'][1]
        self.assertEqual(group_share['group_uuid'], 'group-uuid')
        self.assertEqual(group_share['group_name'], 'Weekend Trip')
        self.assertIsNone(group_share['grantee_uuid'])

    @patch('location.verify_token')
    def test_get_active_shares_unauthenticated(self, mock_verify_token):
        mock_verify_token.return_value = (None, UNAUTHORIZED_ERR)

        response = self.app.get('/location/active')

        self.assertEqual(response.status_code, 401)

    @patch('location.engine')
    @patch('location.verify_token')
    def test_get_active_shares_empty_for_non_participant(self, mock_verify_token, mock_engine):
        # An authenticated user with no involvement in any share gets a
        # clean empty list, not an error.
        mock_verify_token.return_value = ('carol-uuid', None)

        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_conn.execute.return_value.fetchall.return_value = []

        response = self.app.get('/location/active')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['shares'], [])


if __name__ == '__main__':
    unittest.main()
