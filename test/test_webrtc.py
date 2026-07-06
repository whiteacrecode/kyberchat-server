# test/test_webrtc.py
#
# Unit tests for the WebRTC calling blueprint, token registration, and TURN credential generation.
# Uses unittest and mock to test endpoints in isolation.

import os
import sys
import unittest
import json
import hmac
import hashlib
import base64
from unittest.mock import MagicMock, patch

# Ensure cloudrun directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../cloudrun')))

# Set dummy environment variables before importing main
os.environ['TURN_SHARED_SECRET'] = 'the_gluten_of_evil'
os.environ['TURN_SERVER_HOST'] = 'turn.kyberchat.com:3478'
os.environ['IOS_BUNDLE_ID'] = 'org.tomw.kyberchat'

import main

class WebRTCTestCase(unittest.TestCase):

    def setUp(self):
        self.app = main.app.test_client()
        self.app.testing = True

    @patch('webrtc.verify_token')
    @patch('webrtc.engine')
    def test_register_voip_token(self, mock_engine, mock_verify_token):
        # Mock valid token auth
        mock_verify_token.return_value = ('user-uuid-123', None)

        # Mock database connection
        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        
        # Scenario 1: Brand new registration
        mock_conn.execute.return_value.fetchone.return_value = None

        response = self.app.post(
            '/webrtc/register_voip_token',
            data=json.dumps({'voip_token': 'dummy_voip_token_hex', 'platform': 'ios'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'VoIP device registered')

        # Scenario 2: Token already registered (refresh)
        mock_conn.execute.return_value.fetchone.return_value = [42] # existing id

        response = self.app.post(
            '/webrtc/register_voip_token',
            data=json.dumps({'voip_token': 'dummy_voip_token_hex', 'platform': 'ios'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'VoIP device updated')

    @patch('webrtc.verify_token')
    @patch('webrtc.engine')
    def test_unregister_voip_token(self, mock_engine, mock_verify_token):
        mock_verify_token.return_value = ('user-uuid-123', None)
        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        
        # Token found and deleted
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_conn.execute.return_value = mock_result

        response = self.app.post(
            '/webrtc/unregister_voip_token',
            data=json.dumps({'voip_token': 'dummy_voip_token_hex'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'VoIP device unregistered')

    @patch('webrtc.verify_token')
    def test_get_turn_credentials(self, mock_verify_token):
        mock_verify_token.return_value = ('user-uuid-123', None)

        response = self.app.get('/webrtc/turn-credentials')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('ice_servers', data)
        self.assertEqual(len(data['ice_servers']), 3)

        # Validate STUN
        self.assertEqual(data['ice_servers'][0]['urls'], 'stun:stun.l.google.com:19302')

        # Validate TURN UDP and TCP credentials
        turn_udp = data['ice_servers'][1]
        self.assertTrue(turn_udp['urls'].startswith('turn:turn.kyberchat.com:3478'))
        self.assertTrue('username' in turn_udp)
        self.assertTrue('credential' in turn_udp)

        # Manually compute the expected HMAC to verify integrity
        username = turn_udp['username']
        key = b'the_gluten_of_evil'
        expected_sig = hmac.new(key, username.encode('utf-8'), hashlib.sha1).digest()
        expected_credential = base64.b64encode(expected_sig).decode('utf-8')
        
        self.assertEqual(turn_udp['credential'], expected_credential)

    @patch('webrtc.verify_token')
    @patch('webrtc.engine')
    @patch('webrtc._get_app')
    @patch('firebase_admin.messaging.send')
    def test_initiate_call(self, mock_fcm_send, mock_get_app, mock_engine, mock_verify_token):
        mock_verify_token.return_value = ('caller-uuid', None)
        
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        # Mock sender lookup and recipient voip tokens
        mock_conn.execute.side_effect = [
            MagicMock(scalar=lambda: 'caller_username'),  # first call to execute (sender username)
            MagicMock(fetchall=lambda: [('token_1', 'ios'), ('token_2', 'ios')]) # second call (recipient tokens)
        ]

        response = self.app.post(
            '/webrtc/call',
            data=json.dumps({
                'recipient_uuid': 'recipient-uuid',
                'call_uuid': 'call-uuid-999'
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['sent_count'], 2)
        self.assertEqual(data['failed_count'], 0)
        
        # Verify Firebase send was invoked twice
        self.assertEqual(mock_fcm_send.call_count, 2)


if __name__ == '__main__':
    unittest.main()
