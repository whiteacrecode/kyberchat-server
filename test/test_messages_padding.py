# test/test_messages_padding.py
#
# Unit tests for the message relay's padding-tier validation (VIDEO_PLAN.md CP1).
#
# The relay must accept BOTH padding tiers without inspecting contents:
#   • Tier-1 = 1024 bytes (text, key handshakes)
#   • Tier-2 = 4096 bytes (WebRTC SDP / ICE signaling)
# and must reject any off-tier size. It must also relay the exact base64 blob
# it was given (zero-knowledge fidelity) — no re-padding or mutation.

import os
import sys
import json
import base64
import unittest
from unittest.mock import MagicMock, patch

# Ensure cloudrun directory is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../cloudrun')))

import main


def _b64_of_size(n: int) -> str:
    """Base64 of exactly n bytes of deterministic filler."""
    return base64.b64encode(bytes((i % 256 for i in range(n)))).decode('ascii')


class MessagePaddingTierTestCase(unittest.TestCase):

    def setUp(self):
        self.app = main.app.test_client()
        self.app.testing = True

    def _send(self, ciphertext_b64):
        return self.app.post(
            '/messages/send',
            data=json.dumps({
                'recipient_uuid': 'recipient-uuid',
                'ciphertext': ciphertext_b64,
            }),
            content_type='application/json',
        )

    @patch('messages.notify_user')
    @patch('messages.engine')
    @patch('messages.verify_token')
    def _send_with_mocks(self, size, mock_verify, mock_engine, mock_notify):
        """Drive /messages/send with a payload of `size` bytes and a live-looking DB."""
        mock_verify.return_value = ('sender-uuid', None)

        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn

        # First execute() is the recipient-exists SELECT (truthy row); the
        # second is the INSERT. Capturing lets us assert relay fidelity.
        select_result = MagicMock()
        select_result.fetchone.return_value = ('recipient-uuid',)
        mock_conn.execute.side_effect = [select_result, MagicMock()]

        ciphertext_b64 = _b64_of_size(size)
        response = self._send(ciphertext_b64)
        return response, mock_conn, ciphertext_b64

    def test_tier1_1024_accepted_and_relayed_verbatim(self):
        response, mock_conn, sent = self._send_with_mocks(1024)
        self.assertEqual(response.status_code, 201)
        # The INSERT (second execute call) must store exactly what we sent.
        insert_params = mock_conn.execute.call_args_list[1].args[1]
        self.assertEqual(insert_params['ciphertext'], sent)

    def test_tier2_4096_signaling_accepted_and_relayed_verbatim(self):
        response, mock_conn, sent = self._send_with_mocks(4096)
        self.assertEqual(response.status_code, 201)
        insert_params = mock_conn.execute.call_args_list[1].args[1]
        self.assertEqual(insert_params['ciphertext'], sent)

    @patch('messages.notify_user')
    @patch('messages.engine')
    @patch('messages.verify_token')
    def test_off_tier_size_rejected(self, mock_verify, mock_engine, mock_notify):
        mock_verify.return_value = ('sender-uuid', None)
        # 2048 bytes is neither tier — must be rejected before any DB work.
        response = self._send(_b64_of_size(2048))
        self.assertEqual(response.status_code, 400)
        self.assertIn('4096', json.loads(response.data)['error'])
        mock_engine.begin.assert_not_called()


if __name__ == '__main__':
    unittest.main()
