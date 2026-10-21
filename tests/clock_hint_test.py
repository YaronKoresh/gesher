import unittest
from unittest.mock import MagicMock, patch

from gesher import client
from gesher.security import SIGNATURE_WINDOW_SECONDS


class TestAccessDeniedMessage(unittest.TestCase):
    def run_with_status(self, status):
        response = MagicMock()
        response.status_code = status
        with patch("gesher.client.requests.post") as post, patch(
            "gesher.client.threading.Thread"
        ), patch.object(client.logger, "critical") as critical:
            post.return_value.__enter__.return_value = response
            client.start_connector(
                "http://gateway", "key", "http://local", "PIN", 9999
            )
        return [call[0][0] for call in critical.call_args_list]

    def test_403_message_mentions_the_clock_and_the_window(self):
        messages = self.run_with_status(403)
        self.assertEqual(len(messages), 1)
        self.assertIn("Invalid Secret or Signature", messages[0])
        self.assertIn("clock", messages[0])
        self.assertIn(f"{SIGNATURE_WINDOW_SECONDS} seconds", messages[0])

    def test_401_message_is_unchanged(self):
        messages = self.run_with_status(401)
        self.assertEqual(messages, ["⛔ Gatekeeper Rejected: Invalid PIN."])


if __name__ == "__main__":
    unittest.main()
