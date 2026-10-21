import threading
import unittest
from unittest.mock import MagicMock, patch

from gesher import client


class Stop(BaseException):
    pass


class TestCleanCloseReconnect(unittest.TestCase):
    def test_client_waits_before_reconnecting_after_a_clean_close(self):
        response = MagicMock()
        response.status_code = 200
        response.iter_content.return_value = iter([])
        response.__enter__.return_value = response
        response.__exit__.return_value = False

        with patch(
            "gesher.client.requests.post", return_value=response
        ) as post, patch(
            "gesher.client.time.sleep", side_effect=Stop
        ) as sleep, patch("gesher.client.threading.Thread"):
            with self.assertRaises(Stop):
                client.start_connector(
                    "http://gw", "secret", "http://localhost:1", "PIN", 9000
                )

        self.assertEqual(post.call_count, 1)
        sleep.assert_called_once_with(5)


if __name__ == "__main__":
    unittest.main()
