import unittest
from unittest.mock import MagicMock, patch

from gesher import client


class Stop(BaseException):
    pass


class TestStreamLineShape(unittest.TestCase):
    def test_non_object_lines_are_ignored_without_dropping_the_tunnel(self):
        response = MagicMock()
        response.status_code = 200
        lines = [b"[1, 2]\n", b'"text"\n', b"5\n", b"null\n"]
        response.iter_content.return_value = iter(lines)
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            raise Stop()

        with patch("gesher.client.requests.post", return_value=response), patch(
            "gesher.client.time.sleep", side_effect=fake_sleep
        ), patch("gesher.client.threading.Thread"), patch.object(
            client.logger, "error"
        ) as log_error:
            with self.assertRaises(Stop):
                client.start_connector(
                    "http://gw", "secret", "http://localhost:1", "PIN", 9000
                )

        log_error.assert_not_called()
        self.assertEqual(sleeps, [5])


if __name__ == "__main__":
    unittest.main()
