import unittest
from unittest.mock import MagicMock, patch

from gesher import cli, client


def client_argv():
    return [
        "gesher",
        "client",
        "--gateway",
        "http://gateway",
        "--secret",
        "key",
        "--pin",
        "ABC123",
    ]


class TestConnectorResult(unittest.TestCase):
    def rejected_with(self, status):
        response = MagicMock()
        response.status_code = status
        with patch("gesher.client.requests.post") as post, patch(
            "gesher.client.threading.Thread"
        ):
            post.return_value.__enter__.return_value = response
            return client.start_connector(
                "http://gateway", "key", "http://local", "PIN", 9999
            )

    def test_invalid_pin_is_reported_as_a_failure(self):
        self.assertIs(self.rejected_with(401), False)

    def test_invalid_secret_is_reported_as_a_failure(self):
        self.assertIs(self.rejected_with(403), False)


class TestClientExitCode(unittest.TestCase):
    def test_rejected_client_exits_with_status_1(self):
        with patch("sys.argv", client_argv()), patch(
            "gesher.cli.start_connector", return_value=False
        ):
            with self.assertRaises(SystemExit) as ctx:
                cli.main()
        self.assertEqual(ctx.exception.code, 1)

    def test_client_that_returns_nothing_exits_normally(self):
        with patch("sys.argv", client_argv()), patch(
            "gesher.cli.start_connector", return_value=None
        ):
            cli.main()


class TestClientInterrupt(unittest.TestCase):
    def interrupted_in(self, patched):
        with patch("gesher.client.threading.Thread"), patched:
            return client.start_connector(
                "http://gateway", "key", "http://local", "PIN", 9999
            )

    def test_ctrl_c_while_connected_stops_without_a_traceback(self):
        patched = patch(
            "gesher.client.requests.post", side_effect=KeyboardInterrupt
        )
        self.assertIsNone(self.interrupted_in(patched))

    def test_ctrl_c_while_waiting_to_reconnect_stops_quietly(self):
        import requests

        patched = patch.multiple(
            "gesher.client",
            requests=MagicMock(
                post=MagicMock(side_effect=requests.exceptions.ConnectionError),
                exceptions=requests.exceptions,
            ),
            time=MagicMock(sleep=MagicMock(side_effect=KeyboardInterrupt)),
        )
        self.assertIsNone(self.interrupted_in(patched))

    def test_cli_exits_normally_after_ctrl_c(self):
        with patch("sys.argv", client_argv()), patch(
            "gesher.client.threading.Thread"
        ), patch("gesher.client.requests.post", side_effect=KeyboardInterrupt):
            cli.main()


if __name__ == "__main__":
    unittest.main()
