import unittest
from unittest.mock import patch

from gesher import cli


class TestCLI(unittest.TestCase):
    @patch("gesher.cli.run_server")
    def test_server_mode_defaults(self, mock_run_server):
        test_args = ["gesher", "server", "--secret", "auto-secret"]
        with patch("sys.argv", test_args):
            cli.main()

        mock_run_server.assert_called_with(8000, "auto-secret")

    @patch("gesher.cli.run_server")
    def test_server_mode_custom(self, mock_run_server):
        test_args = ["gesher", "server", "--port", "9090", "--secret", "mykey"]
        with patch("sys.argv", test_args):
            cli.main()

        mock_run_server.assert_called_with(9090, "mykey")

    @patch("gesher.cli.start_connector")
    def test_client_mode(self, mock_start_connector):
        test_args = [
            "gesher",
            "client",
            "--gateway",
            "http://my-gateway.com",
            "--secret",
            "mykey",
            "--pin",
            "ABC123",
            "--target",
            "http://localhost:3000",
        ]
        with patch("sys.argv", test_args):
            cli.main()

        mock_start_connector.assert_called_with(
            "http://my-gateway.com", "mykey", "http://localhost:3000", "ABC123", 9000
        )

    @patch("gesher.cli.subprocess.run")
    @patch("gesher.cli.start_cloudflared_tunnel")
    @patch("gesher.cli.run_server")
    def test_server_public_mode(self, mock_run, mock_cf, mock_sub):
        mock_cf.return_value = (None, "https://random.trycloudflare.com")

        test_args = ["gesher", "server", "--secret", "my-key", "--public"]
        with patch("sys.argv", test_args):
            cli.main()

        mock_sub.assert_called()
        mock_cf.assert_called()
