import subprocess
import unittest
from unittest.mock import MagicMock, patch

from gesher import cli


def server_argv():
    return ["gesher", "server", "--secret", "k", "--public"]


class TestTunnelCleanup(unittest.TestCase):
    @patch("gesher.cli.install_cloudflared")
    @patch("gesher.cli.run_server")
    @patch("gesher.cli.start_cloudflared_tunnel")
    def test_tunnel_is_terminated_when_the_server_returns(
        self, mock_cf, mock_run, mock_install
    ):
        proc = MagicMock()
        proc.poll.return_value = None
        mock_cf.return_value = (proc, "https://a.trycloudflare.com")
        with patch("sys.argv", server_argv()):
            cli.main()
        proc.terminate.assert_called_once()
        proc.wait.assert_called()

    @patch("gesher.cli.install_cloudflared")
    @patch("gesher.cli.run_server", side_effect=KeyboardInterrupt)
    @patch("gesher.cli.start_cloudflared_tunnel")
    def test_tunnel_is_terminated_when_the_server_is_interrupted(
        self, mock_cf, mock_run, mock_install
    ):
        proc = MagicMock()
        proc.poll.return_value = None
        mock_cf.return_value = (proc, None)
        with patch("sys.argv", server_argv()):
            with self.assertRaises(KeyboardInterrupt):
                cli.main()
        proc.terminate.assert_called_once()

    @patch("gesher.cli.install_cloudflared")
    @patch("gesher.cli.run_server")
    @patch("gesher.cli.start_cloudflared_tunnel")
    def test_finished_tunnel_is_not_terminated_again(
        self, mock_cf, mock_run, mock_install
    ):
        proc = MagicMock()
        proc.poll.return_value = 1
        mock_cf.return_value = (proc, None)
        with patch("sys.argv", server_argv()):
            cli.main()
        proc.terminate.assert_not_called()

    def test_stop_tunnel_kills_a_process_that_ignores_terminate(self):
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("cf", 5), 0]
        cli.stop_tunnel(proc)
        proc.kill.assert_called_once()

    def test_stop_tunnel_accepts_no_process(self):
        cli.stop_tunnel(None)

    @patch("gesher.cli.run_server")
    def test_server_without_public_mode_starts_no_tunnel(self, mock_run):
        with patch("sys.argv", ["gesher", "server", "--secret", "k"]), patch(
            "gesher.cli.start_cloudflared_tunnel"
        ) as mock_cf:
            cli.main()
        mock_cf.assert_not_called()
        mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
