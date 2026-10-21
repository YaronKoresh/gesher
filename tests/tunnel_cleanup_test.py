import os
import signal
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


@unittest.skipUnless(hasattr(signal, "SIGTERM"), "no SIGTERM")
class TestSigtermCleanup(unittest.TestCase):
    def setUp(self):
        self.original = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, self.original)

    @patch("gesher.cli.install_cloudflared")
    @patch("gesher.cli.start_cloudflared_tunnel")
    def test_sigterm_stops_the_server_and_the_tunnel(
        self, mock_cf, mock_install
    ):
        proc = MagicMock()
        proc.poll.return_value = None
        mock_cf.return_value = (proc, "https://a.trycloudflare.com")

        def serve(port, secret):
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("SIGTERM did not interrupt the server")

        with patch("sys.argv", server_argv()), patch(
            "gesher.cli.run_server", side_effect=serve
        ):
            with self.assertRaises(KeyboardInterrupt):
                cli.main()

        proc.terminate.assert_called_once()

    @patch("gesher.cli.run_server")
    def test_previous_sigterm_handler_is_restored(self, mock_run):
        marker = lambda signum, frame: None
        signal.signal(signal.SIGTERM, marker)

        with patch("sys.argv", ["gesher", "server", "--secret", "k"]):
            cli.main()

        self.assertIs(signal.getsignal(signal.SIGTERM), marker)

    def test_handler_turns_sigterm_into_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            cli.raise_interrupt(signal.SIGTERM, None)


if __name__ == "__main__":
    unittest.main()
