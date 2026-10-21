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
            "http://my-gateway.com",
            "mykey",
            "http://localhost:3000",
            "ABC123",
            9000,
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


class TestCloudflaredInstall(unittest.TestCase):
    def _installed_package(self, machine):
        from unittest.mock import MagicMock

        with patch("gesher.cli.subprocess.run") as run, patch(
            "gesher.cli.platform.system", return_value="Linux"
        ), patch("gesher.cli.platform.machine", return_value=machine), patch(
            "gesher.cli.urllib.request.urlretrieve"
        ) as retrieve, patch("gesher.cli.os.remove"):
            run.side_effect = [FileNotFoundError(), MagicMock()]
            cli.install_cloudflared()
        if not retrieve.called:
            return None
        return retrieve.call_args[0][0].rsplit("/", 1)[-1]

    def test_linux_package_matches_the_cpu_type(self):
        expected = {
            "x86_64": "cloudflared-linux-amd64.deb",
            "aarch64": "cloudflared-linux-arm64.deb",
            "arm64": "cloudflared-linux-arm64.deb",
            "armv7l": "cloudflared-linux-armhf.deb",
            "i686": "cloudflared-linux-386.deb",
        }
        for machine, package in expected.items():
            with self.subTest(machine=machine):
                self.assertEqual(self._installed_package(machine), package)

    def test_unknown_cpu_type_installs_nothing(self):
        self.assertIsNone(self._installed_package("riscv64"))


class TestTunnelUrlWait(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile

        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        import os

        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _run(self, write_on_call, alive=True):
        from unittest.mock import MagicMock

        calls = {"n": 0}

        def fake_sleep(_seconds):
            calls["n"] += 1
            if calls["n"] == write_on_call:
                with open("tunnel.log", "w") as f:
                    f.write("INF https://abc-def.trycloudflare.com ready")

        proc = MagicMock()
        proc.poll.return_value = None if alive else 1
        with patch("gesher.cli.subprocess.Popen", return_value=proc), patch(
            "gesher.cli.time.sleep", side_effect=fake_sleep
        ):
            _, url = cli.start_cloudflared_tunnel(8000)
        return url, calls["n"]

    def test_url_found_after_more_than_five_seconds(self):
        url, polls = self._run(write_on_call=20)

        self.assertEqual(url, "https://abc-def.trycloudflare.com")
        self.assertEqual(polls, 20)

    def test_url_found_at_once_stops_waiting(self):
        url, polls = self._run(write_on_call=1)

        self.assertEqual(url, "https://abc-def.trycloudflare.com")
        self.assertEqual(polls, 1)

    def test_gives_up_when_the_process_exits(self):
        url, polls = self._run(write_on_call=0, alive=False)

        self.assertIsNone(url)
        self.assertEqual(polls, 1)

    def test_gives_up_after_the_wait_limit(self):
        from unittest.mock import MagicMock

        proc = MagicMock()
        proc.poll.return_value = None
        clock = {"t": 1000.0}

        def fake_time():
            return clock["t"]

        def fake_sleep(seconds):
            clock["t"] += seconds

        with patch("gesher.cli.subprocess.Popen", return_value=proc), patch(
            "gesher.cli.time.sleep", side_effect=fake_sleep
        ), patch("gesher.cli.time.time", side_effect=fake_time):
            _, url = cli.start_cloudflared_tunnel(8000)

        self.assertIsNone(url)
        self.assertGreaterEqual(
            clock["t"] - 1000.0, cli.TUNNEL_WAIT_SECONDS - 1
        )


class TestPublicModeMessage(unittest.TestCase):
    @patch("gesher.cli.install_cloudflared")
    @patch("gesher.cli.run_server")
    @patch("gesher.cli.start_cloudflared_tunnel")
    def test_missing_url_is_reported_instead_of_none(
        self, mock_cf, mock_run, mock_install
    ):
        import io
        from contextlib import redirect_stdout

        mock_cf.return_value = (None, None)
        buffer = io.StringIO()
        with patch(
            "sys.argv", ["gesher", "server", "--secret", "k", "--public"]
        ), redirect_stdout(buffer):
            cli.main()

        output = buffer.getvalue()
        self.assertNotIn("None", output)
        self.assertIn("tunnel.log", output)
        mock_run.assert_called_once()
