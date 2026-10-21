import contextlib
import io
import unittest
from unittest.mock import patch

from gesher import cli


class TestCliArguments(unittest.TestCase):
    def run_cli(self, *args):
        stderr = io.StringIO()
        with patch("sys.argv", ["gesher", *args]), patch(
            "gesher.cli.run_server"
        ) as run_server, patch("gesher.cli.start_connector") as connector:
            with contextlib.redirect_stderr(stderr):
                try:
                    cli.main()
                    code = 0
                except SystemExit as exc:
                    code = exc.code
        called = run_server.called or connector.called
        return code, called, stderr.getvalue()

    def client_args(self, **overrides):
        values = {
            "--gateway": "http://127.0.0.1:8000",
            "--secret": "key",
            "--pin": "ABC123",
            "--target": "http://localhost:3000",
            "--dashboard-port": "9000",
        }
        values.update(overrides)
        args = []
        for key, value in values.items():
            args += [key, value]
        return ["client", *args]

    def test_server_port_out_of_range_is_rejected(self):
        for port in ("0", "70000", "-1", "abc"):
            code, called, err = self.run_cli(
                "server", "--secret", "x", "--port", port
            )
            self.assertEqual(code, 2, port)
            self.assertFalse(called, port)
            self.assertIn("--port", err)

    def test_server_empty_secret_is_rejected(self):
        for secret in ("", "   "):
            code, called, err = self.run_cli("server", "--secret", secret)
            self.assertEqual(code, 2)
            self.assertFalse(called)
            self.assertIn("--secret", err)

    def test_server_highest_port_is_accepted(self):
        code, called, _ = self.run_cli(
            "server", "--secret", "x", "--port", "65535"
        )
        self.assertEqual(code, 0)
        self.assertTrue(called)

    def test_client_dashboard_port_out_of_range_is_rejected(self):
        code, called, err = self.run_cli(
            *self.client_args(**{"--dashboard-port": "70000"})
        )
        self.assertEqual(code, 2)
        self.assertFalse(called)
        self.assertIn("--dashboard-port", err)

    def test_client_gateway_without_scheme_is_rejected(self):
        for gateway in ("127.0.0.1:8000", "ftp://host", "http://", ""):
            code, called, err = self.run_cli(
                *self.client_args(**{"--gateway": gateway})
            )
            self.assertEqual(code, 2, gateway)
            self.assertFalse(called, gateway)
            self.assertIn("--gateway", err)

    def test_client_target_without_scheme_is_rejected(self):
        code, called, err = self.run_cli(
            *self.client_args(**{"--target": "localhost:3000"})
        )
        self.assertEqual(code, 2)
        self.assertFalse(called)
        self.assertIn("--target", err)

    def test_client_empty_secret_and_pin_are_rejected(self):
        for flag in ("--secret", "--pin"):
            code, called, err = self.run_cli(*self.client_args(**{flag: ""}))
            self.assertEqual(code, 2, flag)
            self.assertFalse(called, flag)
            self.assertIn(flag, err)

    def test_client_https_gateway_and_default_target_are_accepted(self):
        code, called, _ = self.run_cli(
            "client",
            "--gateway",
            "https://bridge.example.com",
            "--secret",
            "key",
            "--pin",
            "ABC123",
        )
        self.assertEqual(code, 0)
        self.assertTrue(called)


if __name__ == "__main__":
    unittest.main()
