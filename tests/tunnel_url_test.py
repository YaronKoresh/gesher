import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from gesher import cli

ERROR_LINE = (
    'ERR failed to request quick Tunnel error="Post '
    '\\"https://api.trycloudflare.com/tunnel\\": dial tcp: lookup '
    'api.trycloudflare.com: no such host"\n'
)
REAL_URL = "https://abc-def-ghi.trycloudflare.com"


class TestTunnelUrl(unittest.TestCase):
    def test_api_address_in_an_error_line_is_not_a_tunnel_url(self):
        self.assertIsNone(cli.find_tunnel_url(ERROR_LINE))

    def test_real_address_is_found_even_after_an_api_address(self):
        text = ERROR_LINE + f"INF |  {REAL_URL}  |\n"
        self.assertEqual(cli.find_tunnel_url(text), REAL_URL)

    def test_plain_log_without_an_address_gives_none(self):
        self.assertIsNone(cli.find_tunnel_url("INF starting tunnel\n"))

    def test_failed_tunnel_process_reports_no_url(self):
        script = f"import sys; sys.stderr.write({ERROR_LINE!r})"
        original = subprocess.Popen

        def fake(cmd, **kwargs):
            return original([sys.executable, "-c", script], **kwargs)

        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with patch.object(
                    cli.subprocess, "Popen", side_effect=fake
                ), patch.object(cli, "TUNNEL_POLL_INTERVAL", 0.05):
                    proc, url = cli.start_cloudflared_tunnel(8000)
                proc.wait(5)
            finally:
                os.chdir(old_cwd)
        self.assertIsNone(url)


if __name__ == "__main__":
    unittest.main()
