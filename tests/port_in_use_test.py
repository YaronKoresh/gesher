import contextlib
import io
import socket
import unittest
from unittest.mock import patch

from gesher import client, server


@contextlib.contextmanager
def busy_port():
    sock = socket.socket()
    sock.bind(("", 0))
    sock.listen(1)
    try:
        yield sock.getsockname()[1]
    finally:
        sock.close()


class TestPortInUse(unittest.TestCase):
    def test_server_exits_with_a_message_when_the_port_is_busy(self):
        err = io.StringIO()
        with busy_port() as port:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit) as ctx:
                    server.run_server(port, "secret")
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn(f"Cannot listen on port {port}", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_dashboard_reports_a_busy_port_and_returns(self):
        client.SECURITY = None
        with busy_port() as port:
            with patch.object(
                client.logger, "warning"
            ) as warning, patch.object(client.logger, "info") as info:
                client.run_local_dashboard(port, "http://127.0.0.1:1", "PIN")
        warning.assert_called_once()
        self.assertIn(str(port), warning.call_args[0][0])
        self.assertIn("tunnel keeps running", warning.call_args[0][0])
        for call in info.call_args_list:
            self.assertNotIn("Dashboard running", call[0][0])

    def test_dashboard_announces_itself_only_after_binding(self):
        with patch(
            "gesher.client.http.server.ThreadingHTTPServer"
        ) as cls, patch.object(client.logger, "info") as info:
            cls.return_value.serve_forever.side_effect = lambda: (
                self.assertTrue(
                    any(
                        "Dashboard running" in c[0][0]
                        for c in info.call_args_list
                    )
                )
            )
            client.run_local_dashboard(9999, "http://127.0.0.1:1", "PIN")
        cls.return_value.serve_forever.assert_called_once()


if __name__ == "__main__":
    unittest.main()
