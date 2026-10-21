import http.client
import socket
import threading
import time
import unittest
from unittest.mock import patch

from gesher import client, server
from gesher.security import SecurityLayer


class Stop(BaseException):
    pass


class TestServerKeepalive(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("secret")
        server.GATEKEEPER_PIN = "PIN"
        server.CLIENTS = {}
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_idle_tunnel_receives_blank_lines(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/_connect_tunnel",
            headers={
                "Authorization": server.SECURITY.get_auth_header(),
                "X-Join-Code": "PIN",
                "Content-Length": "0",
            },
        )
        with patch.object(server, "KEEPALIVE_INTERVAL", 0.6):
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            started = time.monotonic()
            chunks = []
            while b"\n" not in chunks and len(chunks) < 5:
                size = int(resp.fp.readline().strip(), 16)
                chunks.append(resp.fp.read(size + 2)[:-2])
            conn.close()
        self.assertIn(b"\n", chunks)
        self.assertLess(time.monotonic() - started, 5)

    def test_keepalive_is_shorter_than_the_client_read_timeout(self):
        self.assertLess(
            server.KEEPALIVE_INTERVAL * 2, client.TUNNEL_READ_TIMEOUT
        )


class TestClientReadTimeout(unittest.TestCase):
    def test_silent_gateway_makes_the_client_reconnect(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted = []

        def serve():
            conn, _ = listener.accept()
            accepted.append(conn)
            conn.recv(65536)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            )

        threading.Thread(target=serve, daemon=True).start()
        started = time.monotonic()
        with patch.object(client, "TUNNEL_READ_TIMEOUT", 1), patch(
            "gesher.client.time.sleep", side_effect=Stop
        ) as sleep, patch("gesher.client.threading.Thread"):
            with self.assertRaises(Stop):
                client.start_connector(
                    f"http://127.0.0.1:{port}", "key", "http://local", "PIN", 9
                )
        self.assertLess(time.monotonic() - started, 5)
        sleep.assert_called_once_with(5)
        for conn in accepted:
            conn.close()
        listener.close()

    def test_tunnel_request_uses_a_read_timeout(self):
        with patch("gesher.client.requests.post") as post, patch(
            "gesher.client.threading.Thread"
        ), patch("gesher.client.time.sleep", side_effect=Stop):
            post.side_effect = client.requests.exceptions.ConnectionError()
            with self.assertRaises(Stop):
                client.start_connector(
                    "http://gateway", "key", "http://local", "PIN", 9
                )
        self.assertEqual(
            post.call_args.kwargs["timeout"],
            (client.TUNNEL_CONNECT_TIMEOUT, client.TUNNEL_READ_TIMEOUT),
        )


if __name__ == "__main__":
    unittest.main()
