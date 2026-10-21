import json
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from gesher import client
from gesher.security import SecurityLayer


def one_shot_service():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    request_lines = []

    def serve():
        conn, _ = listener.accept()
        request_lines.append(conn.recv(4096).split(b"\r\n")[0])
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.close()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener.getsockname()[1], request_lines, thread


class TestTrailingSlash(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("test-secret")
        client.SECURITY = self.security

    def task(self, url="/hello"):
        task = {"id": "1", "method": "GET", "url": url, "headers": {}}
        return self.security.encrypt(json.dumps(task))

    @patch("gesher.client.requests.post")
    def test_target_with_trailing_slash_sends_single_slash_path(
        self, mock_post
    ):
        port, request_lines, thread = one_shot_service()
        client.handle_task(
            self.task(), f"http://127.0.0.1:{port}/", "http://gateway"
        )
        thread.join(5)
        self.assertEqual(request_lines, [b"GET /hello HTTP/1.1"])

    @patch("gesher.client.requests.post")
    @patch("gesher.client.requests.request")
    def test_target_with_path_keeps_its_path(self, mock_request, mock_post):
        mock_request.return_value = MagicMock(
            status_code=200, headers={}, content=b""
        )
        client.handle_task(self.task(), "http://host/app/", "http://gateway")
        self.assertEqual(
            mock_request.call_args.kwargs["url"], "http://host/app/hello"
        )

    @patch("gesher.client.requests.post")
    @patch("gesher.client.requests.request")
    def test_gateway_with_trailing_slash_posts_to_single_slash_path(
        self, mock_request, mock_post
    ):
        mock_request.return_value = MagicMock(
            status_code=200, headers={}, content=b""
        )
        client.handle_task(self.task(), "http://host", "http://gateway/")
        self.assertEqual(
            mock_post.call_args[0][0], "http://gateway/_tunnel_response"
        )

    @patch("gesher.client.threading.Thread")
    @patch("gesher.client.requests.post")
    def test_connector_joins_gateway_without_double_slash(
        self, mock_post, mock_thread
    ):
        response = MagicMock(status_code=401)
        mock_post.return_value.__enter__.return_value = response
        accepted = client.start_connector(
            "http://gateway//", "s", "http://host/", "PIN", 9000
        )
        self.assertFalse(accepted)
        self.assertEqual(
            mock_post.call_args[0][0], "http://gateway/_connect_tunnel"
        )


if __name__ == "__main__":
    unittest.main()
